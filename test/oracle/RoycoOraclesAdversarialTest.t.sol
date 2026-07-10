// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import { Test, stdError } from "../../lib/forge-std/src/Test.sol";

import { ERC20Mock } from "../../lib/openzeppelin-contracts/contracts/mocks/token/ERC20Mock.sol";

import { IRoycoKernel } from "../../src/interfaces/IRoycoKernel.sol";
import { IRoycoVaultTranche } from "../../src/interfaces/IRoycoVaultTranche.sol";
import { AggregatorV3Interface } from "../../src/interfaces/external/chainlink/AggregatorV3Interface.sol";
import { WAD } from "../../src/libraries/Constants.sol";
import { TrancheType } from "../../src/libraries/Types.sol";
import { ASSETS_MUST_BE_NON_NEGATIVE } from "../../src/libraries/Units.sol";
import { FundamentalStablecoinChainlinkOracle } from "../../src/oracle/fundamental-oracle/FundamentalStablecoinChainlinkOracle.sol";
import { RoycoTrancheBaseAssetChainlinkOracle } from "../../src/oracle/tranche-share-to-base-asset-oracle/RoycoTrancheBaseAssetChainlinkOracle.sol";
import { RoycoTrancheChainlinkOracle } from "../../src/oracle/tranche-share-to-nav-oracle/RoycoTrancheChainlinkOracle.sol";

import { MockTranche } from "../mock/MockTranche.sol";

/**
 * @title RawReturnTranche
 * @notice A malicious/degenerate tranche double whose convertToAssets returns arbitrary raw bytes via assembly
 * @dev Two modes: exact stored bytes (any length, including non-word-multiples) for shape pinning, and a generated
 *      returndata bomb (bombWordCount zero words with a settable trailing word) so megabyte-scale returns don't
 *      require megabyte-scale storage writes
 */
contract RawReturnTranche {
    /// @notice The exact raw bytes to return from convertToAssets when no bomb is configured
    bytes public rawReturnData;

    /// @notice The number of 32-byte words in the generated returndata bomb (0 disables bomb mode)
    uint256 public bombWordCount;

    /// @notice The value of the bomb's final word (every preceding word is zero)
    uint256 public bombTrailingWord;

    /// @notice Sets the exact raw bytes returned from convertToAssets
    function setRawReturnData(bytes calldata _data) external {
        rawReturnData = _data;
    }

    /// @notice Arms bomb mode: convertToAssets will return `_wordCount` words ending in `_trailingWord`
    function setBomb(uint256 _wordCount, uint256 _trailingWord) external {
        bombWordCount = _wordCount;
        bombTrailingWord = _trailingWord;
    }

    /**
     * @notice Returns the configured raw bytes (or the generated bomb) regardless of the requested share count
     * @dev Mirrors the tranche selector consumed by periphery's low-level readers; deliberately unconstrained so
     *      tests can pin the readers' behavior on every conceivable returndata shape
     */
    function convertToAssets(uint256) external view {
        uint256 wordCount = bombWordCount;
        if (wordCount != 0) {
            uint256 size = wordCount * 32;
            uint256 trailing = bombTrailingWord;
            assembly {
                let ptr := mload(0x40)
                // Every word except the last is untouched (zero) memory; only the trailing word carries data
                mstore(add(ptr, sub(size, 0x20)), trailing)
                return(ptr, size)
            }
        }
        bytes memory data = rawReturnData;
        assembly ("memory-safe") {
            return(add(data, 0x20), mload(data))
        }
    }
}

/// @title KernelMock
/// @notice Minimal kernel double exposing the ST and JT asset getters consumed by the base asset oracle's constructor
contract KernelMock {
    address public immutable ST_ASSET;
    address public immutable JT_ASSET;

    constructor(address _stAsset, address _jtAsset) {
        ST_ASSET = _stAsset;
        JT_ASSET = _jtAsset;
    }
}

/// @title MetadataERC20
/// @notice Minimal ERC20-metadata double with constructor-configurable name, symbol, and decimals
contract MetadataERC20 {
    string public name;
    string public symbol;
    uint8 public decimals;

    constructor(string memory _name, string memory _symbol, uint8 _decimals) {
        name = _name;
        symbol = _symbol;
        decimals = _decimals;
    }
}

/**
 * @title MutableFeedMock
 * @notice Chainlink-compatible feed double with fully settable round data and MUTABLE decimals
 * @dev getRoundData echoes the requested round ID (proving the wrapper forwards it) while answeredInRound is
 *      independently configurable (proving the wrapper does not conflate the two); decimals can be changed after
 *      construction to pin the wrapper's live-forwarding of decimals against its construction-frozen ONE_QUOTE_ASSET
 */
contract MutableFeedMock is AggregatorV3Interface {
    uint8 internal feedDecimals;
    string internal feedDescription;

    uint80 internal roundId_ = 1;
    int256 internal answer_;
    uint256 internal startedAt_;
    uint256 internal updatedAt_;
    uint80 internal answeredInRound_ = 1;

    constructor(uint8 _decimals, string memory _description) {
        feedDecimals = _decimals;
        feedDescription = _description;
        startedAt_ = block.timestamp;
        updatedAt_ = block.timestamp;
    }

    /// @notice Mutates the feed's decimals after construction to model a live-upgraded underlying feed
    function setDecimals(uint8 _decimals) external {
        feedDecimals = _decimals;
    }

    /// @notice Sets the answer returned by both round-data queries
    function setAnswer(int256 _answer) external {
        answer_ = _answer;
    }

    /// @notice Sets every round-data field returned by the feed in one call
    function setRoundData(uint80 _roundId, int256 _answer, uint256 _startedAt, uint256 _updatedAt, uint80 _answeredInRound) external {
        roundId_ = _roundId;
        answer_ = _answer;
        startedAt_ = _startedAt;
        updatedAt_ = _updatedAt;
        answeredInRound_ = _answeredInRound;
    }

    function decimals() external view returns (uint8) {
        return feedDecimals;
    }

    function description() external view returns (string memory) {
        return feedDescription;
    }

    function version() external pure returns (uint256) {
        return 1;
    }

    function latestRoundData() external view returns (uint80, int256, uint256, uint256, uint80) {
        return (roundId_, answer_, startedAt_, updatedAt_, answeredInRound_);
    }

    function getRoundData(uint80 _roundId) external view returns (uint80, int256, uint256, uint256, uint80) {
        // Echo the requested round ID so callers can prove it was forwarded; keep answeredInRound independent
        return (_roundId, answer_, startedAt_, updatedAt_, answeredInRound_);
    }
}

/**
 * @title RoycoTrancheNavChainlinkOracleAdversarialTest
 * @notice Adversarial tests for RoycoTrancheChainlinkOracle against a tranche returning arbitrary raw bytes
 * @dev The oracle reads the NAV as `mload(returnData + len)`, i.e. the LAST 32 bytes of the returndata with NO
 *      length checks (the intentional mandate). For len >= 32 that read always ends exactly at the final returndata
 *      byte; for len < 32 it straddles the bytes-array length word, so the length itself leaks into the answer.
 *      These tests PIN that intentional behavior byte-for-byte
 */
contract RoycoTrancheNavChainlinkOracleAdversarialTest is Test {
    /// =====================================================================
    /// STATE
    /// =====================================================================
    RawReturnTranche internal rawTranche;
    RoycoTrancheChainlinkOracle internal oracle;

    /// =====================================================================
    /// SETUP
    /// =====================================================================

    function setUp() public {
        rawTranche = new RawReturnTranche();
        oracle = new RoycoTrancheChainlinkOracle(address(rawTranche));
    }

    /// =====================================================================
    /// int256 CAST BOUNDARY (toInt256)
    /// =====================================================================

    /// @notice A NAV of exactly int256.max is the largest value the toInt256 cast admits and must be answered losslessly
    function test_latestRoundData_navExactlyIntMax_passes() external {
        rawTranche.setRawReturnData(abi.encode(uint256(0), uint256(0), uint256(type(int256).max)));

        (, int256 answer,,,) = oracle.latestRoundData();
        assertEq(answer, type(int256).max, "A NAV of exactly int256.max must pass the toInt256 cast losslessly");
    }

    /// @notice A NAV of int256.max + 1 is the first value whose int256 cast goes negative and must revert ASSETS_MUST_BE_NON_NEGATIVE
    function test_latestRoundData_navIntMaxPlusOne_revertsNonNegative() external {
        rawTranche.setRawReturnData(abi.encode(uint256(0), uint256(0), uint256(type(int256).max) + 1));

        vm.expectRevert(ASSETS_MUST_BE_NON_NEGATIVE.selector);
        oracle.latestRoundData();
    }

    /// @notice A NAV of uint256.max (cast bit pattern -1) must also revert ASSETS_MUST_BE_NON_NEGATIVE
    function test_latestRoundData_navUintMax_revertsNonNegative() external {
        rawTranche.setRawReturnData(abi.encode(uint256(0), uint256(0), type(uint256).max));

        vm.expectRevert(ASSETS_MUST_BE_NON_NEGATIVE.selector);
        oracle.latestRoundData();
    }

    /**
     * @notice Fuzz: over the full uint256 NAV domain the oracle partitions exactly at int256.max —
     *         nav <= int256.max answers nav, nav > int256.max reverts ASSETS_MUST_BE_NON_NEGATIVE
     * @param _nav The raw NAV word placed in the last 32 bytes of a Dawn-shaped three-word return
     */
    function testFuzz_latestRoundData_fullUintNavDomainPartitionsAtIntMax(uint256 _nav) external {
        rawTranche.setRawReturnData(abi.encode(uint256(0), uint256(0), _nav));

        if (_nav > uint256(type(int256).max)) {
            vm.expectRevert(ASSETS_MUST_BE_NON_NEGATIVE.selector);
            oracle.latestRoundData();
        } else {
            (, int256 answer,,,) = oracle.latestRoundData();
            assertEq(uint256(answer), _nav, "Any NAV within the int256 range must be answered unchanged");
        }
    }

    /// =====================================================================
    /// RETURNDATA BOMBS
    /// =====================================================================

    /**
     * @notice A 10,000-word (320 KB) returndata bomb does not break the oracle: the answer is still the last word
     * @dev Pins the intentional no-length-check design — the reader copies whatever the tranche returns and reads
     *      the trailing word, so a bomb only costs gas, it cannot corrupt the answer
     */
    function test_latestRoundData_survivesTenThousandWordReturndataBomb() external {
        rawTranche.setBomb(10_000, 42e18);

        (, int256 answer,,,) = oracle.latestRoundData();
        assertEq(answer, 42e18, "The answer must be the trailing word of the returndata even for a 10,000 word bomb");
    }

    /// @notice A returndata bomb whose trailing word exceeds int256.max still hits the toInt256 guard, not a silent wrap
    function test_latestRoundData_bombWithOverflowingTrailingWord_revertsNonNegative() external {
        rawTranche.setBomb(10_000, type(uint256).max);

        vm.expectRevert(ASSETS_MUST_BE_NON_NEGATIVE.selector);
        oracle.latestRoundData();
    }

    /// =====================================================================
    /// NON-WORD-MULTIPLE RETURNDATA (length-straddled reads)
    /// =====================================================================

    /**
     * @notice A 1-byte return answers (length << 8) | byte: the read at ptr+1 covers 31 low bytes of the bytes-array
     *         length word (which is 1) followed by the single data byte
     * @dev Hand derivation: length word big-endian = 0x...0001, its bytes [1..31] are 30 zeros then 0x01, then the
     *      data byte 0xAB, so the loaded word is 0x01AB = 427
     */
    function test_latestRoundData_singleByteReturn_answersLengthStraddledWord() external {
        rawTranche.setRawReturnData(hex"ab");

        (, int256 answer,,,) = oracle.latestRoundData();
        assertEq(answer, int256(uint256(0x01ab)), "A 1-byte return must answer (length << 8) | dataByte = 0x01AB");
    }

    /**
     * @notice A 31-byte return leaks the length byte into the answer's top byte: the read at ptr+31 covers the
     *         length word's last byte (0x1F = 31) followed by all 31 data bytes
     * @dev Hand derivation: with the 31 data bytes carrying big-endian D = 7e18, the loaded word is (31 << 248) | 7e18
     */
    function test_latestRoundData_thirtyOneByteReturn_lengthByteLeaksIntoTopByte() external {
        uint256 dataValue = 7e18;
        // bytes31(bytes32(D << 8)) takes the top 31 bytes of D shifted up one byte, i.e. exactly D's 31-byte big-endian form
        rawTranche.setRawReturnData(abi.encodePacked(bytes31(bytes32(dataValue << 8))));

        uint256 expected = (uint256(31) << 248) | dataValue;
        (, int256 answer,,,) = oracle.latestRoundData();
        assertEq(uint256(answer), expected, "A 31-byte return must answer the length byte 0x1F followed by the 31 data bytes");
    }

    /// @notice A 33-byte return answers the last 32 bytes of the returndata: the leading garbage byte is discarded
    function test_latestRoundData_thirtyThreeByteReturn_readsLastThirtyTwoBytes() external {
        rawTranche.setRawReturnData(abi.encodePacked(bytes1(0xAA), uint256(5e18)));

        (, int256 answer,,,) = oracle.latestRoundData();
        assertEq(answer, 5e18, "A 33-byte return must answer its last 32 bytes, discarding the leading byte");
    }

    /// @notice A 63-byte return (one word + 31 bytes) answers its last 32 bytes, straddling the two trailing words
    function test_latestRoundData_sixtyThreeByteReturn_readsLastThirtyTwoBytes() external {
        // Data layout: [32 bytes: big-endian 0x42][31 bytes: big-endian 9e18]; the last 32 bytes are the first
        // word's final byte (0x42) followed by the 31-byte 9e18 (0x42 < 0x80 keeps the straddled word in int256 range)
        rawTranche.setRawReturnData(abi.encodePacked(uint256(0x42), bytes31(bytes32(uint256(9e18) << 8))));

        uint256 expected = (uint256(0x42) << 248) | uint256(9e18);
        (, int256 answer,,,) = oracle.latestRoundData();
        assertEq(uint256(answer), expected, "A 63-byte return must answer its last 32 bytes across the word boundary");
    }

    /**
     * @notice Fuzz: for ANY returndata of length >= 32 — word-aligned or not — the answer is exactly the last
     *         32 bytes of the returndata, independently derived here with a byte-by-byte accumulator
     * @param _seed Seed for the pseudo-random returndata content
     * @param _length The returndata length, bounded to [32, 320] covering aligned and straddled shapes
     */
    function testFuzz_latestRoundData_answerIsLastThirtyTwoBytesOfAnyReturn(bytes32 _seed, uint256 _length) external {
        _length = bound(_length, 32, 320);
        bytes memory raw = new bytes(_length);
        for (uint256 i = 0; i < _length; ++i) {
            raw[i] = bytes1(uint8(uint256(keccak256(abi.encode(_seed, i)))));
        }
        // Clear the top bit of the answer's most significant byte so the toInt256 cast stays in range
        raw[_length - 32] = bytes1(uint8(raw[_length - 32]) & 0x7F);
        rawTranche.setRawReturnData(raw);

        // Independent derivation: accumulate the last 32 bytes big-endian
        uint256 expected;
        for (uint256 i = _length - 32; i < _length; ++i) {
            expected = (expected << 8) | uint8(raw[i]);
        }

        (, int256 answer,,,) = oracle.latestRoundData();
        assertEq(uint256(answer), expected, "The answer must be exactly the last 32 bytes of the returndata for any length >= 32");
    }
}

/**
 * @title RoycoTrancheBaseAssetChainlinkOracleAdversarialTest
 * @notice Adversarial tests for RoycoTrancheBaseAssetChainlinkOracle: checked-sum overflow, the intentional
 *         unchecked int256 cast of the summed claims, raw enum decode behavior on TRANCHE_TYPE, constructor
 *         failure propagation, and metadata against weird-decimals base assets
 */
contract RoycoTrancheBaseAssetChainlinkOracleAdversarialTest is Test {
    /// =====================================================================
    /// STATE
    /// =====================================================================
    ERC20Mock internal baseAsset;
    MockTranche internal seniorTranche;
    KernelMock internal kernel;
    RoycoTrancheBaseAssetChainlinkOracle internal oracle;

    /// @dev Calldata for the oracle's share price query: convertToAssets(1e18)
    bytes internal sharePriceQuery;

    /// =====================================================================
    /// SETUP
    /// =====================================================================

    function setUp() public {
        baseAsset = new ERC20Mock();
        seniorTranche = new MockTranche(address(baseAsset), address(this), TrancheType.SENIOR);
        kernel = new KernelMock(address(baseAsset), address(baseAsset));
        seniorTranche.setKernel(address(kernel));
        oracle = new RoycoTrancheBaseAssetChainlinkOracle(address(seniorTranche));
        sharePriceQuery = abi.encodeCall(IRoycoVaultTranche.convertToAssets, (WAD));
    }

    /// =====================================================================
    /// CLAIM SUM: CHECKED-ADD OVERFLOW AND UNCHECKED int256 CAST
    /// =====================================================================

    /// @notice stAssets + jtAssets exceeding uint256.max hits the checked TRANCHE_UNIT `+` operator and panics 0x11
    function test_latestRoundData_claimSumOverflowingUint256_panicsArithmetic() external {
        vm.mockCall(address(seniorTranche), sharePriceQuery, abi.encode(type(uint256).max, uint256(1), uint256(0)));

        vm.expectRevert(stdError.arithmeticError);
        oracle.latestRoundData();
    }

    /// @notice A claim sum of exactly int256.max is the largest sum answered as a positive price
    function test_latestRoundData_claimSumExactlyIntMax_answersIntMax() external {
        vm.mockCall(address(seniorTranche), sharePriceQuery, abi.encode(uint256(type(int256).max), uint256(0), uint256(0)));

        (, int256 answer,,,) = oracle.latestRoundData();
        assertEq(answer, type(int256).max, "A claim sum of exactly int256.max must be answered as a positive price");
    }

    /**
     * @notice PINS the documented trust assumption: a claim sum of int256.max + 1 (= 2^255) passes through the
     *         unchecked cast and is answered as type(int256).min with NO revert
     * @dev The oracle intentionally omits a range check here; Chainlink consumers reject non-positive answers
     *      downstream, so the wrap surfaces as a rejected negative price rather than a wrong positive one
     */
    function test_latestRoundData_claimSumIntMaxPlusOne_answersIntMinWithoutReverting() external {
        vm.mockCall(address(seniorTranche), sharePriceQuery, abi.encode(uint256(type(int256).max), uint256(1), uint256(0)));

        (, int256 answer,,,) = oracle.latestRoundData();
        assertEq(answer, type(int256).min, "A claim sum of 2^255 must wrap to int256.min through the intentional unchecked cast");
    }

    /// @notice PINS the cast wrap at the top of the domain: a claim sum of uint256.max is answered as -1 with no revert
    function test_latestRoundData_claimSumUintMax_answersMinusOneWithoutReverting() external {
        vm.mockCall(address(seniorTranche), sharePriceQuery, abi.encode(type(uint256).max, uint256(0), uint256(0)));

        (, int256 answer,,,) = oracle.latestRoundData();
        assertEq(answer, -1, "A claim sum of uint256.max must wrap to -1 through the intentional unchecked cast");
    }

    /**
     * @notice Fuzz: for any non-overflowing claim pair the answer preserves the sum's exact bit pattern —
     *         sums <= int256.max are answered non-negative and larger sums wrap negative, never reverting
     * @param _stAssets The ST asset claim word
     * @param _jtAssets The JT asset claim word, bounded so the checked add cannot panic
     */
    function testFuzz_latestRoundData_castWrapPreservesBitPattern(uint256 _stAssets, uint256 _jtAssets) external {
        _jtAssets = bound(_jtAssets, 0, type(uint256).max - _stAssets);
        vm.mockCall(address(seniorTranche), sharePriceQuery, abi.encode(_stAssets, _jtAssets, uint256(0)));

        uint256 sum = _stAssets + _jtAssets;
        (, int256 answer,,,) = oracle.latestRoundData();

        assertEq(uint256(answer), sum, "The answer must preserve the claim sum's exact bit pattern through the cast");
        if (sum > uint256(type(int256).max)) {
            assertLt(answer, 0, "A claim sum above int256.max must surface as a negative answer, not a revert");
        } else {
            assertGe(answer, 0, "A claim sum within the int256 range must surface as a non-negative answer");
        }
    }

    /// =====================================================================
    /// CONSTRUCTOR: TRANCHE_TYPE ENUM DECODE LADDER
    /// =====================================================================

    /// @notice Raw TRANCHE_TYPE value 0 (SENIOR) deploys successfully
    function test_constructor_rawTrancheTypeZero_deploys() external {
        vm.mockCall(address(seniorTranche), abi.encodeWithSelector(IRoycoVaultTranche.TRANCHE_TYPE.selector), abi.encode(uint256(0)));

        RoycoTrancheBaseAssetChainlinkOracle deployed = new RoycoTrancheBaseAssetChainlinkOracle(address(seniorTranche));
        assertEq(deployed.BASE_ASSET(), address(baseAsset), "A SENIOR tranche type must deploy with the kernel's shared base asset");
    }

    /// @notice Raw TRANCHE_TYPE value 1 (JUNIOR) deploys successfully
    function test_constructor_rawTrancheTypeOne_deploys() external {
        vm.mockCall(address(seniorTranche), abi.encodeWithSelector(IRoycoVaultTranche.TRANCHE_TYPE.selector), abi.encode(uint256(1)));

        RoycoTrancheBaseAssetChainlinkOracle deployed = new RoycoTrancheBaseAssetChainlinkOracle(address(seniorTranche));
        assertEq(deployed.BASE_ASSET(), address(baseAsset), "A JUNIOR tranche type must deploy with the kernel's shared base asset");
    }

    /// @notice Raw TRANCHE_TYPE value 2 (LIQUIDITY) is rejected by the oracle's own guard
    function test_constructor_rawTrancheTypeTwo_revertsLiquidityNotSupported() external {
        vm.mockCall(address(seniorTranche), abi.encodeWithSelector(IRoycoVaultTranche.TRANCHE_TYPE.selector), abi.encode(uint256(2)));

        vm.expectRevert(RoycoTrancheBaseAssetChainlinkOracle.LIQUIDITY_TRANCHES_NOT_SUPPORTED.selector);
        new RoycoTrancheBaseAssetChainlinkOracle(address(seniorTranche));
    }

    /**
     * @notice Raw TRANCHE_TYPE value 3 is outside the TrancheType enum: the return-data ABI decoder rejects it
     *         with an EMPTY revert before the oracle's LIQUIDITY guard ever runs
     * @dev PINS the decoder behavior: external-call return-data validation failures revert with no data
     *      (`revert(0, 0)`), unlike an in-contract enum conversion which would panic 0x21
     */
    function test_constructor_rawTrancheTypeThree_revertsEmptyOnEnumDecode() external {
        vm.mockCall(address(seniorTranche), abi.encodeWithSelector(IRoycoVaultTranche.TRANCHE_TYPE.selector), abi.encode(uint256(3)));

        vm.expectRevert(bytes(""));
        new RoycoTrancheBaseAssetChainlinkOracle(address(seniorTranche));
    }

    /**
     * @notice Fuzz: the full raw uint8 TRANCHE_TYPE domain partitions exactly three ways —
     *         0/1 deploy, 2 reverts LIQUIDITY_TRANCHES_NOT_SUPPORTED, and >= 3 reverts empty on enum decode
     * @param _rawTrancheType The raw word returned from TRANCHE_TYPE()
     */
    function testFuzz_constructor_rawTrancheTypeDomainPartition(uint8 _rawTrancheType) external {
        vm.mockCall(address(seniorTranche), abi.encodeWithSelector(IRoycoVaultTranche.TRANCHE_TYPE.selector), abi.encode(uint256(_rawTrancheType)));

        if (_rawTrancheType <= 1) {
            RoycoTrancheBaseAssetChainlinkOracle deployed = new RoycoTrancheBaseAssetChainlinkOracle(address(seniorTranche));
            assertEq(deployed.ROYCO_TRANCHE(), address(seniorTranche), "SENIOR and JUNIOR raw values must deploy successfully");
        } else if (_rawTrancheType == 2) {
            vm.expectRevert(RoycoTrancheBaseAssetChainlinkOracle.LIQUIDITY_TRANCHES_NOT_SUPPORTED.selector);
            new RoycoTrancheBaseAssetChainlinkOracle(address(seniorTranche));
        } else {
            vm.expectRevert(bytes(""));
            new RoycoTrancheBaseAssetChainlinkOracle(address(seniorTranche));
        }
    }

    /// =====================================================================
    /// CONSTRUCTOR: KERNEL FAILURE PROPAGATION
    /// =====================================================================

    /// @notice A kernel whose ST_ASSET() reverts during construction propagates its revert reason unchanged
    function test_constructor_kernelStAssetReverts_propagatesReason() external {
        vm.mockCallRevert(address(kernel), abi.encodeWithSelector(IRoycoKernel.ST_ASSET.selector), "ST_ASSET_DOWN");

        vm.expectRevert(bytes("ST_ASSET_DOWN"));
        new RoycoTrancheBaseAssetChainlinkOracle(address(seniorTranche));
    }

    /// @notice A kernel whose JT_ASSET() reverts during construction propagates its revert reason unchanged
    function test_constructor_kernelJtAssetReverts_propagatesReason() external {
        vm.mockCallRevert(address(kernel), abi.encodeWithSelector(IRoycoKernel.JT_ASSET.selector), "JT_ASSET_DOWN");

        vm.expectRevert(bytes("JT_ASSET_DOWN"));
        new RoycoTrancheBaseAssetChainlinkOracle(address(seniorTranche));
    }

    /// @notice A kernel whose ST_ASSET() reverts with a custom error propagates the error bytes unchanged
    function test_constructor_kernelStAssetCustomError_propagatesBytes() external {
        bytes memory customError = abi.encodeWithSignature("KernelPaused(uint256)", uint256(7));
        vm.mockCallRevert(address(kernel), abi.encodeWithSelector(IRoycoKernel.ST_ASSET.selector), customError);

        vm.expectRevert(customError);
        new RoycoTrancheBaseAssetChainlinkOracle(address(seniorTranche));
    }

    /// =====================================================================
    /// METADATA AGAINST WEIRD-DECIMALS BASE ASSETS
    /// =====================================================================

    /// @dev Deploys a tranche + kernel + oracle stack over the specified base asset
    function _deployOracleFor(address _baseAsset) internal returns (RoycoTrancheBaseAssetChainlinkOracle) {
        MockTranche tranche = new MockTranche(_baseAsset, address(this), TrancheType.SENIOR);
        KernelMock sharedKernel = new KernelMock(_baseAsset, _baseAsset);
        tranche.setKernel(address(sharedKernel));
        return new RoycoTrancheBaseAssetChainlinkOracle(address(tranche));
    }

    /// @notice The oracle mirrors a 6-decimal base asset's decimals (USDC-style markets)
    function test_decimals_sixDecimalBaseAsset_mirrorsSix() external {
        MetadataERC20 usdc = new MetadataERC20("USD Coin", "USDC", 6);
        RoycoTrancheBaseAssetChainlinkOracle sixDecOracle = _deployOracleFor(address(usdc));

        assertEq(sixDecOracle.decimals(), 6, "The oracle must mirror a 6-decimal base asset's decimals");
    }

    /// @notice The oracle mirrors a 0-decimal base asset's decimals: integer-only quoting is passed through, not rejected
    function test_decimals_zeroDecimalBaseAsset_mirrorsZero() external {
        MetadataERC20 integerToken = new MetadataERC20("Integer Token", "INT0", 0);
        RoycoTrancheBaseAssetChainlinkOracle zeroDecOracle = _deployOracleFor(address(integerToken));

        assertEq(zeroDecOracle.decimals(), 0, "The oracle must mirror a 0-decimal base asset's decimals unchanged");
    }

    /// @notice The description composes the tranche name and a 6-decimal base asset's symbol
    function test_description_sixDecimalBaseAsset_composesSymbol() external {
        MetadataERC20 usdc = new MetadataERC20("USD Coin", "USDC", 6);
        RoycoTrancheBaseAssetChainlinkOracle sixDecOracle = _deployOracleFor(address(usdc));

        assertEq(
            sixDecOracle.description(),
            "Returns the price of 1 share of Mock Senior Tranche in its base asset (USDC)",
            "The description must compose the tranche name and the base asset symbol"
        );
    }

    /// @notice The description composes correctly for a 0-decimal base asset: decimals play no role in the description
    function test_description_zeroDecimalBaseAsset_composesSymbol() external {
        MetadataERC20 integerToken = new MetadataERC20("Integer Token", "INT0", 0);
        RoycoTrancheBaseAssetChainlinkOracle zeroDecOracle = _deployOracleFor(address(integerToken));

        assertEq(
            zeroDecOracle.description(),
            "Returns the price of 1 share of Mock Senior Tranche in its base asset (INT0)",
            "The description must compose the base asset symbol regardless of its decimals"
        );
    }
}

/**
 * @title FundamentalStablecoinChainlinkOracleAdversarialTest
 * @notice Adversarial tests for FundamentalStablecoinChainlinkOracle: full-domain peg partition on an 18-decimal
 *         feed, constructor bounds fuzz, byte-exact round-data passthrough over fuzzed round IDs, staleness field
 *         passthrough, live-decimals mirroring against the construction-frozen ONE_QUOTE_ASSET, and description
 *         composition under weird and diverged decimals
 */
contract FundamentalStablecoinChainlinkOracleAdversarialTest is Test {
    /// =====================================================================
    /// STATE
    /// =====================================================================
    MutableFeedMock internal feed18;
    FundamentalStablecoinChainlinkOracle internal wrapper18;

    /// @dev 1.00 in 18-decimal precision
    int256 internal constant ONE_18 = 1e18;
    /// @dev 0.999 in 18-decimal precision
    int256 internal constant MIN_PEG_18 = 0.999e18;

    /// =====================================================================
    /// SETUP
    /// =====================================================================

    function setUp() public {
        feed18 = new MutableFeedMock(18, "DAI / USD");
        wrapper18 = new FundamentalStablecoinChainlinkOracle(address(feed18), MIN_PEG_18);
    }

    /// =====================================================================
    /// PEG-ANCHOR PARTITION OVER THE FULL int256 DOMAIN
    /// =====================================================================

    /**
     * @notice Fuzz: over the full int256 answer domain the 18-decimal wrapper partitions exactly at MIN_PRICE_AT_PEG —
     *         answers >= 0.999e18 anchor to 1e18, everything below (including zero and negatives) passes through
     * @param _answer The raw underlying feed answer, unconstrained over int256
     */
    function testFuzz_latestRoundData_pegAnchorPartitionFullIntDomain(int256 _answer) external {
        feed18.setAnswer(_answer);

        (, int256 wrappedAnswer,,,) = wrapper18.latestRoundData();
        if (_answer >= MIN_PEG_18) {
            assertEq(wrappedAnswer, ONE_18, "Any answer at or above the minimum peg price must anchor to exactly 1 quote asset");
        } else {
            assertEq(wrappedAnswer, _answer, "Any answer below the minimum peg price must pass through unchanged");
        }
    }

    /// @notice The int256 extremes land on the correct sides of the partition: int256.max anchors, int256.min passes through
    function test_latestRoundData_intExtremesPartitionCorrectly() external {
        feed18.setAnswer(type(int256).max);
        (, int256 answerAtMax,,,) = wrapper18.latestRoundData();
        assertEq(answerAtMax, ONE_18, "An answer of int256.max must anchor to 1 quote asset");

        feed18.setAnswer(type(int256).min);
        (, int256 answerAtMin,,,) = wrapper18.latestRoundData();
        assertEq(answerAtMin, type(int256).min, "An answer of int256.min must pass through unchanged");
    }

    /// @notice The threshold boundary pair on the 18-decimal feed: MIN_PEG anchors, MIN_PEG - 1 wei passes through
    function test_latestRoundData_thresholdBoundaryPair18Dec() external {
        feed18.setAnswer(MIN_PEG_18);
        (, int256 answerAtPeg,,,) = wrapper18.latestRoundData();
        assertEq(answerAtPeg, ONE_18, "An answer of exactly the minimum peg price must anchor to 1 quote asset");

        feed18.setAnswer(MIN_PEG_18 - 1);
        (, int256 answerBelowPeg,,,) = wrapper18.latestRoundData();
        assertEq(answerBelowPeg, MIN_PEG_18 - 1, "An answer one wei below the minimum peg price must pass through unchanged");
    }

    /// =====================================================================
    /// CONSTRUCTOR BOUNDS (18-DECIMAL FEED)
    /// =====================================================================

    /// @notice Fuzz: any minimum peg price outside (0, 1e18) is rejected with INVALID_MIN_PRICE_AT_PEG on an 18-decimal feed
    function testFuzz_constructor_rejectsOutOfRangeMinPeg18Dec(int256 _minPriceAtPeg) external {
        vm.assume(_minPriceAtPeg <= 0 || _minPriceAtPeg >= ONE_18);

        vm.expectRevert(FundamentalStablecoinChainlinkOracle.INVALID_MIN_PRICE_AT_PEG.selector);
        new FundamentalStablecoinChainlinkOracle(address(feed18), _minPriceAtPeg);
    }

    /// @notice Fuzz: any minimum peg price inside (0, 1e18) is accepted and stored unchanged on an 18-decimal feed
    function testFuzz_constructor_acceptsInRangeMinPeg18Dec(int256 _minPriceAtPeg) external {
        _minPriceAtPeg = bound(_minPriceAtPeg, 1, ONE_18 - 1);

        FundamentalStablecoinChainlinkOracle wrapper = new FundamentalStablecoinChainlinkOracle(address(feed18), _minPriceAtPeg);
        assertEq(wrapper.MIN_PRICE_AT_PEG(), _minPriceAtPeg, "Any in-range minimum peg price must be stored unchanged");
        assertEq(wrapper.ONE_QUOTE_ASSET(), ONE_18, "ONE_QUOTE_ASSET must be derived from the feed's 18 decimals");
    }

    /**
     * @notice PINS the 0-decimal impossibility: ONE_QUOTE_ASSET = 1 makes the valid range (0, 1) empty, so NO
     *         minimum peg price can construct a wrapper over a 0-decimal feed
     * @dev Both nearest candidates are probed: 0 fails the lower strict bound and 1 fails the upper strict bound
     */
    function test_constructor_zeroDecimalFeedIsUnconstructible() external {
        MutableFeedMock feed0 = new MutableFeedMock(0, "INT / USD");

        vm.expectRevert(FundamentalStablecoinChainlinkOracle.INVALID_MIN_PRICE_AT_PEG.selector);
        new FundamentalStablecoinChainlinkOracle(address(feed0), 0);

        vm.expectRevert(FundamentalStablecoinChainlinkOracle.INVALID_MIN_PRICE_AT_PEG.selector);
        new FundamentalStablecoinChainlinkOracle(address(feed0), 1);
    }

    /// =====================================================================
    /// ROUND-DATA PASSTHROUGH EXACTNESS
    /// =====================================================================

    /**
     * @notice Fuzz: getRoundData(anyRoundId) returns the underlying feed's tuple field-for-field, with the answer
     *         as the ONLY field the wrapper may rewrite (and only per the peg-anchor rule)
     * @dev The mock echoes the requested round ID into its returned roundId, so the roundId equality also proves
     *      the wrapper forwarded the requested ID to the underlying feed unmodified
     * @param _requestedRoundId The round ID requested from the wrapper
     * @param _answer The underlying feed answer, unconstrained over int256
     * @param _startedAt The underlying round's startedAt timestamp, unconstrained over uint256
     * @param _updatedAt The underlying round's updatedAt timestamp, unconstrained over uint256
     * @param _answeredInRound The underlying round's answeredInRound, configured independently of the requested ID
     */
    function testFuzz_getRoundData_fullTuplePassthroughExactness(
        uint80 _requestedRoundId,
        int256 _answer,
        uint256 _startedAt,
        uint256 _updatedAt,
        uint80 _answeredInRound
    )
        external
    {
        feed18.setRoundData(1, _answer, _startedAt, _updatedAt, _answeredInRound);

        (uint80 underlyingRoundId, int256 underlyingAnswer, uint256 underlyingStartedAt, uint256 underlyingUpdatedAt, uint80 underlyingAnsweredInRound) =
            feed18.getRoundData(_requestedRoundId);
        (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound) = wrapper18.getRoundData(_requestedRoundId);

        assertEq(roundId, underlyingRoundId, "The wrapper must pass the underlying round ID through unchanged");
        assertEq(roundId, _requestedRoundId, "The wrapper must forward the requested round ID to the underlying feed");
        assertEq(startedAt, underlyingStartedAt, "The wrapper must pass startedAt through unchanged");
        assertEq(updatedAt, underlyingUpdatedAt, "The wrapper must pass updatedAt through unchanged");
        assertEq(answeredInRound, underlyingAnsweredInRound, "The wrapper must pass answeredInRound through unchanged");
        if (_answer >= MIN_PEG_18) {
            assertEq(answer, ONE_18, "An answer at or above the minimum peg price must anchor to 1 quote asset");
            assertEq(underlyingAnswer, _answer, "The underlying answer itself must be untouched by the wrapper");
        } else {
            assertEq(answer, underlyingAnswer, "An answer below the minimum peg price must pass through unchanged");
        }
    }

    /**
     * @notice Fuzz: latestRoundData passes every non-answer field through unchanged, including staleness-relevant
     *         extremes — startedAt/updatedAt of 0 (never updated) and uint256.max survive untouched on both the
     *         anchored and pass-through answer paths
     * @param _roundId The underlying round ID
     * @param _answer The underlying feed answer, unconstrained over int256
     * @param _startedAt The underlying round's startedAt timestamp, unconstrained over uint256
     * @param _updatedAt The underlying round's updatedAt timestamp, unconstrained over uint256
     * @param _answeredInRound The underlying round's answeredInRound
     */
    function testFuzz_latestRoundData_stalenessFieldsPassThroughUnchanged(
        uint80 _roundId,
        int256 _answer,
        uint256 _startedAt,
        uint256 _updatedAt,
        uint80 _answeredInRound
    )
        external
    {
        feed18.setRoundData(_roundId, _answer, _startedAt, _updatedAt, _answeredInRound);

        (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound) = wrapper18.latestRoundData();

        assertEq(roundId, _roundId, "The wrapper must pass the underlying round ID through unchanged");
        assertEq(startedAt, _startedAt, "The wrapper must pass startedAt through unchanged for staleness checks downstream");
        assertEq(updatedAt, _updatedAt, "The wrapper must pass updatedAt through unchanged for staleness checks downstream");
        assertEq(answeredInRound, _answeredInRound, "The wrapper must pass answeredInRound through unchanged");
        assertEq(answer, _answer >= MIN_PEG_18 ? ONE_18 : _answer, "The answer must follow the peg-anchor partition exactly");
    }

    /// @notice Zero timestamps (a never-updated feed) pass through unchanged: the wrapper adds no staleness opinion of its own
    function test_latestRoundData_zeroTimestampsPassThrough() external {
        feed18.setRoundData(5, MIN_PEG_18, 0, 0, 5);

        (, int256 answer, uint256 startedAt, uint256 updatedAt,) = wrapper18.latestRoundData();
        assertEq(startedAt, 0, "A zero startedAt must pass through so downstream staleness checks can reject it");
        assertEq(updatedAt, 0, "A zero updatedAt must pass through so downstream staleness checks can reject it");
        assertEq(answer, ONE_18, "The anchored answer path must not disturb timestamp passthrough");
    }

    /// =====================================================================
    /// LIVE DECIMALS MIRRORING vs CONSTRUCTION-FROZEN ONE_QUOTE_ASSET
    /// =====================================================================

    /**
     * @notice Fuzz: decimals() mirrors the underlying feed LIVE across the whole 0..77 range while ONE_QUOTE_ASSET
     *         and MIN_PRICE_AT_PEG stay frozen at their construction-time snapshot
     * @dev PINS the intentional divergence: a feed that migrates its decimals after wrapper deployment changes the
     *      wrapper's reported decimals but NOT its anchoring arithmetic
     * @param _liveDecimals The feed's post-construction decimals, bounded to the 0..77 domain
     */
    function testFuzz_decimals_mirrorsLiveFeedWhileOneQuoteAssetStaysFrozen(uint8 _liveDecimals) external {
        _liveDecimals = uint8(bound(_liveDecimals, 0, 77));
        feed18.setDecimals(_liveDecimals);

        assertEq(wrapper18.decimals(), _liveDecimals, "decimals() must mirror the underlying feed's live value at every call");
        assertEq(wrapper18.ONE_QUOTE_ASSET(), ONE_18, "ONE_QUOTE_ASSET must stay frozen at its construction-time snapshot");
        assertEq(wrapper18.MIN_PRICE_AT_PEG(), MIN_PEG_18, "MIN_PRICE_AT_PEG must stay frozen at its construction-time snapshot");
    }

    /// =====================================================================
    /// DESCRIPTION COMPOSITION UNDER WEIRD DECIMALS
    /// =====================================================================

    /// @notice A 1-decimal underlying renders its threshold with a single fractional digit
    function test_description_oneDecimalFeedRendersSingleFractionalDigit() external {
        MutableFeedMock feed1 = new MutableFeedMock(1, "TKN / USD");
        FundamentalStablecoinChainlinkOracle wrapper1 = new FundamentalStablecoinChainlinkOracle(address(feed1), 5);

        assertEq(
            wrapper1.description(),
            "TKN / USD (Royco fundamental stablecoin peg wrapper: prices at or above 0.5 are reported as 1 quote asset)",
            "A 1-decimal feed must render the threshold as a single fractional digit"
        );
    }

    /// @notice A 2-decimal underlying renders its highest valid threshold as 0.99
    function test_description_twoDecimalFeedRendersTwoFractionalDigits() external {
        MutableFeedMock feed2 = new MutableFeedMock(2, "CENT / USD");
        FundamentalStablecoinChainlinkOracle wrapper2 = new FundamentalStablecoinChainlinkOracle(address(feed2), 99);

        assertEq(
            wrapper2.description(),
            "CENT / USD (Royco fundamental stablecoin peg wrapper: prices at or above 0.99 are reported as 1 quote asset)",
            "A 2-decimal feed must render the threshold with two fractional digits"
        );
    }

    /**
     * @notice PINS the live-decimals divergence in description(): the frozen MIN_PRICE_AT_PEG (0.999e18) is rendered
     *         with the feed's LIVE decimals, so after the feed migrates to 2 decimals the threshold renders as
     *         999000000000000000 / 10^2 = "9990000000000000.00"
     */
    function test_description_liveDecimalsShrink_rendersFrozenThresholdAtLivePrecision() external {
        feed18.setDecimals(2);

        assertEq(
            wrapper18.description(),
            "DAI / USD (Royco fundamental stablecoin peg wrapper: prices at or above 9990000000000000.00 are reported as 1 quote asset)",
            "The frozen threshold must be rendered at the feed's live 2-decimal precision"
        );
    }

    /**
     * @notice PINS the 0-live-decimals rendering: with no fractional digits the formatter emits the integer part
     *         followed by a bare trailing decimal point — "999000000000000000."
     * @dev The trailing dot is an intentional consequence of the fixed-width fractional rendering, not a bug to fix here
     */
    function test_description_zeroLiveDecimals_rendersTrailingDecimalPoint() external {
        feed18.setDecimals(0);

        assertEq(
            wrapper18.description(),
            "DAI / USD (Royco fundamental stablecoin peg wrapper: prices at or above 999000000000000000. are reported as 1 quote asset)",
            "A 0-decimal live feed must render the frozen threshold as its integer digits with a bare trailing decimal point"
        );
    }
}
