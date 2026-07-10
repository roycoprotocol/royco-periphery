// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import { Test } from "../../lib/forge-std/src/Test.sol";

import { ERC20Mock } from "../../lib/openzeppelin-contracts/contracts/mocks/token/ERC20Mock.sol";

import { IRoycoVaultTranche } from "../../src/interfaces/IRoycoVaultTranche.sol";
import { PeripheryUtilsLib } from "../../src/libraries/PeripheryUtilsLib.sol";
import { TrancheType } from "../../src/libraries/Types.sol";
import { NAV_UNIT, toUint256 } from "../../src/libraries/Units.sol";

import { MockTranche } from "../mock/MockTranche.sol";

/// @title PeripheryUtilsLibHarness
/// @notice Thin external wrapper around the internal library function so vm.expectRevert, vm.expectCall,
///         and low-level revert-data capture all work against a real cross-contract call frame
contract PeripheryUtilsLibHarness {
    function convertToNAV(address _tranche, uint256 _shares) external view returns (NAV_UNIT nav) {
        nav = PeripheryUtilsLib.convertToNAV(_tranche, _shares);
    }
}

/**
 * @title RawReturnTranche
 * @notice A malicious/degenerate tranche double that answers ANY call with a configurable raw byte string,
 *         either as successful returndata or as revert data, without any ABI encoding or padding
 * @dev This is the only way to produce sub-word and non-word-aligned returndata lengths, which the shared
 *      MockTranche (always >= 3 words) cannot express
 */
contract RawReturnTranche {
    bytes internal payload;
    bool internal shouldRevert;

    /// @notice Arms the fallback to return `_data` verbatim as successful returndata
    function setReturnPayload(bytes calldata _data) external {
        payload = _data;
        shouldRevert = false;
    }

    /// @notice Arms the fallback to revert with `_data` verbatim as revert data
    function setRevertPayload(bytes calldata _data) external {
        payload = _data;
        shouldRevert = true;
    }

    /// @dev Returns/reverts the armed payload byte-for-byte via assembly so no ABI padding is ever appended
    fallback() external {
        bytes memory data = payload;
        bool doRevert = shouldRevert;
        assembly ("memory-safe") {
            switch doRevert
            case 1 { revert(add(data, 0x20), mload(data)) }
            default { return(add(data, 0x20), mload(data)) }
        }
    }
}

/**
 * @title CalldataEchoTranche
 * @notice A tranche double that echoes the exact calldata it received back as raw returndata, optionally
 *         with the calldata length appended as a trailing word
 * @dev Lets tests prove the library's request encoding purely from the nav it reads back: for the 36-byte
 *      call [selector][shares], the last 32 bytes of the echo are the shares argument, and in append-length
 *      mode the trailing word is the exact calldata size
 */
contract CalldataEchoTranche {
    bool internal appendCalldataLength;

    /// @notice Toggles appending `msg.data.length` as a trailing word to the echoed calldata
    function setAppendCalldataLength(bool _append) external {
        appendCalldataLength = _append;
    }

    /// @dev A fallback declared with parameters returns its bytes unmodified (no ABI encoding, no padding)
    fallback(bytes calldata _input) external returns (bytes memory output) {
        output = appendCalldataLength ? abi.encodePacked(_input, _input.length) : bytes(_input);
    }
}

/**
 * @title PeripheryUtilsLibTest
 * @notice Direct, exhaustive unit tests for PeripheryUtilsLib.convertToNAV — the load-bearing raw-returndata
 *         reader behind every periphery oracle and the Pendle SY exchange rate
 * @dev The library executes `nav := mload(add(returnData, mload(returnData)))` over the Solidity-copied
 *      `bytes memory returnData` (length word at ptr, data at ptr+32). Hand derivation of every regime,
 *      pinned by the tests below:
 *      - len == 0: loads the length word itself -> nav = 0 (the intentional no-length-check design);
 *      - 0 < len < 32: loads [ptr+len, ptr+len+32) = the low (32-len) bytes of the length word followed by
 *        ALL len data bytes -> nav = (len << (8*len)) | uint(data); the read ends exactly at the end of the
 *        copied data, so no uninitialized padding is ever read;
 *      - len >= 32: loads data bytes [len-32, len) -> nav = exactly the LAST 32 bytes of the raw returndata,
 *        independent of word alignment; again no padding is read.
 *      On failure the library reverts with revert(add(returnData, 0x20), mload(returnData)), i.e. the callee's
 *      revert data bubbles byte-for-byte.
 */
contract PeripheryUtilsLibTest is Test {
    /// =====================================================================
    /// STATE
    /// =====================================================================

    PeripheryUtilsLibHarness internal harness;
    RawReturnTranche internal rawTranche;
    CalldataEchoTranche internal echoTranche;

    /// @dev Custom error used to test byte-exact bubbling of custom errors with arguments
    error TrancheFailure(uint256 code, address who);

    /// @dev Panic(uint256) selector, per the Solidity ABI error spec
    bytes4 internal constant PANIC_SELECTOR = bytes4(0x4e487b71);

    /// =====================================================================
    /// SETUP
    /// =====================================================================

    function setUp() public {
        harness = new PeripheryUtilsLibHarness();
        rawTranche = new RawReturnTranche();
        echoTranche = new CalldataEchoTranche();
    }

    /// =====================================================================
    /// HELPERS
    /// =====================================================================

    /// @dev Calls convertToNAV through the harness and unwraps the NAV_UNIT for assertion
    function _nav(address _tranche, uint256 _shares) internal view returns (uint256) {
        return toUint256(harness.convertToNAV(_tranche, _shares));
    }

    /// @dev Deterministic pseudo-random byte string (one keccak per 32-byte chunk) for fuzz payloads
    function _pseudoRandomBytes(uint256 _seed, uint256 _len) internal pure returns (bytes memory data) {
        data = new bytes(_len);
        bytes32 word;
        for (uint256 i = 0; i < _len; i++) {
            if (i % 32 == 0) word = keccak256(abi.encode(_seed, i));
            data[i] = word[i % 32];
        }
    }

    /// @dev Independently derives the last 32 bytes of `_data` (length >= 32) as a uint256 via a plain byte loop
    function _lastWordOf(bytes memory _data) internal pure returns (uint256 expected) {
        for (uint256 i = _data.length - 32; i < _data.length; i++) {
            expected = (expected << 8) | uint8(_data[i]);
        }
    }

    /// =====================================================================
    /// SUCCESS PATH: WORD-ALIGNED SHAPES (LAST-WORD MANDATE)
    /// =====================================================================

    /// @notice Empty returndata yields a NAV of zero: the intentional no-length-check design reads the
    ///         (zero) length word of the empty bytes array
    function test_convertToNAV_emptyReturndataYieldsZero() external {
        rawTranche.setReturnPayload("");
        assertEq(_nav(address(rawTranche), 1e18), 0, "An empty successful return must yield a NAV of exactly zero");
    }

    /// @notice A code-less tranche address succeeds with empty returndata and therefore yields zero
    /// @dev Pins the intentional absence of an extcodesize/provenance check in the library
    function test_convertToNAV_codelessTrancheYieldsZero() external {
        assertEq(_nav(makeAddr("NoCodeTranche"), 1e18), 0, "A staticcall to a code-less address must succeed and yield a NAV of exactly zero");
    }

    /// @notice A single-word return (a plain ERC4626-style `uint256 assets`) yields that word as the NAV
    function test_convertToNAV_oneWordReturnYieldsThatWord() external {
        rawTranche.setReturnPayload(abi.encode(uint256(7.5e18)));
        assertEq(_nav(address(rawTranche), 1e18), 7.5e18, "A one-word return must yield that word as the NAV");
    }

    /// @notice A two-word return yields the second (last) word as the NAV
    function test_convertToNAV_twoWordReturnYieldsSecondWord() external {
        rawTranche.setReturnPayload(abi.encode(uint256(3e18), uint256(9e18)));
        assertEq(_nav(address(rawTranche), 1e18), 9e18, "A two-word return must yield the second word as the NAV");
    }

    /// @notice A three-word Royco Dawn shaped return ([stAssets][jtAssets][nav]) yields the trailing word
    function test_convertToNAV_threeWordDawnShapeYieldsTrailingWord() external {
        rawTranche.setReturnPayload(abi.encode(uint256(5e18), uint256(0), uint256(5e18 + 1)));
        assertEq(_nav(address(rawTranche), 1e18), 5e18 + 1, "A Dawn-shaped three-word return must yield the trailing NAV word");
    }

    /// @notice A five-word Royco Day shaped return ([stAssets][jtAssets][w][w][nav]) yields the trailing word
    function test_convertToNAV_fiveWordDayShapeYieldsTrailingWord() external {
        rawTranche.setReturnPayload(abi.encode(uint256(1), uint256(2), type(uint256).max, uint256(0), uint256(42e18)));
        assertEq(_nav(address(rawTranche), 1e18), 42e18, "A Day-shaped five-word return must yield the trailing NAV word");
    }

    /// @notice A seventeen-word return (a hypothetical future protocol shape) yields the trailing word
    function test_convertToNAV_seventeenWordReturnYieldsTrailingWord() external {
        bytes memory payload;
        for (uint256 i = 0; i < 16; i++) {
            payload = abi.encodePacked(payload, uint256(keccak256(abi.encode("garbage", i))));
        }
        payload = abi.encodePacked(payload, uint256(1337e18));
        rawTranche.setReturnPayload(payload);
        assertEq(_nav(address(rawTranche), 1e18), 1337e18, "A seventeen-word return must yield the trailing NAV word regardless of the middle words");
    }

    /// @notice Integration parity with the shared MockTranche: Dawn (0 middle words) and Day (2 middle words)
    ///         shapes both resolve to the tranche's NAV through the library
    function test_convertToNAV_mockTrancheDawnAndDayShapesMatchSharePrice() external {
        ERC20Mock asset = new ERC20Mock();
        MockTranche tranche = new MockTranche(address(asset), address(0xF), TrancheType.SENIOR);
        tranche.setSharePrice(3e18);

        // Dawn shape: [stAssets][jtAssets][nav]
        assertEq(_nav(address(tranche), 1e18), 3e18, "The Dawn-shaped MockTranche return must yield the share price as the NAV for one WAD of shares");

        // Day shape: [stAssets][jtAssets][w][w][nav]
        tranche.setConvertToAssetsMiddleWords(2);
        assertEq(_nav(address(tranche), 1e18), 3e18, "The Day-shaped MockTranche return must yield the share price as the NAV for one WAD of shares");
    }

    /// @notice A 100KB (3,200-word) success-path returndata bomb completes and still yields the last word
    /// @dev Pins that the reader is O(1) over the copied buffer: it never scans, decodes, or length-checks
    function test_convertToNAV_returndataBombStillReadsLastWord() external {
        bytes memory payload = new bytes(100 * 1024);
        // Make the leading word nonzero so a buggy first-word read could not accidentally pass
        payload[31] = 0xFF;
        // Plant the sentinel NAV in the trailing 32 bytes
        bytes32 sentinel = bytes32(uint256(777e18));
        for (uint256 i = 0; i < 32; i++) {
            payload[payload.length - 32 + i] = sentinel[i];
        }
        rawTranche.setReturnPayload(payload);
        assertEq(_nav(address(rawTranche), 1e18), 777e18, "A 100KB returndata bomb must still yield the trailing NAV word");
    }

    /// =====================================================================
    /// SUCCESS PATH: SUB-WORD RETURNDATA (LENGTH-WORD BLEED)
    /// =====================================================================

    /**
     * @notice A 1-byte return of 0xAB yields (1 << 8) | 0xAB = 0x1AB = 427
     * @dev For 0 < len < 32 the load spans the low (32-len) bytes of the length word plus all len data bytes,
     *      so the length value bleeds into the high bits: nav = (len << (8*len)) | uint(data)
     */
    function test_convertToNAV_oneByteReturnBleedsLengthWord() external {
        rawTranche.setReturnPayload(hex"ab");
        assertEq(_nav(address(rawTranche), 1e18), 0x1ab, "A 1-byte return of 0xAB must yield (1 << 8) | 0xAB = 427");
    }

    /// @notice A 16-byte return of uint128(0xDEADBEEF) yields (16 << 128) | 0xDEADBEEF
    function test_convertToNAV_sixteenByteReturnBleedsLengthWord() external {
        rawTranche.setReturnPayload(abi.encodePacked(uint128(0xDEADBEEF)));
        assertEq(_nav(address(rawTranche), 1e18), (uint256(16) << 128) | 0xDEADBEEF, "A 16-byte return must yield (16 << 128) | data");
    }

    /// @notice A 31-byte return of uint248(0xC0FFEE) yields (31 << 248) | 0xC0FFEE
    function test_convertToNAV_thirtyOneByteReturnBleedsLengthWord() external {
        rawTranche.setReturnPayload(abi.encodePacked(uint248(0xC0FFEE)));
        assertEq(_nav(address(rawTranche), 1e18), (uint256(31) << 248) | 0xC0FFEE, "A 31-byte return must yield (31 << 248) | data");
    }

    /// =====================================================================
    /// SUCCESS PATH: NON-WORD-ALIGNED RETURNDATA >= 32 BYTES
    /// =====================================================================

    /**
     * @notice A 33-byte return yields exactly its last 32 bytes: the leading extra byte is dropped
     * @dev For len >= 32 the load covers data bytes [len-32, len) — the read is anchored to the END of the
     *      raw returndata, not to any word boundary, and never touches the zero padding of the bytes array
     */
    function test_convertToNAV_thirtyThreeByteReturnDropsLeadingByte() external {
        rawTranche.setReturnPayload(abi.encodePacked(bytes1(0xAA), uint256(12_345)));
        assertEq(_nav(address(rawTranche), 1e18), 12_345, "A 33-byte return must yield its last 32 bytes, dropping the leading byte");
    }

    /// @notice A 33-byte return whose first word is all 0xFF yields (0xFF..FF << 8) | trailing byte,
    ///         proving the captured window straddles the word boundary
    function test_convertToNAV_thirtyThreeByteReturnStraddlesLeadingWord() external {
        rawTranche.setReturnPayload(abi.encodePacked(type(uint256).max, bytes1(0xCC)));
        assertEq(
            _nav(address(rawTranche), 1e18),
            (type(uint256).max << 8) | 0xCC,
            "A 33-byte return must yield the last 31 bytes of the first word followed by the trailing byte"
        );
    }

    /// @notice A 65-byte return [0x1111][0x2222][0xEE] yields (0x2222 << 8) | 0xEE: the first word is fully
    ///         ignored and the second word is shifted left one byte by the unaligned tail
    function test_convertToNAV_sixtyFiveByteReturnStraddlesWords() external {
        rawTranche.setReturnPayload(abi.encodePacked(uint256(0x1111), uint256(0x2222), bytes1(0xEE)));
        assertEq(_nav(address(rawTranche), 1e18), 0x2222EE, "A 65-byte return must yield the last 32 bytes straddling the second word and the tail byte");
    }

    /// @notice A 95-byte return (31 + 32 + 32 bytes) yields the final packed word intact because the read is
    ///         anchored to the end of the returndata, not to 32-byte offsets from the start
    function test_convertToNAV_ninetyFiveByteReturnReadsLastThirtyTwoBytes() external {
        rawTranche.setReturnPayload(abi.encodePacked(uint248(0xAAAA), uint256(0xBBBB), uint256(0xCCCC)));
        assertEq(_nav(address(rawTranche), 1e18), 0xCCCC, "A 95-byte return must yield its final 32 bytes exactly, unaffected by the misaligned prefix");
    }

    /// =====================================================================
    /// REQUEST ENCODING: SELECTOR + SHARES ARGUMENT
    /// =====================================================================

    /**
     * @notice The library calls the tranche with exactly abi.encodeCall(convertToAssets, (_shares))
     * @dev Two independent proofs: vm.expectCall pins the 36-byte [selector][shares] prefix, and the echoing
     *      tranche pins the argument position — the last 32 bytes of the echoed calldata are the shares value
     */
    function test_convertToNAV_encodesSelectorAndSharesArgument() external {
        uint256 shares = 123_456_789e18;
        vm.expectCall(address(echoTranche), abi.encodeCall(IRoycoVaultTranche.convertToAssets, (shares)));
        assertEq(_nav(address(echoTranche), shares), shares, "The last 32 bytes of the echoed calldata must be the shares argument");
    }

    /// @notice The request calldata is exactly 36 bytes (4-byte selector + one 32-byte argument, nothing else)
    /// @dev The echo tranche appends msg.data.length as the trailing word, which the library then reads as nav
    function test_convertToNAV_requestCalldataIsExactlyThirtySixBytes() external {
        echoTranche.setAppendCalldataLength(true);
        assertEq(_nav(address(echoTranche), 42), 36, "The request calldata must be exactly 36 bytes: a 4-byte selector plus one 32-byte argument");
    }

    /// @notice A shares argument of zero is forwarded unmodified
    function test_convertToNAV_sharesZeroPassThrough() external {
        vm.expectCall(address(echoTranche), abi.encodeCall(IRoycoVaultTranche.convertToAssets, (uint256(0))));
        assertEq(_nav(address(echoTranche), 0), 0, "A shares argument of zero must be forwarded unmodified");
    }

    /// @notice A shares argument of one is forwarded unmodified
    function test_convertToNAV_sharesOnePassThrough() external {
        vm.expectCall(address(echoTranche), abi.encodeCall(IRoycoVaultTranche.convertToAssets, (uint256(1))));
        assertEq(_nav(address(echoTranche), 1), 1, "A shares argument of one must be forwarded unmodified");
    }

    /// @notice A shares argument of type(uint256).max is forwarded unmodified (no scaling, no bounds check)
    function test_convertToNAV_sharesMaxPassThrough() external {
        vm.expectCall(address(echoTranche), abi.encodeCall(IRoycoVaultTranche.convertToAssets, (type(uint256).max)));
        assertEq(_nav(address(echoTranche), type(uint256).max), type(uint256).max, "A shares argument of uint256 max must be forwarded unmodified");
    }

    /// =====================================================================
    /// REVERT BUBBLING: BYTE-EXACT PROPAGATION
    /// =====================================================================

    /// @notice An empty revert from the tranche bubbles up as an empty revert
    function test_convertToNAV_bubblesEmptyRevert() external {
        rawTranche.setRevertPayload("");
        vm.expectRevert(bytes(""));
        harness.convertToNAV(address(rawTranche), 1e18);
    }

    /// @notice A standard Error(string) revert bubbles up byte-for-byte
    function test_convertToNAV_bubblesErrorString() external {
        bytes memory revertData = abi.encodeWithSignature("Error(string)", "kernel paused");
        rawTranche.setRevertPayload(revertData);
        vm.expectRevert(revertData);
        harness.convertToNAV(address(rawTranche), 1e18);
    }

    /// @notice A custom error with arguments bubbles up byte-for-byte, arguments included
    function test_convertToNAV_bubblesCustomErrorWithArgs() external {
        bytes memory revertData = abi.encodeWithSelector(TrancheFailure.selector, uint256(0xBEEF), address(0xdead));
        rawTranche.setRevertPayload(revertData);
        vm.expectRevert(revertData);
        harness.convertToNAV(address(rawTranche), 1e18);
    }

    /// @notice A Panic(0x11) arithmetic-overflow revert bubbles up byte-for-byte
    function test_convertToNAV_bubblesArithmeticPanic() external {
        bytes memory revertData = abi.encodeWithSelector(PANIC_SELECTOR, uint256(0x11));
        rawTranche.setRevertPayload(revertData);
        vm.expectRevert(revertData);
        harness.convertToNAV(address(rawTranche), 1e18);
    }

    /// @notice A Panic(0x32) out-of-bounds revert bubbles up byte-for-byte
    function test_convertToNAV_bubblesOutOfBoundsPanic() external {
        bytes memory revertData = abi.encodeWithSelector(PANIC_SELECTOR, uint256(0x32));
        rawTranche.setRevertPayload(revertData);
        vm.expectRevert(revertData);
        harness.convertToNAV(address(rawTranche), 1e18);
    }

    /// @notice An 8KB revert-data bomb bubbles up byte-for-byte, verified via a low-level call comparison
    function test_convertToNAV_bubblesHugeRevertPayloadByteExact() external {
        bytes memory revertData = _pseudoRandomBytes(uint256(keccak256("huge revert")), 8192);
        rawTranche.setRevertPayload(revertData);

        (bool ok, bytes memory ret) = address(harness).call(abi.encodeCall(harness.convertToNAV, (address(rawTranche), uint256(1e18))));
        assertFalse(ok, "The harness call must fail when the tranche reverts");
        assertEq(ret, revertData, "An 8KB revert payload must bubble up byte-for-byte through the library");
    }

    /// @notice A non-word-aligned 7-byte revert payload bubbles up byte-for-byte with no padding appended
    function test_convertToNAV_bubblesNonAlignedRevertPayloadByteExact() external {
        bytes memory revertData = hex"deadbeefcafe01";
        rawTranche.setRevertPayload(revertData);

        (bool ok, bytes memory ret) = address(harness).call(abi.encodeCall(harness.convertToNAV, (address(rawTranche), uint256(1e18))));
        assertFalse(ok, "The harness call must fail when the tranche reverts");
        assertEq(ret, revertData, "A 7-byte revert payload must bubble up byte-for-byte with no padding appended");
    }

    /// =====================================================================
    /// FUZZ
    /// =====================================================================

    /**
     * @notice Fuzz: for any mandate-honoring shape of 1..64 words with keccak-garbage non-terminal words,
     *         the NAV is the trailing word over the full uint256 domain
     * @param _wordCount The total number of returned words, bounded to [1, 64]
     * @param _navWord The trailing NAV word, over the full uint256 domain
     * @param _seed Entropy for the keccak-garbage non-terminal words
     */
    function testFuzz_convertToNAV_readsTrailingWordForAnyWordCount(uint256 _wordCount, uint256 _navWord, uint256 _seed) external {
        _wordCount = bound(_wordCount, 1, 64);
        bytes memory payload;
        for (uint256 i = 0; i + 1 < _wordCount; i++) {
            payload = abi.encodePacked(payload, uint256(keccak256(abi.encode(_seed, i))));
        }
        payload = abi.encodePacked(payload, _navWord);
        rawTranche.setReturnPayload(payload);

        assertEq(_nav(address(rawTranche), 1e18), _navWord, "The NAV must be the trailing word for any word count and any garbage middle words");
    }

    /**
     * @notice Fuzz: for any returndata length in [1, 31], the NAV equals (len << (8*len)) | uint(data)
     * @dev Independent derivation: the length value is shifted above the data bytes because the load spans
     *      the low (32-len) bytes of the length word followed by all len data bytes; the data value is
     *      accumulated with a plain byte loop, never by mirroring the production mload
     * @param _len The returndata length, bounded to [1, 31]
     * @param _seed Entropy for the payload bytes
     */
    function testFuzz_convertToNAV_subWordReturnMatchesDerivedFormula(uint256 _len, uint256 _seed) external {
        _len = bound(_len, 1, 31);
        bytes memory payload = _pseudoRandomBytes(_seed, _len);
        rawTranche.setReturnPayload(payload);

        uint256 dataValue;
        for (uint256 i = 0; i < _len; i++) {
            dataValue = (dataValue << 8) | uint8(payload[i]);
        }
        uint256 expected = (_len << (8 * _len)) | dataValue;

        assertEq(_nav(address(rawTranche), 1e18), expected, "A sub-word return must yield the length-word tail followed by all data bytes");
    }

    /**
     * @notice Fuzz: for any returndata length in [32, 2048] — aligned or not — the NAV is exactly the last
     *         32 bytes of the raw returndata
     * @param _len The returndata length, bounded to [32, 2048] so unaligned lengths are well represented
     * @param _seed Entropy for the payload bytes
     */
    function testFuzz_convertToNAV_readsLastThirtyTwoBytesForAnyLength(uint256 _len, uint256 _seed) external {
        _len = bound(_len, 32, 2048);
        bytes memory payload = _pseudoRandomBytes(_seed, _len);
        rawTranche.setReturnPayload(payload);

        assertEq(_nav(address(rawTranche), 1e18), _lastWordOf(payload), "The NAV must be exactly the last 32 bytes of the raw returndata for any length");
    }

    /**
     * @notice Fuzz: any revert payload up to 4KB — including empty and non-word-aligned lengths — bubbles up
     *         byte-for-byte through the library
     * @param _len The revert payload length, bounded to [0, 4096]
     * @param _seed Entropy for the payload bytes
     */
    function testFuzz_convertToNAV_revertPayloadBubblesByteExact(uint256 _len, uint256 _seed) external {
        _len = bound(_len, 0, 4096);
        bytes memory revertData = _pseudoRandomBytes(_seed, _len);
        rawTranche.setRevertPayload(revertData);

        (bool ok, bytes memory ret) = address(harness).call(abi.encodeCall(harness.convertToNAV, (address(rawTranche), uint256(1e18))));
        assertFalse(ok, "The harness call must fail when the tranche reverts");
        assertEq(ret, revertData, "Any revert payload must bubble up byte-for-byte through the library");
    }

    /// @notice Fuzz: the shares argument is forwarded unmodified over the full uint256 domain
    /// @param _shares The shares argument, over the full uint256 domain
    function testFuzz_convertToNAV_sharesPassThroughFullDomain(uint256 _shares) external {
        vm.expectCall(address(echoTranche), abi.encodeCall(IRoycoVaultTranche.convertToAssets, (_shares)));
        assertEq(_nav(address(echoTranche), _shares), _shares, "The shares argument must be forwarded unmodified for any value");
    }
}
