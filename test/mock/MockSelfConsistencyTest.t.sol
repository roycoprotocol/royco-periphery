// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import { Test } from "../../lib/forge-std/src/Test.sol";

import { ERC20Mock } from "../../lib/openzeppelin-contracts/contracts/mocks/token/ERC20Mock.sol";

import { IRoycoVaultTranche } from "../../src/interfaces/IRoycoVaultTranche.sol";
import { TrancheType } from "../../src/libraries/Types.sol";
import { toTrancheUnits } from "../../src/libraries/Units.sol";

import { MockTranche } from "./MockTranche.sol";

/**
 * @title MockSelfConsistencyTest
 * @notice Pins the load-bearing properties of MockTranche itself so future mock edits cannot silently weaken the suite
 * @dev Every periphery raw-returndata reader (convertToNAV, the oracles, the Pendle SY) is validated against
 *      MockTranche's mandate-shaped convertToAssets return: [stAssets][jtAssets][middleWords keccak words][nav].
 *      If the mock's shape, word placement, or share-price math drifted, downstream suites could pass vacuously —
 *      these tests fail loudly instead. Expected values are always derived independently with plain checked
 *      arithmetic from the fuzz inputs, never by mirroring the mock's own mulDiv
 */
contract MockSelfConsistencyTest is Test {
    // ═══════════════════════════════════════════════════════════════════════════
    // TEST STATE
    // ═══════════════════════════════════════════════════════════════════════════

    ERC20Mock internal asset;
    MockTranche internal seniorTranche;
    MockTranche internal juniorTranche;

    address internal constant FACTORY_PLACEHOLDER = address(0xF);

    // ═══════════════════════════════════════════════════════════════════════════
    // SETUP
    // ═══════════════════════════════════════════════════════════════════════════

    function setUp() public {
        asset = new ERC20Mock();
        seniorTranche = new MockTranche(address(asset), FACTORY_PLACEHOLDER, TrancheType.SENIOR);
        juniorTranche = new MockTranche(address(asset), FACTORY_PLACEHOLDER, TrancheType.JUNIOR);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // HELPER FUNCTIONS
    // ═══════════════════════════════════════════════════════════════════════════

    /// @notice Calls convertToAssets through a raw staticcall so the full untyped returndata can be inspected
    function _rawConvertToAssets(MockTranche _tranche, uint256 _shares) internal view returns (bytes memory returnData) {
        bool success;
        (success, returnData) = address(_tranche).staticcall(abi.encodeCall(IRoycoVaultTranche.convertToAssets, (_shares)));
        assertTrue(success, "convertToAssets must succeed for the raw shape inspection to be meaningful");
    }

    /// @notice Reads the _index-th 32-byte word of a raw returndata buffer
    function _word(bytes memory _data, uint256 _index) internal pure returns (uint256 word) {
        assembly ("memory-safe") {
            word := mload(add(add(_data, 0x20), mul(_index, 0x20)))
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // SECTION 1: DEFAULTS
    // ═══════════════════════════════════════════════════════════════════════════

    /// @notice The mock must default to the Royco Dawn shape (0 middle words) at a 1:1 share price
    function test_defaults_dawnShapeAndParityPrice() external view {
        assertEq(seniorTranche.convertToAssetsMiddleWords(), 0, "The default middle word count must be 0 (Dawn shape)");
        assertEq(seniorTranche.sharePriceWAD(), 1e18, "The default share price must be exactly 1e18 (1:1)");
        assertEq(juniorTranche.convertToAssetsMiddleWords(), 0, "The junior mock must share the Dawn default shape");
        assertEq(juniorTranche.sharePriceWAD(), 1e18, "The junior mock must share the 1:1 default price");
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // SECTION 2: convertToAssets RAW SHAPE
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * @notice Control run with hand-derived literals: at price 2e18, 3e18 shares value floor(3e18 x 2e18 / 1e18) = 6e18,
     *         so a default senior Dawn return is exactly three words [6e18][0][6e18] and 96 bytes long
     */
    function test_convertToAssets_controlLiterals_seniorDawnShape() external {
        seniorTranche.setSharePrice(2e18);

        bytes memory returnData = _rawConvertToAssets(seniorTranche, 3e18);
        assertEq(returnData.length, 96, "The Dawn shape must be exactly three 32-byte words");
        assertEq(_word(returnData, 0), 6e18, "The first word must be the senior tranche's asset claim");
        assertEq(_word(returnData, 1), 0, "The second word must be zero for a senior tranche");
        assertEq(_word(returnData, 2), 6e18, "The last word must be the NAV");
    }

    /// @notice PINS the shape contract: raw returndatasize must be exactly 32 x (2 leading claims + middleWords + 1 nav)
    /// @param _middleWords Bounded to 0..64, covering Dawn (0), Day (2), and any future protocol shape the suite fuzzes
    /// @param _shares Bounded to 1e30 so share-price math elsewhere stays in checked-arithmetic range
    function testFuzz_convertToAssets_returndataSizeMatchesShape(uint256 _middleWords, uint256 _shares) external {
        _middleWords = bound(_middleWords, 0, 64);
        _shares = bound(_shares, 0, 1e30);
        seniorTranche.setConvertToAssetsMiddleWords(_middleWords);

        bytes memory returnData = _rawConvertToAssets(seniorTranche, _shares);
        assertEq(returnData.length, 32 * (2 + _middleWords + 1), "The raw returndata size must be 32 x (2 + middleWords + 1)");
    }

    /**
     * @notice The first two words must be the ST/JT asset claims keyed on the tranche type: the senior mock puts the
     *         full asset value in word 0 (word 1 zero), the junior mock mirrors it into word 1 (word 0 zero)
     * @dev Expected assets derived independently: floor(shares x price / 1e18) with shares <= 1e30 and price <= 1e30,
     *      so the raw product is at most 1e60 — far below 2^256 — and plain checked arithmetic needs no mulDiv
     */
    function testFuzz_convertToAssets_firstTwoWordsMatchTrancheTypeAndShareMath(uint256 _middleWords, uint256 _shares, uint256 _sharePriceWAD) external {
        _middleWords = bound(_middleWords, 0, 16);
        _shares = bound(_shares, 0, 1e30);
        _sharePriceWAD = bound(_sharePriceWAD, 0, 1e30);
        uint256 expectedAssets = (_shares * _sharePriceWAD) / 1e18;

        seniorTranche.setConvertToAssetsMiddleWords(_middleWords);
        seniorTranche.setSharePrice(_sharePriceWAD);
        bytes memory seniorData = _rawConvertToAssets(seniorTranche, _shares);
        assertEq(_word(seniorData, 0), expectedAssets, "The senior mock must lead with its full asset claim in the stAssets word");
        assertEq(_word(seniorData, 1), 0, "The senior mock must report a zero jtAssets claim");

        juniorTranche.setConvertToAssetsMiddleWords(_middleWords);
        juniorTranche.setSharePrice(_sharePriceWAD);
        bytes memory juniorData = _rawConvertToAssets(juniorTranche, _shares);
        assertEq(_word(juniorData, 0), 0, "The junior mock must report a zero stAssets claim");
        assertEq(_word(juniorData, 1), expectedAssets, "The junior mock must place its full asset claim in the jtAssets word");
    }

    /**
     * @notice The trailing word must equal the NAV — floor(shares x price / 1e18) — for every mandate-honoring shape,
     *         since periphery's convertToNAV reads exactly (and only) the last 32 bytes of the returndata
     */
    function testFuzz_convertToAssets_lastWordEqualsNavForAnyShape(uint256 _middleWords, uint256 _shares, uint256 _sharePriceWAD) external {
        _middleWords = bound(_middleWords, 0, 64);
        _shares = bound(_shares, 0, 1e30);
        _sharePriceWAD = bound(_sharePriceWAD, 0, 1e30);
        uint256 expectedNav = (_shares * _sharePriceWAD) / 1e18;

        seniorTranche.setConvertToAssetsMiddleWords(_middleWords);
        seniorTranche.setSharePrice(_sharePriceWAD);

        bytes memory returnData = _rawConvertToAssets(seniorTranche, _shares);
        uint256 wordCount = returnData.length / 32;
        assertEq(_word(returnData, wordCount - 1), expectedNav, "The last word must always be the independently derived NAV");
    }

    /**
     * @notice The middle words must be the pinned keccak stream uint256(keccak256(abi.encode(shares, i))) and nonzero,
     *         so mandate-compliant readers are provably exercised against garbage (not conveniently zeroed) filler
     */
    function testFuzz_convertToAssets_middleWordsAreNonzeroKeccakStream(uint256 _middleWords, uint256 _shares) external {
        _middleWords = bound(_middleWords, 1, 32);
        _shares = bound(_shares, 0, 1e30);
        seniorTranche.setConvertToAssetsMiddleWords(_middleWords);

        bytes memory returnData = _rawConvertToAssets(seniorTranche, _shares);
        for (uint256 i = 0; i < _middleWords; i++) {
            uint256 middleWord = _word(returnData, 2 + i);
            assertEq(middleWord, uint256(keccak256(abi.encode(_shares, i))), "Each middle word must be the documented keccak stream value");
            assertTrue(middleWord != 0, "Middle filler words must never be zero, or garbage-tolerance tests would weaken");
        }
    }

    /// @notice Zero shares must produce all-zero claims and NAV while preserving the configured shape
    function test_convertToAssets_zeroShares() external {
        seniorTranche.setConvertToAssetsMiddleWords(2);
        seniorTranche.setSharePrice(3e18);

        bytes memory returnData = _rawConvertToAssets(seniorTranche, 0);
        assertEq(returnData.length, 160, "Zero shares must still return the full five-word Day shape");
        assertEq(_word(returnData, 0), 0, "Zero shares must value to a zero stAssets claim");
        assertEq(_word(returnData, 1), 0, "Zero shares must value to a zero jtAssets claim");
        assertEq(_word(returnData, 4), 0, "Zero shares must value to a zero NAV");
    }

    /// @notice Boundary: at the exact 1:1 parity price, uint256.max shares value losslessly to a uint256.max NAV
    function test_convertToAssets_maxSharesAtParityPrice() external view {
        // mulDiv(uint256.max, 1e18, 1e18) = uint256.max exactly, with no intermediate overflow
        bytes memory returnData = _rawConvertToAssets(seniorTranche, type(uint256).max);
        assertEq(returnData.length, 96, "The default Dawn shape must hold at the shares boundary");
        assertEq(_word(returnData, 0), type(uint256).max, "The senior claim must carry the full boundary value");
        assertEq(_word(returnData, 2), type(uint256).max, "The NAV must carry the full boundary value");
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // SECTION 3: DEPOSIT / REDEEM CONSERVATION
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * @notice previewDeposit must match the independent share derivation floor(assets x 1e18 / price)
     * @dev Domain: assets in [1e6, 1e30] and price in [1e16, 1e20] keeps the raw product at most 1e48 (checked math
     *      safe) and guarantees at least floor(1e6 x 1e18 / 1e20) = 1e4 shares, so the preview is never trivially zero
     */
    function testFuzz_previewDeposit_matchesIndependentShareMath(uint256 _assets, uint256 _sharePriceWAD) external {
        _assets = bound(_assets, 1e6, 1e30);
        _sharePriceWAD = bound(_sharePriceWAD, 1e16, 1e20);
        seniorTranche.setSharePrice(_sharePriceWAD);

        uint256 expectedShares = (_assets * 1e18) / _sharePriceWAD;
        assertEq(seniorTranche.previewDeposit(toTrancheUnits(_assets)), expectedShares, "previewDeposit must equal floor(assets x 1e18 / price)");
    }

    /**
     * @notice Deposit conservation: minted shares must equal floor(assets x 1e18 / price), the deposited assets must
     *         move caller -> tranche exactly, and the Deposit event must carry the exact amounts
     * @dev Same overflow-safe domain as the preview fuzz; expected values are derived with plain checked arithmetic
     */
    function testFuzz_deposit_conservationAndEventExactness(uint256 _assets, uint256 _sharePriceWAD) external {
        _assets = bound(_assets, 1e6, 1e30);
        _sharePriceWAD = bound(_sharePriceWAD, 1e16, 1e20);
        seniorTranche.setSharePrice(_sharePriceWAD);

        address depositor = makeAddr("DEPOSITOR");
        asset.mint(depositor, _assets);
        vm.prank(depositor);
        asset.approve(address(seniorTranche), _assets);

        uint256 expectedShares = (_assets * 1e18) / _sharePriceWAD;

        vm.expectEmit(true, true, true, true, address(seniorTranche));
        emit MockTranche.Deposit(depositor, depositor, toTrancheUnits(_assets), expectedShares);

        vm.prank(depositor);
        uint256 mintedShares = seniorTranche.deposit(toTrancheUnits(_assets), depositor);

        assertEq(mintedShares, expectedShares, "Minted shares must equal floor(assets x 1e18 / price)");
        assertEq(seniorTranche.balanceOf(depositor), expectedShares, "The receiver's share balance must equal the minted shares");
        assertEq(seniorTranche.totalSupply(), expectedShares, "The total supply must grow by exactly the minted shares");
        assertEq(asset.balanceOf(depositor), 0, "The depositor must part with exactly the deposited assets");
        assertEq(asset.balanceOf(address(seniorTranche)), _assets, "The tranche must custody exactly the deposited assets");
        assertEq(seniorTranche.totalDepositedAssets(), _assets, "The deposit tracker must record exactly the deposited assets");
    }

    /**
     * @notice Round-trip conservation: redeeming all minted shares burns them fully and returns
     *         floor(shares x price / 1e18) assets, which floor rounding caps at the amount deposited —
     *         a full deposit/redeem cycle can never mint value out of the mock
     */
    function testFuzz_depositRedeem_roundTripNeverCreatesValue(uint256 _assets, uint256 _sharePriceWAD) external {
        _assets = bound(_assets, 1e6, 1e30);
        _sharePriceWAD = bound(_sharePriceWAD, 1e16, 1e20);
        seniorTranche.setSharePrice(_sharePriceWAD);

        address depositor = makeAddr("DEPOSITOR");
        asset.mint(depositor, _assets);
        vm.startPrank(depositor);
        asset.approve(address(seniorTranche), _assets);
        uint256 shares = seniorTranche.deposit(toTrancheUnits(_assets), depositor);
        seniorTranche.redeem(shares, depositor, depositor);
        vm.stopPrank();

        // Independent derivation of the redemption proceeds from the raw fuzz inputs
        uint256 expectedReturned = (shares * _sharePriceWAD) / 1e18;
        assertLe(expectedReturned, _assets, "Floor rounding must never let a round trip return more than was deposited");
        assertEq(asset.balanceOf(depositor), expectedReturned, "The redeemer must receive exactly floor(shares x price / 1e18)");
        assertEq(seniorTranche.balanceOf(depositor), 0, "All shares must be burned after a full redemption");
        assertEq(seniorTranche.totalSupply(), 0, "The total supply must return to zero after a full redemption");
        assertEq(asset.balanceOf(address(seniorTranche)), _assets - expectedReturned, "The tranche keeps only the rounding dust");
    }

    /// @notice A zero-asset deposit must revert with the mock's non-zero-mint guard
    function test_deposit_zeroAssetsReverts() external {
        vm.expectRevert(bytes("MUST_MINT_NON_ZERO_SHARES"));
        seniorTranche.deposit(toTrancheUnits(0), address(this));
    }

    /// @notice A zero-share redemption must revert with the mock's non-zero-request guard
    function test_redeem_zeroSharesReverts() external {
        vm.expectRevert(bytes("MUST_REQUEST_NON_ZERO_SHARES"));
        seniorTranche.redeem(0, address(this), address(this));
    }
}
