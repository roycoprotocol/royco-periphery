// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import { Test } from "../../lib/forge-std/src/Test.sol";
import { Vm } from "../../lib/forge-std/src/Vm.sol";

import { IERC20Errors } from "../../lib/openzeppelin-contracts/contracts/interfaces/draft-IERC6093.sol";
import { ERC20Mock } from "../../lib/openzeppelin-contracts/contracts/mocks/token/ERC20Mock.sol";
import { ERC20 } from "../../lib/openzeppelin-contracts/contracts/token/ERC20/ERC20.sol";
import { IERC20 } from "../../lib/openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";

import { ITransparentUpgradeableProxy } from "../../lib/openzeppelin-contracts-v4/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";

import { Errors } from "../../lib/Pendle-SY-Public/contracts/core/libraries/Errors.sol";

import { IRoycoVaultTranche } from "../../src/interfaces/IRoycoVaultTranche.sol";
import { TrancheType } from "../../src/libraries/Types.sol";
import { TRANCHE_UNIT, toTrancheUnits, toUint256 } from "../../src/libraries/Units.sol";
import { PendleRoycoTrancheSY } from "../../src/pendle/PendleRoycoTrancheSY.sol";
import { PendleRoycoTrancheSYFactory } from "../../src/pendle/PendleRoycoTrancheSYFactory.sol";

import { MockTranche } from "../mock/MockTranche.sol";

import { MockRoycoAuthority } from "./PendleRoycoTrancheSYFactoryTest.t.sol";

/// @notice Authority whose canCall always reverts with a custom error, modeling a compromised or bricked access manager
contract RevertingAuthority {
    /// @dev The error the SY's base asset gate probe must bubble up byte-exactly
    error AUTHORITY_COMPROMISED();

    function canCall(address, address, bytes4) external pure returns (bool, uint32) {
        revert AUTHORITY_COMPROMISED();
    }
}

/// @notice Authority whose canCall succeeds but returns a single 32-byte word instead of the (bool, uint32) two-word tuple
/// @dev The high-level decode in _canDepositTrancheBaseAsset requires at least 64 bytes of returndata, so this must revert
contract ShortReturnAuthority {
    fallback() external {
        assembly ("memory-safe") {
            mstore(0x00, 1)
            return(0x00, 0x20)
        }
    }
}

/**
 * @notice Authority whose canCall returns a well-formed (true, 0) head followed by 16KB of nonzero garbage returndata
 * @dev Solidity's ABI decoder only validates the leading two words and ignores trailing bytes, so the bomb must decode
 *      cleanly and OPEN the gate rather than revert or corrupt the result
 */
contract BombAuthority {
    fallback() external {
        assembly ("memory-safe") {
            mstore(0x00, 1) // allowed = true
            mstore(0x20, 0) // delay = 0
            // Fill the remaining 16KB with nonzero garbage words
            for { let offset := 0x40 } lt(offset, 0x4000) { offset := add(offset, 0x20) } { mstore(offset, not(offset)) }
            return(0x00, 0x4000)
        }
    }
}

/**
 * @notice A malicious Royco tranche double: mints shares 1:1 like an honest tranche, but can misreport the share count
 *         it RETURNS from deposit and/or reenter the calling SY's deposit/redeem mid-flight
 * @dev The lying knob pins where a preview/actual discrepancy lands (the SY mints the RETURNED value verbatim);
 *      the reentry knob pins Pendle's nonReentrant guard, optionally catching the inner revert to record it byte-exactly
 */
contract MaliciousTranche is ERC20 {
    enum ReentryMode {
        NONE,
        REENTER_DEPOSIT,
        REENTER_REDEEM
    }

    address public immutable UNDERLYING_ASSET;
    address public trancheAuthority;

    // Lying configuration: when enabled, deposit returns misreportedShares while still minting honestly 1:1
    bool public misreportEnabled;
    uint256 public misreportedShares;

    // Reentry configuration and recorded outcome
    ReentryMode public reentryMode;
    bool public catchReentry;
    bool public reentrySucceeded;
    bytes public lastReentryRevertData;

    constructor(address _asset, address _authority) ERC20("Malicious Tranche", "EVIL") {
        UNDERLYING_ASSET = _asset;
        trancheAuthority = _authority;
    }

    /// @notice Arms the lying return value: deposit will return _reportedShares regardless of what it mints
    function setMisreport(uint256 _reportedShares) external {
        misreportEnabled = true;
        misreportedShares = _reportedShares;
    }

    /// @notice Arms a reentry into the calling SY during deposit, optionally catching the inner revert to record it
    function setReentry(ReentryMode _mode, bool _catch) external {
        reentryMode = _mode;
        catchReentry = _catch;
    }

    function TRANCHE_TYPE() external pure returns (TrancheType) {
        return TrancheType.SENIOR;
    }

    function asset() external view returns (address) {
        return UNDERLYING_ASSET;
    }

    function authority() external view returns (address) {
        return trancheAuthority;
    }

    /// @notice Honest 1:1 preview: the lie only ever lives in deposit's return value
    function previewDeposit(TRANCHE_UNIT _assets) external pure returns (uint256 shares) {
        return toUint256(_assets);
    }

    /// @notice Mandate-compliant Dawn-shaped valuation at 1:1: [stAssets][jtAssets][nav]
    function convertToAssets(uint256 _shares) external pure {
        bytes memory encoded = abi.encode(_shares, uint256(0), _shares);
        assembly ("memory-safe") {
            return(add(encoded, 0x20), mload(encoded))
        }
    }

    /// @notice Pulls assets and mints shares 1:1 like an honest tranche, then optionally reenters the SY and/or lies
    ///         about the minted share count in its return value
    function deposit(TRANCHE_UNIT _assets, address _receiver) external returns (uint256 shares) {
        uint256 amount = toUint256(_assets);
        IERC20(UNDERLYING_ASSET).transferFrom(msg.sender, address(this), amount);
        _mint(_receiver, amount);

        if (reentryMode == ReentryMode.REENTER_DEPOSIT) {
            if (catchReentry) {
                try PendleRoycoTrancheSY(payable(msg.sender)).deposit(address(this), UNDERLYING_ASSET, 1, 0) returns (uint256) {
                    reentrySucceeded = true;
                } catch (bytes memory _err) {
                    lastReentryRevertData = _err;
                }
            } else {
                PendleRoycoTrancheSY(payable(msg.sender)).deposit(address(this), UNDERLYING_ASSET, 1, 0);
            }
        } else if (reentryMode == ReentryMode.REENTER_REDEEM) {
            if (catchReentry) {
                try PendleRoycoTrancheSY(payable(msg.sender)).redeem(address(this), 1, address(this), 0, false) returns (uint256) {
                    reentrySucceeded = true;
                } catch (bytes memory _err) {
                    lastReentryRevertData = _err;
                }
            } else {
                PendleRoycoTrancheSY(payable(msg.sender)).redeem(address(this), 1, address(this), 0, false);
            }
        }

        return misreportEnabled ? misreportedShares : amount;
    }
}

/**
 * @title PendleRoycoTrancheSYAdversarialTest
 * @notice Adversarial tests for PendleRoycoTrancheSY + PendleRoycoTrancheSYFactory: malicious/misbehaving authorities on
 *         the base asset deposit gate, exchangeRate raw-uint256 mandate boundaries, tranches that lie about minted shares,
 *         reentrant tranches probing Pendle's nonReentrant guard, factory slot/proxy-admin/naming edges, and wrap/unwrap
 *         exactness fuzz
 * @dev Complements (never duplicates) PendleRoycoTrancheSYTest, PendleRoycoTrancheSYFactoryTest, and
 *      PendleRoycoTrancheSYBaseAssetDepositTest, which cover the happy-path deposit flows and real-AccessManager gating
 */
contract PendleRoycoTrancheSYAdversarialTest is Test {
    /// =====================================================================
    /// CONSTANTS
    /// =====================================================================
    address internal constant PENDLE_PROXY_ADMIN = 0xA28c08f165116587D4F3E708743B4dEe155c5E64;
    address internal constant PENDLE_PAUSE_CONTROLLER = 0x2aD631F72fB16d91c4953A7f4260A97C2fE2f31e;
    /// @dev EIP-1967 admin storage slot: bytes32(uint256(keccak256("eip1967.proxy.admin")) - 1)
    bytes32 internal constant ADMIN_SLOT = 0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103;
    /// @dev PMath.ONE — the SY queries convertToAssets with exactly this share count inside exchangeRate
    uint256 internal constant PMATH_ONE = 1e18;

    /// =====================================================================
    /// STATE
    /// =====================================================================
    ERC20Mock internal asset;
    MockRoycoAuthority internal mockRoycoAuthority;
    MockTranche internal seniorTranche;
    PendleRoycoTrancheSYFactory internal syFactory;
    PendleRoycoTrancheSY internal sy;

    address internal rewardManager = makeAddr("rewardManager");
    address internal alice = makeAddr("alice");
    address internal bob = makeAddr("bob");

    /// =====================================================================
    /// SETUP
    /// =====================================================================

    function setUp() public {
        asset = new ERC20Mock();
        mockRoycoAuthority = new MockRoycoAuthority();
        seniorTranche = new MockTranche(address(asset), address(mockRoycoAuthority), TrancheType.SENIOR);
        syFactory = new PendleRoycoTrancheSYFactory();
        sy = PendleRoycoTrancheSY(payable(syFactory.deploySY(address(seniorTranche), rewardManager)));
    }

    /// =====================================================================
    /// HELPERS
    /// =====================================================================

    /// @dev Mints base assets to a user and approves the SY to pull them
    function _mintAndApprove(address _user, uint256 _amount) internal {
        asset.mint(_user, _amount);
        vm.prank(_user);
        asset.approve(address(sy), type(uint256).max);
    }

    /// @dev Deploys a MaliciousTranche behind a wide-open stub authority and an SY over it via the factory
    function _deployMaliciousSetup() internal returns (MaliciousTranche malTranche, PendleRoycoTrancheSY malSy) {
        MockRoycoAuthority openAuthority = new MockRoycoAuthority();
        openAuthority.setCanCall(true, 0);
        malTranche = new MaliciousTranche(address(asset), address(openAuthority));
        malSy = PendleRoycoTrancheSY(payable(syFactory.deploySY(address(malTranche), address(0))));
    }

    /// @dev Funds a user with base assets approved to the specified SY and deposits them, returning the SY shares minted
    function _depositBaseAssetInto(PendleRoycoTrancheSY _sy, address _user, uint256 _amount, uint256 _minSharesOut) internal returns (uint256 sharesOut) {
        asset.mint(_user, _amount);
        vm.startPrank(_user);
        asset.approve(address(_sy), _amount);
        sharesOut = _sy.deposit(_user, address(asset), _amount, _minSharesOut);
        vm.stopPrank();
    }

    /// @dev Mocks the tranche's convertToAssets(PMath.ONE) — the exact query exchangeRate makes — to return raw bytes
    function _mockExchangeRateReturndata(bytes memory _returnData) internal {
        vm.mockCall(address(seniorTranche), abi.encodeCall(IRoycoVaultTranche.convertToAssets, (PMATH_ONE)), _returnData);
    }

    /// =====================================================================
    /// BASE ASSET GATE: canCall MATRIX
    /// =====================================================================

    /**
     * @notice Walks all four (allowed, delay) corners of the canCall matrix at the DEPOSIT level, not just the views:
     *         only (true, 0) lets a base asset deposit through; (true, delay>0), (false, 0), and (false, delay>0) all
     *         reject with SYInvalidTokenIn before any funds move
     */
    function test_gate_canCallMatrix_allFourCorners_depositLevel() public {
        _mintAndApprove(alice, 4e18);

        // (false, 0): not allowed — blocked.
        mockRoycoAuthority.setCanCall(false, 0);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(Errors.SYInvalidTokenIn.selector, address(asset)));
        sy.deposit(alice, address(asset), 1e18, 0);

        // (false, delay>0): not allowed with a pending delay — blocked.
        mockRoycoAuthority.setCanCall(false, 1 hours);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(Errors.SYInvalidTokenIn.selector, address(asset)));
        sy.deposit(alice, address(asset), 1e18, 0);

        // (true, delay>0): allowed but not atomically executable — blocked.
        mockRoycoAuthority.setCanCall(true, 1 hours);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(Errors.SYInvalidTokenIn.selector, address(asset)));
        sy.deposit(alice, address(asset), 1e18, 0);

        // (true, 0): allowed with immediate execution — the only corner that admits the deposit.
        mockRoycoAuthority.setCanCall(true, 0);
        vm.prank(alice);
        uint256 sharesOut = sy.deposit(alice, address(asset), 1e18, 0);
        assertEq(sharesOut, 1e18, "The (true, 0) corner must be the only one that admits a base asset deposit");
        assertEq(sy.balanceOf(alice), 1e18, "Exactly one corner's deposit must have minted SY shares to the depositor");
    }

    /**
     * @notice Fuzz over the full (allowed, delay) domain: the gate is open iff allowed && delay == 0, and every gate
     *         consumer (isValidTokenIn, getTokensIn, previewDeposit) must agree with that single predicate
     * @param _allowed The canCall permission bit returned by the tranche's authority
     * @param _delay The canCall execution delay returned by the tranche's authority (full uint32 domain)
     */
    function testFuzz_gate_canCallMatrix_viewsAndPreviewConsistent(bool _allowed, uint32 _delay) public {
        mockRoycoAuthority.setCanCall(_allowed, _delay);
        bool expectedOpen = _allowed && _delay == 0;

        assertEq(sy.isValidTokenIn(address(asset)), expectedOpen, "The base asset must be a valid token in iff canCall returned (true, 0)");
        assertEq(sy.getTokensIn().length, expectedOpen ? 2 : 1, "getTokensIn must list the base asset iff canCall returned (true, 0)");
        assertTrue(sy.isValidTokenIn(address(seniorTranche)), "The tranche share must remain a valid token in for every gate state");

        if (expectedOpen) {
            assertEq(sy.previewDeposit(address(asset), 1e18), 1e18, "An open gate must preview the tranche's own deposit quote");
        } else {
            vm.expectRevert(abi.encodeWithSelector(Errors.SYInvalidTokenIn.selector, address(asset)));
            sy.previewDeposit(address(asset), 1e18);
        }
    }

    /// =====================================================================
    /// BASE ASSET GATE: MALICIOUS / MISBEHAVING AUTHORITIES
    /// =====================================================================

    /**
     * @notice A reverting authority does not fail open OR closed: the revert bubbles up byte-exactly from every base
     *         asset gate consumer (getTokensIn, isValidTokenIn(asset), previewDeposit(asset), deposit(asset))
     */
    function test_gate_revertingAuthority_bubblesOnAllBaseAssetProbes() public {
        seniorTranche.setAuthority(address(new RevertingAuthority()));

        vm.expectRevert(RevertingAuthority.AUTHORITY_COMPROMISED.selector);
        sy.getTokensIn();

        vm.expectRevert(RevertingAuthority.AUTHORITY_COMPROMISED.selector);
        sy.isValidTokenIn(address(asset));

        vm.expectRevert(RevertingAuthority.AUTHORITY_COMPROMISED.selector);
        sy.previewDeposit(address(asset), 1e18);

        _mintAndApprove(alice, 1e18);
        vm.prank(alice);
        vm.expectRevert(RevertingAuthority.AUTHORITY_COMPROMISED.selector);
        sy.deposit(alice, address(asset), 1e18, 0);
    }

    /**
     * @notice A poisoned authority cannot brick the wrap: isValidTokenIn short-circuits on the yield token before
     *         consulting the authority, so tranche share deposits, redemptions, and non-asset token rejections all
     *         keep working while the authority reverts
     */
    function test_gate_revertingAuthority_trancheSharePathUnaffected() public {
        seniorTranche.setAuthority(address(new RevertingAuthority()));

        // The share check and the random-token check both short-circuit without touching the authority.
        assertTrue(sy.isValidTokenIn(address(seniorTranche)), "The tranche share must stay valid while the authority reverts");
        assertFalse(sy.isValidTokenIn(makeAddr("randomToken")), "A random token must be rejected without consulting the reverting authority");

        // Wrapping and unwrapping tranche shares must work end to end while the authority is bricked.
        asset.mint(alice, 5e18);
        vm.startPrank(alice);
        asset.approve(address(seniorTranche), 5e18);
        uint256 trancheShares = seniorTranche.deposit(toTrancheUnits(5e18), alice);
        seniorTranche.approve(address(sy), trancheShares);
        uint256 syShares = sy.deposit(alice, address(seniorTranche), trancheShares, 0);
        assertEq(syShares, trancheShares, "The 1:1 share wrap must be unaffected by a reverting authority");
        uint256 sharesBack = sy.redeem(alice, syShares, address(seniorTranche), 0, false);
        vm.stopPrank();
        assertEq(sharesBack, syShares, "The 1:1 share unwrap must be unaffected by a reverting authority");
    }

    /// @notice An authority returning only one word (instead of the (bool, uint32) tuple) makes the gate probes revert
    ///         on decode, while the yield token path stays live
    function test_gate_shortReturndataAuthority_baseAssetProbesRevert() public {
        seniorTranche.setAuthority(address(new ShortReturnAuthority()));

        vm.expectRevert();
        sy.getTokensIn();

        vm.expectRevert();
        sy.isValidTokenIn(address(asset));

        assertTrue(sy.isValidTokenIn(address(seniorTranche)), "The tranche share must stay valid while the authority returns short data");
    }

    /// @notice A 16KB returndata bomb wrapped around a valid (true, 0) head decodes cleanly, opens the gate, and the
    ///         base asset deposit settles exactly as it would against an honest authority
    function test_gate_returndataBombAuthority_gateOpensAndDepositSucceeds() public {
        seniorTranche.setAuthority(address(new BombAuthority()));

        assertTrue(sy.isValidTokenIn(address(asset)), "A well-formed (true, 0) head must open the gate regardless of trailing garbage");
        assertEq(sy.getTokensIn().length, 2, "The bomb authority's (true, 0) head must list the base asset as a token in");

        uint256 sharesOut = _depositBaseAssetInto(sy, alice, 3e18, 3e18);
        assertEq(sharesOut, 3e18, "A base asset deposit through the bombed gate must settle exactly like the clean path");
        assertEq(sy.totalSupply(), seniorTranche.balanceOf(address(sy)), "The SY must remain fully backed after depositing through the bombed gate");
    }

    /// @notice A codeless (EOA) authority makes the base asset gate probes revert on the code-existence check, while
    ///         the yield token path stays live
    function test_gate_eoaAuthority_baseAssetProbesRevert() public {
        seniorTranche.setAuthority(makeAddr("eoaAuthority"));

        vm.expectRevert();
        sy.getTokensIn();

        vm.expectRevert();
        sy.isValidTokenIn(address(asset));

        assertTrue(sy.isValidTokenIn(address(seniorTranche)), "The tranche share must stay valid while the authority is codeless");
    }

    /// =====================================================================
    /// exchangeRate: RAW uint256 MANDATE BOUNDARIES
    /// =====================================================================

    /// @notice The NAV word is a raw uint256 passed through verbatim: a NAV of type(uint256).max must be returned
    ///         exactly, with no revert (the SY, unlike the Chainlink oracles, performs no int256 cast)
    function test_exchangeRate_maxUint256Nav_returnedVerbatim() public {
        // The mock computes assets = mulDiv(1e18, sharePriceWAD, 1e18) = sharePriceWAD exactly (512-bit intermediate).
        seniorTranche.setSharePrice(type(uint256).max);
        assertEq(sy.exchangeRate(), type(uint256).max, "exchangeRate must pass the raw uint256 NAV through verbatim at type(uint256).max");
    }

    /// @notice A NAV of 2^255 (one above int256.max) must NOT revert: exchangeRate never casts to int256, in deliberate
    ///         contrast with RoycoTrancheChainlinkOracle which rejects the same NAV with ASSETS_MUST_BE_NON_NEGATIVE
    function test_exchangeRate_navAboveInt256Max_doesNotRevert() public {
        uint256 nav = uint256(1) << 255;
        seniorTranche.setSharePrice(nav);
        assertEq(sy.exchangeRate(), nav, "exchangeRate must not perform any signed cast on the NAV word");
    }

    /// @notice MANDATE PIN: empty convertToAssets returndata makes convertToNAV read a zero length word, so the rate is 0
    function test_exchangeRate_emptyReturndata_readsZero() public {
        _mockExchangeRateReturndata("");
        assertEq(sy.exchangeRate(), 0, "Empty convertToAssets returndata must produce an exchange rate of exactly zero");
    }

    /// @notice MANDATE PIN: a single-word return makes convertToNAV read that word as the NAV — even above int256.max
    function test_exchangeRate_oneWordReturndata_readsThatWord() public {
        _mockExchangeRateReturndata(abi.encode(type(uint256).max));
        assertEq(sy.exchangeRate(), type(uint256).max, "A one-word convertToAssets return must be read as the NAV verbatim");
    }

    /// @notice MANDATE PIN: a two-word return makes convertToNAV read the SECOND word (the last 32 bytes) as the NAV
    function test_exchangeRate_twoWordReturndata_readsSecondWord() public {
        _mockExchangeRateReturndata(abi.encode(uint256(111), uint256(222)));
        assertEq(sy.exchangeRate(), 222, "A two-word convertToAssets return must be read from its last 32 bytes");
    }

    /**
     * @notice Fuzz the Dawn-shaped [stAssets][jtAssets][nav] return over the FULL uint256 domain of every word:
     *         exchangeRate must equal the trailing NAV word verbatim and be wholly independent of the claim words
     * @param _stAssets The leading senior claim word (ignored by exchangeRate)
     * @param _jtAssets The junior claim word (ignored by exchangeRate)
     * @param _nav The trailing NAV word (returned verbatim)
     */
    function testFuzz_exchangeRate_fullNavDomain(uint256 _stAssets, uint256 _jtAssets, uint256 _nav) public {
        _mockExchangeRateReturndata(abi.encode(_stAssets, _jtAssets, _nav));
        assertEq(sy.exchangeRate(), _nav, "exchangeRate must equal the trailing NAV word for any claim words over the full uint256 domain");
    }

    /// =====================================================================
    /// LYING TRANCHE: deposit RETURN VALUE vs previewDeposit
    /// =====================================================================

    /**
     * @notice CHARACTERIZATION: the SY mints exactly what tranche.deposit RETURNS, not what previewDeposit quoted.
     *         An underreporting tranche (mints 10e18, returns 6e18) leaves the depositor with 6e18 SY against 10e18
     *         tranche shares of backing: the shortfall lands entirely on the depositor and the SY becomes over-backed
     */
    function test_deposit_underreportingTranche_mintsReturnedSharesNotPreview() public {
        (MaliciousTranche malTranche, PendleRoycoTrancheSY malSy) = _deployMaliciousSetup();
        malTranche.setMisreport(6e18);

        // The preview is honest (10e18) — the lie only lives in deposit's return value.
        assertEq(malSy.previewDeposit(address(asset), 10e18), 10e18, "The preview must quote the tranche's honest 1:1 rate");

        uint256 sharesOut = _depositBaseAssetInto(malSy, alice, 10e18, 0);

        assertEq(sharesOut, 6e18, "The SY must mint the share count RETURNED by tranche.deposit, not the preview");
        assertEq(malSy.balanceOf(alice), 6e18, "The depositor must absorb the full preview/actual shortfall");
        assertEq(malTranche.balanceOf(address(malSy)), 10e18, "The tranche must hold the honestly minted 10e18 shares for the SY");
        assertEq(malSy.totalSupply(), 6e18, "The SY becomes over-backed: supply below its tranche share backing");
    }

    /// @notice minSharesOut set to the honest preview is the depositor's only defense against an underreporting
    ///         tranche, and the resulting revert must unwind every ledger to its pre-attack state
    function test_deposit_underreportingTranche_minSharesOutRevertsAndFullyUnwinds() public {
        (MaliciousTranche malTranche, PendleRoycoTrancheSY malSy) = _deployMaliciousSetup();
        malTranche.setMisreport(6e18);

        asset.mint(alice, 10e18);
        vm.startPrank(alice);
        asset.approve(address(malSy), 10e18);

        // Pre-attack snapshot of every ledger the flow touches.
        uint256 aliceAssetsBefore = asset.balanceOf(alice);
        uint256 trancheAssetsBefore = asset.balanceOf(address(malTranche));
        uint256 trancheSupplyBefore = malTranche.totalSupply();
        uint256 sySupplyBefore = malSy.totalSupply();

        vm.expectRevert(abi.encodeWithSelector(Errors.SYInsufficientSharesOut.selector, 6e18, 10e18));
        malSy.deposit(alice, address(asset), 10e18, 10e18);
        vm.stopPrank();

        // Post-revert unwind audit: every ledger must equal the pre-attack snapshot.
        assertEq(asset.balanceOf(alice), aliceAssetsBefore, "The depositor's assets must be fully restored after the slippage revert");
        assertEq(asset.balanceOf(address(malTranche)), trancheAssetsBefore, "The tranche's asset balance must be fully unwound after the revert");
        assertEq(malTranche.totalSupply(), trancheSupplyBefore, "The tranche's share supply must be fully unwound after the revert");
        assertEq(malSy.totalSupply(), sySupplyBefore, "The SY's supply must be fully unwound after the revert");
        assertEq(malSy.balanceOf(alice), 0, "No SY shares may survive the slippage revert");
    }

    /**
     * @notice CHARACTERIZATION: an overreporting tranche (mints 10e18, returns 15e18) makes the SY mint 15e18 SY
     *         against 10e18 of backing — the SY trusts the tranche's return verbatim (the tranche is the trusted yield
     *         token), and the insolvency only manifests at redemption, landing on the LAST redeemer
     */
    function test_deposit_overreportingTranche_mintsUnbackedSY_insolvencyLandsOnLastRedeemer() public {
        (MaliciousTranche malTranche, PendleRoycoTrancheSY malSy) = _deployMaliciousSetup();
        malTranche.setMisreport(15e18);

        uint256 sharesOut = _depositBaseAssetInto(malSy, alice, 10e18, 0);
        assertEq(sharesOut, 15e18, "The SY must mint the overreported share count verbatim");
        assertGt(malSy.totalSupply(), malTranche.balanceOf(address(malSy)), "The overreport must leave the SY supply above its backing");

        // The first 10e18 SY (the backed portion) redeems fine.
        vm.prank(alice);
        uint256 backedOut = malSy.redeem(alice, 10e18, address(malTranche), 0, false);
        assertEq(backedOut, 10e18, "The backed portion of the overreported supply must still redeem 1:1");

        // The final 5e18 SY is unbacked: the SY holds zero tranche shares, so the transfer out must revert.
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(IERC20Errors.ERC20InsufficientBalance.selector, address(malSy), 0, 5e18));
        malSy.redeem(alice, 5e18, address(malTranche), 0, false);
    }

    /// @notice CHARACTERIZATION: a tranche returning 0 from deposit makes the SY keep the user's funds and mint 0 SY
    ///         without reverting — minSharesOut is the depositor's ONLY protection against a zero return
    function test_deposit_zeroReturningTranche_mintsZeroSYWithoutReverting() public {
        (MaliciousTranche malTranche, PendleRoycoTrancheSY malSy) = _deployMaliciousSetup();
        malTranche.setMisreport(0);

        uint256 sharesOut = _depositBaseAssetInto(malSy, alice, 10e18, 0);

        assertEq(sharesOut, 0, "A zero deposit return must mint zero SY without reverting when minSharesOut is zero");
        assertEq(malSy.balanceOf(alice), 0, "The depositor receives nothing for their assets when the tranche returns zero");
        assertEq(asset.balanceOf(address(malTranche)), 10e18, "The tranche keeps the depositor's assets despite returning zero shares");
        assertEq(malTranche.balanceOf(address(malSy)), 10e18, "The honestly minted backing is stranded in the SY as a donation");
    }

    /// =====================================================================
    /// REENTRANT TRANCHE: Pendle's nonReentrant GUARD
    /// =====================================================================

    /**
     * @notice PIN: SYBaseUpgV2.deposit is nonReentrant. A tranche that reenters SY.deposit from inside tranche.deposit
     *         is stopped by the guard, the inner Error("ReentrancyGuard: reentrant call") bubbles through the tranche
     *         and reverts the ENTIRE outer deposit, and every ledger unwinds to its pre-attack state
     */
    function test_deposit_reentrantTranche_depositReentryBlockedByGuard() public {
        (MaliciousTranche malTranche, PendleRoycoTrancheSY malSy) = _deployMaliciousSetup();
        malTranche.setReentry(MaliciousTranche.ReentryMode.REENTER_DEPOSIT, false);

        asset.mint(alice, 10e18);
        vm.startPrank(alice);
        asset.approve(address(malSy), 10e18);

        vm.expectRevert(bytes("ReentrancyGuard: reentrant call"));
        malSy.deposit(alice, address(asset), 10e18, 0);
        vm.stopPrank();

        // Post-revert unwind audit: the guard's rejection must revert the whole flow, not just the inner call.
        assertEq(asset.balanceOf(alice), 10e18, "The depositor's assets must be fully restored after the reentrancy revert");
        assertEq(malSy.totalSupply(), 0, "No SY may be minted when the reentrant tranche bubbles the guard's revert");
        assertEq(malTranche.totalSupply(), 0, "The tranche's mid-flight mint must be unwound by the outer revert");
        assertEq(asset.balanceOf(address(malTranche)), 0, "The tranche's mid-flight asset pull must be unwound by the outer revert");
    }

    /// @notice PIN: SYBaseUpgV2.redeem shares the same reentrancy status as deposit, so a tranche reentering
    ///         SY.redeem from inside tranche.deposit is rejected by the identical guard error
    function test_deposit_reentrantTranche_redeemReentryBlockedByGuard() public {
        (MaliciousTranche malTranche, PendleRoycoTrancheSY malSy) = _deployMaliciousSetup();
        malTranche.setReentry(MaliciousTranche.ReentryMode.REENTER_REDEEM, false);

        asset.mint(alice, 10e18);
        vm.startPrank(alice);
        asset.approve(address(malSy), 10e18);

        vm.expectRevert(bytes("ReentrancyGuard: reentrant call"));
        malSy.deposit(alice, address(asset), 10e18, 0);
        vm.stopPrank();

        assertEq(malSy.totalSupply(), 0, "A cross-function deposit->redeem reentry must revert the entire deposit");
    }

    /**
     * @notice Control-run vs hooked-run: a tranche that catches its own failed reentry cannot perturb settlement.
     *         The recorded inner revert must be byte-exact Error("ReentrancyGuard: reentrant call") — the guard's
     *         rejection, not an incidental failure — and the hooked deposit must settle wei-identical to the control
     */
    function test_deposit_reentrantTranche_caughtReentry_outerSettlesIdenticalToControl() public {
        (MaliciousTranche malTranche, PendleRoycoTrancheSY malSy) = _deployMaliciousSetup();

        // Control run: no reentry armed.
        uint256 controlShares = _depositBaseAssetInto(malSy, alice, 5e18, 0);
        assertEq(controlShares, 5e18, "The control deposit of 5e18 assets at 1:1 must mint exactly 5e18 SY");

        // Hooked run: the tranche attempts the reentry, catches the guard's revert, and lets the deposit proceed.
        malTranche.setReentry(MaliciousTranche.ReentryMode.REENTER_DEPOSIT, true);
        uint256 hookedShares = _depositBaseAssetInto(malSy, bob, 5e18, 0);

        // Anti-vacuity + byte-exactness: the probe really ran and was rejected by the guard specifically.
        assertFalse(malTranche.reentrySucceeded(), "The armed reentry must never succeed against the nonReentrant guard");
        assertEq(
            malTranche.lastReentryRevertData(),
            abi.encodeWithSignature("Error(string)", "ReentrancyGuard: reentrant call"),
            "The recorded rejection must be the reentrancy guard's error, byte-exact, not an incidental failure"
        );

        // The attacked run must settle wei-identical to the control run.
        assertEq(hookedShares, controlShares, "A caught reentry attempt must not change the shares minted by one wei");
        assertEq(malSy.balanceOf(bob), controlShares, "The hooked depositor's SY balance must match the control depositor's");
        assertEq(malSy.totalSupply(), malTranche.balanceOf(address(malSy)), "The SY must remain exactly fully backed after the caught reentry");
    }

    /// =====================================================================
    /// FACTORY: SLOT KEYING, v4.9.3 PROXY ADMIN SEMANTICS, NAMING EDGES
    /// =====================================================================

    /**
     * @notice The registry is keyed by the (tranche, rewardManager) PAIR: the same tranche deploys independently under
     *         two reward managers, redeploying an occupied pair reverts SY_ALREADY_DEPLOYED, and the failed redeploy
     *         corrupts neither the occupied slot nor the adjacent one
     */
    function test_deploySY_sameTrancheDifferentRewardManagers_independentSlots() public {
        address rm2 = makeAddr("rewardManager2");

        // setUp already occupied (seniorTranche, rewardManager); the same tranche under rm2 must deploy fresh.
        address sy2 = syFactory.deploySY(address(seniorTranche), rm2);
        assertTrue(sy2 != address(sy), "The same tranche under a different reward manager must yield a distinct SY");
        assertEq(syFactory.trancheToOffchainRewardManagerToSY(address(seniorTranche), rm2), sy2, "The second pair's slot must record its own SY");

        // Both occupied pairs must now reject redeployment.
        vm.expectRevert(PendleRoycoTrancheSYFactory.SY_ALREADY_DEPLOYED.selector);
        syFactory.deploySY(address(seniorTranche), rewardManager);
        vm.expectRevert(PendleRoycoTrancheSYFactory.SY_ALREADY_DEPLOYED.selector);
        syFactory.deploySY(address(seniorTranche), rm2);

        // Neither failed redeploy may corrupt either slot.
        assertEq(syFactory.trancheToOffchainRewardManagerToSY(address(seniorTranche), rewardManager), address(sy), "The first slot must survive both failed redeploys");
        assertEq(syFactory.trancheToOffchainRewardManagerToSY(address(seniorTranche), rm2), sy2, "The second slot must survive both failed redeploys");
        assertEq(PendleRoycoTrancheSY(payable(sy2)).offchainRewardManager(), rm2, "The second SY's baked reward manager must be the second pair's key");
    }

    /**
     * @notice OZ v4.9.3 TransparentUpgradeableProxy sets the constructor's admin_ argument DIRECTLY into the EIP-1967
     *         admin slot via _changeAdmin (no ProxyAdmin is auto-deployed — that is v5 behavior), so the slot must hold
     *         PENDLE_PROXY_ADMIN itself, and the proxy must emit Upgraded(implementation) then AdminChanged(0, admin)
     */
    function test_deploySY_proxyAdmin_v493SetsPendleAdminDirectly_eventExact() public {
        MockTranche freshTranche = new MockTranche(address(asset), address(mockRoycoAuthority), TrancheType.JUNIOR);
        vm.recordLogs();
        address freshSy = syFactory.deploySY(address(freshTranche), rewardManager);
        Vm.Log[] memory logs = vm.getRecordedLogs();

        // The admin slot holds Pendle's proxy admin address verbatim: v4.9.3 deploys no intermediary ProxyAdmin.
        bytes32 storedAdmin = vm.load(freshSy, ADMIN_SLOT);
        assertEq(address(uint160(uint256(storedAdmin))), PENDLE_PROXY_ADMIN, "The EIP-1967 admin slot must hold PENDLE_PROXY_ADMIN directly");
        assertEq(PENDLE_PROXY_ADMIN.code.length, 0, "v4.9.3 must NOT deploy a ProxyAdmin contract at the admin address (that is v5 behavior)");

        // Pull the implementation from the factory's SYDeployed topics for the Upgraded cross-check.
        address implementation;
        bool foundUpgraded;
        bool foundAdminChanged;
        for (uint256 i = 0; i < logs.length; ++i) {
            if (logs[i].emitter == address(syFactory) && logs[i].topics[0] == keccak256("SYDeployed(address,address,address)")) {
                implementation = address(uint160(uint256(logs[i].topics[3])));
            }
        }
        assertTrue(implementation != address(0), "The SYDeployed event must carry the implementation address");

        // ERC1967 event exactness, emitted by the proxy itself during construction.
        for (uint256 i = 0; i < logs.length; ++i) {
            if (logs[i].emitter != freshSy) continue;
            if (logs[i].topics[0] == keccak256("Upgraded(address)")) {
                assertEq(address(uint160(uint256(logs[i].topics[1]))), implementation, "Upgraded must carry the exact implementation as its indexed topic");
                foundUpgraded = true;
            } else if (logs[i].topics[0] == keccak256("AdminChanged(address,address)")) {
                assertEq(logs[i].topics.length, 1, "AdminChanged carries no indexed topics under ERC1967");
                assertEq(logs[i].data, abi.encode(address(0), PENDLE_PROXY_ADMIN), "AdminChanged must record the zero-to-Pendle admin transition byte-exactly");
                foundAdminChanged = true;
            }
        }
        assertTrue(foundUpgraded, "The proxy must emit Upgraded during construction");
        assertTrue(foundAdminChanged, "The proxy must emit AdminChanged during construction");
    }

    /**
     * @notice v4.9.3 transparency pin: the admin's calls are dispatched by the proxy and NEVER forwarded — an admin
     *         call to an SY function reverts with the canonical transparency error, while the ITransparentUpgradeableProxy
     *         admin()/implementation() dispatch answers the admin correctly
     */
    function test_proxy_adminCannotFallbackToImplementation() public {
        // Any non-admin caller reaches the implementation normally.
        assertEq(sy.name(), string.concat("SY ", seniorTranche.name()));

        // The admin is walled off from the implementation entirely.
        vm.prank(PENDLE_PROXY_ADMIN);
        vm.expectRevert(bytes("TransparentUpgradeableProxy: admin cannot fallback to proxy target"));
        sy.name();

        // The admin's dedicated dispatch surface answers with the wired admin.
        vm.prank(PENDLE_PROXY_ADMIN);
        address reportedAdmin = ITransparentUpgradeableProxy(address(sy)).admin();
        assertEq(reportedAdmin, PENDLE_PROXY_ADMIN, "The proxy's admin dispatch must report PENDLE_PROXY_ADMIN");
    }

    /// @notice A tranche with empty name and symbol composes to the bare "SY " / "SY-" prefixes — the factory applies
    ///         no validation or padding to tranche metadata
    function test_deploySY_emptyTrancheMetadata_composesBarePrefixes() public {
        MockTranche bare = new MockTranche(address(asset), address(mockRoycoAuthority), TrancheType.SENIOR);
        vm.mockCall(address(bare), abi.encodeWithSignature("name()"), abi.encode(""));
        vm.mockCall(address(bare), abi.encodeWithSignature("symbol()"), abi.encode(""));

        PendleRoycoTrancheSY bareSy = PendleRoycoTrancheSY(payable(syFactory.deploySY(address(bare), rewardManager)));

        assertEq(bareSy.name(), "SY ", "An empty tranche name must compose to the bare 'SY ' prefix");
        assertEq(bareSy.symbol(), "SY-", "An empty tranche symbol must compose to the bare 'SY-' prefix");
    }

    /// @notice A 100-character tranche name/symbol composes to an exact 103-character concatenation with no truncation
    function test_deploySY_hundredCharTrancheMetadata_composesExactly() public {
        bytes memory nameBytes = new bytes(100);
        for (uint256 i = 0; i < 100; ++i) {
            nameBytes[i] = bytes1(uint8(0x41 + (i % 26))); // A-Z repeating
        }
        string memory longString = string(nameBytes);

        MockTranche verbose = new MockTranche(address(asset), address(mockRoycoAuthority), TrancheType.SENIOR);
        vm.mockCall(address(verbose), abi.encodeWithSignature("name()"), abi.encode(longString));
        vm.mockCall(address(verbose), abi.encodeWithSignature("symbol()"), abi.encode(longString));

        PendleRoycoTrancheSY verboseSy = PendleRoycoTrancheSY(payable(syFactory.deploySY(address(verbose), rewardManager)));

        assertEq(verboseSy.name(), string.concat("SY ", longString), "A 100-char tranche name must compose without truncation");
        assertEq(verboseSy.symbol(), string.concat("SY-", longString), "A 100-char tranche symbol must compose without truncation");
        assertEq(bytes(verboseSy.name()).length, 103, "The composed name must be exactly 3 prefix chars plus 100 tranche chars");
    }

    /// =====================================================================
    /// WRAP / UNWRAP: 1:1 EXACTNESS FUZZ
    /// =====================================================================

    /**
     * @notice PROPERTY: wrapping tranche shares and unwrapping them round-trips EXACTLY for any share amount in
     *         [1, uint248.max] (the SY's supply is a uint248) and any share price over the full uint256 domain —
     *         the wrap is a pure 1:1 pass-through with zero spread, so minSharesOut/minTokenOut can be set exactly
     * @param _shares The tranche share amount to round-trip, bounded only by the SY's uint248 supply accumulator
     * @param _sharePriceWAD The tranche share price over the full uint256 domain (must be irrelevant to the wrap)
     */
    function testFuzz_wrapUnwrap_fullRoundTripExactAtAnyPriceAndAmount(uint256 _shares, uint256 _sharePriceWAD) public {
        _shares = bound(_shares, 1, type(uint248).max);
        seniorTranche.setSharePrice(_sharePriceWAD);

        // Grant alice the tranche shares directly: acquisition math is out of scope for the wrap property.
        deal(address(seniorTranche), alice, _shares, true);

        vm.startPrank(alice);
        seniorTranche.approve(address(sy), _shares);
        // minSharesOut == _shares: the exact boundary must pass for every amount and price.
        uint256 syShares = sy.deposit(alice, address(seniorTranche), _shares, _shares);
        assertEq(syShares, _shares, "The wrap must mint exactly one SY wei per tranche share wei at any price");
        assertEq(seniorTranche.balanceOf(address(sy)), _shares, "The SY must custody exactly the wrapped tranche shares");

        // minTokenOut == _shares: the exact boundary must pass on the way out too.
        uint256 sharesBack = sy.redeem(alice, syShares, address(seniorTranche), _shares, false);
        vm.stopPrank();

        assertEq(sharesBack, _shares, "The unwrap must return exactly one tranche share wei per SY wei at any price");
        assertEq(seniorTranche.balanceOf(alice), _shares, "The round trip must restore the depositor's tranche shares to the wei");
        assertEq(sy.totalSupply(), 0, "The SY supply must return to zero after a full round trip");
        assertEq(seniorTranche.balanceOf(address(sy)), 0, "The SY must hold no residual tranche shares after a full round trip");
    }

    /**
     * @notice PROPERTY: after wrapping _shares and unwrapping an arbitrary portion, every wei is conserved across the
     *         two ledgers — alice's tranche shares plus the SY's custody always sum to _shares, and the SY supply
     *         always equals its custody exactly
     * @param _shares The tranche share amount to wrap
     * @param _redeemShares The portion of the wrapped shares to unwrap
     */
    function testFuzz_wrapUnwrap_partialRedeemConservesEveryWei(uint256 _shares, uint256 _redeemShares) public {
        _shares = bound(_shares, 1, type(uint248).max);
        _redeemShares = bound(_redeemShares, 1, _shares);

        deal(address(seniorTranche), alice, _shares, true);

        vm.startPrank(alice);
        seniorTranche.approve(address(sy), _shares);
        sy.deposit(alice, address(seniorTranche), _shares, _shares);
        sy.redeem(alice, _redeemShares, address(seniorTranche), _redeemShares, false);
        vm.stopPrank();

        assertEq(sy.balanceOf(alice), _shares - _redeemShares, "The remaining SY balance must be exactly the unredeemed portion");
        assertEq(seniorTranche.balanceOf(alice), _redeemShares, "The redeemed tranche shares must equal the redeemed SY exactly");
        assertEq(
            seniorTranche.balanceOf(alice) + seniorTranche.balanceOf(address(sy)),
            _shares,
            "Every tranche share wei must be conserved between the depositor and the SY"
        );
        assertEq(sy.totalSupply(), seniorTranche.balanceOf(address(sy)), "The SY supply must equal its tranche share custody after any partial redeem");
    }
}
