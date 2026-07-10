// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import { Test } from "../../lib/forge-std/src/Test.sol";
import { Vm } from "../../lib/forge-std/src/Vm.sol";
import { PausableUpgradeable } from "../../lib/openzeppelin-contracts-upgradeable/contracts/utils/PausableUpgradeable.sol";
import { UUPSUpgradeable } from "../../lib/openzeppelin-contracts-upgradeable/contracts/proxy/utils/UUPSUpgradeable.sol";
import { IAccessManaged } from "../../lib/openzeppelin-contracts/contracts/access/manager/IAccessManaged.sol";
import { ERC1967Proxy } from "../../lib/openzeppelin-contracts/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import { ExtraRoles } from "../mock/ExtraRoles.sol";
import { DeploySyncerScript } from "../../script/independent/DeploySyncer.s.sol";
import { RolesConfiguration } from "../mock/RolesConfiguration.sol";
import { IRoycoAuth } from "../../src/interfaces/IRoycoAuth.sol";
import { RoycoMarketSyncer } from "../../src/syncer/RoycoMarketSyncer.sol";
import { RoycoAuthorityMock } from "../mock/RoycoAuthorityMock.sol";

/// @dev Minimal well-behaved sync target that only counts successful syncs
contract CountingKernel {
    uint256 public syncCallCount;

    function syncTrancheAccounting() external {
        syncCallCount++;
    }
}

/**
 * @title ReentrantKernel
 * @notice Malicious sync target that re-enters the syncer with an arbitrary configured payload during its own sync
 * @dev With `swallowReentryFailure = false` the inner revert is bubbled byte-exactly (so the outer batch sees the
 *      kernel as failed); with `swallowReentryFailure = true` the inner outcome is latched and the sync succeeds,
 *      exercising the tolerated-failure path without the outer batch ever observing the attack
 */
contract ReentrantKernel {
    address public immutable SYNCER;

    bytes public reentryPayload;
    bool public swallowReentryFailure;
    bool public reentryAttempted;
    bool public reentrySucceeded;
    bytes public reentryReturnData;
    uint256 public syncCallCount;

    constructor(address _syncer) {
        SYNCER = _syncer;
    }

    /// @notice Configures the calldata this kernel re-enters the syncer with and whether inner failures are swallowed
    function setReentryPayload(bytes calldata _payload, bool _swallowReentryFailure) external {
        reentryPayload = _payload;
        swallowReentryFailure = _swallowReentryFailure;
    }

    function syncTrancheAccounting() external {
        // Only attempt the reentry once so nested self-syncs cannot recurse unboundedly
        if (reentryAttempted) {
            syncCallCount++;
            return;
        }
        reentryAttempted = true;
        (bool success, bytes memory returnData) = SYNCER.call(reentryPayload);
        reentrySucceeded = success;
        reentryReturnData = returnData;
        if (!success && !swallowReentryFailure) {
            // Bubble the inner revert byte-exactly so the outer batch observes the reentry rejection
            assembly ("memory-safe") {
                revert(add(returnData, 0x20), mload(returnData))
            }
        }
        syncCallCount++;
    }
}

/**
 * @title RegistryMutatingKernel
 * @notice SYNC_ROLE-holding sync target that mutates the syncer's kernel registry mid-batch
 * @dev Used to pin the state-order behavior of executeBatchAccountingSync's cached `numKernels` against a set that
 *      shrinks or gets swap-reordered while the loop is still running
 */
contract RegistryMutatingKernel {
    RoycoMarketSyncer public immutable SYNCER_CONTRACT;

    address[] internal kernelsToRemove;
    address[] internal kernelsToAdd;
    bool public mutationExecuted;
    uint256 public syncCallCount;

    constructor(RoycoMarketSyncer _syncer) {
        SYNCER_CONTRACT = _syncer;
    }

    /// @notice Configures the registry mutation this kernel performs on its first sync
    function configureMutation(address[] calldata _kernelsToRemove, address[] calldata _kernelsToAdd) external {
        kernelsToRemove = _kernelsToRemove;
        kernelsToAdd = _kernelsToAdd;
    }

    function syncTrancheAccounting() external {
        syncCallCount++;
        if (mutationExecuted) return;
        mutationExecuted = true;
        if (kernelsToRemove.length > 0) SYNCER_CONTRACT.removeMarketKernels(kernelsToRemove);
        if (kernelsToAdd.length > 0) SYNCER_CONTRACT.addMarketKernels(kernelsToAdd);
    }
}

/**
 * @title RevertBombKernel
 * @notice Sync target that reverts with a deterministic patterned payload of the configured size
 * @dev The size must be a multiple of 32 bytes so the patterned fill never writes past the allocation; the payload is
 *      built in memory at revert time so no storage writes are needed for arbitrarily large bombs
 */
contract RevertBombKernel {
    uint256 public immutable BOMB_SIZE;

    constructor(uint256 _bombSize) {
        BOMB_SIZE = _bombSize;
    }

    /// @notice Builds the deterministic patterned bomb payload (word at offset o is keccak256(abi.encode(o)))
    function buildBombPayload() public view returns (bytes memory payload) {
        payload = new bytes(BOMB_SIZE);
        for (uint256 offset = 0; offset < BOMB_SIZE; offset += 32) {
            bytes32 word = keccak256(abi.encode(offset));
            assembly ("memory-safe") {
                mstore(add(add(payload, 0x20), offset), word)
            }
        }
    }

    function syncTrancheAccounting() external view {
        bytes memory payload = buildBombPayload();
        assembly ("memory-safe") {
            revert(add(payload, 0x20), mload(payload))
        }
    }
}

/// @dev Sync target that succeeds but returns 1 MiB of returndata; the syncer's `0x00, 0x00` out params must ignore it
contract SuccessReturndataBombKernel {
    uint256 public syncCallCount;

    function syncTrancheAccounting() external {
        syncCallCount++;
        assembly ("memory-safe") {
            return(0x00, 0x100000)
        }
    }
}

/// @dev Sync target whose fallback executes INVALID, consuming ALL gas forwarded to it (worst-case gas griefing)
contract GasBombKernel {
    fallback() external {
        assembly {
            invalid()
        }
    }
}

/// @dev Upgrade target extending the production syncer with a version probe, proving state survives an upgrade
contract RoycoMarketSyncerV2Mock is RoycoMarketSyncer {
    function syncerImplementationVersion() external pure returns (uint256) {
        return 2;
    }
}

/**
 * @title RoycoMarketSyncerAdversarialTest
 * @notice Adversarial test suite for the RoycoMarketSyncer: hostile kernels (reentrancy, returndata bombs, gas
 *         griefing), state-order attacks on the kernel registry, the full access-control and pause matrices,
 *         ERC-7201 storage isolation, and upgrade state preservation
 * @dev Mirrors the production role wiring used by RoycoMarketSyncerTest (DeploySyncer script +
 *      buildSyncerConfigTransactions) so every probe runs against the exact production access-control topology.
 *      Complements (never duplicates) the unit suite in RoycoMarketSyncerTest and the byte-equivalence suite in
 *      RoycoMarketSyncerSyncDifferentialTest
 */
contract RoycoMarketSyncerAdversarialTest is Test, RolesConfiguration, ExtraRoles {
    // ═══════════════════════════════════════════════════════════════════════════
    // TEST STATE
    // ═══════════════════════════════════════════════════════════════════════════

    /// @dev ERC-7201 storage slot of RoycoMarketSyncerState (private in src, so pinned here byte-for-byte)
    bytes32 internal constant SYNCER_STORAGE_SLOT = 0x65f8145c32d6f7d600ded0f23ff9c2c2e262c975a2f7552b5c41fcd203e2aa00;

    /// @dev keccak256("AccountingSyncFailed(address,bytes)")
    bytes32 internal constant ACCOUNTING_SYNC_FAILED_SIG = keccak256("AccountingSyncFailed(address,bytes)");

    DeploySyncerScript internal deployScript;
    RoycoMarketSyncer internal syncer;
    RoycoAuthorityMock internal roycoAuthority;

    Vm.Wallet internal AUTHORITY_ADMIN;
    address internal AUTHORITY_ADMIN_ADDRESS;

    Vm.Wallet internal DEPLOYER;
    address internal DEPLOYER_ADDRESS;

    Vm.Wallet internal SYNC_OPERATOR;
    address internal SYNC_OPERATOR_ADDRESS;

    Vm.Wallet internal PAUSER;
    address internal PAUSER_ADDRESS;

    Vm.Wallet internal UNAUTHORIZED_USER;
    address internal UNAUTHORIZED_USER_ADDRESS;

    // ═══════════════════════════════════════════════════════════════════════════
    // SETUP
    // ═══════════════════════════════════════════════════════════════════════════

    function setUp() public {
        _setupWallets();
        _deployCreate2Factory();
        _deployAuthority();

        // Deploy the syncer through the production deployment script with no initial kernels
        deployScript = new DeploySyncerScript();
        address[] memory emptyKernels = new address[](0);
        syncer = RoycoMarketSyncer(deployScript.deploySyncer(address(roycoAuthority), emptyKernels, DEPLOYER.privateKey));

        vm.label(address(syncer), "Syncer");
        vm.label(address(roycoAuthority), "RoycoAuthority");

        _configureProductionRoles();
    }

    function _setupWallets() internal {
        AUTHORITY_ADMIN = vm.createWallet("AUTHORITY_ADMIN");
        AUTHORITY_ADMIN_ADDRESS = AUTHORITY_ADMIN.addr;
        vm.label(AUTHORITY_ADMIN_ADDRESS, "AUTHORITY_ADMIN");
        vm.deal(AUTHORITY_ADMIN_ADDRESS, 100 ether);

        DEPLOYER = vm.createWallet("DEPLOYER");
        DEPLOYER_ADDRESS = DEPLOYER.addr;
        vm.label(DEPLOYER_ADDRESS, "DEPLOYER");
        vm.deal(DEPLOYER_ADDRESS, 100 ether);

        SYNC_OPERATOR = vm.createWallet("SYNC_OPERATOR");
        SYNC_OPERATOR_ADDRESS = SYNC_OPERATOR.addr;
        vm.label(SYNC_OPERATOR_ADDRESS, "SYNC_OPERATOR");
        vm.deal(SYNC_OPERATOR_ADDRESS, 100 ether);

        PAUSER = vm.createWallet("PAUSER");
        PAUSER_ADDRESS = PAUSER.addr;
        vm.label(PAUSER_ADDRESS, "PAUSER");
        vm.deal(PAUSER_ADDRESS, 100 ether);

        UNAUTHORIZED_USER = vm.createWallet("UNAUTHORIZED_USER");
        UNAUTHORIZED_USER_ADDRESS = UNAUTHORIZED_USER.addr;
        vm.label(UNAUTHORIZED_USER_ADDRESS, "UNAUTHORIZED_USER");
        vm.deal(UNAUTHORIZED_USER_ADDRESS, 100 ether);
    }

    /// @dev Etches the deterministic CREATE2 factory the deployment script depends on
    function _deployCreate2Factory() internal {
        bytes memory create2FactoryBytecode =
            hex"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe03601600081602082378035828234f58015156039578182fd5b8082525050506014600cf3";
        vm.etch(CREATE2_FACTORY, create2FactoryBytecode);
    }

    function _deployAuthority() internal {
        RoycoAuthorityMock authorityImpl = new RoycoAuthorityMock();
        RoycoAuthorityMock.RoleAssignmentConfiguration[] memory emptyRoles = new RoycoAuthorityMock.RoleAssignmentConfiguration[](0);
        bytes memory initData = abi.encodeCall(RoycoAuthorityMock.initialize, (AUTHORITY_ADMIN_ADDRESS, DEPLOYER_ADDRESS, 7 days, emptyRoles));
        roycoAuthority = RoycoAuthorityMock(address(new ERC1967Proxy(address(authorityImpl), initData)));
    }

    /// @dev Applies the exact production role configuration, then grants pauser/unpauser/upgrader test wallets their roles
    function _configureProductionRoles() internal {
        address[] memory syncOperators = new address[](1);
        syncOperators[0] = SYNC_OPERATOR_ADDRESS;

        DeploySyncerScript.SafeTransaction[] memory transactions =
            deployScript.buildSyncerConfigTransactions(address(roycoAuthority), address(syncer), syncOperators, deployScript.standardRoycoRoles());

        vm.startPrank(AUTHORITY_ADMIN_ADDRESS);
        for (uint256 i = 0; i < transactions.length; i++) {
            (bool success,) = transactions[i].to.call(transactions[i].data);
            require(success, "Failed to configure syncer roles");
        }
        vm.stopPrank();

        vm.startPrank(AUTHORITY_ADMIN_ADDRESS);
        roycoAuthority.grantRole(ADMIN_PAUSER_ROLE, PAUSER_ADDRESS, 0);
        roycoAuthority.grantRole(ADMIN_UNPAUSER_ROLE, PAUSER_ADDRESS, 0);
        roycoAuthority.grantRole(ADMIN_UPGRADER_ROLE, DEPLOYER_ADDRESS, 0);
        vm.stopPrank();
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // HELPER FUNCTIONS
    // ═══════════════════════════════════════════════════════════════════════════

    /// @dev Wraps a single kernel address in an array
    function _single(address _kernel) internal pure returns (address[] memory kernels) {
        kernels = new address[](1);
        kernels[0] = _kernel;
    }

    /// @dev Registers kernels as the SYNC_ROLE operator
    function _addKernels(address[] memory _kernels) internal {
        vm.prank(SYNC_OPERATOR_ADDRESS);
        syncer.addMarketKernels(_kernels);
    }

    /// @dev Grants SYNC_ROLE to a (malicious) kernel so role-holding reentrancy scenarios can be exercised
    function _grantSyncRole(address _kernel) internal {
        vm.prank(AUTHORITY_ADMIN_ADDRESS);
        roycoAuthority.grantRole(SYNC_ROLE, _kernel, 0);
    }

    /// @dev Returns the expected AccessManagedUnauthorized revert bytes for the specified caller
    function _unauthorizedError(address _caller) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(IAccessManaged.AccessManagedUnauthorized.selector, _caller);
    }

    /// @dev Collects all AccountingSyncFailed logs from the recorded set
    function _accountingSyncFailedLogs() internal view returns (Vm.Log[] memory failures) {
        Vm.Log[] memory logs = vm.getRecordedLogs();
        uint256 count = 0;
        failures = new Vm.Log[](logs.length);
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].topics[0] == ACCOUNTING_SYNC_FAILED_SIG) {
                failures[count++] = logs[i];
            }
        }
        assembly ("memory-safe") {
            mstore(failures, count)
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // SECTION 1: ACCESS-CONTROL MATRIX
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * @notice Every restricted function called by an unauthorized EOA must revert with exactly
     *         AccessManagedUnauthorized(caller) — never an incidental failure that could mask a missing guard
     * @dev Loops raw calldata payloads for all 7 restricted entrypoints so the guard is the only thing standing
     *      between the stranger and execution
     */
    function test_accessControl_unauthorizedRevertsOnEveryRestrictedFunction() external {
        address[] memory one = _single(address(new CountingKernel()));
        address newImpl = address(new RoycoMarketSyncer());

        bytes[] memory payloads = new bytes[](7);
        payloads[0] = abi.encodeCall(RoycoMarketSyncer.executeBatchAccountingSync, (true));
        payloads[1] = abi.encodeCall(RoycoMarketSyncer.executeBatchAccountingSyncFor, (one, true));
        payloads[2] = abi.encodeCall(RoycoMarketSyncer.addMarketKernels, (one));
        payloads[3] = abi.encodeCall(RoycoMarketSyncer.removeMarketKernels, (one));
        payloads[4] = abi.encodeCall(IRoycoAuth.pause, ());
        payloads[5] = abi.encodeCall(IRoycoAuth.unpause, ());
        payloads[6] = abi.encodeCall(UUPSUpgradeable.upgradeToAndCall, (newImpl, bytes("")));

        for (uint256 i = 0; i < payloads.length; i++) {
            vm.prank(UNAUTHORIZED_USER_ADDRESS);
            (bool success, bytes memory returnData) = address(syncer).call(payloads[i]);
            assertFalse(success, string.concat("Restricted payload index ", vm.toString(i), " must revert for an unauthorized caller"));
            assertEq(
                returnData,
                _unauthorizedError(UNAUTHORIZED_USER_ADDRESS),
                string.concat("Restricted payload index ", vm.toString(i), " must revert with exactly AccessManagedUnauthorized(caller)")
            );
        }
    }

    /// @notice The authority admin holds ADMIN_ROLE but not SYNC_ROLE, so it must not be exempt from the sync gate
    function test_accessControl_authorityAdminIsNotExemptFromSyncRole() external {
        vm.prank(AUTHORITY_ADMIN_ADDRESS);
        vm.expectRevert(_unauthorizedError(AUTHORITY_ADMIN_ADDRESS));
        syncer.executeBatchAccountingSync(true);
    }

    /**
     * @notice Every restricted function must succeed for its production role holder: SYNC_ROLE for the four
     *         operational functions, ADMIN_PAUSER/UNPAUSER for pause/unpause, and ADMIN_UPGRADER for upgrades
     */
    function test_accessControl_roleHoldersCanCallEveryRestrictedFunction() external {
        CountingKernel kernel = new CountingKernel();

        vm.startPrank(SYNC_OPERATOR_ADDRESS);
        syncer.addMarketKernels(_single(address(kernel)));
        syncer.executeBatchAccountingSync(true);
        syncer.executeBatchAccountingSyncFor(_single(address(kernel)), false);
        syncer.removeMarketKernels(_single(address(kernel)));
        vm.stopPrank();
        assertEq(kernel.syncCallCount(), 2, "The SYNC_ROLE holder must be able to execute both batch sync variants");
        assertFalse(syncer.isMarketKernelRegistered(address(kernel)), "The SYNC_ROLE holder must be able to remove kernels");

        vm.prank(PAUSER_ADDRESS);
        syncer.pause();
        assertTrue(PausableUpgradeable(address(syncer)).paused(), "The ADMIN_PAUSER_ROLE holder must be able to pause");

        vm.prank(PAUSER_ADDRESS);
        syncer.unpause();
        assertFalse(PausableUpgradeable(address(syncer)).paused(), "The ADMIN_UNPAUSER_ROLE holder must be able to unpause");

        // Deploy the fresh implementation BEFORE pranking so the CREATE does not consume the prank
        RoycoMarketSyncer freshImpl = new RoycoMarketSyncer();
        vm.prank(DEPLOYER_ADDRESS);
        syncer.upgradeToAndCall(address(freshImpl), "");
        assertEq(syncer.authority(), address(roycoAuthority), "The ADMIN_UPGRADER_ROLE holder must be able to upgrade without corrupting the authority");
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // SECTION 2: REENTRANT KERNELS
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * @notice A malicious kernel re-entering executeBatchAccountingSyncFor holds no role, so the inner call reverts
     *         AccessManagedUnauthorized(kernel); when the kernel bubbles that revert, the tolerant outer batch emits
     *         AccountingSyncFailed carrying exactly those bytes and still syncs the remaining kernels
     */
    function test_reentrancy_kernelReenteringSyncForWithoutRole_isRejectedAndTolerated() external {
        ReentrantKernel reentrant = new ReentrantKernel(address(syncer));
        CountingKernel innocent = new CountingKernel();
        reentrant.setReentryPayload(abi.encodeCall(RoycoMarketSyncer.executeBatchAccountingSyncFor, (_single(address(innocent)), true)), false);

        address[] memory batch = new address[](2);
        batch[0] = address(reentrant);
        batch[1] = address(innocent);

        vm.recordLogs();
        vm.prank(SYNC_OPERATOR_ADDRESS);
        syncer.executeBatchAccountingSyncFor(batch, true);

        Vm.Log[] memory failures = _accountingSyncFailedLogs();
        assertEq(failures.length, 1, "Only the reentrant kernel's sync should fail");
        assertEq(failures[0].topics[1], bytes32(uint256(uint160(address(reentrant)))), "The failure must be attributed to the reentrant kernel");
        assertEq(
            failures[0].data,
            abi.encode(_unauthorizedError(address(reentrant))),
            "The emitted errorData must be exactly the inner AccessManagedUnauthorized(kernel) revert bytes"
        );
        assertEq(innocent.syncCallCount(), 1, "The innocent kernel must be synced exactly once (only by the outer batch, never by the rejected reentry)");
    }

    /**
     * @notice A malicious kernel re-entering addMarketKernels to self-register is rejected with
     *         AccessManagedUnauthorized(kernel), and an intolerant outer batch bubbles those exact bytes upstream
     */
    function test_reentrancy_kernelReenteringAddKernelsWithoutRole_propagatesWhenNotTolerant() external {
        ReentrantKernel reentrant = new ReentrantKernel(address(syncer));
        reentrant.setReentryPayload(abi.encodeCall(RoycoMarketSyncer.addMarketKernels, (_single(address(reentrant)))), false);

        vm.prank(SYNC_OPERATOR_ADDRESS);
        vm.expectRevert(_unauthorizedError(address(reentrant)));
        syncer.executeBatchAccountingSyncFor(_single(address(reentrant)), false);

        assertFalse(syncer.isMarketKernelRegistered(address(reentrant)), "The reentrant kernel must not have managed to self-register");
    }

    /**
     * @notice A kernel that swallows its rejected reentry succeeds from the batch's perspective (tolerated-failure
     *         path never even triggers), but its latched returndata proves the guard fired and the registry is intact
     * @dev Post-attack unwind audit: registry membership, raw ERC-7201 slot, and event silence are all re-asserted
     */
    function test_reentrancy_kernelSwallowingReentryFailure_leavesRegistryUntouched() external {
        ReentrantKernel reentrant = new ReentrantKernel(address(syncer));
        CountingKernel other = new CountingKernel();
        address attackerKernel = makeAddr("AttackerKernel");
        reentrant.setReentryPayload(abi.encodeCall(RoycoMarketSyncer.addMarketKernels, (_single(attackerKernel))), true);

        address[] memory registered = new address[](2);
        registered[0] = address(reentrant);
        registered[1] = address(other);
        _addKernels(registered);
        bytes32 slotBefore = vm.load(address(syncer), SYNCER_STORAGE_SLOT);

        vm.recordLogs();
        vm.prank(SYNC_OPERATOR_ADDRESS);
        syncer.executeBatchAccountingSync(true);

        // The kernel's own sync succeeded, so no failure event may be emitted despite the attempted attack
        assertEq(_accountingSyncFailedLogs().length, 0, "A kernel that swallows its reentry failure must not surface as a failed sync");
        assertEq(reentrant.syncCallCount(), 1, "The swallowing kernel's sync must have completed");
        assertFalse(reentrant.reentrySucceeded(), "The inner registry mutation must have been rejected by the access manager");
        assertEq(
            reentrant.reentryReturnData(),
            _unauthorizedError(address(reentrant)),
            "The latched inner revert must be exactly AccessManagedUnauthorized(kernel)"
        );

        // Full unwind audit: nothing about the registry may have changed
        assertFalse(syncer.isMarketKernelRegistered(attackerKernel), "The attacker-controlled kernel must not be registered");
        assertEq(syncer.getMarketKernels().length, 2, "Registry cardinality must be unchanged after the attack");
        assertTrue(syncer.isMarketKernelRegistered(address(reentrant)), "The reentrant kernel's own registration must be unchanged");
        assertTrue(syncer.isMarketKernelRegistered(address(other)), "The other kernel's registration must be unchanged");
        assertEq(vm.load(address(syncer), SYNCER_STORAGE_SLOT), slotBefore, "The raw ERC-7201 storage slot must be unchanged after the attack");
        assertEq(other.syncCallCount(), 1, "The other kernel must still have been synced");
    }

    /**
     * @notice The syncer has NO reentrancy guard by design: a SYNC_ROLE-holding kernel can nest a batch sync inside
     *         its own sync and both the nested and outer batches complete — pinned as intentional behavior
     */
    function test_reentrancy_syncRoleKernelCanNestBatchSync_noReentrancyGuardByDesign() external {
        ReentrantKernel reentrant = new ReentrantKernel(address(syncer));
        CountingKernel innocent = new CountingKernel();
        reentrant.setReentryPayload(abi.encodeCall(RoycoMarketSyncer.executeBatchAccountingSyncFor, (_single(address(innocent)), true)), false);
        _grantSyncRole(address(reentrant));

        vm.recordLogs();
        vm.prank(SYNC_OPERATOR_ADDRESS);
        syncer.executeBatchAccountingSyncFor(_single(address(reentrant)), true);

        assertTrue(reentrant.reentrySucceeded(), "The nested batch sync must succeed because no reentrancy guard exists (intentional)");
        assertEq(innocent.syncCallCount(), 1, "The nested batch must have synced its target kernel");
        assertEq(reentrant.syncCallCount(), 1, "The outer batch must have completed the reentrant kernel's own sync");
        assertEq(_accountingSyncFailedLogs().length, 0, "Neither the outer nor the nested batch should record a failure");
    }

    /**
     * @notice State-order attack: a SYNC_ROLE kernel that removes itself mid-batch shrinks the set below the cached
     *         `numKernels`, so the loop's EnumerableSet.at(i) reads out of bounds and the whole batch reverts with
     *         panic 0x32 — tolerance does not help because the panic happens in the syncer itself, not the kernel call
     */
    function test_reentrancy_registryShrinkMidBatch_panicsOutOfBoundsDespiteTolerance() external {
        RegistryMutatingKernel mutator = new RegistryMutatingKernel(syncer);
        CountingKernel other = new CountingKernel();
        mutator.configureMutation(_single(address(mutator)), new address[](0));
        _grantSyncRole(address(mutator));

        address[] memory registered = new address[](2);
        registered[0] = address(mutator);
        registered[1] = address(other);
        _addKernels(registered);

        // Cached numKernels = 2; after the mid-batch removal the set holds 1 element, so at(1) panics with 0x32
        vm.prank(SYNC_OPERATOR_ADDRESS);
        vm.expectRevert(abi.encodeWithSelector(0x4e487b71, uint256(0x32)));
        syncer.executeBatchAccountingSync(true);

        // The panic reverts the entire batch, so the mid-batch removal itself is also unwound
        assertTrue(syncer.isMarketKernelRegistered(address(mutator)), "The reverted batch must unwind the mid-batch self-removal");
        assertEq(other.syncCallCount(), 0, "No kernel sync may survive the reverted batch");
    }

    /**
     * @notice State-order pin: with registry [M, B, C], a mid-batch remove(M)+add(D) swap-and-pops C into the
     *         already-visited index 0 and appends D, so the cached-length loop syncs M, B, and D but silently
     *         skips C for this batch
     * @dev EnumerableSet trace: [M, B, C] --remove(M)--> [C, B] --add(D)--> [C, B, D]; loop visits indices 0 (M,
     *      already called), 1 (B), 2 (D)
     */
    function test_reentrancy_registrySwapMidBatch_syncsSwappedInKernelAndSkipsSwappedOne() external {
        RegistryMutatingKernel mutator = new RegistryMutatingKernel(syncer);
        CountingKernel kernelB = new CountingKernel();
        CountingKernel kernelC = new CountingKernel();
        CountingKernel kernelD = new CountingKernel();
        mutator.configureMutation(_single(address(mutator)), _single(address(kernelD)));
        _grantSyncRole(address(mutator));

        address[] memory registered = new address[](3);
        registered[0] = address(mutator);
        registered[1] = address(kernelB);
        registered[2] = address(kernelC);
        _addKernels(registered);

        vm.prank(SYNC_OPERATOR_ADDRESS);
        syncer.executeBatchAccountingSync(true);

        assertEq(mutator.syncCallCount(), 1, "The mutating kernel must have been synced before removing itself");
        assertEq(kernelB.syncCallCount(), 1, "Kernel B kept its index and must have been synced");
        assertEq(kernelC.syncCallCount(), 0, "Kernel C was swapped into the already-visited index 0 and must have been silently skipped");
        assertEq(kernelD.syncCallCount(), 1, "Kernel D was appended mid-batch inside the cached length and must have been synced");

        // Final registry reflects the mid-batch mutation exactly
        assertFalse(syncer.isMarketKernelRegistered(address(mutator)), "The mutating kernel must remain removed");
        assertTrue(syncer.isMarketKernelRegistered(address(kernelC)), "Kernel C must still be registered despite being skipped");
        assertTrue(syncer.isMarketKernelRegistered(address(kernelD)), "Kernel D must remain registered");
        assertEq(syncer.getMarketKernels().length, 3, "The registry must hold exactly B, C, and D after the batch");
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // SECTION 3: RETURNDATA BOMBS AND GAS GRIEFING
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * @notice A kernel reverting with a 50 KiB (51,200-byte) payload must be tolerated: the batch completes and the
     *         AccountingSyncFailed event carries all 51,200 bytes byte-exactly with canonical ABI encoding
     */
    function test_executeBatchSyncFor_revertBomb50KiB_tolerant_emitsExactBytes() external {
        RevertBombKernel bomb = new RevertBombKernel(51_200);
        CountingKernel innocent = new CountingKernel();
        bytes memory expectedPayload = bomb.buildBombPayload();

        address[] memory batch = new address[](2);
        batch[0] = address(bomb);
        batch[1] = address(innocent);

        vm.recordLogs();
        vm.prank(SYNC_OPERATOR_ADDRESS);
        syncer.executeBatchAccountingSyncFor(batch, true);

        Vm.Log[] memory failures = _accountingSyncFailedLogs();
        assertEq(failures.length, 1, "Only the bombing kernel should fail");
        assertEq(failures[0].topics[1], bytes32(uint256(uint160(address(bomb)))), "The failure must be attributed to the bombing kernel");
        assertEq(failures[0].data, abi.encode(expectedPayload), "The 50 KiB bomb must be emitted byte-exactly with canonical ABI encoding");
        assertEq(innocent.syncCallCount(), 1, "The kernel after the bomb must still be synced");
    }

    /// @notice An intolerant batch must bubble a 50 KiB revert bomb upstream byte-exactly
    function test_executeBatchSyncFor_revertBomb50KiB_notTolerant_bubblesExactBytes() external {
        RevertBombKernel bomb = new RevertBombKernel(51_200);
        bytes memory expectedPayload = bomb.buildBombPayload();

        bytes memory actualRevertData;
        vm.prank(SYNC_OPERATOR_ADDRESS);
        try syncer.executeBatchAccountingSyncFor(_single(address(bomb)), false) {
            revert("The intolerant batch should have reverted");
        } catch (bytes memory revertData) {
            actualRevertData = revertData;
        }

        assertEq(actualRevertData.length, 51_200, "All 51,200 bomb bytes must be bubbled");
        assertEq(actualRevertData, expectedPayload, "The bubbled revert bomb must be byte-identical to the kernel's payload");
    }

    /**
     * @notice A kernel returning 1 MiB of returndata on SUCCESS must be ignored cheaply: the dispatch uses
     *         zero-length out params, so the batch completes within a 10M gas cap and emits nothing
     */
    function test_executeBatchSyncFor_successReturndataBomb_isIgnoredCheaply() external {
        SuccessReturndataBombKernel bomb = new SuccessReturndataBombKernel();
        CountingKernel innocent = new CountingKernel();

        address[] memory batch = new address[](2);
        batch[0] = address(bomb);
        batch[1] = address(innocent);

        vm.recordLogs();
        vm.prank(SYNC_OPERATOR_ADDRESS);
        (bool success, bytes memory returnData) = address(syncer).call{ gas: 10_000_000 }(
            abi.encodeCall(RoycoMarketSyncer.executeBatchAccountingSyncFor, (batch, true))
        );

        assertTrue(success, "A 1 MiB success-path returndata bomb must not break or noticeably burden the batch");
        assertEq(returnData.length, 0, "The batch itself returns nothing");
        assertEq(bomb.syncCallCount(), 1, "The bombing kernel's sync must have executed");
        assertEq(innocent.syncCallCount(), 1, "The kernel after the bomb must still be synced");
        assertEq(_accountingSyncFailedLogs().length, 0, "A successful sync must never emit a failure event");
    }

    /**
     * @notice A kernel that consumes ALL forwarded gas (INVALID opcode) under a realistic 20M gas cap: the EVM's
     *         63/64 retention leaves the tolerant batch enough gas to record the failure (empty errorData, since an
     *         all-gas-consuming kernel returns no data) and finish syncing the remaining kernels
     */
    function test_executeBatchSyncFor_gasBombKernel_tolerant_batchCompletesVia63of64Retention() external {
        GasBombKernel bomb = new GasBombKernel();
        CountingKernel innocent = new CountingKernel();

        address[] memory batch = new address[](2);
        batch[0] = address(bomb);
        batch[1] = address(innocent);

        vm.recordLogs();
        vm.prank(SYNC_OPERATOR_ADDRESS);
        (bool success,) = address(syncer).call{ gas: 20_000_000 }(abi.encodeCall(RoycoMarketSyncer.executeBatchAccountingSyncFor, (batch, true)));

        assertTrue(success, "The tolerant batch must survive an all-gas-consuming kernel thanks to 63/64 gas retention");
        Vm.Log[] memory failures = _accountingSyncFailedLogs();
        assertEq(failures.length, 1, "The gas bomb must be recorded as a single failed sync");
        assertEq(failures[0].topics[1], bytes32(uint256(uint160(address(bomb)))), "The failure must be attributed to the gas bomb");
        assertEq(failures[0].data, abi.encode(bytes("")), "An all-gas-consuming kernel leaves no returndata, so errorData must be empty");
        assertEq(innocent.syncCallCount(), 1, "The kernel after the gas bomb must still be synced with the retained gas");
    }

    /// @notice An intolerant batch hit by an all-gas-consuming kernel reverts with EMPTY revert data (OOG leaves none)
    function test_executeBatchSyncFor_gasBombKernel_notTolerant_revertsWithEmptyData() external {
        GasBombKernel bomb = new GasBombKernel();
        CountingKernel innocent = new CountingKernel();

        address[] memory batch = new address[](2);
        batch[0] = address(bomb);
        batch[1] = address(innocent);

        vm.prank(SYNC_OPERATOR_ADDRESS);
        (bool success, bytes memory returnData) = address(syncer).call{ gas: 20_000_000 }(
            abi.encodeCall(RoycoMarketSyncer.executeBatchAccountingSyncFor, (batch, false))
        );

        assertFalse(success, "The intolerant batch must revert when a kernel consumes all forwarded gas");
        assertEq(returnData.length, 0, "The propagated revert data must be empty because the gas bomb returned none");
        assertEq(innocent.syncCallCount(), 0, "Kernels after the gas bomb must not have been synced");
    }

    /// @notice The registered-kernel batch path (executeBatchAccountingSync) also survives a gas bomb when tolerant
    function test_executeBatchSync_gasBombKernel_tolerant_registeredBatchCompletes() external {
        GasBombKernel bomb = new GasBombKernel();
        CountingKernel innocent = new CountingKernel();

        address[] memory registered = new address[](2);
        registered[0] = address(bomb);
        registered[1] = address(innocent);
        _addKernels(registered);

        vm.recordLogs();
        vm.prank(SYNC_OPERATOR_ADDRESS);
        syncer.executeBatchAccountingSync(true);

        Vm.Log[] memory failures = _accountingSyncFailedLogs();
        assertEq(failures.length, 1, "The gas bomb must be recorded as the only failed sync");
        assertEq(failures[0].data, abi.encode(bytes("")), "The gas bomb's errorData must be empty");
        assertEq(innocent.syncCallCount(), 1, "The registered kernel after the gas bomb must still be synced");
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // SECTION 4: BATCH AND REGISTRY SET SEMANTICS
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * @notice Duplicate kernels in executeBatchAccountingSyncFor calldata are intentionally not deduplicated: a
     *         failing kernel listed three times is attempted three times and emits three identical failure events
     * @dev The success-path duplicate pin lives in RoycoMarketSyncerTest; this covers the failure path
     */
    function test_executeBatchSyncFor_duplicateFailingKernel_emitsOneEventPerOccurrence() external {
        RevertBombKernel failing = new RevertBombKernel(32);
        bytes memory expectedPayload = failing.buildBombPayload();

        address[] memory batch = new address[](3);
        batch[0] = address(failing);
        batch[1] = address(failing);
        batch[2] = address(failing);

        vm.recordLogs();
        vm.prank(SYNC_OPERATOR_ADDRESS);
        syncer.executeBatchAccountingSyncFor(batch, true);

        Vm.Log[] memory failures = _accountingSyncFailedLogs();
        assertEq(failures.length, 3, "Each duplicate occurrence must be attempted and emit its own failure event");
        for (uint256 i = 0; i < failures.length; i++) {
            assertEq(failures[i].topics[1], bytes32(uint256(uint160(address(failing)))), "Every failure must be attributed to the duplicated kernel");
            assertEq(failures[i].data, abi.encode(expectedPayload), "Every duplicate failure must carry identical byte-exact errorData");
        }
    }

    /// @notice Duplicate kernels in the initialize array hit the same set-addition guard as addMarketKernels
    function test_initialize_duplicateKernelsInInitialArray_reverts() external {
        RoycoMarketSyncer newImpl = new RoycoMarketSyncer();
        address kernel = address(new CountingKernel());
        address[] memory duplicates = new address[](2);
        duplicates[0] = kernel;
        duplicates[1] = kernel;

        vm.expectRevert(abi.encodeWithSelector(RoycoMarketSyncer.KERNEL_ALREADY_REGISTERED.selector, kernel));
        new ERC1967Proxy(address(newImpl), abi.encodeCall(RoycoMarketSyncer.initialize, (address(roycoAuthority), duplicates)));
    }

    /// @notice A registered batch of 200 kernels syncs every kernel exactly once in a single call
    function test_executeBatchSync_twoHundredRegisteredKernels_allSyncedExactlyOnce() external {
        uint256 numKernels = 200;
        address[] memory kernels = new address[](numKernels);
        for (uint256 i = 0; i < numKernels; i++) {
            kernels[i] = address(new CountingKernel());
        }
        _addKernels(kernels);
        assertEq(syncer.getMarketKernels().length, numKernels, "All 200 kernels must be registered");

        vm.prank(SYNC_OPERATOR_ADDRESS);
        syncer.executeBatchAccountingSync(true);

        for (uint256 i = 0; i < numKernels; i++) {
            assertEq(CountingKernel(kernels[i]).syncCallCount(), 1, "Every one of the 200 registered kernels must be synced exactly once");
        }
    }

    /**
     * @notice Fuzz: add-then-remove-then-readd registry sequences keep getMarketKernels and isMarketKernelRegistered
     *         mutually consistent against an independently derived membership model
     * @param _seed Entropy for deriving the distinct kernel addresses
     * @param _countSeed Bound to [1, 16] kernels so removal masks cover the full population
     * @param _removalMask Bit i decides whether kernel i is removed in the middle phase
     */
    function testFuzz_registry_addRemoveReaddConsistency(uint256 _seed, uint8 _countSeed, uint16 _removalMask) external {
        uint256 numKernels = bound(uint256(_countSeed), 1, 16);

        // Derive distinct kernel addresses (keccak-derived, so collisions are cryptographically negligible)
        address[] memory all = new address[](numKernels);
        for (uint256 i = 0; i < numKernels; i++) {
            all[i] = address(uint160(uint256(keccak256(abi.encode(_seed, i)))));
        }
        _addKernels(all);

        // Independently derive the removal subset from the mask
        uint256 numRemoved = 0;
        for (uint256 i = 0; i < numKernels; i++) {
            if ((_removalMask >> i) & 1 == 1) numRemoved++;
        }
        address[] memory removed = new address[](numRemoved);
        uint256 cursor = 0;
        for (uint256 i = 0; i < numKernels; i++) {
            if ((_removalMask >> i) & 1 == 1) removed[cursor++] = all[i];
        }

        vm.prank(SYNC_OPERATOR_ADDRESS);
        syncer.removeMarketKernels(removed);

        // Membership must match the mask-derived model exactly
        for (uint256 i = 0; i < numKernels; i++) {
            bool expectRemoved = (_removalMask >> i) & 1 == 1;
            assertEq(syncer.isMarketKernelRegistered(all[i]), !expectRemoved, "Membership after removal must match the independently derived model");
        }
        address[] memory values = syncer.getMarketKernels();
        assertEq(values.length, numKernels - numRemoved, "Registry cardinality must equal additions minus removals");
        for (uint256 i = 0; i < values.length; i++) {
            assertTrue(syncer.isMarketKernelRegistered(values[i]), "Every enumerated kernel must also report as registered");
        }

        // Re-adding the removed kernels must restore full membership
        vm.prank(SYNC_OPERATOR_ADDRESS);
        syncer.addMarketKernels(removed);
        for (uint256 i = 0; i < numKernels; i++) {
            assertTrue(syncer.isMarketKernelRegistered(all[i]), "Every kernel must be registered again after the re-add");
        }
        assertEq(syncer.getMarketKernels().length, numKernels, "Registry cardinality must be fully restored after the re-add");
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // SECTION 5: STORAGE ISOLATION, PAUSE MATRIX, AND UPGRADE STATE PRESERVATION
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * @notice The hardcoded ERC-7201 slot must equal its formula, and the raw slot word must track the registry's
     *         set length (the AddressSet's underlying bytes32[] length lives at the base slot)
     */
    function test_storage_erc7201SlotMatchesDerivationAndTracksSetLength() external {
        bytes32 derived = keccak256(abi.encode(uint256(keccak256("Royco.storage.RoycoMarketSyncerState")) - 1)) & ~bytes32(uint256(0xff));
        assertEq(SYNCER_STORAGE_SLOT, derived, "The pinned storage slot must match the ERC-7201 derivation formula");

        assertEq(uint256(vm.load(address(syncer), SYNCER_STORAGE_SLOT)), 0, "The raw base slot must read 0 while the registry is empty");

        address[] memory kernels = new address[](3);
        kernels[0] = address(new CountingKernel());
        kernels[1] = address(new CountingKernel());
        kernels[2] = address(new CountingKernel());
        _addKernels(kernels);
        assertEq(uint256(vm.load(address(syncer), SYNCER_STORAGE_SLOT)), 3, "The raw base slot must equal the registered kernel count");

        vm.prank(SYNC_OPERATOR_ADDRESS);
        syncer.removeMarketKernels(_single(kernels[1]));
        assertEq(uint256(vm.load(address(syncer), SYNCER_STORAGE_SLOT)), 2, "The raw base slot must shrink with removals");
    }

    /**
     * @notice The raw ERC-7201 slot and full registry contents must be bit-identical before and after heavy
     *         adversarial traffic (bombs, failures, duplicates, rejected unauthorized calls)
     */
    function test_storage_slotUnchangedAfterHeavyAdversarialOperations() external {
        address[] memory kernels = new address[](3);
        kernels[0] = address(new CountingKernel());
        kernels[1] = address(new RevertBombKernel(51_200));
        kernels[2] = address(new GasBombKernel());
        _addKernels(kernels);

        bytes32 slotBefore = vm.load(address(syncer), SYNCER_STORAGE_SLOT);
        address[] memory valuesBefore = syncer.getMarketKernels();

        // Heavy adversarial traffic: two full registered batches plus a duplicate-riddled ad hoc batch, each
        // gas-capped at 20M so the gas bomb burns a bounded amount instead of 63/64 of the whole test's gas
        address[] memory adHocBatch = new address[](4);
        adHocBatch[0] = kernels[0];
        adHocBatch[1] = kernels[0];
        adHocBatch[2] = kernels[1];
        adHocBatch[3] = kernels[2];
        bytes[] memory trafficPayloads = new bytes[](3);
        trafficPayloads[0] = abi.encodeCall(RoycoMarketSyncer.executeBatchAccountingSync, (true));
        trafficPayloads[1] = abi.encodeCall(RoycoMarketSyncer.executeBatchAccountingSync, (true));
        trafficPayloads[2] = abi.encodeCall(RoycoMarketSyncer.executeBatchAccountingSyncFor, (adHocBatch, true));
        for (uint256 i = 0; i < trafficPayloads.length; i++) {
            vm.prank(SYNC_OPERATOR_ADDRESS);
            (bool trafficSuccess,) = address(syncer).call{ gas: 20_000_000 }(trafficPayloads[i]);
            assertTrue(trafficSuccess, "Every tolerant adversarial batch must complete");
        }

        // A rejected unauthorized mutation attempt must also leave no trace
        vm.prank(UNAUTHORIZED_USER_ADDRESS);
        (bool success,) = address(syncer).call(abi.encodeCall(RoycoMarketSyncer.addMarketKernels, (_single(makeAddr("Sneaky")))));
        assertFalse(success, "The unauthorized mutation attempt must be rejected");

        assertEq(vm.load(address(syncer), SYNCER_STORAGE_SLOT), slotBefore, "The raw ERC-7201 base slot must be unchanged by sync traffic");
        assertEq(
            uint256(vm.load(address(syncer), bytes32(uint256(SYNCER_STORAGE_SLOT) + 1))),
            0,
            "The mapping slot adjacent to the base slot must remain untouched (mappings never write their own slot)"
        );
        address[] memory valuesAfter = syncer.getMarketKernels();
        assertEq(valuesAfter.length, valuesBefore.length, "Registry cardinality must be unchanged by sync traffic");
        for (uint256 i = 0; i < valuesAfter.length; i++) {
            assertEq(valuesAfter[i], valuesBefore[i], "Registry contents and ordering must be unchanged by sync traffic");
        }
    }

    /**
     * @notice A paused syncer must block all four operational functions with EnforcedPause even for the SYNC_ROLE
     *         holder (whenNotPaused runs before the access check in the modifier order)
     */
    function test_pause_blocksAllFourOperationalFunctionsForRoleHolder() external {
        address[] memory one = _single(address(new CountingKernel()));

        vm.prank(PAUSER_ADDRESS);
        syncer.pause();

        bytes[] memory payloads = new bytes[](4);
        payloads[0] = abi.encodeCall(RoycoMarketSyncer.executeBatchAccountingSync, (true));
        payloads[1] = abi.encodeCall(RoycoMarketSyncer.executeBatchAccountingSyncFor, (one, true));
        payloads[2] = abi.encodeCall(RoycoMarketSyncer.addMarketKernels, (one));
        payloads[3] = abi.encodeCall(RoycoMarketSyncer.removeMarketKernels, (one));

        for (uint256 i = 0; i < payloads.length; i++) {
            vm.prank(SYNC_OPERATOR_ADDRESS);
            (bool success, bytes memory returnData) = address(syncer).call(payloads[i]);
            assertFalse(success, string.concat("Operational payload index ", vm.toString(i), " must be blocked while paused"));
            assertEq(
                returnData,
                abi.encodeWithSelector(PausableUpgradeable.EnforcedPause.selector),
                string.concat("Operational payload index ", vm.toString(i), " must revert with exactly EnforcedPause")
            );
        }
    }

    /**
     * @notice Upgrading to a V2 implementation must preserve the registered kernel set, the raw ERC-7201 slot, the
     *         authority wiring, and full operational capability, while exposing the new V2 surface
     */
    function test_upgrade_preservesRegisteredKernelsAndOperationalState() external {
        CountingKernel kernel1 = new CountingKernel();
        CountingKernel kernel2 = new CountingKernel();
        CountingKernel kernel3 = new CountingKernel();
        address[] memory kernels = new address[](3);
        kernels[0] = address(kernel1);
        kernels[1] = address(kernel2);
        kernels[2] = address(kernel3);
        _addKernels(kernels);

        bytes32 slotBefore = vm.load(address(syncer), SYNCER_STORAGE_SLOT);
        address[] memory valuesBefore = syncer.getMarketKernels();

        // Upgrade to the V2 mock implementation through the authorized upgrader
        RoycoMarketSyncerV2Mock v2Impl = new RoycoMarketSyncerV2Mock();
        vm.prank(DEPLOYER_ADDRESS);
        syncer.upgradeToAndCall(address(v2Impl), "");

        // The V2 surface must be live and every piece of pre-upgrade state intact
        assertEq(RoycoMarketSyncerV2Mock(address(syncer)).syncerImplementationVersion(), 2, "The proxy must serve the V2 implementation after the upgrade");
        assertEq(syncer.authority(), address(roycoAuthority), "The authority must be preserved across the upgrade");
        assertEq(vm.load(address(syncer), SYNCER_STORAGE_SLOT), slotBefore, "The raw ERC-7201 base slot must be preserved across the upgrade");
        address[] memory valuesAfter = syncer.getMarketKernels();
        assertEq(valuesAfter.length, valuesBefore.length, "The registered kernel count must be preserved across the upgrade");
        for (uint256 i = 0; i < valuesAfter.length; i++) {
            assertEq(valuesAfter[i], valuesBefore[i], "Registered kernels and their ordering must be preserved across the upgrade");
            assertTrue(syncer.isMarketKernelRegistered(valuesAfter[i]), "Every pre-upgrade kernel must still report as registered");
        }

        // The upgraded syncer must remain fully operational under the same roles
        vm.prank(SYNC_OPERATOR_ADDRESS);
        syncer.executeBatchAccountingSync(true);
        assertEq(kernel1.syncCallCount(), 1, "Kernel 1 must be syncable through the upgraded implementation");
        assertEq(kernel2.syncCallCount(), 1, "Kernel 2 must be syncable through the upgraded implementation");
        assertEq(kernel3.syncCallCount(), 1, "Kernel 3 must be syncable through the upgraded implementation");
    }
}
