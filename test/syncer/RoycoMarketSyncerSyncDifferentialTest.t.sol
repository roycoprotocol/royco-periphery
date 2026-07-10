// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import { Test } from "../../lib/forge-std/src/Test.sol";
import { Vm } from "../../lib/forge-std/src/Vm.sol";

import { AccessManager } from "../../lib/openzeppelin-contracts/contracts/access/manager/AccessManager.sol";
import { ERC1967Proxy } from "../../lib/openzeppelin-contracts/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import { IRoycoKernel } from "../../src/interfaces/IRoycoKernel.sol";
import { RoycoMarketSyncer } from "../../src/syncer/RoycoMarketSyncer.sol";

/// @title ReferenceSyncer
/// @notice Plain Solidity reference implementation of the syncer's low level sync dispatch, used as the differential baseline
/// @dev High level Solidity allocates fresh memory for every returndata capture, so its emitted events are canonically
///      ABI encoded by construction — the assembly implementation must match it byte for byte
contract ReferenceSyncer {
    /// @notice Mirrors the syncer's AccountingSyncFailed event
    event AccountingSyncFailed(address indexed kernel, bytes errorData);

    /// @notice Executes the reference sync flow for each specified kernel
    function syncBatch(address[] calldata _marketKernels, bool _tolerateReversions) external {
        for (uint256 i = 0; i < _marketKernels.length; ++i) {
            (bool success, bytes memory returnData) = _marketKernels[i].call(abi.encodeWithSelector(IRoycoKernel.syncTrancheAccounting.selector));
            if (!success) {
                if (!_tolerateReversions) {
                    assembly ("memory-safe") {
                        revert(add(returnData, 0x20), mload(returnData))
                    }
                }
                emit AccountingSyncFailed(_marketKernels[i], returnData);
            }
        }
    }
}

/// @title ConfigurableKernel
/// @notice Sync target that succeeds with configurable return data or reverts with an arbitrary configured payload
contract ConfigurableKernel {
    bytes public revertPayload;
    bool public shouldRevert;
    uint256 public syncCallCount;
    bytes public lastCalldata;

    /// @notice Configures the kernel to revert with the exact specified payload
    function setRevertPayload(bytes calldata _payload) external {
        revertPayload = _payload;
        shouldRevert = true;
    }

    /// @notice Mirrors both protocols' sync entrypoint; matches the selector the syncer dispatches
    function syncTrancheAccounting() external returns (uint256[18] memory dayShapedState) {
        lastCalldata = msg.data;
        if (shouldRevert) {
            bytes memory payload = revertPayload;
            assembly ("memory-safe") {
                revert(add(payload, 0x20), mload(payload))
            }
        }
        syncCallCount++;
        dayShapedState[17] = type(uint256).max;
    }
}

/// @title RoycoMarketSyncerSyncDifferentialTest
/// @notice Differential and boundary tests proving the syncer's assembly sync dispatch is byte equivalent to a plain
///         Solidity reference implementation across arbitrary revert payloads and batch orderings
contract RoycoMarketSyncerSyncDifferentialTest is Test {
    RoycoMarketSyncer internal syncer;
    ReferenceSyncer internal referenceSyncer;

    /// @dev Payload lengths covering every alignment class: empty, sub word, word aligned, word plus selector, and multi word
    uint256[9] internal SIZE_LADDER = [uint256(0), 1, 4, 31, 32, 33, 63, 132, 256];

    function setUp() external {
        // The test contract administers the access manager, so the syncer's restricted surface is admin callable
        AccessManager accessManager = new AccessManager(address(this));
        syncer = RoycoMarketSyncer(
            address(
                new ERC1967Proxy(
                    address(new RoycoMarketSyncer()), abi.encodeCall(RoycoMarketSyncer.initialize, (address(accessManager), new address[](0)))
                )
            )
        );
        referenceSyncer = new ReferenceSyncer();
    }

    /// @notice The hardcoded log topic must equal the keccak256 hash of the event signature
    function test_eventTopicHashMatchesSignature() external {
        vm.recordLogs();
        address kernel = _deployRevertingKernel(hex"deadbeef");
        syncer.executeBatchAccountingSyncFor(_single(kernel), true);
        Vm.Log[] memory logs = vm.getRecordedLogs();
        assertEq(logs[0].topics[0], keccak256("AccountingSyncFailed(address,bytes)"), "Topic 0 should be the event signature hash");
        assertEq(logs[0].topics[1], bytes32(uint256(uint160(kernel))), "Topic 1 should be the indexed kernel");
    }

    /// @notice The syncer must dispatch exactly the 4 byte syncTrancheAccounting selector as calldata
    function test_dispatchesExactlyFourByteSelector() external {
        ConfigurableKernel kernel = new ConfigurableKernel();
        syncer.executeBatchAccountingSyncFor(_single(address(kernel)), false);
        assertEq(kernel.lastCalldata(), abi.encodePacked(IRoycoKernel.syncTrancheAccounting.selector), "Calldata should be exactly the selector");
        assertEq(kernel.syncCallCount(), 1, "The kernel should have executed the sync");
    }

    /// @notice Successful syncs execute state changes and emit nothing, ignoring the kernel's return data
    function test_successPathIgnoresReturnDataAndEmitsNothing() external {
        ConfigurableKernel kernel = new ConfigurableKernel();
        vm.recordLogs();
        syncer.executeBatchAccountingSyncFor(_single(address(kernel)), true);
        assertEq(vm.getRecordedLogs().length, 0, "Successful syncs should emit no events");
        assertEq(kernel.syncCallCount(), 1, "The kernel should have executed the sync");
    }

    /// @notice Intolerant batches bubble the exact downstream revert payload for every alignment class
    function test_bubblesExactRevertPayload_sizeLadder() external {
        for (uint256 i = 0; i < SIZE_LADDER.length; i++) {
            bytes memory payload = _patternedPayload(SIZE_LADDER[i], i);
            address kernel = _deployRevertingKernel(payload);
            (bool success, bytes memory returnData) = address(syncer).call(
                abi.encodeCall(RoycoMarketSyncer.executeBatchAccountingSyncFor, (_single(kernel), false))
            );
            assertFalse(success, "Intolerant batch should revert");
            assertEq(returnData, payload, "Bubbled revert data should be byte identical to the kernel's payload");
        }
    }

    /// @notice Tolerant batches over a descending size ladder emit canonical event data despite maximally dirty scratch memory
    function test_tolerantEventData_descendingSizeLadder() external {
        // Descending sizes force every later payload to land in memory dirtied by a longer earlier one
        address[] memory kernels = new address[](SIZE_LADDER.length);
        bytes[] memory payloads = new bytes[](SIZE_LADDER.length);
        for (uint256 i = 0; i < SIZE_LADDER.length; i++) {
            uint256 size = SIZE_LADDER[SIZE_LADDER.length - 1 - i];
            payloads[i] = _patternedPayload(size, i);
            kernels[i] = _deployRevertingKernel(payloads[i]);
        }

        vm.recordLogs();
        syncer.executeBatchAccountingSyncFor(kernels, true);
        Vm.Log[] memory logs = vm.getRecordedLogs();

        assertEq(logs.length, kernels.length, "Every failed sync should emit an event");
        for (uint256 i = 0; i < logs.length; i++) {
            assertEq(logs[i].topics[1], bytes32(uint256(uint160(kernels[i]))), "Events should be emitted in batch order");
            assertEq(logs[i].data, abi.encode(payloads[i]), "Event data should be canonically ABI encoded");
        }
    }

    /// @notice Differential fuzz: the assembly dispatch must produce byte identical logs to the Solidity reference for any batch
    /// @param _seed Entropy for payload sizes and contents across a mixed success and failure batch
    function testFuzz_differentialAgainstReferenceImplementation(uint256 _seed) external {
        // Build a mixed batch of 5 kernels: fuzzed revert payloads with one interleaved success
        address[] memory kernels = new address[](5);
        for (uint256 i = 0; i < kernels.length; i++) {
            if (i == 2) {
                kernels[i] = address(new ConfigurableKernel());
                continue;
            }
            uint256 size = uint256(keccak256(abi.encode(_seed, i, "size"))) % 300;
            bytes memory payload = new bytes(size);
            for (uint256 j = 0; j < size; j++) {
                payload[j] = bytes1(uint8(uint256(keccak256(abi.encode(_seed, i, j >> 5))) >> ((j & 31) << 3)));
            }
            kernels[i] = _deployRevertingKernel(payload);
        }

        // Run the reference implementation and capture its canonical logs
        vm.recordLogs();
        referenceSyncer.syncBatch(kernels, true);
        Vm.Log[] memory expected = vm.getRecordedLogs();

        // Run the syncer's assembly implementation and capture its logs
        vm.recordLogs();
        syncer.executeBatchAccountingSyncFor(kernels, true);
        Vm.Log[] memory actual = vm.getRecordedLogs();

        // Both implementations must emit identical event sets
        assertEq(actual.length, expected.length, "Log counts should match the reference");
        for (uint256 i = 0; i < actual.length; i++) {
            assertEq(actual[i].topics.length, expected[i].topics.length, "Topic counts should match the reference");
            assertEq(actual[i].topics[0], expected[i].topics[0], "Event signatures should match the reference");
            assertEq(actual[i].topics[1], expected[i].topics[1], "Indexed kernels should match the reference");
            assertEq(actual[i].data, expected[i].data, "Event data should be byte identical to the reference");
        }
    }

    /// @notice Differential fuzz: intolerant batches must bubble byte identical revert data to the reference for any payload
    /// @param _payload The arbitrary revert payload to propagate
    function testFuzz_differentialBubbling(bytes calldata _payload) external {
        vm.assume(_payload.length <= 1024);
        address kernel = _deployRevertingKernel(_payload);

        (bool referenceSuccess, bytes memory referenceData) = address(referenceSyncer).call(abi.encodeCall(ReferenceSyncer.syncBatch, (_single(kernel), false)));
        (bool syncerSuccess, bytes memory syncerData) = address(syncer).call(
            abi.encodeCall(RoycoMarketSyncer.executeBatchAccountingSyncFor, (_single(kernel), false))
        );

        assertFalse(referenceSuccess, "Reference should revert");
        assertFalse(syncerSuccess, "Syncer should revert");
        assertEq(syncerData, referenceData, "Bubbled revert data should be byte identical to the reference");
        assertEq(syncerData, _payload, "Bubbled revert data should be byte identical to the kernel's payload");
    }

    /// @dev Deploys a kernel configured to revert with the exact specified payload
    function _deployRevertingKernel(bytes memory _payload) internal returns (address kernel) {
        ConfigurableKernel configurableKernel = new ConfigurableKernel();
        configurableKernel.setRevertPayload(_payload);
        kernel = address(configurableKernel);
    }

    /// @dev Builds a deterministic patterned payload of the specified size
    function _patternedPayload(uint256 _size, uint256 _salt) internal pure returns (bytes memory payload) {
        payload = new bytes(_size);
        for (uint256 i = 0; i < _size; i++) {
            payload[i] = bytes1(uint8((i + _salt * 37 + 7) % 256));
        }
    }

    /// @dev Wraps a single kernel address in an array
    function _single(address _kernel) internal pure returns (address[] memory kernels) {
        kernels = new address[](1);
        kernels[0] = _kernel;
    }
}
