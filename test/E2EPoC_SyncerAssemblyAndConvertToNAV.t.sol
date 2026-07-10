// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import { Test, Vm } from "../lib/forge-std/src/Test.sol";
import { AccessManager } from "../lib/openzeppelin-contracts/contracts/access/manager/AccessManager.sol";
import { ERC1967Proxy } from "../lib/openzeppelin-contracts/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import { PeripheryUtilsLib } from "../src/libraries/PeripheryUtilsLib.sol";
import { TrancheType } from "../src/libraries/Types.sol";
import { NAV_UNIT, toUint256 } from "../src/libraries/Units.sol";
import { RoycoMarketSyncer } from "../src/syncer/RoycoMarketSyncer.sol";
import { MockTranche } from "./mock/MockTranche.sol";

/// @notice Kernel that reverts with an exact-length payload and records the calldata it received
contract RevertingKernel {
    bytes public payloadToRevertWith;
    bool public shouldRevert;
    bytes public lastCalldata;

    function setRevertPayload(bytes calldata _payload) external {
        payloadToRevertWith = _payload;
        shouldRevert = true;
    }

    function setSucceed() external {
        shouldRevert = false;
    }

    fallback() external {
        lastCalldata = msg.data;
        if (shouldRevert) {
            bytes memory p = payloadToRevertWith;
            assembly {
                revert(add(p, 0x20), mload(p))
            }
        }
    }
}

/// @notice Staticcall-safe reverter (no state writes) for exercising convertToNAV's revert bubbling
contract ViewReverter {
    bytes public payloadToRevertWith;

    function setRevertPayload(bytes calldata _payload) external {
        payloadToRevertWith = _payload;
    }

    fallback() external {
        bytes memory p = payloadToRevertWith;
        assembly {
            revert(add(p, 0x20), mload(p))
        }
    }
}

contract NAVHarness {
    function callConvertToNAV(address _tranche, uint256 _shares) external view returns (uint256) {
        return toUint256(PeripheryUtilsLib.convertToNAV(_tranche, _shares));
    }
}

contract E2EPoC_SyncerAssemblyAndConvertToNAV is Test {
    bytes32 internal constant TOPIC = keccak256("AccountingSyncFailed(address,bytes)");

    RoycoMarketSyncer internal syncer;
    RevertingKernel internal kernel;

    function setUp() external {
        AccessManager manager = new AccessManager(address(this));
        syncer = RoycoMarketSyncer(
            address(new ERC1967Proxy(address(new RoycoMarketSyncer()), abi.encodeCall(RoycoMarketSyncer.initialize, (address(manager), new address[](0)))))
        );
        kernel = new RevertingKernel();
        address[] memory kernels = new address[](1);
        kernels[0] = address(kernel);
        syncer.addMarketKernels(kernels);
    }

    /// @notice The emitted AccountingSyncFailed data must be canonically ABI encoded for every payload size class
    function test_poc_accountingSyncFailedEventBytes_exactCanonicalEncoding() external {
        uint256[6] memory sizes = [uint256(0), 1, 4, 32, 36, 100];
        for (uint256 s = 0; s < sizes.length; s++) {
            bytes memory payload = new bytes(sizes[s]);
            for (uint256 j = 0; j < payload.length; j++) {
                payload[j] = 0xFF; // worst case: all-ones so stale memory/padding bugs surface
            }
            kernel.setRevertPayload(payload);

            // Dirty the syncer-side free memory tail is not directly possible; instead run twice so the second
            // run reuses memory that previously held a longer payload (checks the padding-zero word)
            vm.recordLogs();
            syncer.executeBatchAccountingSync(true);
            Vm.Log[] memory logs = vm.getRecordedLogs();
            assertEq(logs.length, 1, "expected exactly one log");
            assertEq(logs[0].emitter, address(syncer), "wrong emitter");
            assertEq(logs[0].topics.length, 2, "expected 2 topics");
            assertEq(logs[0].topics[0], TOPIC, "topic0 mismatch vs recomputed signature hash");
            assertEq(logs[0].topics[1], bytes32(uint256(uint160(address(kernel)))), "kernel topic mismatch");
            assertEq(keccak256(logs[0].data), keccak256(abi.encode(payload)), "log data not canonical abi.encode(bytes)");
        }

        // Descending sizes: a 100-byte all-0xFF payload followed by a 36-byte one exercises the padding-zero word
        // against stale 0xFF bytes left in the same memory region within a single call frame
        RevertingKernel k2 = new RevertingKernel();
        bytes memory big = new bytes(100);
        bytes memory small = new bytes(36);
        for (uint256 j = 0; j < 100; j++) {
            big[j] = 0xEE;
        }
        for (uint256 j = 0; j < 36; j++) {
            small[j] = 0xDD;
        }
        kernel.setRevertPayload(big);
        k2.setRevertPayload(small);
        address[] memory both = new address[](2);
        both[0] = address(kernel);
        both[1] = address(k2);
        vm.recordLogs();
        syncer.executeBatchAccountingSyncFor(both, true);
        Vm.Log[] memory logs2 = vm.getRecordedLogs();
        assertEq(logs2.length, 2, "expected two logs");
        assertEq(keccak256(logs2[0].data), keccak256(abi.encode(big)), "big payload data mismatch");
        assertEq(keccak256(logs2[1].data), keccak256(abi.encode(small)), "small payload not canonical after larger payload reuse");
    }

    /// @notice tolerate=false must propagate the exact downstream revert bytes
    function test_poc_intolerantSync_bubblesExactRevertData() external {
        bytes memory payload = abi.encodeWithSignature("Error(string)", "boom");
        kernel.setRevertPayload(payload);
        vm.expectRevert(bytes("boom"));
        syncer.executeBatchAccountingSync(false);
    }

    /// @notice The kernel must receive exactly the 4-byte syncTrancheAccounting selector
    function test_poc_syncCalldata_isExactSelector() external {
        kernel.setSucceed();
        syncer.executeBatchAccountingSync(false);
        bytes memory received = kernel.lastCalldata();
        assertEq(received.length, 4, "calldata must be exactly 4 bytes");
        assertEq(bytes4(received), bytes4(keccak256("syncTrancheAccounting()")), "selector mismatch");
    }

    /// @notice convertToNAV reads the trailing word regardless of middle-word count; empty returndata yields 0
    function test_poc_convertToNAV_lastWordAndEdgeCases() external {
        NAVHarness harness = new NAVHarness();
        MockTranche tranche = new MockTranche(address(new RevertingKernel()), address(this), TrancheType.SENIOR);
        // Mint some supply so the mock has a NAV to report: deposit path requires the asset; instead drive sharePrice directly
        // MockTranche._convertToAssets uses sharePriceWAD, no supply needed for conversion
        tranche.setSharePrice(2e18);

        // Dawn shape: [stAssets][jtAssets][nav]
        tranche.setConvertToAssetsMiddleWords(0);
        assertEq(harness.callConvertToNAV(address(tranche), 1e18), 2e18, "dawn-shape NAV mismatch");

        // Day shape: [stAssets][jtAssets][ltAssets][stShares][nav]
        tranche.setConvertToAssetsMiddleWords(2);
        assertEq(harness.callConvertToNAV(address(tranche), 1e18), 2e18, "day-shape NAV mismatch");

        // Future shape with 7 middle words
        tranche.setConvertToAssetsMiddleWords(7);
        assertEq(harness.callConvertToNAV(address(tranche), 1e18), 2e18, "future-shape NAV mismatch");

        // Empty returndata (EOA target): staticcall succeeds with 0 bytes -> NAV 0
        assertEq(harness.callConvertToNAV(address(0xBEEF), 1e18), 0, "empty returndata must yield 0");

        // Revert bubbling
        ViewReverter reverter = new ViewReverter();
        reverter.setRevertPayload(abi.encodeWithSignature("Error(string)", "nav-broken"));
        vm.expectRevert(bytes("nav-broken"));
        harness.callConvertToNAV(address(reverter), 1e18);
    }
}
