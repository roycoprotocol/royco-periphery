// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import { Test } from "../../lib/forge-std/src/Test.sol";
import { Vm } from "../../lib/forge-std/src/Vm.sol";

import { ERC20Mock } from "../../lib/openzeppelin-contracts/contracts/mocks/token/ERC20Mock.sol";

import { WAD } from "../../src/libraries/Constants.sol";
import { TrancheType } from "../../src/libraries/Types.sol";
import { RoycoTrancheChainlinkOracle } from "../../src/oracle/tranche-share-to-nav-oracle/RoycoTrancheChainlinkOracle.sol";
import { RoycoTrancheChainlinkOracleFactory } from "../../src/oracle/tranche-share-to-nav-oracle/RoycoTrancheChainlinkOracleFactory.sol";

import { MockTranche } from "../mock/MockTranche.sol";

/// @title RoycoTrancheChainlinkOracleFactoryTest
/// @notice Audit-grade unit tests for RoycoTrancheChainlinkOracleFactory backed by MockTranche
/// @dev The factory is permissionless and intentionally does NOT verify tranche provenance (no Royco factory lookup),
///      keeping deployments protocol-agnostic across Royco Dawn and Day. Tests that previously asserted
///      INVALID_TRANCHE for non-factory tranches now assert that deployment succeeds for any non-null tranche.
contract RoycoTrancheChainlinkOracleFactoryTest is Test {
    /// =====================================================================
    /// STATE
    /// =====================================================================
    ERC20Mock internal asset;
    MockTranche internal seniorTranche;
    MockTranche internal juniorTranche;
    RoycoTrancheChainlinkOracleFactory internal oracleFactory;

    /// @dev Placeholder authority passed to the mock tranches (the oracle factory never queries it)
    address internal constant FACTORY_PLACEHOLDER = address(0xF);

    /// @dev Mirrored from RoycoTrancheChainlinkOracleFactory for vm.expectEmit
    event OracleDeployed(address indexed tranche, address indexed oracle);

    /// =====================================================================
    /// SETUP
    /// =====================================================================

    function setUp() public {
        asset = new ERC20Mock();

        seniorTranche = new MockTranche(address(asset), FACTORY_PLACEHOLDER, TrancheType.SENIOR);
        juniorTranche = new MockTranche(address(asset), FACTORY_PLACEHOLDER, TrancheType.JUNIOR);

        oracleFactory = new RoycoTrancheChainlinkOracleFactory();
    }

    /// =====================================================================
    /// deployOracle - happy path
    /// =====================================================================

    function test_deployOracle_seniorTranche() public {
        address predicted = oracleFactory.predictOracleAddress(address(seniorTranche));

        vm.expectEmit(true, true, false, false, address(oracleFactory));
        emit OracleDeployed(address(seniorTranche), predicted);

        address deployed = oracleFactory.deployOracle(address(seniorTranche));

        assertEq(deployed, predicted);
        assertGt(deployed.code.length, 0);
        assertEq(oracleFactory.trancheToOracle(address(seniorTranche)), deployed);
    }

    function test_deployOracle_juniorTranche() public {
        address predicted = oracleFactory.predictOracleAddress(address(juniorTranche));

        vm.expectEmit(true, true, false, false, address(oracleFactory));
        emit OracleDeployed(address(juniorTranche), predicted);

        address deployed = oracleFactory.deployOracle(address(juniorTranche));

        assertEq(deployed, predicted);
        assertGt(deployed.code.length, 0);
        assertEq(oracleFactory.trancheToOracle(address(juniorTranche)), deployed);
    }

    function test_deployOracle_oracleWiredToCorrectTranche() public {
        address deployed = oracleFactory.deployOracle(address(seniorTranche));
        assertEq(RoycoTrancheChainlinkOracle(deployed).ROYCO_TRANCHE(), address(seniorTranche));
    }

    function test_deployOracle_deployedOracleIsFunctional() public {
        // Mock tranche default share price = 1e18, so latestRoundData returns WAD.
        address deployed = oracleFactory.deployOracle(address(seniorTranche));
        (, int256 answer,,,) = RoycoTrancheChainlinkOracle(deployed).latestRoundData();
        assertEq(answer, int256(WAD));
    }

    function test_deployOracle_setsMappingsIndependentlyForBothTranches() public {
        address stOracle = oracleFactory.deployOracle(address(seniorTranche));
        address jtOracle = oracleFactory.deployOracle(address(juniorTranche));

        assertEq(oracleFactory.trancheToOracle(address(seniorTranche)), stOracle);
        assertEq(oracleFactory.trancheToOracle(address(juniorTranche)), jtOracle);
        assertTrue(stOracle != jtOracle);
    }

    function test_deployOracle_returnedAddressMatchesPredict() public {
        address predicted = oracleFactory.predictOracleAddress(address(seniorTranche));
        address deployed = oracleFactory.deployOracle(address(seniorTranche));
        assertEq(deployed, predicted);
    }

    /// =====================================================================
    /// deployOracle - provenance is intentionally NOT verified
    /// =====================================================================
    /// @dev Repurposed from the Royco Dawn INVALID_TRANCHE revert tests: the factory no longer consults any
    ///      canonical Royco factory, so deployment succeeds for any non-null tranche and oracle consumers are
    ///      responsible for vetting the tranche an oracle prices.

    function test_deployOracle_succeedsForAnyTranche_provenanceNotVerified() public {
        // A tranche that no canonical Royco factory knows about deploys successfully.
        MockTranche unvetted = new MockTranche(address(asset), FACTORY_PLACEHOLDER, TrancheType.SENIOR);

        address predicted = oracleFactory.predictOracleAddress(address(unvetted));
        address deployed = oracleFactory.deployOracle(address(unvetted));

        assertEq(deployed, predicted);
        assertEq(oracleFactory.trancheToOracle(address(unvetted)), deployed);
        assertEq(RoycoTrancheChainlinkOracle(deployed).ROYCO_TRANCHE(), address(unvetted));
    }

    function test_deployOracle_succeedsForTrancheFromAnyOrigin() public {
        // Tranches wired to a completely different authority/factory topology deploy just as well.
        address otherFactory = makeAddr("otherFactory");
        MockTranche otherSt = new MockTranche(address(asset), otherFactory, TrancheType.SENIOR);
        MockTranche otherJt = new MockTranche(address(asset), otherFactory, TrancheType.JUNIOR);

        address stOracle = oracleFactory.deployOracle(address(otherSt));
        address jtOracle = oracleFactory.deployOracle(address(otherJt));

        assertEq(oracleFactory.trancheToOracle(address(otherSt)), stOracle);
        assertEq(oracleFactory.trancheToOracle(address(otherJt)), jtOracle);
    }

    function test_deployOracle_succeedsForEOA_noTrancheQueryAtDeployment() public {
        // The oracle constructor performs no call into the tranche, so even a code-less address deploys.
        // The resulting oracle is only as good as the tranche behind it - consumers must vet it.
        address eoa = makeAddr("eoa");
        address predicted = oracleFactory.predictOracleAddress(eoa);

        address deployed = oracleFactory.deployOracle(eoa);

        assertEq(deployed, predicted);
        assertEq(oracleFactory.trancheToOracle(eoa), deployed);
    }

    /// =====================================================================
    /// deployOracle - revert paths
    /// =====================================================================

    function test_deployOracle_revertsOnNullAddress() public {
        vm.expectRevert(RoycoTrancheChainlinkOracleFactory.NULL_ADDRESS.selector);
        oracleFactory.deployOracle(address(0));
    }

    function test_deployOracle_revertsOnRedeploy() public {
        oracleFactory.deployOracle(address(seniorTranche));

        // Second deploy collides at the deterministic CREATE2 address; the `new` opcode reverts.
        vm.expectRevert();
        oracleFactory.deployOracle(address(seniorTranche));
    }

    function test_deployOracle_failedRedeployDoesNotCorruptMapping() public {
        address firstOracle = oracleFactory.deployOracle(address(seniorTranche));

        vm.expectRevert();
        oracleFactory.deployOracle(address(seniorTranche));

        // Mapping still points at the original oracle.
        assertEq(oracleFactory.trancheToOracle(address(seniorTranche)), firstOracle);
    }

    /// =====================================================================
    /// predictOracleAddress
    /// =====================================================================

    function test_predictOracleAddress_isDeterministic() public view {
        address pred1 = oracleFactory.predictOracleAddress(address(seniorTranche));
        address pred2 = oracleFactory.predictOracleAddress(address(seniorTranche));
        assertEq(pred1, pred2);
    }

    function test_predictOracleAddress_differentTranchesProduceDifferentAddresses() public view {
        address stPred = oracleFactory.predictOracleAddress(address(seniorTranche));
        address jtPred = oracleFactory.predictOracleAddress(address(juniorTranche));
        assertTrue(stPred != jtPred);
    }

    function test_predictOracleAddress_callerIndependent() public {
        // predict has no msg.sender dependency: same input from any caller yields the same address.
        address fromThisCaller = oracleFactory.predictOracleAddress(address(seniorTranche));
        vm.prank(makeAddr("randomCaller"));
        address fromAnotherCaller = oracleFactory.predictOracleAddress(address(seniorTranche));
        assertEq(fromThisCaller, fromAnotherCaller);
    }

    function test_predictOracleAddress_doesNotValidateTranche() public {
        // Predict is a pure deterministic function over the tranche address; it does NOT call the tranche.
        // Even an unvetted or non-contract address yields a non-zero prediction.
        address random = makeAddr("random");
        assertTrue(oracleFactory.predictOracleAddress(random) != address(0));
    }

    /// =====================================================================
    /// PERMISSIONLESS / DETERMINISM
    /// =====================================================================

    function test_deployOracle_permissionlessProducesSameAddressAcrossCallers() public {
        address predicted = oracleFactory.predictOracleAddress(address(seniorTranche));

        vm.prank(makeAddr("randomCaller"));
        address deployed = oracleFactory.deployOracle(address(seniorTranche));

        assertEq(deployed, predicted);
    }

    function test_deployOracle_eventCarriesCorrectTrancheAndOracleTopics() public {
        address predicted = oracleFactory.predictOracleAddress(address(juniorTranche));

        vm.recordLogs();
        oracleFactory.deployOracle(address(juniorTranche));
        Vm.Log[] memory logs = vm.getRecordedLogs();

        // Find the OracleDeployed log among possibly-emitted events.
        bytes32 expectedTopic0 = keccak256("OracleDeployed(address,address)");
        bool found;
        for (uint256 i = 0; i < logs.length; ++i) {
            if (logs[i].emitter != address(oracleFactory)) continue;
            if (logs[i].topics.length != 3 || logs[i].topics[0] != expectedTopic0) continue;
            assertEq(address(uint160(uint256(logs[i].topics[1]))), address(juniorTranche));
            assertEq(address(uint160(uint256(logs[i].topics[2]))), predicted);
            found = true;
            break;
        }
        assertTrue(found);
    }

    /// =====================================================================
    /// FUZZ
    /// =====================================================================

    function testFuzz_predictOracleAddress_doesNotRevert(address _tranche) public view {
        // Predict is total: must not revert for any input.
        oracleFactory.predictOracleAddress(_tranche);
    }

    function testFuzz_predictOracleAddress_isDeterministicAcrossInputs(address _trancheA, address _trancheB) public view {
        // Same input → same address; different inputs → different addresses (CREATE2 is collision-resistant for different init codes).
        if (_trancheA == _trancheB) {
            assertEq(oracleFactory.predictOracleAddress(_trancheA), oracleFactory.predictOracleAddress(_trancheB));
        } else {
            assertTrue(oracleFactory.predictOracleAddress(_trancheA) != oracleFactory.predictOracleAddress(_trancheB));
        }
    }

    function testFuzz_deployOracle_callerIndependence(address _caller) public {
        vm.assume(_caller != address(0));
        address predicted = oracleFactory.predictOracleAddress(address(seniorTranche));

        vm.prank(_caller);
        address deployed = oracleFactory.deployOracle(address(seniorTranche));

        assertEq(deployed, predicted);
        assertEq(oracleFactory.trancheToOracle(address(seniorTranche)), deployed);
    }
}
