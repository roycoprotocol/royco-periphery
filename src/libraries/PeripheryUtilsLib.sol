// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import { IRoycoVaultTranche } from "../interfaces/IRoycoVaultTranche.sol";
import { NAV_UNIT } from "./Units.sol";

/**
 * @title PeripheryUtilsLib
 * @author Waymont
 * @notice A library providing utility functions for Royco periphery contracts
 */
library PeripheryUtilsLib {
    /**
     * @notice Converts a specified number of tranche shares to their net asset value using the tranche's current exchange rate
     * @dev The NAV is read from the last 32 bytes of the return data: `nav` is the final field of `convertToAssets`'s returned struct on every Royco protocol version
     * @dev Uses low-level calls to gracefully handle reversions and protocol-specific return encodings, bubbling up the revert reason on failure
     * @param _tranche The Royco tranche to query
     * @param _shares The number of tranche shares to convert to NAV units
     * @return nav The net asset value of the specified shares in NAV units
     */
    function convertToNAV(address _tranche, uint256 _shares) internal view returns (NAV_UNIT nav) {
        // Query the tranche for the asset claims backing the specified number of shares
        (bool success, bytes memory returnData) = _tranche.staticcall(abi.encodeCall(IRoycoVaultTranche.convertToAssets, (_shares)));
        assembly ("memory-safe") {
            // If the query reverted, revert with the downstream error
            if iszero(success) {
                revert(add(returnData, 0x20), mload(returnData))
            }
            // Read the NAV from the last 32 bytes of the return data
            nav := mload(add(returnData, mload(returnData)))
        }
    }
}
