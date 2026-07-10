// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

/**
 * @title IRoycoKernel
 * @notice Abridged interface for a Royco kernel, containing only the functions consumed by periphery contracts
 * @dev Every function declared here is ABI-identical on Royco Dawn and Royco Day kernels
 */
interface IRoycoKernel {
    /// @notice Retrieves the ST asset address
    /// @return stAsset The senior tranche's base asset address
    function ST_ASSET() external view returns (address stAsset);

    /// @notice Retrieves the JT asset address
    /// @return jtAsset The junior tranche's base asset address
    function JT_ASSET() external view returns (address jtAsset);

    /**
     * @notice Synchronizes and persists the raw and effective NAVs of the market's tranches
     * @dev Declared without its return value: the synced accounting state struct is protocol-specific (14 fields on Royco
     *      Dawn, 18 on Royco Day) while the selector is identical, so periphery callers intentionally ignore the return
     *      data and invoke this function via low-level calls
     */
    function syncTrancheAccounting() external;
}
