// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.1
pragma solidity ^0.8.28;

/**
 * @title TrancheType
 * @dev Defines the types of Royco tranches deployed per market
 * @custom:type SENIOR - The identifier for the senior tranche (protected capital)
 * @custom:type JUNIOR - The identifier for the junior tranche (first-loss capital)
 * @custom:type LIQUIDITY - The identifier for the liquidity tranche (market-making capital)
 */
enum TrancheType {
    SENIOR,
    JUNIOR,
    LIQUIDITY
}
