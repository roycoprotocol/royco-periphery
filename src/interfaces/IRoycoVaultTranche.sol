// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.1
pragma solidity ^0.8.28;

import { IERC20Metadata } from "../../lib/openzeppelin-contracts/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import { TrancheType } from "../libraries/Types.sol";
import { TRANCHE_UNIT } from "../libraries/Units.sol";

/**
 * @title IRoycoVaultTranche
 * @notice Abridged interface for a Royco vault tranche, containing only the functions consumed by periphery contracts
 * @dev Extends ERC20 metadata since every Royco tranche is an ERC20 share token
 * @dev Every function declared here shares its selector across Royco Dawn and Royco Day tranches; functions whose return
 *      encoding diverges between the two protocols are documented accordingly
 */
interface IRoycoVaultTranche is IERC20Metadata {
    /// @notice Returns the address of the kernel that this tranche is associated with
    /// @return kernel The address of the kernel responsible for executing deposits and redemptions for this tranche
    function KERNEL() external view returns (address kernel);

    /**
     * @notice Returns the tranche type indicating whether this is a senior, junior, or liquidity tranche
     * @dev Royco Dawn tranches only ever return SENIOR or JUNIOR; only Royco Day tranches can return LIQUIDITY
     * @return trancheType An enumerator indicating the tranche's type
     */
    function TRANCHE_TYPE() external view returns (TrancheType trancheType);

    /// @notice Returns the address of the underlying base asset for this tranche
    /// @return asset The address of the ERC20 token used as the base asset for deposits into this tranche
    function asset() external view returns (address asset);

    /**
     * @notice Previews the number of shares that would be minted for a given deposit amount
     * @dev Does not mutate any state
     * @param _assets The amount of assets to deposit, denominated in the tranche's base asset units
     * @return shares The number of shares that would be minted for the specified deposit amount
     */
    function previewDeposit(TRANCHE_UNIT _assets) external view returns (uint256 shares);

    /**
     * @notice Converts a specified number of shares to asset claims using the current exchange rate
     * @dev Does not mutate any state
     * @dev Declared without its return value: the returned AssetClaims struct is protocol-specific (three words on Royco
     *      Dawn, five on Royco Day) while the selector is identical, so periphery callers never decode the full struct —
     *      only the leading `stAssets`/`jtAssets` words and the final `nav` word are positionally stable, and they are
     *      read via low-level calls
     * @param _shares The number of shares to convert
     */
    function convertToAssets(uint256 _shares) external view;

    /**
     * @notice Deposits assets into the tranche and mints shares to the receiver
     * @dev Transfers assets from the caller and mints shares to the receiver
     * @param _assets The amount of assets to deposit, denominated in the tranche's base asset units
     * @param _receiver The address that will receive the minted shares
     * @return shares The number of shares minted to the receiver
     */
    function deposit(TRANCHE_UNIT _assets, address _receiver) external returns (uint256 shares);
}
