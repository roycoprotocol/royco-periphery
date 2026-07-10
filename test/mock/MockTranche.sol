// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import { ERC20 } from "../../lib/openzeppelin-contracts/contracts/token/ERC20/ERC20.sol";
import { IERC20 } from "../../lib/openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import { SafeERC20 } from "../../lib/openzeppelin-contracts/contracts/token/ERC20/utils/SafeERC20.sol";
import { Math } from "../../lib/openzeppelin-contracts/contracts/utils/math/Math.sol";

import { TrancheType } from "../../src/libraries/Types.sol";
import { TRANCHE_UNIT, toUint256 } from "../../src/libraries/Units.sol";

/// @title MockTranche
/// @notice A simplified mock of a Royco vault tranche for testing periphery contracts
/// @dev Matches the tranche ABI consumed by periphery's abridged IRoycoVaultTranche (same selectors) without inheriting
///      it: the interface declares `convertToAssets` without its protocol-specific return value, and this mock encodes its
///      return per the periphery mandate — stAssets/jtAssets in the first two words, nav in the last, and a configurable
///      number of arbitrary protocol-specific words in between — so low-level readers are exercised against any shape
/// @dev Adapted from the Royco Dawn test mock: functions beyond the abridged interface (maxDeposit, redeem, burn,
///      seizures, protocol fee mints, etc.) are kept as plain public functions with identical behavior
/// @dev Uses a simple 1:1 asset-to-share ratio for simplicity, with configurable share price
contract MockTranche is ERC20 {
    using SafeERC20 for IERC20;
    using Math for uint256;

    // Events mirrored from the Royco Dawn tranche interface (not part of periphery's abridged interface)
    event Deposit(address indexed sender, address indexed receiver, TRANCHE_UNIT assets, uint256 shares);
    event Redeem(address indexed sender, address indexed receiver, uint256 assets, uint256 shares);

    address public immutable UNDERLYING_ASSET;
    TrancheType public immutable TRANCHE_TYPE_VALUE;

    // Configurable share price (in WAD, 1e18 = 1:1)
    uint256 public sharePriceWAD = 1e18;

    // Number of protocol specific words encoded between the leading claims and the trailing NAV (0 mirrors Dawn, 2 mirrors Day)
    uint256 public convertToAssetsMiddleWords;

    // Mock kernel address (not used in tests but needed for interface)
    address public kernelAddress;

    // Track total deposited assets for NAV calculation
    uint256 public totalDepositedAssets;

    // The tranche's authority (defaults to the factory, mirroring the live deployment topology)
    address public trancheAuthority;

    constructor(
        address _asset,
        address _authority,
        TrancheType _trancheType
    )
        ERC20(_trancheType == TrancheType.SENIOR ? "Mock Senior Tranche" : "Mock Junior Tranche", _trancheType == TrancheType.SENIOR ? "MST" : "MJT")
    {
        UNDERLYING_ASSET = _asset;
        TRANCHE_TYPE_VALUE = _trancheType;
        trancheAuthority = _authority;
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // MOCK CONFIGURATION
    // ═══════════════════════════════════════════════════════════════════════════

    /// @notice Sets the number of protocol specific words encoded between the leading claims and the trailing NAV
    function setConvertToAssetsMiddleWords(uint256 _middleWords) external {
        convertToAssetsMiddleWords = _middleWords;
    }

    /// @notice Sets the share price for testing yield scenarios
    /// @param _sharePriceWAD New share price in WAD (1e18 = 1:1)
    function setSharePrice(uint256 _sharePriceWAD) external {
        sharePriceWAD = _sharePriceWAD;
    }

    /// @notice Sets the kernel address
    function setKernel(address _kernel) external {
        kernelAddress = _kernel;
    }

    /// @notice Sets the tranche's authority
    function setAuthority(address _authority) external {
        trancheAuthority = _authority;
    }

    /// @notice Simulates yield by increasing share price
    /// @param _yieldPercentWAD Yield percentage in WAD (e.g., 0.1e18 for 10%)
    function simulateYield(uint256 _yieldPercentWAD) external {
        sharePriceWAD = sharePriceWAD.mulDiv(1e18 + _yieldPercentWAD, 1e18);
    }

    /// @notice Simulates loss by decreasing share price
    /// @param _lossPercentWAD Loss percentage in WAD (e.g., 0.1e18 for 10%)
    function simulateLoss(uint256 _lossPercentWAD) external {
        sharePriceWAD = sharePriceWAD.mulDiv(1e18 - _lossPercentWAD, 1e18);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // IRoycoVaultTranche IMPLEMENTATION (periphery's abridged interface + Dawn extras)
    // ═══════════════════════════════════════════════════════════════════════════

    function KERNEL() external view returns (address) {
        return kernelAddress;
    }

    function TRANCHE_TYPE() external view returns (TrancheType) {
        return TRANCHE_TYPE_VALUE;
    }

    function asset() external view returns (address) {
        return UNDERLYING_ASSET;
    }

    /// @notice Returns the tranche's authority (the Royco factory by default, mirroring the live deployment topology)
    function authority() external view returns (address) {
        return trancheAuthority;
    }

    function previewDeposit(TRANCHE_UNIT _assets) external view returns (uint256 shares) {
        shares = _convertToShares(toUint256(_assets));
    }

    /// @notice Values shares per the periphery mandate: stAssets/jtAssets lead, nav trails, anything in between
    /// @dev Returns raw words via assembly: [stAssets][jtAssets][convertToAssetsMiddleWords arbitrary nonzero words][nav].
    ///      0 middle words mirrors Royco Dawn, 2 mirrors Royco Day, and any other count models a future protocol version
    function convertToAssets(uint256 _shares) external view {
        uint256 assets = _convertToAssets(_shares);
        uint256 stAssets = TRANCHE_TYPE_VALUE == TrancheType.SENIOR ? assets : 0;
        uint256 jtAssets = TRANCHE_TYPE_VALUE == TrancheType.JUNIOR ? assets : 0;

        // Lead with the ST and JT asset claims
        bytes memory encoded = abi.encodePacked(stAssets, jtAssets);
        // Encode arbitrary nonzero protocol specific words in between, which mandate compliant readers must ignore
        for (uint256 i = 0; i < convertToAssetsMiddleWords; i++) {
            encoded = abi.encodePacked(encoded, uint256(keccak256(abi.encode(_shares, i))));
        }
        // Trail with the NAV
        encoded = abi.encodePacked(encoded, assets);

        assembly ("memory-safe") {
            return(add(encoded, 0x20), mload(encoded))
        }
    }

    function deposit(TRANCHE_UNIT _assets, address _receiver) external returns (uint256 shares) {
        uint256 assetAmount = toUint256(_assets);
        require(assetAmount > 0, "MUST_MINT_NON_ZERO_SHARES");

        shares = _convertToShares(assetAmount);

        // Transfer assets from caller
        IERC20(UNDERLYING_ASSET).safeTransferFrom(msg.sender, address(this), assetAmount);

        // Track deposited assets
        totalDepositedAssets += assetAmount;

        // Mint shares
        _mint(_receiver, shares);

        emit Deposit(msg.sender, _receiver, _assets, shares);
    }

    function redeem(uint256 _shares, address _receiver, address _owner) external {
        require(_shares > 0, "MUST_REQUEST_NON_ZERO_SHARES");

        // Handle allowance if caller is not owner
        if (msg.sender != _owner) {
            _spendAllowance(_owner, msg.sender, _shares);
        }

        uint256 assets = _convertToAssets(_shares);

        // Burn shares
        _burn(_owner, _shares);

        // Update tracked assets
        if (totalDepositedAssets >= assets) {
            totalDepositedAssets -= assets;
        } else {
            totalDepositedAssets = 0;
        }

        // Transfer assets
        IERC20(UNDERLYING_ASSET).safeTransfer(_receiver, assets);

        emit Redeem(msg.sender, _receiver, assets, _shares);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // INTERNAL HELPERS
    // ═══════════════════════════════════════════════════════════════════════════

    function _convertToShares(uint256 _assets) internal view returns (uint256) {
        // shares = assets * 1e18 / sharePriceWAD
        return _assets.mulDiv(1e18, sharePriceWAD, Math.Rounding.Floor);
    }

    function _convertToAssets(uint256 _shares) internal view returns (uint256) {
        // assets = shares * sharePriceWAD / 1e18
        return _shares.mulDiv(sharePriceWAD, 1e18, Math.Rounding.Floor);
    }
}
