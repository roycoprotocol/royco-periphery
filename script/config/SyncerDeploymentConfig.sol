// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

/**
 * @title SyncerDeploymentConfig
 * @notice Single configuration contract for all syncer deployment parameters
 * @dev Each named config is a tracked deployment: it pins the access manager authority, the market kernels to register,
 *      the sync operators, and the role identifiers bound on that deployment's authority. Nothing is shared across
 *      entries, so deployments for any Royco protocol version coexist side by side — add a new entry per deployment
 */
abstract contract SyncerDeploymentConfig {
    /**
     * ═══════════════════════════════════════════════════════════════════════════
     * CHAIN IDs
     * ═══════════════════════════════════════════════════════════════════════════
     */
    uint256 internal constant MAINNET = 1;
    uint256 internal constant AVALANCHE = 43_114;
    uint256 internal constant ARBITRUM = 42_161;
    uint256 internal constant BASE = 8453;

    /**
     * ═══════════════════════════════════════════════════════════════════════════
     * SYNCER NAMES
     * ═══════════════════════════════════════════════════════════════════════════
     */
    string public constant MAINNET_SYNCER = "MAINNET_SYNCER";
    string public constant AVALANCHE_SYNCER = "AVALANCHE_SYNCER";
    string public constant ARBITRUM_SYNCER = "ARBITRUM_SYNCER";
    string public constant BASE_SYNCER = "BASE_SYNCER";

    /**
     * ═══════════════════════════════════════════════════════════════════════════
     * SYNCER CONFIG STRUCTS
     * ═══════════════════════════════════════════════════════════════════════════
     */

    /**
     * @notice The role identifiers bound on a deployment's authority
     * @custom:field syncRole - The role authorized for the syncer's operational surface and granted to the syncer and its operators
     * @custom:field pauserRole - The role authorized to pause the syncer
     * @custom:field unpauserRole - The role authorized to unpause the syncer
     * @custom:field upgraderRole - The role authorized to upgrade the syncer
     */
    struct SyncerRoles {
        uint64 syncRole;
        uint64 pauserRole;
        uint64 unpauserRole;
        uint64 upgraderRole;
    }

    /**
     * @notice Deployment parameters for a single tracked syncer
     * @custom:field chainId - The chain this deployment lives on
     * @custom:field roycoAuthority - The access manager authority for the syncer
     * @custom:field marketKernels - The kernels registered with the syncer at initialization
     * @custom:field configSpecificSyncOperators - Additional sync operators for this deployment
     * @custom:field roles - The role identifiers bound on this deployment's authority
     */
    struct SyncerConfig {
        uint256 chainId;
        address roycoAuthority;
        address[] marketKernels;
        address[] configSpecificSyncOperators;
        SyncerRoles roles;
    }

    /// @dev The tracked syncer deployments by name
    mapping(string syncerName => SyncerConfig) internal _syncerConfigs;

    /// @dev Base sync operators that are granted the sync role for all syncers
    /// @dev First address is the Royco backend keeper
    address[] internal _baseSyncOperators = [0x806836249FEbbF6ca3008BFF6C3257110f435480];

    /// @notice Thrown when no config exists for the requested syncer name
    error SyncerConfigNotFound(string syncerName);

    /// @notice Thrown when the requested config belongs to a different chain
    error SyncerChainIdMismatch(string syncerName, uint256 expectedChainId, uint256 actualChainId);

    /// @dev Registers the tracked deployments
    constructor() {
        _initializeSyncerConfigs();
    }

    /**
     * @notice Returns the deployment config for the specified syncer name
     * @param syncerName The name of the tracked syncer deployment
     * @return config The deployment config with the combined base and config-specific sync operators
     */
    function getSyncerConfig(string memory syncerName) public view returns (SyncerConfig memory config) {
        SyncerConfig storage storedConfig = _syncerConfigs[syncerName];
        require(storedConfig.roycoAuthority != address(0), SyncerConfigNotFound(syncerName));
        require(storedConfig.chainId == block.chainid, SyncerChainIdMismatch(syncerName, storedConfig.chainId, block.chainid));

        // Build the config with the combined sync operators (base + config-specific)
        config.chainId = storedConfig.chainId;
        config.roycoAuthority = storedConfig.roycoAuthority;
        config.marketKernels = storedConfig.marketKernels;
        config.configSpecificSyncOperators = _combineArrays(_baseSyncOperators, storedConfig.configSpecificSyncOperators);
        config.roles = storedConfig.roles;
    }

    /**
     * ═══════════════════════════════════════════════════════════════════════════
     * SYNCER CONFIG INITIALIZATION
     * ═══════════════════════════════════════════════════════════════════════════
     */
    function _initializeSyncerConfigs() internal {
        /**
         * ═══════════════════════════════════════════════════════════════════════════
         * MAINNET SYNCER CONFIG (Royco Dawn)
         * ═══════════════════════════════════════════════════════════════════════════
         */
        SyncerConfig storage config = _syncerConfigs[MAINNET_SYNCER];
        config.chainId = MAINNET;
        // The Royco Dawn factory, which is itself the access manager on Dawn deployments
        config.roycoAuthority = 0x7cC6fB28eC7b5e7afC3cB3986141797ffc27253C;
        config.roles = standardRoycoRoles();

        // Market kernels to add to the syncer:
        // - Neutrl sNUSD
        config.marketKernels.push(0x0aE0978B868804929fd4C06B3B22D9197B8cd3c6);
        // - Tokemak autoUSD
        config.marketKernels.push(0x8748D1c21CC550B435487F473d9Aaf6C84dA46A6);
        // - Smokehouse USDC Morpho
        config.marketKernels.push(0x6dBdf6EBdF02F50ec6a7d6F782850996928176F9);
        // - Maple syrupUSDC
        config.marketKernels.push(0xde1Ce2cF64808e50d000F93058784270E412B3A4);

        /**
         * ═══════════════════════════════════════════════════════════════════════════
         * AVALANCHE SYNCER CONFIG (Royco Dawn)
         * ═══════════════════════════════════════════════════════════════════════════
         */
        config = _syncerConfigs[AVALANCHE_SYNCER];
        config.chainId = AVALANCHE;
        config.roycoAuthority = 0x7cC6fB28eC7b5e7afC3cB3986141797ffc27253C;
        config.roles = standardRoycoRoles();

        // Market kernels to add to the syncer:
        // - Avant savUSD
        config.marketKernels.push(0x7240FF91b471217FF93349184ABE9f102Ca1955C);

        /**
         * ═══════════════════════════════════════════════════════════════════════════
         * ARBITRUM SYNCER CONFIG (Royco Dawn)
         * ═══════════════════════════════════════════════════════════════════════════
         */
        config = _syncerConfigs[ARBITRUM_SYNCER];
        config.chainId = ARBITRUM;
        config.roycoAuthority = 0x7cC6fB28eC7b5e7afC3cB3986141797ffc27253C;
        config.roles = standardRoycoRoles();

        // Market kernels to add to the syncer:
        // - Metastreet sUSDai
        config.marketKernels.push(0xFdb17E53eA5d342124b8473188BCB9F05F1949CA);

        /**
         * ═══════════════════════════════════════════════════════════════════════════
         * BASE SYNCER CONFIG (Royco Dawn)
         * ═══════════════════════════════════════════════════════════════════════════
         */
        config = _syncerConfigs[BASE_SYNCER];
        config.chainId = BASE;
        config.roycoAuthority = 0x568c9709DaA2f7B7cc66AbC3E41DA0f0A339551A;
        config.roles = standardRoycoRoles();

        // Market kernels to add to the syncer:
        // - Noon sUSN
        config.marketKernels.push(0x3FBC599C113923439Ca6878B7A9b5433Cc3F4116);
    }

    /// @notice The standard Royco role derivations, shared by Dawn and Day authorities
    /// @dev Assigned per entry so any deployment can override any role identifier its authority binds differently
    function standardRoycoRoles() public pure returns (SyncerRoles memory roles) {
        roles = SyncerRoles({
            syncRole: uint64(uint256(keccak256(abi.encode("ROYCO_SYNC_ROLE")))),
            pauserRole: uint64(uint256(keccak256(abi.encode("ROYCO_ADMIN_PAUSER_ROLE")))),
            unpauserRole: uint64(uint256(keccak256(abi.encode("ROYCO_ADMIN_UNPAUSER_ROLE")))),
            upgraderRole: uint64(uint256(keccak256(abi.encode("ROYCO_ADMIN_UPGRADER_ROLE"))))
        });
    }

    /// @notice Combines two address arrays into one
    function _combineArrays(address[] storage _base, address[] storage _additional) internal view returns (address[] memory combined) {
        combined = new address[](_base.length + _additional.length);
        for (uint256 i = 0; i < _base.length; i++) {
            combined[i] = _base[i];
        }
        for (uint256 i = 0; i < _additional.length; i++) {
            combined[_base.length + i] = _additional[i];
        }
    }
}
