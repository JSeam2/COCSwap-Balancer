// SPDX-License-Identifier: AGPL-3.0

pragma solidity ^0.8.24;

import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";

import { IVault } from "@balancer-labs/v3-interfaces/contracts/vault/IVault.sol";
import { IVaultAdmin } from "@balancer-labs/v3-interfaces/contracts/vault/IVaultAdmin.sol";
import { IBasePoolFactory } from "@balancer-labs/v3-interfaces/contracts/vault/IBasePoolFactory.sol";
import { IProtocolFeeController } from "@balancer-labs/v3-interfaces/contracts/vault/IProtocolFeeController.sol";
import { IHalo2Verifier } from "../pools/IHalo2Verifier.sol";
import { IChainlinkPriceCache } from "../utils/ChainlinkPriceCache.sol";

/**
 * @title FeeManager
 * @notice Governs the fee management of Balancer pools with verification-based dynamic fee calculation
 * @dev Uses EZKL to verify the dynamic fee calculation is correct
 */
contract FeeManager is Ownable {
    address public immutable vault;

    struct FeeConfig {
        IHalo2Verifier verifier;
        IChainlinkPriceCache priceCache;
        uint256 lookback;
        uint256 scalingFactorDiv;
        uint256 scalingFactorMul;
        uint256 dynamicFee;
    }
    
    // Mapping of pools to their current dynamic fee
    mapping(address => FeeConfig) public feeConfig;

    // Events
    event NewFeeConfig(address indexed pool, address verifier, address priceCache, uint256 lookback, uint256 scalingFactorDiv, uint256 scalingFactorMul, uint256 initialFee);
    event FeeUpdated(address indexed pool, uint256 swapFeePercentage);
    
    // Errors
    error VerificationFailed();
    error InvalidPool();
    error InvalidHook();
    error FeeTooHigh();

    /**
     * @notice Constructor to initialize the FeeManager contract
     * @param _vault The Balancer Vault address
     */
    constructor(
        address _vault
    ) Ownable(msg.sender) {
        vault = _vault;
    }


    /**
     * @notice Registers the initial fee configuration for a pool
     * @param pool The pool address
     * @param _verifier The Halo2 verifier contract for fee verification
     * @param _priceCache The price cache contract for historical price data
     * @param _lookback Number of historical price points to consider
     * @param _scalingFactorDiv Scaling factor for fee calculations
     * @param _scalingFactorMul Scaling factor for fee calculations
     * @param _initDynamicFee Initial dynamic fee value
     */
    function registerFeeConfig(
        address pool,
        address _verifier,
        address _priceCache,
        uint256 _lookback,
        uint256 _scalingFactorDiv,
        uint256 _scalingFactorMul,
        uint256 _initDynamicFee
    ) public onlyOwner {
        // NOTE: This allows the owner to override the pool
        // Setup the initial fee config
        feeConfig[pool] = FeeConfig({
            verifier: IHalo2Verifier(_verifier),
            priceCache: IChainlinkPriceCache(_priceCache),
            lookback: _lookback,
            scalingFactorDiv: _scalingFactorDiv,
            scalingFactorMul: _scalingFactorMul,
            dynamicFee: _initDynamicFee
        });

        emit NewFeeConfig(pool, _verifier, _priceCache, _lookback, _scalingFactorDiv, _scalingFactorMul, _initDynamicFee);
    }


    /**
     * @notice Updates the dynamic swap fee for a pool after verifying the calculation proof
     * @param pool The pool address
     * @param proof ZK proof for the fee calculation
     * @param dynamicFeeUnscaled Unscaled dynamic fee value
     */
    function setStaticSwapFeePercentage(
        address pool,
        bytes calldata proof,
        uint256 dynamicFeeUnscaled
    ) public {
        FeeConfig storage config = feeConfig[pool];
        
        if (address(config.verifier) == address(0)) {
            revert InvalidPool();
        }
        
        // Calculate the scaled fee
        uint256 scaledFee = (dynamicFeeUnscaled * config.scalingFactorMul) / (config.scalingFactorDiv);
        
        // Get historical price
        uint256[] memory historical = config.priceCache.getHistoricalPrice(config.lookback);

        // Add historical to instances and append dynamicFee at the end
        uint256 historicalLength = historical.length;

        // Construct instances: we take lookback + 1 to append dynamic fee into the instances
        uint256[] memory instances = new uint256[](historicalLength + 1);

        for (uint256 i = 0; i < historicalLength; ++i) {
            instances[i] = historical[i];
        }
        instances[historicalLength] = dynamicFeeUnscaled;

        if (!config.verifier.verifyProof(proof, instances)) {
            revert VerificationFailed();
        } else {
            // Update the stored dynamic fee
            config.dynamicFee = scaledFee;
            
            // Set the fee on the vault
            IVaultAdmin(vault).setStaticSwapFeePercentage(pool, scaledFee);
            emit FeeUpdated(pool, scaledFee);
        }
    }
}