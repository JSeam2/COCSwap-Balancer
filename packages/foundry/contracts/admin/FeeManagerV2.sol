// SPDX-License-Identifier: AGPL-3.0

pragma solidity ^0.8.24;

import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import { IVault } from "@balancer-labs/v3-interfaces/contracts/vault/IVault.sol";
import { IVaultExplorer } from "@balancer-labs/v3-interfaces/contracts/vault/IVaultExplorer.sol";
import { IVaultAdmin } from "@balancer-labs/v3-interfaces/contracts/vault/IVaultAdmin.sol";
import { IBasePoolFactory } from "@balancer-labs/v3-interfaces/contracts/vault/IBasePoolFactory.sol";
import { IProtocolFeeController } from "@balancer-labs/v3-interfaces/contracts/vault/IProtocolFeeController.sol";
import { IHalo2Verifier } from "../utils/IHalo2Verifier.sol";
import { IChainlinkPriceCache } from "../utils/ChainlinkPriceCache.sol";

/**
 * @title FeeManagerV2
 * @notice Governs the fee management of Balancer pools with verification-based dynamic fee calculation
 * @dev Key change with FeeManager.sol each deployment of a FeeManager is responsible for a given token pair
 */

contract FeeManagerV2 {
   // Immutable
   string public description;
   address public immutable vault;
   IChainlinkPriceCache public immutable priceCache;
   IHalo2Verifier public immutable verifier;
   uint256 public immutable lookback;
   uint256 public immutable scalingFactorDiv;
   uint256 public immutable scalingFactorMul;

   // Mutable
   uint256 public dynamicFee;

   // Events
   event FeeUpdated(uint256 swapFeePercentage);
   event PoolUpdated(address indexed pool, uint256 swapFeePercentage);

   // Errors
   error VerificationFailed();
   error InvalidPool();

   /**
    * @notice Constructor to initialize the FeeManager contract
    * @param _description description of the FeeManager
    * @param _vault The Balancer Vault address
    * @param _priceCache Chainlink Price Cache contract that stores historical price data
    * @param _verifier EZKL's Halo2Verifier for verifying proofs
    * @param _lookback lookback periods for price data
    * @param _scalingFactorDiv scaling factor to divide by, to fit instances to FixedPoint.ONE
    * @param _scalingFactorMul scaling factor to multiply by, to fit instances to FixedPoint.ONE
    */
   constructor(
      string memory _description,
      address _vault,
      address _priceCache,
      address _verifier,
      uint256 _lookback,
      uint256 _scalingFactorDiv,
      uint256 _scalingFactorMul
   ) {
      description = _description;
      vault = _vault;
      priceCache = IChainlinkPriceCache(_priceCache);
      verifier = IHalo2Verifier(_verifier);
      lookback = _lookback;
      scalingFactorDiv = _scalingFactorDiv;
      scalingFactorMul = _scalingFactorMul;
   }

   /**
    * @notice Updates the dynamicFee on the FeeManager
    * @param proof ZK proof of the dynamic fee calculation
    * @param dynamicFeeUnscaled Unscaled dynamic fee value, this should be the last element of the instances in the proof file
    */
   function updateFee(bytes calldata proof, uint256 dynamicFeeUnscaled) public returns (bool) {
      // Get historical price and construct instances
      uint256[] memory historical = priceCache.getHistoricalPrice(lookback);
      uint256 historicalLength = historical.length;
      uint256[] memory instances = new uint256[](historicalLength + 1);

      for (uint256 i = 0; i < historicalLength; ++i) {
         instances[i] = historical[i];
      }
      instances[historicalLength] = dynamicFeeUnscaled;

      if (!verifier.verifyProof(proof, instances)) {
         revert VerificationFailed();
      }

      // Calculate scaled dynamicFee, we round to 5dp which is 0.00001e18 = 1e13 this is because solvers on Paraswap cannot process too many dp
      // note 100% is 1e18 as given in FixedPoint.ONE
      // note in this function we add a 0.5e13 to round up if the remainder is >= 0.5
      dynamicFee = (((dynamicFeeUnscaled * scalingFactorMul) / scalingFactorDiv) + 0.5e13) / 1e13 * 1e13;
      emit FeeUpdated(dynamicFee);

      return true;
   }

   /**
    * @notice Publishes the dynamicFee by calling setStaticSwapFeePercentage on the various pools in the function args.
    * Pools need to have set the FeeManager contract as swap fee manager
    * @param pools array of pools
    */
   function publishFee(address[] calldata pools) public returns (bool) {
      uint256 poolsLength = pools.length;

      for (uint256 i = 0; i < poolsLength; ++i) {
         IVaultAdmin(vault).setStaticSwapFeePercentage(pools[i], dynamicFee);
         emit PoolUpdated(pools[i], dynamicFee);
      }

      return true;
   }
}
