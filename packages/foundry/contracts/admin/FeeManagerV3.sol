// SPDX-License-Identifier: AGPL-3.0

pragma solidity ^0.8.24;

import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
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

contract FeeManagerV3 {
   // Immutable
   // Description of the FeeManager
   string public description;
   // Balancer Vault Address
   address public immutable vault;
   // lit network public key
   address public immutable litPublicKey;
   // EZKL Halo2Verifier Address
   IHalo2Verifier public immutable verifier;

   // Scaling Factors for EZKL Halo2Verifier to Balancer Vault
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
   error SignatureFailed();

   /**
    * @notice Constructor to initialize the FeeManager contract
    * @param _description description of the FeeManager
    * @param _vault The Balancer Vault address
    * @param _litPublicKey lit public key
    * @param _verifier EZKL's Halo2Verifier for verifying proofs
    * @param _scalingFactorDiv scaling factor to divide by, to fit instances to FixedPoint.ONE
    * @param _scalingFactorMul scaling factor to multiply by, to fit instances to FixedPoint.ONE
    */
   constructor(
      string memory _description,
      address _vault,
      address _litPublicKey,
      address _verifier,
      uint256 _scalingFactorDiv,
      uint256 _scalingFactorMul
   ) {
      description = _description;
      vault = _vault;
      litPublicKey = _litPublicKey;
      verifier = IHalo2Verifier(_verifier);
      scalingFactorDiv = _scalingFactorDiv;
      scalingFactorMul = _scalingFactorMul;
   }

   /**
    * @notice Updates the dynamicFee on the FeeManager
    * @param proof ZK proof of the dynamic fee calculation
    * @param data Bytes data to be passed to the verifier
    * @param dynamicFeeUnscaled Unscaled dynamic fee value, this should be the last element of the instances in the proof file
    * @param signature Signature of the dynamic fee calculation
    */
   function updateFee(
      bytes calldata proof,
      uint256[] calldata inputData,
      uint256 dynamicFeeUnscaled,
      bytes memory signature
   ) public returns (bool) {
      // check input data sig
      (address recovered, , ) = ECDSA.tryRecover(
         keccak256(abi.encode(inputData)),
         signature
      )

      if (recovered != litPublicKey) {
         revert SignatureFailed();
      }


      // Get historical price and construct instances
      uint256 inputDataLength = inputData.length;
      uint256[] memory instances = new uint256[](inputDataLength + 1);

      for (uint256 i = 0; i < inputDataLength; ++i) {
         instances[i] = inputData[i];
      }
      instances[inputDataLength] = dynamicFeeUnscaled;

      if (!verifier.verifyProof(proof, instances)) {
         revert VerificationFailed();
      }

      // Calculate scaled dynamicFee, we round to 5dp which is 0.00001e18 = 1e13 this is because solvers on Paraswap cannot process too many dp
      // note 100% is 1e18 as given in FixedPoint.ONE
      // note we add 5e12 to round
      dynamicFee = (((dynamicFeeUnscaled * scalingFactorMul) / scalingFactorDiv) + 5e12) / 1e13 * 1e13;
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
