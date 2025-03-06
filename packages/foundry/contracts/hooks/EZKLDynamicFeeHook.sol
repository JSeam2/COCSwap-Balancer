// SPDX-License-Identifier: AGPL-3.0

pragma solidity ^0.8.24;

import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import { IBasePoolFactory } from "@balancer-labs/v3-interfaces/contracts/vault/IBasePoolFactory.sol";
import { IRouterCommon } from "@balancer-labs/v3-interfaces/contracts/vault/IRouterCommon.sol";
import { IHooks } from "@balancer-labs/v3-interfaces/contracts/vault/IHooks.sol";
import { IVault } from "@balancer-labs/v3-interfaces/contracts/vault/IVault.sol";
import {
    LiquidityManagement,
    TokenConfig,
    PoolSwapParams,
    HookFlags
} from "@balancer-labs/v3-interfaces/contracts/vault/VaultTypes.sol";

import { VaultGuard } from "@balancer-labs/v3-vault/contracts/VaultGuard.sol";
import { BaseHooks } from "@balancer-labs/v3-vault/contracts/BaseHooks.sol";
import { IHalo2Verifier } from "../pools/IHalo2Verifier.sol";
import { IChainlinkPriceCache } from "../utils/ChainlinkPriceCache.sol";

/**
 * @notice Hook that calculates the optimal fees a pool should have
 * @dev Uses the dynamic fee mechanism to modify base fees
 */
contract EZKLDynamicFeeHook is BaseHooks, VaultGuard {
    // EZKL verifier
    IHalo2Verifier public immutable _verifier;
    IChainlinkPriceCache public immutable _priceCache;
    uint256 public immutable _scalingFactor;
    uint256 public immutable _lookback;
    uint256 public _dynamicFee;

    /**
     * @notice A new `VeBALFeeDiscountHookExample` contract has been registered successfully.
     * @dev If the registration fails the call will revert, so there will be no event.
     * @param hooksContract This contract
     * @param pool The pool on which the hook was registered
     */
    event EZKLDynamicFeeHookRegistered(
        address indexed hooksContract,
        address indexed pool
    );

    event EZKLDynamicFeeHookUpdated(
        address indexed hooksContract,
        uint256 dynamicFee
    );

    error VerificationFail();

    constructor(IVault vault, address verifier, uint256 scalingFactor, uint256 lookback) VaultGuard(vault) {
        _verifier = IHalo2Verifier(verifier);
        _scalingFactor = scalingFactor;
        _lookback = lookback;

    }

    /// @inheritdoc IHooks
    function getHookFlags() public pure override returns (HookFlags memory hookFlags) {
        hookFlags.shouldCallComputeDynamicSwapFee = true;
    }

    /// @inheritdoc IHooks
    function onRegister(
        address,
        address pool,
        TokenConfig[] memory,
        LiquidityManagement calldata
    ) public override onlyVault returns (bool) {
        emit EZKLDynamicFeeHookRegistered(address(this), pool);
        return true;
    }

    /// @inheritdoc IHooks
    function onComputeDynamicSwapFeePercentage(
        PoolSwapParams calldata,
        address,
        uint256  // this hook overrides the staticSwapFeePercentage
    ) public view override onlyVault returns (bool, uint256) {
        return (true, _dynamicFee);
    }

    /**
     * @notice Update fee percentage
     */
    function updateFee(bytes calldata proof, uint256 dynamicFee) external {
        // construct instances we take lookback + 1 to append dynamic fee into the instances
        uint256[] memory instances = new uint256[](_lookback + 1);

        // Get historical price
        uint256[] memory historical = _priceCache.getHistoricalPrice(_lookback);

        // add historical to instances and append dynamicfee at the end
        uint256 historicalLength = historical.length;
        for (uint256 i = 0; i < historicalLength; ++i) {
            instances[i] = historical[i];
        }
        instances[_lookback] = dynamicFee;

        if (_verifier.verifyProof(proof, instances)) {
            _dynamicFee = dynamicFee;

            emit EZKLDynamicFeeHookUpdated(
                address(this),
                _dynamicFee
            );
        } else {
            revert VerificationFail();
        }
    }
}
