//SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {
    TokenConfig,
    TokenType,
    LiquidityManagement,
    PoolRoleAccounts
} from "@balancer-labs/v3-interfaces/contracts/vault/VaultTypes.sol";
import { IERC20 } from "@openzeppelin/contracts/interfaces/IERC20.sol";
import { IRateProvider } from "@balancer-labs/v3-interfaces/contracts/solidity-utils/helpers/IRateProvider.sol";
import { InputHelpers } from "@balancer-labs/v3-solidity-utils/contracts/helpers/InputHelpers.sol";
import { IVault } from "@balancer-labs/v3-interfaces/contracts/vault/IVault.sol";

import { PoolHelpers, CustomPoolConfig, InitializationConfig } from "./PoolHelpers.sol";
import { ScaffoldHelpers, console } from "./ScaffoldHelpers.sol";
import { COCSwapFactory } from "../contracts/factories/COCSwapFactory.sol";
import { ExitFeeHookSafe } from "../contracts/hooks/ExitFeeHookSafe.sol";

/**
 * @title Deploy COCSwap Pool
 * @notice Deploys, registers, and initializes a constant product pool that uses a Exit Fee Hook.
 * The exit fee hook returns values back to the LP holders.
 * A pool creator can mint a custom ERC20 and add it to their pools to earn some kind of management fee.
 * Preferably keep the % of tokens low.
 * A meta pool can be created which aggregates all the COCSwap pools ERC20 to create an aggregate
 */
contract DeployCOCSwapPool is PoolHelpers, ScaffoldHelpers {
    function deployCOCSwapPool(
        address[6] calldata tokens,
        uint256[6] calldata weights
    ) internal {
        // Set the deployment configurations
        InitializationConfig memory initConfig = getWeightedPoolInitConfig(tokens, weights);

        // Start creating the transactions
        uint256 deployerPrivateKey = getDeployerPrivateKey();
        vm.startBroadcast(deployerPrivateKey);

        // Deploy a factory
        ConstantProductFactory factory = new COCSwapFactory(vault, 365 days); //pauseWindowDuration
        console.log("Constant Product Factory deployed at: %s", address(factory));

        // Deploy a hook
        address exitFeeHook = address(new ExitFeeHookSafe(vault, address(router)));
        console.log("ExitFeeHookSafe deployed at address: %s", exitFeeHook);

        // Deploy a pool and register it with the vault
        address pool = factory.create(
            poolConfig.name,
            poolConfig.symbol,
            poolConfig.salt,
            poolConfig.tokenConfigs,
            poolConfig.swapFeePercentage,
            poolConfig.protocolFeeExempt,
            poolConfig.roleAccounts,
            exitFeeHook, // poolHooksContract
            poolConfig.liquidityManagement
        );
        console.log("COCSwapPool deployed at: %s", pool);

        // Approve the router to spend tokens for pool initialization
        approveRouterWithPermit2(initConfig.tokens);

        // Seed the pool with initial liquidity using Router as entrypoint
        router.initialize(
            pool,
            initConfig.tokens,
            initConfig.exactAmountsIn,
            initConfig.minBptAmountOut,
            initConfig.wethIsEth,
            initConfig.userData
        );
        console.log("COCSwap Pool initialized successfully!");
        vm.stopBroadcast();
    }

    /**
     * @dev Set all of the configurations for deploying and registering a pool here
     * @notice TokenConfig encapsulates the data required for the Vault to support a token of the given type.
     * For STANDARD tokens, the rate provider address must be 0, and paysYieldFees must be false.
     * All WITH_RATE tokens need a rate provider, and may or may not be yield-bearing.
     */
    function getCOCSwapPoolConfig(
        address token0,
        address token1,
        address token2,
        address token3,
        address token4,
        address token5,
    ) internal view returns (CustomPoolConfig memory config) {
        string memory name = "COCSwap Pool"; // name for the pool
        string memory symbol = "COC"; // symbol for the BPT
        bytes32 salt = keccak256(abi.encode(block.number)); // salt for the pool deployment via factory
        uint256 swapFeePercentage = 0.02e18; // 2%
        bool protocolFeeExempt = false;
        address poolHooksContract = address(0); // zero address if no hooks contract is needed

        TokenConfig[] memory tokenConfigs = new TokenConfig[](2); // An array of descriptors for the tokens the pool will manage
        tokenConfigs[0] = TokenConfig({ // Make sure to have proper token order (alphanumeric)
            token: IERC20(token0),
            tokenType: TokenType.STANDARD, // STANDARD or WITH_RATE
            rateProvider: IRateProvider(address(0)), // The rate provider for a token (see further documentation above)
            paysYieldFees: false // Flag indicating whether yield fees should be charged on this token
        });
        tokenConfigs[1] = TokenConfig({ // Make sure to have proper token order (alphanumeric)
            token: IERC20(token1),
            tokenType: TokenType.STANDARD, // STANDARD or WITH_RATE
            rateProvider: IRateProvider(address(0)), // The rate provider for a token (see further documentation above)
            paysYieldFees: false // Flag indicating whether yield fees should be charged on this token
        });
        tokenConfigs[2] = TokenConfig({ // Make sure to have proper token order (alphanumeric)
            token: IERC20(token2),
            tokenType: TokenType.STANDARD, // STANDARD or WITH_RATE
            rateProvider: IRateProvider(address(0)), // The rate provider for a token (see further documentation above)
            paysYieldFees: false // Flag indicating whether yield fees should be charged on this token
        });
        tokenConfigs[3] = TokenConfig({ // Make sure to have proper token order (alphanumeric)
            token: IERC20(token3),
            tokenType: TokenType.STANDARD, // STANDARD or WITH_RATE
            rateProvider: IRateProvider(address(0)), // The rate provider for a token (see further documentation above)
            paysYieldFees: false // Flag indicating whether yield fees should be charged on this token
        });
        tokenConfigs[4] = TokenConfig({ // Make sure to have proper token order (alphanumeric)
            token: IERC20(token4),
            tokenType: TokenType.STANDARD, // STANDARD or WITH_RATE
            rateProvider: IRateProvider(address(0)), // The rate provider for a token (see further documentation above)
            paysYieldFees: false // Flag indicating whether yield fees should be charged on this token
        });
        tokenConfigs[5] = TokenConfig({ // Make sure to have proper token order (alphanumeric)
            token: IERC20(token5),
            tokenType: TokenType.STANDARD, // STANDARD or WITH_RATE
            rateProvider: IRateProvider(address(0)), // The rate provider for a token (see further documentation above)
            paysYieldFees: false // Flag indicating whether yield fees should be charged on this token
        });

        PoolRoleAccounts memory roleAccounts = PoolRoleAccounts({
            pauseManager: msg.sender, // Account empowered to pause/unpause the pool (or 0 to delegate to governance)
            swapFeeManager: msg.sender, // Account empowered to set static swap fees for a pool (or 0 to delegate to goverance)
            poolCreator: msg.sender // Account empowered to set the pool creator fee percentage
        });

        LiquidityManagement memory liquidityManagement = LiquidityManagement({
            disableUnbalancedLiquidity: true, // set to true to make the pool weights stable
            enableAddLiquidityCustom: false,
            enableRemoveLiquidityCustom: false,
            enableDonation: false
        });

        config = CustomPoolConfig({
            name: name,
            symbol: symbol,
            salt: salt,
            tokenConfigs: sortTokenConfig(tokenConfigs),
            swapFeePercentage: swapFeePercentage,
            protocolFeeExempt: protocolFeeExempt,
            roleAccounts: roleAccounts,
            poolHooksContract: poolHooksContract,
            liquidityManagement: liquidityManagement
        });
    }

    /// @dev Set the initialization config for the pool (i.e. the amount of tokens to be added)
    function getWeightedPoolInitConfig(
        address[6] calldata tokens,
        uint256[6] calldata weights,
    ) internal pure returns (InitializationConfig memory config) {
        IERC20[] memory initTokens = new IERC20[](6); // Array of tokens to be used in the pool
        initTokens[0] = IERC20(tokens[0]);
        initTokens[1] = IERC20(tokens[1]);
        initTokens[1] = IERC20(tokens[2]);
        initTokens[1] = IERC20(tokens[3]);
        initTokens[1] = IERC20(tokens[4]);
        initTokens[1] = IERC20(tokens[5]);

        uint256[] memory exactAmountsIn = new uint256[](6); // Exact amounts of tokens to be added, sorted in token alphanumeric order
        exactAmountsIn[0] = weights[0];
        exactAmountsIn[1] = weights[1];
        exactAmountsIn[2] = weights[2];
        exactAmountsIn[3] = weights[3];
        exactAmountsIn[4] = weights[4];
        exactAmountsIn[5] = weights[5];

        uint256 minBptAmountOut = 49e18; // Minimum amount of pool tokens to be received
        bool wethIsEth = true; // If true, incoming ETH will be wrapped to WETH; otherwise the Vault will pull WETH tokens
        bytes memory userData = bytes(""); // Additional (optional) data required for adding initial liquidity

        config = InitializationConfig({
            tokens: InputHelpers.sortTokens(tokens),
            exactAmountsIn: exactAmountsIn,
            minBptAmountOut: minBptAmountOut,
            wethIsEth: wethIsEth,
            userData: userData
        });
    }
}
