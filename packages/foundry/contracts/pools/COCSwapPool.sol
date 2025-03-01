//SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { BalancerPoolToken } from "@balancer-labs/v3-vault/contracts/BalancerPoolToken.sol";
import { PoolSwapParams, Rounding, SwapKind, PoolConfig } from "@balancer-labs/v3-interfaces/contracts/vault/VaultTypes.sol";
import { IVault } from "@balancer-labs/v3-interfaces/contracts/vault/IVault.sol";
import { FixedPoint } from "@balancer-labs/v3-solidity-utils/contracts/math/FixedPoint.sol";
import { WeightedMath } from "@balancer-labs/v3-solidity-utils/contracts/math/WeightedMath.sol";
import { InputHelpers } from "@balancer-labs/v3-solidity-utils/contracts/helpers/InputHelpers.sol";
import {
    IUnbalancedLiquidityInvariantRatioBounds
} from "@balancer-labs/v3-interfaces/contracts/vault/IUnbalancedLiquidityInvariantRatioBounds.sol";
import {
    IWeightedPool,
    WeightedPoolDynamicData,
    WeightedPoolImmutableData
} from "@balancer-labs/v3-interfaces/contracts/pool-weighted/IWeightedPool.sol";
import { PoolInfo } from "@balancer-labs/v3-pool-utils/contracts/PoolInfo.sol";
import { IHalo2Verifier } from "./IHalo2Verifier.sol";


/**
 * @title IOdosRouter
 * @notice Interface for interacting with Odos router for token swaps
 * Deployments at https://github.com/odos-xyz/odos-router-v2/blob/main/README.md#chain-deployments
 */
interface IOdosRouter {
    /// @dev Contains all information needed to describe an intput token for swapMulti
    struct inputTokenInfo {
        address tokenAddress;
        uint256 amountIn;
        address receiver;
    }
    /// @dev Contains all information needed to describe an output token for swapMulti
    struct outputTokenInfo {
        address tokenAddress;
        uint256 relativeValue;
        address receiver;
    }

    /// @notice Externally facing interface for swapping between two sets of tokens
    /// @param inputs list of input token structs for the path being executed
    /// @param outputs list of output token structs for the path being executed
    /// @param valueOutMin minimum amount of value out the user will accept
    /// @param pathDefinition Encoded path definition for executor
    /// @param executor Address of contract that will execute the path
    /// @param referralCode referral code to specify the source of the swap
    function swapMulti(
        inputTokenInfo[] memory inputs,
        outputTokenInfo[] memory outputs,
        uint256 valueOutMin,
        bytes calldata pathDefinition,
        address executor,
        uint32 referralCode
    )
        external
        payable
        returns (uint256[] memory amountsOut);
}


/**
 * @title COCSwap Pool
 * @notice COCSwap pool is a custom pool which actively rebalances its vault using convex optimization.
 * The rebalancing is made verifiable using EZKL Halo2Verifier.
 * https://blog.ezkl.xyz/post/cocswap/
 */
contract COCSwapPool is IWeightedPool, BalancerPoolToken, PoolInfo {
    using FixedPoint for uint256;

    struct COCSwapPoolParams {
        string name;
        string symbol;
        uint256 totalTokens;
        uint256[] weights;
        address verifier;
        address odosRouter;
        address odosExecutor;
        uint256 rebalanceTimelock;
    }

    // constants
    uint256 public constant _MIN_INVARIANT_RATIO = 70e16; // 70%
    uint256 public constant _MAX_INVARIANT_RATIO = 300e16; // 300%
    uint256 public constant _MIN_SWAP_FEE_PERCENTAGE = 0.001e16; // 0.001%
    uint256 public constant _MAX_SWAP_FEE_PERCENTAGE = 10e16; // 10%

    // A minimum normalized weight imposes a maximum weight ratio. We need this due to limitations in the
    // implementation of the fixed point power function, as these ratios are often exponents.
    uint256 internal constant _MIN_WEIGHT = 1e16; // 1%

    // initialization
    uint256 public immutable totalTokens;
    IHalo2Verifier public immutable verifier;
    IOdosRouter public immutable odosRouter;
    address public immutable odosExecutor;

    // current weights
    mapping (uint256 => uint256) public normalizedWeights;

    // time in seconds, delay till next rebalance
    uint256 public rebalanceTimelock;
    // time in seconds, timestamp where rebalance happened
    uint256 public lastRebalanceTime;



    /**
     * @notice `getRate` from `IRateProvider` was called on a Weighted Pool.
     * @dev It is not safe to nest Weighted Pools as WITH_RATE tokens in other pools, where they function as their own
     * rate provider. The default `getRate` implementation from `BalancerPoolToken` computes the BPT rate using the
     * invariant, which has a non-trivial (and non-linear) error. Without the ability to specify a rounding direction,
     * the rate could be manipulable.
     *
     * It is fine to nest Weighted Pools as STANDARD tokens, or to use them with external rate providers that are
     * stable and have at most 1 wei of rounding error (e.g., oracle-based).
     */
    error WeightedPoolBptRateUnsupported();

    error NormalizedWeightInvariant();

    error VerificationFail();

    error DivisionByZero();

    error AlreadyInitialized();


    /// @notice remember to initialize the weights by running the optimization algo
    constructor(
        IVault vault,
        COCSwapPoolParams memory params
    ) BalancerPoolToken(vault, params.name, params.symbol) PoolInfo(vault) {
        totalTokens = params.totalTokens;
        _normalizeWeights(params.weights);

        verifier = IHalo2Verifier(params.verifier);
        odosRouter = IOdosRouter(params.odosRouter);
        odosExecutor = params.odosExecutor;
        rebalanceTimelock = params.rebalanceTimelock;
        lastRebalanceTime = block.timestamp;

    }

    /**
     * @notice Execute a swap in the pool.
     * @param params Swap parameters
     * @return amountCalculatedScaled18 Calculated amount for the swap
     */
    function onSwap(PoolSwapParams calldata params) external returns (uint256 amountCalculatedScaled18) {
        uint256 balanceTokenInScaled18 = params.balancesScaled18[params.indexIn];
        uint256 balanceTokenOutScaled18 = params.balancesScaled18[params.indexOut];

        if (params.kind == SwapKind.EXACT_IN) {
            uint256 amountOutScaled18 = WeightedMath.computeOutGivenExactIn(
                balanceTokenInScaled18,
                normalizedWeights[params.indexIn],
                balanceTokenOutScaled18,
                normalizedWeights[params.indexOut],
                params.amountGivenScaled18
            );

            return amountOutScaled18;
        } else {
            uint256 amountInScaled18 = WeightedMath.computeInGivenExactOut(
                balanceTokenInScaled18,
                normalizedWeights[params.indexIn],
                balanceTokenOutScaled18,
                normalizedWeights[params.indexOut],
                params.amountGivenScaled18
            );

            // Fees are added after scaling happens, to reduce the complexity of the rounding direction analysis.
            return amountInScaled18;
        }
    }

    /**
     * @notice Computes and returns the pool's invariant.
     * @dev This function computes the invariant based on current balances
     * @param balancesLiveScaled18 Array of current pool balances for each token in the pool, scaled to 18 decimals
     * @return invariant The calculated invariant of the pool, represented as a uint256
     */
    function computeInvariant(uint256[] memory balancesLiveScaled18, Rounding rounding) public view returns (uint256) {
        function(uint256[] memory, uint256[] memory) internal pure returns (uint256) _upOrDown = rounding ==
            Rounding.ROUND_UP
            ? WeightedMath.computeInvariantUp
            : WeightedMath.computeInvariantDown;

        return _upOrDown(getNormalizedWeights(), balancesLiveScaled18);
    }

    /**
     * @dev Computes the new balance of a token after an operation, given the invariant growth ratio and all other
     * balances.
     * @param balancesLiveScaled18 Current live balances (adjusted for decimals, rates, etc.)
     * @param tokenInIndex The index of the token we're computing the balance for (tokens are sorted alphanumerically)
     * @param invariantRatio The ratio of the new invariant (after an operation) to the old
     * @return newBalance The new balance of the selected token, after the operation
     */
    function computeBalance(
        uint256[] memory balancesLiveScaled18,
        uint256 tokenInIndex,
        uint256 invariantRatio
    ) external view returns (uint256 newBalance) {
         return
            WeightedMath.computeBalanceOutGivenInvariant(
                balancesLiveScaled18[tokenInIndex],
                normalizedWeights[tokenInIndex],
                invariantRatio
            );
    }

    /**
     * @notice Get the normalized weights.
     * @return normalizedWeights The normalized weights, sorted in token registration order
     */
    function getNormalizedWeights() public view returns (uint256[] memory) {
        uint256[] memory weights = new uint256[](totalTokens);

        for (uint256 i = 0; i < totalTokens; ++i) {
            weights[i] = normalizedWeights[i];
        }

        return weights;
    }


    /**
     * @notice The rebalance is done in 2 stages. updateWeights is needed for the first step. This is reliant on the ezkl circuit
     * @param proof The Zero Knowledge Proof bytestring
     * @param instances The instances used in the Zero Knowledge Proof
     */
    function updateWeights(bytes calldata proof, uint256[] calldata instances) public {
        // Chainlink only offers a single data slice which isn't sufficient for our models
        // TODO: We need a way to prove the data used here somehow
        // TODO: to decide if this should be protected???
        if (!verifier.verifyProof(proof, instances)) {
            revert VerificationFail();
        }

        _normalizeWeights(instances);
    }

    /**
     * @notice pass an array of weights this doesn't need to sum to one.
     * This routine gets the % weight given total sum. In the event of out of ranges it clips values.
     */
    function _normalizeWeights(uint256[] memory weights) internal {
        uint256 normalizedSum = 0;
        uint256 totalSum = 0;
        uint256 appliedSum = 0;

        // get total sum
        for (uint8 i = 0; i < totalTokens; ++i) {
            totalSum = totalSum + weights[i];
        }

        if (totalSum == 0) {
            revert DivisionByZero();
        }


        // Calculate normalized weights
        for (uint256 i = 0; i < totalTokens; ++i) {
            // Calculate weight as a percentage (scaled to 1e18 for precision)
            uint256 normalizedWeight = weights[i] * 1e18 / totalSum;

            // Apply minimum weight constraint
            if (normalizedWeight < _MIN_WEIGHT) {
                normalizedWeights[i] = _MIN_WEIGHT;
                appliedSum += _MIN_WEIGHT;
            } else {
                normalizedWeights[i] = normalizedWeight;
                appliedSum += normalizedWeight;
            }
        }

        // Handle rounding errors to ensure weights sum to 100%
        if (appliedSum != 1e18) {
            // Find the index of the largest weight to adjust
            uint256 largestIdx = 0;
            for (uint256 i = 1; i < totalTokens; ++i) {
                if (normalizedWeights[i] > normalizedWeights[largestIdx] && normalizedWeights[i] > _MIN_WEIGHT) {
                    largestIdx = i;
                }
            }

            if (appliedSum < 1e18) {
                // add to the largest weight to make the sum exactly 100%
                normalizedWeights[largestIdx] = normalizedWeights[largestIdx] + (1e18 - appliedSum);
            } else {
                // remove from the largest weight to make the sum exactly 100%
                normalizedWeights[largestIdx] = normalizedWeights[largestIdx] - (appliedSum - 1e18);

            }
        }

    }

    // Mock rebalance
    function rebalance(bytes memory pathDefinition) public returns (bool) {
        // TODO
        return true;
    }

    // /**
    //  * @notice The rebalance is done in 2 stages. rebalance is the second stage. This is reliant on an swap router like odos.
    //  * note that we will experience alpha decay once the pool has more money as slippage will increase.
    //  * @param pathDefinition the odos router path definition obtained from Odos API
    //  */
    // function rebalance(bytes memory pathDefinition) external {
    //     // Get current balances and calculate total value
    //     uint256[] memory currentBalances = new uint256[](_totalTokens);
    //     uint256[] memory targetBalances = new uint256[](_totalTokens);
    //     address[] memory tokenAddresses = new address[](_totalTokens);
    //     uint256 totalValue = 0;

    //     // Get current balances and token addresses
    //     for (uint8 i = 0; i < _totalTokens; ++i) {
    //         tokenAddresses[i] = tokens[i];
    //         currentBalances[i] = IERC20(tokens[i]).balanceOf(address(this));
    //         totalValue += currentBalances[i] * getTokenPrice(tokens[i]);
    //     }

    //     // Calculate target balances based on normalized weights
    //     uint256[] memory normalizedWeights = new uint256[](_totalTokens);
    //     for (uint8 i = 0; i < _totalTokens; ++i) {
    //         if (i == 0) { normalizedWeights[i] = normalizedWeight0; }
    //         else if (i == 1) { normalizedWeights[i] = normalizedWeight1; }
    //         else if (i == 2) { normalizedWeights[i] = normalizedWeight2; }
    //         else if (i == 3) { normalizedWeights[i] = normalizedWeight3; }
    //         else if (i == 4) { normalizedWeights[i] = normalizedWeight4; }
    //         else if (i == 5) { normalizedWeights[i] = normalizedWeight5; }

    //         // Calculate target balance based on weight
    //         targetBalances[i] = (totalValue * normalizedWeights[i]) / FixedPoint.ONE;
    //         // TODO get token price from chainlink
    //         targetBalances[i] = targetBalances[i] / getTokenPrice(tokens[i]);
    //     }

    //     // Determine which tokens to sell (input) and which to buy (output)
    //     IOdosRouter.inputTokenInfo[] memory inputs = new IOdosRouter.inputTokenInfo[](0);
    //     IOdosRouter.outputTokenInfo[] memory outputs = new IOdosRouter.outputTokenInfo[](0);

    //     // First, count how many inputs and outputs we'll have
    //     uint256 inputCount = 0;
    //     uint256 outputCount = 0;

    //     for (uint8 i = 0; i < _totalTokens; ++i) {
    //         if (currentBalances[i] > targetBalances[i]) {
    //             inputCount++;
    //         } else if (currentBalances[i] < targetBalances[i]) {
    //             outputCount++;
    //         }
    //     }

    //     // Then, create the arrays with the correct size
    //     inputs = new IOdosRouter.inputTokenInfo[](inputCount);
    //     outputs = new IOdosRouter.outputTokenInfo[](outputCount);

    //     // Fill the input and output arrays
    //     uint256 inputIndex = 0;
    //     uint256 outputIndex = 0;

    //     for (uint8 i = 0; i < _totalTokens; ++i) {
    //         if (currentBalances[i] > targetBalances[i]) {
    //             // We need to sell some of this token
    //             uint256 amountToSell = currentBalances[i] - targetBalances[i];
    //             inputs[inputIndex] = IOdosRouter.inputTokenInfo({
    //                 tokenAddress: tokens[i],
    //                 amountIn: amountToSell,
    //                 receiver: address(this)
    //             });
    //             ++inputIndex;
    //         } else if (currentBalances[i] < targetBalances[i]) {
    //             // We need to buy some of this token
    //             // For relative value, use the difference in value terms
    //             uint256 valueNeeded = (targetBalances[i] - currentBalances[i]) * getTokenPrice(tokens[i]);
    //             outputs[outputIndex] = IOdosRouter.outputTokenInfo({
    //                 tokenAddress: tokens[i],
    //                 relativeValue: valueNeeded,
    //                 receiver: address(this)
    //             });
    //             ++outputIndex;
    //         }
    //     }

    //     // Skip if no rebalancing needed
    //     if (inputs.length == 0 || outputs.length == 0) {
    //         return;
    //     }

    //     // Approve the router to spend our tokens
    //     for (uint256 i = 0; i < inputs.length; i++) {
    //         IERC20(inputs[i].tokenAddress).approve(address(odosRouter), inputs[i].amountIn);
    //     }

    //     // Execute the swap
    //     odosRouter.swapMulti(
    //         inputs,
    //         outputs,
    //         0, // We're setting minimum value out to 0 to ensure the transaction doesn't revert
    //         pathDefinition,
    //         odosExecutor,
    //         0 // No referral code
    //     );

    //     emit Rebalanced();
    // }

    //The minimum swap fee percentage for a pool
    function getMinimumSwapFeePercentage() external pure returns (uint256) {
        return _MIN_SWAP_FEE_PERCENTAGE;
    }

    // The maximum swap fee percentage for a pool
    function getMaximumSwapFeePercentage() external pure returns (uint256) {
        return _MAX_SWAP_FEE_PERCENTAGE;
    }

    /// @inheritdoc IUnbalancedLiquidityInvariantRatioBounds
    function getMinimumInvariantRatio() external pure returns (uint256) {
        return WeightedMath._MIN_INVARIANT_RATIO;
    }

    /// @inheritdoc IUnbalancedLiquidityInvariantRatioBounds
    function getMaximumInvariantRatio() external pure returns (uint256) {
        return WeightedMath._MAX_INVARIANT_RATIO;
    }

    function getWeightedPoolDynamicData() external view virtual returns (WeightedPoolDynamicData memory data) {
        data.balancesLiveScaled18 = _vault.getCurrentLiveBalances(address(this));
        (, data.tokenRates) = _vault.getPoolTokenRates(address(this));
        data.staticSwapFeePercentage = _vault.getStaticSwapFeePercentage((address(this)));
        data.totalSupply = totalSupply();

        PoolConfig memory poolConfig = _vault.getPoolConfig(address(this));
        data.isPoolInitialized = poolConfig.isPoolInitialized;
        data.isPoolPaused = poolConfig.isPoolPaused;
        data.isPoolInRecoveryMode = poolConfig.isPoolInRecoveryMode;
    }

    function getWeightedPoolImmutableData() external view virtual returns (WeightedPoolImmutableData memory data) {
        data.tokens = _vault.getPoolTokens(address(this));
        (data.decimalScalingFactors, ) = _vault.getPoolTokenRates(address(this));
        data.normalizedWeights = getNormalizedWeights();
    }

    function getRate() public pure override returns (uint256) {
        revert WeightedPoolBptRateUnsupported();
    }

}
