//SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { BalancerPoolToken } from "@balancer-labs/v3-vault/contracts/BalancerPoolToken.sol";
import { IWeightedPool } from "@balancer-labs/v3-interfaces/contracts/pool-weighted/IWeightedPool.sol";
import { PoolSwapParams, Rounding } from "@balancer-labs/v3-interfaces/contracts/vault/VaultTypes.sol";
import { IVault } from "@balancer-labs/v3-interfaces/contracts/vault/IVault.sol";
import { FixedPoint } from "@balancer-labs/v3-solidity-utils/contracts/math/FixedPoint.sol";
import { WeightedMath } from "@balancer-labs/v3-solidity-utils/contracts/math/WeightedMath.sol";
import { InputHelpers } from "@balancer-labs/v3-solidity-utils/contracts/helpers/InputHelpers.sol";
import {
    IUnbalancedLiquidityInvariantRatioBounds
} from "@balancer-labs/v3-interfaces/contracts/vault/IUnbalancedLiquidityInvariantRatioBounds.sol";


/**
 * @title Halo2Verifier from ezkl
 * @notice This is the Halo2Verifier from the ezkl library
 * You will need to obtain the PK (proving key) in order to generate the proof and instances
 */
interface IHalo2Verifier {
    function verifyProof(
        bytes calldata proof,
        uint256[] calldata instances
    ) external returns (bool)
}

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
        returns (uint256[] memory amountsOut)
}



/**
 * @title COCSwap Pool
 * @notice COCSwap pool is a custom pool which actively rebalances its vault using convex optimization.
 * The rebalancing is made verifiable using EZKL Halo2Verifier.
 * https://blog.ezkl.xyz/post/cocswap/
 */
contract COCSwapPool is IWeightedPool, BalancerPoolToken {
    using FixedPoint for uint256;

    // constants
    uint256 public constant _MIN_INVARIANT_RATIO = 70e16; // 70%
    uint256 public constant _MAX_INVARIANT_RATIO = 300e16; // 300%
    uint256 public constant _MIN_SWAP_FEE_PERCENTAGE = 0.001e16; // 0.001%
    uint256 public constant _MAX_SWAP_FEE_PERCENTAGE = 10e16; // 10%

    // A minimum normalized weight imposes a maximum weight ratio. We need this due to limitations in the
    // implementation of the fixed point power function, as these ratios are often exponents.
    uint256 internal constant _MIN_WEIGHT = 1e16; // 1%

    // initialization
    uint256 public totalTokens;
    uint256 public pool
    IHalo2Verifier public verifier;
    IOdosRouter public odosRouter;


    // current weights, note that we reduced this from 8 to 6
    uint256 public normalizedWeight0;
    uint256 public normalizedWeight1;
    uint256 public normalizedWeight2;
    uint256 public normalizedWeight3;
    uint256 public normalizedWeight4;
    uint256 public normalizedWeight5;

    // pending weights
    uint256 public pendingWeight0;
    uint256 public pendingWeight1;
    uint256 public pendingWeight2;
    uint256 public pendingWeight3;
    uint256 public pendingWeight4;
    uint256 public pendingWeight5;

    // time in seconds, delay till next rebalance
    uint64 public rebalanceDelay;
    // time in seconds, short cooldown (1min) after each rebalance to prevent sniping
    uint64 public cooldown;
    // time in seconds, timestamp where rebalance happened
    uint64 public lastRebalanceTime;



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


    /// @notice remember to initialize the weights by running the optimization algo
    constructor(IVault vault, string memory name, string memory symbol) BalancerPoolToken(vault, name, symbol) {
        totalTokens = params.numTokens;
        InputHelpers.ensureInputLengthMatch(totalTokens, params.normalizedWeights.length);

        // Ensure each normalized weight is above the minimum.
        uint256 normalizedSum = 0;
        for (uint8 i = 0; i < totalTokens; ++i) {
            uint256 _normalizedWeight = params.normalizedWeights[i];

            if (_normalizedWeight < _MIN_WEIGHT) {
                revert MinWeight();
            }
            normalizedSum = normalizedSum + _normalizedWeight;

            // prettier-ignore
            if (i == 0) { normalizedWeight0 = _normalizedWeight; }
            else if (i == 1) { normalizedWeight1 = _normalizedWeight; }
            else if (i == 2) { normalizedWeight2 = _normalizedWeight; }
            else if (i == 3) { normalizedWeight3 = _normalizedWeight; }
            else if (i == 4) { normalizedWeight4 = _normalizedWeight; }
            else if (i == 5) { normalizedWeight5 = _normalizedWeight; }
        }

        // Ensure that the normalized weights sum to ONE.
        if (normalizedSum != FixedPoint.ONE) {
            revert NormalizedWeightInvariant();
        }
    }

    /**
     * @notice Initialize the hooks contract
     * @dev This function is called instead of a constructor since the pool will be deployed via factory
     * @param _pool The pool address this hooks contract is associated with
     * @param _zkVerifier The Halo2 verifier contract
     * @param _odosRouter The Odos router for executing swaps
     * @param _oracleDataProvider The oracle data provider address
     * @param _rebalanceTimelock Minimum time between rebalances
     */
    function initialize(
        address _pool,
        address _verifier,
        address _odosRouter,
        address _oracleDataProvider,
        uint256 _rebalanceTimelock
    ) external {
        require(pool == address(0), "Already initialized");
        require(_pool != address(0), "Invalid pool address");

        pool = _pool;
        verifier = IHalo2Verifier(_verifier);
        odosRouter = IOdosRouter(_odosRouter);
        oracleDataProvider = _oracleDataProvider;
        rebalanceTimelock = _rebalanceTimelock;
        lastRebalanceTime = block.timestamp;

        emit InitializedCOCSwapPool(_pool, _zkVerifier, _odosRouter);
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
                _getNormalizedWeight(params.indexIn),
                balanceTokenOutScaled18,
                _getNormalizedWeight(params.indexOut),
                params.amountGivenScaled18
            );

            return amountOutScaled18;
        } else {
            uint256 amountInScaled18 = WeightedMath.computeInGivenExactOut(
                balanceTokenInScaled18,
                _getNormalizedWeight(params.indexIn),
                balanceTokenOutScaled18,
                _getNormalizedWeight(params.indexOut),
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

        return _upOrDown(_getNormalizedWeights(), balancesLiveScaled18);
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
                _getNormalizedWeight(tokenInIndex),
                invariantRatio
            );
    }

    /**
     * @notice Get the normalized weights.
     * @return normalizedWeights The normalized weights, sorted in token registration order
     */
    function getNormalizedWeights() external view returns (uint256[] memory) {
        return _getNormalizedWeights();
    }

    function _getNormalizedWeight(uint256 tokenIndex) internal view virtual returns (uint256) {
        // prettier-ignore
        if (tokenIndex == 0) { return _normalizedWeight0; }
        else if (tokenIndex == 1) { return _normalizedWeight1; }
        else if (tokenIndex == 2) { return _normalizedWeight2; }
        else if (tokenIndex == 3) { return _normalizedWeight3; }
        else if (tokenIndex == 4) { return _normalizedWeight4; }
        else if (tokenIndex == 5) { return _normalizedWeight5; }
        else {
            revert IVaultErrors.InvalidToken();
        }
    }

    function _getNormalizedWeights() internal view virtual returns (uint256[] memory) {
        uint256 _totalTokens = totalTokens;
        uint256[] memory normalizedWeights = new uint256[](_totalTokens);

        // prettier-ignore
        {
            normalizedWeights[0] = _normalizedWeight0;
            normalizedWeights[1] = _normalizedWeight1;
            if (totalTokens > 2) { normalizedWeights[2] = _normalizedWeight2; } else { return normalizedWeights; }
            if (totalTokens > 3) { normalizedWeights[3] = _normalizedWeight3; } else { return normalizedWeights; }
            if (totalTokens > 4) { normalizedWeights[4] = _normalizedWeight4; } else { return normalizedWeights; }
            if (totalTokens > 5) { normalizedWeights[5] = _normalizedWeight5; }
        }

        return normalizedWeights;
    }

    function _getNormalizedWeight(uint256 tokenIndex) internal view virtual returns (uint256) {
        // prettier-ignore
        if (tokenIndex == 0) { return _normalizedWeight0; }
        else if (tokenIndex == 1) { return _normalizedWeight1; }
        else if (tokenIndex == 2) { return _normalizedWeight2; }
        else if (tokenIndex == 3) { return _normalizedWeight3; }
        else if (tokenIndex == 4) { return _normalizedWeight4; }
        else if (tokenIndex == 5) { return _normalizedWeight5; }
        else if (tokenIndex == 6) { return _normalizedWeight6; }
        else if (tokenIndex == 7) { return _normalizedWeight7; }
        else {
            revert IVaultErrors.InvalidToken();
        }
    }

    /**
     * @notice The rebalance is done in 2 stages. updateWeights is needed for the first step. This is reliant on the ezkl circuit
     * @param proof The Zero Knowledge Proof bytestring
     * @param instances The instances used in the Zero Knowledge Proof
     */
    function updateWeights(bytes calldata proof, uint256[] calldata instances) external {
        InputHelpers.ensureInputLengthMatch(totalTokens, params.normalizedWeights.length);

        for (uint8 i = 0; i < _totalTokens; ++i) {
            // We use FixedPoint operations to ensure proper rounding
            uint256 normalizedWeight = instances[i];

            // Validate each weight meets minimum requirement
            if (normalizedWeight < _MIN_WEIGHT) {
                revert MinWeight();
            }

            normalizedWeights[i] = normalizedWeight;
            normalizedSum = normalizedSum + normalizedWeight;
        }

        // Ensure that the normalized weights sum to ONE with proper rounding tolerance
        // Using a small epsilon to account for potential rounding errors
        if (normalizedSum < FixedPoint.ONE - 10 || normalizedSum > FixedPoint.ONE + 10) {
            revert NormalizedWeightInvariant();
        }

        // Assign pending weights with verified values
        for (uint8 i = 0; i < _totalTokens; ++i) {
            // prettier-ignore
            if (i == 0) { pendingWeight0 = normalizedWeights[i]; }
            else if (i == 1) { pendingWeight1 = normalizedWeights[i]; }
            else if (i == 2) { pendingWeight2 = normalizedWeights[i]; }
            else if (i == 3) { pendingWeight3 = normalizedWeights[i]; }
            else if (i == 4) { pendingWeight4 = normalizedWeights[i]; }
            else if (i == 5) { pendingWeight5 = normalizedWeights[i]; }
        }

        if (!verifier.verifyProof(proof, instances)) {
            revert VerificationFail();
        };

    }

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

    /// @inheritdoc IWeightedPool
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

    /// @inheritdoc IWeightedPool
    function getWeightedPoolImmutableData() external view virtual returns (WeightedPoolImmutableData memory data) {
        data.tokens = _vault.getPoolTokens(address(this));
        (data.decimalScalingFactors, ) = _vault.getPoolTokenRates(address(this));
        data.normalizedWeights = _getNormalizedWeights();
    }

    /// @inheritdoc IRateProvider
    function getRate() public pure override returns (uint256) {
        revert WeightedPoolBptRateUnsupported();
    }

}
