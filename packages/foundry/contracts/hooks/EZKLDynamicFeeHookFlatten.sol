// SPDX-License-Identifier: AGPL-3.0
pragma solidity ^0.8.0 ^0.8.20 ^0.8.24;

// contracts/utils/ChainlinkPriceCache.sol

/**
 * @title IChainlinkCache
 * @notice Interface for the ChainlinkCache contract
 * @dev Defines methods for retrieving historical oracle data
 */
interface IChainlinkPriceCache {
    /**
     * @notice Get historical price array
     * @param lookback Number of answers to retrieve from current position
     * @return Array of historical prices
     */
    function getHistoricalPrice(uint256 lookback) external view returns (uint256[] memory);

    /**
     * @notice Get historical price array between specified snapshot IDs
     * @param start The starting snapshot ID (inclusive)
     * @param end The ending snapshot ID (inclusive)
     * @return Array of historical prices
     */
    function getHistoricalPriceRange(uint256 start, uint256 end) external view returns (uint256[] memory);

    /**
     * @notice Get historical timestamps
     * @param lookback Number of answers to retrieve from current position
     * @return Array of historical timestamps
     */
    function getHistoricalTimestamp(uint256 lookback) external view returns (uint256[] memory);

    /**
     * @notice Get historical timestamps
     * @param start The starting snapshot ID (inclusive)
     * @param end The ending snapshot ID (inclusive)
     * @return Array of historical timestamps
     */
    function getHistoricalTimestampRange(uint256 start, uint256 end) external view returns (uint256[] memory);

    /**
     * @notice update the cache
     */
    function update() external;
}

/**
 * @title IAggregatorInterface
 * @notice Interface for Chainlink oracle aggregators
 */
interface IAggregatorInterface {
    function latestAnswer() external view returns (int256);
    function latestTimestamp() external view returns (uint256);
    function latestRound() external view returns (uint256);
    function getAnswer(uint256 roundId) external view returns (int256);
    function getTimestamp(uint256 roundId) external view returns (uint256);

    event AnswerUpdated(int256 indexed current, uint256 indexed roundId, uint256 updatedAt);
    event NewRound(uint256 indexed roundId, address indexed startedBy, uint256 startedAt);
}

/**
 * @title ChainlinkPriceCache
 * @notice Contract for caching Chainlink price data and timestamps in easy to access array
 */
contract ChainlinkPriceCache is IChainlinkPriceCache {

    // oracle addresses:
    // mainnet
    // ETH/USD contract address 0x5f4eC3Df9cbd43714FE2740f5E3616155c5b8419
    // USDC/ETH contract address 0x986b5E1e1755e3C2440e960477f25201B0a8bbD4
    // arbitrum
    // ETH/USD contract address 0x639Fe6ab55C921f74e7fac1ee960C0B6293ba612
    // base
    // ETH/USD contract address 0x71041dddad3595F9CEd3DcCFBe3D1F4b0a16Bb70
    // USDC/USD contract address 0x7e860098F58bBFC8648a4311b374B1D669a2bc6B

    IAggregatorInterface public immutable oracle;

    // delay in seconds until the next update can be made
    uint256 public immutable delay;

    // last updated snapshot ID
    uint256 public latestSnapshotId;

    // description
    string public description;

    // storage for oracle data snapshots
    mapping (uint256 => uint256) public timestamps;
    mapping (uint256 => uint256)  public prices;

    error WaitForDelay();
    error InvalidRange();
    error NoDataAvailable();

    event Updated(uint256 indexed timestamp, uint256 price);

    /**
     * @notice Initializes the contract with an oracle and historical data
     * @param _description Description of cache
     * @param _oracle Chainlink oracle address
     * @param _delay Minimum delay in seconds between updates
     * @param _roundIds Array of Chainlink round IDs to populate initial history
     */
    constructor(string memory _description, address _oracle, uint256 _delay, uint256[] memory _roundIds) {
        oracle = IAggregatorInterface(_oracle);
        delay = _delay;
        description = _description;
        
        uint256 roundIdsLength = _roundIds.length;
        
        if (roundIdsLength == 0) {
            latestSnapshotId = 0;
            return;
        }
        
        latestSnapshotId = roundIdsLength - 1;

        for (uint256 i = 0; i < roundIdsLength; ++i) {
            timestamps[i] = oracle.getTimestamp(_roundIds[i]);
            prices[i] = uint256(oracle.getAnswer(_roundIds[i]));
        }
    }

    /// @inheritdoc IChainlinkPriceCache
    function update() external {
        uint256 lastTimestamp = timestamps[latestSnapshotId];

        uint256 latestTimestamp = oracle.latestTimestamp();
        uint256 latestPrice = uint256(oracle.latestAnswer());

        if ((lastTimestamp + delay) > latestTimestamp) {
            revert WaitForDelay();
        }

        ++latestSnapshotId;

        timestamps[latestSnapshotId] = latestTimestamp;
        prices[latestSnapshotId] = latestPrice;

        emit Updated(latestTimestamp, latestPrice);
    }

    /// @inheritdoc IChainlinkPriceCache
    function getHistoricalPrice(uint256 lookback) external view returns (uint256[] memory) {
        if (latestSnapshotId == 0 && prices[0] == 0) {
            revert NoDataAvailable();
        }
        
        // Check if lookback exceeds available history
        if (lookback > latestSnapshotId + 1) {
            revert NoDataAvailable();
        }
        
        uint256[] memory result = new uint256[](lookback);
        
        for (uint256 i = 0; i < lookback; i++) {
            uint256 snapshotId = latestSnapshotId - i;
            result[i] = prices[snapshotId];
        }
        
        return result;
    }

    /// @inheritdoc IChainlinkPriceCache
    function getHistoricalTimestamp(uint256 lookback) external view returns (uint256[] memory) {
        if (latestSnapshotId == 0 && timestamps[0] == 0) {
            revert NoDataAvailable();
        }

        // Check if lookback exceeds available history
        if (lookback > latestSnapshotId + 1) {
            revert NoDataAvailable();
        }

        uint256[] memory result = new uint256[](lookback);

        for (uint256 i = 0; i < lookback; i++) {
            uint256 snapshotId = latestSnapshotId - i;
            result[i] = timestamps[snapshotId];
        }

        return result;
    }

    /// @inheritdoc IChainlinkPriceCache
    function getHistoricalPriceRange(uint256 start, uint256 end) external view returns (uint256[] memory) {
        if (end < start || end > latestSnapshotId) {
            revert InvalidRange();
        }
        
        if (latestSnapshotId == 0 && timestamps[0] == 0) {
            revert NoDataAvailable();
        }
        
        uint256 size = end - start + 1;
        uint256[] memory result = new uint256[](size);
        
        for (uint256 i = 0; i < size; i++) {
            result[i] = prices[start + i];
        }
        
        return result;
    }

    /// @inheritdoc IChainlinkPriceCache
    function getHistoricalTimestampRange(uint256 start, uint256 end) external view returns (uint256[] memory) {
        if (end < start || end > latestSnapshotId) {
            revert InvalidRange();
        }

        if (latestSnapshotId == 0 && timestamps[0] == 0) {
            revert NoDataAvailable();
        }

        uint256 size = end - start + 1;
        uint256[] memory result = new uint256[](size);

        for (uint256 i = 0; i < size; i++) {
            result[i] = timestamps[start + i];
        }

        return result;
    }
}

// lib/balancer-v3-monorepo/pkg/interfaces/contracts/solidity-utils/helpers/IAuthentication.sol

/// @notice Simple interface for permissioned calling of external functions.
interface IAuthentication {
    /// @notice The sender does not have permission to call a function.
    error SenderNotAllowed();

    /**
     * @notice Returns the action identifier associated with the external function described by `selector`.
     * @param selector The 4-byte selector of the permissioned function
     * @return actionId The computed actionId
     */
    function getActionId(bytes4 selector) external view returns (bytes32 actionId);
}

// lib/balancer-v3-monorepo/pkg/interfaces/contracts/vault/IAuthorizer.sol

/// @notice Interface to the Vault's permission system.
interface IAuthorizer {
    /**
     * @notice Returns true if `account` can perform the action described by `actionId` in the contract `where`.
     * @param actionId Identifier for the action to be performed
     * @param account Account trying to perform the action
     * @param where Target contract for the action
     * @return success True if the action is permitted
     */
    function canPerform(bytes32 actionId, address account, address where) external view returns (bool success);
}

// lib/permit2/src/interfaces/IEIP712.sol

interface IEIP712 {
    function DOMAIN_SEPARATOR() external view returns (bytes32);
}

// lib/openzeppelin-contracts/contracts/token/ERC20/IERC20.sol

// OpenZeppelin Contracts (last updated v5.0.0) (token/ERC20/IERC20.sol)

/**
 * @dev Interface of the ERC20 standard as defined in the EIP.
 */
interface IERC20 {
    /**
     * @dev Emitted when `value` tokens are moved from one account (`from`) to
     * another (`to`).
     *
     * Note that `value` may be zero.
     */
    event Transfer(address indexed from, address indexed to, uint256 value);

    /**
     * @dev Emitted when the allowance of a `spender` for an `owner` is set by
     * a call to {approve}. `value` is the new allowance.
     */
    event Approval(address indexed owner, address indexed spender, uint256 value);

    /**
     * @dev Returns the value of tokens in existence.
     */
    function totalSupply() external view returns (uint256);

    /**
     * @dev Returns the value of tokens owned by `account`.
     */
    function balanceOf(address account) external view returns (uint256);

    /**
     * @dev Moves a `value` amount of tokens from the caller's account to `to`.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * Emits a {Transfer} event.
     */
    function transfer(address to, uint256 value) external returns (bool);

    /**
     * @dev Returns the remaining number of tokens that `spender` will be
     * allowed to spend on behalf of `owner` through {transferFrom}. This is
     * zero by default.
     *
     * This value changes when {approve} or {transferFrom} are called.
     */
    function allowance(address owner, address spender) external view returns (uint256);

    /**
     * @dev Sets a `value` amount of tokens as the allowance of `spender` over the
     * caller's tokens.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * IMPORTANT: Beware that changing an allowance with this method brings the risk
     * that someone may use both the old and the new allowance by unfortunate
     * transaction ordering. One possible solution to mitigate this race
     * condition is to first reduce the spender's allowance to 0 and set the
     * desired value afterwards:
     * https://github.com/ethereum/EIPs/issues/20#issuecomment-263524729
     *
     * Emits an {Approval} event.
     */
    function approve(address spender, uint256 value) external returns (bool);

    /**
     * @dev Moves a `value` amount of tokens from `from` to `to` using the
     * allowance mechanism. `value` is then deducted from the caller's
     * allowance.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * Emits a {Transfer} event.
     */
    function transferFrom(address from, address to, uint256 value) external returns (bool);
}

// contracts/pools/IHalo2Verifier.sol

/**
 * @title Halo2Verifier from ezkl
 * @notice This is the Halo2Verifier from the ezkl library
 * You will need to obtain the PK (proving key) in order to generate the proof and instances
 */
interface IHalo2Verifier {
    function verifyProof(
        bytes calldata proof,
        uint256[] calldata instances
    ) external returns (bool);
}

// lib/balancer-v3-monorepo/pkg/interfaces/contracts/solidity-utils/helpers/IRateProvider.sol

/// @notice General interface for token exchange rates.
interface IRateProvider {
    /**
     * @notice An 18 decimal fixed point number representing the exchange rate of one token to another related token.
     * @dev The meaning of this rate depends on the context. Note that there may be an error associated with a token
     * rate, and the caller might require a certain rounding direction to ensure correctness. This (legacy) interface
     * does not take a rounding direction or return an error, so great care must be taken when interpreting and using
     * rates in downstream computations.
     *
     * @return rate The current token rate
     */
    function getRate() external view returns (uint256 rate);
}

// lib/permit2/src/interfaces/IAllowanceTransfer.sol

/// @title AllowanceTransfer
/// @notice Handles ERC20 token permissions through signature based allowance setting and ERC20 token transfers by checking allowed amounts
/// @dev Requires user's token approval on the Permit2 contract
interface IAllowanceTransfer is IEIP712 {
    /// @notice Thrown when an allowance on a token has expired.
    /// @param deadline The timestamp at which the allowed amount is no longer valid
    error AllowanceExpired(uint256 deadline);

    /// @notice Thrown when an allowance on a token has been depleted.
    /// @param amount The maximum amount allowed
    error InsufficientAllowance(uint256 amount);

    /// @notice Thrown when too many nonces are invalidated.
    error ExcessiveInvalidation();

    /// @notice Emits an event when the owner successfully invalidates an ordered nonce.
    event NonceInvalidation(
        address indexed owner, address indexed token, address indexed spender, uint48 newNonce, uint48 oldNonce
    );

    /// @notice Emits an event when the owner successfully sets permissions on a token for the spender.
    event Approval(
        address indexed owner, address indexed token, address indexed spender, uint160 amount, uint48 expiration
    );

    /// @notice Emits an event when the owner successfully sets permissions using a permit signature on a token for the spender.
    event Permit(
        address indexed owner,
        address indexed token,
        address indexed spender,
        uint160 amount,
        uint48 expiration,
        uint48 nonce
    );

    /// @notice Emits an event when the owner sets the allowance back to 0 with the lockdown function.
    event Lockdown(address indexed owner, address token, address spender);

    /// @notice The permit data for a token
    struct PermitDetails {
        // ERC20 token address
        address token;
        // the maximum amount allowed to spend
        uint160 amount;
        // timestamp at which a spender's token allowances become invalid
        uint48 expiration;
        // an incrementing value indexed per owner,token,and spender for each signature
        uint48 nonce;
    }

    /// @notice The permit message signed for a single token allowance
    struct PermitSingle {
        // the permit data for a single token alownce
        PermitDetails details;
        // address permissioned on the allowed tokens
        address spender;
        // deadline on the permit signature
        uint256 sigDeadline;
    }

    /// @notice The permit message signed for multiple token allowances
    struct PermitBatch {
        // the permit data for multiple token allowances
        PermitDetails[] details;
        // address permissioned on the allowed tokens
        address spender;
        // deadline on the permit signature
        uint256 sigDeadline;
    }

    /// @notice The saved permissions
    /// @dev This info is saved per owner, per token, per spender and all signed over in the permit message
    /// @dev Setting amount to type(uint160).max sets an unlimited approval
    struct PackedAllowance {
        // amount allowed
        uint160 amount;
        // permission expiry
        uint48 expiration;
        // an incrementing value indexed per owner,token,and spender for each signature
        uint48 nonce;
    }

    /// @notice A token spender pair.
    struct TokenSpenderPair {
        // the token the spender is approved
        address token;
        // the spender address
        address spender;
    }

    /// @notice Details for a token transfer.
    struct AllowanceTransferDetails {
        // the owner of the token
        address from;
        // the recipient of the token
        address to;
        // the amount of the token
        uint160 amount;
        // the token to be transferred
        address token;
    }

    /// @notice A mapping from owner address to token address to spender address to PackedAllowance struct, which contains details and conditions of the approval.
    /// @notice The mapping is indexed in the above order see: allowance[ownerAddress][tokenAddress][spenderAddress]
    /// @dev The packed slot holds the allowed amount, expiration at which the allowed amount is no longer valid, and current nonce thats updated on any signature based approvals.
    function allowance(address user, address token, address spender)
        external
        view
        returns (uint160 amount, uint48 expiration, uint48 nonce);

    /// @notice Approves the spender to use up to amount of the specified token up until the expiration
    /// @param token The token to approve
    /// @param spender The spender address to approve
    /// @param amount The approved amount of the token
    /// @param expiration The timestamp at which the approval is no longer valid
    /// @dev The packed allowance also holds a nonce, which will stay unchanged in approve
    /// @dev Setting amount to type(uint160).max sets an unlimited approval
    function approve(address token, address spender, uint160 amount, uint48 expiration) external;

    /// @notice Permit a spender to a given amount of the owners token via the owner's EIP-712 signature
    /// @dev May fail if the owner's nonce was invalidated in-flight by invalidateNonce
    /// @param owner The owner of the tokens being approved
    /// @param permitSingle Data signed over by the owner specifying the terms of approval
    /// @param signature The owner's signature over the permit data
    function permit(address owner, PermitSingle memory permitSingle, bytes calldata signature) external;

    /// @notice Permit a spender to the signed amounts of the owners tokens via the owner's EIP-712 signature
    /// @dev May fail if the owner's nonce was invalidated in-flight by invalidateNonce
    /// @param owner The owner of the tokens being approved
    /// @param permitBatch Data signed over by the owner specifying the terms of approval
    /// @param signature The owner's signature over the permit data
    function permit(address owner, PermitBatch memory permitBatch, bytes calldata signature) external;

    /// @notice Transfer approved tokens from one address to another
    /// @param from The address to transfer from
    /// @param to The address of the recipient
    /// @param amount The amount of the token to transfer
    /// @param token The token address to transfer
    /// @dev Requires the from address to have approved at least the desired amount
    /// of tokens to msg.sender.
    function transferFrom(address from, address to, uint160 amount, address token) external;

    /// @notice Transfer approved tokens in a batch
    /// @param transferDetails Array of owners, recipients, amounts, and tokens for the transfers
    /// @dev Requires the from addresses to have approved at least the desired amount
    /// of tokens to msg.sender.
    function transferFrom(AllowanceTransferDetails[] calldata transferDetails) external;

    /// @notice Enables performing a "lockdown" of the sender's Permit2 identity
    /// by batch revoking approvals
    /// @param approvals Array of approvals to revoke.
    function lockdown(TokenSpenderPair[] calldata approvals) external;

    /// @notice Invalidate nonces for a given (token, spender) pair
    /// @param token The token to invalidate nonces for
    /// @param spender The spender to invalidate nonces for
    /// @param newNonce The new nonce to set. Invalidates all nonces less than it.
    /// @dev Can't invalidate more than 2**16 nonces per transaction.
    function invalidateNonces(address token, address spender, uint48 newNonce) external;
}

// lib/balancer-v3-monorepo/pkg/interfaces/contracts/vault/IBasePoolFactory.sol

/**
 * @notice Base interface for a Balancer Pool Factory.
 * @dev All pool factories should be derived from `BasePoolFactory` to enable common behavior for all pool types
 * (e.g., address prediction, tracking deployed pools, and governance-facilitated migration).
 */
interface IBasePoolFactory is IAuthentication {
    /**
     * @notice A pool was deployed.
     * @param pool The address of the new pool
     */
    event PoolCreated(address indexed pool);

    /// @notice The factory was disabled by governance.
    event FactoryDisabled();

    /// @notice Attempted pool creation after the factory was disabled.
    error Disabled();

    /// @notice A pool index is beyond the current bounds of the array.
    error IndexOutOfBounds();

    /**
     * @notice Check whether a pool was deployed by this factory.
     * @param pool The pool to check
     * @return success True if `pool` was created by this factory
     */
    function isPoolFromFactory(address pool) external view returns (bool success);

    /**
     * @notice Return the total number of pools deployed by this factory.
     * @dev This can then be used to "paginate" calls to `getPools` to control gas costs.
     * @return poolCount The number of pools deployed by this factory
     */
    function getPoolCount() external view returns (uint256 poolCount);

    /**
     * @notice Return a subset of the list of pools deployed by this factory.
     * @dev `start` must be a valid index, but if `count` exceeds the total length, it will not revert, but simply
     * stop at the end and return fewer results than requested.
     *
     * @param start The index of the first pool to return
     * @param count The maximum number of pools to return
     * @return pools The list of pools deployed by this factory, starting at `start` and returning up to `count` pools
     */
    function getPoolsInRange(uint256 start, uint256 count) external view returns (address[] memory pools);

    /**
     * @notice Return the complete list of pools deployed by this factory.
     * @return pools The list of pools deployed by this factory
     */
    function getPools() external view returns (address[] memory pools);

    /**
     * @notice Return the address where a new pool will be deployed, based on the factory address and salt.
     * @param constructorArgs The arguments used to create the pool
     * @param salt The salt used to deploy the pool
     * @return deploymentAddress The predicted address of the pool, given the salt
     */
    function getDeploymentAddress(
        bytes memory constructorArgs,
        bytes32 salt
    ) external view returns (address deploymentAddress);

    /**
     * @notice Check whether this factory has been disabled by governance.
     * @return success True if this factory was disabled
     */
    function isDisabled() external view returns (bool success);

    /**
     * @notice Disable the factory, preventing the creation of more pools.
     * @dev Existing pools are unaffected. Once a factory is disabled, it cannot be re-enabled.
     */
    function disable() external;
}

// lib/openzeppelin-contracts/contracts/token/ERC20/extensions/IERC20Metadata.sol

// OpenZeppelin Contracts (last updated v5.0.0) (token/ERC20/extensions/IERC20Metadata.sol)

/**
 * @dev Interface for the optional metadata functions from the ERC20 standard.
 */
interface IERC20Metadata is IERC20 {
    /**
     * @dev Returns the name of the token.
     */
    function name() external view returns (string memory);

    /**
     * @dev Returns the symbol of the token.
     */
    function symbol() external view returns (string memory);

    /**
     * @dev Returns the decimals places of the token.
     */
    function decimals() external view returns (uint8);
}

// lib/openzeppelin-contracts/contracts/interfaces/IERC4626.sol

// OpenZeppelin Contracts (last updated v5.0.0) (interfaces/IERC4626.sol)

/**
 * @dev Interface of the ERC4626 "Tokenized Vault Standard", as defined in
 * https://eips.ethereum.org/EIPS/eip-4626[ERC-4626].
 */
interface IERC4626 is IERC20, IERC20Metadata {
    event Deposit(address indexed sender, address indexed owner, uint256 assets, uint256 shares);

    event Withdraw(
        address indexed sender,
        address indexed receiver,
        address indexed owner,
        uint256 assets,
        uint256 shares
    );

    /**
     * @dev Returns the address of the underlying token used for the Vault for accounting, depositing, and withdrawing.
     *
     * - MUST be an ERC-20 token contract.
     * - MUST NOT revert.
     */
    function asset() external view returns (address assetTokenAddress);

    /**
     * @dev Returns the total amount of the underlying asset that is “managed” by Vault.
     *
     * - SHOULD include any compounding that occurs from yield.
     * - MUST be inclusive of any fees that are charged against assets in the Vault.
     * - MUST NOT revert.
     */
    function totalAssets() external view returns (uint256 totalManagedAssets);

    /**
     * @dev Returns the amount of shares that the Vault would exchange for the amount of assets provided, in an ideal
     * scenario where all the conditions are met.
     *
     * - MUST NOT be inclusive of any fees that are charged against assets in the Vault.
     * - MUST NOT show any variations depending on the caller.
     * - MUST NOT reflect slippage or other on-chain conditions, when performing the actual exchange.
     * - MUST NOT revert.
     *
     * NOTE: This calculation MAY NOT reflect the “per-user” price-per-share, and instead should reflect the
     * “average-user’s” price-per-share, meaning what the average user should expect to see when exchanging to and
     * from.
     */
    function convertToShares(uint256 assets) external view returns (uint256 shares);

    /**
     * @dev Returns the amount of assets that the Vault would exchange for the amount of shares provided, in an ideal
     * scenario where all the conditions are met.
     *
     * - MUST NOT be inclusive of any fees that are charged against assets in the Vault.
     * - MUST NOT show any variations depending on the caller.
     * - MUST NOT reflect slippage or other on-chain conditions, when performing the actual exchange.
     * - MUST NOT revert.
     *
     * NOTE: This calculation MAY NOT reflect the “per-user” price-per-share, and instead should reflect the
     * “average-user’s” price-per-share, meaning what the average user should expect to see when exchanging to and
     * from.
     */
    function convertToAssets(uint256 shares) external view returns (uint256 assets);

    /**
     * @dev Returns the maximum amount of the underlying asset that can be deposited into the Vault for the receiver,
     * through a deposit call.
     *
     * - MUST return a limited value if receiver is subject to some deposit limit.
     * - MUST return 2 ** 256 - 1 if there is no limit on the maximum amount of assets that may be deposited.
     * - MUST NOT revert.
     */
    function maxDeposit(address receiver) external view returns (uint256 maxAssets);

    /**
     * @dev Allows an on-chain or off-chain user to simulate the effects of their deposit at the current block, given
     * current on-chain conditions.
     *
     * - MUST return as close to and no more than the exact amount of Vault shares that would be minted in a deposit
     *   call in the same transaction. I.e. deposit should return the same or more shares as previewDeposit if called
     *   in the same transaction.
     * - MUST NOT account for deposit limits like those returned from maxDeposit and should always act as though the
     *   deposit would be accepted, regardless if the user has enough tokens approved, etc.
     * - MUST be inclusive of deposit fees. Integrators should be aware of the existence of deposit fees.
     * - MUST NOT revert.
     *
     * NOTE: any unfavorable discrepancy between convertToShares and previewDeposit SHOULD be considered slippage in
     * share price or some other type of condition, meaning the depositor will lose assets by depositing.
     */
    function previewDeposit(uint256 assets) external view returns (uint256 shares);

    /**
     * @dev Mints shares Vault shares to receiver by depositing exactly amount of underlying tokens.
     *
     * - MUST emit the Deposit event.
     * - MAY support an additional flow in which the underlying tokens are owned by the Vault contract before the
     *   deposit execution, and are accounted for during deposit.
     * - MUST revert if all of assets cannot be deposited (due to deposit limit being reached, slippage, the user not
     *   approving enough underlying tokens to the Vault contract, etc).
     *
     * NOTE: most implementations will require pre-approval of the Vault with the Vault’s underlying asset token.
     */
    function deposit(uint256 assets, address receiver) external returns (uint256 shares);

    /**
     * @dev Returns the maximum amount of the Vault shares that can be minted for the receiver, through a mint call.
     * - MUST return a limited value if receiver is subject to some mint limit.
     * - MUST return 2 ** 256 - 1 if there is no limit on the maximum amount of shares that may be minted.
     * - MUST NOT revert.
     */
    function maxMint(address receiver) external view returns (uint256 maxShares);

    /**
     * @dev Allows an on-chain or off-chain user to simulate the effects of their mint at the current block, given
     * current on-chain conditions.
     *
     * - MUST return as close to and no fewer than the exact amount of assets that would be deposited in a mint call
     *   in the same transaction. I.e. mint should return the same or fewer assets as previewMint if called in the
     *   same transaction.
     * - MUST NOT account for mint limits like those returned from maxMint and should always act as though the mint
     *   would be accepted, regardless if the user has enough tokens approved, etc.
     * - MUST be inclusive of deposit fees. Integrators should be aware of the existence of deposit fees.
     * - MUST NOT revert.
     *
     * NOTE: any unfavorable discrepancy between convertToAssets and previewMint SHOULD be considered slippage in
     * share price or some other type of condition, meaning the depositor will lose assets by minting.
     */
    function previewMint(uint256 shares) external view returns (uint256 assets);

    /**
     * @dev Mints exactly shares Vault shares to receiver by depositing amount of underlying tokens.
     *
     * - MUST emit the Deposit event.
     * - MAY support an additional flow in which the underlying tokens are owned by the Vault contract before the mint
     *   execution, and are accounted for during mint.
     * - MUST revert if all of shares cannot be minted (due to deposit limit being reached, slippage, the user not
     *   approving enough underlying tokens to the Vault contract, etc).
     *
     * NOTE: most implementations will require pre-approval of the Vault with the Vault’s underlying asset token.
     */
    function mint(uint256 shares, address receiver) external returns (uint256 assets);

    /**
     * @dev Returns the maximum amount of the underlying asset that can be withdrawn from the owner balance in the
     * Vault, through a withdraw call.
     *
     * - MUST return a limited value if owner is subject to some withdrawal limit or timelock.
     * - MUST NOT revert.
     */
    function maxWithdraw(address owner) external view returns (uint256 maxAssets);

    /**
     * @dev Allows an on-chain or off-chain user to simulate the effects of their withdrawal at the current block,
     * given current on-chain conditions.
     *
     * - MUST return as close to and no fewer than the exact amount of Vault shares that would be burned in a withdraw
     *   call in the same transaction. I.e. withdraw should return the same or fewer shares as previewWithdraw if
     *   called
     *   in the same transaction.
     * - MUST NOT account for withdrawal limits like those returned from maxWithdraw and should always act as though
     *   the withdrawal would be accepted, regardless if the user has enough shares, etc.
     * - MUST be inclusive of withdrawal fees. Integrators should be aware of the existence of withdrawal fees.
     * - MUST NOT revert.
     *
     * NOTE: any unfavorable discrepancy between convertToShares and previewWithdraw SHOULD be considered slippage in
     * share price or some other type of condition, meaning the depositor will lose assets by depositing.
     */
    function previewWithdraw(uint256 assets) external view returns (uint256 shares);

    /**
     * @dev Burns shares from owner and sends exactly assets of underlying tokens to receiver.
     *
     * - MUST emit the Withdraw event.
     * - MAY support an additional flow in which the underlying tokens are owned by the Vault contract before the
     *   withdraw execution, and are accounted for during withdraw.
     * - MUST revert if all of assets cannot be withdrawn (due to withdrawal limit being reached, slippage, the owner
     *   not having enough shares, etc).
     *
     * Note that some implementations will require pre-requesting to the Vault before a withdrawal may be performed.
     * Those methods should be performed separately.
     */
    function withdraw(uint256 assets, address receiver, address owner) external returns (uint256 shares);

    /**
     * @dev Returns the maximum amount of Vault shares that can be redeemed from the owner balance in the Vault,
     * through a redeem call.
     *
     * - MUST return a limited value if owner is subject to some withdrawal limit or timelock.
     * - MUST return balanceOf(owner) if owner is not subject to any withdrawal limit or timelock.
     * - MUST NOT revert.
     */
    function maxRedeem(address owner) external view returns (uint256 maxShares);

    /**
     * @dev Allows an on-chain or off-chain user to simulate the effects of their redeemption at the current block,
     * given current on-chain conditions.
     *
     * - MUST return as close to and no more than the exact amount of assets that would be withdrawn in a redeem call
     *   in the same transaction. I.e. redeem should return the same or more assets as previewRedeem if called in the
     *   same transaction.
     * - MUST NOT account for redemption limits like those returned from maxRedeem and should always act as though the
     *   redemption would be accepted, regardless if the user has enough shares, etc.
     * - MUST be inclusive of withdrawal fees. Integrators should be aware of the existence of withdrawal fees.
     * - MUST NOT revert.
     *
     * NOTE: any unfavorable discrepancy between convertToAssets and previewRedeem SHOULD be considered slippage in
     * share price or some other type of condition, meaning the depositor will lose assets by redeeming.
     */
    function previewRedeem(uint256 shares) external view returns (uint256 assets);

    /**
     * @dev Burns exactly shares from owner and sends assets of underlying tokens to receiver.
     *
     * - MUST emit the Withdraw event.
     * - MAY support an additional flow in which the underlying tokens are owned by the Vault contract before the
     *   redeem execution, and are accounted for during redeem.
     * - MUST revert if all of shares cannot be redeemed (due to withdrawal limit being reached, slippage, the owner
     *   not having enough shares, etc).
     *
     * NOTE: some implementations will require pre-requesting to the Vault before a withdrawal may be performed.
     * Those methods should be performed separately.
     */
    function redeem(uint256 shares, address receiver, address owner) external returns (uint256 assets);
}

// lib/balancer-v3-monorepo/pkg/interfaces/contracts/vault/IVaultErrors.sol

/// @notice Errors are declared inside an interface (namespace) to improve DX with Typechain.
interface IVaultErrors {
    /*******************************************************************************
                            Registration and Initialization
    *******************************************************************************/

    /**
     * @notice A pool has already been registered. `registerPool` may only be called once.
     * @param pool The already registered pool
     */
    error PoolAlreadyRegistered(address pool);

    /**
     * @notice A pool has already been initialized. `initialize` may only be called once.
     * @param pool The already initialized pool
     */
    error PoolAlreadyInitialized(address pool);

    /**
     * @notice A pool has not been registered.
     * @param pool The unregistered pool
     */
    error PoolNotRegistered(address pool);

    /**
     * @notice A referenced pool has not been initialized.
     * @param pool The uninitialized pool
     */
    error PoolNotInitialized(address pool);

    /**
     * @notice A hook contract rejected a pool on registration.
     * @param poolHooksContract Address of the hook contract that rejected the pool registration
     * @param pool Address of the rejected pool
     * @param poolFactory Address of the pool factory
     */
    error HookRegistrationFailed(address poolHooksContract, address pool, address poolFactory);

    /**
     * @notice A token was already registered (i.e., it is a duplicate in the pool).
     * @param token The duplicate token
     */
    error TokenAlreadyRegistered(IERC20 token);

    /// @notice The token count is below the minimum allowed.
    error MinTokens();

    /// @notice The token count is above the maximum allowed.
    error MaxTokens();

    /// @notice Invalid tokens (e.g., zero) cannot be registered.
    error InvalidToken();

    /// @notice The token type given in a TokenConfig during pool registration is invalid.
    error InvalidTokenType();

    /// @notice The data in a TokenConfig struct is inconsistent or unsupported.
    error InvalidTokenConfiguration();

    /// @notice Tokens with more than 18 decimals are not supported.
    error InvalidTokenDecimals();

    /**
     * @notice The token list passed into an operation does not match the pool tokens in the pool.
     * @param pool Address of the pool
     * @param expectedToken The correct token at a given index in the pool
     * @param actualToken The actual token found at that index
     */
    error TokensMismatch(address pool, address expectedToken, address actualToken);

    /*******************************************************************************
                                 Transient Accounting
    *******************************************************************************/

    /// @notice A transient accounting operation completed with outstanding token deltas.
    error BalanceNotSettled();

    /// @notice A user called a Vault function (swap, add/remove liquidity) outside the lock context.
    error VaultIsNotUnlocked();

    /// @notice The pool has returned false to the beforeSwap hook, indicating the transaction should revert.
    error DynamicSwapFeeHookFailed();

    /// @notice The pool has returned false to the beforeSwap hook, indicating the transaction should revert.
    error BeforeSwapHookFailed();

    /// @notice The pool has returned false to the afterSwap hook, indicating the transaction should revert.
    error AfterSwapHookFailed();

    /// @notice The pool has returned false to the beforeInitialize hook, indicating the transaction should revert.
    error BeforeInitializeHookFailed();

    /// @notice The pool has returned false to the afterInitialize hook, indicating the transaction should revert.
    error AfterInitializeHookFailed();

    /// @notice The pool has returned false to the beforeAddLiquidity hook, indicating the transaction should revert.
    error BeforeAddLiquidityHookFailed();

    /// @notice The pool has returned false to the afterAddLiquidity hook, indicating the transaction should revert.
    error AfterAddLiquidityHookFailed();

    /// @notice The pool has returned false to the beforeRemoveLiquidity hook, indicating the transaction should revert.
    error BeforeRemoveLiquidityHookFailed();

    /// @notice The pool has returned false to the afterRemoveLiquidity hook, indicating the transaction should revert.
    error AfterRemoveLiquidityHookFailed();

    /// @notice An unauthorized Router tried to call a permissioned function (i.e., using the Vault's token allowance).
    error RouterNotTrusted();

    /*******************************************************************************
                                        Swaps
    *******************************************************************************/

    /// @notice The user tried to swap zero tokens.
    error AmountGivenZero();

    /// @notice The user attempted to swap a token for itself.
    error CannotSwapSameToken();

    /**
     * @notice The user attempted to operate with a token that is not in the pool.
     * @param token The unregistered token
     */
    error TokenNotRegistered(IERC20 token);

    /**
     * @notice An amount in or out has exceeded the limit specified in the swap request.
     * @param amount The total amount in or out
     * @param limit The amount of the limit that has been exceeded
     */
    error SwapLimit(uint256 amount, uint256 limit);

    /**
     * @notice A hook adjusted amount in or out has exceeded the limit specified in the swap request.
     * @param amount The total amount in or out
     * @param limit The amount of the limit that has been exceeded
     */
    error HookAdjustedSwapLimit(uint256 amount, uint256 limit);

    /// @notice The amount given or calculated for an operation is below the minimum limit.
    error TradeAmountTooSmall();

    /*******************************************************************************
                                    Add Liquidity
    *******************************************************************************/

    /// @notice Add liquidity kind not supported.
    error InvalidAddLiquidityKind();

    /**
     * @notice A required amountIn exceeds the maximum limit specified for the operation.
     * @param tokenIn The incoming token
     * @param amountIn The total token amount in
     * @param maxAmountIn The amount of the limit that has been exceeded
     */
    error AmountInAboveMax(IERC20 tokenIn, uint256 amountIn, uint256 maxAmountIn);

    /**
     * @notice A hook adjusted amountIn exceeds the maximum limit specified for the operation.
     * @param tokenIn The incoming token
     * @param amountIn The total token amount in
     * @param maxAmountIn The amount of the limit that has been exceeded
     */
    error HookAdjustedAmountInAboveMax(IERC20 tokenIn, uint256 amountIn, uint256 maxAmountIn);

    /**
     * @notice The BPT amount received from adding liquidity is below the minimum specified for the operation.
     * @param amountOut The total BPT amount out
     * @param minAmountOut The amount of the limit that has been exceeded
     */
    error BptAmountOutBelowMin(uint256 amountOut, uint256 minAmountOut);

    /// @notice Pool does not support adding liquidity with a customized input.
    error DoesNotSupportAddLiquidityCustom();

    /// @notice Pool does not support adding liquidity through donation.
    error DoesNotSupportDonation();

    /*******************************************************************************
                                    Remove Liquidity
    *******************************************************************************/

    /// @notice Remove liquidity kind not supported.
    error InvalidRemoveLiquidityKind();

    /**
     * @notice The actual amount out is below the minimum limit specified for the operation.
     * @param tokenOut The outgoing token
     * @param amountOut The total BPT amount out
     * @param minAmountOut The amount of the limit that has been exceeded
     */
    error AmountOutBelowMin(IERC20 tokenOut, uint256 amountOut, uint256 minAmountOut);

    /**
     * @notice The hook adjusted amount out is below the minimum limit specified for the operation.
     * @param tokenOut The outgoing token
     * @param amountOut The total BPT amount out
     * @param minAmountOut The amount of the limit that has been exceeded
     */
    error HookAdjustedAmountOutBelowMin(IERC20 tokenOut, uint256 amountOut, uint256 minAmountOut);

    /**
     * @notice The required BPT amount in exceeds the maximum limit specified for the operation.
     * @param amountIn The total BPT amount in
     * @param maxAmountIn The amount of the limit that has been exceeded
     */
    error BptAmountInAboveMax(uint256 amountIn, uint256 maxAmountIn);

    /// @notice Pool does not support removing liquidity with a customized input.
    error DoesNotSupportRemoveLiquidityCustom();

    /*******************************************************************************
                                     Fees
    *******************************************************************************/

    /**
     * @notice Error raised when there is an overflow in the fee calculation.
     * @dev This occurs when the sum of the parts (aggregate swap or yield fee) is greater than the whole
     * (total swap or yield fee). Also validated when the protocol fee controller updates aggregate fee
     * percentages in the Vault.
     */
    error ProtocolFeesExceedTotalCollected();

    /**
     * @notice Error raised when the swap fee percentage is less than the minimum allowed value.
     * @dev The Vault itself does not impose a universal minimum. Rather, it validates against the
     * range specified by the `ISwapFeePercentageBounds` interface. and reverts with this error
     * if it is below the minimum value returned by the pool.
     *
     * Pools with dynamic fees do not check these limits.
     */
    error SwapFeePercentageTooLow();

    /**
     * @notice Error raised when the swap fee percentage is greater than the maximum allowed value.
     * @dev The Vault itself does not impose a universal minimum. Rather, it validates against the
     * range specified by the `ISwapFeePercentageBounds` interface. and reverts with this error
     * if it is above the maximum value returned by the pool.
     *
     * Pools with dynamic fees do not check these limits.
     */
    error SwapFeePercentageTooHigh();

    /**
     * @notice Primary fee percentages result in an aggregate fee that cannot be stored with the required precision.
     * @dev Primary fee percentages are 18-decimal values, stored here in 64 bits, and calculated with full 256-bit
     * precision. However, the resulting aggregate fees are stored in the Vault with 24-bit precision, which
     * corresponds to 0.00001% resolution (i.e., a fee can be 1%, 1.00001%, 1.00002%, but not 1.000005%).
     * Disallow setting fees such that there would be precision loss in the Vault, leading to a discrepancy between
     * the aggregate fee calculated here and that stored in the Vault.
     */
    error FeePrecisionTooHigh();

    /// @notice A given percentage is above the maximum (usually a value close to FixedPoint.ONE, or 1e18 wei).
    error PercentageAboveMax();

    /*******************************************************************************
                                    Queries
    *******************************************************************************/

    /// @notice A user tried to execute a query operation when they were disabled.
    error QueriesDisabled();

    /// @notice An admin tried to re-enable queries, but they were disabled permanently.
    error QueriesDisabledPermanently();

    /*******************************************************************************
                                Recovery Mode
    *******************************************************************************/

    /**
     * @notice Cannot enable recovery mode when already enabled.
     * @param pool The pool
     */
    error PoolInRecoveryMode(address pool);

    /**
     * @notice Cannot disable recovery mode when not enabled.
     * @param pool The pool
     */
    error PoolNotInRecoveryMode(address pool);

    /*******************************************************************************
                                Authentication
    *******************************************************************************/

    /**
     * @notice Error indicating the sender is not the Vault (e.g., someone is trying to call a permissioned function).
     * @param sender The account attempting to call a permissioned function
     */
    error SenderIsNotVault(address sender);

    /*******************************************************************************
                                        Pausing
    *******************************************************************************/

    /// @notice The caller specified a pause window period longer than the maximum.
    error VaultPauseWindowDurationTooLarge();

    /// @notice The caller specified a buffer period longer than the maximum.
    error PauseBufferPeriodDurationTooLarge();

    /// @notice A user tried to perform an operation while the Vault was paused.
    error VaultPaused();

    /// @notice Governance tried to unpause the Vault when it was not paused.
    error VaultNotPaused();

    /// @notice Governance tried to pause the Vault after the pause period expired.
    error VaultPauseWindowExpired();

    /**
     * @notice A user tried to perform an operation involving a paused Pool.
     * @param pool The paused pool
     */
    error PoolPaused(address pool);

    /**
     * @notice Governance tried to unpause the Pool when it was not paused.
     * @param pool The unpaused pool
     */
    error PoolNotPaused(address pool);

    /**
     * @notice Governance tried to pause a Pool after the pause period expired.
     * @param pool The pool
     */
    error PoolPauseWindowExpired(address pool);

    /*******************************************************************************
                                ERC4626 token buffers
    *******************************************************************************/

    /**
     * @notice The buffer for the given wrapped token was already initialized.
     * @param wrappedToken The wrapped token corresponding to the buffer
     */
    error BufferAlreadyInitialized(IERC4626 wrappedToken);

    /**
     * @notice The buffer for the given wrapped token was not initialized.
     * @param wrappedToken The wrapped token corresponding to the buffer
     */
    error BufferNotInitialized(IERC4626 wrappedToken);

    /// @notice The user is trying to remove more than their allocated shares from the buffer.
    error NotEnoughBufferShares();

    /**
     * @notice The wrapped token asset does not match the underlying token.
     * @dev This should never happen, but a malicious wrapper contract might not return the correct address.
     * Legitimate wrapper contracts should make the asset a constant or immutable value.
     *
     * @param wrappedToken The wrapped token corresponding to the buffer
     * @param underlyingToken The underlying token returned by `asset`
     */
    error WrongUnderlyingToken(IERC4626 wrappedToken, address underlyingToken);

    /**
     * @notice A wrapped token reported the zero address as its underlying token asset.
     * @dev This should never happen, but a malicious wrapper contract might do this (e.g., in an attempt to
     * re-initialize the buffer).
     *
     * @param wrappedToken The wrapped token corresponding to the buffer
     */
    error InvalidUnderlyingToken(IERC4626 wrappedToken);

    /**
     * @notice The amount given to wrap/unwrap was too small, which can introduce rounding issues.
     * @param wrappedToken The wrapped token corresponding to the buffer
     */
    error WrapAmountTooSmall(IERC4626 wrappedToken);

    /// @notice Buffer operation attempted while vault buffers are paused.
    error VaultBuffersArePaused();

    /// @notice Buffer shares were minted to the zero address.
    error BufferSharesInvalidReceiver();

    /// @notice Buffer shares were burned from the zero address.
    error BufferSharesInvalidOwner();

    /**
     * @notice The total supply of a buffer can't be lower than the absolute minimum.
     * @param totalSupply The total supply value that was below the minimum
     */
    error BufferTotalSupplyTooLow(uint256 totalSupply);

    /// @dev A wrap/unwrap operation consumed more or returned less underlying tokens than it should.
    error NotEnoughUnderlying(IERC4626 wrappedToken, uint256 expectedUnderlyingAmount, uint256 actualUnderlyingAmount);

    /// @dev A wrap/unwrap operation consumed more or returned less wrapped tokens than it should.
    error NotEnoughWrapped(IERC4626 wrappedToken, uint256 expectedWrappedAmount, uint256 actualWrappedAmount);

    /// @dev Shares issued during initialization are below the requested amount.
    error IssuedSharesBelowMin(uint256 issuedShares, uint256 minIssuedShares);

    /*******************************************************************************
                                    Miscellaneous
    *******************************************************************************/

    /// @notice Pool does not support adding / removing liquidity with an unbalanced input.
    error DoesNotSupportUnbalancedLiquidity();

    /// @notice The contract should not receive ETH.
    error CannotReceiveEth();

    /**
     * @notice The `VaultExtension` contract was called by an account directly.
     * @dev It can only be called by the Vault via delegatecall.
     */
    error NotVaultDelegateCall();

    /// @notice The `VaultExtension` contract was configured with an incorrect Vault address.
    error WrongVaultExtensionDeployment();

    /// @notice The `ProtocolFeeController` contract was configured with an incorrect Vault address.
    error WrongProtocolFeeControllerDeployment();

    /// @notice The `VaultAdmin` contract was configured with an incorrect Vault address.
    error WrongVaultAdminDeployment();

    /// @notice Quote reverted with a reserved error code.
    error QuoteResultSpoofed();
}

// lib/balancer-v3-monorepo/pkg/interfaces/contracts/vault/VaultTypes.sol

/**
 * @notice Represents a pool's liquidity management configuration.
 * @param disableUnbalancedLiquidity If set, liquidity can only be added or removed proportionally
 * @param enableAddLiquidityCustom If set, the pool has implemented `onAddLiquidityCustom`
 * @param enableRemoveLiquidityCustom If set, the pool has implemented `onRemoveLiquidityCustom`
 * @param enableDonation If set, the pool will not revert if liquidity is added with AddLiquidityKind.DONATION
 */
struct LiquidityManagement {
    bool disableUnbalancedLiquidity;
    bool enableAddLiquidityCustom;
    bool enableRemoveLiquidityCustom;
    bool enableDonation;
}

// @notice Custom type to store the entire configuration of the pool.
type PoolConfigBits is bytes32;

/**
 * @notice Represents a pool's configuration (hooks configuration are separated in another struct).
 * @param liquidityManagement Flags related to adding/removing liquidity
 * @param staticSwapFeePercentage The pool's native swap fee
 * @param aggregateSwapFeePercentage The total swap fee charged, including protocol and pool creator components
 * @param aggregateYieldFeePercentage The total swap fee charged, including protocol and pool creator components
 * @param tokenDecimalDiffs Compressed storage of the token decimals of each pool token
 * @param pauseWindowEndTime Timestamp after which the pool cannot be paused
 * @param isPoolRegistered If true, the pool has been registered with the Vault
 * @param isPoolInitialized If true, the pool has been initialized with liquidity, and is available for trading
 * @param isPoolPaused If true, the pool has been paused (by governance or the pauseManager)
 * @param isPoolInRecoveryMode If true, the pool has been placed in recovery mode, enabling recovery mode withdrawals
 */
struct PoolConfig {
    LiquidityManagement liquidityManagement;
    uint256 staticSwapFeePercentage;
    uint256 aggregateSwapFeePercentage;
    uint256 aggregateYieldFeePercentage;
    uint40 tokenDecimalDiffs;
    uint32 pauseWindowEndTime;
    bool isPoolRegistered;
    bool isPoolInitialized;
    bool isPoolPaused;
    bool isPoolInRecoveryMode;
}

/**
 * @notice The flag portion of the `HooksConfig`.
 * @dev `enableHookAdjustedAmounts` must be true for all contracts that modify the `amountCalculated`
 * in after hooks. Otherwise, the Vault will ignore any "hookAdjusted" amounts. Setting any "shouldCall"
 * flags to true will cause the Vault to call the corresponding hook during operations.
 */
struct HookFlags {
    bool enableHookAdjustedAmounts;
    bool shouldCallBeforeInitialize;
    bool shouldCallAfterInitialize;
    bool shouldCallComputeDynamicSwapFee;
    bool shouldCallBeforeSwap;
    bool shouldCallAfterSwap;
    bool shouldCallBeforeAddLiquidity;
    bool shouldCallAfterAddLiquidity;
    bool shouldCallBeforeRemoveLiquidity;
    bool shouldCallAfterRemoveLiquidity;
}

/// @notice Represents a hook contract configuration for a pool (HookFlags + hooksContract address).
struct HooksConfig {
    bool enableHookAdjustedAmounts;
    bool shouldCallBeforeInitialize;
    bool shouldCallAfterInitialize;
    bool shouldCallComputeDynamicSwapFee;
    bool shouldCallBeforeSwap;
    bool shouldCallAfterSwap;
    bool shouldCallBeforeAddLiquidity;
    bool shouldCallAfterAddLiquidity;
    bool shouldCallBeforeRemoveLiquidity;
    bool shouldCallAfterRemoveLiquidity;
    address hooksContract;
}

/**
 * @notice Represents temporary state used during a swap operation.
 * @param indexIn The zero-based index of tokenIn
 * @param indexOut The zero-based index of tokenOut
 * @param amountGivenScaled18 The amountGiven (i.e., tokenIn for ExactIn), adjusted for token decimals
 * @param swapFeePercentage The swap fee to be applied (might be static or dynamic)
 */
struct SwapState {
    uint256 indexIn;
    uint256 indexOut;
    uint256 amountGivenScaled18;
    uint256 swapFeePercentage;
}

/**
 * @notice Represents the Vault's configuration.
 * @param isQueryDisabled If set to true, disables query functionality of the Vault. Can be modified by governance
 * @param isVaultPaused If set to true, swaps and add/remove liquidity operations are halted
 * @param areBuffersPaused If set to true, the Vault wrap/unwrap primitives associated with buffers will be disabled
 */
struct VaultState {
    bool isQueryDisabled;
    bool isVaultPaused;
    bool areBuffersPaused;
}

/**
 * @notice Represents the accounts holding certain roles for a given pool. This is passed in on pool registration.
 * @param pauseManager Account empowered to pause/unpause the pool (note that governance can always pause a pool)
 * @param swapFeeManager Account empowered to set static swap fees for a pool (or 0 to delegate to governance)
 * @param poolCreator Account empowered to set the pool creator fee (or 0 if all fees go to the protocol and LPs)
 */
struct PoolRoleAccounts {
    address pauseManager;
    address swapFeeManager;
    address poolCreator;
}

/*******************************************************************************
                                   Tokens
*******************************************************************************/

// Note that the following tokens are unsupported by the Vault. This list is not meant to be exhaustive, but covers
// many common types of tokens that will not work with the Vault architecture. (See https://github.com/d-xo/weird-erc20
// for examples of token features that are problematic for many protocols.)
//
// * Rebasing tokens (e.g., aDAI). The Vault keeps track of token balances in its internal accounting; any token whose
//   balance changes asynchronously (i.e., outside a swap or liquidity operation), would get out-of-sync with this
//   internal accounting. This category would also include "airdrop" tokens, whose balances can change unexpectedly.
//
// * Double entrypoint (e.g., old Synthetix tokens, now fixed). These could likewise bypass internal accounting by
//   registering the token under one address, then accessing it through another. This is especially troublesome
//   in v3, with the introduction of ERC4626 buffers.
//
// * Fee on transfer (e.g., PAXG). The Vault issues credits and debits according to given and calculated token amounts,
//   and settlement assumes that the send/receive transfer functions transfer exactly the given number of tokens.
//   If this is not the case, transactions will not settle. Unlike with the other types, which are fundamentally
//   incompatible, it would be possible to design a Router to handle this - but we didn't try it. In any case, it's
//   not supported in the current Routers.
//
// * Tokens with more than 18 decimals (e.g., YAM-V2). The Vault handles token scaling: i.e., handling I/O for
//   amounts in native token decimals, but doing calculations with full 18-decimal precision. This requires reading
//   and storing the decimals for each token. Since virtually all tokens are 18 or fewer decimals, and we have limited
//   storage space, 18 was a reasonable maximum. Unlike the other types, this is enforceable by the Vault. Attempting
//   to register such tokens will revert with `InvalidTokenDecimals`. Of course, we must also be able to read the token
//   decimals, so the Vault only supports tokens that implement `IERC20Metadata.decimals`, and return a value less than
//   or equal to 18.
//
//  * Token decimals are checked and stored only once, on registration. Valid tokens store their decimals as immutable
//    variables or constants. Malicious tokens that don't respect this basic property would not work anywhere in DeFi.
//
// These types of tokens are supported but discouraged, as they don't tend to play well with AMMs generally.
//
// * Very low-decimal tokens (e.g., GUSD). The Vault has been extensively tested with 6-decimal tokens (e.g., USDC),
//   but going much below that may lead to unanticipated effects due to precision loss, especially with smaller trade
//   values.
//
// * Revert on zero value approval/transfer. The Vault has been tested against these, but peripheral contracts, such
//   as hooks, might not have been designed with this in mind.
//
// * Other types from "weird-erc20," such as upgradeable, pausable, or tokens with blocklists. We have seen cases
//   where a token upgrade fails, "bricking" the token - and many operations on pools containing that token. Any
//   sort of "permissioned" token that can make transfers fail can cause operations on pools containing them to
//   revert. Even Recovery Mode cannot help then, as it does a proportional withdrawal of all tokens. If one of
//   them is bricked, the whole operation will revert. Since v3 does not have "internal balances" like v2, there
//   is no recourse.
//
//   Of course, many tokens in common use have some of these "features" (especially centralized stable coins), so
//   we have to support them anyway. Working with common centralized tokens is a risk common to all of DeFi.

/**
 * @notice Token types supported by the Vault.
 * @dev In general, pools may contain any combination of these tokens.
 *
 * STANDARD tokens (e.g., BAL, WETH) have no rate provider.
 * WITH_RATE tokens (e.g., wstETH) require a rate provider. These may be tokens like wstETH, which need to be wrapped
 * because the underlying stETH token is rebasing, and such tokens are unsupported by the Vault. They may also be
 * tokens like sEUR, which track an underlying asset, but are not yield-bearing. Finally, this encompasses
 * yield-bearing ERC4626 tokens, which can be used to facilitate swaps without requiring wrapping or unwrapping
 * in most cases. The `paysYieldFees` flag can be used to indicate whether a token is yield-bearing (e.g., waDAI),
 * not yield-bearing (e.g., sEUR), or yield-bearing but exempt from fees (e.g., in certain nested pools, where
 * yield fees are charged elsewhere).
 *
 * NB: STANDARD must always be the first enum element, so that newly initialized data structures default to Standard.
 */
enum TokenType {
    STANDARD,
    WITH_RATE
}

/**
 * @notice Encapsulate the data required for the Vault to support a token of the given type.
 * @dev For STANDARD tokens, the rate provider address must be 0, and paysYieldFees must be false. All WITH_RATE tokens
 * need a rate provider, and may or may not be yield-bearing.
 *
 * At registration time, it is useful to include the token address along with the token parameters in the structure
 * passed to `registerPool`, as the alternative would be parallel arrays, which would be error prone and require
 * validation checks. `TokenConfig` is only used for registration, and is never put into storage (see `TokenInfo`).
 *
 * @param token The token address
 * @param tokenType The token type (see the enum for supported types)
 * @param rateProvider The rate provider for a token (see further documentation above)
 * @param paysYieldFees Flag indicating whether yield fees should be charged on this token
 */
struct TokenConfig {
    IERC20 token;
    TokenType tokenType;
    IRateProvider rateProvider;
    bool paysYieldFees;
}

/**
 * @notice This data structure is stored in `_poolTokenInfo`, a nested mapping from pool -> (token -> TokenInfo).
 * @dev Since the token is already the key of the nested mapping, it would be redundant (and an extra SLOAD) to store
 * it again in the struct. When we construct PoolData, the tokens are separated into their own array.
 *
 * @param tokenType The token type (see the enum for supported types)
 * @param rateProvider The rate provider for a token (see further documentation above)
 * @param paysYieldFees Flag indicating whether yield fees should be charged on this token
 */
struct TokenInfo {
    TokenType tokenType;
    IRateProvider rateProvider;
    bool paysYieldFees;
}

/**
 * @notice Data structure used to represent the current pool state in memory
 * @param poolConfigBits Custom type to store the entire configuration of the pool.
 * @param tokens Pool tokens, sorted in token registration order
 * @param tokenInfo Configuration data for each token, sorted in token registration order
 * @param balancesRaw Token balances in native decimals
 * @param balancesLiveScaled18 Token balances after paying yield fees, applying decimal scaling and rates
 * @param tokenRates 18-decimal FP values for rate tokens (e.g., yield-bearing), or FP(1) for standard tokens
 * @param decimalScalingFactors Conversion factor used to adjust for token decimals for uniform precision in
 * calculations. It is 1e18 (FP 1) for 18-decimal tokens
 */
struct PoolData {
    PoolConfigBits poolConfigBits;
    IERC20[] tokens;
    TokenInfo[] tokenInfo;
    uint256[] balancesRaw;
    uint256[] balancesLiveScaled18;
    uint256[] tokenRates;
    uint256[] decimalScalingFactors;
}

enum Rounding {
    ROUND_UP,
    ROUND_DOWN
}

/*******************************************************************************
                                    Swaps
*******************************************************************************/

enum SwapKind {
    EXACT_IN,
    EXACT_OUT
}

// There are two "SwapParams" structs defined below. `VaultSwapParams` corresponds to the external swap API defined
// in the Router contracts, which uses explicit token addresses, the amount given and limit on the calculated amount
// expressed in native token decimals, and optional user data passed in from the caller.
//
// `PoolSwapParams` passes some of this information through (kind, userData), but "translates" the parameters to fit
// the internal swap API used by `IBasePool`. It scales amounts to full 18-decimal precision, adds the token balances,
// converts the raw token addresses to indices, and adds the address of the Router originating the request. It does
// not need the limit, since this is checked at the Router level.

/**
 * @notice Data passed into primary Vault `swap` operations.
 * @param kind Type of swap (Exact In or Exact Out)
 * @param pool The pool with the tokens being swapped
 * @param tokenIn The token entering the Vault (balance increases)
 * @param tokenOut The token leaving the Vault (balance decreases)
 * @param amountGivenRaw Amount specified for tokenIn or tokenOut (depending on the type of swap)
 * @param limitRaw Minimum or maximum value of the calculated amount (depending on the type of swap)
 * @param userData Additional (optional) user data
 */
struct VaultSwapParams {
    SwapKind kind;
    address pool;
    IERC20 tokenIn;
    IERC20 tokenOut;
    uint256 amountGivenRaw;
    uint256 limitRaw;
    bytes userData;
}

/**
 * @notice Data for a swap operation, used by contracts implementing `IBasePool`.
 * @param kind Type of swap (exact in or exact out)
 * @param amountGivenScaled18 Amount given based on kind of the swap (e.g., tokenIn for EXACT_IN)
 * @param balancesScaled18 Current pool balances
 * @param indexIn Index of tokenIn
 * @param indexOut Index of tokenOut
 * @param router The address (usually a router contract) that initiated a swap operation on the Vault
 * @param userData Additional (optional) data required for the swap
 */
struct PoolSwapParams {
    SwapKind kind;
    uint256 amountGivenScaled18;
    uint256[] balancesScaled18;
    uint256 indexIn;
    uint256 indexOut;
    address router;
    bytes userData;
}

/**
 * @notice Data for the hook after a swap operation.
 * @param kind Type of swap (exact in or exact out)
 * @param tokenIn Token to be swapped from
 * @param tokenOut Token to be swapped to
 * @param amountInScaled18 Amount of tokenIn (entering the Vault)
 * @param amountOutScaled18 Amount of tokenOut (leaving the Vault)
 * @param tokenInBalanceScaled18 Updated (after swap) balance of tokenIn
 * @param tokenOutBalanceScaled18 Updated (after swap) balance of tokenOut
 * @param amountCalculatedScaled18 Token amount calculated by the swap
 * @param amountCalculatedRaw Token amount calculated by the swap
 * @param router The address (usually a router contract) that initiated a swap operation on the Vault
 * @param pool Pool address
 * @param userData Additional (optional) data required for the swap
 */
struct AfterSwapParams {
    SwapKind kind;
    IERC20 tokenIn;
    IERC20 tokenOut;
    uint256 amountInScaled18;
    uint256 amountOutScaled18;
    uint256 tokenInBalanceScaled18;
    uint256 tokenOutBalanceScaled18;
    uint256 amountCalculatedScaled18;
    uint256 amountCalculatedRaw;
    address router;
    address pool;
    bytes userData;
}

/*******************************************************************************
                                Add liquidity
*******************************************************************************/

enum AddLiquidityKind {
    PROPORTIONAL,
    UNBALANCED,
    SINGLE_TOKEN_EXACT_OUT,
    DONATION,
    CUSTOM
}

/**
 * @notice Data for an add liquidity operation.
 * @param pool Address of the pool
 * @param to Address of user to mint to
 * @param maxAmountsIn Maximum amounts of input tokens
 * @param minBptAmountOut Minimum amount of output pool tokens
 * @param kind Add liquidity kind
 * @param userData Optional user data
 */
struct AddLiquidityParams {
    address pool;
    address to;
    uint256[] maxAmountsIn;
    uint256 minBptAmountOut;
    AddLiquidityKind kind;
    bytes userData;
}

/*******************************************************************************
                                Remove liquidity
*******************************************************************************/

enum RemoveLiquidityKind {
    PROPORTIONAL,
    SINGLE_TOKEN_EXACT_IN,
    SINGLE_TOKEN_EXACT_OUT,
    CUSTOM
}

/**
 * @notice Data for an remove liquidity operation.
 * @param pool Address of the pool
 * @param from Address of user to burn from
 * @param maxBptAmountIn Maximum amount of input pool tokens
 * @param minAmountsOut Minimum amounts of output tokens
 * @param kind Remove liquidity kind
 * @param userData Optional user data
 */
struct RemoveLiquidityParams {
    address pool;
    address from;
    uint256 maxBptAmountIn;
    uint256[] minAmountsOut;
    RemoveLiquidityKind kind;
    bytes userData;
}

/*******************************************************************************
                                Remove liquidity
*******************************************************************************/

enum WrappingDirection {
    WRAP,
    UNWRAP
}

/**
 * @notice Data for a wrap/unwrap operation.
 * @param kind Type of swap (Exact In or Exact Out)
 * @param direction Direction of the wrapping operation (Wrap or Unwrap)
 * @param wrappedToken Wrapped token, compatible with interface ERC4626
 * @param amountGivenRaw Amount specified for tokenIn or tokenOut (depends on the type of swap and wrapping direction)
 * @param limitRaw Minimum or maximum amount specified for the other token (depends on the type of swap and wrapping
 * direction)
 */
struct BufferWrapOrUnwrapParams {
    SwapKind kind;
    WrappingDirection direction;
    IERC4626 wrappedToken;
    uint256 amountGivenRaw;
    uint256 limitRaw;
}

// Protocol Fees are 24-bit values. We transform them by multiplying by 1e11, so that they can be set to any value
// between 0% and 100% (step 0.00001%). Protocol and pool creator fees are set in the `ProtocolFeeController`, and
// ensure both constituent and aggregate fees do not exceed this precision.
uint256 constant FEE_BITLENGTH = 24;
uint256 constant FEE_SCALING_FACTOR = 1e11;
// Used to ensure the safety of fee-related math (e.g., pools or hooks don't set it greater than 100%).
// This value should work for practical purposes and is well within the max precision requirements.
uint256 constant MAX_FEE_PERCENTAGE = 99.9999e16; // 99.9999%

// lib/balancer-v3-monorepo/pkg/interfaces/contracts/vault/IHooks.sol

// Explicitly import VaultTypes structs because we expect this interface to be heavily used by external developers.
// Internally, when this list gets too long, we usually just do a simple import to keep things tidy.

/**
 * @notice Interface for pool hooks.
 * @dev Hooks are functions invoked by the Vault at specific points in the flow of each operation. This guarantees that
 * they are called in the correct order, and with the correct arguments. To maintain this security, these functions
 * should only be called by the Vault. The recommended way to do this is to derive the hook contract from `BaseHooks`,
 * then use the `onlyVault` modifier from `VaultGuard`. (See the examples in /pool-hooks.)
 */
interface IHooks {
    /***************************************************************************
                                   Register
    ***************************************************************************/

    /**
     * @notice Hook executed when a pool is registered with a non-zero hooks contract.
     * @dev Returns true if registration was successful, and false to revert the pool registration.
     * Make sure this function is properly implemented (e.g. check the factory, and check that the
     * given pool is from the factory). The Vault address will be msg.sender.
     *
     * @param factory Address of the pool factory (contract deploying the pool)
     * @param pool Address of the pool
     * @param tokenConfig An array of descriptors for the tokens the pool will manage
     * @param liquidityManagement Liquidity management flags indicating which functions are enabled
     * @return success True if the hook allowed the registration, false otherwise
     */
    function onRegister(
        address factory,
        address pool,
        TokenConfig[] memory tokenConfig,
        LiquidityManagement calldata liquidityManagement
    ) external returns (bool success);

    /**
     * @notice Return the set of hooks implemented by the contract.
     * @dev The Vault will only call hooks the pool says it supports, and of course only if a hooks contract is defined
     * (i.e., the `poolHooksContract` in `PoolRegistrationParams` is non-zero).
     * `onRegister` is the only "mandatory" hook.
     *
     * @return hookFlags Flags indicating which hooks the contract supports
     */
    function getHookFlags() external view returns (HookFlags memory hookFlags);

    /***************************************************************************
                                   Initialize
    ***************************************************************************/

    /**
     * @notice Hook executed before pool initialization.
     * @dev Called if the `shouldCallBeforeInitialize` flag is set in the configuration. Hook contracts should use
     * the `onlyVault` modifier to guarantee this is only called by the Vault.
     *
     * @param exactAmountsIn Exact amounts of input tokens
     * @param userData Optional, arbitrary data sent with the encoded request
     * @return success True if the pool wishes to proceed with initialization
     */
    function onBeforeInitialize(uint256[] memory exactAmountsIn, bytes memory userData) external returns (bool success);

    /**
     * @notice Hook to be executed after pool initialization.
     * @dev Called if the `shouldCallAfterInitialize` flag is set in the configuration. Hook contracts should use
     * the `onlyVault` modifier to guarantee this is only called by the Vault.
     *
     * @param exactAmountsIn Exact amounts of input tokens
     * @param bptAmountOut Amount of pool tokens minted during initialization
     * @param userData Optional, arbitrary data sent with the encoded request
     * @return success True if the pool accepts the initialization results
     */
    function onAfterInitialize(
        uint256[] memory exactAmountsIn,
        uint256 bptAmountOut,
        bytes memory userData
    ) external returns (bool success);

    /***************************************************************************
                                   Add Liquidity
    ***************************************************************************/

    /**
     * @notice Hook to be executed before adding liquidity.
     * @dev Called if the `shouldCallBeforeAddLiquidity` flag is set in the configuration. Hook contracts should use
     * the `onlyVault` modifier to guarantee this is only called by the Vault.
     *
     * @param router The address (usually a router contract) that initiated an add liquidity operation on the Vault
     * @param pool Pool address, used to fetch pool information from the Vault (pool config, tokens, etc.)
     * @param kind The add liquidity operation type (e.g., proportional, custom)
     * @param maxAmountsInScaled18 Maximum amounts of input tokens
     * @param minBptAmountOut Minimum amount of output pool tokens
     * @param balancesScaled18 Current pool balances, sorted in token registration order
     * @param userData Optional, arbitrary data sent with the encoded request
     * @return success True if the pool wishes to proceed with settlement
     */
    function onBeforeAddLiquidity(
        address router,
        address pool,
        AddLiquidityKind kind,
        uint256[] memory maxAmountsInScaled18,
        uint256 minBptAmountOut,
        uint256[] memory balancesScaled18,
        bytes memory userData
    ) external returns (bool success);

    /**
     * @notice Hook to be executed after adding liquidity.
     * @dev Called if the `shouldCallAfterAddLiquidity` flag is set in the configuration. The Vault will ignore
     * `hookAdjustedAmountsInRaw` unless `enableHookAdjustedAmounts` is true. Hook contracts should use the
     * `onlyVault` modifier to guarantee this is only called by the Vault.
     *
     * @param router The address (usually a router contract) that initiated an add liquidity operation on the Vault
     * @param pool Pool address, used to fetch pool information from the Vault (pool config, tokens, etc.)
     * @param kind The add liquidity operation type (e.g., proportional, custom)
     * @param amountsInScaled18 Actual amounts of tokens added, sorted in token registration order
     * @param amountsInRaw Actual amounts of tokens added, sorted in token registration order
     * @param bptAmountOut Amount of pool tokens minted
     * @param balancesScaled18 Current pool balances, sorted in token registration order
     * @param userData Additional (optional) data provided by the user
     * @return success True if the pool wishes to proceed with settlement
     * @return hookAdjustedAmountsInRaw New amountsInRaw, potentially modified by the hook
     */
    function onAfterAddLiquidity(
        address router,
        address pool,
        AddLiquidityKind kind,
        uint256[] memory amountsInScaled18,
        uint256[] memory amountsInRaw,
        uint256 bptAmountOut,
        uint256[] memory balancesScaled18,
        bytes memory userData
    ) external returns (bool success, uint256[] memory hookAdjustedAmountsInRaw);

    /***************************************************************************
                                 Remove Liquidity
    ***************************************************************************/

    /**
     * @notice Hook to be executed before removing liquidity.
     * @dev Called if the `shouldCallBeforeRemoveLiquidity` flag is set in the configuration. Hook contracts should use
     * the `onlyVault` modifier to guarantee this is only called by the Vault.
     *
     * @param router The address (usually a router contract) that initiated a remove liquidity operation on the Vault
     * @param pool Pool address, used to fetch pool information from the Vault (pool config, tokens, etc.)
     * @param kind The type of remove liquidity operation (e.g., proportional, custom)
     * @param maxBptAmountIn Maximum amount of input pool tokens
     * @param minAmountsOutScaled18 Minimum output amounts, sorted in token registration order
     * @param balancesScaled18 Current pool balances, sorted in token registration order
     * @param userData Optional, arbitrary data sent with the encoded request
     * @return success True if the pool wishes to proceed with settlement
     */
    function onBeforeRemoveLiquidity(
        address router,
        address pool,
        RemoveLiquidityKind kind,
        uint256 maxBptAmountIn,
        uint256[] memory minAmountsOutScaled18,
        uint256[] memory balancesScaled18,
        bytes memory userData
    ) external returns (bool success);

    /**
     * @notice Hook to be executed after removing liquidity.
     * @dev Called if the `shouldCallAfterRemoveLiquidity` flag is set in the configuration. The Vault will ignore
     * `hookAdjustedAmountsOutRaw` unless `enableHookAdjustedAmounts` is true. Hook contracts should use the
     * `onlyVault` modifier to guarantee this is only called by the Vault.
     *
     * @param router The address (usually a router contract) that initiated a remove liquidity operation on the Vault
     * @param pool Pool address, used to fetch pool information from the Vault (pool config, tokens, etc.)
     * @param kind The type of remove liquidity operation (e.g., proportional, custom)
     * @param bptAmountIn Amount of pool tokens to burn
     * @param amountsOutScaled18 Scaled amount of tokens to receive, sorted in token registration order
     * @param amountsOutRaw Actual amount of tokens to receive, sorted in token registration order
     * @param balancesScaled18 Current pool balances, sorted in token registration order
     * @param userData Additional (optional) data provided by the user
     * @return success True if the pool wishes to proceed with settlement
     * @return hookAdjustedAmountsOutRaw New amountsOutRaw, potentially modified by the hook
     */
    function onAfterRemoveLiquidity(
        address router,
        address pool,
        RemoveLiquidityKind kind,
        uint256 bptAmountIn,
        uint256[] memory amountsOutScaled18,
        uint256[] memory amountsOutRaw,
        uint256[] memory balancesScaled18,
        bytes memory userData
    ) external returns (bool success, uint256[] memory hookAdjustedAmountsOutRaw);

    /***************************************************************************
                                    Swap
    ***************************************************************************/

    /**
     * @notice Called before a swap to give the Pool an opportunity to perform actions.
     * @dev Called if the `shouldCallBeforeSwap` flag is set in the configuration. Hook contracts should use the
     * `onlyVault` modifier to guarantee this is only called by the Vault.
     *
     * @param params Swap parameters (see PoolSwapParams for struct definition)
     * @param pool Pool address, used to get pool information from the Vault (poolData, token config, etc.)
     * @return success True if the pool wishes to proceed with settlement
     */
    function onBeforeSwap(PoolSwapParams calldata params, address pool) external returns (bool success);

    /**
     * @notice Called after a swap to perform further actions once the balances have been updated by the swap.
     * @dev Called if the `shouldCallAfterSwap` flag is set in the configuration. The Vault will ignore
     * `hookAdjustedAmountCalculatedRaw` unless `enableHookAdjustedAmounts` is true. Hook contracts should
     * use the `onlyVault` modifier to guarantee this is only called by the Vault.
     *
     * @param params Swap parameters (see above for struct definition)
     * @return success True if the pool wishes to proceed with settlement
     * @return hookAdjustedAmountCalculatedRaw New amount calculated, potentially modified by the hook
     */
    function onAfterSwap(
        AfterSwapParams calldata params
    ) external returns (bool success, uint256 hookAdjustedAmountCalculatedRaw);

    /**
     * @notice Called after `onBeforeSwap` and before the main swap operation, if the pool has dynamic fees.
     * @dev Called if the `shouldCallComputeDynamicSwapFee` flag is set in the configuration. Hook contracts should use
     * the `onlyVault` modifier to guarantee this is only called by the Vault.
     *
     * @param params Swap parameters (see PoolSwapParams for struct definition)
     * @param pool Pool address, used to get pool information from the Vault (poolData, token config, etc.)
     * @param staticSwapFeePercentage 18-decimal FP value of the static swap fee percentage, for reference
     * @return success True if the pool wishes to proceed with settlement
     * @return dynamicSwapFeePercentage Value of the swap fee percentage, as an 18-decimal FP value
     */
    function onComputeDynamicSwapFeePercentage(
        PoolSwapParams calldata params,
        address pool,
        uint256 staticSwapFeePercentage
    ) external view returns (bool success, uint256 dynamicSwapFeePercentage);
}

// lib/balancer-v3-monorepo/pkg/interfaces/contracts/vault/IVaultMain.sol

/**
 * @notice Interface for functions defined on the main Vault contract.
 * @dev These are generally "critical path" functions (swap, add/remove liquidity) that are in the main contract
 * for technical or performance reasons.
 */
interface IVaultMain {
    /*******************************************************************************
                              Transient Accounting
    *******************************************************************************/

    /**
     * @notice Creates a context for a sequence of operations (i.e., "unlocks" the Vault).
     * @dev Performs a callback on msg.sender with arguments provided in `data`. The Callback is `transient`,
     * meaning all balances for the caller have to be settled at the end.
     *
     * @param data Contains function signature and args to be passed to the msg.sender
     * @return result Resulting data from the call
     */
    function unlock(bytes calldata data) external returns (bytes memory result);

    /**
     * @notice Settles deltas for a token; must be successful for the current lock to be released.
     * @dev Protects the caller against leftover dust in the Vault for the token being settled. The caller
     * should know in advance how many tokens were paid to the Vault, so it can provide it as a hint to discard any
     * excess in the Vault balance.
     *
     * If the given hint is equal to or higher than the difference in reserves, the difference in reserves is given as
     * credit to the caller. If it's higher, the caller sent fewer tokens than expected, so settlement would fail.
     *
     * If the given hint is lower than the difference in reserves, the hint is given as credit to the caller.
     * In this case, the excess would be absorbed by the Vault (and reflected correctly in the reserves), but would
     * not affect settlement.
     *
     * The credit supplied by the Vault can be calculated as `min(reserveDifference, amountHint)`, where the reserve
     * difference equals current balance of the token minus existing reserves of the token when the function is called.
     *
     * @param token Address of the token
     * @param amountHint Amount paid as reported by the caller
     * @return credit Credit received in return of the payment
     */
    function settle(IERC20 token, uint256 amountHint) external returns (uint256 credit);

    /**
     * @notice Sends tokens to a recipient.
     * @dev There is no inverse operation for this function. Transfer funds to the Vault and call `settle` to cancel
     * debts.
     *
     * @param token Address of the token
     * @param to Recipient address
     * @param amount Amount of tokens to send
     */
    function sendTo(IERC20 token, address to, uint256 amount) external;

    /***************************************************************************
                                       Swaps
    ***************************************************************************/

    /**
     * @notice Swaps tokens based on provided parameters.
     * @dev All parameters are given in raw token decimal encoding.
     * @param vaultSwapParams Parameters for the swap (see above for struct definition)
     * @return amountCalculatedRaw Calculated swap amount
     * @return amountInRaw Amount of input tokens for the swap
     * @return amountOutRaw Amount of output tokens from the swap
     */
    function swap(
        VaultSwapParams memory vaultSwapParams
    ) external returns (uint256 amountCalculatedRaw, uint256 amountInRaw, uint256 amountOutRaw);

    /***************************************************************************
                                   Add Liquidity
    ***************************************************************************/

    /**
     * @notice Adds liquidity to a pool.
     * @dev Caution should be exercised when adding liquidity because the Vault has the capability
     * to transfer tokens from any user, given that it holds all allowances.
     *
     * @param params Parameters for the add liquidity (see above for struct definition)
     * @return amountsIn Actual amounts of input tokens
     * @return bptAmountOut Output pool token amount
     * @return returnData Arbitrary (optional) data with an encoded response from the pool
     */
    function addLiquidity(
        AddLiquidityParams memory params
    ) external returns (uint256[] memory amountsIn, uint256 bptAmountOut, bytes memory returnData);

    /***************************************************************************
                                 Remove Liquidity
    ***************************************************************************/

    /**
     * @notice Removes liquidity from a pool.
     * @dev Trusted routers can burn pool tokens belonging to any user and require no prior approval from the user.
     * Untrusted routers require prior approval from the user. This is the only function allowed to call
     * _queryModeBalanceIncrease (and only in a query context).
     *
     * @param params Parameters for the remove liquidity (see above for struct definition)
     * @return bptAmountIn Actual amount of BPT burned
     * @return amountsOut Actual amounts of output tokens
     * @return returnData Arbitrary (optional) data with an encoded response from the pool
     */
    function removeLiquidity(
        RemoveLiquidityParams memory params
    ) external returns (uint256 bptAmountIn, uint256[] memory amountsOut, bytes memory returnData);

    /*******************************************************************************
                                    Pool Information
    *******************************************************************************/

    /**
     * @notice Gets the index of a token in a given pool.
     * @dev Reverts if the pool is not registered, or if the token does not belong to the pool.
     * @param pool Address of the pool
     * @param token Address of the token
     * @return tokenCount Number of tokens in the pool
     * @return index Index corresponding to the given token in the pool's token list
     */
    function getPoolTokenCountAndIndexOfToken(
        address pool,
        IERC20 token
    ) external view returns (uint256 tokenCount, uint256 index);

    /*******************************************************************************
                                 Balancer Pool Tokens
    *******************************************************************************/

    /**
     * @notice Transfers pool token from owner to a recipient.
     * @dev Notice that the pool token address is not included in the params. This function is exclusively called by
     * the pool contract, so msg.sender is used as the token address.
     *
     * @param owner Address of the owner
     * @param to Address of the recipient
     * @param amount Amount of tokens to transfer
     * @return success True if successful, false otherwise
     */
    function transfer(address owner, address to, uint256 amount) external returns (bool);

    /**
     * @notice Transfers pool token from a sender to a recipient using an allowance.
     * @dev Notice that the pool token address is not included in the params. This function is exclusively called by
     * the pool contract, so msg.sender is used as the token address.
     *
     * @param spender Address allowed to perform the transfer
     * @param from Address of the sender
     * @param to Address of the recipient
     * @param amount Amount of tokens to transfer
     * @return success True if successful, false otherwise
     */
    function transferFrom(address spender, address from, address to, uint256 amount) external returns (bool success);

    /*******************************************************************************
                                  ERC4626 Buffers
    *******************************************************************************/

    /**
     * @notice Wraps/unwraps tokens based on the parameters provided.
     * @dev All parameters are given in raw token decimal encoding. It requires the buffer to be initialized,
     * and uses the internal wrapped token buffer when it has enough liquidity to avoid external calls.
     *
     * @param params Parameters for the wrap/unwrap operation (see struct definition)
     * @return amountCalculatedRaw Calculated swap amount
     * @return amountInRaw Amount of input tokens for the swap
     * @return amountOutRaw Amount of output tokens from the swap
     */
    function erc4626BufferWrapOrUnwrap(
        BufferWrapOrUnwrapParams memory params
    ) external returns (uint256 amountCalculatedRaw, uint256 amountInRaw, uint256 amountOutRaw);

    /*******************************************************************************
                                     Miscellaneous
    *******************************************************************************/

    /**
     * @notice Returns the VaultExtension contract address.
     * @dev Function is in the main Vault contract. The VaultExtension handles less critical or frequently used
     * functions, since delegate calls through the Vault are more expensive than direct calls.
     *
     * @return vaultExtension Address of the VaultExtension
     */
    function getVaultExtension() external view returns (address vaultExtension);
}

// lib/balancer-v3-monorepo/pkg/vault/contracts/BaseHooks.sol

/**
 * @notice Base for pool hooks contracts.
 * @dev Hook contracts that only implement a subset of callbacks can inherit from here instead of IHooks,
 * and only override what they need. `VaultGuard` allows use of the `onlyVault` modifier, which isn't used
 * in this abstract contract, but should be used in real derived hook contracts.
 */
abstract contract BaseHooks is IHooks {
    /// @inheritdoc IHooks
    function onRegister(
        address,
        address,
        TokenConfig[] memory,
        LiquidityManagement calldata
    ) public virtual returns (bool) {
        // By default, deny all factories. This method must be overwritten by the hook contract.
        return false;
    }

    /// @inheritdoc IHooks
    function getHookFlags() public view virtual returns (HookFlags memory);

    /// @inheritdoc IHooks
    function onBeforeInitialize(uint256[] memory, bytes memory) public virtual returns (bool) {
        return false;
    }

    /// @inheritdoc IHooks
    function onAfterInitialize(uint256[] memory, uint256, bytes memory) public virtual returns (bool) {
        return false;
    }

    /// @inheritdoc IHooks
    function onBeforeAddLiquidity(
        address,
        address,
        AddLiquidityKind,
        uint256[] memory,
        uint256,
        uint256[] memory,
        bytes memory
    ) public virtual returns (bool) {
        return false;
    }

    /// @inheritdoc IHooks
    function onAfterAddLiquidity(
        address,
        address,
        AddLiquidityKind,
        uint256[] memory,
        uint256[] memory amountsInRaw,
        uint256,
        uint256[] memory,
        bytes memory
    ) public virtual returns (bool, uint256[] memory) {
        return (false, amountsInRaw);
    }

    /// @inheritdoc IHooks
    function onBeforeRemoveLiquidity(
        address,
        address,
        RemoveLiquidityKind,
        uint256,
        uint256[] memory,
        uint256[] memory,
        bytes memory
    ) public virtual returns (bool) {
        return false;
    }

    /// @inheritdoc IHooks
    function onAfterRemoveLiquidity(
        address,
        address,
        RemoveLiquidityKind,
        uint256,
        uint256[] memory,
        uint256[] memory amountsOutRaw,
        uint256[] memory,
        bytes memory
    ) public virtual returns (bool, uint256[] memory) {
        return (false, amountsOutRaw);
    }

    /// @inheritdoc IHooks
    function onBeforeSwap(PoolSwapParams calldata, address) public virtual returns (bool) {
        // return false to trigger an error if shouldCallBeforeSwap is true but this function is not overridden.
        return false;
    }

    /// @inheritdoc IHooks
    function onAfterSwap(AfterSwapParams calldata) public virtual returns (bool, uint256) {
        // return false to trigger an error if shouldCallAfterSwap is true but this function is not overridden.
        // The second argument is not used.
        return (false, 0);
    }

    /// @inheritdoc IHooks
    function onComputeDynamicSwapFeePercentage(
        PoolSwapParams calldata,
        address,
        uint256
    ) public view virtual returns (bool, uint256) {
        return (false, 0);
    }
}

// lib/balancer-v3-monorepo/pkg/interfaces/contracts/vault/IRouterCommon.sol

/// @notice Interface for functions shared between the `Router` and `BatchRouter`.
interface IRouterCommon {
    /**
     * @notice Data for the add liquidity hook.
     * @param sender Account originating the add liquidity operation
     * @param pool Address of the liquidity pool
     * @param maxAmountsIn Maximum amounts of tokens to be added, sorted in token registration order
     * @param minBptAmountOut Minimum amount of pool tokens to be received
     * @param kind Type of join (e.g., single or multi-token)
     * @param wethIsEth If true, incoming ETH will be wrapped to WETH and outgoing WETH will be unwrapped to ETH
     * @param userData Additional (optional) data sent with the request to add liquidity
     */
    struct AddLiquidityHookParams {
        address sender;
        address pool;
        uint256[] maxAmountsIn;
        uint256 minBptAmountOut;
        AddLiquidityKind kind;
        bool wethIsEth;
        bytes userData;
    }

    /**
     * @notice Data for the remove liquidity hook.
     * @param sender Account originating the remove liquidity operation
     * @param pool Address of the liquidity pool
     * @param minAmountsOut Minimum amounts of tokens to be received, sorted in token registration order
     * @param maxBptAmountIn Maximum amount of pool tokens provided
     * @param kind Type of exit (e.g., single or multi-token)
     * @param wethIsEth If true, incoming ETH will be wrapped to WETH and outgoing WETH will be unwrapped to ETH
     * @param userData Additional (optional) data sent with the request to remove liquidity
     */
    struct RemoveLiquidityHookParams {
        address sender;
        address pool;
        uint256[] minAmountsOut;
        uint256 maxBptAmountIn;
        RemoveLiquidityKind kind;
        bool wethIsEth;
        bytes userData;
    }

    /**
     * @notice Get the first sender which initialized the call to Router.
     * @return sender The address of the sender
     */
    function getSender() external view returns (address sender);

    /*******************************************************************************
                                         Utils
    *******************************************************************************/

    struct PermitApproval {
        address token;
        address owner;
        address spender;
        uint256 amount;
        uint256 nonce;
        uint256 deadline;
    }

    /**
     * @notice Permits multiple allowances and executes a batch of function calls on this contract.
     * @param permitBatch An array of `PermitApproval` structs, each representing an ERC20 permit request
     * @param permitSignatures An array of bytes, corresponding to the permit request signature in `permitBatch`
     * @param permit2Batch A batch of permit2 approvals
     * @param permit2Signature A permit2 signature for the batch approval
     * @param multicallData An array of bytes arrays, each representing an encoded function call on this contract
     * @return results Array of bytes arrays, each representing the return data from each function call executed
     */
    function permitBatchAndCall(
        PermitApproval[] calldata permitBatch,
        bytes[] calldata permitSignatures,
        IAllowanceTransfer.PermitBatch calldata permit2Batch,
        bytes calldata permit2Signature,
        bytes[] calldata multicallData
    ) external payable returns (bytes[] memory results);

    /**
     * @notice Executes a batch of function calls on this contract.
     * @param data Encoded function calls to be executed in the batch.
     * @return results Array of bytes arrays, each representing the return data from each function call executed.
     */
    function multicall(bytes[] calldata data) external payable returns (bytes[] memory results);
}

// lib/balancer-v3-monorepo/pkg/interfaces/contracts/vault/IProtocolFeeController.sol

/// @notice Contract that handles protocol and pool creator fees for the Vault.
interface IProtocolFeeController {
    /**
     * @notice Emitted when the protocol swap fee percentage is updated.
     * @param swapFeePercentage The updated protocol swap fee percentage
     */
    event GlobalProtocolSwapFeePercentageChanged(uint256 swapFeePercentage);

    /**
     * @notice Emitted when the protocol yield fee percentage is updated.
     * @param yieldFeePercentage The updated protocol yield fee percentage
     */
    event GlobalProtocolYieldFeePercentageChanged(uint256 yieldFeePercentage);

    /**
     * @notice Emitted when the protocol swap fee percentage is updated for a specific pool.
     * @param pool The pool whose protocol swap fee will be changed
     * @param swapFeePercentage The updated protocol swap fee percentage
     */
    event ProtocolSwapFeePercentageChanged(address indexed pool, uint256 swapFeePercentage);

    /**
     * @notice Emitted when the protocol yield fee percentage is updated for a specific pool.
     * @param pool The pool whose protocol yield fee will be changed
     * @param yieldFeePercentage The updated protocol yield fee percentage
     */
    event ProtocolYieldFeePercentageChanged(address indexed pool, uint256 yieldFeePercentage);

    /**
     * @notice Emitted when the pool creator swap fee percentage of a pool is updated.
     * @param pool The pool whose pool creator swap fee will be changed
     * @param poolCreatorSwapFeePercentage The new pool creator swap fee percentage for the pool
     */
    event PoolCreatorSwapFeePercentageChanged(address indexed pool, uint256 poolCreatorSwapFeePercentage);

    /**
     * @notice Emitted when the pool creator yield fee percentage of a pool is updated.
     * @param pool The pool whose pool creator yield fee will be changed
     * @param poolCreatorYieldFeePercentage The new pool creator yield fee percentage for the pool
     */
    event PoolCreatorYieldFeePercentageChanged(address indexed pool, uint256 poolCreatorYieldFeePercentage);

    /**
     * @notice Logs the collection of protocol swap fees in a specific token and amount.
     * @dev Note that since charging protocol fees (i.e., distributing tokens between pool and fee balances) occurs
     * in the Vault, but fee collection happens in the ProtocolFeeController, the swap fees reported here may encompass
     * multiple operations.
     *
     * @param pool The pool on which the swap fee was charged
     * @param token The token in which the swap fee was charged
     * @param amount The amount of the token collected in fees
     */
    event ProtocolSwapFeeCollected(address indexed pool, IERC20 indexed token, uint256 amount);

    /**
     * @notice Logs the collection of protocol yield fees in a specific token and amount.
     * @dev Note that since charging protocol fees (i.e., distributing tokens between pool and fee balances) occurs
     * in the Vault, but fee collection happens in the ProtocolFeeController, the yield fees reported here may encompass
     * multiple operations.
     *
     * @param pool The pool on which the yield fee was charged
     * @param token The token in which the yield fee was charged
     * @param amount The amount of the token collected in fees
     */
    event ProtocolYieldFeeCollected(address indexed pool, IERC20 indexed token, uint256 amount);

    /**
     * @notice Logs the withdrawal of protocol fees in a specific token and amount.
     * @param pool The pool from which protocol fees are being withdrawn
     * @param token The token being withdrawn
     * @param recipient The recipient of the funds
     * @param amount The amount of the fee token that was withdrawn
     */
    event ProtocolFeesWithdrawn(address indexed pool, IERC20 indexed token, address indexed recipient, uint256 amount);

    /**
     * @notice Logs the withdrawal of pool creator fees in a specific token and amount.
     * @param pool The pool from which pool creator fees are being withdrawn
     * @param token The token being withdrawn
     * @param recipient The recipient of the funds (the pool creator if permissionless, or another account)
     * @param amount The amount of the fee token that was withdrawn
     */
    event PoolCreatorFeesWithdrawn(
        address indexed pool,
        IERC20 indexed token,
        address indexed recipient,
        uint256 amount
    );

    /**
     * @notice Error raised when the protocol swap fee percentage exceeds the maximum allowed value.
     * @dev Note that this is checked for both the global and pool-specific protocol swap fee percentages.
     */
    error ProtocolSwapFeePercentageTooHigh();

    /**
     * @notice Error raised when the protocol yield fee percentage exceeds the maximum allowed value.
     * @dev Note that this is checked for both the global and pool-specific protocol yield fee percentages.
     */
    error ProtocolYieldFeePercentageTooHigh();

    /**
     * @notice Error raised if there is no pool creator on a withdrawal attempt from the given pool.
     * @param pool The pool with no creator
     */
    error PoolCreatorNotRegistered(address pool);

    /**
     * @notice Error raised if the wrong account attempts to withdraw pool creator fees.
     * @param caller The account attempting to withdraw pool creator fees
     * @param pool The pool the caller tried to withdraw from
     */
    error CallerIsNotPoolCreator(address caller, address pool);

    /// @notice Error raised when the pool creator swap or yield fee percentage exceeds the maximum allowed value.
    error PoolCreatorFeePercentageTooHigh();

    /**
     * @notice Get the address of the main Vault contract.
     * @return vault The Vault address
     */
    function vault() external view returns (IVault);

    /**
     * @notice Collects aggregate fees from the Vault for a given pool.
     * @param pool The pool with aggregate fees
     */
    function collectAggregateFees(address pool) external;

    /**
     * @notice Getter for the current global protocol swap fee.
     * @return protocolSwapFeePercentage The global protocol swap fee percentage
     */
    function getGlobalProtocolSwapFeePercentage() external view returns (uint256 protocolSwapFeePercentage);

    /**
     * @notice Getter for the current global protocol yield fee.
     * @return protocolYieldFeePercentage The global protocol yield fee percentage
     */
    function getGlobalProtocolYieldFeePercentage() external view returns (uint256 protocolYieldFeePercentage);

    /**
     * @notice Getter for the current protocol swap fee for a given pool.
     * @param pool The address of the pool
     * @return protocolSwapFeePercentage The global protocol swap fee percentage
     * @return isOverride True if the protocol fee has been overridden
     */
    function getPoolProtocolSwapFeeInfo(
        address pool
    ) external view returns (uint256 protocolSwapFeePercentage, bool isOverride);

    /**
     * @notice Getter for the current protocol yield fee for a given pool.
     * @param pool The address of the pool
     * @return protocolYieldFeePercentage The global protocol yield fee percentage
     * @return isOverride True if the protocol fee has been overridden
     */
    function getPoolProtocolYieldFeeInfo(
        address pool
    ) external view returns (uint256 protocolYieldFeePercentage, bool isOverride);

    /**
     * @notice Returns the amount of each pool token allocated to the protocol for withdrawal.
     * @dev Includes both swap and yield fees.
     * @param pool The address of the pool on which fees were collected
     * @return feeAmounts The total amounts of each token available for withdrawal, sorted in token registration order
     */
    function getProtocolFeeAmounts(address pool) external view returns (uint256[] memory feeAmounts);

    /**
     * @notice Returns the amount of each pool token allocated to the pool creator for withdrawal.
     * @dev Includes both swap and yield fees.
     * @param pool The address of the pool on which fees were collected
     * @return feeAmounts The total amounts of each token available for withdrawal, sorted in token registration order
     */
    function getPoolCreatorFeeAmounts(address pool) external view returns (uint256[] memory feeAmounts);

    /**
     * @notice Returns a calculated aggregate percentage from protocol and pool creator fee percentages.
     * @dev Not tied to any particular pool; this just performs the low-level "additive fee" calculation. Note that
     * pool creator fees are calculated based on creatorAndLpFees, and not in totalFees. Since aggregate fees are
     * stored in the Vault with 24-bit precision, this will truncate any values that require greater precision.
     * It is expected that pool creators will negotiate with the DAO and agree on reasonable values for these fee
     * components, but the truncation ensures it will not revert for any valid set of fee percentages.
     *
     * See example below:
     *
     * tokenOutAmount = 10000; poolSwapFeePct = 10%; protocolFeePct = 40%; creatorFeePct = 60%
     * totalFees = tokenOutAmount * poolSwapFeePct = 10000 * 10% = 1000
     * protocolFees = totalFees * protocolFeePct = 1000 * 40% = 400
     * creatorAndLpFees = totalFees - protocolFees = 1000 - 400 = 600
     * creatorFees = creatorAndLpFees * creatorFeePct = 600 * 60% = 360
     * lpFees (will stay in the pool) = creatorAndLpFees - creatorFees = 600 - 360 = 240
     *
     * @param protocolFeePercentage The protocol portion of the aggregate fee percentage
     * @param poolCreatorFeePercentage The pool creator portion of the aggregate fee percentage
     * @return aggregateFeePercentage The computed aggregate percentage
     */
    function computeAggregateFeePercentage(
        uint256 protocolFeePercentage,
        uint256 poolCreatorFeePercentage
    ) external pure returns (uint256 aggregateFeePercentage);

    /**
     * @notice Override the protocol swap fee percentage for a specific pool.
     * @dev This is a permissionless call, and will set the pool's fee to the current global fee, if it is different
     * from the current value, and the fee is not controlled by governance (i.e., has never been overridden).
     *
     * @param pool The pool for which we are setting the protocol swap fee
     */
    function updateProtocolSwapFeePercentage(address pool) external;

    /**
     * @notice Override the protocol yield fee percentage for a specific pool.
     * @dev This is a permissionless call, and will set the pool's fee to the current global fee, if it is different
     * from the current value, and the fee is not controlled by governance (i.e., has never been overridden).
     *
     * @param pool The pool for which we are setting the protocol yield fee
     */
    function updateProtocolYieldFeePercentage(address pool) external;

    /***************************************************************************
                                Permissioned Functions
    ***************************************************************************/

    /**
     * @notice Add pool-specific entries to the protocol swap and yield percentages.
     * @dev This must be called from the Vault during pool registration. It will initialize the pool to the global
     * protocol fee percentage values (or 0, if the `protocolFeeExempt` flags is set), and return the initial aggregate
     * fee percentages, based on an initial pool creator fee of 0.
     *
     * @param pool The address of the pool being registered
     * @param poolCreator The address of the pool creator (or 0 if there won't be a pool creator fee)
     * @param protocolFeeExempt If true, the pool is initially exempt from protocol fees
     * @return aggregateSwapFeePercentage The initial aggregate swap fee percentage
     * @return aggregateYieldFeePercentage The initial aggregate yield fee percentage
     */
    function registerPool(
        address pool,
        address poolCreator,
        bool protocolFeeExempt
    ) external returns (uint256 aggregateSwapFeePercentage, uint256 aggregateYieldFeePercentage);

    /**
     * @notice Set the global protocol swap fee percentage, used by standard pools.
     * @param newProtocolSwapFeePercentage The new protocol swap fee percentage
     */
    function setGlobalProtocolSwapFeePercentage(uint256 newProtocolSwapFeePercentage) external;

    /**
     * @notice Set the global protocol yield fee percentage, used by standard pools.
     * @param newProtocolYieldFeePercentage The new protocol yield fee percentage
     */
    function setGlobalProtocolYieldFeePercentage(uint256 newProtocolYieldFeePercentage) external;

    /**
     * @notice Override the protocol swap fee percentage for a specific pool.
     * @param pool The address of the pool for which we are setting the protocol swap fee
     * @param newProtocolSwapFeePercentage The new protocol swap fee percentage for the pool
     */
    function setProtocolSwapFeePercentage(address pool, uint256 newProtocolSwapFeePercentage) external;

    /**
     * @notice Override the protocol yield fee percentage for a specific pool.
     * @param pool The address of the pool for which we are setting the protocol yield fee
     * @param newProtocolYieldFeePercentage The new protocol yield fee percentage for the pool
     */
    function setProtocolYieldFeePercentage(address pool, uint256 newProtocolYieldFeePercentage) external;

    /**
     * @notice Assigns a new pool creator swap fee percentage to the specified pool.
     * @dev Fees are divided between the protocol, pool creator, and LPs. The pool creator percentage is applied to
     * the "net" amount after protocol fees, and divides the remainder between the pool creator and LPs. If the
     * pool creator fee is near 100%, almost none of the fee amount remains in the pool for LPs.
     *
     * @param pool The address of the pool for which the pool creator fee will be changed
     * @param poolCreatorSwapFeePercentage The new pool creator swap fee percentage to apply to the pool
     */
    function setPoolCreatorSwapFeePercentage(address pool, uint256 poolCreatorSwapFeePercentage) external;

    /**
     * @notice Assigns a new pool creator yield fee percentage to the specified pool.
     * @dev Fees are divided between the protocol, pool creator, and LPs. The pool creator percentage is applied to
     * the "net" amount after protocol fees, and divides the remainder between the pool creator and LPs. If the
     * pool creator fee is near 100%, almost none of the fee amount remains in the pool for LPs.
     *
     * @param pool The address of the pool for which the pool creator fee will be changed
     * @param poolCreatorYieldFeePercentage The new pool creator yield fee percentage to apply to the pool
     */
    function setPoolCreatorYieldFeePercentage(address pool, uint256 poolCreatorYieldFeePercentage) external;

    /**
     * @notice Withdraw collected protocol fees for a given pool (all tokens). This is a permissioned function.
     * @dev Sends swap and yield protocol fees to the recipient.
     * @param pool The pool on which fees were collected
     * @param recipient Address to send the tokens
     */
    function withdrawProtocolFees(address pool, address recipient) external;

    /**
     * @notice Withdraw collected protocol fees for a given pool and a given token. This is a permissioned function.
     * @dev Sends swap and yield protocol fees to the recipient.
     * @param pool The pool on which fees were collected
     * @param recipient Address to send the tokens
     * @param token Token to withdraw
     */
    function withdrawProtocolFeesForToken(address pool, address recipient, IERC20 token) external;

    /**
     * @notice Withdraw collected pool creator fees for a given pool. This is a permissioned function.
     * @dev Sends swap and yield pool creator fees to the recipient.
     * @param pool The pool on which fees were collected
     * @param recipient Address to send the tokens
     */
    function withdrawPoolCreatorFees(address pool, address recipient) external;

    /**
     * @notice Withdraw collected pool creator fees for a given pool.
     * @dev Sends swap and yield pool creator fees to the registered poolCreator. Since this is a known and immutable
     * value, this function is permissionless.
     *
     * @param pool The pool on which fees were collected
     */
    function withdrawPoolCreatorFees(address pool) external;
}
// lib/balancer-v3-monorepo/pkg/interfaces/contracts/vault/IVaultAdmin.sol

/**
 * @notice Interface for functions defined on the `VaultAdmin` contract.
 * @dev `VaultAdmin` is the Proxy extension of `VaultExtension`, and handles the least critical operations,
 * as two delegate calls add gas to each call. Most of the permissioned calls are here.
 */
interface IVaultAdmin {
    /*******************************************************************************
                               Constants and immutables
    *******************************************************************************/

    /**
     * @notice Returns the main Vault address.
     * @dev The main Vault contains the entrypoint and main liquidity operation implementations.
     * @return vault The address of the main Vault
     */
    function vault() external view returns (IVault);

    /**
     * @notice Returns the Vault's pause window end time.
     * @dev This value is immutable, and represents the timestamp after which the Vault can no longer be paused
     * by governance. Balancer timestamps are 32 bits.
     *
     * @return pauseWindowEndTime The timestamp when the Vault's pause window ends
     */
    function getPauseWindowEndTime() external view returns (uint32 pauseWindowEndTime);

    /**
     * @notice Returns the Vault's buffer period duration.
     * @dev This value is immutable. It represents the period during which, if paused, the Vault will remain paused.
     * This ensures there is time available to address whatever issue caused the Vault to be paused. Balancer
     * timestamps are 32 bits.
     *
     * @return bufferPeriodDuration The length of the buffer period in seconds
     */
    function getBufferPeriodDuration() external view returns (uint32 bufferPeriodDuration);

    /**
     * @notice Returns the Vault's buffer period end time.
     * @dev This value is immutable. If already paused, the Vault can be unpaused until this timestamp. Balancer
     * timestamps are 32 bits.
     *
     * @return bufferPeriodEndTime The timestamp after which the Vault remains permanently unpaused
     */
    function getBufferPeriodEndTime() external view returns (uint32 bufferPeriodEndTime);

    /**
     * @notice Get the minimum number of tokens in a pool.
     * @dev We expect the vast majority of pools to be 2-token.
     * @return minTokens The minimum token count of a pool
     */
    function getMinimumPoolTokens() external pure returns (uint256 minTokens);

    /**
     * @notice Get the maximum number of tokens in a pool.
     * @return maxTokens The maximum token count of a pool
     */
    function getMaximumPoolTokens() external pure returns (uint256 maxTokens);

    /**
     * @notice Get the minimum total supply of pool tokens (BPT) for an initialized pool.
     * @dev This prevents pools from being completely drained. When the pool is initialized, this minimum amount of BPT
     * is minted to the zero address. This is an 18-decimal floating point number; BPT are always 18 decimals.
     *
     * @return poolMinimumTotalSupply The minimum total supply a pool can have after initialization
     */
    function getPoolMinimumTotalSupply() external pure returns (uint256 poolMinimumTotalSupply);

    /**
     * @notice Get the minimum total supply of an ERC4626 wrapped token buffer in the Vault.
     * @dev This prevents buffers from being completely drained. When the buffer is initialized, this minimum number
     * of shares is added to the shares resulting from the initial deposit. Buffer total supply accounting is internal
     * to the Vault, as buffers are not tokenized.
     *
     * @return bufferMinimumTotalSupply The minimum total supply a buffer can have after initialization
     */
    function getBufferMinimumTotalSupply() external pure returns (uint256 bufferMinimumTotalSupply);

    /**
     * @notice Get the minimum trade amount in a pool operation.
     * @dev This limit is applied to the 18-decimal "upscaled" amount in any operation (swap, add/remove liquidity).
     * @return minimumTradeAmount The minimum trade amount as an 18-decimal floating point number
     */
    function getMinimumTradeAmount() external view returns (uint256 minimumTradeAmount);

    /**
     * @notice Get the minimum wrap amount in a buffer operation.
     * @dev This limit is applied to the wrap operation amount, in native underlying token decimals.
     * @return minimumWrapAmount The minimum wrap amount in native underlying token decimals
     */
    function getMinimumWrapAmount() external view returns (uint256 minimumWrapAmount);

    /*******************************************************************************
                                    Vault Pausing
    *******************************************************************************/

    /**
     * @notice Indicates whether the Vault is paused.
     * @dev If the Vault is paused, all non-Recovery Mode state-changing operations on pools will revert. Note that
     * ERC4626 buffers and the Vault have separate and independent pausing mechanisms. Pausing the Vault does not
     * also pause buffers (though we anticipate they would likely be paused and unpaused together). Call
     * `areBuffersPaused` to check the pause state of the buffers.
     *
     * @return vaultPaused True if the Vault is paused
     */
    function isVaultPaused() external view returns (bool vaultPaused);

    /**
     * @notice Returns the paused status, and end times of the Vault's pause window and buffer period.
     * @dev Balancer timestamps are 32 bits.
     * @return vaultPaused True if the Vault is paused
     * @return vaultPauseWindowEndTime The timestamp of the end of the Vault's pause window
     * @return vaultBufferPeriodEndTime The timestamp of the end of the Vault's buffer period
     */
    function getVaultPausedState()
        external
        view
        returns (bool vaultPaused, uint32 vaultPauseWindowEndTime, uint32 vaultBufferPeriodEndTime);

    /**
     * @notice Pause the Vault: an emergency action which disables all operational state-changing functions on pools.
     * @dev This is a permissioned function that will only work during the Pause Window set during deployment.
     * Note that ERC4626 buffer operations have an independent pause mechanism, which is not affected by pausing
     * the Vault. Custom routers could still wrap/unwrap using buffers while the Vault is paused, unless buffers
     * are also paused (with `pauseVaultBuffers`).
     */
    function pauseVault() external;

    /**
     * @notice Reverse a `pause` operation, and restore Vault pool operations to normal functionality.
     * @dev This is a permissioned function that will only work on a paused Vault within the Buffer Period set during
     * deployment. Note that the Vault will automatically unpause after the Buffer Period expires. As noted above,
     * ERC4626 buffers and Vault operations on pools are independent. Unpausing the Vault does not reverse
     * `pauseVaultBuffers`. If buffers were also paused, they will remain in that state until explicitly unpaused.
     */
    function unpauseVault() external;

    /*******************************************************************************
                                    Pool Pausing
    *******************************************************************************/

    /**
     * @notice Pause the Pool: an emergency action which disables all pool functions.
     * @dev This is a permissioned function that will only work during the Pause Window set during pool factory
     * deployment.
     *
     * @param pool The pool being paused
     */
    function pausePool(address pool) external;

    /**
     * @notice Reverse a `pause` operation, and restore the Pool to normal functionality.
     * @dev This is a permissioned function that will only work on a paused Pool within the Buffer Period set during
     * deployment. Note that the Pool will automatically unpause after the Buffer Period expires.
     *
     * @param pool The pool being unpaused
     */
    function unpausePool(address pool) external;

    /*******************************************************************************
                                         Fees
    *******************************************************************************/

    /**
     * @notice Assigns a new static swap fee percentage to the specified pool.
     * @dev This is a permissioned function, disabled if the pool is paused. The swap fee percentage must be within
     * the bounds specified by the pool's implementation of `ISwapFeePercentageBounds`.
     * Emits the SwapFeePercentageChanged event.
     *
     * @param pool The address of the pool for which the static swap fee will be changed
     * @param swapFeePercentage The new swap fee percentage to apply to the pool
     */
    function setStaticSwapFeePercentage(address pool, uint256 swapFeePercentage) external;

    /**
     * @notice Collects accumulated aggregate swap and yield fees for the specified pool.
     * @dev Fees are sent to the ProtocolFeeController address.
     * @param pool The pool on which all aggregate fees should be collected
     * @return swapFeeAmounts An array with the total swap fees collected, sorted in token registration order
     * @return yieldFeeAmounts An array with the total yield fees collected, sorted in token registration order
     */
    function collectAggregateFees(
        address pool
    ) external returns (uint256[] memory swapFeeAmounts, uint256[] memory yieldFeeAmounts);

    /**
     * @notice Update an aggregate swap fee percentage.
     * @dev Can only be called by the current protocol fee controller. Called when governance overrides a protocol fee
     * for a specific pool, or to permissionlessly update a pool to a changed global protocol fee value (if the pool's
     * fee has not previously been set by governance). Ensures the aggregate percentage <= FixedPoint.ONE, and also
     * that the final value does not lose precision when stored in 24 bits (see `FEE_BITLENGTH` in VaultTypes.sol).
     * Emits an `AggregateSwapFeePercentageChanged` event.
     *
     * @param pool The pool whose swap fee percentage will be updated
     * @param newAggregateSwapFeePercentage The new aggregate swap fee percentage
     */
    function updateAggregateSwapFeePercentage(address pool, uint256 newAggregateSwapFeePercentage) external;

    /**
     * @notice Update an aggregate yield fee percentage.
     * @dev Can only be called by the current protocol fee controller. Called when governance overrides a protocol fee
     * for a specific pool, or to permissionlessly update a pool to a changed global protocol fee value (if the pool's
     * fee has not previously been set by governance). Ensures the aggregate percentage <= FixedPoint.ONE, and also
     * that the final value does not lose precision when stored in 24 bits (see `FEE_BITLENGTH` in VaultTypes.sol).
     * Emits an `AggregateYieldFeePercentageChanged` event.
     *
     * @param pool The pool whose yield fee percentage will be updated
     * @param newAggregateYieldFeePercentage The new aggregate yield fee percentage
     */
    function updateAggregateYieldFeePercentage(address pool, uint256 newAggregateYieldFeePercentage) external;

    /**
     * @notice Sets a new Protocol Fee Controller for the Vault.
     * @dev This is a permissioned call. Emits a `ProtocolFeeControllerChanged` event.
     * @param newProtocolFeeController The address of the new Protocol Fee Controller
     */
    function setProtocolFeeController(IProtocolFeeController newProtocolFeeController) external;

    /*******************************************************************************
                                    Recovery Mode
    *******************************************************************************/

    /**
     * @notice Enable recovery mode for a pool.
     * @dev This is a permissioned function. It enables a safe proportional withdrawal, with no external calls.
     * Since there are no external calls, ensuring that entering Recovery Mode cannot fail, we cannot compute and so
     * must forfeit any yield fees between the last operation and enabling Recovery Mode. For the same reason, live
     * balances cannot be updated while in Recovery Mode, as doing so might cause withdrawals to fail.
     *
     * @param pool The address of the pool
     */
    function enableRecoveryMode(address pool) external;

    /**
     * @notice Disable recovery mode for a pool.
     * @dev This is a permissioned function. It re-syncs live balances (which could not be updated during
     * Recovery Mode), forfeiting any yield fees that accrued while enabled. It makes external calls, and could
     * potentially fail if there is an issue with any associated Rate Providers.
     *
     * @param pool The address of the pool
     */
    function disableRecoveryMode(address pool) external;

    /*******************************************************************************
                                  Query Functionality
    *******************************************************************************/

    /**
     * @notice Disables query functionality on the Vault. Can only be called by governance.
     * @dev The query functions rely on a specific EVM feature to detect static calls. Query operations are exempt from
     * settlement constraints, so it's critical that no state changes can occur. We retain the ability to disable
     * queries in the unlikely event that EVM changes violate its assumptions (perhaps on an L2).
     * This function can be acted upon as an emergency measure in ambiguous contexts where it's not 100% clear whether
     * disabling queries is completely necessary; queries can still be re-enabled after this call.
     */
    function disableQuery() external;

    /**
     * @notice Disables query functionality permanently on the Vault. Can only be called by governance.
     * @dev Shall only be used when there is no doubt that queries pose a fundamental threat to the system.
     */
    function disableQueryPermanently() external;

    /**
     * @notice Enables query functionality on the Vault. Can only be called by governance.
     * @dev Only works if queries are not permanently disabled.
     */
    function enableQuery() external;

    /*******************************************************************************
                                  ERC4626 Buffers
    *******************************************************************************/

    /**
     * @notice Indicates whether the Vault buffers are paused.
     * @dev When buffers are paused, all buffer operations (i.e., calls on the Router with `isBuffer` true)
     * will revert. Pausing buffers is reversible. Note that ERC4626 buffers and the Vault have separate and
     * independent pausing mechanisms. Pausing the Vault does not also pause buffers (though we anticipate they
     * would likely be paused and unpaused together). Call `isVaultPaused` to check the pause state of the Vault.
     *
     * @return buffersPaused True if the Vault buffers are paused
     */
    function areBuffersPaused() external view returns (bool buffersPaused);

    /**
     * @notice Pauses native vault buffers globally.
     * @dev When buffers are paused, it's not possible to add liquidity or wrap/unwrap tokens using the Vault's
     * `erc4626BufferWrapOrUnwrap` primitive. However, it's still possible to remove liquidity. Currently it's not
     * possible to pause vault buffers individually.
     *
     * This is a permissioned call, and is reversible (see `unpauseVaultBuffers`). Note that the Vault has a separate
     * and independent pausing mechanism. It is possible to pause the Vault (i.e. pool operations), without affecting
     * buffers, and vice versa.
     */
    function pauseVaultBuffers() external;

    /**
     * @notice Unpauses native vault buffers globally.
     * @dev When buffers are paused, it's not possible to add liquidity or wrap/unwrap tokens using the Vault's
     * `erc4626BufferWrapOrUnwrap` primitive. However, it's still possible to remove liquidity. As noted above,
     * ERC4626 buffers and Vault operations on pools are independent. Unpausing buffers does not reverse `pauseVault`.
     * If the Vault was also paused, it will remain in that state until explicitly unpaused.
     *
     * This is a permissioned call.
     */
    function unpauseVaultBuffers() external;

    /**
     * @notice Initializes buffer for the given wrapped token.
     * @param wrappedToken Address of the wrapped token that implements IERC4626
     * @param amountUnderlyingRaw Amount of underlying tokens that will be deposited into the buffer
     * @param amountWrappedRaw Amount of wrapped tokens that will be deposited into the buffer
     * @param minIssuedShares Minimum amount of shares to receive from the buffer, expressed in underlying token
     * native decimals
     * @param sharesOwner Address that will own the deposited liquidity. Only this address will be able to remove
     * liquidity from the buffer
     * @return issuedShares the amount of tokens sharesOwner has in the buffer, expressed in underlying token amounts.
     * (it is the BPT of an internal ERC4626 buffer). It is expressed in underlying token native decimals.
     */
    function initializeBuffer(
        IERC4626 wrappedToken,
        uint256 amountUnderlyingRaw,
        uint256 amountWrappedRaw,
        uint256 minIssuedShares,
        address sharesOwner
    ) external returns (uint256 issuedShares);

    /**
     * @notice Adds liquidity to an internal ERC4626 buffer in the Vault, proportionally.
     * @dev The buffer needs to be initialized beforehand.
     * @param wrappedToken Address of the wrapped token that implements IERC4626
     * @param maxAmountUnderlyingInRaw Maximum amount of underlying tokens to add to the buffer. It is expressed in
     * underlying token native decimals
     * @param maxAmountWrappedInRaw Maximum amount of wrapped tokens to add to the buffer. It is expressed in wrapped
     * token native decimals
     * @param exactSharesToIssue The value in underlying tokens that `sharesOwner` wants to add to the buffer,
     * in underlying token decimals
     * @param sharesOwner Address that will own the deposited liquidity. Only this address will be able to remove
     * liquidity from the buffer
     * @return amountUnderlyingRaw Amount of underlying tokens deposited into the buffer
     * @return amountWrappedRaw Amount of wrapped tokens deposited into the buffer
     */
    function addLiquidityToBuffer(
        IERC4626 wrappedToken,
        uint256 maxAmountUnderlyingInRaw,
        uint256 maxAmountWrappedInRaw,
        uint256 exactSharesToIssue,
        address sharesOwner
    ) external returns (uint256 amountUnderlyingRaw, uint256 amountWrappedRaw);

    /**
     * @notice Removes liquidity from an internal ERC4626 buffer in the Vault.
     * @dev Only proportional exits are supported, and the sender has to be the owner of the shares.
     * This function unlocks the Vault just for this operation; it does not work with a Router as an entrypoint.
     *
     * Pre-conditions:
     * - The buffer needs to be initialized.
     * - sharesOwner is the original msg.sender, it needs to be checked in the Router. That's why
     *   this call is authenticated; only routers approved by the DAO can remove the liquidity of a buffer.
     * - The buffer needs to have some liquidity and have its asset registered in `_bufferAssets` storage.
     *
     * @param wrappedToken Address of the wrapped token that implements IERC4626
     * @param sharesToRemove Amount of shares to remove from the buffer. Cannot be greater than sharesOwner's
     * total shares. It is expressed in underlying token native decimals
     * @param minAmountUnderlyingOutRaw Minimum amount of underlying tokens to receive from the buffer. It is expressed
     * in underlying token native decimals
     * @param minAmountWrappedOutRaw Minimum amount of wrapped tokens to receive from the buffer. It is expressed in
     * wrapped token native decimals
     * @return removedUnderlyingBalanceRaw Amount of underlying tokens returned to the user
     * @return removedWrappedBalanceRaw Amount of wrapped tokens returned to the user
     */
    function removeLiquidityFromBuffer(
        IERC4626 wrappedToken,
        uint256 sharesToRemove,
        uint256 minAmountUnderlyingOutRaw,
        uint256 minAmountWrappedOutRaw
    ) external returns (uint256 removedUnderlyingBalanceRaw, uint256 removedWrappedBalanceRaw);

    /**
     * @notice Returns the asset registered for a given wrapped token.
     * @dev The asset can never change after buffer initialization.
     * @param wrappedToken Address of the wrapped token that implements IERC4626
     * @return underlyingToken Address of the underlying token registered for the wrapper; `address(0)` if the buffer
     * has not been initialized.
     */
    function getBufferAsset(IERC4626 wrappedToken) external view returns (address underlyingToken);

    /**
     * @notice Returns the shares (internal buffer BPT) of a liquidity owner: a user that deposited assets
     * in the buffer.
     *
     * @param wrappedToken Address of the wrapped token that implements IERC4626
     * @param liquidityOwner Address of the user that owns liquidity in the wrapped token's buffer
     * @return ownerShares Amount of shares allocated to the liquidity owner, in native underlying token decimals
     */
    function getBufferOwnerShares(
        IERC4626 wrappedToken,
        address liquidityOwner
    ) external view returns (uint256 ownerShares);

    /**
     * @notice Returns the supply shares (internal buffer BPT) of the ERC4626 buffer.
     * @param wrappedToken Address of the wrapped token that implements IERC4626
     * @return bufferShares Amount of supply shares of the buffer, in native underlying token decimals
     */
    function getBufferTotalShares(IERC4626 wrappedToken) external view returns (uint256 bufferShares);

    /**
     * @notice Returns the amount of underlying and wrapped tokens deposited in the internal buffer of the Vault.
     * @dev All values are in native token decimals of the wrapped or underlying tokens.
     * @param wrappedToken Address of the wrapped token that implements IERC4626
     * @return underlyingBalanceRaw Amount of underlying tokens deposited into the buffer, in native token decimals
     * @return wrappedBalanceRaw Amount of wrapped tokens deposited into the buffer, in native token decimals
     */
    function getBufferBalance(
        IERC4626 wrappedToken
    ) external view returns (uint256 underlyingBalanceRaw, uint256 wrappedBalanceRaw);

    /*******************************************************************************
                                Authentication
    *******************************************************************************/

    /**
     * @notice Sets a new Authorizer for the Vault.
     * @dev This is a permissioned call. Emits an `AuthorizerChanged` event.
     * @param newAuthorizer The address of the new authorizer
     */
    function setAuthorizer(IAuthorizer newAuthorizer) external;
}

// lib/balancer-v3-monorepo/pkg/interfaces/contracts/vault/IVaultEvents.sol

/// @dev Events are declared inside an interface (namespace) to improve DX with Typechain.
interface IVaultEvents {
    /**
     * @notice A Pool was registered by calling `registerPool`.
     * @param pool The pool being registered
     * @param factory The factory creating the pool
     * @param tokenConfig An array of descriptors for the tokens the pool will manage
     * @param swapFeePercentage The static swap fee of the pool
     * @param pauseWindowEndTime The pool's pause window end time
     * @param roleAccounts Addresses the Vault will allow to change certain pool settings
     * @param hooksConfig Flags indicating which hooks the pool supports and address of hooks contract
     * @param liquidityManagement Supported liquidity management hook flags
     */
    event PoolRegistered(
        address indexed pool,
        address indexed factory,
        TokenConfig[] tokenConfig,
        uint256 swapFeePercentage,
        uint32 pauseWindowEndTime,
        PoolRoleAccounts roleAccounts,
        HooksConfig hooksConfig,
        LiquidityManagement liquidityManagement
    );

    /**
     * @notice A Pool was initialized by calling `initialize`.
     * @param pool The pool being initialized
     */
    event PoolInitialized(address indexed pool);

    /**
     * @notice A swap has occurred.
     * @param pool The pool with the tokens being swapped
     * @param tokenIn The token entering the Vault (balance increases)
     * @param tokenOut The token leaving the Vault (balance decreases)
     * @param amountIn Number of tokenIn tokens
     * @param amountOut Number of tokenOut tokens
     * @param swapFeePercentage Swap fee percentage applied (can differ if dynamic)
     * @param swapFeeAmount Swap fee amount paid
     */
    event Swap(
        address indexed pool,
        IERC20 indexed tokenIn,
        IERC20 indexed tokenOut,
        uint256 amountIn,
        uint256 amountOut,
        uint256 swapFeePercentage,
        uint256 swapFeeAmount
    );

    /**
     * @notice A wrap operation has occurred.
     * @param wrappedToken The wrapped token address
     * @param depositedUnderlying Number of underlying tokens deposited
     * @param mintedShares Number of shares (wrapped tokens) minted
     * @param bufferBalances The final buffer balances, packed in 128-bit words (underlying, wrapped)
     */
    event Wrap(
        IERC4626 indexed wrappedToken,
        uint256 depositedUnderlying,
        uint256 mintedShares,
        bytes32 bufferBalances
    );

    /**
     * @notice An unwrap operation has occurred.
     * @param wrappedToken The wrapped token address
     * @param burnedShares Number of shares (wrapped tokens) burned
     * @param withdrawnUnderlying Number of underlying tokens withdrawn
     * @param bufferBalances The final buffer balances, packed in 128-bit words (underlying, wrapped)
     */
    event Unwrap(
        IERC4626 indexed wrappedToken,
        uint256 burnedShares,
        uint256 withdrawnUnderlying,
        bytes32 bufferBalances
    );

    /**
     * @notice Liquidity has been added to a pool (including initialization).
     * @param pool The pool with liquidity added
     * @param liquidityProvider The user performing the operation
     * @param kind The add liquidity operation type (e.g., proportional, custom)
     * @param totalSupply The total supply of the pool after the operation
     * @param amountsAddedRaw The amount of each token that was added, sorted in token registration order
     * @param swapFeeAmountsRaw The total swap fees charged, sorted in token registration order
     */
    event LiquidityAdded(
        address indexed pool,
        address indexed liquidityProvider,
        AddLiquidityKind indexed kind,
        uint256 totalSupply,
        uint256[] amountsAddedRaw,
        uint256[] swapFeeAmountsRaw
    );

    /**
     * @notice Liquidity has been removed from a pool.
     * @param pool The pool with liquidity removed
     * @param liquidityProvider The user performing the operation
     * @param kind The remove liquidity operation type (e.g., proportional, custom)
     * @param totalSupply The total supply of the pool after the operation
     * @param amountsRemovedRaw The amount of each token that was removed, sorted in token registration order
     * @param swapFeeAmountsRaw The total swap fees charged, sorted in token registration order
     */
    event LiquidityRemoved(
        address indexed pool,
        address indexed liquidityProvider,
        RemoveLiquidityKind indexed kind,
        uint256 totalSupply,
        uint256[] amountsRemovedRaw,
        uint256[] swapFeeAmountsRaw
    );

    /**
     * @notice The Vault's pause status has changed.
     * @param paused True if the Vault was paused
     */
    event VaultPausedStateChanged(bool paused);

    /// @notice `disableQuery` has been called on the Vault, disabling query functionality.
    event VaultQueriesDisabled();

    /// @notice `enableQuery` has been called on the Vault, enabling query functionality.
    event VaultQueriesEnabled();

    /**
     * @notice A Pool's pause status has changed.
     * @param pool The pool that was just paused or unpaused
     * @param paused True if the pool was paused
     */
    event PoolPausedStateChanged(address indexed pool, bool paused);

    /**
     * @notice Emitted when the swap fee percentage of a pool is updated.
     * @param swapFeePercentage The new swap fee percentage for the pool
     */
    event SwapFeePercentageChanged(address indexed pool, uint256 swapFeePercentage);

    /**
     * @notice Recovery mode has been enabled or disabled for a pool.
     * @param pool The pool
     * @param recoveryMode True if recovery mode was enabled
     */
    event PoolRecoveryModeStateChanged(address indexed pool, bool recoveryMode);

    /**
     * @notice A protocol or pool creator fee has changed, causing an update to the aggregate swap fee.
     * @dev The `ProtocolFeeController` will emit an event with the underlying change.
     * @param pool The pool whose aggregate swap fee percentage changed
     * @param aggregateSwapFeePercentage The new aggregate swap fee percentage
     */
    event AggregateSwapFeePercentageChanged(address indexed pool, uint256 aggregateSwapFeePercentage);

    /**
     * @notice A protocol or pool creator fee has changed, causing an update to the aggregate yield fee.
     * @dev The `ProtocolFeeController` will emit an event with the underlying change.
     * @param pool The pool whose aggregate yield fee percentage changed
     * @param aggregateYieldFeePercentage The new aggregate yield fee percentage
     */
    event AggregateYieldFeePercentageChanged(address indexed pool, uint256 aggregateYieldFeePercentage);

    /**
     * @notice A new authorizer is set by `setAuthorizer`.
     * @param newAuthorizer The address of the new authorizer
     */
    event AuthorizerChanged(IAuthorizer indexed newAuthorizer);

    /**
     * @notice A new protocol fee controller is set by `setProtocolFeeController`.
     * @param newProtocolFeeController The address of the new protocol fee controller
     */
    event ProtocolFeeControllerChanged(IProtocolFeeController indexed newProtocolFeeController);

    /**
     * @notice Liquidity was added to an ERC4626 buffer corresponding to the given wrapped token.
     * @dev The underlying token can be derived from the wrapped token, so it's not included here.
     *
     * @param wrappedToken The wrapped token that identifies the buffer
     * @param amountUnderlying The amount of the underlying token that was deposited
     * @param amountWrapped The amount of the wrapped token that was deposited
     * @param bufferBalances The final buffer balances, packed in 128-bit words (underlying, wrapped)
     */
    event LiquidityAddedToBuffer(
        IERC4626 indexed wrappedToken,
        uint256 amountUnderlying,
        uint256 amountWrapped,
        bytes32 bufferBalances
    );

    /**
     * @notice Buffer shares were minted for an ERC4626 buffer corresponding to a given wrapped token.
     * @dev The shares are not tokenized like pool BPT, but accounted for in the Vault. `getBufferOwnerShares`
     * retrieves the current total shares for a given buffer and address, and `getBufferTotalShares` returns the
     * "totalSupply" of a buffer.
     *
     * @param wrappedToken The wrapped token that identifies the buffer
     * @param to The owner of the minted shares
     * @param issuedShares The amount of "internal BPT" shares created
     */
    event BufferSharesMinted(IERC4626 indexed wrappedToken, address indexed to, uint256 issuedShares);

    /**
     * @notice Buffer shares were burned for an ERC4626 buffer corresponding to a given wrapped token.
     * @dev The shares are not tokenized like pool BPT, but accounted for in the Vault. `getBufferOwnerShares`
     * retrieves the current total shares for a given buffer and address, and `getBufferTotalShares` returns the
     * "totalSupply" of a buffer.
     *
     * @param wrappedToken The wrapped token that identifies the buffer
     * @param from The owner of the burned shares
     * @param burnedShares The amount of "internal BPT" shares burned
     */
    event BufferSharesBurned(IERC4626 indexed wrappedToken, address indexed from, uint256 burnedShares);

    /**
     * @notice Liquidity was removed from an ERC4626 buffer.
     * @dev The underlying token can be derived from the wrapped token, so it's not included here.
     * @param wrappedToken The wrapped token that identifies the buffer
     * @param amountUnderlying The amount of the underlying token that was withdrawn
     * @param amountWrapped The amount of the wrapped token that was withdrawn
     * @param bufferBalances The final buffer balances, packed in 128-bit words (underlying, wrapped)
     */
    event LiquidityRemovedFromBuffer(
        IERC4626 indexed wrappedToken,
        uint256 amountUnderlying,
        uint256 amountWrapped,
        bytes32 bufferBalances
    );

    /**
     * @notice The Vault buffers pause status has changed.
     * @dev If buffers all paused, all buffer operations (i.e., all calls through the Router with `isBuffer`
     * set to true) will revert.
     *
     * @param paused True if the Vault buffers were paused
     */
    event VaultBuffersPausedStateChanged(bool paused);

    /**
     * @notice Pools can use this event to emit event data from the Vault.
     * @param pool Pool address
     * @param eventKey Event key
     * @param eventData Encoded event data
     */
    event VaultAuxiliary(address indexed pool, bytes32 indexed eventKey, bytes eventData);
}

// lib/balancer-v3-monorepo/pkg/interfaces/contracts/vault/IVaultExtension.sol

/**
 * @notice Interface for functions defined on the `VaultExtension` contract.
 * @dev `VaultExtension` handles less critical or frequently used functions, since delegate calls through
 * the Vault are more expensive than direct calls. The main Vault contains the core code for swaps and
 * liquidity operations.
 */
interface IVaultExtension {
    /*******************************************************************************
                              Constants and immutables
    *******************************************************************************/

    /**
     * @notice Returns the main Vault address.
     * @dev The main Vault contains the entrypoint and main liquidity operation implementations.
     * @return vault The address of the main Vault
     */
    function vault() external view returns (IVault);

    /**
     * @notice Returns the VaultAdmin contract address.
     * @dev The VaultAdmin contract mostly implements permissioned functions.
     * @return vaultAdmin The address of the Vault admin
     */
    function getVaultAdmin() external view returns (address vaultAdmin);

    /*******************************************************************************
                              Transient Accounting
    *******************************************************************************/

    /**
     * @notice Returns whether the Vault is unlocked (i.e., executing an operation).
     * @dev The Vault must be unlocked to perform state-changing liquidity operations.
     * @return unlocked True if the Vault is unlocked, false otherwise
     */
    function isUnlocked() external view returns (bool unlocked);

    /**
     *  @notice Returns the count of non-zero deltas.
     *  @return nonzeroDeltaCount The current value of `_nonzeroDeltaCount`
     */
    function getNonzeroDeltaCount() external view returns (uint256 nonzeroDeltaCount);

    /**
     * @notice Retrieves the token delta for a specific token.
     * @dev This function allows reading the value from the `_tokenDeltas` mapping.
     * @param token The token for which the delta is being fetched
     * @return tokenDelta The delta of the specified token
     */
    function getTokenDelta(IERC20 token) external view returns (int256 tokenDelta);

    /**
     * @notice Retrieves the reserve (i.e., total Vault balance) of a given token.
     * @param token The token for which to retrieve the reserve
     * @return reserveAmount The amount of reserves for the given token
     */
    function getReservesOf(IERC20 token) external view returns (uint256 reserveAmount);

    /**
     * @notice This flag is used to detect and tax "round-trip" interactions (adding and removing liquidity in the
     * same pool).
     * @dev Taxing remove liquidity proportional whenever liquidity was added in the same `unlock` call adds an extra
     * layer of security, discouraging operations that try to undo others for profit. Remove liquidity proportional
     * is the only standard way to exit a position without fees, and this flag is used to enable fees in that case.
     * It also discourages indirect swaps via unbalanced add and remove proportional, as they are expected to be worse
     * than a simple swap for every pool type.
     *
     * @param pool Address of the pool to check
     * @return liquidityAdded True if liquidity has been added to this pool in the current transaction
     
     * Note that there is no `sessionId` argument; it always returns the value for the current (i.e., latest) session.
     */
    function getAddLiquidityCalledFlag(address pool) external view returns (bool liquidityAdded);

    /*******************************************************************************
                                    Pool Registration
    *******************************************************************************/

    /**
     * @notice Registers a pool, associating it with its factory and the tokens it manages.
     * @dev A pool can opt-out of pausing by providing a zero value for the pause window, or allow pausing indefinitely
     * by providing a large value. (Pool pause windows are not limited by the Vault maximums.) The vault defines an
     * additional buffer period during which a paused pool will stay paused. After the buffer period passes, a paused
     * pool will automatically unpause. Balancer timestamps are 32 bits.
     *
     * A pool can opt out of Balancer governance pausing by providing a custom `pauseManager`. This might be a
     * multi-sig contract or an arbitrary smart contract with its own access controls, that forwards calls to
     * the Vault.
     *
     * If the zero address is provided for the `pauseManager`, permissions for pausing the pool will default to the
     * authorizer.
     *
     * @param pool The address of the pool being registered
     * @param tokenConfig An array of descriptors for the tokens the pool will manage
     * @param swapFeePercentage The initial static swap fee percentage of the pool
     * @param pauseWindowEndTime The timestamp after which it is no longer possible to pause the pool
     * @param protocolFeeExempt If true, the pool's initial aggregate fees will be set to 0
     * @param roleAccounts Addresses the Vault will allow to change certain pool settings
     * @param poolHooksContract Contract that implements the hooks for the pool
     * @param liquidityManagement Liquidity management flags with implemented methods
     */
    function registerPool(
        address pool,
        TokenConfig[] memory tokenConfig,
        uint256 swapFeePercentage,
        uint32 pauseWindowEndTime,
        bool protocolFeeExempt,
        PoolRoleAccounts calldata roleAccounts,
        address poolHooksContract,
        LiquidityManagement calldata liquidityManagement
    ) external;

    /**
     * @notice Checks whether a pool is registered.
     * @param pool Address of the pool to check
     * @return registered True if the pool is registered, false otherwise
     */
    function isPoolRegistered(address pool) external view returns (bool registered);

    /**
     * @notice Initializes a registered pool by adding liquidity; mints BPT tokens for the first time in exchange.
     * @param pool Address of the pool to initialize
     * @param to Address that will receive the output BPT
     * @param tokens Tokens used to seed the pool (must match the registered tokens)
     * @param exactAmountsIn Exact amounts of input tokens
     * @param minBptAmountOut Minimum amount of output pool tokens
     * @param userData Additional (optional) data required for adding initial liquidity
     * @return bptAmountOut Output pool token amount
     */
    function initialize(
        address pool,
        address to,
        IERC20[] memory tokens,
        uint256[] memory exactAmountsIn,
        uint256 minBptAmountOut,
        bytes memory userData
    ) external returns (uint256 bptAmountOut);

    /*******************************************************************************
                                    Pool Information
    *******************************************************************************/

    /**
     * @notice Checks whether a pool is initialized.
     * @dev An initialized pool can be considered registered as well.
     * @param pool Address of the pool to check
     * @return initialized True if the pool is initialized, false otherwise
     */
    function isPoolInitialized(address pool) external view returns (bool initialized);

    /**
     * @notice Gets the tokens registered to a pool.
     * @param pool Address of the pool
     * @return tokens List of tokens in the pool
     */
    function getPoolTokens(address pool) external view returns (IERC20[] memory tokens);

    /**
     * @notice Gets pool token rates.
     * @dev This function performs external calls if tokens are yield-bearing. All returned arrays are in token
     * registration order.
     *
     * @param pool Address of the pool
     * @return decimalScalingFactors Conversion factor used to adjust for token decimals for uniform precision in
     * calculations. FP(1) for 18-decimal tokens
     * @return tokenRates 18-decimal FP values for rate tokens (e.g., yield-bearing), or FP(1) for standard tokens
     */
    function getPoolTokenRates(
        address pool
    ) external view returns (uint256[] memory decimalScalingFactors, uint256[] memory tokenRates);

    /**
     * @notice Returns comprehensive pool data for the given pool.
     * @dev This contains the pool configuration (flags), tokens and token types, rates, scaling factors, and balances.
     * @param pool The address of the pool
     * @return poolData The `PoolData` result
     */
    function getPoolData(address pool) external view returns (PoolData memory poolData);

    /**
     * @notice Gets the raw data for a pool: tokens, raw balances, scaling factors.
     * @param pool Address of the pool
     * @return tokens The pool tokens, sorted in registration order
     * @return tokenInfo Token info structs (type, rate provider, yield flag), sorted in token registration order
     * @return balancesRaw Current native decimal balances of the pool tokens, sorted in token registration order
     * @return lastBalancesLiveScaled18 Last saved live balances, sorted in token registration order
     */
    function getPoolTokenInfo(
        address pool
    )
        external
        view
        returns (
            IERC20[] memory tokens,
            TokenInfo[] memory tokenInfo,
            uint256[] memory balancesRaw,
            uint256[] memory lastBalancesLiveScaled18
        );

    /**
     * @notice Gets current live balances of a given pool (fixed-point, 18 decimals), corresponding to its tokens in
     * registration order.
     *
     * @param pool Address of the pool
     * @return balancesLiveScaled18 Token balances after paying yield fees, applying decimal scaling and rates
     */
    function getCurrentLiveBalances(address pool) external view returns (uint256[] memory balancesLiveScaled18);

    /**
     * @notice Gets the configuration parameters of a pool.
     * @dev The `PoolConfig` contains liquidity management and other state flags, fee percentages, the pause window.
     * @param pool Address of the pool
     * @return poolConfig The pool configuration as a `PoolConfig` struct
     */
    function getPoolConfig(address pool) external view returns (PoolConfig memory poolConfig);

    /**
     * @notice Gets the hooks configuration parameters of a pool.
     * @dev The `HooksConfig` contains flags indicating which pool hooks are implemented.
     * @param pool Address of the pool
     * @return hooksConfig The hooks configuration as a `HooksConfig` struct
     */
    function getHooksConfig(address pool) external view returns (HooksConfig memory hooksConfig);

    /**
     * @notice The current rate of a pool token (BPT) = invariant / totalSupply.
     * @param pool Address of the pool
     * @return rate BPT rate
     */
    function getBptRate(address pool) external view returns (uint256 rate);

    /*******************************************************************************
                                 Balancer Pool Tokens
    *******************************************************************************/

    /**
     * @notice Gets the total supply of a given ERC20 token.
     * @param token The token address
     * @return tokenTotalSupply Total supply of the token
     */
    function totalSupply(address token) external view returns (uint256 tokenTotalSupply);

    /**
     * @notice Gets the balance of an account for a given ERC20 token.
     * @param token Address of the token
     * @param account Address of the account
     * @return tokenBalance Token balance of the account
     */
    function balanceOf(address token, address account) external view returns (uint256 tokenBalance);

    /**
     * @notice Gets the allowance of a spender for a given ERC20 token and owner.
     * @param token Address of the token
     * @param owner Address of the owner
     * @param spender Address of the spender
     * @return tokenAllowance Amount of tokens the spender is allowed to spend
     */
    function allowance(address token, address owner, address spender) external view returns (uint256 tokenAllowance);

    /**
     * @notice Approves a spender to spend pool tokens on behalf of sender.
     * @dev Notice that the pool token address is not included in the params. This function is exclusively called by
     * the pool contract, so msg.sender is used as the token address.
     *
     * @param owner Address of the owner
     * @param spender Address of the spender
     * @param amount Amount of tokens to approve
     * @return success True if successful, false otherwise
     */
    function approve(address owner, address spender, uint256 amount) external returns (bool success);

    /*******************************************************************************
                                     Pool Pausing
    *******************************************************************************/

    /**
     * @notice Indicates whether a pool is paused.
     * @dev If a pool is paused, all non-Recovery Mode state-changing operations will revert.
     * @param pool The pool to be checked
     * @return poolPaused True if the pool is paused
     */
    function isPoolPaused(address pool) external view returns (bool poolPaused);

    /**
     * @notice Returns the paused status, and end times of the Pool's pause window and buffer period.
     * @dev Note that even when set to a paused state, the pool will automatically unpause at the end of
     * the buffer period. Balancer timestamps are 32 bits.
     *
     * @param pool The pool whose data is requested
     * @return poolPaused True if the Pool is paused
     * @return poolPauseWindowEndTime The timestamp of the end of the Pool's pause window
     * @return poolBufferPeriodEndTime The timestamp after which the Pool unpauses itself (if paused)
     * @return pauseManager The pause manager, or the zero address
     */
    function getPoolPausedState(
        address pool
    )
        external
        view
        returns (bool poolPaused, uint32 poolPauseWindowEndTime, uint32 poolBufferPeriodEndTime, address pauseManager);

    /*******************************************************************************
                                   ERC4626 Buffers
    *******************************************************************************/

    /**
     * @notice Checks if the wrapped token has an initialized buffer in the Vault.
     * @dev An initialized buffer should have an asset registered in the Vault.
     * @param wrappedToken Address of the wrapped token that implements IERC4626
     * @return isBufferInitialized True if the ERC4626 buffer is initialized
     */
    function isERC4626BufferInitialized(IERC4626 wrappedToken) external view returns (bool isBufferInitialized);

    /**
     * @notice Gets the registered asset for a given buffer.
     * @dev To avoid malicious wrappers (e.g., that might potentially change their asset after deployment), routers
     * should never call `wrapper.asset()` directly, at least without checking it against the asset registered with
     * the Vault on initialization.
     *
     * @param wrappedToken The wrapped token specifying the buffer
     * @return asset The underlying asset of the wrapped token
     */
    function getERC4626BufferAsset(IERC4626 wrappedToken) external view returns (address asset);

    /*******************************************************************************
                                          Fees
    *******************************************************************************/

    /**
     * @notice Returns the accumulated swap fees (including aggregate fees) in `token` collected by the pool.
     * @param pool The address of the pool for which aggregate fees have been collected
     * @param token The address of the token in which fees have been accumulated
     * @return swapFeeAmount The total amount of fees accumulated in the specified token
     */
    function getAggregateSwapFeeAmount(address pool, IERC20 token) external view returns (uint256 swapFeeAmount);

    /**
     * @notice Returns the accumulated yield fees (including aggregate fees) in `token` collected by the pool.
     * @param pool The address of the pool for which aggregate fees have been collected
     * @param token The address of the token in which fees have been accumulated
     * @return yieldFeeAmount The total amount of fees accumulated in the specified token
     */
    function getAggregateYieldFeeAmount(address pool, IERC20 token) external view returns (uint256 yieldFeeAmount);

    /**
     * @notice Fetches the static swap fee percentage for a given pool.
     * @param pool The address of the pool whose static swap fee percentage is being queried
     * @return swapFeePercentage The current static swap fee percentage for the specified pool
     */
    function getStaticSwapFeePercentage(address pool) external view returns (uint256 swapFeePercentage);

    /**
     * @notice Fetches the role accounts for a given pool (pause manager, swap manager, pool creator)
     * @param pool The address of the pool whose roles are being queried
     * @return roleAccounts A struct containing the role accounts for the pool (or 0 if unassigned)
     */
    function getPoolRoleAccounts(address pool) external view returns (PoolRoleAccounts memory roleAccounts);

    /**
     * @notice Query the current dynamic swap fee percentage of a pool, given a set of swap parameters.
     * @dev Reverts if the hook doesn't return the success flag set to `true`.
     * @param pool The pool
     * @param swapParams The swap parameters used to compute the fee
     * @return dynamicSwapFeePercentage The dynamic swap fee percentage
     */
    function computeDynamicSwapFeePercentage(
        address pool,
        PoolSwapParams memory swapParams
    ) external view returns (uint256 dynamicSwapFeePercentage);

    /**
     * @notice Returns the Protocol Fee Controller address.
     * @return protocolFeeController Address of the ProtocolFeeController
     */
    function getProtocolFeeController() external view returns (IProtocolFeeController protocolFeeController);

    /*******************************************************************************
                                     Recovery Mode
    *******************************************************************************/

    /**
     * @notice Checks whether a pool is in Recovery Mode.
     * @dev Recovery Mode enables a safe proportional withdrawal path, with no external calls.
     * @param pool Address of the pool to check
     * @return inRecoveryMode True if the pool is in Recovery Mode, false otherwise
     */
    function isPoolInRecoveryMode(address pool) external view returns (bool inRecoveryMode);

    /**
     * @notice Remove liquidity from a pool specifying exact pool tokens in, with proportional token amounts out.
     * The request is implemented by the Vault without any interaction with the pool, ensuring that
     * it works the same for all pools, and cannot be disabled by a new pool type.
     *
     * @param pool Address of the pool
     * @param from Address of user to burn pool tokens from
     * @param exactBptAmountIn Input pool token amount
     * @param minAmountsOut Minimum amounts of tokens to be received, sorted in token registration order
     * @return amountsOut Actual calculated amounts of output tokens, sorted in token registration order
     */
    function removeLiquidityRecovery(
        address pool,
        address from,
        uint256 exactBptAmountIn,
        uint256[] memory minAmountsOut
    ) external returns (uint256[] memory amountsOut);

    /*******************************************************************************
                                    Queries
    *******************************************************************************/

    /**
     * @notice Performs a callback on msg.sender with arguments provided in `data`.
     * @dev Used to query a set of operations on the Vault. Only off-chain eth_call are allowed,
     * anything else will revert.
     *
     * Allows querying any operation on the Vault that has the `onlyWhenUnlocked` modifier.
     *
     * Allows the external calling of a function via the Vault contract to
     * access Vault's functions guarded by `onlyWhenUnlocked`.
     * `transient` modifier ensuring balances changes within the Vault are settled.
     *
     * @param data Contains function signature and args to be passed to the msg.sender
     * @return result Resulting data from the call
     */
    function quote(bytes calldata data) external returns (bytes memory result);

    /**
     * @notice Performs a callback on msg.sender with arguments provided in `data`.
     * @dev Used to query a set of operations on the Vault. Only off-chain eth_call are allowed,
     * anything else will revert.
     *
     * Allows querying any operation on the Vault that has the `onlyWhenUnlocked` modifier.
     *
     * Allows the external calling of a function via the Vault contract to
     * access Vault's functions guarded by `onlyWhenUnlocked`.
     * `transient` modifier ensuring balances changes within the Vault are settled.
     *
     * This call always reverts, returning the result in the revert reason.
     *
     * @param data Contains function signature and args to be passed to the msg.sender
     */
    function quoteAndRevert(bytes calldata data) external;

    /**
     * @notice Returns true if queries are disabled on the Vault.
     * @dev If true, queries might either be disabled temporarily or permanently.
     * @return queryDisabled True if query functionality is reversibly disabled
     */
    function isQueryDisabled() external view returns (bool queryDisabled);

    /**
     * @notice Returns true if queries are disabled permanently; false if they are enabled.
     * @dev This is a one-way switch. Once queries are disabled permanently, they can never be re-enabled.
     * @return queryDisabledPermanently True if query functionality is permanently disabled
     */
    function isQueryDisabledPermanently() external view returns (bool queryDisabledPermanently);

    /**
     * @notice Pools can use this event to emit event data from the Vault.
     * @param eventKey Event key
     * @param eventData Encoded event data
     */
    function emitAuxiliaryEvent(bytes32 eventKey, bytes calldata eventData) external;

    /*******************************************************************************
                                Authentication
    *******************************************************************************/

    /**
     * @notice Returns the Authorizer address.
     * @dev The authorizer holds the permissions granted by governance. It is set on Vault deployment,
     * and can be changed through a permissioned call.
     *
     * @return authorizer Address of the authorizer contract
     */
    function getAuthorizer() external view returns (IAuthorizer authorizer);
}

// lib/balancer-v3-monorepo/pkg/vault/contracts/VaultGuard.sol

/// @notice Contract that shares the modifier `onlyVault`.
contract VaultGuard {
    IVault internal immutable _vault;

    constructor(IVault vault) {
        _vault = vault;
    }

    modifier onlyVault() {
        _ensureOnlyVault();
        _;
    }

    function _ensureOnlyVault() private view {
        if (msg.sender != address(_vault)) {
            revert IVaultErrors.SenderIsNotVault(msg.sender);
        }
    }
}


// lib/balancer-v3-monorepo/pkg/interfaces/contracts/vault/IVault.sol

/// @notice Composite interface for all Vault operations: swap, add/remove liquidity, and associated queries.
interface IVault is IVaultMain, IVaultExtension, IVaultAdmin, IVaultErrors, IVaultEvents, IAuthentication {
    /// @return vault The main Vault address.
    function vault() external view override(IVaultAdmin, IVaultExtension) returns (IVault);
}


// contracts/hooks/EZKLDynamicFeeHook.sol

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

    constructor(IVault vault, address verifier, address priceCache, uint256 scalingFactor, uint256 lookback) VaultGuard(vault) {
        _verifier = IHalo2Verifier(verifier);
        _priceCache = IChainlinkPriceCache(priceCache);
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
    function updateFee(bytes calldata proof, uint256 dynamicFeeUnscaled) external {
        // construct instances we take lookback + 1 to append dynamic fee into the instances
        uint256[] memory instances = new uint256[](_lookback + 1);

        // Get historical price
        uint256[] memory historical = _priceCache.getHistoricalPrice(_lookback);

        // add historical to instances and append dynamicfee at the end
        uint256 historicalLength = historical.length;
        for (uint256 i = 0; i < historicalLength; ++i) {
            instances[i] = historical[i];
        }
        instances[_lookback] = dynamicFeeUnscaled;

        if (_verifier.verifyProof(proof, instances)) {
            _dynamicFee = (dynamicFeeUnscaled * 1e18) / (_scalingFactor * 1e18);

            emit EZKLDynamicFeeHookUpdated(
                address(this),
                _dynamicFee
            );
        } else {
            revert VerificationFail();
        }
    }
}

