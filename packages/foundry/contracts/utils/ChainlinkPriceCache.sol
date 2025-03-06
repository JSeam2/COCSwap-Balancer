// SPDX-License-Identifier: AGPL-3.0
pragma solidity ^0.8.24;

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