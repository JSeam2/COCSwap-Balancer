// SPDX-License-Identifier: AGPL-3.0
pragma solidity ^0.8.24;

/**
 * @title IChainlinkCache
 * @notice Interface for the ChainlinkCache contract
 * @dev Defines methods for retrieving historical oracle data
 */
interface IChainlinkCache {
    struct Snapshot {
        uint256 timestamp;
        int256 answer;
    }

    /**
     * @notice Get historical data for a specific number of past snapshots
     * @param lookback Number of snapshots to retrieve from current position
     * @return Array of historical oracle data snapshots
     */
    function getHistorical(uint256 lookback) external view returns (Snapshot[] memory);

    /**
     * @notice Get historical data between specified snapshot IDs
     * @param start The starting snapshot ID (inclusive)
     * @param end The ending snapshot ID (inclusive)
     * @return Array of historical oracle data snapshots
     */
    function getHistoricalRange(uint256 start, uint256 end) external view returns (Snapshot[] memory);
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
 * @title ChainlinkCache
 * @notice Contract for caching Chainlink oracle data and providing historical snapshots
 * @dev Stores oracle data snapshots with timestamps and provides methods to retrieve historical data
 */
contract ChainlinkCache is IChainlinkCache {

    // Example oracle addresses:
    // ETH/USD contract address 0x5f4eC3Df9cbd43714FE2740f5E3616155c5b8419
    // USDC/ETH contract address 0x986b5E1e1755e3C2440e960477f25201B0a8bbD4
    IAggregatorInterface public immutable oracle;

    // delay in seconds until the next update can be made
    uint256 public immutable delay;

    // last updated snapshot ID
    uint256 public latestSnapshotId;

    // storage for oracle data snapshots
    mapping(uint256 => Snapshot) public snapshots;

    error WaitForDelay();
    error InvalidRange();
    error NoDataAvailable();

    event Updated(uint256 indexed timestamp, int256 answer);

    /**
     * @notice Initializes the contract with an oracle and historical data
     * @param _oracle Chainlink oracle address
     * @param _delay Minimum delay in seconds between updates
     * @param _roundIds Array of Chainlink round IDs to populate initial history
     */
    constructor(address _oracle, uint256 _delay, uint256[] memory _roundIds) {
        oracle = IAggregatorInterface(_oracle);
        delay = _delay;
        
        uint256 roundIdsLength = _roundIds.length;
        
        if (roundIdsLength == 0) {
            latestSnapshotId = 0;
            return;
        }
        
        latestSnapshotId = roundIdsLength - 1;

        for (uint256 i = 0; i < roundIdsLength; ++i) {
            snapshots[i] = Snapshot({
                timestamp: oracle.getTimestamp(_roundIds[i]),
                answer: oracle.getAnswer(_roundIds[i])
            });
        }
    }

    /**
     * @notice Updates the cache with the latest data from the oracle
     * @dev Reverts if not enough time has passed since the last update
     */
    function update() external {
        uint256 lastTimestamp = snapshots[latestSnapshotId].timestamp;
        uint256 latestTimestamp = oracle.latestTimestamp();
        int256 latestAnswer = oracle.latestAnswer();

        if ((lastTimestamp + delay) > latestTimestamp) {
            revert WaitForDelay();
        }

        ++latestSnapshotId;

        snapshots[latestSnapshotId] = Snapshot({
            timestamp: latestTimestamp,
            answer: latestAnswer
        });

        emit Updated(latestTimestamp, latestAnswer);
    }

    /**
     * @notice Get historical data for a specific number of past snapshots
     * @param lookback Number of snapshots to retrieve from current position
     * @return result Array of historical oracle data snapshots
     * @dev Reverts if no data is available or if lookback exceeds available data
     */
    function getHistorical(uint256 lookback) external view returns (Snapshot[] memory) {
        if (latestSnapshotId == 0 && snapshots[0].timestamp == 0) {
            revert NoDataAvailable();
        }
        
        // Check if lookback exceeds available history
        if (lookback > latestSnapshotId + 1) {
            revert NoDataAvailable();
        }
        
        Snapshot[] memory result = new Snapshot[](lookback);
        
        for (uint256 i = 0; i < lookback; i++) {
            uint256 snapshotId = latestSnapshotId - i;
            result[i] = snapshots[snapshotId];
        }
        
        return result;
    }

    /**
     * @notice Get historical data between specified snapshot IDs
     * @param start The starting snapshot ID (inclusive)
     * @param end The ending snapshot ID (inclusive)
     * @return result Array of historical oracle data snapshots
     * @dev Reverts if range is invalid or no data is available
     */
    function getHistoricalRange(uint256 start, uint256 end) external view returns (Snapshot[] memory) {
        if (end < start || end > latestSnapshotId) {
            revert InvalidRange();
        }
        
        if (latestSnapshotId == 0 && snapshots[0].timestamp == 0) {
            revert NoDataAvailable();
        }
        
        uint256 size = end - start + 1;
        Snapshot[] memory result = new Snapshot[](size);
        
        for (uint256 i = 0; i < size; i++) {
            result[i] = snapshots[start + i];
        }
        
        return result;
    }
}