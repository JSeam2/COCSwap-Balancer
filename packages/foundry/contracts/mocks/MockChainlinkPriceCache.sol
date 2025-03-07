// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { IChainlinkPriceCache } from "../utils/ChainlinkPriceCache.sol";

contract MockChainlinkPriceCache is IChainlinkPriceCache {
    constructor() {}

    function getHistoricalPrice(uint256 lookback) external view returns (uint256[] memory ) {
        uint256[] memory result = new uint256[](lookback);

        for (uint256 i = 0; i < lookback; i++) {
            result[i] = 1e18;
        }

        return result;
    }

    function getHistoricalTimestamp(uint256 lookback) external view returns (uint256[] memory) {
        uint256[] memory result = new uint256[](lookback);

        for (uint256 i = 0; i < lookback; i++) {
            result[i] = block.timestamp;
        }

        return result;
    }

    function getHistoricalPriceRange(uint256 start, uint256 end) external view returns (uint256[] memory) {
        uint256 size = end - start + 1;
        uint256[] memory result = new uint256[](size);

        for (uint256 i = 0; i < size; i++) {
            result[i] = 1e18;
        }
    }

    function getHistoricalTimestampRange(uint256 start, uint256 end) external view returns (uint256[] memory) {
        uint256 size = end - start + 1;
        uint256[] memory result = new uint256[](size);

        for (uint256 i = 0; i < size; i++) {
            result[i] = block.timestamp;
        }

    }

    function update() public {
        return;
    }
}