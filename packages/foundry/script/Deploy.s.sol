//SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { ScaffoldHelpers } from "./ScaffoldHelpers.sol";
import { IERC20 } from "@openzeppelin/contracts/interfaces/IERC20.sol";
import { DeployMockTokens } from "./00_DeployMockTokens.s.sol";
import { DeployConstantSumPool } from "./01_DeployConstantSumPool.s.sol";
import { DeployConstantProductPool } from "./02_DeployConstantProductPool.s.sol";
import { DeployWeightedPool8020 } from "./03_DeployWeightedPool8020.s.sol";
import { DeployCOCSwapPool } from "./04_DeployCOCSwapPool.s.sol";

/**
 * @title Deploy Script
 * @dev Run all deploy scripts here to allow for scaffold integrations with nextjs front end
 * @dev Run this script with `yarn deploy`
 */
contract DeployScript is
    ScaffoldHelpers,
    DeployMockTokens,
    DeployConstantSumPool,
    DeployConstantProductPool,
    DeployWeightedPool8020,
    DeployCOCSwapPool
{
    function run() external scaffoldExport {
        // Deploy mock tokens to use for the pools and hooks
        (
            address mockToken0,
            address mockToken1,
            address mockToken2,
            address mockToken3,
            address mockToken4,
            address mockToken5,
            address mockVeBAL,
        ) = deployMockTokens();

        // Deploy, register, and initialize a constant sum pool with a swap fee discount hook
        deployConstantSumPool(mockToken0, mockToken1, mockVeBAL);

        // Deploy, register, and initialize a constant product pool with a lottery hook
        deployConstantProductPool(mockToken0, mockToken1);

        // Deploy, register, and initialize a weighted pool with an exit fee hook
        deployWeightedPool8020(mockToken0, mockToken1);

        // Deploy, register, and initialize a COCSwap pool
        address[] tokens = new address[4]();
        tokens[0] = mockToken0;
        tokens[1] = mockToken1;
        tokens[2] = mockToken2;
        tokens[3] = mockToken3;

        uint256[] weights = new uint256[4]();
        weights[0] = 25e16;
        weights[1] = 25e16;
        weights[2] = 25e16;
        weights[3] = 25e16;

        deployCOCSwapPool(tokens, weights);
    }

    modifier scaffoldExport() {
        _;
        exportDeployments();
    }
}
