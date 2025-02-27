//SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { IVault } from "@balancer-labs/v3-interfaces/contracts/vault/IVault.sol";
import { IERC20 } from "@openzeppelin/contracts/interfaces/IERC20.sol";

import { ScaffoldHelpers, console } from "./ScaffoldHelpers.sol";
import { MockToken1 } from "../contracts/mocks/MockToken1.sol";
import { MockToken2 } from "../contracts/mocks/MockToken2.sol";
import { MockVeBAL } from "../contracts/mocks/MockVeBAL.sol";

/**
 * @title Deploy Mock Tokens
 * @notice Deploys mock tokens for use with pools and hooks
 */
contract DeployMockTokens is ScaffoldHelpers {
    function deployMockTokens() internal returns (
        address mockToken0,
        address mockToken1,
        address mockToken2,
        address mockToken3,
        address mockToken4,
        address mockToken5,
        address mockVeBAL
    ) {
        // Start creating the transactions
        uint256 deployerPrivateKey = getDeployerPrivateKey();
        vm.startBroadcast(deployerPrivateKey);

        // Used to register & initialize pool contracts
        mockToken0 = address(new MockToken1("Pepe the Frog", "PEPE", 1000e18));
        mockToken1 = address(new MockToken2("Department of Government Efficiency", "DOGE", 1000e18));
        mockToken2 = address(new MockToken1("COCSwap", "KOKU", 1000e18));
        mockToken3 = address(new MockToken1("Cumrocket", "CUM", 1000e18));
        mockToken4 = address(new MockToken1("Luna", "LUNA", 1000e18));
        mockToken5 = address(new MockToken1("USDT", "USDT", 1000e6));

        console.log("MockToken0 deployed at: %s", mockToken0);
        console.log("MockToken1 deployed at: %s", mockToken1);
        console.log("MockToken2 deployed at: %s", mockToken2);
        console.log("MockToken3 deployed at: %s", mockToken3);
        console.log("MockToken4 deployed at: %s", mockToken4);
        console.log("MockToken5 deployed at: %s", mockToken5);

        // Used for the VeBALFeeDiscountHook
        mockVeBAL = address(new MockVeBAL("Vote-escrow BAL", "veBAL", 1000e18));
        console.log("Mock Vote-escrow BAL deployed at: %s", mockVeBAL);

        vm.stopBroadcast();
    }
}
