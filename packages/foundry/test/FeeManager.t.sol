// SPDX-License-Identifier: GPL-3.0-or-later

pragma solidity ^0.8.24;

import "forge-std/Test.sol";

import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";

import { IVault } from "@balancer-labs/v3-interfaces/contracts/vault/IVault.sol";
import { IVaultAdmin } from "@balancer-labs/v3-interfaces/contracts/vault/IVaultAdmin.sol";
import { IBasePoolFactory } from "@balancer-labs/v3-interfaces/contracts/vault/IBasePoolFactory.sol";
import { IProtocolFeeController } from "@balancer-labs/v3-interfaces/contracts/vault/IProtocolFeeController.sol";

import { BaseVaultTest } from "@balancer-labs/v3-vault/test/foundry/utils/BaseVaultTest.sol";
import { PoolMock } from "@balancer-labs/v3-vault/contracts/test/PoolMock.sol";

import { FeeManager } from "../contracts/admin/FeeManager.sol";
import { MockVerifier } from "../contracts/mocks/MockVerifier.sol";
import { IHalo2Verifier } from "../contracts/pools/IHalo2Verifier.sol";
import { MockChainlinkPriceCache } from "../contracts/mocks/MockChainlinkPriceCache.sol";
import { IChainlinkPriceCache } from "../contracts/utils/ChainlinkPriceCache.sol";

contract MockVaultAdmin {
    uint256 public lastSwapFeePercentage;
    address public lastPool;

    function setStaticSwapFeePercentage(address pool, uint256 swapFeePercentage) external {
        lastPool = pool;
        lastSwapFeePercentage = swapFeePercentage;
    }
}

contract FeeManagerTest is Test {
    // Constants for test configuration
    uint256 internal constant LOOKBACK = 336;
    uint256 internal constant SCALING_FACTOR = 1e6;
    uint256 internal constant INITIAL_FEE = 5e16; // 5%
    uint256 internal constant UPDATED_FEE = 2e16; // 2%

    // Contract instances
    FeeManager public feeManager;
    MockVaultAdmin public mockVaultAdmin;
    MockVerifier public mockVerifier;
    MockChainlinkPriceCache public mockPriceCache;
    address public poolAddress;

    // Events from FeeManager for testing
    event NewFeeConfig(address indexed pool, address verifier, address priceCache, uint256 lookback, uint256 scalingFactor, uint256 initialFee);
    event FeeUpdated(address indexed pool, uint256 swapFeePercentage);

    function setUp() public {
        // Deploy mock contracts
        mockVaultAdmin = new MockVaultAdmin();
        mockVerifier = new MockVerifier();
        mockPriceCache = new MockChainlinkPriceCache();
        
        // Deploy FeeManager
        feeManager = new FeeManager(address(mockVaultAdmin));
        
        // Set up a fake pool address for testing
        poolAddress = address(0x123);
    }

    function testRegisterFeeConfig() public {
        // Expect the NewFeeConfig event to be emitted
        vm.expectEmit(true, true, true, true);
        emit NewFeeConfig(
            poolAddress, 
            address(mockVerifier), 
            address(mockPriceCache), 
            LOOKBACK, 
            SCALING_FACTOR, 
            INITIAL_FEE
        );

        // Register a fee configuration for the pool
        feeManager.registerFeeConfig(
            poolAddress,
            address(mockVerifier),
            address(mockPriceCache),
            LOOKBACK,
            SCALING_FACTOR,
            INITIAL_FEE
        );

        // Verify the fee configuration was stored correctly
        (
            IHalo2Verifier verifier,
            IChainlinkPriceCache priceCache,
            uint256 lookback,
            uint256 scalingFactor,
            uint256 dynamicFee
        ) = feeManager.feeConfig(poolAddress);
        
        assertEq(address(verifier), address(mockVerifier), "Verifier address mismatch");
        assertEq(address(priceCache), address(mockPriceCache), "Price cache address mismatch");
        assertEq(lookback, LOOKBACK, "Lookback mismatch");
        assertEq(scalingFactor, SCALING_FACTOR, "Scaling factor mismatch");
        assertEq(dynamicFee, INITIAL_FEE, "Initial fee mismatch");
    }

    function testRegisterFeeConfigNotOwner() public {
        // Try to register a fee configuration from a non-owner account
        address nonOwner = address(0x456);
        vm.prank(nonOwner);
        
        // Should revert with an Unauthorized error (from Ownable)
        vm.expectRevert(abi.encodeWithSignature("OwnableUnauthorizedAccount(address)", nonOwner));
        feeManager.registerFeeConfig(
            poolAddress,
            address(mockVerifier),
            address(mockPriceCache),
            LOOKBACK,
            SCALING_FACTOR,
            INITIAL_FEE
        );
    }

    function testSetStaticSwapFeePercentage() public {
        // First register the fee configuration
        feeManager.registerFeeConfig(
            poolAddress,
            address(mockVerifier),
            address(mockPriceCache),
            LOOKBACK,
            SCALING_FACTOR,
            INITIAL_FEE
        );

        // Create a proof (empty for mock)
        bytes memory dummyProof = new bytes(0);
        
        // Expect the FeeUpdated event to be emitted
        vm.expectEmit(true, true, true, true);
        emit FeeUpdated(poolAddress, UPDATED_FEE * SCALING_FACTOR);

        // Update the fee
        feeManager.setStaticSwapFeePercentage(
            poolAddress,
            dummyProof,
            UPDATED_FEE
        );

        // Verify the fee was updated in the FeeManager
        (
            IHalo2Verifier verifier,
            IChainlinkPriceCache priceCache,
            uint256 lookback,
            uint256 scalingFactor,
            uint256 dynamicFee
        ) = feeManager.feeConfig(poolAddress);
        assertEq(dynamicFee, UPDATED_FEE, "Fee not updated in FeeManager");

        // Verify the fee was set on the vault admin
        assertEq(mockVaultAdmin.lastPool(), poolAddress, "Pool address not set correctly on vault");
        assertEq(mockVaultAdmin.lastSwapFeePercentage(), UPDATED_FEE * SCALING_FACTOR, "Fee not set correctly on vault");
    }

    function testSetStaticSwapFeePercentageInvalidPool() public {
        // Attempt to update fee for an unregistered pool
        address unregisteredPool = address(0x789);
        bytes memory dummyProof = new bytes(0);

        // Should revert with InvalidPool error
        vm.expectRevert(FeeManager.InvalidPool.selector);
        feeManager.setStaticSwapFeePercentage(
            unregisteredPool,
            dummyProof,
            UPDATED_FEE
        );
    }

    function testVerificationFailedScenario() public {
        // Deploy a custom verifier that returns false
        MockVerifierFailing failingVerifier = new MockVerifierFailing();
        
        // Register with the failing verifier
        feeManager.registerFeeConfig(
            poolAddress,
            address(failingVerifier),
            address(mockPriceCache),
            LOOKBACK,
            SCALING_FACTOR,
            INITIAL_FEE
        );

        bytes memory dummyProof = new bytes(0);
        
        // Should revert with VerificationFailed error
        vm.expectRevert(FeeManager.VerificationFailed.selector);
        feeManager.setStaticSwapFeePercentage(
            poolAddress,
            dummyProof,
            UPDATED_FEE
        );
    }
}

// Mock verifier that always returns false for testing verification failure
contract MockVerifierFailing is IHalo2Verifier {
    function verifyProof(
        bytes calldata,
        uint256[] calldata
    ) external pure returns (bool) {
        return false;
    }
}