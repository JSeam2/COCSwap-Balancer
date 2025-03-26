// SPDX-License-Identifier: GPL-3.0-or-later

pragma solidity ^0.8.24;

import "forge-std/Test.sol";

import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";

import { IVault } from "@balancer-labs/v3-interfaces/contracts/vault/IVault.sol";
import { IVaultAdmin } from "@balancer-labs/v3-interfaces/contracts/vault/IVaultAdmin.sol";
import { IVaultExplorer } from "@balancer-labs/v3-interfaces/contracts/vault/IVaultExplorer.sol";
import { IBasePoolFactory } from "@balancer-labs/v3-interfaces/contracts/vault/IBasePoolFactory.sol";
import { IProtocolFeeController } from "@balancer-labs/v3-interfaces/contracts/vault/IProtocolFeeController.sol";
import { WeightedPoolFactory } from "@balancer-labs/v3-pool-weighted/contracts/WeightedPoolFactory.sol";
import { IRateProvider } from "@balancer-labs/v3-interfaces/contracts/solidity-utils/helpers/IRateProvider.sol";
import {
    TokenConfig,
    PoolRoleAccounts,
    LiquidityManagement,
    TokenType
} from "@balancer-labs/v3-interfaces/contracts/vault/VaultTypes.sol";

import { BaseVaultTest } from "@balancer-labs/v3-vault/test/foundry/utils/BaseVaultTest.sol";
import { PoolMock } from "@balancer-labs/v3-vault/contracts/test/PoolMock.sol";

import { FeeManager } from "../contracts/admin/FeeManager.sol";
import { MockVerifier } from "../contracts/mocks/MockVerifier.sol";
import { MockToken1 } from "../contracts/mocks/MockToken1.sol";
import { IHalo2Verifier } from "../contracts/utils/IHalo2Verifier.sol";
import { ETHUSDDynamicFeeVerifier } from "../contracts/verifiers/ETHUSDDynamicFeeVerifier.sol";
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
    uint256 internal constant LOOKBACK = 337;
    uint256 internal constant SCALING_FACTOR_DIV = 4194304;
    uint256 internal constant SCALING_FACTOR_MUL = 100000000000000;
    uint256 internal constant INITIAL_FEE = 176160768;

    // Contract instances
    FeeManager public feeManager;
    MockVaultAdmin public mockVaultAdmin;
    MockVerifier public mockVerifier;
    MockChainlinkPriceCache public mockPriceCache;
    address public poolAddress;

    // Events from FeeManager for testing
    event NewFeeConfig(address indexed pool, address verifier, address priceCache, uint256 lookback, uint256 scalingFactorDiv, uint256 scalingFactorMul, uint256 initialFee);
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
            SCALING_FACTOR_DIV,
            SCALING_FACTOR_MUL,
            INITIAL_FEE
        );

        // Register a fee configuration for the pool
        feeManager.registerFeeConfig(
            poolAddress,
            address(mockVerifier),
            address(mockPriceCache),
            LOOKBACK,
            SCALING_FACTOR_DIV,
            SCALING_FACTOR_MUL,
            INITIAL_FEE
        );

        // Verify the fee configuration was stored correctly
        (
            IHalo2Verifier verifier,
            IChainlinkPriceCache priceCache,
            uint256 lookback,
            uint256 scalingFactorDiv,
            uint256 scalingFactorMul,
            uint256 dynamicFee
        ) = feeManager.feeConfig(poolAddress);
        
        assertEq(address(verifier), address(mockVerifier), "Verifier address mismatch");
        assertEq(address(priceCache), address(mockPriceCache), "Price cache address mismatch");
        assertEq(lookback, LOOKBACK, "Lookback mismatch");
        assertEq(scalingFactorDiv, SCALING_FACTOR_DIV, "Scaling factor mismatch");
        assertEq(scalingFactorMul, SCALING_FACTOR_MUL, "Scaling factor mismatch");
        assertEq(dynamicFee, INITIAL_FEE, "Initial fee mismatch");
    }

    function testRegisterFeeConfigNotOwner() public {
        // Try to register a fee configuration from a non-owner account
        address nonOwner = address(0x456);
        vm.prank(nonOwner);
        
        vm.expectRevert();
        feeManager.registerFeeConfig(
            poolAddress,
            address(mockVerifier),
            address(mockPriceCache),
            LOOKBACK,
            SCALING_FACTOR_DIV,
            SCALING_FACTOR_MUL,
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
            SCALING_FACTOR_DIV,
            SCALING_FACTOR_MUL,
            INITIAL_FEE
        );

        // Create a proof (empty for mock)
        bytes memory dummyProof = new bytes(0);
        
        // Expect the FeeUpdated event to be emitted
        vm.expectEmit(true, true, true, true);
        emit FeeUpdated(poolAddress, INITIAL_FEE * SCALING_FACTOR_MUL / SCALING_FACTOR_DIV);

        // Update the fee
        feeManager.setStaticSwapFeePercentage(
            poolAddress,
            dummyProof,
            INITIAL_FEE
        );

        // Verify the fee was updated in the FeeManager
        (
            IHalo2Verifier verifier,
            IChainlinkPriceCache priceCache,
            uint256 lookback,
            uint256 scalingFactorDiv,
            uint256 scalingFactorMul,
            uint256 dynamicFee
        ) = feeManager.feeConfig(poolAddress);
        assertEq(dynamicFee, INITIAL_FEE * SCALING_FACTOR_MUL / SCALING_FACTOR_DIV, "Fee not updated in FeeManager");

        // Verify the fee was set on the vault admin
        assertEq(mockVaultAdmin.lastPool(), poolAddress, "Pool address not set correctly on vault");
        assertEq(mockVaultAdmin.lastSwapFeePercentage(), INITIAL_FEE * SCALING_FACTOR_MUL / SCALING_FACTOR_DIV, "Fee not set correctly on vault");
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
            INITIAL_FEE
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
            SCALING_FACTOR_DIV,
            SCALING_FACTOR_MUL,
            INITIAL_FEE
        );

        bytes memory dummyProof = new bytes(0);
        
        // Should revert with VerificationFailed error
        vm.expectRevert(FeeManager.VerificationFailed.selector);
        feeManager.setStaticSwapFeePercentage(
            poolAddress,
            dummyProof,
            INITIAL_FEE
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

contract FeeManagerBaseForkTest is Test {
    // Constants for test configuration
    uint256 internal constant LOOKBACK = 337;
    uint256 internal constant SCALING_FACTOR_DIV = 4194304;
    uint256 internal constant SCALING_FACTOR_MUL = 100000000000000;
    uint256 internal constant INITIAL_FEE = 176160768;

    // Base mainnet addresses
    address public vault = 0xbA1333333333a1BA1108E8412f11850A5C319bA9;
    IChainlinkPriceCache public priceCache = IChainlinkPriceCache(0x74F1e0C70B9C40CaEc42Bb098D125197FB4E7213);
    WeightedPoolFactory public weightedPoolFactory = WeightedPoolFactory(0x5cF4928a3205728bd12830E1840F7DB85c62a4B9);
    
    // Contract instances
    FeeManager public feeManager;
    IHalo2Verifier public verifier;
    address public poolAddress;
    string poolAddressString;
    IERC20 public tokenA;
    IERC20 public tokenB;
    
    // Events from FeeManager for testing
    event NewFeeConfig(address indexed pool, address verifier, address priceCache, uint256 lookback, uint256 scalingFactorDiv, uint256 scalingFactorMul, uint256 initialFee);
    event FeeUpdated(address indexed pool, uint256 swapFeePercentage);

    function setUp() public {
        // For this test, we'll fork Base mainnet
        vm.createSelectFork("base");

        // Get the real verifier from ETHUSDDynamicFeeVerifier contract
        verifier = IHalo2Verifier(address(new ETHUSDDynamicFeeVerifier()));
        
        // Deploy FeeManager with the real Base vault address
        feeManager = new FeeManager(vault);

        // Create tokens at predetermined addresses for consistent ordering
        vm.startPrank(address(0x1));
        address tokenAAddr = address(0x1000000000000000000000000000000000000000);
        address tokenBAddr = address(0x2000000000000000000000000000000000000000);
        
        // Deploy tokens at deterministic addresses
        vm.etch(tokenAAddr, address(new MockToken1("A", "A", 1e18)).code);
        vm.etch(tokenBAddr, address(new MockToken1("B", "B", 1e18)).code);
        
        tokenA = IERC20(tokenAAddr);
        tokenB = IERC20(tokenBAddr);
        vm.stopPrank();

        // Set up token configurations with already sorted tokens (by address)
        TokenConfig[] memory tokens = new TokenConfig[](2);
        tokens[0] = TokenConfig({
            token: tokenA,
            tokenType: TokenType.STANDARD,
            rateProvider: IRateProvider(address(0)),
            paysYieldFees: false
        });
        tokens[1] = TokenConfig({
            token: tokenB,
            tokenType: TokenType.STANDARD,
            rateProvider: IRateProvider(address(0)),
            paysYieldFees: false
        });

        uint256[] memory weights = new uint256[](2);
        weights[0] = 5e17;
        weights[1] = 5e17;

        // Set up role accounts
        PoolRoleAccounts memory roleAccounts = PoolRoleAccounts({
            pauseManager: address(this),
            swapFeeManager: address(feeManager),
            poolCreator: address(0)
        });

        // Create a weighted pool with 50-50 weights
        poolAddress = weightedPoolFactory.create(
            "Test Pool",
            "TEST",
            tokens,
            weights,
            roleAccounts,
            0.001e18, // 0.1% swap fee
            address(0), // no pool hooks
            true, // enable donation
            false, // don't disable unbalanced liquidity
            bytes32(0)
        );
        
        // Verify pool was created successfully
        assertTrue(poolAddress != address(0), "Pool creation failed");

        // Register the fee configuration for the pool
        feeManager.registerFeeConfig(
            poolAddress,
            address(verifier),
            address(priceCache),
            LOOKBACK,
            SCALING_FACTOR_DIV,
            SCALING_FACTOR_MUL,
            INITIAL_FEE
        );

    }
    
    function testPoolIsProperlySetup() public {
        // Check if the pool address is valid
        assertTrue(poolAddress != address(0), "Pool address should not be zero");
        
        // Verify the pool has the FeeManager as its swap fee manager
        PoolRoleAccounts memory roleAcc = IVaultExplorer(vault).getPoolRoleAccounts(poolAddress);
        assertEq(roleAcc.swapFeeManager, address(feeManager), "FeeManager should be the swap fee manager for the pool");
        
        // Verify the fee configuration was registered correctly
        (
            IHalo2Verifier configVerifier,
            IChainlinkPriceCache configPriceCache,
            uint256 configLookback,
            uint256 configScalingFactorDiv,
            uint256 configScalingFactorMul,
            uint256 configDynamicFee
        ) = feeManager.feeConfig(poolAddress);
        
        assertEq(address(configVerifier), address(verifier), "Verifier address mismatch");
        assertEq(address(configPriceCache), address(priceCache), "Price cache address mismatch");
        assertEq(configLookback, LOOKBACK, "Lookback mismatch");
        assertEq(configScalingFactorDiv, SCALING_FACTOR_DIV, "ScalingFactorDiv mismatch");
        assertEq(configScalingFactorMul, SCALING_FACTOR_MUL, "ScalingFactorMul mismatch");
        assertEq(configDynamicFee, INITIAL_FEE, "Initial fee mismatch");
    }

    function testSetStaticFee() public {
        // get historical price
        uint256[] memory historicalPrice = priceCache.getHistoricalPrice(LOOKBACK);

        // store historical price in an input.json do the formatting later
        // { "input_data": historicalPrice }
        string memory price = "";
        price = vm.serializeUint(price, "input_data", historicalPrice);
        vm.writeJson(price, "./test/input.json");

        string[] memory call_archon = new string[](2);
        call_archon[0] = "python";
        call_archon[1] = "./test/archon.py";

        // Get the hex string output from the script
        bytes memory hexData = vm.ffi(call_archon);

        // Decode the ABI-encoded bytes into `proof` and `fee`
        (bytes memory proof, uint256 fee) = abi.decode(hexData, (bytes, uint256));

        bool res = feeManager.setStaticSwapFeePercentage(
            poolAddress,
            proof,
            fee
        );

        assertTrue(res, "setStaticSwapFeePercentage failed");
    }

}