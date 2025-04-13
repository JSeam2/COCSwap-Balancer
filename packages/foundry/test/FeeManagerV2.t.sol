// SPDX-License-Identifier: GPL-3.0-or-later

pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import { console } from "forge-std/console.sol";

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

import { FeeManagerV2 } from "../contracts/admin/FeeManagerV2.sol";
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

contract FeeManagerV2Test is Test {
    // Constants for test configuration
    string internal constant DESCRIPTION = "ETH/USD Fee Manager";
    uint256 internal constant LOOKBACK = 337;
    uint256 internal constant SCALING_FACTOR_DIV = 4194304;
    uint256 internal constant SCALING_FACTOR_MUL = 100000000000000;
    uint256 internal constant INITIAL_FEE = 176160768;

    // Contract instances
    FeeManagerV2 public feeManagerV2;
    MockVaultAdmin public mockVaultAdmin;
    MockVerifier public mockVerifier;
    MockChainlinkPriceCache public mockPriceCache;
    address[] public pools;

    // Events from FeeManagerV2 for testing
    event FeeUpdated(uint256 swapFeePercentage);
    event PoolUpdated(address indexed pool, uint256 swapFeePercentage);

    function setUp() public {
        // Deploy mock contracts
        mockVaultAdmin = new MockVaultAdmin();
        mockVerifier = new MockVerifier();
        mockPriceCache = new MockChainlinkPriceCache();
        
        // Deploy FeeManagerV2 with the required parameters
        feeManagerV2 = new FeeManagerV2(
            DESCRIPTION,
            address(mockVaultAdmin),
            address(mockPriceCache),
            address(mockVerifier),
            LOOKBACK,
            SCALING_FACTOR_DIV,
            SCALING_FACTOR_MUL
        );
        
        // Setup test pools
        pools = new address[](2);
        pools[0] = address(0x123);
        pools[1] = address(0x456);
    }

    function testConstructor() public {
        assertEq(feeManagerV2.description(), DESCRIPTION, "Description mismatch");
        assertEq(feeManagerV2.vault(), address(mockVaultAdmin), "Vault address mismatch");
        assertEq(address(feeManagerV2.priceCache()), address(mockPriceCache), "Price cache address mismatch");
        assertEq(address(feeManagerV2.verifier()), address(mockVerifier), "Verifier address mismatch");
        assertEq(feeManagerV2.lookback(), LOOKBACK, "Lookback mismatch");
        assertEq(feeManagerV2.scalingFactorDiv(), SCALING_FACTOR_DIV, "ScalingFactorDiv mismatch");
        assertEq(feeManagerV2.scalingFactorMul(), SCALING_FACTOR_MUL, "ScalingFactorMul mismatch");
    }

    function testUpdateFee() public {
        // Setup mock behavior to return historical prices
        uint256[] memory historical = new uint256[](LOOKBACK);
        for (uint256 i = 0; i < LOOKBACK; i++) {
            historical[i] = 1000 + i; // Some arbitrary price data
        }
        
        // Expect the priceCache.getHistoricalPrice to be called and return our mocked data
        vm.mockCall(
            address(mockPriceCache),
            abi.encodeWithSelector(IChainlinkPriceCache.getHistoricalPrice.selector, LOOKBACK),
            abi.encode(historical)
        );
        
        // Create a proof (empty for mock)
        bytes memory dummyProof = new bytes(0);
        
        // Expect the FeeUpdated event to be emitted
        vm.expectEmit(true, true, true, true);
        emit FeeUpdated(INITIAL_FEE * SCALING_FACTOR_MUL / SCALING_FACTOR_DIV);

        // Update the fee
        bool result = feeManagerV2.updateFee(dummyProof, INITIAL_FEE);
        
        // Verify the result
        assertTrue(result, "updateFee should return true");
        
        // Verify the fee was updated in the FeeManagerV2
        assertEq(feeManagerV2.dynamicFee(), INITIAL_FEE * SCALING_FACTOR_MUL / SCALING_FACTOR_DIV, "Fee not updated correctly");
    }

    function testUpdateFeeVerificationFailed() public {
        // Setup mock behavior for price cache
        uint256[] memory historical = new uint256[](LOOKBACK);
        vm.mockCall(
            address(mockPriceCache),
            abi.encodeWithSelector(IChainlinkPriceCache.getHistoricalPrice.selector, LOOKBACK),
            abi.encode(historical)
        );
        
        // Setup mock behavior for verifier to fail
        vm.mockCall(
            address(mockVerifier),
            abi.encodeWithSelector(IHalo2Verifier.verifyProof.selector),
            abi.encode(false)
        );
        
        bytes memory dummyProof = new bytes(0);
        
        // Should revert with VerificationFailed error
        vm.expectRevert(FeeManagerV2.VerificationFailed.selector);
        feeManagerV2.updateFee(dummyProof, INITIAL_FEE);
    }

    function testPublishFee() public {
        // First update the fee
        uint256[] memory historical = new uint256[](LOOKBACK);
        vm.mockCall(
            address(mockPriceCache),
            abi.encodeWithSelector(IChainlinkPriceCache.getHistoricalPrice.selector, LOOKBACK),
            abi.encode(historical)
        );
        
        vm.mockCall(
            address(mockVerifier),
            abi.encodeWithSelector(IHalo2Verifier.verifyProof.selector),
            abi.encode(true)
        );
        
        // Update the fee first
        feeManagerV2.updateFee(new bytes(0), INITIAL_FEE);
        uint256 expectedFee = INITIAL_FEE * SCALING_FACTOR_MUL / SCALING_FACTOR_DIV;
        
        // Now test publishFee
        // Expect PoolUpdated events for each pool
        for (uint256 i = 0; i < pools.length; i++) {
            vm.expectEmit(true, true, true, true);
            emit PoolUpdated(pools[i], expectedFee);
        }
        
        // Publish the fee to the pools
        bool result = feeManagerV2.publishFee(pools);
        
        // Verify the result
        assertTrue(result, "publishFee should return true");
        
        // Verify the fee was set on the last pool (we can only check the most recent call)
        assertEq(mockVaultAdmin.lastPool(), pools[pools.length - 1], "Last pool address not set correctly on vault");
        assertEq(mockVaultAdmin.lastSwapFeePercentage(), expectedFee, "Fee not set correctly on vault");
    }

    function testUpdateFeeRounding(uint256 fee) public {
        // The model will not produce a large fee so we can avoid fuzzing too large values
        // If the fee is too large it will simply fail to pass the balancer vault checks.
        if (fee > 1e18) {
            return;
        }

        // Setup mock behavior to return historical prices
        uint256[] memory historical = new uint256[](LOOKBACK);

        vm.mockCall(
            address(mockPriceCache),
            abi.encodeWithSelector(IChainlinkPriceCache.getHistoricalPrice.selector, LOOKBACK),
            abi.encode(historical)
        );

        // Mock verifier to return true
        vm.mockCall(
            address(mockVerifier),
            abi.encodeWithSelector(IHalo2Verifier.verifyProof.selector),
            abi.encode(true)
        );

        bytes memory dummyProof = new bytes(0);

        // Test various inputs and round to 5 dp
        uint256 scaledFee = (fee * SCALING_FACTOR_MUL) / SCALING_FACTOR_DIV;
        uint256 expectedRoundedFee = (scaledFee + 5e12) / 1e13 * 1e13;
        console.logUint(expectedRoundedFee);

        feeManagerV2.updateFee(dummyProof, fee);
        assertEq(feeManagerV2.dynamicFee(), expectedRoundedFee, "Fee not rounded correctly to 5dp");
        assertTrue(feeManagerV2.dynamicFee() % 1e13 == 0, "Fee not rounded to 5 decimal places");
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

// contract FeeManagerV2BaseForkTest is Test {
//     // Constants for test configuration
//     string internal constant DESCRIPTION = "ETH/USD Fee Manager";
//     uint256 internal constant LOOKBACK = 337;
//     uint256 internal constant SCALING_FACTOR_DIV = 4194304;
//     uint256 internal constant SCALING_FACTOR_MUL = 100000000000000;
//     uint256 internal constant INITIAL_FEE = 176160768;

//     // Base mainnet addresses
//     address public vault = 0xbA1333333333a1BA1108E8412f11850A5C319bA9;
//     IChainlinkPriceCache public priceCache = IChainlinkPriceCache(0x74F1e0C70B9C40CaEc42Bb098D125197FB4E7213);
//     WeightedPoolFactory public weightedPoolFactory = WeightedPoolFactory(0x5cF4928a3205728bd12830E1840F7DB85c62a4B9);
//     
//     // Contract instances
//     FeeManagerV2 public feeManagerV2;
//     IHalo2Verifier public verifier;
//     address[] public pools;
//     IERC20 public tokenA;
//     IERC20 public tokenB;
//     
//     // Events from FeeManagerV2 for testing
//     event FeeUpdated(uint256 swapFeePercentage);
//     event PoolUpdated(address indexed pool, uint256 swapFeePercentage);

//     function setUp() public {
//         // For this test, we'll fork Base mainnet
//         vm.createSelectFork("base");

//         // Get the real verifier from ETHUSDDynamicFeeVerifier contract
//         verifier = IHalo2Verifier(address(new ETHUSDDynamicFeeVerifier()));
//         
//         // Deploy FeeManagerV2 with the required parameters
//         feeManagerV2 = new FeeManagerV2(
//             DESCRIPTION,
//             vault,
//             address(priceCache),
//             address(verifier),
//             LOOKBACK,
//             SCALING_FACTOR_DIV,
//             SCALING_FACTOR_MUL
//         );

//         // Create tokens at predetermined addresses for consistent ordering
//         vm.startPrank(address(0x1));
//         address tokenAAddr = address(0x1000000000000000000000000000000000000000);
//         address tokenBAddr = address(0x2000000000000000000000000000000000000000);
//         
//         // Deploy tokens at deterministic addresses
//         vm.etch(tokenAAddr, address(new MockToken1("A", "A", 1e18)).code);
//         vm.etch(tokenBAddr, address(new MockToken1("B", "B", 1e18)).code);
//         
//         tokenA = IERC20(tokenAAddr);
//         tokenB = IERC20(tokenBAddr);
//         vm.stopPrank();

//         // Set up token configurations with already sorted tokens (by address)
//         TokenConfig[] memory tokens = new TokenConfig[](2);
//         tokens[0] = TokenConfig({
//             token: tokenA,
//             tokenType: TokenType.STANDARD,
//             rateProvider: IRateProvider(address(0)),
//             paysYieldFees: false
//         });
//         tokens[1] = TokenConfig({
//             token: tokenB,
//             tokenType: TokenType.STANDARD,
//             rateProvider: IRateProvider(address(0)),
//             paysYieldFees: false
//         });

//         uint256[] memory weights = new uint256[](2);
//         weights[0] = 5e17;
//         weights[1] = 5e17;

//         // Set up role accounts
//         PoolRoleAccounts memory roleAccounts = PoolRoleAccounts({
//             pauseManager: address(this),
//             swapFeeManager: address(feeManagerV2),
//             poolCreator: address(0)
//         });

//         // Create a weighted pool with 50-50 weights
//         address poolAddress = weightedPoolFactory.create(
//             "Test Pool",
//             "TEST",
//             tokens,
//             weights,
//             roleAccounts,
//             0.001e18, // 0.1% swap fee
//             address(0), // no pool hooks
//             true, // enable donation
//             false, // don't disable unbalanced liquidity
//             bytes32(0)
//         );
//         
//         // Add the pool to our pool array
//         pools = new address[](1);
//         pools[0] = poolAddress;
//         
//         // Verify pool was created successfully
//         assertTrue(poolAddress != address(0), "Pool creation failed");
//     }
//     
//     function testPoolIsProperlySetup() public {
//         // Check if we have at least one pool
//         assertTrue(pools.length > 0, "No pools created");
//         
//         // Verify the pool has the FeeManagerV2 as its swap fee manager
//         PoolRoleAccounts memory roleAcc = IVaultExplorer(vault).getPoolRoleAccounts(pools[0]);
//         assertEq(roleAcc.swapFeeManager, address(feeManagerV2), "FeeManagerV2 should be the swap fee manager for the pool");
//     }

//     function testGenerateAndUpdateFee() public {
//         // get historical price
//         uint256[] memory historicalPrice = priceCache.getHistoricalPrice(LOOKBACK);

//         // store historical price in an input.json do the formatting later
//         // { "input_data": historicalPrice }
//         string memory price = "";
//         price = vm.serializeUint(price, "input_data", historicalPrice);
//         vm.writeJson(price, "./test/input.json");

//         string[] memory call_archon = new string[](2);
//         call_archon[0] = "python";
//         call_archon[1] = "./test/archon.py";

//         // Get the hex string output from the script
//         bytes memory hexData = vm.ffi(call_archon);

//         // Decode the ABI-encoded bytes into `proof` and `fee`
//         (bytes memory proof, uint256 fee) = abi.decode(hexData, (bytes, uint256));

//         // Update the fee
//         bool updateResult = feeManagerV2.updateFee(proof, fee);
//         assertTrue(updateResult, "updateFee failed");
//         
//         // Publish the fee to the pools
//         bool publishResult = feeManagerV2.publishFee(pools);
//         assertTrue(publishResult, "publishFee failed");
//         
//         // Check the current fee on the pool
//         uint256 currentFee = IVaultExplorer(vault).getPoolSwapFeePercentage(pools[0]);
//         assertEq(currentFee, feeManagerV2.dynamicFee(), "Pool fee doesn't match the dynamic fee");
//     }
// }