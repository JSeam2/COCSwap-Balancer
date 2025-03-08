// SPDX-License-Identifier: GPL-3.0-or-later

pragma solidity ^0.8.24;

import "forge-std/Test.sol";

import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import { IRouter } from "@balancer-labs/v3-interfaces/contracts/vault/IRouter.sol";
import { IVault } from "@balancer-labs/v3-interfaces/contracts/vault/IVault.sol";
import {
    LiquidityManagement,
    PoolRoleAccounts,
    SwapKind
} from "@balancer-labs/v3-interfaces/contracts/vault/VaultTypes.sol";

import { CastingHelpers } from "@balancer-labs/v3-solidity-utils/contracts/helpers/CastingHelpers.sol";
import { FixedPoint } from "@balancer-labs/v3-solidity-utils/contracts/math/FixedPoint.sol";

import { BaseVaultTest } from "@balancer-labs/v3-vault/test/foundry/utils/BaseVaultTest.sol";
import { PoolMock } from "@balancer-labs/v3-vault/contracts/test/PoolMock.sol";

import { EZKLDynamicFeeHook } from "../contracts/hooks/EZKLDynamicFeeHook.sol";
import { MockVerifier } from "../contracts/mocks/MockVerifier.sol";
import { IHalo2Verifier } from "../contracts/pools/IHalo2Verifier.sol";
import { MockChainlinkPriceCache } from "../contracts/mocks/MockChainlinkPriceCache.sol";
import { IChainlinkPriceCache } from "../contracts/utils/ChainlinkPriceCache.sol";


contract EZKLDynamicFeeHookTest is BaseVaultTest {
    using CastingHelpers for address[];
    using FixedPoint for uint256;

    uint256 internal daiIdx;
    uint256 internal usdcIdx;

    // Maximum swap fee of 10%
    uint64 public constant MAX_SWAP_FEE_PERCENTAGE = 10e16;

    // Maximum number of swaps executed on each test, while attempting to win the lottery.
    uint256 private constant MAX_ITERATIONS = 100;

    // EZKL hook configuration
    uint256 internal _scalingFactor = 1;
    uint256 internal _lookback = 336;

    IHalo2Verifier public verifier;
    IChainlinkPriceCache public priceCache;

    function setUp() public virtual override {
        BaseVaultTest.setUp();

        (daiIdx, usdcIdx) = getSortedIndexes(address(dai), address(usdc));


    }

    // Sets the hook for the pool, and stores the address in `poolHooksContract`.
    function createHook() internal override returns (address) {
        // lp will be the owner of the hook. Only the owner can set hook fee percentages.
        vm.prank(lp);

        MockVerifier _verifier = new MockVerifier();
        verifier = IHalo2Verifier(address(_verifier));

        MockChainlinkPriceCache _cache = new MockChainlinkPriceCache();
        priceCache = IChainlinkPriceCache(address(_cache));

        EZKLDynamicFeeHook hook = new EZKLDynamicFeeHook(
            IVault(address(vault)),
            address(verifier),
            address(priceCache),
            _scalingFactor,
            _lookback
        );
        return address(hook);
    }

    // Overrides pool creation to set liquidityManagement (disables unbalanced liquidity).
    function _createPool(
        address[] memory tokens,
        string memory label
    ) internal override returns (address newPool, bytes memory poolArgs) {
        string memory name = "EZKL Dynamic Fee Pool";
        string memory symbol = "EZKL-Dynamic-Fee-POOL";

        newPool = address(deployPoolMock(IVault(address(vault)), name, symbol));
        vm.label(newPool, label);

        PoolRoleAccounts memory roleAccounts;
        roleAccounts.poolCreator = lp;

        LiquidityManagement memory liquidityManagement;
        liquidityManagement.disableUnbalancedLiquidity = true;

        vm.expectEmit();
        emit EZKLDynamicFeeHook.EZKLDynamicFeeHookRegistered(poolHooksContract, address(newPool));

        factoryMock.registerPool(
            newPool,
            vault.buildTokenConfig(tokens.asIERC20()),
            roleAccounts,
            poolHooksContract,
            liquidityManagement
        );

        poolArgs = abi.encode(vault, name, symbol);
    }

    function testDynamicFeeHookSwap() public {
        // 1. Set initial dynamic fee and perform a swap
        uint256 initialSwapFeePercentage = 5e16; // 5%
        
        // Set initial dynamic fee through mock verification
        bytes memory dummyProof = new bytes(0);
        uint256 initialDynamicFeeUnscaled = initialSwapFeePercentage * _scalingFactor * 1e18 / 1e18;
        
        // Update the dynamic fee
        EZKLDynamicFeeHook(poolHooksContract).updateFee(dummyProof, initialDynamicFeeUnscaled);
        
        // Verify the fee is set correctly
        assertEq(EZKLDynamicFeeHook(poolHooksContract)._dynamicFee(), initialSwapFeePercentage, "Initial dynamic fee not set correctly");
        
        // Perform initial swap and check balances
        uint256 exactAmountIn = poolInitAmount / 100;
        uint256 expectedAmountOut = exactAmountIn;
        uint256 expectedHookFee = exactAmountIn.mulDown(initialSwapFeePercentage);
        expectedAmountOut -= expectedHookFee;
        
        BaseVaultTest.Balances memory balancesBefore = getBalances(bob);
        
        vm.prank(bob);
        router.swapSingleTokenExactIn(
            pool,
            dai,
            usdc,
            exactAmountIn,
            expectedAmountOut,
            MAX_UINT256,
            false,
            bytes("")
        );
        
        BaseVaultTest.Balances memory balancesAfter = getBalances(bob);
        
        // Check balances after first swap
        assertEq(
            balancesBefore.userTokens[daiIdx] - balancesAfter.userTokens[daiIdx],
            exactAmountIn,
            "Bob's DAI balance is wrong after first swap"
        );
        assertEq(
            balancesAfter.userTokens[usdcIdx] - balancesBefore.userTokens[usdcIdx],
            expectedAmountOut,
            "Bob's USDC balance is wrong after first swap"
        );
        
        // 2. Update the dynamic fee and perform another swap
        uint256 updatedSwapFeePercentage = 2e16; // 2%
        uint256 updatedDynamicFeeUnscaled = updatedSwapFeePercentage * _scalingFactor * 1e18 / 1e18;
        
        // Update the dynamic fee using mock verification
        vm.expectEmit();
        emit EZKLDynamicFeeHook.EZKLDynamicFeeHookUpdated(poolHooksContract, updatedSwapFeePercentage);
        
        EZKLDynamicFeeHook(poolHooksContract).updateFee(dummyProof, updatedDynamicFeeUnscaled);
        
        // Verify the fee is updated correctly
        assertEq(EZKLDynamicFeeHook(poolHooksContract)._dynamicFee(), updatedSwapFeePercentage, "Updated dynamic fee not set correctly");
        
        // 3. Perform another swap with the updated fee and check balances
        balancesBefore = getBalances(bob);
        
        exactAmountIn = poolInitAmount / 100;
        expectedAmountOut = exactAmountIn;
        expectedHookFee = exactAmountIn.mulDown(updatedSwapFeePercentage);
        expectedAmountOut -= expectedHookFee;
        
        vm.prank(bob);
        router.swapSingleTokenExactIn(
            pool,
            dai,
            usdc,
            exactAmountIn,
            expectedAmountOut,
            MAX_UINT256,
            false,
            bytes("")
        );
        
        balancesAfter = getBalances(bob);
        
        // Check balances after second swap
        assertEq(
            balancesBefore.userTokens[daiIdx] - balancesAfter.userTokens[daiIdx],
            exactAmountIn,
            "Bob's DAI balance is wrong after second swap"
        );
        assertEq(
            balancesAfter.userTokens[usdcIdx] - balancesBefore.userTokens[usdcIdx],
            expectedAmountOut,
            "Bob's USDC balance is wrong after second swap"
        );
        
        // Verify vault balances
        assertEq(
            balancesAfter.vaultTokens[daiIdx] - balancesBefore.vaultTokens[daiIdx],
            exactAmountIn,
            "Vault's DAI balance is wrong"
        );
        assertEq(
            balancesBefore.vaultTokens[usdcIdx] - balancesAfter.vaultTokens[usdcIdx],
            expectedAmountOut,
            "Vault's USDC balance is wrong"
        );
        
        // Verify pool balances
        assertEq(
            balancesAfter.poolTokens[daiIdx] - balancesBefore.poolTokens[daiIdx],
            exactAmountIn,
            "Pool's DAI balance is wrong"
        );
        assertEq(
            balancesBefore.poolTokens[usdcIdx] - balancesAfter.poolTokens[usdcIdx],
            expectedAmountOut,
            "Pool's USDC balance is wrong"
        );
    }
}
