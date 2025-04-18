# 🐔 COCSwap on Scaffold Balancer v3

COCSwap example on Balancer v3. [More details on COCSwap found on this blog post.](https://blog.ezkl.xyz/post/cocswap/)

COCSwap is a suite of tools to help LPs make more money by allowing the use of verifiable ZKML strategies in their pools.

![image](./img.jpg)

## 🐔 COCSwap Features
1. Relies on [ezkl](https://github.com/zkonduit/ezkl) for verifiable offchain compute and inference. ZKML allow proprietary models to remain private. People can get the performance of the model by backtesting the ZKML models. Currently, EZKL helps update contract hyperparams in an async way.

2. Dynamic Fee Manager [In Production]

3. Dynamically Weighted Pool (COCSwapPool) [TBD]

## Dynamic Fee Manager

The Dynamic Fee Manager works as follows

- Cache Chainlink Oracle Price Data in the PriceCache contract.

- Pass the Historical Price Data to a EZKL ZK Circuit to generate a witness and proof for the optimal fee.

- Take the proof and optimal fee and pass it to the relevant pool via `FeeManager.setStaticSwapFeePercentage`

### Dynamic Fee Demo
[Youtube Video](https://youtu.be/sycKW0ecO3I?si=EzoCvZOMLKuaMKVm)


### Quickstart

#### Deploying Chainlink Price Cache

1. Run `yarn getRoundIds <chain> <delay seconds> <start timestamp> <end timestamp>` to populate the roundIds required to bootstrap the chainlink price cache.

2. Deploy the chainlink price cache with the roundIds and delay.

#### Deploying FeeManagerV2

1. Deploy a Pool on Balancer

2. In the Swap Fee Manager field set it to the Fee Manager Address listed below.

**Note 1:** `_scalingFactorDiv` is calculated via `2^param scale` via the circuit settings.
`_scalingFactorMul` is needed to correct the values to the appropriate ranges as `FixedPoint.ONE` is `1e18` on Balancer.

**Note 2:** Currently this function is gated via the EZKL team, DM jseam or other EZKL core team members to get a pool included.

4. Run `packages/foundry/contracts/utils/cronjob_v2.py`. You will also need to set the right secrets in `secrets.py`. This script is used to call `ChainlinkPriceCache.update` and to call `FeeManagerV2.updateFee` and `FeeManagerV2.publishFee`.


### Base Contract Deployment

#### Price Cache
- [ETH/USD ChainlinkPriceCache](https://basescan.org/address/0x74F1e0C70B9C40CaEc42Bb098D125197FB4E7213) `0x74F1e0C70B9C40CaEc42Bb098D125197FB4E7213`
- [WBTC/USD ChainlinkPriceCache](https://basescan.org/address/0x69f15CCad7bD060c00E2116946d43F0d2Abd80B7) `0x69f15CCad7bD060c00E2116946d43F0d2Abd80B7`

#### Fee Manager
- [FeeManager](https://basescan.org/address/0x9CFf5B653DF0429933763Bb92345D074Aa9b0622) `0x9CFf5B653DF0429933763Bb92345D074Aa9b0622`

#### Fee Manager V2
This is a permissionless version

- [FeeManagerV2 ETHUSD OLD](https://basescan.org/address/0x3064044c66738fFa362DADAf982e148233Ad7CFa) `0x3064044c66738fFa362DADAf982e148233Ad7CFa`

- [FeeManagerV2 ETHUSD with Rounding to support routers](https://basescan.org/address/0xdbd4864b2d120e83F77B942d3Daf5C791d3e27CD) `0xdbd4864b2d120e83F77B942d3Daf5C791d3e27CD`

#### Dynamic Fee Verifier
- [ETHUSDDynamicFeeVerifier](https://basescan.org/address/0x5A003cAdBCf4db875246fA5785faC427c2D766Db) `0x5A003cAdBCf4db875246fA5785faC427c2D766Db`

- [BTCUSDDynamicFeeVerifier](https://basescan.org/address/0x1315b97065a6E02DA0406f13a9fd5BCE0e7f338a) `0x1315b97065a6E02DA0406f13a9fd5BCE0e7f338a`

#### Gryo E-CLP Pool
- ~~[EZKL Gyro E-CLP Pool ysUSDC-waBasWETH Boosted Pool](https://balancer.fi/pools/base/v3/0xe0AFFb1e0EF262B0e2427515504f4A5e4B288c62) `0xe0AFFb1e0EF262B0e2427515504f4A5e4B288c62`~~

- ~~[EZKL Gyro E-CLP Pool USDC-cbBTC Pool ](https://balancer.fi/pools/base/v3/0x1aE96B5A7Ccb602C51228729E4EF07f8e5Cf0557) `0x1aE96B5A7Ccb602C51228729E4EF07f8e5Cf0557`~~

- [WETH-USDC-EZKL](https://balancer.fi/pools/base/v3/0x81a85b9ec797110f2ee665c119e8f28a2456d6f1) `0x81a85b9ec797110f2ee665c119e8f28a2456d6f1`

- ~~[WBTC-USDC](https://balancer.fi/pools/base/v3/0x1aE96B5A7Ccb602C51228729E4EF07f8e5Cf0557) `0x1aE96B5A7Ccb602C51228729E4EF07f8e5Cf0557`~~

### Sonic Contract Deployment

#### Price Cache
- [ETH/USD ChainlinkPriceCache](https://sonicscan.org/address/0x29d1AA89c6d380FC3F03A82E7A9207465bC9381d) `0x29d1AA89c6d380FC3F03A82E7A9207465bC9381d`

#### Dynamic Fee Verifier
- [ETHUSDDynamicFeeVerifier](https://sonicscan.org/address/0xa1e8a03882C5b5c3a3537C607578dD523f829bb6) `0xa1e8a03882C5b5c3a3537C607578dD523f829bb6`

#### Fee Manager V2
- [FeeManager](https://sonicscan.org/address/0x5c591971F4b3875A6d443b53a6fd7071C6e966fD) `0x5c591971F4b3875A6d443b53a6fd7071C6e966fD`


## COCSwapPools
- TBD

## ✨ Features

- Deploy custom pool and hooks to a local anvil fork
- Explore pool configuration and liquidity details using the frontend
- Instantly execute swaps, joins, and exits using a burner wallet

## 📽️ Video Tutorials

- [Intro to Balancer v3](https://www.youtube.com/watch?v=vjB2cogaO-c)
- [Intro to Scaffold Balancer v3](https://www.youtube.com/watch?v=m6q5M34ZdXw)
- [Create Custom AMMs on Balancer v3](https://www.youtube.com/watch?v=kXynS3jAu0M)
- [Create a Pool Hook](https://www.youtube.com/watch?v=kaz6duliRPA)
- [Create a Custom Router](https://www.youtube.com/watch?v=pO1ChmSFTaY)

## 🪧 Table Of Contents

- [🧑‍💻 Environment Setup](#-environment-setup)
- [👩‍🏫 Learn Core Concepts](#-learn-core-concepts)
- [🕵️ Explore the Examples](#-explore-the-examples)
- [🌊 Create a Custom Pool](#-create-a-custom-pool)
- [🏭 Create a Pool Factory](#-create-a-pool-factory)
- [🪝 Create a Pool Hook](#-create-a-pool-hook)
- [🚢 Deploy the Contracts](#-deploy-the-contracts)
- [🧪 Test the Contracts](#-test-the-contracts)

## 🧑‍💻 Environment Setup

### Requirements

- [Node (>= v18.17)](https://nodejs.org/en/download/)
- Yarn ([v1](https://classic.yarnpkg.com/en/docs/install/) or [v2+](https://yarnpkg.com/getting-started/install))
- [Git](https://git-scm.com/downloads)
- [Foundry](https://book.getfoundry.sh/getting-started/installation) (>= v0.2.0)

### Quickstart

1. Ensure you have the latest version of foundry installed

```
foundryup
```

2. Clone this repo & install dependencies

```bash
git clone https://github.com/balancer/scaffold-balancer-v3.git
cd scaffold-balancer-v3
yarn install
```

3. In a `packages/foundry/.env` file, provide an RPC URL for Ethereum Mainnet

```
MAINNET_RPC_URL=
```

4. Start a local anvil fork of Ethereum mainnet

```bash
yarn fork
```

> By default, this project is setup to fork Ethereum mainnet. However, you can fork another network by following these steps:
>
> 1. Change `targetFork` in `scaffold.config.ts` to `chains.gnosis`
> 2. Modify `PoolHelpers.sol` to use the correct contract addresses
> 3. Run `yarn fork --network gnosis`

5. Deploy the mock tokens, pool factories, pool hooks, and custom pools contracts

```bash
yarn deploy
```

> By default, the anvil account #0 will be the deployer and recieve the mock tokens and BPT from pool initialization

6. Start the nextjs frontend

```bash
yarn start
```

7. Explore the frontend

- Navigate to http://localhost:3000 to see the home page
- Visit the [Pools Page](http://localhost:3000/pools) to search by address or select using the pool buttons
- Visit the [Hooks Page](http://localhost:3000/hooks) to see a growing library of pool hook examples
- Vist the [Debug Page](http://localhost:3000/debug) to see external read and write functions for each contract

8. Run the Foundry tests

```
yarn test
```

### Scaffold ETH 2 Tips

SE-2 offers a variety of configuration options for connecting an account, choosing networks, and deploying contracts

<details><summary><strong>🔥 Burner Wallet</strong></summary>

If you do not have an active wallet extension connected to your web browser, then scaffold eth will automatically connect to a "burner wallet" that is randomly generated on the frontend and saved to the browser's local storage. When using the burner wallet, transactions will be instantly signed, which is convenient for quick iterative development.

To force the use of burner wallet, disable your browsers wallet extensions and refresh the page. Note that the burner wallet comes with 0 ETH to pay for gas so you will need to click the faucet button in top right corner. Also the mock tokens for the pool are minted to your deployer account set in `.env` so you will want to navigate to the "Debug Contracts" page to mint your burner wallet some mock tokens to use with the pool.

![Burner Wallet](https://github.com/Dev-Rel-as-a-Service/scaffold-balancer-v3/assets/73561520/0a1f3456-f22a-46b5-9e05-0ef5cd17cce7)

![Debug Tab Mint](https://github.com/Dev-Rel-as-a-Service/scaffold-balancer-v3/assets/73561520/fbb53772-8f6d-454d-a153-0e7a2925ef9f)

</details>

<details><summary><strong>👛 Browser Extension Wallet</strong></summary>
    
- To use your preferred browser extension wallet, ensure that the account you are using matches the PK you previously provided in the `foundry/.env` file
- You may need to add a local development network with rpc url `http://127.0.0.1:8545/` and chain id `31337`. Also, you may need to reset the nonce data for your wallet exension if it gets out of sync.

</details>

<details><summary><strong>🐛 Debug Contracts Page </strong></summary>

The [Debug Contracts Page](http://localhost:3000/debug) can be useful for viewing and interacting with all of the externally avaiable read and write functions of a contract. The page will automatically hot reload with contracts that are deployed via the `01_DeployConstantSumFactory.s.sol` script. We use this handy setup to mint `mockERC20` tokens to any connected wallet

</details>

<details><summary><strong>🌐 Changing The Frontend Network Connection</strong></summary>

- The network the frontend points at is set via `targetNetworks` in the `scaffold.config.ts` file using `chains` from viem.
- By default, the frontend runs on a local node at `http://127.0.0.1:8545`

```typescript
const scaffoldConfig = {
  targetNetworks: [chains.foundry],
```

</details>

<details><summary><strong>🍴 Changing The Forked Network</strong></summary>

- By default, the `yarn fork` command points at sepolia, but any of the network aliases from the `[rpc_endpoints]` of `foundry.toml` can be used to modify the `"fork"` alias in the `packages/foundry/package.json` file

```json
	"fork": "anvil --fork-url ${0:-sepolia} --chain-id 31337 --config-out localhost.json",
```

- To point the frontend at a different forked network, change the `targetFork` in `scaffold.config.ts`

```typescript
const scaffoldConfig = {
  // The networks the frontend can connect to
  targetNetworks: [chains.foundry],

  // If using chains.foundry as your targetNetwork, you must specify a network to fork
  targetFork: chains.sepolia,
```

</details>

## 👩‍🏫 Learn Core Concepts

- [Contract Architecture](https://docs-v3.balancer.fi/concepts/core-concepts/architecture.html)
- [Balancer Pool Tokens](https://docs-v3.balancer.fi/concepts/core-concepts/balancer-pool-tokens.html)
- [Balancer Pool Types](https://docs-v3.balancer.fi/concepts/explore-available-balancer-pools/)
- [Building Custom AMMs](https://docs.balancer.fi/build/build-an-amm/create-custom-amm-with-novel-invariant.html)
- [Extend an Existing Pool Type Using Hooks](https://docs.balancer.fi/build/build-a-hook/extend-existing-pool-type.html)
- [Exploring Hooks and Custom Routers](https://pitchandrolls.com/2024/08/30/unlocking-the-power-of-balancer-v3-exploring-hooks-and-custom-routers/)
- [Hook Development Tips](https://medium.com/@johngrant/unlocking-the-power-of-balancer-v3-hook-development-made-simple-831391a68296)

![v3-components](https://github.com/user-attachments/assets/ccda9323-790f-4276-b092-c867fd80bf9e)

## 🕵️ Explore the Examples

Each of the following examples have turn key deploy scripts that can be found in the [foundry/script/](https://github.com/balancer/scaffold-balancer-v3/tree/main/packages/foundry/script) directory

### Constant Sum Pool with Dynamic Swap Fee Hook

The swap fee percentage is altered by the hook contract before the pool calculates the amount for the swap

![dynamic-fee-hook](https://github.com/user-attachments/assets/5ba69ea3-6894-4eeb-befa-ed87cfeb6b13)

### Constant Product Pool with Lottery Hook

An after swap hook that uses a random number to determine if user should pay into the lottery or receive the prize

![after-swap-hook](https://github.com/user-attachments/assets/594ce1ac-2edc-4d16-9631-14feb2d085f8)

### Weighted Pool with Exit Fee Hook

An after remove liquidity hook adjusts the amounts before the vault transfers tokens to the user

![after-remove-liquidity-hook](https://github.com/user-attachments/assets/2e8f4a5c-f168-4021-b316-28a79472c8d1)

## 🌊 Create a Custom Pool

Custom AMMs built on Balancer inherit the security of the Balancer vault, and benefit from a streamlined development process.

### Learn the Basics

- [Read the docs](https://docs.balancer.fi/build/build-an-amm/create-custom-amm-with-novel-invariant.html)
- [Watch a video](https://www.youtube.com/watch?v=kXynS3jAu0M)

### Recall the Key Requirements

- Must inherit from `IBasePool` and `BalancerPoolToken`
- Must implement `onSwap`, `computeInvariant`, and `computeBalance`
- Must implement `getMaximumSwapFeePercentage` and `getMinimumSwapFeePercentage`

## 🏭 Create a Pool Factory

While not mandatory, we do recommend using a factory contract for the deployment and registration of custom pools.

### Learn the Basics

- [Read the docs](https://docs.balancer.fi/build/build-an-amm/deploy-custom-amm-using-factory.html)
- [Watch a video](https://www.youtube.com/watch?v=kXynS3jAu0M)

### Recall the Key Requirements

- A pool factory contract must inherit from [BasePoolFactory](https://github.com/balancer/balancer-v3-monorepo/blob/main/pkg/vault/contracts/factories/BasePoolFactory.sol)
- Use the internal `_create` function to deploy a new pool
- Use the internal `_registerPoolWithVault` fuction to register a pool immediately after creation

## 🪝 Create a Pool Hook

Hooks introduce a new framework for extending the functionality of existing pool types at key points throughout pool operation lifecycles.

### Learn the Basics

- [Read the docs](https://docs.balancer.fi/build/build-a-hook/extend-existing-pool-type.html)
- [Watch a video](https://www.youtube.com/watch?v=kaz6duliRPA)

### Recall the Key Requirements

- A hooks contract must inherit from [BasePoolHooks.sol](https://github.com/balancer/balancer-v3-monorepo/blob/main/pkg/vault/contracts/BaseHooks.sol)
- A hooks contract should also inherit from [VaultGuard.sol](https://github.com/balancer/balancer-v3-monorepo/blob/main/pkg/vault/contracts/VaultGuard.sol)
- Must implement `onRegister` to determine if a pool is allowed to use the hook contract
- Must implement `getHookFlags` to define which hooks are supported
- The `onlyVault` modifier should be applied to all hooks functions (i.e. `onRegister`, `onBeforeSwap`, `onAfterSwap` ect.)

## 🚢 Deploy the Contracts

The deploy scripts are located in the [foundry/script/](https://github.com/balancer/scaffold-balancer-v3/tree/main/packages/foundry/script) directory. To better understand the lifecycle of deploying a pool that uses a hooks contract, see the diagram below

![pool-deploy-scripts](https://github.com/user-attachments/assets/bb906080-8f42-46c0-af90-ba01ba1754fc)

### Understand Scaffold

For all the scaffold integrations to work properly, each deploy script must be imported into `Deploy.s.sol` and inherited by the `DeployScript` contract in `Deploy.s.sol`

### Broadcast Transactions

Run the following command to deploy the contracts to a local anvil fork

```bash
yarn deploy
```

Add a `--network` flag to deploy the contracts to a live network

```bash
yarn deploy --network sepolia
```

## 🧪 Test the Contracts

The [balancer-v3-monorepo](https://github.com/balancer/balancer-v3-monorepo) provides testing utility contracts like [BasePoolTest](https://github.com/balancer/balancer-v3-monorepo/blob/main/pkg/vault/test/foundry/utils/BasePoolTest.sol) and [BaseVaultTest](https://github.com/balancer/balancer-v3-monorepo/blob/main/pkg/vault/test/foundry/utils/BaseVaultTest.sol). Therefore, the best way to begin writing tests for custom factories, pools, and hooks contracts is to leverage the examples established by the source code.

### Factories

The example `ConstantSumFactoryTest` mirrors the [WeightedPool8020FactoryTest
](https://github.com/balancer/balancer-v3-monorepo/blob/main/pkg/pool-weighted/test/foundry/WeightedPool8020Factory.t.sol)

```
yarn test --match-contract ConstantSumFactoryTest
```

### Pools

The example `ConstantSumPoolTest` mirrors the [WeightedPoolTest](https://github.com/balancer/balancer-v3-monorepo/blob/main/pkg/pool-weighted/test/foundry/WeightedPool.t.sol)

```
yarn test --match-contract ConstantSumPoolTest
```

### Hooks

The example `VeBALFeeDiscountHookExampleTest` mirrors the [VeBALFeeDiscountHookExampleTest](https://github.com/balancer/balancer-v3-monorepo/blob/main/pkg/pool-hooks/test/foundry/VeBALFeeDiscountHookExample.t.sol)

```
yarn test --match-contract VeBALFeeDiscountHookExampleTest
```
