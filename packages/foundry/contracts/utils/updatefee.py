"""
Utility contract to test the update fee logic. This is mostly meant for testing purposes.
Use cronjob.py for production.
"""
import time
import json
import logging
from web3 import Web3
from web3.exceptions import ContractLogicError
import secrets
import traceback
import requests
import uuid

DEBUG = False

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("hook_updater.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("HookUpdater")

price_cache_abi = """[{"inputs":[{"internalType":"string","name":"_description","type":"string"},{"internalType":"address","name":"_oracle","type":"address"},{"internalType":"uint256","name":"_delay","type":"uint256"},{"internalType":"uint256[]","name":"_roundIds","type":"uint256[]"}],"stateMutability":"nonpayable","type":"constructor"},{"inputs":[],"name":"InvalidRange","type":"error"},{"inputs":[],"name":"NoDataAvailable","type":"error"},{"inputs":[],"name":"WaitForDelay","type":"error"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"uint256","name":"timestamp","type":"uint256"},{"indexed":false,"internalType":"uint256","name":"price","type":"uint256"}],"name":"Updated","type":"event"},{"inputs":[],"name":"delay","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"description","outputs":[{"internalType":"string","name":"","type":"string"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"uint256","name":"lookback","type":"uint256"}],"name":"getHistoricalPrice","outputs":[{"internalType":"uint256[]","name":"","type":"uint256[]"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"uint256","name":"start","type":"uint256"},{"internalType":"uint256","name":"end","type":"uint256"}],"name":"getHistoricalPriceRange","outputs":[{"internalType":"uint256[]","name":"","type":"uint256[]"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"uint256","name":"lookback","type":"uint256"}],"name":"getHistoricalTimestamp","outputs":[{"internalType":"uint256[]","name":"","type":"uint256[]"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"uint256","name":"start","type":"uint256"},{"internalType":"uint256","name":"end","type":"uint256"}],"name":"getHistoricalTimestampRange","outputs":[{"internalType":"uint256[]","name":"","type":"uint256[]"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"latestSnapshotId","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"oracle","outputs":[{"internalType":"contract IAggregatorInterface","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"uint256","name":"","type":"uint256"}],"name":"prices","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"uint256","name":"","type":"uint256"}],"name":"timestamps","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"update","outputs":[],"stateMutability":"nonpayable","type":"function"}]"""
dyn_fee_hook_abi = """[{"inputs":[{"internalType":"contract IVault","name":"vault","type":"address"},{"internalType":"address","name":"verifier","type":"address"},{"internalType":"address","name":"priceCache","type":"address"},{"internalType":"uint256","name":"scalingFactor","type":"uint256"},{"internalType":"uint256","name":"lookback","type":"uint256"}],"stateMutability":"nonpayable","type":"constructor"},{"inputs":[{"internalType":"address","name":"sender","type":"address"}],"name":"SenderIsNotVault","type":"error"},{"inputs":[],"name":"VerificationFail","type":"error"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"hooksContract","type":"address"},{"indexed":true,"internalType":"address","name":"pool","type":"address"}],"name":"EZKLDynamicFeeHookRegistered","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"hooksContract","type":"address"},{"indexed":false,"internalType":"uint256","name":"dynamicFee","type":"uint256"}],"name":"EZKLDynamicFeeHookUpdated","type":"event"},{"inputs":[],"name":"_dynamicFee","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"_lookback","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"_priceCache","outputs":[{"internalType":"contract IChainlinkPriceCache","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"_scalingFactor","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"_verifier","outputs":[{"internalType":"contract IHalo2Verifier","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"getHookFlags","outputs":[{"components":[{"internalType":"bool","name":"enableHookAdjustedAmounts","type":"bool"},{"internalType":"bool","name":"shouldCallBeforeInitialize","type":"bool"},{"internalType":"bool","name":"shouldCallAfterInitialize","type":"bool"},{"internalType":"bool","name":"shouldCallComputeDynamicSwapFee","type":"bool"},{"internalType":"bool","name":"shouldCallBeforeSwap","type":"bool"},{"internalType":"bool","name":"shouldCallAfterSwap","type":"bool"},{"internalType":"bool","name":"shouldCallBeforeAddLiquidity","type":"bool"},{"internalType":"bool","name":"shouldCallAfterAddLiquidity","type":"bool"},{"internalType":"bool","name":"shouldCallBeforeRemoveLiquidity","type":"bool"},{"internalType":"bool","name":"shouldCallAfterRemoveLiquidity","type":"bool"}],"internalType":"struct HookFlags","name":"hookFlags","type":"tuple"}],"stateMutability":"pure","type":"function"},{"inputs":[{"internalType":"address","name":"","type":"address"},{"internalType":"address","name":"","type":"address"},{"internalType":"enum AddLiquidityKind","name":"","type":"uint8"},{"internalType":"uint256[]","name":"","type":"uint256[]"},{"internalType":"uint256[]","name":"amountsInRaw","type":"uint256[]"},{"internalType":"uint256","name":"","type":"uint256"},{"internalType":"uint256[]","name":"","type":"uint256[]"},{"internalType":"bytes","name":"","type":"bytes"}],"name":"onAfterAddLiquidity","outputs":[{"internalType":"bool","name":"","type":"bool"},{"internalType":"uint256[]","name":"","type":"uint256[]"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"uint256[]","name":"","type":"uint256[]"},{"internalType":"uint256","name":"","type":"uint256"},{"internalType":"bytes","name":"","type":"bytes"}],"name":"onAfterInitialize","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"","type":"address"},{"internalType":"address","name":"","type":"address"},{"internalType":"enum RemoveLiquidityKind","name":"","type":"uint8"},{"internalType":"uint256","name":"","type":"uint256"},{"internalType":"uint256[]","name":"","type":"uint256[]"},{"internalType":"uint256[]","name":"amountsOutRaw","type":"uint256[]"},{"internalType":"uint256[]","name":"","type":"uint256[]"},{"internalType":"bytes","name":"","type":"bytes"}],"name":"onAfterRemoveLiquidity","outputs":[{"internalType":"bool","name":"","type":"bool"},{"internalType":"uint256[]","name":"","type":"uint256[]"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"components":[{"internalType":"enum SwapKind","name":"kind","type":"uint8"},{"internalType":"contract IERC20","name":"tokenIn","type":"address"},{"internalType":"contract IERC20","name":"tokenOut","type":"address"},{"internalType":"uint256","name":"amountInScaled18","type":"uint256"},{"internalType":"uint256","name":"amountOutScaled18","type":"uint256"},{"internalType":"uint256","name":"tokenInBalanceScaled18","type":"uint256"},{"internalType":"uint256","name":"tokenOutBalanceScaled18","type":"uint256"},{"internalType":"uint256","name":"amountCalculatedScaled18","type":"uint256"},{"internalType":"uint256","name":"amountCalculatedRaw","type":"uint256"},{"internalType":"address","name":"router","type":"address"},{"internalType":"address","name":"pool","type":"address"},{"internalType":"bytes","name":"userData","type":"bytes"}],"internalType":"struct AfterSwapParams","name":"","type":"tuple"}],"name":"onAfterSwap","outputs":[{"internalType":"bool","name":"","type":"bool"},{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"","type":"address"},{"internalType":"address","name":"","type":"address"},{"internalType":"enum AddLiquidityKind","name":"","type":"uint8"},{"internalType":"uint256[]","name":"","type":"uint256[]"},{"internalType":"uint256","name":"","type":"uint256"},{"internalType":"uint256[]","name":"","type":"uint256[]"},{"internalType":"bytes","name":"","type":"bytes"}],"name":"onBeforeAddLiquidity","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"uint256[]","name":"","type":"uint256[]"},{"internalType":"bytes","name":"","type":"bytes"}],"name":"onBeforeInitialize","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"","type":"address"},{"internalType":"address","name":"","type":"address"},{"internalType":"enum RemoveLiquidityKind","name":"","type":"uint8"},{"internalType":"uint256","name":"","type":"uint256"},{"internalType":"uint256[]","name":"","type":"uint256[]"},{"internalType":"uint256[]","name":"","type":"uint256[]"},{"internalType":"bytes","name":"","type":"bytes"}],"name":"onBeforeRemoveLiquidity","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"components":[{"internalType":"enum SwapKind","name":"kind","type":"uint8"},{"internalType":"uint256","name":"amountGivenScaled18","type":"uint256"},{"internalType":"uint256[]","name":"balancesScaled18","type":"uint256[]"},{"internalType":"uint256","name":"indexIn","type":"uint256"},{"internalType":"uint256","name":"indexOut","type":"uint256"},{"internalType":"address","name":"router","type":"address"},{"internalType":"bytes","name":"userData","type":"bytes"}],"internalType":"struct PoolSwapParams","name":"","type":"tuple"},{"internalType":"address","name":"","type":"address"}],"name":"onBeforeSwap","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"components":[{"internalType":"enum SwapKind","name":"kind","type":"uint8"},{"internalType":"uint256","name":"amountGivenScaled18","type":"uint256"},{"internalType":"uint256[]","name":"balancesScaled18","type":"uint256[]"},{"internalType":"uint256","name":"indexIn","type":"uint256"},{"internalType":"uint256","name":"indexOut","type":"uint256"},{"internalType":"address","name":"router","type":"address"},{"internalType":"bytes","name":"userData","type":"bytes"}],"internalType":"struct PoolSwapParams","name":"","type":"tuple"},{"internalType":"address","name":"","type":"address"},{"internalType":"uint256","name":"","type":"uint256"}],"name":"onComputeDynamicSwapFeePercentage","outputs":[{"internalType":"bool","name":"","type":"bool"},{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"","type":"address"},{"internalType":"address","name":"pool","type":"address"},{"components":[{"internalType":"contract IERC20","name":"token","type":"address"},{"internalType":"enum TokenType","name":"tokenType","type":"uint8"},{"internalType":"contract IRateProvider","name":"rateProvider","type":"address"},{"internalType":"bool","name":"paysYieldFees","type":"bool"}],"internalType":"struct TokenConfig[]","name":"","type":"tuple[]"},{"components":[{"internalType":"bool","name":"disableUnbalancedLiquidity","type":"bool"},{"internalType":"bool","name":"enableAddLiquidityCustom","type":"bool"},{"internalType":"bool","name":"enableRemoveLiquidityCustom","type":"bool"},{"internalType":"bool","name":"enableDonation","type":"bool"}],"internalType":"struct LiquidityManagement","name":"","type":"tuple"}],"name":"onRegister","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"bytes","name":"proof","type":"bytes"},{"internalType":"uint256","name":"dynamicFeeUnscaled","type":"uint256"}],"name":"updateFee","outputs":[],"stateMutability":"nonpayable","type":"function"}]"""
ezkl_verifier_abi = """[{"inputs":[{"internalType":"bytes","name":"proof","type":"bytes"},{"internalType":"uint256[]","name":"instances","type":"uint256[]"}],"name":"verifyProof","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"nonpayable","type":"function"}]"""
fee_manager_abi = """[{"inputs":[{"internalType":"address","name":"_vault","type":"address"}],"stateMutability":"nonpayable","type":"constructor"},{"inputs":[],"name":"FeeTooHigh","type":"error"},{"inputs":[],"name":"InvalidHook","type":"error"},{"inputs":[],"name":"InvalidPool","type":"error"},{"inputs":[{"internalType":"address","name":"owner","type":"address"}],"name":"OwnableInvalidOwner","type":"error"},{"inputs":[{"internalType":"address","name":"account","type":"address"}],"name":"OwnableUnauthorizedAccount","type":"error"},{"inputs":[],"name":"VerificationFailed","type":"error"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"pool","type":"address"},{"indexed":false,"internalType":"uint256","name":"swapFeePercentage","type":"uint256"}],"name":"FeeUpdated","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"pool","type":"address"},{"indexed":false,"internalType":"address","name":"verifier","type":"address"},{"indexed":false,"internalType":"address","name":"priceCache","type":"address"},{"indexed":false,"internalType":"uint256","name":"lookback","type":"uint256"},{"indexed":false,"internalType":"uint256","name":"scalingFactor","type":"uint256"},{"indexed":false,"internalType":"uint256","name":"initialFee","type":"uint256"}],"name":"NewFeeConfig","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"previousOwner","type":"address"},{"indexed":true,"internalType":"address","name":"newOwner","type":"address"}],"name":"OwnershipTransferred","type":"event"},{"inputs":[{"internalType":"address","name":"","type":"address"}],"name":"feeConfig","outputs":[{"internalType":"contract IHalo2Verifier","name":"verifier","type":"address"},{"internalType":"contract IChainlinkPriceCache","name":"priceCache","type":"address"},{"internalType":"uint256","name":"lookback","type":"uint256"},{"internalType":"uint256","name":"scalingFactor","type":"uint256"},{"internalType":"uint256","name":"dynamicFee","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"owner","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"pool","type":"address"},{"internalType":"address","name":"_verifier","type":"address"},{"internalType":"address","name":"_priceCache","type":"address"},{"internalType":"uint256","name":"_lookback","type":"uint256"},{"internalType":"uint256","name":"_scalingFactor","type":"uint256"},{"internalType":"uint256","name":"_initDynamicFee","type":"uint256"}],"name":"registerFeeConfig","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"renounceOwnership","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"pool","type":"address"},{"internalType":"bytes","name":"proof","type":"bytes"},{"internalType":"uint256","name":"dynamicFeeUnscaled","type":"uint256"}],"name":"setStaticSwapFeePercentage","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"newOwner","type":"address"}],"name":"transferOwnership","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"vault","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"}]"""

WALLET_PRIVATE_KEY = secrets.WALLET_PRIVATE_KEY
WALLET_ADDRESS = secrets.WALLET_ADDRESS

def get_historical_prices(web3, price_cache_contract_address, lookback=337, length=337):
    """
    Fetch historical prices from the ChainlinkPriceCache contract
    
    Args:
        web3: Web3 instance
        price_cache_contract_address: Address of the deployed ChainlinkPriceCache contract
        lookback: Number of historical prices to retrieve (default: 337)
        
    Returns:
        List of historical prices
    """
    try:
        # Create contract instance
        price_cache_contract = web3.eth.contract(
            address=price_cache_contract_address,
            abi=price_cache_abi
        )
        
        # Call getHistoricalPrice function
        historical_prices = price_cache_contract.functions.getHistoricalPrice(lookback).call()
        historical_timestamps = price_cache_contract.functions.getHistoricalTimestamp(lookback).call()
        
        # Log the results
        logger.info(f"Successfully retrieved {len(historical_prices)} historical prices")
        logger.info(f"prices = {historical_prices}")
        logger.info(f"timestamps = {historical_timestamps}")

        if DEBUG:
            if len(historical_prices) < length:
                while len(historical_prices) < length:
                    historical_prices.append(historical_prices[-1])

        # format into json
        output_data = {
            "input_data": [historical_prices],
            "output_data": None
        }

        print(output_data)

        if DEBUG:
            with open("input_debug.json", "w") as f:
                json.dump(output_data, f)

        return output_data
            
    except ContractLogicError as e:
        logger.error(f"Contract logic error: {str(e)}")
        # Check for specific error messages
        if "NoDataAvailable" in str(e):
            logger.error("No historical data available. The contract may not have enough history.")
        return []
    except Exception as e:
        logger.error(f"Error retrieving historical prices: {str(e)}")
        logger.error(traceback.format_exc())
        return []


def call_lilith(output_data):
    """
    Calls lilith with the historical prices and returns proof, outputs
    """
    latest_uuid = str(uuid.uuid4())

    try:
        res = requests.post(
            url=f"{secrets.ARCHON_URL}/recipe?user_id=8c9f812f-b85e-47d6-9fca-c4f9b34622b7",
            headers={
                "X-API-KEY": secrets.ARCHON_API_KEY,
                "Content-Type": "application/json",
            },
            json={
                "commands": [
                    {
                        "artifact": "balancer_fee_model",
                        "binary": "ezkl",
                        "deployment": "0195d1ec-e714-72e4-baef-578131cc7f39",
                        "command": [
                            "gen-witness",
                            f"--data input_{latest_uuid}.json",
                            f"--compiled-circuit model.compiled",
                            f"--output witness_{latest_uuid}.json"
                        ],
                    },
                    {
                        "artifact": "balancer_fee_model",
                        "binary": "ezkl",
                        "deployment": "0195d1ec-e714-72e4-baef-578131cc7f39",
                        "command": [
                            "prove",
                            f"--witness witness_{latest_uuid}.json",
                            f"--compiled-circuit model.compiled" ,
                            "--pk-path pk.key",
                            f"--proof-path proof_{latest_uuid}.json",
                        ],
                        "output_path": [f"proof_{latest_uuid}.json"]
                    },
                ],
                "data": [{
                    "target_path": f"input_{latest_uuid}.json",
                    "data": output_data
                }],
            }
        )

        if res.status_code >= 400:
            logger.error(f"Error: HTTP {res.status_code}")
            logger.error(f"Error message: {res.content}")
        else:
            logger.info("Request successful")

            data = json.loads(res.content.decode('utf-8'))
            logger.info(f"full data: {data}")
            logger.info(f"id: {data['id']}")

            cluster_id = data["id"]


            query_count = 0
            proof_data = None

            while query_count < 60:
                time.sleep(10)
                # get job status
                # pass id to client so client polls
                res = requests.get(
                    url=f"{secrets.ARCHON_URL}/recipe/{str(cluster_id)}?user_id=8c9f812f-b85e-47d6-9fca-c4f9b34622b7",
                    headers={
                        "X-API-KEY": secrets.ARCHON_API_KEY,
                    }
                )
                res.raise_for_status()
                data = json.loads(res.content.decode('utf-8'))
                logger.info(f"witness data: {data[0]}")
                logger.info(f"prove data: {data[1]}")
                logger.info(f"prove status: {data[1]['status']}")

                status = data[1]['status']

                if status == "Complete":
                    logger.info(f"Complete: {data}")
                    json_data = json.loads(data[1]['output'][0]['utf8_string'])

                    res.raise_for_status()

                    logger.info(f"hex_proof: {json_data['hex_proof']}")

                    instances = json_data['pretty_public_inputs']['inputs'][0] + \
                        json_data['pretty_public_inputs']['outputs'][0]

                    logger.info(f"instances: {instances}")

                    return json_data['hex_proof'], instances

                if status == "Errored":
                    logger.error("ERRORED")
                    logger.error(f"Error data: {data}")
                    break


                query_count += 1

    except Exception as e:
        logger.error(f"Error parsing response: {str(e)}")
        logger.error(traceback.format_exc())


def update_fee():
    """
    Updates the fee on the dynamic fee hook contract using the proof and output from Lilith
    """
    try:
        # Initialize web3 connection
        w3 = Web3(Web3.HTTPProvider(secrets.ETHEREUM_NODE_URL))
        account = w3.eth.account.from_key(WALLET_PRIVATE_KEY)
        
        # Get historical prices and generate proof
        historical_prices = get_historical_prices(w3, secrets.CACHE_CONTRACT_ADDRESS, 337)

        if not historical_prices:
            logger.error("Failed to get historical prices. Cannot update hook.")
            return
            
        # Call Lilith to get proof and dynamic fee
        proof, instances = call_lilith(historical_prices)
        if not proof or not instances:
            logger.error("Failed to get proof and dynamic fee from Lilith. Cannot update fee.")
            return
            
        logger.info(f"Got proof and dynamicFeeUnscaled: {instances[-1]}")

        # call the fee manager
        fee_manager_contract = w3.eth.contract(
            address=secrets.FEE_MANAGER_ADDRESS,
            abi=fee_manager_abi
        )

        transaction = fee_manager_contract.functions.setStaticSwapFeePercentage(
            secrets.POOL_CONTRACT_ADDRESS,
            Web3.to_bytes(hexstr=proof),
            int(instances[-1], 16)
        ).build_transaction({
            'from': WALLET_ADDRESS,
            'nonce': w3.eth.get_transaction_count(WALLET_ADDRESS),
            'gas': 30000000,
            'gasPrice': w3.eth.gas_price + 10,
        })

        # Sign and send transaction
        signed_tx = w3.eth.account.sign_transaction(transaction, WALLET_PRIVATE_KEY)
        tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)

        logger.info(f"Transaction sent with hash: {tx_hash.hex()}")

        # Wait for transaction receipt
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=300)
        if receipt.status == 1:
            logger.info(f"Successfully updated dynamic fee on FeeManager contract")
        else:
            logger.error(f"Transaction failed with status: {receipt.status}")


        # Call the ezkl verifier
        # if DEBUG:
        #     verifier_contract = w3.eth.contract(
        #         address=secrets.EZKL_VERIFIER_ADDRESS,
        #         abi=ezkl_verifier_abi
        #     )

        #     transaction = verifier_contract.functions.verifyProof(
        #         proof,
        #         historical_prices['input_data'] + [int(dynamicFeeUnscaled, 16)]
        #     ).build_transaction({
        #         'from': WALLET_ADDRESS,
        #         'nonce': w3.eth.get_transaction_count(WALLET_ADDRESS),
        #         'gas': 2000000,
        #         'gasPrice': w3.eth.gas_price,
        #     })

        #     # Sign and send transaction
        #     signed_tx = w3.eth.account.sign_transaction(transaction, WALLET_PRIVATE_KEY)
        #     tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)

        #     logger.info(f"Transaction sent with hash: {tx_hash.hex()}")

        #     # Wait for transaction receipt
        #     receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=300)
        #     if receipt.status == 1:
        #         logger.info(f"Successfully updated dynamic fee on hook contract")
        #     else:
        #         logger.error(f"Transaction failed with status: {receipt.status}")

        
        # # Create contract instance for the hook
        # hook_contract = w3.eth.contract(
        #     address=secrets.HOOK_CONTRACT_ADDRESS,
        #     abi=dyn_fee_hook_abi
        # )
        
        # # Build transaction to call updateFee function
        # transaction = hook_contract.functions.updateFee(
        #     proof,
        #     int(dynamicFeeUnscaled, 16)
        # ).build_transaction({
        #     'from': WALLET_ADDRESS,
        #     'nonce': w3.eth.get_transaction_count(WALLET_ADDRESS),
        #     'gas': 2000000,  # Gas limit
        #     'gasPrice': w3.eth.gas_price,
        # })
        
        # # Sign and send transaction
        # signed_tx = w3.eth.account.sign_transaction(transaction, WALLET_PRIVATE_KEY)
        # tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
        
        # logger.info(f"Transaction sent with hash: {tx_hash.hex()}")
        
        # # Wait for transaction receipt
        # receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=300)
        # if receipt.status == 1:
        #     logger.info(f"Successfully updated dynamic fee on hook contract")
        # else:
        #     logger.error(f"Transaction failed with status: {receipt.status}")
            
    except ContractLogicError as e:
        logger.error(f"Contract logic error: {str(e)}")
        logger.error(traceback.format_exc())
    except Exception as e:
        logger.error(f"Error updating hook: {str(e)}")
        logger.error(traceback.format_exc())


if __name__ == "__main__":
    update_fee()
