
import time
import json
import logging
import datetime
from web3 import Web3
from web3.exceptions import ContractLogicError
import secrets
import traceback
import tempfile
import requests
import uuid

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

WALLET_PRIVATE_KEY = secrets.WALLET_PRIVATE_KEY
WALLET_ADDRESS = secrets.WALLET_ADDRESS

def get_historical_prices(web3, price_cache_contract_address, lookback=10):
    """
    Fetch historical prices from the ChainlinkPriceCache contract
    
    Args:
        web3: Web3 instance
        price_cache_contract_address: Address of the deployed ChainlinkPriceCache contract
        lookback: Number of historical prices to retrieve (default: 10)
        
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

        return historical_prices
            
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


def call_lilith(historical_prices, length=337):
    latest_uuid = str(uuid.uuid4())

    if len(historical_prices) != length:
        while len(historical_prices) != length:
            historical_prices.append(historical_prices[-1])


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
                        "deployment": "01957919-8fcc-76c8-a81b-386cf5b9bf20",
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
                        "deployment": "01957919-8fcc-76c8-a81b-386cf5b9bf20",
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
                    "data": {"input_data": [historical_prices]}
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

                    proof_data = res.json()

                    logger.info(f"hex_proof: {json_data['hex_proof']}")
                    logger.info(f"instances: {json_data['pretty_public_inputs']['outputs']}")

                    break

                if status == "Errored":
                    logger.error("ERRORED")
                    logger.error(f"Error data: {data}")
                    break


                query_count += 1

    except Exception as e:
        logger.error(f"Error parsing response: {str(e)}")
        logger.error(traceback.format_exc())


if __name__ == "__main__":
    w3 = Web3(Web3.HTTPProvider(secrets.ETHEREUM_NODE_URL))
    historical_prices = get_historical_prices(w3, secrets.CONTRACT_ADDRESS, 100)
    call_lilith(historical_prices)