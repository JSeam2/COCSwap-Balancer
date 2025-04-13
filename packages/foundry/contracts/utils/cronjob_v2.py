import time
import json
import logging
import datetime
from web3 import Web3
from web3.exceptions import ContractLogicError
import secrets
import traceback
import requests
import uuid

# DEBUG MODE
DEBUG_MODE=False

# Configure logging
logging.basicConfig(
    level=logging.DEBUG if DEBUG_MODE else logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("contract_updater.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("ContractUpdater")

# Number of blocks to lookback for logs
# 1800 as base has an average of 2 seconds per blockl
LOG_LOOKBACK = 1800

# Contract information
CACHE_CONTRACT_ADDRESS = secrets.CACHE_CONTRACT_ADDRESS
CACHE_CONTRACT_ABI = json.loads('''
[{"inputs":[{"internalType":"string","name":"_description","type":"string"},{"internalType":"address","name":"_oracle","type":"address"},{"internalType":"uint256","name":"_delay","type":"uint256"},{"internalType":"uint256[]","name":"_roundIds","type":"uint256[]"}],"stateMutability":"nonpayable","type":"constructor"},{"inputs":[],"name":"InvalidRange","type":"error"},{"inputs":[],"name":"NoDataAvailable","type":"error"},{"inputs":[],"name":"WaitForDelay","type":"error"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"uint256","name":"timestamp","type":"uint256"},{"indexed":false,"internalType":"uint256","name":"price","type":"uint256"}],"name":"Updated","type":"event"},{"inputs":[],"name":"delay","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"description","outputs":[{"internalType":"string","name":"","type":"string"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"uint256","name":"lookback","type":"uint256"}],"name":"getHistoricalPrice","outputs":[{"internalType":"uint256[]","name":"","type":"uint256[]"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"uint256","name":"start","type":"uint256"},{"internalType":"uint256","name":"end","type":"uint256"}],"name":"getHistoricalPriceRange","outputs":[{"internalType":"uint256[]","name":"","type":"uint256[]"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"uint256","name":"lookback","type":"uint256"}],"name":"getHistoricalTimestamp","outputs":[{"internalType":"uint256[]","name":"","type":"uint256[]"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"uint256","name":"start","type":"uint256"},{"internalType":"uint256","name":"end","type":"uint256"}],"name":"getHistoricalTimestampRange","outputs":[{"internalType":"uint256[]","name":"","type":"uint256[]"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"latestSnapshotId","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"oracle","outputs":[{"internalType":"contract IAggregatorInterface","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"uint256","name":"","type":"uint256"}],"name":"prices","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"uint256","name":"","type":"uint256"}],"name":"timestamps","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"update","outputs":[],"stateMutability":"nonpayable","type":"function"}]
''')

POOL_CONTRACT_ADDRESSES = secrets.POOL_CONTRACT_ADDRESSES
FEE_MANAGER_ADDRESS = secrets.FEE_MANAGER_ADDRESS
FEE_MANAGER_ABI = json.loads('''
[{"inputs":[{"internalType":"string","name":"_description","type":"string"},{"internalType":"address","name":"_vault","type":"address"},{"internalType":"address","name":"_priceCache","type":"address"},{"internalType":"address","name":"_verifier","type":"address"},{"internalType":"uint256","name":"_lookback","type":"uint256"},{"internalType":"uint256","name":"_scalingFactorDiv","type":"uint256"},{"internalType":"uint256","name":"_scalingFactorMul","type":"uint256"}],"stateMutability":"nonpayable","type":"constructor"},{"inputs":[],"name":"InvalidPool","type":"error"},{"inputs":[],"name":"VerificationFailed","type":"error"},{"anonymous":false,"inputs":[{"indexed":false,"internalType":"uint256","name":"swapFeePercentage","type":"uint256"}],"name":"FeeUpdated","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"pool","type":"address"},{"indexed":false,"internalType":"uint256","name":"swapFeePercentage","type":"uint256"}],"name":"PoolUpdated","type":"event"},{"inputs":[],"name":"description","outputs":[{"internalType":"string","name":"","type":"string"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"dynamicFee","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"lookback","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"priceCache","outputs":[{"internalType":"contract IChainlinkPriceCache","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address[]","name":"pools","type":"address[]"}],"name":"publishFee","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"scalingFactorDiv","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"scalingFactorMul","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"bytes","name":"proof","type":"bytes"},{"internalType":"uint256","name":"dynamicFeeUnscaled","type":"uint256"}],"name":"updateFee","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"vault","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"verifier","outputs":[{"internalType":"contract IHalo2Verifier","name":"","type":"address"}],"stateMutability":"view","type":"function"}]
''')

# Lilith configuration
ARCHON_URL = secrets.ARCHON_URL
ARCHON_API_KEY = secrets.ARCHON_API_KEY
ARCHON_USER_ID = secrets.ARCHON_USER_ID
ARCHON_ARTIFACT = secrets.ARCHON_ARTIFACT
ARCHON_DEPLOYMENT = secrets.ARCHON_DEPLOYMENT

# RPC configuration
ETHEREUM_NODE_URL = secrets.ETHEREUM_NODE_URL

# Wallet configuration
WALLET_PRIVATE_KEY = secrets.WALLET_PRIVATE_KEY
WALLET_ADDRESS = secrets.WALLET_ADDRESS

# Constants
WAIT_FOR_DELAY_RETRY_TIME = 120  # seconds
UPDATE_WINDOW_BUFFER = 60  # seconds before the next valid update time to start attempting updates
CHECK_INTERVAL = 15  # seconds between each check when waiting
MAX_RETRIES = 10  # Maximum number of retries on failure

# Error signatures from contract
ERROR_WAIT_FOR_DELAY = "0x11c973a0"  # Hex signature for WaitForDelay error
ERROR_INVALID_RANGE = "0x2105b620"   # Hex signature for InvalidRange error
ERROR_NO_DATA_AVAILABLE = "0x390d9a43"  # Hex signature for NoDataAvailable error


class ContractUpdater:
    def __init__(
            self,
            cache_contract_address,
            cache_contract_abi,
            pool_contract_addresses,
            fee_manager_contract_address,
            fee_manager_contract_abi,
            node_url,
            wallet_address,
            private_key,
        ):
        try:
            logger.info(f"Connecting to Ethereum node at {node_url}")

            self.w3 = Web3(Web3.HTTPProvider(node_url))

            if not self.w3.is_connected():
                logger.error(f"Failed to connect to Ethereum node at {node_url}")
                raise ConnectionError(f"Failed to connect to Ethereum node at {node_url}")
            else:
                chain_id = self.w3.eth.chain_id
                block_number = self.w3.eth.block_number
                logger.info(f"Connected to Ethereum node. Chain ID: {chain_id}, Block number: {block_number}")

            # setup cache contract
            self.cache_contract_address = Web3.to_checksum_address(cache_contract_address)
            logger.info(f"Using ChainlinkPriceCache contract address: {self.cache_contract_address}")
            self.cache_contract = self.w3.eth.contract(address=self.cache_contract_address, abi=cache_contract_abi)

            # setup pool
            self.pool_contract_addresses = [Web3.to_checksum_address(x) for x in pool_contract_addresses]
            logger.info(f"Using Pool contract address: {self.pool_contract_addresses}")

            # setup fee manager
            self.fee_manager_contract_address = Web3.to_checksum_address(fee_manager_contract_address)
            logger.info(f"Using FeeManager contract address: {self.fee_manager_contract_address}")
            self.fee_manager_contract = self.w3.eth.contract(address=self.fee_manager_contract_address, abi=fee_manager_contract_abi)

            self.wallet_address = Web3.to_checksum_address(wallet_address)
            logger.info(f"Using wallet address: {self.wallet_address}")
            self.private_key = private_key

            # Check wallet balance
            balance = self.w3.eth.get_balance(self.wallet_address)
            balance_eth = self.w3.from_wei(balance, 'ether')
            logger.info(f"Wallet balance: {balance_eth} ETH")
            if balance_eth < 0.01:
                logger.warning(f"Low wallet balance: {balance_eth} ETH. Consider topping up.")

            # Initialize contract data
            self.refresh_contract_data()

        except Exception as e:
            logger.error(f"Error initializing contract: {e}")
            logger.error(f"Traceback: {traceback.format_exc()}")
            raise

    def refresh_contract_data(self):
        """Refresh all contract data"""
        try:
            # Get contract description
            self.description = self.cache_contract.functions.description().call()
            logger.info(f"Contract description: {self.description}")

            # Get delay value
            self.delay = self.cache_contract.functions.delay().call()
            logger.info(f"Contract delay: {self.delay} seconds")

            # Get latest snapshot ID
            self.latest_snapshot_id = self.cache_contract.functions.latestSnapshotId().call()
            logger.info(f"Latest snapshot ID: {self.latest_snapshot_id}")

            # Get latest timestamp
            self.latest_timestamp = self.cache_contract.functions.timestamps(self.latest_snapshot_id).call()

            # Convert to human-readable time
            timestamp_datetime = datetime.datetime.fromtimestamp(self.latest_timestamp)
            logger.info(f"Latest timestamp: {self.latest_timestamp} ({timestamp_datetime.strftime('%Y-%m-%d %H:%M:%S')})")

            # Calculate the next eligible update time
            self.next_update_time = self.latest_timestamp + self.delay
            next_update_datetime = datetime.datetime.fromtimestamp(self.next_update_time)
            logger.info(f"Next eligible update time: {self.next_update_time} ({next_update_datetime.strftime('%Y-%m-%d %H:%M:%S')})")

            return True
        except Exception as e:
            logger.error(f"Error refreshing contract data: {e}")
            logger.error(f"Traceback: {traceback.format_exc()}")
            return False

    def time_to_next_update(self):
        """Calculate time remaining until next update is possible"""
        current_time = int(time.time())
        time_to_update = self.next_update_time - current_time

        return time_to_update

    def is_update_time(self):
        """Check if it's time to update based on latest timestamp and delay"""
        current_time = int(time.time())
        # Return True if current time is at or past the next update time
        return current_time >= (self.next_update_time - UPDATE_WINDOW_BUFFER)

    def simulate_transaction(self, contract_function, tx_params):
        """
        Simulate a transaction before sending to check if it will revert

        Args:
            contract_function: The contract function to call
            tx_params: Transaction parameters

        Returns:
            Tuple of (success, error_message)
        """
        try:
            # Create a copy of transaction parameters for simulation
            sim_params = tx_params.copy()

            # Get the current block for state override
            block = self.w3.eth.get_block('latest')
            block_number = block['number']

            logger.info(f"Simulating transaction on block {block_number}")

            # Call the function with eth_call to simulate execution
            result = contract_function.call(sim_params, block_identifier=block_number)

            # If we reach here, the transaction should succeed
            logger.info(f"Transaction simulation successful: {result}")
            return True, None

        except ContractLogicError as e:
            error_message = str(e)
            logger.warning(f"Transaction would revert: {error_message}")

            # Custom contract error handling - return the specific error
            if ERROR_WAIT_FOR_DELAY in error_message:
                return False, "WaitForDelay"
            elif ERROR_INVALID_RANGE in error_message:
                return False, "InvalidRange"
            elif ERROR_NO_DATA_AVAILABLE in error_message:
                return False, "NoDataAvailable"
            else:
                return False, error_message

        except Exception as e:
            logger.error(f"Error simulating transaction: {e}")
            logger.error(f"Traceback: {traceback.format_exc()}")
            return False, str(e)

    def call_update(self, retry_count=0):
        """Call the update function on the contract with gas price adjustments on retries"""
        try:
            # First simulate the transaction to check if it would succeed
            update_fn = self.cache_contract.functions.update()
            
            # Create simulation parameters
            sim_params = {'from': self.wallet_address}
            
            # Simulate the transaction
            success, error = self.simulate_transaction(update_fn, sim_params)
            
            if not success:
                logger.warning(f"Transaction simulation failed: {error}")
                return False, error
                
            logger.info("Transaction simulation successful, proceeding with actual transaction")

            # Get latest block info
            latest_block = self.w3.eth.get_block("latest")
            base_fee_per_gas = latest_block.get('baseFeePerGas', self.w3.eth.gas_price)
            
            # Calculate max priority fee per gas (tip)
            priority_fee_base = self.w3.to_wei(0.00136, 'gwei')
            priority_multiplier = 1.0 + (retry_count * 0.2)  # 10% increase per retry
            max_priority_fee_per_gas = int(priority_fee_base * priority_multiplier)
            
            # Calculate max fee per gas 
            # Formula: baseFeePerGas * buffer + maxPriorityFeePerGas
            buffer = 1.2 + (retry_count * 0.2)  # Buffer increases with retries
            max_fee_per_gas = int(base_fee_per_gas * buffer) + max_priority_fee_per_gas
            
            logger.info(f"Using max fee: {self.w3.from_wei(max_fee_per_gas, 'gwei')} Gwei, max priority fee: {self.w3.from_wei(max_priority_fee_per_gas, 'gwei')} Gwei (retry {retry_count})")

            # Get the transaction count for nonce
            nonce = self.w3.eth.get_transaction_count(self.wallet_address)
            logger.info(f"Using nonce: {nonce}")
            
            # Use a fixed gas limit instead of estimating
            # This bypasses the estimate_gas call which can trigger the custom error
            gas_limit = 130000  # Fixed gas limit that should be sufficient for most update calls
            logger.info(f"Using fixed gas limit: {gas_limit}")

            # Build the transaction with fixed gas limit and EIP-1559 gas parameters
            tx = update_fn.build_transaction({
                'from': self.wallet_address,
                'nonce': nonce,
                'gas': gas_limit,
                'maxFeePerGas': max_fee_per_gas,
                'maxPriorityFeePerGas': max_priority_fee_per_gas,
                'type': 2,  # EIP-1559 transaction type
                'chainId': self.w3.eth.chain_id,
            })

            # Debug transaction details
            logger.debug(f"update transaction details: {tx}")

            # Sign the transaction
            signed_tx = self.w3.eth.account.sign_transaction(tx, self.private_key)
            logger.info(f"update transaction signed. Hash: {self.w3.to_hex(self.w3.keccak(signed_tx.raw_transaction))}")

            # Send the transaction
            tx_hash = self.w3.eth.send_raw_transaction(signed_tx.raw_transaction)
            logger.info(f"update transaction sent: 0x{tx_hash.hex()}")
            
            # Wait for transaction receipt with a timeout
            try:
                receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=300)
                logger.info(f"update transaction confirmed in block {receipt['blockNumber']}")
                
                # Check status of transaction
                if receipt['status'] == 1:
                    logger.info(f"update transaction succeeded. Gas used: {receipt['gasUsed']}")
                    return True, None
                else:
                    logger.error(f"update transaction failed. Gas used: {receipt['gasUsed']}")
                    return False, "update transaction failed"
            except Exception as timeout_error:
                logger.warning(f"update transaction may be pending: {str(timeout_error)}")
                return False, "Timeout"
            
        except ContractLogicError as e:
            error_message = str(e)

            # Custom contract error handling
            if ERROR_WAIT_FOR_DELAY in error_message:
                # This is the specific error we're seeing in the logs
                logger.warning(f"Contract custom error detected: {ERROR_WAIT_FOR_DELAY} (WaitForDelay)")
                return False, "WaitForDelay"
            elif ERROR_INVALID_RANGE in error_message:
                logger.error(f"Contract error: InvalidRange ({ERROR_INVALID_RANGE})")
                return False, "InvalidRange"
            elif ERROR_NO_DATA_AVAILABLE in error_message:
                logger.error(f"Contract error: NoDataAvailable ({ERROR_NO_DATA_AVAILABLE})")
                return False, "NoDataAvailable"
            elif "WaitForDelay" in error_message:
                logger.warning(f"WaitForDelay error: {error_message}")
                return False, "WaitForDelay"
            else:
                logger.error(f"Contract error: {error_message}")
                logger.error(f"Traceback: {traceback.format_exc()}")
                return False, str(e)
                
        except Exception as e:
            error_message = str(e)

            if "out of gas" in error_message.lower():
                logger.error(f"Out of gas error: {error_message}")
                return False, "OutOfGas"
            elif "underpriced" in error_message.lower():
                logger.error(f"Replacement transaction underpriced: {error_message}")
                return False, "Underpriced"
            elif "bad request" in error_message.lower():
                logger.error(f"Bad Request error from node provider: {error_message}")
                logger.error(f"Traceback: {traceback.format_exc()}")
                return False, "BadRequest"
            else:
                logger.error(f"Error calling update function: {error_message}")
                logger.error(f"Traceback: {traceback.format_exc()}")
                return False, str(e)

    def call_get_historical_prices(self, lookback=337):
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
            # Call getHistoricalPrice function
            self.historical_prices = self.cache_contract.functions.getHistoricalPrice(lookback).call()
            self.historical_timestamps = self.cache_contract.functions.getHistoricalTimestamp(lookback).call()

            # Log the results
            logger.info(f"Successfully retrieved {len(self.historical_prices)} historical prices")
            logger.debug(f"prices = {self.historical_prices}")
            logger.debug(f"timestamps = {self.historical_timestamps}")

            # format into json
            self.input_data = {
                "input_data": [self.historical_prices],
                "output_data": None
            }

            if DEBUG_MODE:
                with open("input_debug.json", "w") as f:
                    json.dump(self.input_data, f)

            return self.input_data

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

    def call_lilith(self):
        """
        Calls lilith with the historical prices and returns proof, outputs
        """
        latest_uuid = str(uuid.uuid4())

        try:
            res = requests.post(
                url=f"{ARCHON_URL}/recipe?user_id={ARCHON_USER_ID}",
                headers={
                    "X-API-KEY": ARCHON_API_KEY,
                    "Content-Type": "application/json",
                },
                json={
                    "commands": [
                        {
                            "artifact": ARCHON_ARTIFACT,
                            "binary": "ezkl",
                            "deployment": ARCHON_DEPLOYMENT,
                            "command": [
                                "gen-witness",
                                f"--data input_{latest_uuid}.json",
                                f"--compiled-circuit model.compiled",
                                f"--output witness_{latest_uuid}.json"
                            ],
                        },
                        {
                            "artifact": ARCHON_ARTIFACT,
                            "binary": "ezkl",
                            "deployment": ARCHON_DEPLOYMENT,
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
                        "data": self.input_data
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

                while query_count < 60:
                    time.sleep(10)
                    # get job status
                    # pass id to client so client polls
                    res = requests.get(
                        url=f"{ARCHON_URL}/recipe/{str(cluster_id)}?user_id={ARCHON_USER_ID}",
                        headers={
                            "X-API-KEY": ARCHON_API_KEY,
                        }
                    )
                    res.raise_for_status()
                    data = json.loads(res.content.decode('utf-8'))
                    logger.debug(f"witness data: {data[0]}")
                    logger.debug(f"prove data: {data[1]}")
                    logger.debug(f"prove status: {data[1]['status']}")

                    status = data[1]['status']

                    if status == "Complete":
                        logger.info(f"Complete: {data}")
                        json_data = json.loads(data[1]['output'][0]['utf8_string'])

                        res.raise_for_status()

                        self.proof_hexstring = json_data['hex_proof']
                        self.proof = Web3.to_bytes(hexstr=json_data['hex_proof'])

                        logger.debug(f"hex_proof: {self.proof_hexstring}")

                        self.instances = json_data['pretty_public_inputs']['inputs'][0] + \
                            json_data['pretty_public_inputs']['outputs'][0]

                        logger.debug(f"instances: {self.instances}")

                        return self.proof, self.instances

                    if status == "Errored":
                        logger.error("ERRORED")
                        logger.error(f"Error data: {data}")
                        break

                    query_count += 1

        except Exception as e:
            logger.error(f"Error parsing response: {str(e)}")
            logger.error(traceback.format_exc())

    def call_update_fee(self, retry_count=0):
        """Call the update function on the contract with gas price adjustments on retries"""
        try:
            # First simulate the transaction to check if it would succeed
            update_fee_fn = self.fee_manager_contract.functions.updateFee(
                self.proof,
                int(self.instances[-1], 16)
            )
            
            # Create simulation parameters
            sim_params = {'from': self.wallet_address}
            
            # Simulate the transaction
            success, error = self.simulate_transaction(update_fee_fn, sim_params)
            
            if not success:
                logger.warning(f"Transaction simulation failed: {error}")
                return False, error
                
            logger.info("Transaction simulation successful, proceeding with actual transaction")
            
            # Get latest block info
            latest_block = self.w3.eth.get_block("latest")
            base_fee_per_gas = latest_block.get('baseFeePerGas', self.w3.eth.gas_price)
            
            # Calculate max priority fee per gas (tip)
            # Start with 1.5 Gwei and increase based on retry count
            priority_fee_base = self.w3.to_wei(0.00136, 'gwei')
            priority_multiplier = 1.0 + (retry_count * 0.2)
            max_priority_fee_per_gas = int(priority_fee_base * priority_multiplier)
            
            # Calculate max fee per gas 
            # Formula: baseFeePerGas * buffer + maxPriorityFeePerGas
            buffer = 1.2 + (retry_count * 0.2)  # Buffer increases with retries
            max_fee_per_gas = int(base_fee_per_gas * buffer) + max_priority_fee_per_gas
            
            logger.info(f"Using max fee: {self.w3.from_wei(max_fee_per_gas, 'gwei')} Gwei, max priority fee: {self.w3.from_wei(max_priority_fee_per_gas, 'gwei')} Gwei (retry {retry_count})")

            # Get the transaction count for nonce
            nonce = self.w3.eth.get_transaction_count(self.wallet_address)
            logger.info(f"Using nonce: {nonce}")

            # Use a fixed gas limit instead of estimating
            # This bypasses the estimate_gas call which can trigger the custom error
            gas_limit = 30000000  # Fixed gas limit that should be sufficient for most update calls
            logger.info(f"Using fixed gas limit: {gas_limit}")

            # Build the transaction with fixed gas limit and EIP-1559 gas parameters
            tx = update_fee_fn.build_transaction({
                'from': self.wallet_address,
                'nonce': nonce,
                'gas': gas_limit,
                'maxFeePerGas': max_fee_per_gas,
                'maxPriorityFeePerGas': max_priority_fee_per_gas,
                'type': 2,  # EIP-1559 transaction type
                'chainId': self.w3.eth.chain_id,
            })

            # Debug transaction details
            logger.debug(f"Transaction details: {tx}")

            # Sign the transaction
            signed_tx = self.w3.eth.account.sign_transaction(tx, self.private_key)
            logger.info(f"Transaction signed. Hash: {self.w3.to_hex(self.w3.keccak(signed_tx.raw_transaction))}")

            # Send the transaction
            tx_hash = self.w3.eth.send_raw_transaction(signed_tx.raw_transaction)
            logger.info(f"updateFee transaction sent: 0x{tx_hash.hex()}")

            # Wait for transaction receipt with a timeout
            try:
                receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=300)
                logger.info(f"updateFee transaction confirmed in block {receipt['blockNumber']}")

                # Check status of transaction
                if receipt['status'] == 1:
                    logger.info(f"updateFee Transaction succeeded. Gas used: {receipt['gasUsed']}")
                    return True, None
                else:
                    logger.error(f"updateFee Transaction failed. Gas used: {receipt['gasUsed']}")
                    return False, "Transaction failed"
            except Exception as timeout_error:
                logger.warning(f"updateFee Transaction may be pending: {str(timeout_error)}")
                return False, "Timeout"

        except ContractLogicError as e:
            error_message = str(e)

            # Custom contract error handling
            if ERROR_WAIT_FOR_DELAY in error_message:
                # This is the specific error we're seeing in the logs
                logger.warning(f"Contract custom error detected: {ERROR_WAIT_FOR_DELAY} (WaitForDelay)")
                return False, "WaitForDelay"
            elif ERROR_INVALID_RANGE in error_message:
                logger.error(f"Contract error: InvalidRange ({ERROR_INVALID_RANGE})")
                return False, "InvalidRange"
            elif ERROR_NO_DATA_AVAILABLE in error_message:
                logger.error(f"Contract error: NoDataAvailable ({ERROR_NO_DATA_AVAILABLE})")
                return False, "NoDataAvailable"
            elif "WaitForDelay" in error_message:
                logger.warning(f"WaitForDelay error: {error_message}")
                return False, "WaitForDelay"
            else:
                logger.error(f"Contract error: {error_message}")
                logger.error(f"Traceback: {traceback.format_exc()}")
                return False, str(e)

        except Exception as e:
            error_message = str(e)

            if "out of gas" in error_message.lower():
                logger.error(f"Out of gas error: {error_message}")
                return False, "OutOfGas"
            elif "underpriced" in error_message.lower():
                logger.error(f"Replacement transaction underpriced: {error_message}")
                return False, "Underpriced"
            elif "bad request" in error_message.lower():
                logger.error(f"Bad Request error from node provider: {error_message}")
                logger.error(f"Traceback: {traceback.format_exc()}")
                return False, "BadRequest"
            else:
                logger.error(f"Error calling updateFee function: {error_message}")
                logger.error(f"Traceback: {traceback.format_exc()}")
                return False, str(e)


    def check_recent_fee_update(self):
        """
        Check if updateFee was called within the last hour
        Returns True if a recent update was found, False otherwise
        """
        try:
            # Get current block number
            current_block = self.w3.eth.block_number
            
            # Look back approximately 1 hour
            # For Base with ~2 second block time, we need to look back ~1800 blocks
            from_block = max(0, current_block - LOG_LOOKBACK)
            
            logs = self.fee_manager_contract.events.FeeUpdated().get_logs(from_block=from_block)
            logger.info(f"FeeUpdated logs: {logs}")

            if len(logs) > 0:
                return True

            else:
                logger.info("No recent FeeUpdated event, proceed to call updateFee")
                return False
            
        except Exception as e:
            logger.error(f"Error checking for recent fee updates: {e}")
            logger.error(f"Traceback: {traceback.format_exc()}")

            # If we can't check, assume no recent updates to be safe
            return False
    
    def check_update_in_progress(self):
        """
        Check if there are any pending update transactions for the price cache contract,
        regardless of which wallet is sending them.
        Returns True if an update is in progress, False otherwise
        """
        try:
            # Check the mempool for pending transactions
            pending_txs = self.w3.eth.get_block('pending', full_transactions=True)
            
            if pending_txs and 'transactions' in pending_txs:
                # Look for any transactions to the cache contract
                for tx in pending_txs['transactions']:
                    if tx.get('to') and tx['to'].lower() == self.cache_contract_address.lower():
                        # For better accuracy, we could decode the input data to check if it's actually
                        # calling the update() function, but this requires access to the contract ABI
                        input_data = tx.get('input', '')
                        # The function signature for update() should be the first 4 bytes (8 hex chars + '0x')
                        update_signature = self.w3.keccak(text="update()").hex()[:10]  # '0x' + first 8 chars
                        
                        # Ensure both are strings for comparison
                        if isinstance(input_data, bytes):
                            input_data = input_data.hex()
                            if not input_data.startswith('0x'):
                                input_data = '0x' + input_data
                        
                        if input_data.startswith(update_signature):
                            logger.info(f"Found pending update transaction from {tx['from']} to cache contract")
                            return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error checking for pending updates: {e}")
            logger.error(f"Traceback: {traceback.format_exc()}")
            # If we can't check, assume no updates in progress to be safe
            return False

    def run(self):
        """Run the updater loop with intelligent timing"""
        logger.info("Starting contract updater with intelligent timing")
        
        while True:
            try:
                # Refresh contract data including latest timestamp and delay
                self.refresh_contract_data()

                # Check if it's time to update the price cache
                if self.is_update_time():
                    logger.info("It's time to attempt the price cache update")

                    # Initialize retry counter
                    retries = 0
                    update_successful = False

                    # Check if there's an update in the mempool
                    if not self.check_update_in_progress():
                        # First, simulate the transaction to check if it would succeed
                        # This helps us avoid gas costs for transactions that will definitely fail
                        update_fn = self.cache_contract.functions.update()
                        sim_params = {'from': self.wallet_address}
                        sim_success, sim_error = self.simulate_transaction(update_fn, sim_params)
                        
                        if not sim_success:
                            if sim_error == "WaitForDelay":
                                # If WaitForDelay error, calculate better wait time
                                current_time = int(time.time())
                                time_to_update = max(0, self.next_update_time - current_time)
                                
                                if time_to_update > 0:
                                    logger.info(f"Simulation showed WaitForDelay error. Next valid update in {time_to_update} seconds.")
                                    # Don't retry until time has passed, continue to fee update check
                                    # The next loop iteration will try again
                                    continue
                            else:
                                logger.warning(f"Simulation failed with error: {sim_error}. Attempting actual transaction in case simulation is inaccurate.")
                        else:
                            logger.info("Transaction simulation successful, proceeding with actual transaction")
                        
                        # Try to update until successful or max retries reached
                        while not update_successful and retries < MAX_RETRIES:
                            # Call update function with retry count
                            success, error = self.call_update(retry_count=retries)

                            if success:
                                logger.info("Price cache update successful!")
                                update_successful = True
                                # Refresh contract data after successful update
                                self.refresh_contract_data()
                            else:
                                retries += 1

                                if error == "WaitForDelay":
                                    # If WaitForDelay error, calculate better wait time
                                    current_time = int(time.time())
                                    time_to_update = max(0, self.next_update_time - current_time)

                                    if time_to_update > 0:
                                        # If we know exactly how long to wait, use that
                                        wait_time = min(time_to_update + 1, 60)  # Cap at 60 seconds
                                        logger.info(f"WaitForDelay error. Next valid update in {time_to_update} seconds. Waiting {wait_time} seconds before retry {retries}/{MAX_RETRIES}...")
                                    else:
                                        # If we're already past the theoretical update time, use shorter wait
                                        wait_time = min(WAIT_FOR_DELAY_RETRY_TIME, 10)
                                        logger.info(f"WaitForDelay error despite being past update time. Waiting {wait_time} seconds before retry {retries}/{MAX_RETRIES}...")

                                    time.sleep(wait_time)
                                elif error == "OutOfGas":
                                    # If out of gas, alert the user and wait before retrying
                                    logger.critical("ATTENTION: Wallet needs to be topped up! Out of gas error.")
                                    print("\n" + "!" * 80)
                                    print("CRITICAL: Your wallet needs to be topped up! Transaction failed due to insufficient gas.")
                                    print("Please add funds to your wallet address: " + self.wallet_address)
                                    print("!" * 80 + "\n")
                                    time.sleep(5)  # Short wait before retry with higher gas price
                                elif error == "Underpriced":
                                    # For underpriced transactions, just retry with higher gas
                                    logger.warning("Transaction underpriced. Will retry with higher gas price.")
                                    time.sleep(5)  # Short wait before retry with higher gas price
                                elif error == "Timeout":
                                    # If timeout occurred, retry with higher gas price
                                    logger.warning(f"Transaction timeout. Will retry with higher gas price. Retry {retries}/{MAX_RETRIES}")
                                    time.sleep(10)  # Short wait before retry
                                elif error == "InvalidRange" or error == "NoDataAvailable":
                                    # These are contract-specific errors that may require manual intervention
                                    logger.error(f"Contract error {error}. This may require manual intervention. Retry {retries}/{MAX_RETRIES}")
                                    time.sleep(30)  # Longer wait for contract errors
                                elif error == "BadRequest":
                                    # Handle bad request errors from the node provider
                                    logger.error(f"Bad Request error from the node provider. Retry {retries}/{MAX_RETRIES}")
                                    time.sleep(15)  # Short wait
                                else:
                                    # For other errors, log and retry
                                    logger.error(f"Error: {error}. Retry {retries}/{MAX_RETRIES}")
                                    time.sleep(30)  # 30 seconds wait

                        if not update_successful:
                            logger.warning(f"Failed to update price cache after {MAX_RETRIES} attempts. Will try again later.")
                            # Wait a bit before checking again to avoid excessive logging
                            time.sleep(120)
                else:
                    # Check if we should run the fee update routine
                    # Only run if no price cache update is in progress
                    if not self.check_update_in_progress():
                        # Also check if a fee update was already done recently
                        if not self.check_recent_fee_update():
                            logger.info("Running fee update routine")
                            
                            # 1. Call get historical prices
                            historical_data = self.call_get_historical_prices()
                            if historical_data:
                                # 2. Call Lilith to get proof and dynamic fee
                                proof_result = self.call_lilith()
                                if proof_result:
                                    # Unpack the proof and instances
                                    _proof, _instances = proof_result
                                    
                                    # 3. Call update fee
                                    success, error = self.call_update_fee()
                                    if success:
                                        logger.info("Successfully updated fee")
                                    else:
                                        logger.error(f"Failed to update fee: {error}")
                                        # If the error is something we can recover from by waiting, 
                                        # the loop will continue and retry later
                                else:
                                    logger.error("Failed to get proof from Lilith")
                            else:
                                logger.error("Failed to get historical prices")
                        else:
                            logger.info("Skipping fee update routine - recent update detected")
                    else:
                        logger.info("Skipping fee update routine - price cache update in progress")
                    
                    # Calculate time remaining until next price cache update
                    time_remaining = self.time_to_next_update()

                    # Format time remaining nicely
                    if time_remaining > 0:
                        minutes, seconds = divmod(time_remaining, 60)
                        hours, minutes = divmod(minutes, 60)

                        if hours > 0:
                            time_str = f"{int(hours)}h {int(minutes)}m {int(seconds)}s"
                        else:
                            time_str = f"{int(minutes)}m {int(seconds)}s"

                        logger.info(f"Next price cache update in {time_str} (at {datetime.datetime.fromtimestamp(self.next_update_time).strftime('%Y-%m-%d %H:%M:%S')})")

                        # If we have more than 5 minutes, wait longer between checks
                        if time_remaining > 300:
                            sleep_time = min(time_remaining / 10, 300)  # At most 5 minute sleep
                        else:
                            sleep_time = CHECK_INTERVAL  # Check more frequently as we get closer

                        time.sleep(sleep_time)
                    else:
                        # Should not get here often, but just in case
                        logger.info("Time to price cache update has passed but not detected earlier. Checking again.")
                        time.sleep(5)

            except Exception as e:
                # Catch any unexpected errors in the main loop
                logger.error(f"Unexpected error in main loop: {e}")
                logger.error(f"Traceback: {traceback.format_exc()}")
                time.sleep(60)  # Wait a minute before continuing


def main():
    logger.info("Smart Contract Updater Starting")
    
    try:
        # Check if the secrets file exists and has the required variables
        required_vars = [
            'CACHE_CONTRACT_ADDRESS',
            'POOL_CONTRACT_ADDRESSES',
            'FEE_MANAGER_ADDRESS',
            'ETHEREUM_NODE_URL',
            'WALLET_PRIVATE_KEY',
            'WALLET_ADDRESS',
            'ARCHON_URL',
            'ARCHON_API_KEY',
            'ARCHON_USER_ID',
            'ARCHON_ARTIFACT',
            'ARCHON_DEPLOYMENT'
        ]
        missing_vars = []

        for var in required_vars:
            if not hasattr(secrets, var):
                missing_vars.append(var)

        if missing_vars:
            logger.error(f"Missing required variables in secrets file: {', '.join(missing_vars)}")
            raise ValueError(f"Missing required variables in secrets file: {', '.join(missing_vars)}")

        updater = ContractUpdater(
            CACHE_CONTRACT_ADDRESS,
            CACHE_CONTRACT_ABI,
            POOL_CONTRACT_ADDRESSES,
            FEE_MANAGER_ADDRESS,
            FEE_MANAGER_ABI,
            ETHEREUM_NODE_URL,
            WALLET_ADDRESS,
            WALLET_PRIVATE_KEY,
        )
        
        updater.run()
    except KeyboardInterrupt:
        logger.info("Script interrupted by user")
    except Exception as e:
        logger.critical(f"Fatal error: {e}")
        logger.critical(f"Traceback: {traceback.format_exc()}")
        raise


if __name__ == "__main__":
    main()