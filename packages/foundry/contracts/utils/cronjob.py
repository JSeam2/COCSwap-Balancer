import time
import json
import logging
import datetime
from web3 import Web3
from web3.exceptions import ContractLogicError
import secrets
import traceback

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("contract_updater.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("ContractUpdater")

# Contract information
CACHE_CONTRACT_ADDRESS = secrets.CACHE_CONTRACT_ADDRESS
CACHE_CONTRACT_ABI = json.loads('''
[{"inputs":[{"internalType":"string","name":"_description","type":"string"},{"internalType":"address","name":"_oracle","type":"address"},{"internalType":"uint256","name":"_delay","type":"uint256"},{"internalType":"uint256[]","name":"_roundIds","type":"uint256[]"}],"stateMutability":"nonpayable","type":"constructor"},{"inputs":[],"name":"InvalidRange","type":"error"},{"inputs":[],"name":"NoDataAvailable","type":"error"},{"inputs":[],"name":"WaitForDelay","type":"error"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"uint256","name":"timestamp","type":"uint256"},{"indexed":false,"internalType":"uint256","name":"price","type":"uint256"}],"name":"Updated","type":"event"},{"inputs":[],"name":"delay","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"description","outputs":[{"internalType":"string","name":"","type":"string"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"uint256","name":"lookback","type":"uint256"}],"name":"getHistoricalPrice","outputs":[{"internalType":"uint256[]","name":"","type":"uint256[]"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"uint256","name":"start","type":"uint256"},{"internalType":"uint256","name":"end","type":"uint256"}],"name":"getHistoricalPriceRange","outputs":[{"internalType":"uint256[]","name":"","type":"uint256[]"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"uint256","name":"lookback","type":"uint256"}],"name":"getHistoricalTimestamp","outputs":[{"internalType":"uint256[]","name":"","type":"uint256[]"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"uint256","name":"start","type":"uint256"},{"internalType":"uint256","name":"end","type":"uint256"}],"name":"getHistoricalTimestampRange","outputs":[{"internalType":"uint256[]","name":"","type":"uint256[]"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"latestSnapshotId","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"oracle","outputs":[{"internalType":"contract IAggregatorInterface","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"uint256","name":"","type":"uint256"}],"name":"prices","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"uint256","name":"","type":"uint256"}],"name":"timestamps","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"update","outputs":[],"stateMutability":"nonpayable","type":"function"}]
''')

ETHEREUM_NODE_URL = secrets.ETHEREUM_NODE_URL

# Wallet configuration
WALLET_PRIVATE_KEY = secrets.WALLET_PRIVATE_KEY
WALLET_ADDRESS = secrets.WALLET_ADDRESS

# Constants
WAIT_FOR_DELAY_RETRY_TIME = 30  # seconds
DEBUG_MODE = True  # Set to True for more verbose debugging
UPDATE_WINDOW_BUFFER = 60  # seconds before the next valid update time to start attempting updates
CHECK_INTERVAL = 15  # seconds between each check when waiting
MAX_RETRIES = 5  # Maximum number of retries on failure

# Error signatures from contract
ERROR_WAIT_FOR_DELAY = "0x11c973a0"  # Hex signature for WaitForDelay error
ERROR_INVALID_RANGE = "0x2105b620"   # Hex signature for InvalidRange error
ERROR_NO_DATA_AVAILABLE = "0x390d9a43"  # Hex signature for NoDataAvailable error


class ContractUpdater:
    def __init__(self, node_url, contract_address, contract_abi, wallet_address, private_key):
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

            self.contract_address = Web3.to_checksum_address(contract_address)
            logger.info(f"Using contract address: {self.contract_address}")
            self.contract = self.w3.eth.contract(address=self.contract_address, abi=contract_abi)

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
            if DEBUG_MODE:
                logger.error(f"Traceback: {traceback.format_exc()}")
            raise

    def refresh_contract_data(self):
        """Refresh all contract data"""
        try:
            # Get contract description
            self.description = self.contract.functions.description().call()
            logger.info(f"Contract description: {self.description}")

            # Get delay value
            self.delay = self.contract.functions.delay().call()
            logger.info(f"Contract delay: {self.delay} seconds")

            # Get latest snapshot ID
            self.latest_snapshot_id = self.contract.functions.latestSnapshotId().call()
            logger.info(f"Latest snapshot ID: {self.latest_snapshot_id}")

            # Get latest timestamp
            self.latest_timestamp = self.contract.functions.timestamps(self.latest_snapshot_id).call()

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
            if DEBUG_MODE:
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

    def call_update(self, retry_count=0):
        """Call the update function on the contract with gas price adjustments on retries"""
        try:
            # Get base gas price
            base_gas_price = self.w3.eth.gas_price
            
            # Apply gas price multiplier based on retry count (10% increase per retry)
            multiplier = 1.0 + (retry_count * 0.2)  # 20% increase per retry
            gas_price = int(base_gas_price * multiplier)
            
            gas_price_gwei = self.w3.from_wei(gas_price, 'gwei')
            logger.info(f"Using gas price: {gas_price_gwei} Gwei (retry {retry_count}, multiplier {multiplier:.2f}x)")

            # Get the transaction count for nonce
            nonce = self.w3.eth.get_transaction_count(self.wallet_address)
            logger.info(f"Using nonce: {nonce}")
            
            # Use a fixed gas limit instead of estimating
            # This bypasses the estimate_gas call which can trigger the custom error
            gas_limit = 130000  # Fixed gas limit that should be sufficient for most update calls
            logger.info(f"Using fixed gas limit: {gas_limit}")

            # Build the transaction with fixed gas limit and adjusted gas price
            tx = self.contract.functions.update().build_transaction({
                'from': self.wallet_address,
                'nonce': nonce,
                'gas': gas_limit,
                'gasPrice': gas_price,
                'chainId': self.w3.eth.chain_id,
            })

            # Debug transaction details
            if DEBUG_MODE:
                logger.info(f"Transaction details: {tx}")

            # Sign the transaction
            signed_tx = self.w3.eth.account.sign_transaction(tx, self.private_key)
            logger.info(f"Transaction signed. Hash: {self.w3.to_hex(self.w3.keccak(signed_tx.raw_transaction))}")

            # Send the transaction
            tx_hash = self.w3.eth.send_raw_transaction(signed_tx.raw_transaction)
            logger.info(f"Update transaction sent: {tx_hash.hex()}")
            
            # Wait for transaction receipt with a timeout
            try:
                receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
                logger.info(f"Transaction confirmed in block {receipt['blockNumber']}")
                
                # Check status of transaction
                if receipt['status'] == 1:
                    logger.info(f"Transaction succeeded. Gas used: {receipt['gasUsed']}")
                    return True, None
                else:
                    logger.error(f"Transaction failed. Gas used: {receipt['gasUsed']}")
                    return False, "Transaction failed"
            except Exception as timeout_error:
                logger.warning(f"Transaction may be pending: {str(timeout_error)}")
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
                if DEBUG_MODE:
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
                if DEBUG_MODE:
                    logger.error(f"Traceback: {traceback.format_exc()}")
                return False, "BadRequest"
            else:
                logger.error(f"Error calling update function: {error_message}")
                if DEBUG_MODE:
                    logger.error(f"Traceback: {traceback.format_exc()}")
                return False, str(e)

    def run(self):
        """Run the updater loop with intelligent timing"""
        logger.info("Starting contract updater with intelligent timing")
        
        while True:
            try:
                # Refresh contract data including latest timestamp and delay
                self.refresh_contract_data()

                # Check if it's time to update
                if self.is_update_time():
                    logger.info("It's time to attempt the update")

                    # Initialize retry counter
                    retries = 0
                    update_successful = False

                    # Try to update until successful or max retries reached
                    while not update_successful and retries < MAX_RETRIES:
                        # Call update function with retry count
                        success, error = self.call_update(retry_count=retries)

                        if success:
                            logger.info("Update successful!")
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
                                time.sleep(15)  # Short wait

                    if not update_successful:
                        logger.warning(f"Failed to update after {MAX_RETRIES} attempts. Will try again later.")
                        # Wait a bit before checking again to avoid excessive logging
                        time.sleep(60)
                else:
                    # Not yet time to update
                    time_remaining = self.time_to_next_update()

                    # Format time remaining nicely
                    if time_remaining > 0:
                        minutes, seconds = divmod(time_remaining, 60)
                        hours, minutes = divmod(minutes, 60)

                        if hours > 0:
                            time_str = f"{int(hours)}h {int(minutes)}m {int(seconds)}s"
                        else:
                            time_str = f"{int(minutes)}m {int(seconds)}s"

                        logger.info(f"Next update in {time_str} (at {datetime.datetime.fromtimestamp(self.next_update_time).strftime('%Y-%m-%d %H:%M:%S')})")

                        # If we have more than 5 minutes, wait longer between checks
                        if time_remaining > 300:
                            sleep_time = min(time_remaining / 10, 300)  # At most 5 minute sleep
                        else:
                            sleep_time = CHECK_INTERVAL  # Check more frequently as we get closer

                        time.sleep(sleep_time)
                    else:
                        # Should not get here often, but just in case
                        logger.info("Time to update has passed but not detected earlier. Checking again.")
                        time.sleep(5)

            except Exception as e:
                # Catch any unexpected errors in the main loop
                logger.error(f"Unexpected error in main loop: {e}")
                if DEBUG_MODE:
                    logger.error(f"Traceback: {traceback.format_exc()}")
                time.sleep(60)  # Wait a minute before continuing


def main():
    logger.info("Smart Contract Updater Starting")
    
    try:
        # Check if the secrets file exists and has the required variables
        required_vars = ['CACHE_CONTRACT_ADDRESS', 'ETHEREUM_NODE_URL', 'WALLET_PRIVATE_KEY', 'WALLET_ADDRESS']
        missing_vars = []

        for var in required_vars:
            if not hasattr(secrets, var):
                missing_vars.append(var)

        if missing_vars:
            logger.error(f"Missing required variables in secrets file: {', '.join(missing_vars)}")
            raise ValueError(f"Missing required variables in secrets file: {', '.join(missing_vars)}")

        updater = ContractUpdater(
            ETHEREUM_NODE_URL,
            CACHE_CONTRACT_ADDRESS,
            CACHE_CONTRACT_ABI,
            WALLET_ADDRESS,
            WALLET_PRIVATE_KEY
        )
        
        updater.run()
    except KeyboardInterrupt:
        logger.info("Script interrupted by user")
    except Exception as e:
        logger.critical(f"Fatal error: {e}")
        if DEBUG_MODE:
            logger.critical(f"Traceback: {traceback.format_exc()}")
        raise


if __name__ == "__main__":
    main()