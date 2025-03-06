# Tools to populate timeseries onchain

## ChainlinkPriceCache.sol

This contract is meant to populate periodic prices off chainlink oracles. It allows users to get an array of prices for use in on-chain ML operations.

## cronjob.py

This is a python script that runs a periodic cronjob to update values onchain. Make sure to copy `secrets.py.example` to `secrets.py` and fill in the values.

The script will periodically call update() function based on the delay onchain
