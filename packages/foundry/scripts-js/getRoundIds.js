#!/usr/bin/env node

const { ethers } = require('ethers');
require('dotenv').config();

// Chainlink Aggregator Interface ABI (minimal required for our purposes)
const aggregatorABI = [
  "function latestRound() external view returns (uint256)",
  "function getTimestamp(uint256 roundId) external view returns (uint256)",
  "function getRoundData(uint80 _roundId) external view returns (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound)"
];

async function getRoundIds() {
  // Parse command line arguments
  const args = process.argv.slice(2);
  
  if (args.length !== 4) {
    console.error("Get Round Ids to populate the ChainlinkCache contract");
    console.error("Usage: node getRoundIds.js <oracle_address> <delay_seconds> <start_timestamp> <end_timestamp>");
    console.error("Example: node getRoundIds 0x639Fe6ab55C921f74e7fac1ee960C0B6293ba612 14400 1735718400 1741204800");
    process.exit(1);
  }
  
  const oracleAddress = args[0];
  const delaySeconds = parseInt(args[1]);
  const startTimestamp = parseInt(args[2]);
  const endTimestamp = parseInt(args[3]);
  
  // Connect to Ethereum node (using public providers)
  let provider;
  try {
    // Try provider in env
    // provider = new ethers.providers.JsonRpcProvider(process.env.MAINNET_RPC_URL);
    // provider = new ethers.providers.JsonRpcProvider(process.env.ARBITRUM_RPC_URL);
    provider = new ethers.providers.JsonRpcProvider(process.env.BASE_RPC_URL);
    await provider.getBlockNumber(); // Test connection
  } catch (error) {
    console.error("Failed to connect to Ethereum node:", error.message);
    process.exit(1);
  }
  
  const oracle = new ethers.Contract(oracleAddress, aggregatorABI, provider);
  
  console.log(`\nFetching round data for Oracle: ${oracleAddress}`);
  console.log(`Delay: ${delaySeconds} seconds`);
  console.log(`Time Range: ${new Date(startTimestamp * 1000).toISOString()} to ${new Date(endTimestamp * 1000).toISOString()}\n`);
  
  try {
    // Get the latest round as a starting point
    const latestRound = await oracle.latestRound();
    console.log(`Latest Round ID: ${latestRound.toString()}`);
    
    // Initialize variables
    const roundIds = [];
    let lastTimestamp = 99999999999;
    
    // Start from the latest round and go backwards
    for (let i = 0; i < 10000; i++) { // Limit to 1000 iterations for safety
      try {
        // Calculate the round ID to check (decreasing from latest)
        const roundToCheck = latestRound.sub(i);
        
        // Get the timestamp for this round
        const timestamp = await oracle.getTimestamp(roundToCheck);
        
        // If we've gone earlier than our start timestamp, break
        if (timestamp < startTimestamp) {
          break;
        }
        
        // if no round is populated and the timestamp is roughly within the range of endTimestamp, add it into the array
        if (roundIds.length === 0) {
          // console.log("No roundIds populated yet")
          if (timestamp <= endTimestamp) {
            roundIds.push(roundToCheck.toString()); // Add to the beginning to maintain chronological order
            lastTimestamp = timestamp;
            console.log(`Found Round ID: ${roundToCheck.toString()}, Timestamp: ${new Date(timestamp * 1000).toISOString()}`);
          }
        }
        else {
          if (timestamp <= (lastTimestamp - delaySeconds)) {
            roundIds.unshift(roundToCheck.toString()); // Add to the beginning to maintain chronological order
            lastTimestamp = timestamp;
            console.log(`Found Round ID: ${roundToCheck.toString()}, Timestamp: ${new Date(timestamp * 1000).toISOString()}`);
          }
        }
      } catch (error) {
        // Skip rounds that have errors (might be phase changes)
        console.log(error);
        continue;
      }
    }
    
    // Prepare constructor arguments
    if (roundIds.length > 0) {
      console.log(`\nFound ${roundIds.length} rounds that meet the criteria.`);
      console.log(`\nConstructor Arguments:`);
      console.log(`Oracle Address: ${oracleAddress}`);
      console.log(`Delay: ${delaySeconds}`);
      console.log(`Round IDs: [${roundIds.join(', ')}]`);
      
      // Format for Solidity constructor call
      console.log(`\nSolidity constructor call:`);
      console.log(`new ChainlinkCache(${oracleAddress}, ${delaySeconds}, [${roundIds.join(', ')}])`);
    } else {
      console.log(`\nNo rounds found meeting the criteria.`);
    }
    
  } catch (error) {
    console.error("Error fetching data:", error.message);
    process.exit(1);
  }
}

// Execute the main function
getRoundIds().catch(console.error);