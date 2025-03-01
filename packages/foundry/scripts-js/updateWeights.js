const { ethers } = require('ethers');
require('dotenv').config();
const fs = require('fs');
const path = require('path');

// Read deployed contract info
const getDeployedContracts = () => {
  const deployedContractsPath = path.join(__dirname, '../../nextjs/contracts/deployedContracts.ts');
  const content = fs.readFileSync(deployedContractsPath, 'utf8');
  
  // Extract the JSON part from the TypeScript file
  const jsonMatch = content.match(/const deployedContracts = (.+?) as const;/s);
  if (!jsonMatch) {
    throw new Error('Could not find deployedContracts in the TS file');
  }
  
  // Parse the JSON string
  return eval(`(${jsonMatch[1]})`);
};

async function main() {
  const argv = process.argv.slice(2);
  
  if (argv.length < 4) {
    console.error('Usage: node updateWeights.js <action> <networkId> <poolAddress> <proofPath>');
    console.error('  action: "updateWeights" or "rebalance"');
    console.error('  networkId: The network ID (e.g., 31337 for local, 1 for mainnet)');
    console.error('  poolAddress: The address of the pool to update');
    console.error('  proofPath: Path to the proof file for updateWeights or pathDefinition for rebalance');
    process.exit(1);
  }

  const action = argv[0];
  const networkId = argv[1];
  const poolAddress = argv[2];
  const proofPath = argv[3];

  // Check if the action is valid
  if (action !== 'updateWeights' && action !== 'rebalance') {
    console.error('Invalid action. Must be "updateWeights" or "rebalance"');
    process.exit(1);
  }

  try {
    // Handle both relative and absolute paths
    let resolvedProofPath = proofPath;
    
    // If it's a relative path that includes 'packages/foundry', 
    // adjust it to avoid duplication when running from the package workspace
    if (proofPath.startsWith('./packages/foundry') && process.cwd().includes('packages/foundry')) {
      resolvedProofPath = proofPath.replace('./packages/foundry', '.');
    }
    
    // If it's just a relative path, resolve it
    if (resolvedProofPath.startsWith('./') || resolvedProofPath.startsWith('../')) {
      resolvedProofPath = path.resolve(process.cwd(), resolvedProofPath);
    }
    
    console.log(`Looking for proof file at: ${resolvedProofPath}`);
    
    // Read proof file
    const proofData = fs.readFileSync(resolvedProofPath, 'utf8');
    const proof = JSON.parse(proofData);

    // Connect to provider
    let provider;
    if (networkId === '31337') {
      console.log("Attempting to connect to local Anvil node...");
      try {
        // Add additional debugging
        provider = new ethers.providers.JsonRpcProvider('http://localhost:8545');
        console.log("Provider created, testing connection...");
        
        // Make a simple call to check the connection
        const blockNumber = await provider.getBlockNumber();
        console.log(`Successfully connected to Anvil on port 8545. Current block: ${blockNumber}`);
      } catch (error) {
        console.error("Error connecting to Anvil:", error.message);
        throw new Error("Could not connect to a local Ethereum node. Make sure Anvil is running on port 8545.");
      }
    } else {
      // For non-local networks, use environment variable or a default RPC URL
      const rpcUrl = process.env.RPC_URL || `https://eth-mainnet.alchemyapi.io/v2/${process.env.ALCHEMY_API_KEY}`;
      provider = new ethers.providers.JsonRpcProvider(rpcUrl);
    }

    // Get wallet from private key
    const privateKey = process.env.DEPLOYER_PRIVATE_KEY;
    if (!privateKey) {
      throw new Error('Private key not found in environment variables');
    }
    const wallet = new ethers.Wallet(privateKey, provider);

    // Get ABI from deployed contracts or use local ABI
    let contractAbi;
    try {
      const deployedContracts = getDeployedContracts();
      const contractInfo = deployedContracts[networkId]?.contracts?.['COCSwapPool'];
      
      if (contractInfo) {
        contractAbi = contractInfo.abi;
      } else {
        console.log("Contract info not found in deployedContracts.ts, trying to load abi from file");
        // For local development, use the ABI from the output directory
        const cocSwapPoolAbiPath = path.join(__dirname, '../out/COCSwapPool.sol/COCSwapPool.json');
        const cocSwapPoolJson = JSON.parse(fs.readFileSync(cocSwapPoolAbiPath, 'utf8'));
        contractAbi = cocSwapPoolJson.abi;
      }
    } catch (error) {
      console.error("Error loading contract ABI:", error);
      throw new Error(`Failed to load contract ABI for network ID ${networkId}`);
    }

    // Create contract instance using the provided pool address
    console.log(`Using pool address: ${poolAddress}`);
    const contract = new ethers.Contract(poolAddress, contractAbi, wallet);

    // Execute the action
    let tx;
    if (action === 'updateWeights') {
      // Use hex_proof for the proof string and pretty_public_inputs.outputs for instances
      const hexProof = proof.hex_proof;
      
      // Extract instances from pretty_public_inputs.outputs
      let instances;
      if (proof.pretty_public_inputs && proof.pretty_public_inputs.outputs && proof.pretty_public_inputs.outputs.length > 0) {
        instances = proof.pretty_public_inputs.outputs[0].map(i => ethers.BigNumber.from(i));
      } else {
        throw new Error('Instances not found in pretty_public_inputs.outputs');
      }

      console.log(`Updating weights with proof from: ${proofPath}`);
      console.log(`Instances (weights): ${instances.map(i => i.toString()).join(', ')}`);
      
      tx = await contract.updateWeights(hexProof, instances);
    } else {
      // For rebalance, we need the pathDefinition
      let pathDefinition = proof.pathDefinition || proof;

      console.log(`Rebalancing with path definition from: ${proofPath}`);
      
      tx = await contract.rebalance(pathDefinition);
    }

    console.log(`Transaction sent with hash: ${tx.hash}`);
    const receipt = await tx.wait();
    console.log(`Transaction confirmed in block ${receipt.blockNumber}`);
    console.log(`Gas used: ${receipt.gasUsed.toString()}`);
    console.log(`Status: ${receipt.status === 1 ? 'Success' : 'Failed'}`);

  } catch (error) {
    console.error('Error:', error);
    process.exit(1);
  }
}

main();