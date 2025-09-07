const express = require("express");
const cors = require("cors");
const dotenv = require("dotenv");
const Web3 = require("web3");
const http = require("http");
const socketIo = require("socket.io");
const mysql = require("mysql2/promise");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const solc = require("solc");
const semver = require('semver');
const { ethers } = require("ethers");



const {
  getAllTokenBalances,
  getTokenTransactions,
  getTokenHolders,
  getKnownTokenContracts,
  indexContractsFromChain,
  indexTransactionsFromChain,
  getDataBaseTransactions,
} = require("./utils");


const { dbService } = require('./database.service');

const db = mysql.createPool({
  host: "localhost",
  user: "root",
  password: "P@55word",
  database: "ucc_chain_test",
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});

// Load environment variables
dotenv.config();

// Configuration
const JWT_SECRET = process.env.JWT_SECRET || "your_jwt_secret_here";
const SALT_ROUNDS = parseInt(process.env.SALT_ROUNDS) || 10;

// Create Express app
const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(
  cors({
    origin: ["http://localhost:3000", "https://ucscan.net"],
    methods: ["GET", "POST"],
  })
);
app.use(express.json());
app.use(express.static("public"));

const RPC_WS = "ws://168.231.122.245:8546";
const RPC_API = "https://rpc.ucscan.net";

// Initialize Web3 with the RPC endpoint
const web3 = new Web3(RPC_API);
const web3Ws = new Web3(RPC_WS);

// Helper function to extract imports from source code
function extractImports(sourceCode) {
  const imports = [];
  const importRegex = /import\s+["']([^"']+)["'];/g;
  let match;

  while ((match = importRegex.exec(sourceCode)) !== null) {
    imports.push(match[1]);
  }

  return imports;
}

// Helper function to build source tree (simplified - you'd need to implement actual file resolution)
async function buildSourceTree(mainSource, imports) {
  const sources = {
    "main.sol": { content: mainSource },
  };

  return sources;
}

// Helper function to detect appropriate EVM version
function detectEvmVersion(compilerVersion) {
  const version = compilerVersion.replace("v", "");
  const [major, minor] = version.split(".").map(Number);

  if (major === 0 && minor <= 4) {
    return "homestead";
  } else if (major === 0 && minor <= 5) {
    return "byzantium";
  } else if (major === 0 && minor <= 6) {
    return "constantinople";
  } else if (major === 0 && minor <= 7) {
    return "istanbul";
  } else if (major === 0 && minor <= 8 && minor < 5) {
    return "berlin";
  } else {
    return "london";
  }
}

// Enhanced bytecode normalization
function advancedNormalizeBytecode(bytecode) {
  if (!bytecode || bytecode === "0x") return "";

  let clean = bytecode.startsWith("0x") ? bytecode.slice(2) : bytecode;
  clean = clean.toLowerCase();

  // Remove common metadata patterns
  const metadataPatterns = [
    /a165627a7a72305820[a-f0-9]{64}0029$/, // Swarm hash v0
    /a265627a7a72305820[a-f0-9]{64}0029$/, // Swarm hash v1
    /a2646970667358[a-f0-9]{68}64736f6c63[a-f0-9]{6}0033$/, // IPFS hash
    /a264697066735822[a-f0-9]{68}64736f6c63[a-f0-9]{6}0033$/, // IPFS hash variant
  ];

  for (const pattern of metadataPatterns) {
    clean = clean.replace(pattern, "");
  }

  // Try to remove metadata based on length encoding
  if (clean.length >= 4) {
    try {
      const last4 = clean.slice(-4);
      const metadataLength = parseInt(last4, 16);

      if (
        metadataLength > 0 &&
        metadataLength < 2000 &&
        metadataLength * 2 + 4 <= clean.length
      ) {
        const potentialMetadata = clean.slice(-(metadataLength * 2 + 4), -4);

        // Check if it looks like metadata (contains known patterns)
        if (
          potentialMetadata.includes("627a7a72305820") ||
          potentialMetadata.includes("646970667358") ||
          potentialMetadata.includes("736f6c63")
        ) {
          clean = clean.slice(0, -(metadataLength * 2 + 4));
        }
      }
    } catch (e) {}
  }

  if (clean.length > 100) {
    const potentialArgsStart = Math.max(0, clean.length - 500);
    const potentialArgs = clean.slice(potentialArgsStart);

    // If we see padded addresses or common patterns, try to remove them
    if (potentialArgs.includes("000000000000000000000000")) {
    }
  }

  return clean;
}

// Exact match comparison
function compareExactMatch(onchain, compiled) {
  if (!onchain || !compiled) return 0;
  return onchain === compiled ? 100 : 0;
}

// Fuzzy match comparison (allows for small differences)
function compareFuzzyMatch(onchain, compiled) {
  if (!onchain || !compiled) return 0;

  const maxLength = Math.max(onchain.length, compiled.length);
  const minLength = Math.min(onchain.length, compiled.length);

  if (maxLength === 0) return 100;

  let matches = 0;
  for (let i = 0; i < minLength; i++) {
    if (onchain[i] === compiled[i]) {
      matches++;
    }
  }

  return Math.round((matches / maxLength) * 100);
}

// Structural match comparison (ignores metadata and focuses on core logic)
function compareStructuralMatch(onchain, compiled) {
  if (!onchain || !compiled) return 0;

  // Extract function signatures and core opcodes
  const onchainStructure = extractBytecodeStructure(onchain);
  const compiledStructure = extractBytecodeStructure(compiled);

  if (onchainStructure === compiledStructure) {
    return 100;
  }

  // Calculate similarity based on common opcodes and patterns
  const onchainOpcodes = extractOpcodes(onchain);
  const compiledOpcodes = extractOpcodes(compiled);

  const commonOpcodes = onchainOpcodes.filter((op) =>
    compiledOpcodes.includes(op)
  );
  const totalOpcodes = new Set([...onchainOpcodes, ...compiledOpcodes]).size;

  return totalOpcodes > 0
    ? Math.round((commonOpcodes.length / totalOpcodes) * 100)
    : 0;
}

// Extract bytecode structure (simplified)
function extractBytecodeStructure(bytecode) {
  // Look for function dispatch patterns, jump destinations, etc.
  const patterns = [
    /60806040/,
    /5b(?:60|61|62|63)/,
    /63[a-f0-9]{8}/,
    /73[a-f0-9]{40}/,
  ];

  let structure = "";
  for (const pattern of patterns) {
    const matches = bytecode.match(new RegExp(pattern.source, "g")) || [];
    structure += matches.join(",") + "|";
  }

  return structure;
}

// Extract opcodes for comparison
function extractOpcodes(bytecode) {
  const opcodes = [];
  for (let i = 0; i < bytecode.length; i += 2) {
    const opcode = bytecode.slice(i, i + 2);
    opcodes.push(opcode);
  }
  return opcodes;
}

// Simulate deployment to handle constructor arguments
function simulateDeployment(
  creationBytecode,
  constructorArgs,
  targetDeployedBytecode
) {
  try {
    if (!constructorArgs || constructorArgs === "0x") {
      return null;
    }

    // Remove 0x prefix from constructor args
    const cleanArgs = constructorArgs.startsWith("0x")
      ? constructorArgs.slice(2)
      : constructorArgs;

    const withArgs = creationBytecode + cleanArgs;

    return null;
  } catch (e) {
    return null;
  }
}

// Generate helpful suggestions for failed verifications
function generateVerificationSuggestions(matchPercentage, bestMatch) {
  const suggestions = [];

  if (matchPercentage > 90) {
    suggestions.push(
      "Try different optimization settings (enabled/disabled or different runs count)"
    );
    suggestions.push("Check if constructor arguments are needed");
    suggestions.push(
      "Verify the exact compiler version used during deployment"
    );
  } else if (matchPercentage > 70) {
    suggestions.push("Check for imported library versions and addresses");
    suggestions.push("Verify all source files are included if using imports");
    suggestions.push("Try different EVM versions in compiler settings");
  } else {
    suggestions.push("Verify you have the correct source code");
    suggestions.push(
      "Check if this is a proxy contract pointing to an implementation"
    );
    suggestions.push("Ensure the contract name matches the deployed contract");
  }

  return suggestions;
}

async function getContractVerificationData(address) {
  let conn;
  try {
    conn = await db.getConnection();

    // Fetch contract verification data from your database
    const [rows] = await conn.execute(
      `SELECT 
        contractName, solSource, version, isOptimized, runs,
        abi, isVerified, verificationMessage, verifiedAt,
        constructorArgs, metadata, functionSignatures, eventSignatures,
        matchPercentage, compiledBytecodeLength, onchainBytecodeLength,
        address, updatedAt
      FROM contracts 
      WHERE address = ?`,
      [address]
    );

    if (rows.length === 0) {
      // Contract exists on-chain but not verified in our database
      return {
        isVerified: false,
        verificationStatus: "unverified",
        message:
          "Contract not verified. You can verify it using our verification service.",
        abi: null,
        sourceCode: null,
        functions: [],
        events: [],
      };
    }

    const contract = rows[0];
    // console.log("Fetched contract data:", contract);

    // Parse JSON fields safely
    const abi = safeParseJSON(contract.abi, []);
    const metadata = safeParseJSON(contract.metadata, {});
    const functionSigs = safeParseJSON(contract.functionSignatures, {});
    const eventSigs = safeParseJSON(contract.eventSignatures, {});

    // Return comprehensive contract info
    return {
      // Verification status - THIS IS THE KEY FIX
      isVerified: Boolean(contract.isVerified), // Ensure this converts 1/0 to true/false
      verificationStatus: contract.isVerified ? "verified" : "unverified",
      verificationMessage: contract.verificationMessage,
      verifiedAt: contract.verifiedAt,
      matchPercentage: contract.matchPercentage,

      // Contract details
      name: contract.contractName,
      sourceCode: contract.isVerified ? contract.solSource : null, // Only show source if verified
      abi: contract.isVerified ? abi : null, // Only show ABI if verified

      // Compilation info
      compiler: {
        version: contract.version,
        optimization: {
          enabled: Boolean(contract.isOptimized),
          runs: contract.runs,
        },
      },

      // Contract interface (parsed for easy use)
      functions: extractFunctionsFromAbi(abi),
      events: extractEventsFromAbi(abi),

      // Token info (if it's a token contract)
      token: {
        type: contract.type,
        symbol: contract.symbol,
        totalSupply: contract.totalSupply,
        decimals: contract.decimals,
      },

      // Creation info
      creation: {
        creator: contract.creator,
        blockNumber: contract.blockNumber,
        timestamp: contract.timestamp,
      },

      // Technical details
      bytecode: {
        compiledLength: contract.compiledBytecodeLength,
        onchainLength: contract.onchainBytecodeLength,
      },

      // Additional metadata
      metadata: metadata,
      constructorArguments: contract.constructorArgs,
    };
  } catch (error) {
    console.error("Error fetching contract verification data:", error);
    return {
      isVerified: false,
      verificationStatus: "error",
      message: "Error fetching contract verification data",
      abi: null,
      sourceCode: null,
    };
  } finally {
    if (conn) {
      try {
        conn.release();
      } catch (releaseError) {
        console.error("Error releasing connection:", releaseError);
      }
    }
  }
}

// Safe JSON parsing with fallback
function safeParseJSON(jsonString, defaultValue = []) {
  if (!jsonString) return defaultValue;

  try {
    return JSON.parse(jsonString);
  } catch (error) {
    console.warn("Failed to parse JSON:", error.message);
    return defaultValue;
  }
}

function extractContractData(contract, contractName) {
  if (!contract) return null;

  return {
    name: contractName,
    metadata: contract.metadata || {},
    functionSignatures: extractFunctionSignatures(contract.abi || []),
    eventSignatures: extractEventSignatures(contract.abi || []),
  };
}

// Helper function to extract function signatures
function extractFunctionSignatures(abi) {
  return abi
    .filter((item) => item.type === "function")
    .reduce((acc, fn) => {
      const signature = `${fn.name}(${fn.inputs
        ?.map((i) => i.type)
        .join(",")})`;
      acc[signature] = fn;
      return acc;
    }, {});
}

// Helper function to extract event signatures
function extractEventSignatures(abi) {
  return abi
    .filter((item) => item.type === "event")
    .reduce((acc, event) => {
      const signature = `${event.name}(${event.inputs
        ?.map((i) => i.type)
        .join(",")})`;
      acc[signature] = event;
      return acc;
    }, {});
}

// Extract functions from ABI for frontend display
function extractFunctionsFromAbi(abi) {
  if (!Array.isArray(abi)) return [];

  return abi
    .filter((item) => item.type === "function")
    .map((fn) => ({
      name: fn.name,
      signature: `${fn.name}(${fn.inputs?.map((i) => i.type).join(",") || ""})`,
      inputs: fn.inputs || [],
      outputs: fn.outputs || [],
      stateMutability: fn.stateMutability || "nonpayable",
      payable: fn.stateMutability === "payable",
      constant: fn.stateMutability === "view" || fn.stateMutability === "pure",
    }));
}

// Extract events from ABI for frontend display
function extractEventsFromAbi(abi) {
  if (!Array.isArray(abi)) return [];

  return abi
    .filter((item) => item.type === "event")
    .map((event) => ({
      name: event.name,
      signature: `${event.name}(${
        event.inputs?.map((i) => i.type).join(",") || ""
      })`,
      inputs: event.inputs || [],
      anonymous: event.anonymous || false,
    }));
}

// Enhanced compiler loading with multiple fallback strategies
async function loadCompilerVersion(version) {
  console.log(`Attempting to load compiler version: ${version}`);
  
  // Normalize version format
  let normalizedVersion = normalizeCompilerVersion(version);
  console.log(`Normalized version: ${normalizedVersion}`);

  // Strategy 1: Try exact version match
  try {
    const compiler = await loadWithTimeout(normalizedVersion, 30000);
    console.log(`Successfully loaded compiler version: ${normalizedVersion}`);
    return compiler;
  } catch (error) {
    console.warn(`Failed to load exact version ${normalizedVersion}:`, error.message);
  }

  // Strategy 2: Try with 'v' prefix if not present
  if (!normalizedVersion.startsWith('v')) {
    const versionWithV = 'v' + normalizedVersion;
    try {
      const compiler = await loadWithTimeout(versionWithV, 30000);
      console.log(`Successfully loaded compiler version with 'v' prefix: ${versionWithV}`);
      return compiler;
    } catch (error) {
      console.warn(`Failed to load version with 'v' prefix ${versionWithV}:`, error.message);
    }
  }

  // Strategy 3: Try without 'v' prefix if present
  if (normalizedVersion.startsWith('v')) {
    const versionWithoutV = normalizedVersion.substring(1);
    try {
      const compiler = await loadWithTimeout(versionWithoutV, 30000);
      console.log(`Successfully loaded compiler version without 'v' prefix: ${versionWithoutV}`);
      return compiler;
    } catch (error) {
      console.warn(`Failed to load version without 'v' prefix ${versionWithoutV}:`, error.message);
    }
  }

  // Strategy 4: Try finding compatible version from available releases
  try {
    const availableVersions = await getAvailableVersions();
    const compatibleVersion = findCompatibleVersion(normalizedVersion, availableVersions);
    
    if (compatibleVersion) {
      const compiler = await loadWithTimeout(compatibleVersion, 30000);
      console.log(`Successfully loaded compatible compiler version: ${compatibleVersion}`);
      return compiler;
    }
  } catch (error) {
    console.warn('Failed to load compatible version:', error.message);
  }

  throw new Error(`Unable to load compiler version ${version}. Please check if the version exists and try formats like "0.8.19", "v0.8.19", or "0.8.19+commit.7dd6d404"`);
}

function normalizeCompilerVersion(version) {
  if (!version) throw new Error('Version is required');
  
  // Remove any whitespace
  version = version.trim();
  
  // If it's already a full release name, return as is
  if (version.includes('+commit.') || version.startsWith('v') && version.includes('+commit.')) {
    return version;
  }
  
  // If it's just a version number like "0.8.19", try to find the exact release
  if (/^\d+\.\d+\.\d+$/.test(version)) {
    return version;
  }
  
  // If it starts with 'v', remove it for now
  if (version.startsWith('v')) {
    return version.substring(1);
  }
  
  return version;
}

function loadWithTimeout(version, timeout = 30000) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(new Error(`Compiler loading timeout after ${timeout}ms for version ${version}`));
    }, timeout);

    try {
      solc.loadRemoteVersion(version, (err, solcSnapshot) => {
        clearTimeout(timer);
        if (err) {
          console.error(`Compiler loading error for ${version}:`, err);
          return reject(new Error(`Failed to load compiler version ${version}: ${err.message || err}`));
        }
        
        if (!solcSnapshot) {
          return reject(new Error(`Received null compiler snapshot for version ${version}`));
        }
        
        resolve(solcSnapshot);
      });
    } catch (syncError) {
      clearTimeout(timer);
      reject(new Error(`Synchronous error loading compiler ${version}: ${syncError.message}`));
    }
  });
}

async function getAvailableVersions() {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      reject(new Error('Timeout fetching available compiler versions'));
    }, 10000);

    try {
      solc.loadRemoteVersion('latest', (err, solcSnapshot) => {
        clearTimeout(timeout);
        if (err) {
          return reject(new Error(`Failed to fetch available versions: ${err.message}`));
        }
        
        // This is a fallback - in practice you might want to use the solc releases API
        // For now, return some common versions
        resolve([
          'v0.8.24+commit.e11b9ed9',
          'v0.8.23+commit.f704f362', 
          'v0.8.22+commit.4fc1097e',
          'v0.8.21+commit.d9974bed',
          'v0.8.20+commit.a1b79de6',
          'v0.8.19+commit.7dd6d404',
          'v0.8.18+commit.87f61d96',
          'v0.8.17+commit.8df45f5f',
          'v0.8.16+commit.07c72cc5',
          'v0.8.15+commit.e14f2714'
        ]);
      });
    } catch (error) {
      clearTimeout(timeout);
      reject(error);
    }
  });
}

function findCompatibleVersion(requestedVersion, availableVersions) {
  // Remove 'v' prefix for comparison
  const cleanRequested = requestedVersion.replace(/^v/, '');
  
  // Try to find exact match first
  for (const available of availableVersions) {
    const cleanAvailable = available.replace(/^v/, '').split('+')[0];
    if (cleanRequested === cleanAvailable) {
      return available;
    }
  }
  
  // Try to find semver compatible version
  try {
    const validRequested = semver.valid(semver.coerce(cleanRequested));
    if (validRequested) {
      for (const available of availableVersions) {
        const cleanAvailable = available.replace(/^v/, '').split('+')[0];
        const validAvailable = semver.valid(semver.coerce(cleanAvailable));
        if (validAvailable && semver.satisfies(validAvailable, `~${validRequested}`)) {
          return available;
        }
      }
    }
  } catch (semverError) {
    console.warn('Semver comparison failed:', semverError.message);
  }
  
  return null;
}

// Enhanced compilation function with better error handling
async function compileContract(solcjs, input) {
  try {
    let compilationResult;

    // Determine the correct compilation method
    if (typeof solcjs.compile === 'function') {
      // Try modern compilation method
      try {
        compilationResult = solcjs.compile(JSON.stringify(input));
      } catch (compileError) {
        // Fallback to legacy method if modern fails
        if (typeof solcjs.compileStandardWrapper === 'function') {
          compilationResult = solcjs.compileStandardWrapper(JSON.stringify(input));
        } else {
          throw compileError;
        }
      }
    } else if (typeof solcjs.compileStandard === 'function') {
      compilationResult = solcjs.compileStandard(JSON.stringify(input));
    } else if (typeof solcjs.compileStandardWrapper === 'function') {
      compilationResult = solcjs.compileStandardWrapper(JSON.stringify(input));
    } else {
      throw new Error('No suitable compilation method found in solc instance');
    }

    // Parse the result if it's a string
    const output = typeof compilationResult === 'string' 
      ? JSON.parse(compilationResult) 
      : compilationResult;

    return output;
  } catch (error) {
    console.error('Compilation failed:', error);
    throw new Error(`Compilation failed: ${error.message}`);
  }
}

// Create HTTP server and socket.io instance
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: ["http://localhost:3000", "https://ucscan.net"],
    methods: ["GET", "POST"],
  },
});

web3Ws.eth
  .subscribe("newBlockHeaders")
  .on("connected", () => {
    console.log("🔗 Connected to WebSocket node (Validator)");
  })
  .on("data", async (blockHeader) => {
    // console.log(`📦 New block header received: #${blockHeader.number}`);

    try {
      const block = await web3Ws.eth.getBlock(blockHeader.number, true);
      if (!block) {
        console.warn(`⚠️ Could not fetch block ${blockHeader.number}`);
        return;
      }

      // console.log(
      //   `📌 Processing block ${block.number} (${block.transactions.length} txs)`
      // );

      if (block.transactions.length < 1) return;

      for (const tx of block.transactions) {
        console.log(`➡️ Processing TX: ${tx.hash}`);

        try {
          const [result] = await db.execute(
            `INSERT INTO transactions 
              (hash, blockNumber, fromAddress, toAddress, value, gas, gasPrice, timestamp)
             VALUES (?, ?, ?, ?, ?, ?, ?, FROM_UNIXTIME(?))
              ON DUPLICATE KEY UPDATE
                blockNumber = VALUES(blockNumber),
                fromAddress = VALUES(fromAddress),
                toAddress = VALUES(toAddress),
                value = VALUES(value),
                gas = VALUES(gas),
                gasPrice = VALUES(gasPrice),
                timestamp = VALUES(timestamp)`,
            [
              tx.hash,
              tx.blockNumber,
              tx.from,
              tx.to,
              tx.value,
              tx.gas,
              tx.gasPrice,
              block.timestamp, // ✅ pass UNIX timestamp (NOT ISO string)
            ]
          );

          console.log(
            `✅ TX saved [hash: ${tx.hash}] - Result:`,
            JSON.stringify(result)
          );
        } catch (dbTxErr) {
          console.error(
            `❌ DB error while saving TX ${tx.hash}:`,
            dbTxErr.message
          );
        }

        // Detect contract creation
        // if (!tx.to) {
        //   console.log(`🔍 TX ${tx.hash} is contract creation, checking receipt...`);

        //   try {
        //     const receipt = await web3Ws.eth.getTransactionReceipt(tx.hash);

        //     if (receipt && receipt.contractAddress) {
        //       console.log(
        //         `📜 Contract created at ${receipt.contractAddress} (from ${tx.from})`
        //       );

        //       let isERC20 = false;
        //       let symbol = null;
        //       let totalSupply = null;
        //       let decimals = null;

        //       try {
        //         const contract = new web3Ws.eth.Contract(
        //           require("./utils").ERC20_ABI,
        //           receipt.contractAddress
        //         );

        //         totalSupply = await contract.methods.totalSupply().call();
        //         symbol = await contract.methods.symbol().call();
        //         decimals = await contract.methods.decimals().call();
        //         isERC20 = true;

        //         console.log(
        //           `💰 ERC20 detected [symbol: ${symbol}, supply: ${totalSupply}, decimals: ${decimals}]`
        //         );
        //       } catch (e) {
        //         console.log(`ℹ️ Not ERC20: ${receipt.contractAddress}`);
        //       }

        //       console.log("📝 Attempting to save contract to DB...");

        //       try {
        //         const [result] = await db.execute(
        //           `INSERT INTO contracts
        //             (address, creator, blockNumber, timestamp, type, symbol, isVerified, totalSupply, decimals)
        //            VALUES (?, ?, ?, FROM_UNIXTIME(?), ?, ?, ?, ?, ?)
        //            ON DUPLICATE KEY UPDATE
        //              blockNumber = VALUES(blockNumber),
        //              timestamp = VALUES(timestamp),
        //              type = VALUES(type),
        //              symbol = VALUES(symbol),
        //              totalSupply = VALUES(totalSupply),
        //              decimals = VALUES(decimals)`,
        //           [
        //             receipt.contractAddress,
        //             tx.from,
        //             block.number,
        //             block.timestamp,
        //             isERC20 ? "ERC20" : "other",
        //             symbol,
        //             false,
        //             totalSupply,
        //             decimals,
        //           ]
        //         );

        //         console.log(
        //           `✅ Contract saved: ${receipt.contractAddress}, result:`,
        //           JSON.stringify(result)
        //         );
        //       } catch (dbErr) {
        //         console.error(
        //           `❌ DB error for contract ${receipt.contractAddress}:`,
        //           dbErr.message
        //         );
        //       }
        //     }
        //   } catch (err) {
        //     console.error(
        //       `❌ Error fetching receipt for TX ${tx.hash}:`,
        //       err.message
        //     );
        //   }
        // }
      }

      console.log(
        `🎯 Finished indexing block ${block.number} (${block.transactions.length} txs)`
      );
    } catch (err) {
      console.error("❌ Error processing block:", err.message);
    }
  })
  .on("error", (err) => {
    console.error("❌ WebSocket subscription error:", err.message);
  });

// Check if connected to the blockchain
web3.eth.net
  .isListening()
  .then(() => console.log("Connected to Universe Chain EVM Testnet"))
  .catch(() => console.log("Failed to connect to Universe Chain EVM Testnet"));

// Store for rate limiting
const rateLimitStore = new Map();

// Authentication middleware
const authenticate = (req, res, next) => {
  const token = req.headers["authorization"];

  if (!token) {
    return next(); // No token, continue without authentication
  }

  try {
    const decoded = jwt.verify(token.replace("Bearer ", ""), JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ error: "Invalid token" });
  }
};

// Rate limiting middleware
const rateLimiter = (req, res, next) => {
  // Use user ID if authenticated, otherwise use API key or default
  const apiKey = req.user
    ? `user_${req.user.id}`
    : req.headers["x-api-key"] || "default";
  const now = Date.now();
  const windowMs = 60000; // 1 minute
  const maxRequests = req.user ? 1000 : 100; // Higher limit for authenticated users

  if (!rateLimitStore.has(apiKey)) {
    rateLimitStore.set(apiKey, {
      requests: [],
      tier: req.user ? "authenticated" : "free", // authenticated, free, basic, premium
    });
  }

  const clientInfo = rateLimitStore.get(apiKey);

  // Clean old requests
  clientInfo.requests = clientInfo.requests.filter(
    (timestamp) => now - timestamp < windowMs
  );

  // Check if client has exceeded limit
  if (clientInfo.requests.length >= maxRequests) {
    return res.status(429).json({ error: "Rate limit exceeded" });
  }

  // Add current request
  clientInfo.requests.push(now);
  next();
};

// Routes

// Get network info
app.get("/api/network", authenticate, rateLimiter, async (req, res) => {
  try {
    const [chainId, blockNumber, gasPrice] = await Promise.all([
      web3.eth.getChainId(),
      web3.eth.getBlockNumber(),
      web3.eth.getGasPrice(),
    ]);

    res.json({
      chainId,
      blockHeight: blockNumber,
      blockTime: 5, // Average block time for POA
      gasPrice: web3.utils.fromWei(gasPrice, "gwei") + " Gwei",
      totalSupply: "99,999,999,999 tUCC", // As specified in requirements
    });
  } catch (error) {
    console.error("Error fetching network info:", error);
    res.status(500).json({ error: "Failed to fetch network info" });
  }
});

// Get latest blocks
app.get("/api/blocks", authenticate, rateLimiter, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;

    // Get latest block number
    const latestBlockNumber = await web3.eth.getBlockNumber();

    // Calculate start block
    const startBlock = latestBlockNumber - (page - 1) * limit;

    // Fetch blocks
    const blocks = [];
    for (let i = 0; i < limit && startBlock - i >= 0; i++) {
      const block = await web3.eth.getBlock(startBlock - i);
      if (block) {
        // Get transaction count for this block
        const transactionCount = block.transactions.length;

        blocks.push({
          number: block.number,
          hash: block.hash,
          timestamp: new Date(block.timestamp * 1000).toISOString(),
          transactions: transactionCount,
          gasUsed: block.gasUsed,
          gasLimit: block.gasLimit,
          miner: block.miner,
        });
      }
    }

    res.json({
      blocks,
      totalPages: Math.ceil(latestBlockNumber / limit),
      currentPage: page,
    });
  } catch (error) {
    console.error("Error fetching blocks:", error);
    res.status(500).json({ error: "Failed to fetch blocks" });
  }
});

// Get block by number
app.get("/api/blocks/:number", authenticate, rateLimiter, async (req, res) => {
  try {
    const blockNumber = req.params.number;
    const block = await web3.eth.getBlock(blockNumber);

    if (block) {
      // Get transaction count for this block
      const transactionCount = block.transactions.length;

      const blockData = {
        number: block.number,
        hash: block.hash,
        timestamp: new Date(block.timestamp * 1000).toISOString(),
        transactions: transactionCount,
        gasUsed: block.gasUsed,
        gasLimit: block.gasLimit,
        miner: block.miner,
        parentHash: block.parentHash,
        nonce: block.nonce,
        difficulty: block.difficulty,
        totalDifficulty: block.totalDifficulty,
        size: block.size,
        gasUsed: block.gasUsed,
        gasLimit: block.gasLimit,
        logsBloom: block.logsBloom,
        transactionsRoot: block.transactionsRoot,
        stateRoot: block.stateRoot,
        receiptsRoot: block.receiptsRoot,
        extraData: block.extraData,
      };

      res.json(blockData);
    } else {
      res.status(404).json({ error: "Block not found" });
    }
  } catch (error) {
    console.error("Error fetching block:", error);
    res.status(500).json({ error: "Failed to fetch block" });
  }
});

app.get("/api/verified-tokens", authenticate, rateLimiter, async (req, res) => {
  try {
    const [rows] = await db.execute(`SELECT address FROM contracts WHERE isVerified = 1`);
    res.json([...rows.map(r => r.address)]);
  } catch (error) {
    console.error("Error fetching verified tokens:", error);
    res.status(500).json({ error: "Failed to fetch verified tokens" });
  }
});

app.get("/api/transactions", authenticate, rateLimiter, async (req, res) => {
  try {
    // Parse and validate page/limit query params
    let page = parseInt(req.query.page, 10);
    let limit = parseInt(req.query.limit, 10);

    if (isNaN(page) || page < 1) page = 1;
    if (isNaN(limit) || limit < 1 || limit > 100) limit = 10; // cap limit at 100

    const offset = (page - 1) * limit;
    const address = req.query.address;

    const transactions = [];
    let rows;

    if (address) {
      [rows] = await db.execute(
        `SELECT * FROM transactions 
         WHERE fromAddress = ? OR toAddress = ? 
         ORDER BY blockNumber DESC 
         LIMIT ${limit} OFFSET ${offset}`,
        [address, address]
      );
    } else {
      [rows] = await db.execute(
        `SELECT * FROM transactions 
         ORDER BY blockNumber DESC 
         LIMIT ${limit} OFFSET ${offset}`
      );
    }

    for (const row of rows) {
      transactions.push({
        hash: row.hash,
        blockNumber: row.blockNumber,
        timestamp: row.timestamp,
        from: row.fromAddress,
        to: row.toAddress,
        value: web3.utils.fromWei(row.value, "ether") + " tUCC",
        gasUsed: row.gas,
        status: "success", // Assuming success for simplicity
      });
    }

    res.json({
      transactions,
      totalPages: Math.ceil(transactions.length / limit),
      currentPage: page,
    });
  } catch (error) {
    console.error("Error fetching transactions:", error);
    res.status(500).json({ error: "Failed to fetch transactions" });
  }
});


// Get contracts
// app.get('/api/contracts', rateLimiter, async (req, res) => {
//   try {
//     const { address } = req.query;
//     // if (!address || !web3.utils.isAddress(address)) {
//     //   return res.status(400).json({ error: "Invalid address" });
//     // }
//     const response = await fetch(RPC_API, {
//       method: "POST",
//       headers: { "Content-Type": "application/json" },
//       body: JSON.stringify({
//         "jsonrpc": "2.0",
//         "method": "eth_call",
//         "params": [
//           {
//             "to": "0xTokenContractAddress",
//             "data": `0x70a08231000000000000000000000000${address.replace(/^0x/, '')}`
//           },
//           "latest"
//         ],
//         "id": 1
//       })
//     });
//     console.log("REQUEST ", response);
//     const data = await response.json();
//     console.log('Token balance fetched successfully:', data);
//   } catch (error) {
//     console.error('Error fetching token balance:', error);
//     res.status(500).json({ error: 'Failed to fetch token balance' });
//   }
// });

// app.get('/api/contracts', authenticate, rateLimiter, async (req, res) => {
//   try {
//     const { address, token } = req.query;
//     if (!address || !web3.utils.isAddress(address)) {
//       return res.status(400).json({ error: "Invalid address" });
//     }

//     const data = web3.eth.abi.encodeFunctionCall({
//       name: 'balanceOf',
//       type: 'function',
//       inputs: [{ type: 'address', name: '_owner' }]
//     }, [address]);

//     const response = await fetch(RPC_API, {
//       method: "POST",
//       headers: { "Content-Type": "application/json" },
//       body: JSON.stringify({
//         jsonrpc: "2.0",
//         method: "eth_call",
//         params: [{ to: token, data }, "latest"],
//         id: 1
//       })
//     });

//     const result = await response.json();

//     if (result.error) {
//       throw new Error(result.error.message);
//     }

//     const rawBalance = web3.utils.toBN(result.result).toString();

//     res.json({ address, token, balance: rawBalance });
//   } catch (error) {
//     console.error("Error fetching token balance:", error);
//     res.status(500).json({ error: "Failed to fetch token balance" });
//   }
// });

// Get all addresses
app.get("/api/addresses", authenticate, rateLimiter, async (req, res) => {
  try {
    const { page = 1, limit = 10 } = req.query;
    const addresses = await getAllAddresses(page, limit);
    res.json({ type: "addresses", data: addresses });
  } catch (error) {
    console.error("Error fetching all addresses:", error);
    res.status(500).json({ error: "Failed to fetch all addresses" });
  }
});

app.get(
  "/api/transactions/:hash",
  authenticate,
  rateLimiter,
  async (req, res) => {
    try {
      const transactionHash = req.params.hash;
      const transaction = await web3.eth.getTransaction(transactionHash);

      if (transaction) {
        // Get transaction receipt for status and gas used
        const receipt = await web3.eth.getTransactionReceipt(transactionHash);

        const transactionData = {
          hash: transaction.hash,
          blockNumber: transaction.blockNumber,
          timestamp: new Date().toISOString(), // We'll need to get this from the block
          from: transaction.from,
          to: transaction.to,
          value: web3.utils.fromWei(transaction.value, "ether") + " tUCC",
          gasUsed: receipt ? receipt.gasUsed : 0,
          gasPrice: web3.utils.fromWei(transaction.gasPrice, "gwei") + " Gwei",
          nonce: transaction.nonce,
          input: transaction.input,
          status: receipt ? (receipt.status ? "success" : "failed") : "pending",
        };

        // Get timestamp from block
        if (transaction.blockNumber) {
          const block = await web3.eth.getBlock(transaction.blockNumber);
          if (block) {
            transactionData.timestamp = new Date(
              block.timestamp * 1000
            ).toISOString();
          }
        }

        res.json(transactionData);
      } else {
        res.status(404).json({ error: "Transaction not found" });
      }
    } catch (error) {
      console.error("Error fetching transaction:", error);
      res.status(500).json({ error: "Failed to fetch transaction" });
    }
  }
);

// Get tokens (mock data for now)
app.get("/api/tokens", authenticate, rateLimiter, async (req, res) => {
  const tokens = await getKnownTokenContracts();
  res.json({
    tokens,
  });
});

app.get("/api/fix", authenticate, rateLimiter, async (req, res) => {
  try {
    // await indexTransactionsFromChain(web3);
    console.log("AHh this should start here")
    const response = await indexTransactionsFromChain(web3);
    res.status(200).json({
      message: "FIXING COMPLETED",
      response
    });
  } catch (error) {
    console.log(error);
    res.status(500).json({ error: "Fix failed", err: error });
  }
});

// Get validators (mock data for now)
app.get("/api/validators", authenticate, rateLimiter, (req, res) => {
  res.json([
    {
      name: "Validator Node 1",
      address: "0x1234567890abcdef1234567890abcdef12345678",
      status: "active",
      stake: "1,000,000 tUCC",
      blocks: 1234567,
      uptime: "99.98%",
    },
  ]);
});

// Search endpoint
// app.get('/api/search/:query', authenticate, rateLimiter, async (req, res) => {
//   try {
//     const query = req.params.query.toLowerCase();

//     // Check if query is a block number
//     const blockNumber = parseInt(query);
//     if (!isNaN(blockNumber)) {
//       const block = await web3.eth.getBlock(blockNumber);
//       if (block) {
//         return res.json({ type: 'block', data: block });
//       }
//     }

//     // Check if query is a transaction hash
//     if (query.startsWith('0x') && query.length === 66) {
//       const transaction = await web3.eth.getTransaction(query);
//       if (transaction) {
//         return res.json({ type: 'transaction', data: transaction });
//       }
//     }

//     // Check if query is an address
//     if (query.startsWith('0x') && query.length === 42) {
//       const code = await web3.eth.getCode(query);
//       const balance = await web3.eth.getBalance(query);
//       const isContract = code !== '0x';

//       // Check if contract is verified (mock implementation)
//       // const isVerified = query === '0x1234567890abcdef1234567890abcdef12345678'; // Mock verified address

//       return res.json({
//         type: 'address',
//         data: {
//           address: query,
//           balance: web3.utils.fromWei(balance, 'ether') + ' tUCC',
//           isContract: isContract,
//           isVerified: false
//         }
//       });
//     }

//     res.json({ type: 'not_found', data: null });
//   } catch (error) {
//     console.error('Error searching:', error);
//     res.status(500).json({ error: 'Search failed' });
//   }
// });

app.get("/api/search/:query", authenticate, rateLimiter, async (req, res) => {
  try {
    const query = req.params.query.toLowerCase();

    // Check if query is a valid integer block number (no decimals, no scientific notation)
    if (/^\d+$/.test(query)) {
      const blockNumber = web3.utils.toBN(query); // safe conversion
      const block = await web3.eth.getBlock(blockNumber.toNumber());
      if (block) {
        return res.json({ type: "block", data: block });
      }
    }

    // Check if query is a transaction hash
    if (query.startsWith("0x") && query.length === 66) {
      const transaction = await web3.eth.getTransaction(query);
      if (transaction) {
        return res.json({ type: "transaction", data: transaction });
      }
    }

    // Check if query is an address
    if (query.startsWith("0x") && query.length === 42) {
      const code = await web3.eth.getCode(query);
      const balance = await web3.eth.getBalance(query);
      const isContract = code !== "0x";

      return res.json({
        type: "address",
        data: {
          address: query,
          balance: web3.utils.fromWei(balance, "ether") + " tUCC",
          isContract,
          isVerified: false,
        },
      });
    }

    res.json({ type: "not_found", data: null });
  } catch (error) {
    console.error("Error searching:", error);
    res.status(500).json({ error: "Search failed" });
  }
});

// Get address info
// app.get(
//   "/api/address/:address",
//   authenticate,
//   rateLimiter,
//   async (req, res) => {
//     try {
//       const address = req.params.address;

//       // Validate address
//       if (!web3.utils.isAddress(address)) {
//         return res.status(400).json({ error: "Invalid address" });
//       }

//       // Get balance
//       const balance = await web3.eth.getBalance(address);

//       // Get code to check if it's a contract
//       const code = await web3.eth.getCode(address);
//       const isContract = code !== "0x";

//       // Get transaction count
//       const txnCount = await web3.eth.getTransactionCount(address);

//       // Check if contract is verified (mock implementation)
//       const isVerified =
//         address === "0x1234567890abcdef1234567890abcdef12345678"; // Mock verified address

//       // Get token balances
//       const knownTokens = await getKnownTokenContracts();
//       const tokenBalances = await getAllTokenBalances(
//         web3,
//         address,
//         knownTokens
//       );

//       // Get contract info if it's a contract
//       let contractInfo = null;
//       if (isContract) {
//         contractInfo = {
//           isVerified: isVerified,
//           abi: isVerified
//             ? '[{"inputs":[],"name":"getValue","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"}]'
//             : null,
//           sourceCode: isVerified
//             ? "contract SimpleStorage { uint256 value; }"
//             : null,
//         };
//       }

//       res.json({
//         address: address,
//         balance: web3.utils.fromWei(balance, "ether") + " tUCC",
//         tokenBalances: tokenBalances,
//         isContract: isContract,
//         isVerified: isVerified,
//         txnCount: txnCount,
//         contractInfo: contractInfo,
//       });
//     } catch (error) {
//       console.error("Error fetching address info:", error);
//       res.status(500).json({ error: "Failed to fetch address info" });
//     }
//   }
// );

// app.get("/api/address/:address", authenticate, rateLimiter, async (req, res) => {
//   try {
//     const address = req.params.address;

//     // Validate address format
//     if (!web3.utils.isAddress(address)) {
//       return res.status(400).json({ error: "Invalid Ethereum address format" });
//     }

//     console.log("Fetching address info for:", address);

//     // Get basic blockchain data
//     const [balance, code, txnCount] = await Promise.all([
//       web3.eth.getBalance(address),
//       web3.eth.getCode(address),
//       web3.eth.getTransactionCount(address)
//     ]);

//     const isContract = code !== "0x";
//     const balanceInEther = web3.utils.fromWei(balance, "ether");

//     console.log("Address type:", isContract ? "Contract" : "EOA");

//     // Get token balances
//     const knownTokens = await getKnownTokenContracts();
//     const tokenBalances = await getAllTokenBalances(web3, address, knownTokens);

//     // Get contract verification data from database (NO MORE MOCK DATA)
//     let contractInfo = null;
//     if (isContract) {
//       contractInfo = await getContractVerificationData(address.toLowerCase());
//     }

//     // Response
//     const response = {
//       success: true,
//       address: address,
//       balance: `${balanceInEther} tUCC`,
//       isContract: isContract,
//       transactionCount: txnCount,
//       tokenBalances: tokenBalances,
//       contractInfo: contractInfo
//     };

//     console.log("Address info fetched successfully:", {
//       address,
//       isContract,
//       isVerified: contractInfo?.isVerified || false,
//       hasAbi: contractInfo?.abi ? true : false
//     });

//     res.json(response);

//   } catch (error) {
//     console.error("Error fetching address info:", error);
//     res.status(500).json({
//       error: "Failed to fetch address information",
//       details: process.env.NODE_ENV === 'development' ? error.message : "Internal server error"
//     });
//   }
// });

// Get token transactions for a contract
app.get(
  "/api/token-transactions/:contractAddress",
  authenticate,
  rateLimiter,
  async (req, res) => {
    try {
      const contractAddress = req.params.contractAddress;

      // Validate address
      if (!web3.utils.isAddress(contractAddress)) {
        return res.status(400).json({ error: "Invalid contract address" });
      }

      // Get token transactions
      const tokenTransactions = await getTokenTransactions(
        web3,
        contractAddress
      );

      res.json({
        contractAddress: contractAddress,
        transactions: tokenTransactions,
      });
    } catch (error) {
      console.error("Error fetching token transactions:", error);
      res.status(500).json({ error: "Failed to fetch token transactions" });
    }
  }
);

app.get(
  "/api/address/:address",
  authenticate,
  rateLimiter,
  async (req, res) => {
    try {
      const address = req.params.address;

      // Validate address format
      if (!web3.utils.isAddress(address)) {
        return res
          .status(400)
          .json({ error: "Invalid Ethereum address format" });
      }

      // console.log("Fetching address info for:", address);

      // Get basic blockchain data
      const [balance, code, txnCount] = await Promise.all([
        web3.eth.getBalance(address),
        web3.eth.getCode(address),
        web3.eth.getTransactionCount(address),
      ]);

      // console.log("Fetching some", { balance, code, txnCount });

      const isContract = code !== "0x";
      const balanceInEther = web3.utils.fromWei(balance, "ether");


      // Get token balances
      const knownTokens = await getKnownTokenContracts();
      const tokenBalances = await getAllTokenBalances(
        web3,
        address,
        knownTokens
      );

      // Get contract verification data from database
      let contractInfo = null;
      let isVerified = false;

      if (isContract) {
        contractInfo = await getContractVerificationData(address.toLowerCase());
        isVerified = contractInfo.isVerified; // Get the actual verification status
      }

      

      // Response
      const response = {
        success: true,
        address: address,
        balance: `${balanceInEther} tUCC`,
        isContract: isContract,
        isVerified: isVerified, // Include isVerified at the root level for easy access
        transactionCount: txnCount,
        tokenBalances: tokenBalances,
        contractInfo: contractInfo,
      };

      

      res.json(response);
    } catch (error) {
      console.error("Error fetching address info:", error);
      res.status(500).json({
        error: "Failed to fetch address information",
        details:
          process.env.NODE_ENV === "development"
            ? error.message
            : "Internal server error",
      });
    }
  }
);

// Get token holders for a contract
app.get(
  "/api/token-holders/:contractAddress",
  authenticate,
  rateLimiter,
  async (req, res) => {
    try {
      const contractAddress = req.params.contractAddress;

      // Validate address
      if (!web3.utils.isAddress(contractAddress)) {
        return res.status(400).json({ error: "Invalid contract address" });
      }

      // Get token holders
      const tokenHolders = await getTokenHolders(web3, contractAddress);

      res.json({
        contractAddress: contractAddress,
        holders: tokenHolders,
      });
    } catch (error) {
      console.error("Error fetching token holders:", error);
      res.status(500).json({ error: "Failed to fetch token holders" });
    }
  }
);

// Contract verification endpoint

// app.post(
//   "/api/verify-contract",
//   authenticate,
//   rateLimiter,
//   async (req, res) => {
//     const {
//       address,
//       compilerVersion,
//       optimization,
//       runs,
//       sourceCode,
//       contractName,
//       constructorArguments = "",
//       libraries = {},
//     } = req.body;

//     console.log("Verification request received:", {
//       address,
//       compilerVersion,
//       optimization,
//       runs,
//       contractName,
//       sourceCodeLength: sourceCode?.length,
//       constructorArguments: constructorArguments?.length || 0,
//       libraries: Object.keys(libraries).length,
//     });

//     if (!address || !compilerVersion || !sourceCode) {
//       return res
//         .status(400)
//         .json({
//           error:
//             "Missing required fields: address, compilerVersion, or sourceCode",
//         });
//     }

//     // Validate Ethereum address
//     if (!/^0x[a-fA-F0-9]{40}$/.test(address)) {
//       return res.status(400).json({ error: "Invalid Ethereum address format" });
//     }

//     let conn;
//     try {
//       // 1. Connect to blockchain & fetch deployed bytecode
//       console.log("Fetching on-chain bytecode for address:", address);
//       const provider = new ethers.JsonRpcProvider(RPC_API);
//       const onchainBytecode = await provider.getCode(address);

//       if (!onchainBytecode || onchainBytecode === "0x") {
//         console.log("No bytecode found for address:", address);
//         return res.status(404).json({ error: "Contract not found on-chain" });
//       }

//       console.log("On-chain bytecode length:", onchainBytecode.length);

//       // 2. Determine contract structure and imports
//       const imports = extractImports(sourceCode);
//       const sources = await buildSourceTree(sourceCode, imports);

//       // 3. Build enhanced solc input
//       const input = {
//         language: "Solidity",
//         sources,
//         settings: {
//           optimizer: {
//             enabled: optimization === true,
//             runs: parseInt(runs) || 200,
//           },
//           outputSelection: {
//             "*": {
//               "*": [
//                 "abi",
//                 "evm.bytecode.object",
//                 "evm.deployedBytecode.object",
//                 "metadata",
//                 "evm.methodIdentifiers",
//               ],
//             },
//           },
//           libraries: libraries || {},
//           evmVersion: detectEvmVersion(compilerVersion),
//           metadata: {
//             useLiteralContent: true,
//           },
//         },
//       };

//       // console.log("Loading compiler version:", compilerVersion);

//       // // 4. Load compiler with better error handling
//       // let solcjs;
//       // try {
//       //   solcjs = await new Promise((resolve, reject) => {
//       //     const timeout = setTimeout(() => {
//       //       reject(new Error(`Compiler loading timeout for version ${compilerVersion}`));
//       //     }, 30000);

//       //     solc.loadRemoteVersion(compilerVersion, (err, solcSnapshot) => {
//       //       clearTimeout(timeout);
//       //       if (err) {
//       //         console.error("Compiler loading error:", err);
//       //         return reject(new Error(`Failed to load compiler version ${compilerVersion}: ${err.message}`));
//       //       }
//       //       resolve(solcSnapshot);
//       //     });
//       //   });
//       // } catch (loadError) {
//       //   console.error("Compiler load failed:", loadError);
//       //   return res.status(400).json({
//       //     error: "Compiler version not available",
//       //     details: `Could not load compiler version ${compilerVersion}. Please check if the version exists.`
//       //   });
//       // }

//       // // 5. Compile source with error handling
//       // console.log("Compiling source code...");
//       // let output;
//       // try {
//       //   const compilationResult = solcjs.compile(JSON.stringify(input));
//       //   output = JSON.parse(compilationResult);
//       // } catch (compileError) {
//       //   console.error("Compilation failed:", compileError);
//       //   return res.status(400).json({
//       //     error: "Compilation failed",
//       //     details: compileError.message
//       //   });
//       // }

//       console.log("Loading compiler version:", compilerVersion);

//       let solcjs;
//       try {
//         solcjs = await loadCompilerVersion(compilerVersion);
//       } catch (loadError) {
//         console.error("Compiler load failed:", loadError);
//         return res.status(400).json({
//           error: "Compiler version not available",
//           details: `Could not load compiler version ${compilerVersion}. Please try a different version or use the format like "0.8.19".`,
//         });
//       }

//       // 5. Compile source with error handling
//       console.log("Compiling source code...");
//       let output;
//       try {
//         let compilationResult;

//         if (typeof solcjs.compile === "function") {
//           // Modern @ethereum/solc package
//           compilationResult = solcjs.compile(JSON.stringify(input));
//         } else if (typeof solcjs.compileStandard === "function") {
//           // solc with compileStandard
//           compilationResult = solcjs.compileStandard(JSON.stringify(input));
//         } else {
//           // Legacy solc package
//           compilationResult = solcjs.compile(JSON.stringify(input));
//         }

//         // Parse the result if it's a string
//         output =
//           typeof compilationResult === "string"
//             ? JSON.parse(compilationResult)
//             : compilationResult;
//       } catch (compileError) {
//         console.error("Compilation failed:", compileError);
//         return res.status(400).json({
//           error: "Compilation failed",
//           details: compileError.message,
//         });
//       }

//       // Handle compilation errors and warnings
//       if (output.errors) {
//         const errors = output.errors.filter((e) => e.severity === "error");
//         const warnings = output.errors.filter((e) => e.severity === "warning");

//         if (errors.length > 0) {
//           console.error("Compilation errors:", errors);
//           return res.status(400).json({
//             error: "Compilation errors",
//             details: errors.map((e) => e.formattedMessage),
//             warnings: warnings.map((w) => w.formattedMessage),
//           });
//         }

//         if (warnings.length > 0) {
//           console.warn("Compilation warnings:", warnings);
//         }
//       }

//       // Check if contracts were compiled
//       if (!output.contracts || Object.keys(output.contracts).length === 0) {
//         console.error("No contracts found in compilation output");
//         return res.status(400).json({
//           error: "No contracts found in compilation output",
//           details:
//             "The source code did not compile to any contract artifacts. Please check your Solidity code.",
//         });
//       }

//       console.log(
//         "Compilation successful. Contracts found:",
//         Object.keys(output.contracts)
//       );

//       // 6. Enhanced bytecode comparison
//       const normalizedOnchain = advancedNormalizeBytecode(onchainBytecode);
//       console.log(
//         "Normalized on-chain bytecode length:",
//         normalizedOnchain.length
//       );

//       let bestMatch = null;
//       let bestMatchPercentage = 0;

//       // Iterate through all compiled contracts
//       for (const file in output.contracts) {
//         for (const name in output.contracts[file]) {
//           const contract = output.contracts[file][name];

//           // Skip if no deployed bytecode
//           if (
//             !contract.evm ||
//             !contract.evm.deployedBytecode ||
//             !contract.evm.deployedBytecode.object
//           ) {
//             continue;
//           }

//           // Skip if specific contract name provided and doesn't match
//           if (contractName && name !== contractName) {
//             continue;
//           }

//           let compiledDeployedBytecode =
//             "0x" + contract.evm.deployedBytecode.object;

//           // Handle constructor arguments if provided
//           if (constructorArguments) {
//             const creationBytecode = "0x" + contract.evm.bytecode.object;
//             const expectedDeployedBytecode = simulateDeployment(
//               creationBytecode,
//               constructorArguments,
//               normalizedOnchain
//             );
//             if (expectedDeployedBytecode) {
//               compiledDeployedBytecode = expectedDeployedBytecode;
//             }
//           }

//           const normalizedCompiled = advancedNormalizeBytecode(
//             compiledDeployedBytecode
//           );

//           console.log(`Contract ${name}:`);
//           console.log(
//             `- Compiled bytecode length: ${normalizedCompiled.length}`
//           );
//           console.log(
//             `- On-chain bytecode length: ${normalizedOnchain.length}`
//           );

//           // Multiple comparison methods
//           const exactMatch = compareExactMatch(
//             normalizedOnchain,
//             normalizedCompiled
//           );
//           const fuzzyMatch = compareFuzzyMatch(
//             normalizedOnchain,
//             normalizedCompiled
//           );
//           const structuralMatch = compareStructuralMatch(
//             normalizedOnchain,
//             normalizedCompiled
//           );

//           const matchPercentage = Math.max(
//             exactMatch,
//             fuzzyMatch,
//             structuralMatch
//           );

//           console.log(`- Exact match: ${exactMatch}%`);
//           console.log(`- Fuzzy match: ${fuzzyMatch}%`);
//           console.log(`- Structural match: ${structuralMatch}%`);
//           console.log(`- Best match: ${matchPercentage}%`);

//           if (matchPercentage > bestMatchPercentage) {
//             bestMatchPercentage = matchPercentage;
//             bestMatch = {
//               contract,
//               name,
//               file,
//               matchPercentage,
//               exactMatch,
//               fuzzyMatch,
//               structuralMatch,
//             };
//           }

//           // Perfect match found
//           if (matchPercentage === 100) {
//             console.log("Perfect match found for contract:", name);
//             break;
//           }
//         }
//         if (bestMatchPercentage === 100) {
//           break;
//         }
//       }

//       const isVerified = bestMatchPercentage >= 98; // Slightly more strict threshold
//       const compiledBytecode = bestMatch
//         ? "0x" + bestMatch.contract.evm.bytecode.object
//         : "";
//       const abi = bestMatch ? JSON.stringify(bestMatch.contract.abi) : "[]";

//       console.log("Verification result:", {
//         contractName: bestMatch?.name,
//         matchPercentage: bestMatchPercentage,
//         isVerified,
//         matchDetails: bestMatch
//           ? {
//               exact: bestMatch.exactMatch,
//               fuzzy: bestMatch.fuzzyMatch,
//               structural: bestMatch.structuralMatch,
//             }
//           : null,
//       });

//       // 7. Save to DB with enhanced info

//       try {
//         conn = await db.getConnection();

//         // Extract contract data if verification successful
//         const contractData = bestMatch
//           ? extractContractData(bestMatch.contract, bestMatch.name)
//           : null;

//         await conn.execute(
//           `INSERT INTO contracts 
//           (address, solSource, version, isOptimized, runs, abi, 
//            compiledBytecodeLength, onchainBytecodeLength, matchPercentage, 
//            isVerified, verificationMessage, verifiedAt, contractName, 
//            constructorArgs, metadata, functionSignatures, eventSignatures) 
//         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
//         ON DUPLICATE KEY UPDATE 
//           solSource = VALUES(solSource),
//           version = VALUES(version),
//           isOptimized = VALUES(isOptimized),
//           runs = VALUES(runs),
//           abi = VALUES(abi),
//           compiledBytecodeLength = VALUES(compiledBytecodeLength),
//           onchainBytecodeLength = VALUES(onchainBytecodeLength),
//           matchPercentage = VALUES(matchPercentage),
//           isVerified = VALUES(isVerified),  // This must be included
//           verificationMessage = VALUES(verificationMessage),
//           verifiedAt = VALUES(verifiedAt),
//           contractName = VALUES(contractName),
//           constructorArgs = VALUES(constructorArgs),
//           metadata = VALUES(metadata),
//           functionSignatures = VALUES(functionSignatures),
//           eventSignatures = VALUES(eventSignatures),
//           updatedAt = NOW()`,
//           [
//             address.toLowerCase(),
//             sourceCode,
//             compilerVersion,
//             optimization ? 1 : 0,
//             parseInt(runs) || 200,
//             abi,
//             compiledBytecode.length,
//             onchainBytecode.length,
//             bestMatchPercentage,
//             isVerified ? 1 : 0, // This must be 1 for true
//             isVerified
//               ? `Verification successful for ${bestMatch?.name || "contract"}`
//               : `Bytecode mismatch (${bestMatchPercentage}% best match)`,
//             isVerified ? new Date() : null, // verifiedAt should be set only when verified
//             contractData?.name || contractName || null,
//             constructorArguments || null,
//             contractData ? JSON.stringify(contractData.metadata) : null,
//             contractData
//               ? JSON.stringify(contractData.functionSignatures)
//               : null,
//             contractData ? JSON.stringify(contractData.eventSignatures) : null,
//           ]
//         );

//         console.log("Database insertion result:", {
//           address: address.toLowerCase(),
//           isVerified: isVerified ? 1 : 0,
//           matchPercentage: bestMatchPercentage,
//           verifiedAt: isVerified ? new Date() : null,
//         });

//         // Verify the data was actually saved
//         try {
//           const [verifyRows] = await conn.execute(
//             "SELECT isVerified, matchPercentage FROM contracts WHERE address = ?",
//             [address.toLowerCase()]
//           );
//           console.log("Post-insert verification check:", verifyRows[0]);
//         } catch (verifyError) {
//           console.error("Error verifying database insertion:", verifyError);
//         }

//         console.log("Enhanced verification results saved to database");
//       } catch (dbError) {
//         console.error("Database error:", dbError);
//         // Don't throw here, just log the error
//       }

//       // Return response
//       if (isVerified) {
//         return res.json({
//           success: true,
//           contractName: bestMatch?.name,
//           message: `Verification successful for ${
//             bestMatch?.name || "contract"
//           }`,
//           matchPercentage: bestMatchPercentage,
//           matchDetails: {
//             exact: bestMatch?.exactMatch,
//             fuzzy: bestMatch?.fuzzyMatch,
//             structural: bestMatch?.structuralMatch,
//           },
//           abi: bestMatch ? bestMatch.contract.abi : [],
//         });
//       } else {
//         return res.status(400).json({
//           success: false,
//           error: "Bytecode mismatch",
//           message: `Compiled bytecode does not match on-chain code (${bestMatchPercentage}% best match)`,
//           matchPercentage: bestMatchPercentage,
//           suggestions: generateVerificationSuggestions(
//             bestMatchPercentage,
//             bestMatch
//           ),
//           details:
//             bestMatchPercentage > 80
//               ? "High similarity detected. Try adjusting compiler settings, constructor arguments, or check for imported library versions."
//               : "Low similarity. Please verify the source code, compiler version, and optimization settings match the original deployment.",
//         });
//       }
//     } catch (err) {
//       console.error("Verification error:", err);
//       return res.status(500).json({
//         error: "Internal server error during verification",
//         details:
//           process.env.NODE_ENV === "development"
//             ? err.message
//             : "Please try again with different parameters.",
//       });
//     } finally {
//       if (conn) {
//         try {
//           conn.release();
//         } catch (releaseError) {
//           console.error("Error releasing database connection:", releaseError);
//         }
//       }
//     }
//   }
// );

app.post("/api/verify-contract", authenticate, rateLimiter, async (req, res) => {
  const {
    address,
    compilerVersion,
    optimization,
    runs,
    sourceCode,
    contractName,
    constructorArguments = "",
    libraries = {},
  } = req.body;

  console.log("Verification request received:", {
    address,
    compilerVersion,
    optimization,
    runs,
    contractName,
    sourceCodeLength: sourceCode?.length,
    constructorArguments: constructorArguments?.length || 0,
    libraries: Object.keys(libraries).length,
  });

  // Enhanced input validation
  if (!address || !compilerVersion || !sourceCode) {
    return res.status(400).json({
      error: "Missing required fields: address, compilerVersion, or sourceCode",
      details: {
        address: !address ? "Address is required" : null,
        compilerVersion: !compilerVersion ? "Compiler version is required" : null,
        sourceCode: !sourceCode ? "Source code is required" : null
      }
    });
  }

  // Validate Ethereum address
  if (!/^0x[a-fA-F0-9]{40}$/.test(address)) {
    return res.status(400).json({ 
      error: "Invalid Ethereum address format",
      details: "Address must be a 40-character hexadecimal string starting with 0x"
    });
  }

  // Validate compiler version format
  if (!/^v?\d+\.\d+\.\d+/.test(compilerVersion)) {
    return res.status(400).json({
      error: "Invalid compiler version format",
      details: "Compiler version should be in format like '0.8.19' or 'v0.8.19+commit.7dd6d404'"
    });
  }

  let conn;
  try {
    // 1. Connect to blockchain & fetch deployed bytecode
    console.log("Fetching on-chain bytecode for address:", address);
    
    if (!RPC_API) {
      throw new Error("RPC_API not configured");
    }
    
    const provider = new ethers.JsonRpcProvider(RPC_API);
    const onchainBytecode = await provider.getCode(address);

    if (!onchainBytecode || onchainBytecode === "0x") {
      console.log("No bytecode found for address:", address);
      return res.status(404).json({ 
        error: "Contract not found on-chain",
        details: "No bytecode exists at the provided address. Please verify the address is correct and the contract is deployed."
      });
    }

    console.log("On-chain bytecode length:", onchainBytecode.length);

    // 2. Determine contract structure and imports
    let imports, sources;
    try {
      imports = extractImports(sourceCode);
      sources = await buildSourceTree(sourceCode, imports);
    } catch (sourceError) {
      return res.status(400).json({
        error: "Source code processing failed",
        details: sourceError.message
      });
    }

    // 3. Build enhanced solc input with validation
    const optimizationEnabled = optimization === true || optimization === 'true' || optimization === 1;
    const optimizationRuns = parseInt(runs) || 200;
    
    const input = {
      language: "Solidity",
      sources,
      settings: {
        optimizer: {
          enabled: optimizationEnabled,
          runs: optimizationRuns,
        },
        outputSelection: {
          "*": {
            "*": [
              "abi",
              "evm.bytecode.object",
              "evm.deployedBytecode.object",
              "metadata",
              "evm.methodIdentifiers",
            ],
          },
        },
        libraries: libraries || {},
        evmVersion: detectEvmVersion(compilerVersion),
        metadata: {
          useLiteralContent: true,
        },
      },
    };

   
    // 4. Load compiler with enhanced error handling
    let solcjs;
    try {
      solcjs = await loadCompilerVersion(compilerVersion);
    } catch (loadError) {
      console.error("Compiler load failed:", loadError);
      return res.status(400).json({
        error: "Compiler version not available",
        details: loadError.message,
        suggestions: [
          "Try common formats like '0.8.19', 'v0.8.19', or '0.8.19+commit.7dd6d404'",
          "Check if the compiler version exists in Solidity releases",
          "Use a more recent or well-supported compiler version"
        ]
      });
    }

    // 5. Compile source with enhanced error handling
    console.log("Compiling source code...");
    let output;
    try {
      output = await compileContract(solcjs, input);
    } catch (compileError) {
      console.error("Compilation failed:", compileError);
      return res.status(400).json({
        error: "Compilation failed",
        details: compileError.message,
        suggestions: [
          "Check your Solidity syntax",
          "Ensure all imports are available",
          "Verify pragma version matches compiler version",
          "Check for any missing dependencies"
        ]
      });
    }

    // Handle compilation errors and warnings
    if (output.errors) {
      const errors = output.errors.filter((e) => e.severity === "error");
      const warnings = output.errors.filter((e) => e.severity === "warning");

      if (errors.length > 0) {
        console.error("Compilation errors:", errors);
        return res.status(400).json({
          error: "Compilation errors",
          details: errors.map((e) => e.formattedMessage),
          warnings: warnings.map((w) => w.formattedMessage),
        });
      }

      if (warnings.length > 0) {
        console.warn("Compilation warnings:", warnings);
      }
    }

    // Check if contracts were compiled
    if (!output.contracts || Object.keys(output.contracts).length === 0) {
      console.error("No contracts found in compilation output");
      return res.status(400).json({
        error: "No contracts found in compilation output",
        details: "The source code did not compile to any contract artifacts. Please check your Solidity code.",
      });
    }


    // 6. Enhanced bytecode comparison
    const normalizedOnchain = advancedNormalizeBytecode(onchainBytecode);
    // console.log("Normalized on-chain bytecode length:", normalizedOnchain.length);

    let bestMatch = null;
    let bestMatchPercentage = 0;

    // Iterate through all compiled contracts
    for (const file in output.contracts) {
      for (const name in output.contracts[file]) {
        const contract = output.contracts[file][name];

        // Skip if no deployed bytecode
        if (!contract.evm || !contract.evm.deployedBytecode || !contract.evm.deployedBytecode.object) {
          console.log(`Skipping contract ${name} - no deployed bytecode`);
          continue;
        }

        // Skip if specific contract name provided and doesn't match
        if (contractName && name !== contractName) {
          console.log(`Skipping contract ${name} - name filter applied`);
          continue;
        }

        let compiledDeployedBytecode = "0x" + contract.evm.deployedBytecode.object;

        // Handle constructor arguments if provided
        if (constructorArguments) {
          const creationBytecode = "0x" + contract.evm.bytecode.object;
          const expectedDeployedBytecode = simulateDeployment(
            creationBytecode,
            constructorArguments,
            normalizedOnchain
          );
          if (expectedDeployedBytecode) {
            compiledDeployedBytecode = expectedDeployedBytecode;
          }
        }

        const normalizedCompiled = advancedNormalizeBytecode(compiledDeployedBytecode);

        // console.log(`Contract ${name}:`);
        // console.log(`- Compiled bytecode length: ${normalizedCompiled.length}`);
        // console.log(`- On-chain bytecode length: ${normalizedOnchain.length}`);

        // Multiple comparison methods
        const exactMatch = compareExactMatch(normalizedOnchain, normalizedCompiled);
        const fuzzyMatch = compareFuzzyMatch(normalizedOnchain, normalizedCompiled);
        const structuralMatch = compareStructuralMatch(normalizedOnchain, normalizedCompiled);

        const matchPercentage = Math.max(exactMatch, fuzzyMatch, structuralMatch);

        // console.log(`- Exact match: ${exactMatch}%`);
        // console.log(`- Fuzzy match: ${fuzzyMatch}%`);
        // console.log(`- Structural match: ${structuralMatch}%`);
        // console.log(`- Best match: ${matchPercentage}%`);

        if (matchPercentage > bestMatchPercentage) {
          bestMatchPercentage = matchPercentage;
          bestMatch = {
            contract,
            name,
            file,
            matchPercentage,
            exactMatch,
            fuzzyMatch,
            structuralMatch,
          };
        }

        // Perfect match found
        if (matchPercentage === 100) {
          console.log("Perfect match found for contract:", name);
          break;
        }
      }
      if (bestMatchPercentage === 100) {
        break;
      }
    }

    const isVerified = bestMatchPercentage >= 98;
    const compiledBytecode = bestMatch ? "0x" + bestMatch.contract.evm.bytecode.object : "";
    const abi = bestMatch ? JSON.stringify(bestMatch.contract.abi) : "[]";

    // console.log("Verification result:", {
    //   contractName: bestMatch?.name,
    //   matchPercentage: bestMatchPercentage,
    //   isVerified,
    //   matchDetails: bestMatch ? {
    //     exact: bestMatch.exactMatch,
    //     fuzzy: bestMatch.fuzzyMatch,
    //     structural: bestMatch.structuralMatch,
    //   } : null,
    // });

    // 7. Save to DB with enhanced info
    try {
      conn = await db.getConnection();

      // Extract contract data if verification successful
      const contractData = bestMatch ? extractContractData(bestMatch.contract, bestMatch.name) : null;

      await conn.execute(
        `INSERT INTO contracts 
          (address, solSource, version, isOptimized, runs, abi, 
           compiledBytecodeLength, onchainBytecodeLength, matchPercentage, 
           isVerified, verificationMessage, verifiedAt, contractName, 
           constructorArgs, metadata, functionSignatures, eventSignatures) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON DUPLICATE KEY UPDATE 
          solSource = VALUES(solSource),
          version = VALUES(version),
          isOptimized = VALUES(isOptimized),
          runs = VALUES(runs),
          abi = VALUES(abi),
          compiledBytecodeLength = VALUES(compiledBytecodeLength),
          onchainBytecodeLength = VALUES(onchainBytecodeLength),
          matchPercentage = VALUES(matchPercentage),
          isVerified = VALUES(isVerified),
          verificationMessage = VALUES(verificationMessage),
          verifiedAt = VALUES(verifiedAt),
          contractName = VALUES(contractName),
          constructorArgs = VALUES(constructorArgs),
          metadata = VALUES(metadata),
          functionSignatures = VALUES(functionSignatures),
          eventSignatures = VALUES(eventSignatures),
          updatedAt = NOW()`,
        [
          address.toLowerCase(),
          sourceCode,
          compilerVersion,
          optimizationEnabled ? 1 : 0,
          optimizationRuns,
          abi,
          compiledBytecode.length,
          onchainBytecode.length,
          bestMatchPercentage,
          isVerified ? 1 : 0,
          isVerified
            ? `Verification successful for ${bestMatch?.name || "contract"}`
            : `Bytecode mismatch (${bestMatchPercentage}% best match)`,
          isVerified ? new Date() : null,
          contractData?.name || contractName || null,
          constructorArguments || null,
          contractData ? JSON.stringify(contractData.metadata) : null,
          contractData ? JSON.stringify(contractData.functionSignatures) : null,
          contractData ? JSON.stringify(contractData.eventSignatures) : null,
        ]
      );

      // console.log("Database insertion successful");

      // Verify the data was saved
      const [verifyRows] = await conn.execute(
        "SELECT isVerified, matchPercentage FROM contracts WHERE address = ?",
        [address.toLowerCase()]
      );
      // console.log("Post-insert verification check:", verifyRows[0]);
      
    } catch (dbError) {
      console.error("Database error:", dbError);
      // Continue with response even if DB save fails
    }

    // Return response
    if (isVerified) {
      return res.json({
        success: true,
        contractName: bestMatch?.name,
        message: `Verification successful for ${bestMatch?.name || "contract"}`,
        matchPercentage: bestMatchPercentage,
        matchDetails: {
          exact: bestMatch?.exactMatch,
          fuzzy: bestMatch?.fuzzyMatch,
          structural: bestMatch?.structuralMatch,
        },
        abi: bestMatch ? bestMatch.contract.abi : [],
      });
    } else {
      return res.status(400).json({
        success: false,
        error: "Bytecode mismatch",
        message: `Compiled bytecode does not match on-chain code (${bestMatchPercentage}% best match)`,
        matchPercentage: bestMatchPercentage,
        suggestions: generateVerificationSuggestions(bestMatchPercentage, bestMatch),
        details: bestMatchPercentage > 80
          ? "High similarity detected. Try adjusting compiler settings, constructor arguments, or check for imported library versions."
          : "Low similarity. Please verify the source code, compiler version, and optimization settings match the original deployment.",
      });
    }
    
  } catch (err) {
    console.error("Verification error:", err);
    return res.status(500).json({
      error: "Internal server error during verification",
      details: process.env.NODE_ENV === "development" 
        ? err.message 
        : "Please try again with different parameters.",
      stack: process.env.NODE_ENV === "development" ? err.stack : undefined
    });
  } finally {
    if (conn) {
      try {
        conn.release();
      } catch (releaseError) {
        console.error("Error releasing database connection:", releaseError);
      }
    }
  }
});

// Get contract details for your details page
app.get("/api/contracts/:address", async (req, res) => {
  const { address } = req.params;

  if (!/^0x[a-fA-F0-9]{40}$/.test(address)) {
    return res.status(400).json({ error: "Invalid address format" });
  }

  let conn;
  try {
    conn = await db.getConnection();

    const [rows] = await conn.execute(
      `SELECT 
        contractName, solSource, version, isOptimized, runs,
        abi, isVerified, verificationMessage, verifiedAt,
        constructorArgs, metadata, functionSignatures, eventSignatures,
        matchPercentage, compiledBytecodeLength, onchainBytecodeLength,
        address, updatedAt
      FROM contracts 
      WHERE address = ?`,
      [address]
    );

    if (rows.length === 0) {
      return res.status(404).json({
        error: "Contract not found",
        message: "This contract hasn't been verified yet.",
      });
    }

    const contract = rows[0];

    // Parse JSON fields safely
    const abi = safeParseJSON(contract.abi, []);
    const metadata = safeParseJSON(contract.metadata, {});
    const functionSigs = safeParseJSON(contract.functionSignatures, {});
    const eventSigs = safeParseJSON(contract.eventSignatures, {});

    // Format response for frontend
    const response = {
      success: true,
      contract: {
        // Basic contract info
        address: contract.address,
        name: contract.contractName,
        creator: contract.creator,
        blockNumber: contract.blockNumber,
        timestamp: contract.timestamp,

        // Token info (if applicable)
        type: contract.type,
        symbol: contract.symbol,
        totalSupply: contract.totalSupply,
        decimals: contract.decimals,

        // Verification info
        isVerified: Boolean(contract.isVerified),
        verification: {
          status: contract.isVerified ? "verified" : "unverified",
          matchPercentage: contract.matchPercentage,
          message: contract.verificationMessage,
          verifiedAt: contract.verifiedAt,
          compiler: {
            version: contract.version,
            optimization: {
              enabled: Boolean(contract.isOptimized),
              runs: contract.runs,
            },
          },
        },

        // Source code (only show if verified)
        sourceCode: contract.isVerified ? contract.solSource : null,
        constructorArguments: contract.constructorArgs,

        // Contract interface
        abi: abi,
        functions: extractFunctionsFromAbi(abi),
        events: extractEventsFromAbi(abi),

        // Additional metadata
        metadata: metadata,
        bytecode: {
          compiledLength: contract.compiledBytecodeLength,
          onchainLength: contract.onchainBytecodeLength,
        },

        // Timestamps
        createdAt: contract.createdAt,
        updatedAt: contract.updatedAt,
      },
    };

    res.json(response);
  } catch (err) {
    console.error("Error fetching contract details:", err);
    // res.status(500).json({ error: "Failed to fetch contract details" });
  } finally {
    if (conn) conn.release();
  }
});

// Get only source code (for code viewer)
app.get("/api/contracts/:address/source", async (req, res) => {
  const { address } = req.params;

  let conn;
  try {
    conn = await db.getConnection();

    const [rows] = await conn.execute(
      `SELECT solSource, contractName, version, isVerified 
      FROM contracts 
      WHERE address = ? AND isVerified = 1`,
      [address.toLowerCase()]
    );

    if (rows.length === 0) {
      return res
        .status(404)
        .json({ error: "Verified contract source not found" });
    }

    res.json({
      success: true,
      sourceCode: rows[0].solSource,
      contractName: rows[0].contractName,
      compilerVersion: rows[0].version,
    });
  } catch (err) {
    console.error("Error fetching source code:", err);
    res.status(500).json({ error: "Failed to fetch source code" });
  } finally {
    if (conn) conn.release();
  }
});

// Get only ABI (for contract interaction)
app.get("/api/contracts/:address/abi", async (req, res) => {
  const { address } = req.params;

  let conn;
  try {
    conn = await db.getConnection();

    const [rows] = await conn.execute(
      `SELECT abi, contractName, functionSignatures, eventSignatures
      FROM contracts 
      WHERE address = ? AND isVerified = 1`,
      [address.toLowerCase()]
    );

    if (rows.length === 0) {
      return res.status(404).json({ error: "Verified contract ABI not found" });
    }

    const contract = rows[0];
    const abi = safeParseJSON(contract.abi, []);

    res.json({
      success: true,
      contractName: contract.contractName,
      abi: abi,
      functions: extractFunctionsFromAbi(abi),
      events: extractEventsFromAbi(abi),
    });
  } catch (err) {
    console.error("Error fetching ABI:", err);
    res.status(500).json({ error: "Failed to fetch ABI" });
  } finally {
    if (conn) conn.release();
  }
});

// API documentation endpoint
app.get("/api/docs", authenticate, (req, res) => {
  res.json({
    name: "Universe Chain Explorer API",
    version: "1.0.0",
    description: "API for accessing Universe Chain EVM Testnet data",
    endpoints: [
      {
        method: "GET",
        path: "/api/network",
        description: "Get network information",
        rate_limit: "100 requests per minute",
      },
      {
        method: "GET",
        path: "/api/blocks",
        description: "Get latest blocks",
        rate_limit: "100 requests per minute",
      },
      {
        method: "GET",
        path: "/api/blocks/:number",
        description: "Get block by number",
        rate_limit: "100 requests per minute",
      },
      {
        method: "GET",
        path: "/api/transactions",
        description: "Get latest transactions",
        rate_limit: "100 requests per minute",
      },
      {
        method: "GET",
        path: "/api/transactions/:hash",
        description: "Get transaction by hash",
        rate_limit: "100 requests per minute",
      },
      {
        method: "GET",
        path: "/api/address/:address",
        description: "Get address information",
        rate_limit: "100 requests per minute",
      },
      {
        method: "GET",
        path: "/api/search/:query",
        description: "Search for blocks, transactions, or addresses",
        rate_limit: "100 requests per minute",
      },
      {
        method: "POST",
        path: "/api/verify-contract",
        description: "Verify a smart contract",
        rate_limit: "100 requests per minute",
      },
    ],
    rate_limiting: {
      free_tier: "100 requests per minute",
      authenticated_tier: "1000 requests per minute",
      basic_tier: "1000 requests per minute",
      premium_tier: "10000 requests per minute",
    },
    authentication: "Register for an account to get higher rate limits",
    endpoints: [
      {
        method: "GET",
        path: "/api/network",
        description: "Get network information",
        rate_limit:
          "100 requests per minute (free) or 1000 requests per minute (authenticated)",
      },
      {
        method: "GET",
        path: "/api/blocks",
        description: "Get latest blocks",
        rate_limit:
          "100 requests per minute (free) or 1000 requests per minute (authenticated)",
      },
      {
        method: "GET",
        path: "/api/blocks/:number",
        description: "Get block by number",
        rate_limit:
          "100 requests per minute (free) or 1000 requests per minute (authenticated)",
      },
      {
        method: "GET",
        path: "/api/transactions",
        description: "Get latest transactions",
        rate_limit:
          "100 requests per minute (free) or 1000 requests per minute (authenticated)",
      },
      {
        method: "GET",
        path: "/api/transactions/:hash",
        description: "Get transaction by hash",
        rate_limit:
          "100 requests per minute (free) or 1000 requests per minute (authenticated)",
      },
      {
        method: "GET",
        path: "/api/address/:address",
        description: "Get address information",
        rate_limit:
          "100 requests per minute (free) or 1000 requests per minute (authenticated)",
      },
      {
        method: "GET",
        path: "/api/search/:query",
        description: "Search for blocks, transactions, or addresses",
        rate_limit:
          "100 requests per minute (free) or 1000 requests per minute (authenticated)",
      },
      {
        method: "POST",
        path: "/api/verify-contract",
        description: "Verify a smart contract",
        rate_limit:
          "100 requests per minute (free) or 1000 requests per minute (authenticated)",
      },
      {
        method: "POST",
        path: "/api/register",
        description: "Register a new user account",
        rate_limit: "10 requests per minute",
      },
      {
        method: "POST",
        path: "/api/login",
        description: "Login to your account",
        rate_limit: "10 requests per minute",
      },
    ],
  });
});

// User registration endpoint
app.post("/api/register", async (req, res) => {
  try {
    const { username, email, password } = req.body;

    // Validate input
    if (!username || !email || !password) {
      return res
        .status(400)
        .json({ error: "Username, email, and password are required" });
    }

    // Check if user already exists
    const [existingUsers] = await db.execute(
      "SELECT id FROM users WHERE username = ? OR email = ?",
      [username, email]
    );

    if (existingUsers.length > 0) {
      return res
        .status(400)
        .json({ error: "Username or email already exists" });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

    // Insert new user
    const [result] = await db.execute(
      "INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
      [username, email, hashedPassword]
    );

    // Create JWT token
    const token = jwt.sign(
      { id: result.insertId, username, email },
      JWT_SECRET,
      { expiresIn: "24h" }
    );

    res.status(201).json({
      message: "User registered successfully",
      token,
      user: {
        id: result.insertId,
        username,
        email,
      },
    });
  } catch (error) {
    console.error("Error registering user:", error);
    res.status(500).json({ error: "Failed to register user" });
  }
});

// User login endpoint
app.post("/api/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    // Validate input
    if (!username || !password) {
      return res
        .status(400)
        .json({ error: "Username and password are required" });
    }

    // Find user
    const [users] = await db.execute(
      "SELECT id, username, email, password FROM users WHERE username = ?",
      [username]
    );

    if (users.length === 0) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const user = users[0];

    // Check password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    // Create JWT token
    const token = jwt.sign(
      { id: user.id, username: user.username, email: user.email },
      JWT_SECRET,
      { expiresIn: "24h" }
    );

    // Remove password from response
    const { password: _, ...userWithoutPassword } = user;

    res.json({
      message: "Login successful",
      token,
      user: userWithoutPassword,
    });
  } catch (error) {
    console.error("Error logging in:", error);
    res.status(500).json({ error: "Failed to login" });
  }
});

// Start server
server.listen(PORT, () => {
  console.log(`Universe Chain Explorer backend running on port ${PORT}`);
  console.log(`Connecting to RPC: https://rpc.ucscan.net`);
  console.log(`Chain ID: 1366`);
  console.log(`WebSocket server running on port ${PORT}`);
});

// WebSocket connection for real-time updates
io.on("connection", (socket) => {
  console.log("New client connected");

  // Send initial data
  sendLatestData(socket);

  // Set up interval to send updates
  const interval = setInterval(() => {
    sendLatestData(socket);
  }, 5000); // Send updates every 5 seconds

  socket.on("disconnect", () => {
    console.log("Client disconnected");
    clearInterval(interval);
  });
});


// Function to send latest data to connected clients
async function sendLatestData(socket) {
  try {
    // Get latest block
    const latestBlockNumber = await web3.eth.getBlockNumber();
    const latestBlock = await web3.eth.getBlock(latestBlockNumber);

    // Get latest transactions
    const latestTransactions = [];
    const block = await web3.eth.getBlock(latestBlockNumber, true);
    if (block && block.transactions) {
      for (let i = 0; i < Math.min(5, block.transactions.length); i++) {
        const tx = block.transactions[i];
        latestTransactions.push({
          hash: tx.hash,
          blockNumber: tx.blockNumber,
          timestamp: new Date(block.timestamp * 1000).toISOString(),
          from: tx.from,
          to: tx.to,
          value: web3.utils.fromWei(tx.value, "ether") + " tUCC",
          gasUsed: tx.gas,
          status: "success",
        });
      }
    }

    // Emit data to client
    socket.emit("latestData", {
      latestBlock: {
        number: latestBlock.number,
        hash: latestBlock.hash,
        timestamp: new Date(latestBlock.timestamp * 1000).toISOString(),
        transactions: latestBlock.transactions.length,
      },
      latestTransactions: latestTransactions,
    });
  } catch (error) {
    console.error("Error sending latest data:", error);
  }
}
