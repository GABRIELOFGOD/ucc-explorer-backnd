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
const { ethers } = require("ethers");

const {
  getAllTokenBalances,
  getTokenTransactions,
  getTokenHolders,
  getKnownTokenContracts,
  indexContractsFromChain,
} = require("./utils");

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
app.use(cors(
  {
    origin: ["http://localhost:3000", "https://ucscan.net"],
    methods: ["GET", "POST"],
  }
));
app.use(express.json());
app.use(express.static("public"));

const RPC_WS = "ws://168.231.122.245:8546";
const RPC_API = "http://168.231.122.245:8545";

// Initialize Web3 with the RPC endpoint
const web3 = new Web3("http://168.231.122.245:8545");
const web3Ws = new Web3(RPC_WS);

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
  .on("connected", () =>
    console.log("🔗 Connected to WebSocket node (Validator)")
  )
  .on("data", async (blockHeader) => {
    try {
      const block = await web3Ws.eth.getBlock(blockHeader.number, true);
      if (!block || block.transactions.length < 1) return;

      for (const tx of block.transactions) {
        // Save transaction
        await db.execute(
          `INSERT IGNORE INTO transactions 
            (hash, blockNumber, fromAddress, toAddress, value, gas, gasPrice, timestamp)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
          [
            tx.hash,
            tx.blockNumber,
            tx.from,
            tx.to,
            tx.value,
            tx.gas,
            tx.gasPrice,
            new Date(block.timestamp * 1000).toISOString(),
          ]
        );

        // Detect contract creation (to == null)
        // if (!tx.to) {
        //   try {
        //     const receipt = await web3Ws.eth.getTransactionReceipt(tx.hash);
        //     if (receipt && receipt.contractAddress) {
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
        //       } catch (e) {
        //         console.log(`ℹ️ Not ERC20: ${receipt.contractAddress}`);
        //       }

        //       // Debug log before saving
        //       console.log("📝 Saving contract to DB:", {
        //         address: receipt.contractAddress,
        //         creator: tx.from,
        //         block: block.number,
        //         timestamp: block.timestamp,
        //         type: isERC20 ? "ERC20" : "other",
        //         symbol,
        //         totalSupply,
        //         decimals,
        //       });

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

        //         console.log("✅ DB insert/update result:", result);
        //         console.log(
        //           `🆕 Contract detected: ${receipt.contractAddress} (type: ${
        //             isERC20 ? "ERC20" : "other"
        //           }, symbol: ${symbol || "-"})`
        //         );
        //       } catch (dbErr) {
        //         console.error(
        //           `❌ DB error for contract ${receipt.contractAddress}:`,
        //           dbErr
        //         );
        //       }
        //     }
        //   } catch (err) {
        //     console.error("❌ Error processing contract creation:", err);
        //   }
        // }
      }

      console.log(
        `✅ Indexed block ${block.number} (${block.transactions.length} txs)`
      );
    } catch (err) {
      console.error("❌ Error processing block:", err);
    }
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

// Get latest transactions
// app.get('/api/transactions', authenticate, rateLimiter, async (req, res) => {
//   try {
//     const page = parseInt(req.query.page) || 1;
//     const limit = parseInt(req.query.limit) || 10;

//     // Get latest block number
//     const latestBlockNumber = await web3.eth.getBlockNumber();

//     // Fetch transactions from latest blocks
//     const transactions = [];
//     let blockNumber = latestBlockNumber;
//     let txCount = 0;

//     while (txCount < limit && blockNumber >= 0) {
//       const block = await web3.eth.getBlock(blockNumber, true);

//       if (block && block.transactions) {
//         // Add transactions from this block (in reverse order to get latest first)
//         for (let i = block.transactions.length - 1; i >= 0 && txCount < limit; i--) {
//           const tx = block.transactions[i];
//           transactions.push({
//             hash: tx.hash,
//             blockNumber: tx.blockNumber,
//             timestamp: new Date(block.timestamp * 1000).toISOString(),
//             from: tx.from,
//             to: tx.to,
//             value: web3.utils.fromWei(tx.value, 'ether') + ' tUCC',
//             gasUsed: tx.gas,
//             status: 'success' // Assuming success for simplicity
//           });
//           txCount++;
//         }
//       }

//       blockNumber--;

//       // Safety check to prevent infinite loop
//       if (latestBlockNumber - blockNumber > 100) {
//         break;
//       }
//     }

//     res.json({
//       transactions,
//       totalPages: Math.ceil(latestBlockNumber / limit),
//       currentPage: page
//     });
//   } catch (error) {
//     console.error('Error fetching transactions:', error);
//     res.status(500).json({ error: 'Failed to fetch transactions' });
//   }
// });

// Get transaction by hash

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
    tokens
  });
});

app.get("/api/fix", authenticate, rateLimiter, async (req, res) => {
  try {
    await indexContractsFromChain(web3);
    res.status(200).json({
      message: "FIXING COMPLETED"
    })
  } catch (error) {
    res.status(500).json({ error: "Fix failed", err: error });
  }
})

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
app.get(
  "/api/address/:address",
  authenticate,
  rateLimiter,
  async (req, res) => {
    try {
      const address = req.params.address;

      // Validate address
      if (!web3.utils.isAddress(address)) {
        return res.status(400).json({ error: "Invalid address" });
      }

      // Get balance
      const balance = await web3.eth.getBalance(address);

      // Get code to check if it's a contract
      const code = await web3.eth.getCode(address);
      const isContract = code !== "0x";

      // Get transaction count
      const txnCount = await web3.eth.getTransactionCount(address);

      // Check if contract is verified (mock implementation)
      const isVerified =
        address === "0x1234567890abcdef1234567890abcdef12345678"; // Mock verified address

      // Get token balances
      const knownTokens = await getKnownTokenContracts();
      const tokenBalances = await getAllTokenBalances(
        web3,
        address,
        knownTokens
      );

      // Get contract info if it's a contract
      let contractInfo = null;
      if (isContract) {
        contractInfo = {
          isVerified: isVerified,
          abi: isVerified
            ? '[{"inputs":[],"name":"getValue","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"}]'
            : null,
          sourceCode: isVerified
            ? "contract SimpleStorage { uint256 value; }"
            : null,
        };
      }

      res.json({
        address: address,
        balance: web3.utils.fromWei(balance, "ether") + " tUCC",
        tokenBalances: tokenBalances,
        isContract: isContract,
        isVerified: isVerified,
        txnCount: txnCount,
        contractInfo: contractInfo,
      });
    } catch (error) {
      console.error("Error fetching address info:", error);
      res.status(500).json({ error: "Failed to fetch address info" });
    }
  }
);

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
// app.post("/api/verify-contract", authenticate, rateLimiter, async (req, res) => {
//   try {
//     const { address, sourceCode, compilerVersion, optimization } = req.body;

//     // 1. Validate contract address
//     if (!web3.utils.isAddress(address)) {
//       return res.status(400).json({ error: "Invalid address" });
//     }

//     const deployedCode = await web3.eth.getCode(address);
//     if (deployedCode === "0x") {
//       return res.status(400).json({ error: "Address is not a contract" });
//     }

//     // 2. Load specified solc version
//     const solcInstance = await new Promise((resolve, reject) => {
//       solc.loadRemoteVersion(compilerVersion, (err, solcSpecific) => {
//         if (err) reject(err);
//         else resolve(solcSpecific);
//       });
//     });

//     // 3. Prepare input for compilation
//     const input = {
//       language: "Solidity",
//       sources: {
//         "Contract.sol": { content: sourceCode },
//       },
//       settings: {
//         optimizer: { enabled: optimization, runs: 200 },
//         outputSelection: { "*": { "*": ["evm.bytecode.object"] } },
//       },
//     };

//     // 4. Compile
//     const output = JSON.parse(solcInstance.compile(JSON.stringify(input)));

//     if (output.errors) {
//       return res.status(400).json({ error: "Compilation failed", details: output.errors });
//     }

//     const compiledBytecode =
//       output.contracts["Contract.sol"][Object.keys(output.contracts["Contract.sol"])[0]]
//         .evm.bytecode.object;

//     // 5. Compare deployed and compiled bytecode (ignoring metadata)
//     const normalize = (code) => code.replace(/a165627a7a72305820.*0029$/, "");
//     const match = normalize(deployedCode) === normalize("0x" + compiledBytecode);

//     if (!match) {
//       return res.status(400).json({ error: "Bytecode mismatch – contract not verified" });
//     }

//     // 6. Save verified contract info in DB
//     await db.query("UPDATE contracts SET isVerified = 1 WHERE address = ?", [address]);

//     res.json({
//       success: true,
//       message: "Contract verified successfully",
//       address,
//       compilerVersion,
//       optimization,
//     });
//   } catch (error) {
//     console.error("Error verifying contract:", error);
//     res.status(500).json({ error: "Failed to verify contract" });
//   }
// });

app.post("/api/verify-contract", authenticate, rateLimiter, async (req, res) => {
  const { address, compilerVersion, optimization, runs, sourceCode } = req.body;

  if (!address || !compilerVersion || !sourceCode) {
    return res.status(400).json({ error: "Missing required fields" });
  }

  try {
    // 1. Get on-chain deployed bytecode
    const provider = new ethers.JsonRpcProvider(RPC_API);
    const onchainBytecode = await provider.getCode(address);
    if (!onchainBytecode || onchainBytecode === "0x") {
      return res.status(404).json({ error: "Contract not found on-chain" });
    }

    // 2. Prepare solc input
    const input = {
      language: "Solidity",
      sources: {
        "Contract.sol": { content: sourceCode }
      },
      settings: {
        optimizer: {
          enabled: optimization === true,
          runs: runs || 200
        },
        outputSelection: {
          "*": {
            "*": ["abi", "evm.bytecode.object", "evm.deployedBytecode.object"]
          }
        }
      }
    };

    // 3. Load the requested compiler version
    const solcjs = await new Promise((resolve, reject) => {
      solc.loadRemoteVersion(compilerVersion, (err, solcSnapshot) => {
        if (err) return reject(err);
        resolve(solcSnapshot);
      });
    });

    // 4. Compile with the right version
    const output = JSON.parse(solcjs.compile(JSON.stringify(input)));
    if (output.errors) {
      const errors = output.errors.filter(e => e.severity === "error");
      if (errors.length > 0) {
        return res.status(400).json({ error: errors.map(e => e.formattedMessage) });
      }
    }

    // 5. Try to match one of the compiled contracts with on-chain bytecode
    let matchedContract = null;
    let matchedName = null;

    for (const fileName in output.contracts) {
      for (const contractName in output.contracts[fileName]) {
        const contract = output.contracts[fileName][contractName];
        const compiledRuntime = "0x" + contract.evm.deployedBytecode.object;

        if (compiledRuntime && compiledRuntime.length > 2) {
          if (onchainBytecode.startsWith(compiledRuntime)) {
            matchedContract = contract;
            matchedName = contractName;
            break;
          }
        }
      }
      if (matchedContract) break;
    }

    if (!matchedContract) {
      return res.status(400).json({ error: "No matching contract found in compilation output" });
    }

    // 6. Extract details
    const compiledBytecode = "0x" + matchedContract.evm.bytecode.object;
    const abi = JSON.stringify(matchedContract.abi);

    const compiledLength = compiledBytecode.length;
    const onchainLength = onchainBytecode.length;
    const isMatch = onchainBytecode.startsWith("0x" + matchedContract.evm.deployedBytecode.object);

    // 7. Store in DB
    const conn = await pool.getConnection();
    await conn.execute(
      `INSERT INTO contracts 
      (address, solSource, version, isOptimized, runs, abi, compiledBytecodeLength, onchainBytecodeLength, matchPercentage, isVerified, verificationMessage, verifiedAt) 
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())
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
      verifiedAt = VALUES(verifiedAt)`,
      [
        address,
        sourceCode,
        compilerVersion,
        optimization ? 1 : 0,
        runs || 200,
        abi,
        compiledLength,
        onchainLength,
        isMatch ? 100 : 0,
        isMatch ? 1 : 0,
        isMatch ? `Verification successful for ${matchedName}` : "Bytecode mismatch"
      ]
    );
    conn.release();

    return res.json({
      success: isMatch,
      contractName: matchedName,
      message: isMatch
        ? `Verification successful for ${matchedName}`
        : "Bytecode mismatch"
    });

  } catch (err) {
    console.error("Verification error:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// API documentation
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
  console.log(`Connecting to RPC: http://168.231.122.245:8545`);
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
