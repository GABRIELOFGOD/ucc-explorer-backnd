const Web3 = require('web3');
const BN = require("bn.js");

// ERC-20 ABI for balanceOf function and Transfer event
// const ERC20_ABI = [
//   {
//     "constant": true,
//     "inputs": [{"name": "_owner", "type": "address"}],
//     "name": "balanceOf",
//     "outputs": [{"name": "balance", "type": "uint256"}],
//     "type": "function"
//   },
//   {
//     "constant": true,
//     "inputs": [],
//     "name": "decimals",
//     "outputs": [{"name": "", "type": "uint8"}],
//     "type": "function"
//   },
//   {
//     "constant": true,
//     "inputs": [],
//     "name": "symbol",
//     "outputs": [{"name": "", "type": "string"}],
//     "type": "function"
//   },
//   {
//     "anonymous": false,
//     "inputs": [
//       {"indexed": true, "name": "from", "type": "address"},
//       {"indexed": true, "name": "to", "type": "address"},
//       {"indexed": false, "name": "value", "type": "uint256"}
//     ],
//     "name": "Transfer",
//     "type": "event"
//   }
// ];

const ERC20_ABI = [
  {
    "inputs": [{"internalType": "address","name": "owner","type": "address"}],
    "name": "balanceOf",
    "outputs": [{"internalType": "uint256","name": "","type": "uint256"}],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [],
    "name": "decimals",
    "outputs": [{"internalType": "uint8","name": "","type": "uint8"}],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [],
    "name": "symbol",
    "outputs": [{"internalType": "string","name": "","type": "string"}],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [],
    "name": "name",
    "outputs": [{"internalType": "string","name": "","type": "string"}],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "anonymous": false,
    "inputs": [
      {"indexed": true,"internalType": "address","name": "from","type": "address"},
      {"indexed": true,"internalType": "address","name": "to","type": "address"},
      {"indexed": false,"internalType": "uint256","name": "value","type": "uint256"}
    ],
    "name": "Transfer",
    "type": "event"
  }
];

// Function to fetch token balance for an address
// async function getTokenBalance(web3, tokenAddress, userAddress) {
//   try {
//     const tokenContract = new web3.eth.Contract(ERC20_ABI, tokenAddress);
//     const balance = await tokenContract.methods.balanceOf(userAddress).call();
//     const decimals = await tokenContract.methods.decimals().call();
//     const symbol = await tokenContract.methods.symbol().call();
    
//     // Convert balance to decimal format
//     const balanceDecimal = parseFloat(balance) / (10 ** decimals);
    
//     return {
//       tokenAddress,
//       symbol,
//       balance: balanceDecimal,
//       rawBalance: balance
//     };
//   } catch (error) {
//     console.error(`Error fetching balance for token ${tokenAddress}:`, error);
//     return null;
//   }
// }

async function getTokenBalance(web3, tokenAddress, userAddress) {
  try {
    const tokenContract = new web3.eth.Contract(ERC20_ABI, tokenAddress);

    const [balance, decimals, symbol, name] = await Promise.all([
      tokenContract.methods.balanceOf(userAddress).call(),
      tokenContract.methods.decimals().call(),
      tokenContract.methods.symbol().call(),
      tokenContract.methods.name().call(),
    ]);

    const balanceDecimal = parseFloat(balance) / (10 ** decimals);

    return {
      tokenAddress,
      name,
      symbol,
      decimals,
      balance: balanceDecimal,
      rawBalance: balance
    };
  } catch (error) {
    console.error(`Error fetching balance for token ${tokenAddress}:`, error);
    return null;
  }
}

// Function to fetch all token balances for an address
async function getAllTokenBalances(web3, userAddress, tokenAddresses) {
  const tokenBalances = [];
  
  // Fetch balance for each token
  for (const tokenAddress of tokenAddresses) {
    const balance = await getTokenBalance(web3, tokenAddress, userAddress);
    if (balance) {
      tokenBalances.push(balance);
    }
  }
  
  return tokenBalances;
}

// Function to fetch token transfer events for a contract
// async function getTokenTransactions(web3, tokenAddress, fromBlock = 0, toBlock = 'latest') {
//   try {
//     const tokenContract = new web3.eth.Contract(ERC20_ABI, tokenAddress);
    
//     // Get transfer events
//     const events = await tokenContract.getPastEvents('Transfer', {
//       fromBlock: fromBlock,
//       toBlock: toBlock
//     });
    
//     // Get token decimals and symbol for value formatting
//     let decimals = 18;
//     let symbol = 'TOKEN';
//     try {
//       decimals = await tokenContract.methods.decimals().call();
//       symbol = await tokenContract.methods.symbol().call();
//     } catch (error) {
//       console.warn(`Could not fetch token metadata for ${tokenAddress}:`, error);
//     }
    
//     // Format events
//     const transactions = events.map(event => {
//       const value = parseFloat(event.returnValues.value) / (10 ** decimals);
      
//       return {
//         transactionHash: event.transactionHash,
//         blockNumber: event.blockNumber,
//         from: event.returnValues.from,
//         to: event.returnValues.to,
//         value: value,
//         symbol: symbol,
//         rawValue: event.returnValues.value
//       };
//     });
    
//     return transactions;
//   } catch (error) {
//     console.error(`Error fetching token transactions for ${tokenAddress}:`, error);
//     return [];
//   }
// }

async function getTokenTransactions(web3, tokenAddress, fromBlock = 0, toBlock = "latest") {
  try {
    const tokenContract = new web3.eth.Contract(ERC20_ABI, tokenAddress);

    // Resolve latest block
    const latestBlock =
      toBlock === "latest" ? await web3.eth.getBlockNumber() : toBlock;

    // Get token metadata
    let decimals = 18;
    let symbol = "TOKEN";
    try {
      decimals = await tokenContract.methods.decimals().call();
      symbol = await tokenContract.methods.symbol().call();
    } catch (error) {
      console.warn(`Could not fetch token metadata for ${tokenAddress}:`, error);
    }

    const step = 2000; // safe chunk size (adjust if Besu still complains)
    let allTransactions = [];

    // Fetch events in chunks
    for (let start = fromBlock; start <= latestBlock; start += step) {
      const end = Math.min(start + step - 1, latestBlock);

      const events = await tokenContract.getPastEvents("Transfer", {
        fromBlock: start,
        toBlock: end,
      });

      const transactions = events.map((event) => {
        const value = Number(event.returnValues.value) / 10 ** decimals;

        return {
          transactionHash: event.transactionHash,
          blockNumber: event.blockNumber,
          from: event.returnValues.from,
          to: event.returnValues.to,
          value,
          symbol,
          rawValue: event.returnValues.value,
        };
      });

      allTransactions = allTransactions.concat(transactions);
    }

    // Sort by blockNumber ascending (or descending if you prefer latest first)
    allTransactions.sort((a, b) => a.blockNumber - b.blockNumber);

    return allTransactions;
  } catch (error) {
    console.error(`Error fetching token transactions for ${tokenAddress}:`, error);
    return [];
  }
}

// Function to fetch token holders for a contract
// async function getTokenHolders(web3, tokenAddress, fromBlock = 0, toBlock = 'latest') {
//   try {
//     const tokenContract = new web3.eth.Contract(ERC20_ABI, tokenAddress);
    
//     // Get transfer events
//     const events = await tokenContract.getPastEvents('Transfer', {
//       fromBlock: fromBlock,
//       toBlock: toBlock
//     });
    
//     // Get token decimals and symbol for value formatting
//     let decimals = 18;
//     let symbol = 'TOKEN';
//     try {
//       decimals = await tokenContract.methods.decimals().call();
//       symbol = await tokenContract.methods.symbol().call();
//     } catch (error) {
//       console.warn(`Could not fetch token metadata for ${tokenAddress}:`, error);
//     }
    
//     // Track holder balances
//     const holderBalances = {};
    
//     // Process events to calculate balances
//     for (const event of events) {
//       const from = event.returnValues.from;
//       const to = event.returnValues.to;
//       const value = parseFloat(event.returnValues.value);
      
//       // Subtract from sender
//       if (from !== '0x0000000000000000000000000000000000000000') {
//         if (!holderBalances[from]) {
//           holderBalances[from] = 0;
//         }
//         holderBalances[from] -= value;
//       }
      
//       // Add to receiver
//       if (!holderBalances[to]) {
//         holderBalances[to] = 0;
//       }
//       holderBalances[to] += value;
//     }
    
//     // Convert to array and filter out zero balances
//     const holders = Object.entries(holderBalances)
//       .map(([address, rawBalance]) => {
//         const balance = rawBalance / (10 ** decimals);
//         return {
//           address,
//           balance,
//           rawBalance,
//           symbol
//         };
//       })
//       .filter(holder => holder.balance > 0)
//       .sort((a, b) => b.balance - a.balance); // Sort by balance descending
    
//     return holders;
//   } catch (error) {
//     console.error(`Error fetching token holders for ${tokenAddress}:`, error);
//     return [];
//   }
// }

async function getTokenHolders(web3, tokenAddress, fromBlock = 0, toBlock = "latest") {
  try {
    const tokenContract = new web3.eth.Contract(ERC20_ABI, tokenAddress);

    // Get latest block number if "latest" was passed
    const latestBlock =
      toBlock === "latest" ? await web3.eth.getBlockNumber() : toBlock;

    // Get token metadata
    let decimals = 18;
    let symbol = "TOKEN";
    try {
      decimals = await tokenContract.methods.decimals().call();
      symbol = await tokenContract.methods.symbol().call();
    } catch (error) {
      console.warn(`Could not fetch token metadata for ${tokenAddress}:`, error);
    }

    const step = 2000; // Besu’s safe range; adjust if needed
    const holderBalances = {};

    // Fetch in chunks
    for (let start = fromBlock; start <= latestBlock; start += step) {
      const end = Math.min(start + step - 1, latestBlock);

      const events = await tokenContract.getPastEvents("Transfer", {
        fromBlock: start,
        toBlock: end,
      });

      // Process events
      for (const event of events) {
        const { from, to, value } = event.returnValues;
        const amount = new BN(value);

        // Subtract from sender
        if (from !== "0x0000000000000000000000000000000000000000") {
          if (!holderBalances[from]) holderBalances[from] = new BN(0);
          holderBalances[from] = holderBalances[from].sub(amount);
        }

        // Add to receiver
        if (to !== "0x0000000000000000000000000000000000000000") {
          if (!holderBalances[to]) holderBalances[to] = new BN(0);
          holderBalances[to] = holderBalances[to].add(amount);
        }
      }
    }

    // Format results
    const holders = Object.entries(holderBalances)
      .map(([address, rawBN]) => {
        const rawBalance = rawBN;
        const balance = parseFloat(rawBN.toString()) / 10 ** decimals;
        return {
          address,
          balance,
          rawBalance: rawBN.toString(),
          symbol,
        };
      })
      .filter((holder) => holder.balance > 0)
      .sort((a, b) => b.balance - a.balance);

    return holders;
  } catch (error) {
    console.error(`Error fetching token holders for ${tokenAddress}:`, error);
    return [];
  }
}

// Function to get known token contracts (for now, we'll use a static list)
// In a production environment, this would be fetched from a database or API
const mysql = require('mysql2/promise');
const dbConfig = {
  host: "localhost",
  user: "root",
  password: "P@55word",
  database: "ucc_chain_test",
};

let dbPool;
function getDbPool() {
  if (!dbPool) dbPool = mysql.createPool(dbConfig);
  return dbPool;
}

async function getKnownTokenContracts() {
  try {
    const db = getDbPool();
    const [rows] = await db.query('SELECT address, isVerified FROM contracts');
    // console.log(rows);
    return rows.map(r => r.address);
  } catch (err) {
    console.error('Error fetching token contracts from DB:', err);
    return [];
  }
}

async function indexContractsFromChain(web3, fromBlock = 100000, toBlock = "latest") {
  try {
    const latestBlock = toBlock === "latest" ? await web3.eth.getBlockNumber() : toBlock;

    const db = getDbPool();

    const step = 100; // adjust chunk size depending on RPC limits
    for (let start = fromBlock; start <= latestBlock; start += step) {
      const end = Math.min(start + step - 1, latestBlock);
      console.log(`📦 Scanning blocks ${start} → ${end}`);

      const blocks = await Promise.all(

        Array.from({ length: end - start + 1 }, (_, i) =>
          web3.eth.getBlock(start + i, true)
        )
      );

      for (const block of blocks) {
        if (!block || !block.transactions || block.transactions.length < 1) continue;

        for (const tx of block.transactions) {
          // Contract creation has tx.to = null
          if (!tx.to) {
            try {
              const receipt = await web3.eth.getTransactionReceipt(tx.hash);
              if (receipt && receipt.contractAddress) {
                let isERC20 = false;
                let symbol = null;
                let totalSupply = null;
                let decimals = null;

                try {
                  const contract = new web3.eth.Contract(ERC20_ABI, receipt.contractAddress);

                  // Probe ERC20 methods
                  totalSupply = await contract.methods.totalSupply().call();
                  symbol = await contract.methods.symbol().call();
                  decimals = await contract.methods.decimals().call();
                  isERC20 = true;
                } catch (e) {
                  console.log(`ℹ️ Not ERC20: ${receipt.contractAddress}`);
                }

                // Debug log before insert
                // console.log("📝 Preparing to save contract:", {
                //   address: receipt.contractAddress,
                //   creator: tx.from,
                //   block: block.number,
                //   timestamp: block.timestamp,
                //   type: isERC20 ? "ERC20" : "other",
                //   symbol,
                //   totalSupply,
                //   decimals,
                // });

                // Insert / update into DB
                try {
                  const [result] = await db.execute(
                    `INSERT INTO contracts
                       (address, creator, blockNumber, timestamp, type, symbol, isVerified, totalSupply, decimals)
                     VALUES (?, ?, ?, FROM_UNIXTIME(?), ?, ?, ?, ?, ?)
                     ON DUPLICATE KEY UPDATE
                       blockNumber = VALUES(blockNumber),
                       timestamp = VALUES(timestamp),
                       type = VALUES(type),
                       symbol = VALUES(symbol),
                       totalSupply = VALUES(totalSupply),
                       decimals = VALUES(decimals)`,
                    [
                      receipt.contractAddress,
                      tx.from,
                      block.number,
                      block.timestamp,
                      isERC20 ? "ERC20" : "other",
                      symbol,
                      false,
                      totalSupply,
                      decimals,
                    ]
                  );

                  // Debug result of DB insert
                  console.log("✅ DB insert/update result:", result);
                } catch (dbErr) {
                  console.error(`❌ DB error for contract ${receipt.contractAddress}:`, dbErr);
                }

                (
                  `🆕 Contract found: ${receipt.contractAddress} (type: ${
                    isERC20 ? "ERC20" : "other"
                  }, symbol: ${symbol || "-"})`
                );
              }
            } catch (err) {
              console.error(
                `❌ Error processing contract creation in block ${block.number}:`,
                err.message
              );
            }
          }
        }
      }
    }

    console.log("✅ Initial contract indexing finished.");
  } catch (err) {
    console.error("console.log❌ Error indexing contracts:", err);
  }
}

async function indexTransactionsFromChain(web3, fromBlock = 0, toBlock = "latest") {
  try {
    const latestBlock = toBlock === "latest" ? await web3.eth.getBlockNumber() : toBlock;

    const db = getDbPool();

    const step = 100; // adjust batch size depending on RPC
    for (let start = fromBlock; start <= latestBlock; start += step) {
      const end = Math.min(start + step - 1, latestBlock);
      console.log(`📦 Scanning blocks ${start} → ${end}`);

      // Fetch blocks in parallel with transactions included
      const blocks = await Promise.all(
        Array.from({ length: end - start + 1 }, (_, i) =>
          web3.eth.getBlock(start + i, true)
        )
      );

      for (const block of blocks) {
        if (!block || !block.transactions || block.transactions.length < 1) continue;

        for (const tx of block.transactions) {
          try {
            const receipt = await web3.eth.getTransactionReceipt(tx.hash);
            if (!receipt) continue;

            const value = web3.utils.fromWei(tx.value, "ether"); // store in ether for readability
            const gas = receipt.gasUsed?.toString() || tx.gas?.toString() || "0";
            const gasPrice = tx.gasPrice?.toString() || "0";

            try {
              await db.execute(
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
                  value,
                  gas,
                  gasPrice,
                  block.timestamp,
                ]
              );
              console.log(`✅ Tx saved: ${tx.hash}`);
            } catch (dbErr) {
              console.error(`❌ DB error for tx ${tx.hash}:`, dbErr);
            }
          } catch (err) {
            console.error(`❌ Error processing tx ${tx.hash}:`, err.message);
          }
        }
      }
    }

    console.log("✅ Initial transaction indexing finished.");
  } catch (err) {
    console.error("❌ Error indexing transactions:", err);
  }
}

const getDataBaseTransactions = async () => {
  console.log("Started")
  try {
    const db = getDbPool();
    const all = await db.execute(
      `SELECT * FROM transactions 
         ORDER BY blockNumber DESC`
    )
    console.log("Started")

    console.log("ALL", all);
    return all;
  } catch (error) {
    console.log("ERROR", error);
  }
}


module.exports = {
  getTokenBalance,
  getAllTokenBalances,
  getTokenTransactions,
  getTokenHolders,
  getDataBaseTransactions,
  getKnownTokenContracts,
  indexContractsFromChain,
  ERC20_ABI,
  indexTransactionsFromChain
};