-- CREATE TABLE IF NOT EXISTS contracts (
--   id INT AUTO_INCREMENT PRIMARY KEY,
--   address VARCHAR(42) UNIQUE,
--   creator VARCHAR(42),
--   blockNumber BIGINT,
--   timestamp DATETIME,
--   type VARCHAR(20),
--   symbol VARCHAR(20),
--   isVerified TINYINT(1),
--   totalSupply BIGINT,
--   decimals INT
-- );

CREATE TABLE IF NOT EXISTS contracts (
  id INT AUTO_INCREMENT PRIMARY KEY,
  address VARCHAR(42) UNIQUE NOT NULL,
  creator VARCHAR(42),
  blockNumber BIGINT,
  timestamp DATETIME,
  type VARCHAR(20),
  symbol VARCHAR(20),
  isVerified TINYINT(1) DEFAULT 0,
  totalSupply BIGINT,
  decimals INT,
  solSource LONGTEXT,
  version VARCHAR(64),
  isOptimized TINYINT(1) DEFAULT 0,
  runs INT DEFAULT 200,
  abi LONGTEXT,
  compiledBytecodeLength INT,
  onchainBytecodeLength INT,
  matchPercentage INT,
  verificationMessage TEXT,
  verifiedAt DATETIME,
  createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
  updatedAt DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);
