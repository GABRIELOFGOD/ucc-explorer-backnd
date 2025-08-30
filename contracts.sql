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

-- CREATE TABLE IF NOT EXISTS contracts (
--   id INT AUTO_INCREMENT PRIMARY KEY,
--   address VARCHAR(42) UNIQUE NOT NULL,
--   creator VARCHAR(42),
--   blockNumber BIGINT,
--   timestamp DATETIME,
--   type VARCHAR(20),
--   symbol VARCHAR(20),
--   isVerified TINYINT(1) DEFAULT 0,
--   totalSupply BIGINT,
--   decimals INT,
--   solSource LONGTEXT,
--   version VARCHAR(64),
--   isOptimized TINYINT(1) DEFAULT 0,
--   runs INT DEFAULT 200,
--   abi LONGTEXT,
--   compiledBytecodeLength INT,
--   onchainBytecodeLength INT,
--   matchPercentage INT,
--   verificationMessage TEXT,
--   verifiedAt DATETIME,
--   createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
--   updatedAt DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
-- );

CREATE TABLE IF NOT EXISTS contracts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    address VARCHAR(255) NOT NULL UNIQUE,
    solSource MEDIUMTEXT,
    version VARCHAR(50),
    isOptimized BOOLEAN,
    runs INT,
    abi LONGTEXT,
    compiledBytecodeLength INT,
    onchainBytecodeLength INT,
    matchPercentage DECIMAL(7,3) DEFAULT 0, -- allows up to 9999.999
    isVerified BOOLEAN,
    verificationMessage TEXT,
    verifiedAt DATETIME,
    contractName VARCHAR(255),
    constructorArgs TEXT,
    metadata LONGTEXT,
    functionSignatures LONGTEXT,
    eventSignatures LONGTEXT,
    createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);
