// const mysql = require('mysql2/promise');
const mysql = require("mysql2/promise");


class DatabaseService {
  constructor() {
    this.pool = null;
    this.isConnected = false;
    this.initializePool();
  }

  initializePool() {
    const dbConfig = {
      host: process.env.DB_HOST || 'localhost',
      user: process.env.DB_USER || 'root',
      password: process.env.DB_PASSWORD || 'P@55word',
      database: process.env.DB_NAME || 'ucc_chain_test',
      port: process.env.DB_PORT || 3306,
      waitForConnections: true,
      connectionLimit: 15,
      queueLimit: 0,
      charset: 'utf8mb4',
      timezone: '+00:00',
      supportBigNumbers: true,
      bigNumberStrings: true,
      dateStrings: false,
      multipleStatements: false,
      idleTimeout: 60000,
      maxIdle: 10
    };

    this.pool = mysql.createPool(dbConfig);
    console.log('Database pool initialized with config:', {
      host: dbConfig.host,
      database: dbConfig.database,
      connectionLimit: dbConfig.connectionLimit
    });
  }

  async getConnection(retries = 3) {
    for (let attempt = 1; attempt <= retries; attempt++) {
      try {
        const connection = await this.pool.getConnection();
        return connection;
      } catch (error) {
        console.error(`Database connection attempt ${attempt}/${retries} failed:`, error.message);
        if (attempt === retries) {
          throw new Error(`Failed to get database connection after ${retries} attempts: ${error.message}`);
        }
        await this.delay(1000 * attempt);
      }
    }
  }

  async testConnection() {
    let connection;
    try {
      connection = await this.getConnection();
      const [rows] = await connection.execute('SELECT 1 as test, NOW() as timestamp');
      this.isConnected = true;
      console.log('✅ Database connection test successful:', rows[0]);
      return true;
    } catch (error) {
      this.isConnected = false;
      console.error('❌ Database connection test failed:', error.message);
      return false;
    } finally {
      if (connection) connection.release();
    }
  }

  // Contract verification methods
  async saveContractVerification(verificationData) {
    const {
      address,
      sourceCode,
      compilerVersion,
      optimizationEnabled,
      optimizationRuns,
      abi,
      compiledBytecode,
      onchainBytecode,
      matchPercentage,
      isVerified,
      verificationMessage,
      contractName,
      constructorArguments,
      metadata,
      functionSignatures,
      eventSignatures
    } = verificationData;

    let connection;
    try {
      connection = await this.getConnection();
      
      // Start transaction
      await connection.beginTransaction();

      console.log('Saving contract verification:', {
        address: address.toLowerCase(),
        isVerified,
        matchPercentage: matchPercentage.toFixed(2)
      });

      const [result] = await connection.execute(`
        INSERT INTO contracts 
        (address, solSource, version, isOptimized, runs, abi, 
         compiledBytecodeLength, onchainBytecodeLength, matchPercentage, 
         isVerified, verificationMessage, verifiedAt, contractName, 
         constructorArgs, metadata, functionSignatures, eventSignatures, 
         createdAt, updatedAt) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW())
        ON DUPLICATE KEY UPDATE 
          solSource = VALUES(solSource),
          version = VALUES(version),
          isOptimized = VALUES(isOptimized),
          runs = VALUES(runs),
          abi = VALUES(abi),
          compiledBytecodeLength = VALUES(compiledBytecodeLength),
          onchainBytecodeLength = VALUES(onchainBytecodeLength),
          isVerified = VALUES(isVerified),
          verificationMessage = VALUES(verificationMessage),
          verifiedAt = VALUES(verifiedAt),
          contractName = VALUES(contractName),
          constructorArgs = VALUES(constructorArgs),
          metadata = VALUES(metadata),
          functionSignatures = VALUES(functionSignatures),
          eventSignatures = VALUES(eventSignatures),
          updatedAt = NOW()
      `, [
        address.toLowerCase(),
        sourceCode,
        compilerVersion,
        optimizationEnabled ? 1 : 0,
        optimizationRuns || 200,
        abi || '[]',
        (compiledBytecode || '').length,
        (onchainBytecode || '').length,
        Math.round(matchPercentage * 100) / 100,
        isVerified ? 1 : 0,
        verificationMessage || '',
        isVerified ? new Date() : null,
        contractName || null,
        constructorArguments || null,
        metadata ? JSON.stringify(metadata) : null,
        functionSignatures ? JSON.stringify(functionSignatures) : null,
        eventSignatures ? JSON.stringify(eventSignatures) : null
      ]);

      // Verify the save operation
      const [verifyRows] = await connection.execute(
        'SELECT * FROM contracts WHERE address = ?',
        [address.toLowerCase()]
      );

      if (verifyRows.length === 0) {
        throw new Error('Contract verification data was not saved');
      }

      // Commit transaction
      await connection.commit();

      console.log('✅ Contract verification saved successfully:', {
        address: verifyRows[0].address,
        isVerified: Boolean(verifyRows[0].isVerified),
        matchPercentage: verifyRows[0].matchPercentage
      });

      return {
        success: true,
        data: verifyRows[0],
        operation: result.insertId ? 'insert' : 'update'
      };

    } catch (error) {
      if (connection) {
        await connection.rollback();
      }
      console.error('❌ Failed to save contract verification:', {
        error: error.message,
        code: error.code,
        address: address.toLowerCase()
      });
      throw error;
    } finally {
      if (connection) connection.release();
    }
  }

  async getContractDetails(address) {
    let connection;
    try {
      connection = await this.getConnection();
      const [rows] = await connection.execute(`
        SELECT 
          address,
          contractName,
          isVerified,
          verificationMessage,
          verifiedAt,
          abi,
          version,
          isOptimized,
          runs,
          metadata,
          functionSignatures,
          eventSignatures,
          createdAt,
          updatedAt
        FROM contracts 
        WHERE address = ?
      `, [address.toLowerCase()]);

      if (rows.length === 0) {
        return null;
      }

      const contract = rows[0];
      return {
        ...contract,
        isVerified: Boolean(contract.isVerified),
        isOptimized: Boolean(contract.isOptimized),
        abi: contract.abi ? JSON.parse(contract.abi) : null,
        metadata: contract.metadata ? JSON.parse(contract.metadata) : null,
        functionSignatures: contract.functionSignatures ? JSON.parse(contract.functionSignatures) : null,
        eventSignatures: contract.eventSignatures ? JSON.parse(contract.eventSignatures) : null
      };
    } catch (error) {
      console.error('❌ Failed to get contract details:', error.message);
      throw error;
    } finally {
      if (connection) connection.release();
    }
  }

  async getVerifiedContracts(limit = 50, offset = 0) {
    let connection;
    try {
      connection = await this.getConnection();
      
      // Get total count
      const [countRows] = await connection.execute(
        'SELECT COUNT(*) as total FROM contracts WHERE isVerified = 1'
      );
      const total = countRows[0].total;

      // Get contracts
      const [rows] = await connection.execute(`
        SELECT 
          address,
          contractName,
          verifiedAt,
          version,
          createdAt
        FROM contracts 
        WHERE isVerified = 1 
        ORDER BY verifiedAt DESC
        LIMIT ? OFFSET ?
      `, [limit, offset]);

      return {
        contracts: rows,
        total,
        limit,
        offset,
        hasMore: offset + limit < total
      };
    } catch (error) {
      console.error('❌ Failed to get verified contracts:', error.message);
      throw error;
    } finally {
      if (connection) connection.release();
    }
  }

  async searchContracts(query, verified = null, limit = 20) {
    let connection;
    try {
      connection = await this.getConnection();
      
      let sql = `
        SELECT 
          address,
          contractName,
          isVerified,
          verifiedAt,
          version,
        FROM contracts 
        WHERE (address LIKE ? OR contractName LIKE ?)
      `;
      
      const params = [`%${query}%`, `%${query}%`];

      if (verified !== null) {
        sql += ' AND isVerified = ?';
        params.push(verified ? 1 : 0);
      }

      sql += ' ORDER BY isVerified DESC, verifiedAt DESC LIMIT ?';
      params.push(limit);

      const [rows] = await connection.execute(sql, params);

      return rows.map(contract => ({
        ...contract,
        isVerified: Boolean(contract.isVerified)
      }));
    } catch (error) {
      console.error('❌ Failed to search contracts:', error.message);
      throw error;
    } finally {
      if (connection) connection.release();
    }
  }

  async getContractStats() {
    let connection;
    try {
      connection = await this.getConnection();
      
      const [stats] = await connection.execute(`
        SELECT 
          COUNT(*) as total,
          SUM(CASE WHEN isVerified = 1 THEN 1 ELSE 0 END) as verified,
          SUM(CASE WHEN isVerified = 0 THEN 1 ELSE 0 END) as unverified,
          AVG(CASE WHEN isVerified = 1 THEN matchPercentage ELSE NULL END) as avgMatchPercentage,
          COUNT(CASE WHEN DATE(createdAt) = CURDATE() THEN 1 END) as todayCount,
          COUNT(CASE WHEN DATE(verifiedAt) = CURDATE() THEN 1 END) as todayVerified
        FROM contracts
      `);

      return {
        total: stats[0].total || 0,
        verified: stats[0].verified || 0,
        unverified: stats[0].unverified || 0,
        verificationRate: stats[0].total > 0 ? (stats[0].verified / stats[0].total * 100).toFixed(2) : 0,
        averageMatchPercentage: stats[0].avgMatchPercentage ? parseFloat(stats[0].avgMatchPercentage).toFixed(2) : 0,
        todaySubmissions: stats[0].todayCount || 0,
        todayVerifications: stats[0].todayVerified || 0
      };
    } catch (error) {
      console.error('❌ Failed to get contract stats:', error.message);
      throw error;
    } finally {
      if (connection) connection.release();
    }
  }

  async getRecentVerifications(limit = 10) {
    let connection;
    try {
      connection = await this.getConnection();
      
      const [rows] = await connection.execute(`
        SELECT 
          address,
          contractName,
          verifiedAt,
          version,
        FROM contracts 
        WHERE isVerified = 1 AND verifiedAt IS NOT NULL
        ORDER BY verifiedAt DESC
        LIMIT ?
      `, [limit]);

      return rows;
    } catch (error) {
      console.error('❌ Failed to get recent verifications:', error.message);
      throw error;
    } finally {
      if (connection) connection.release();
    }
  }

  // Utility methods
  delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  async close() {
    if (this.pool) {
      await this.pool.end();
      console.log('Database pool closed');
    }
  }
}

// Create singleton instance
const dbService = new DatabaseService();

// Export both the class and instance
module.exports = {
  DatabaseService,
  dbService
};

// Handle graceful shutdown
process.on('SIGINT', async () => {
  await dbService.close();
  process.exit(0);
});

process.on('SIGTERM', async () => {
  await dbService.close();
  process.exit(0);
});