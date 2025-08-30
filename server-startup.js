
require('dotenv').config();
const express = require('express');
const { dbService } = require('./database.service');

// Function to find available port
async function findAvailablePort(startPort = 3000, maxPort = 3010) {
  const net = require('net');
  
  for (let port = startPort; port <= maxPort; port++) {
    try {
      await new Promise((resolve, reject) => {
        const server = net.createServer();
        server.listen(port, (err) => {
          if (err) {
            reject(err);
          } else {
            server.close(() => resolve());
          }
        });
      });
      return port;
    } catch (error) {
      if (port === maxPort) {
        throw new Error(`No available ports found between ${startPort} and ${maxPort}`);
      }
      continue;
    }
  }
}

// Kill existing process on port (macOS/Linux)
async function killPortProcess(port) {
  const { exec } = require('child_process');
  const util = require('util');
  const execPromise = util.promisify(exec);
  
  try {
    console.log(`🔍 Checking for processes on port ${port}...`);
    
    // Find process using the port
    const { stdout } = await execPromise(`lsof -ti:${port}`);
    const pid = stdout.trim();
    
    if (pid) {
      console.log(`⚠️  Found process ${pid} using port ${port}`);
      console.log('🛑 Attempting to terminate the process...');
      
      // Kill the process
      await execPromise(`kill -9 ${pid}`);
      console.log(`✅ Process ${pid} terminated`);
      
      // Wait a moment for the port to be released
      await new Promise(resolve => setTimeout(resolve, 2000));
      return true;
    }
    
    return false;
  } catch (error) {
    console.log(`ℹ️  No process found on port ${port} or unable to check`);
    return false;
  }
}

// Enhanced server initialization with port management
async function startServerWithPortManagement(app) {
  console.log('\n🚀 Starting Smart Contract Verification Server...\n');

  try {
    // 1. Test database connection first
    console.log('1️⃣ Testing database connection...');
    const dbHealthy = await dbService.testConnection();
    
    if (!dbHealthy) {
      console.error('❌ Database connection failed!');
      console.log('   Please ensure MySQL is running and configured correctly');
      console.log('   Server will start but verification features will be limited\n');
    } else {
      console.log('✅ Database connection successful\n');
    }

    // 2. Handle port conflicts
    const preferredPort = process.env.PORT || 3000;
    let port = parseInt(preferredPort);
    
    console.log(`2️⃣ Setting up server on port ${port}...`);
    
    // Try to kill existing process on the preferred port
    if (await killPortProcess(port)) {
      console.log('✅ Port cleared successfully\n');
    } else {
      // Find an available port
      try {
        port = await findAvailablePort(port, port + 10);
        console.log(`✅ Using available port ${port}\n`);
      } catch (portError) {
        console.error('❌ Could not find available port:', portError.message);
        process.exit(1);
      }
    }

    // 3. Start the server
    const server = app.listen(port, '0.0.0.0', () => {
      console.log('🎉 Server started successfully!');
      console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
      console.log(`🌐 Server running on: http://localhost:${port}`);
      console.log(`📝 Environment: ${process.env.NODE_ENV || 'development'}`);
      console.log(`💾 Database: ${dbHealthy ? '✅ Connected' : '❌ Disconnected'}`);
      console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
      console.log('\n📋 Available API Endpoints:');
      console.log(`   POST http://localhost:${port}/api/verify-contract        - Verify smart contract`);
      console.log(`   GET  http://localhost:${port}/api/address/:address       - Get address information`);
      console.log(`   GET  http://localhost:${port}/api/contract/:address      - Get contract details`);
      console.log(`   GET  http://localhost:${port}/api/contracts/verified     - List verified contracts`);
      console.log(`   GET  http://localhost:${port}/api/contracts/search       - Search contracts`);
      console.log(`   GET  http://localhost:${port}/api/contracts/stats        - Contract statistics`);
      console.log(`   GET  http://localhost:${port}/api/verification/health    - System health check`);
      console.log('\n🔍 Ready to verify smart contracts!');
      
      if (port !== parseInt(preferredPort)) {
        console.log(`\nℹ️  Note: Using port ${port} instead of ${preferredPort} due to port conflict`);
      }
      console.log('');
    });

    // Handle server errors
    server.on('error', async (error) => {
      if (error.code === 'EADDRINUSE') {
        console.error(`❌ Port ${port} is still in use after cleanup attempt`);
        console.log('   Trying to find another available port...');
        
        try {
          const newPort = await findAvailablePort(port + 1, port + 10);
          console.log(`🔄 Retrying with port ${newPort}...`);
          
          const newServer = app.listen(newPort, () => {
            console.log(`✅ Server successfully started on port ${newPort}`);
          });
          
          return newServer;
        } catch (retryError) {
          console.error('❌ Could not start server on any available port');
          process.exit(1);
        }
      } else {
        console.error('❌ Server error:', error.message);
        process.exit(1);
      }
    });

    // Graceful shutdown
    const gracefulShutdown = async (signal) => {
      console.log(`\n⚠️  Received ${signal}. Starting graceful shutdown...`);
      
      server.close(async () => {
        console.log('✅ HTTP server closed');
        
        try {
          await dbService.close();
          console.log('✅ Database connections closed');
          console.log('✅ Server shutdown complete');
          process.exit(0);
        } catch (shutdownError) {
          console.error('❌ Error during shutdown:', shutdownError.message);
          process.exit(1);
        }
      });
    };

    process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
    process.on('SIGINT', () => gracefulShutdown('SIGINT'));

    return server;

  } catch (error) {
    console.error('❌ Server startup failed:', error.message);
    console.error(error.stack);
    process.exit(1);
  }
}

module.exports = { startServerWithPortManagement, findAvailablePort, killPortProcess };

// If running this file directly, start the server
if (require.main === module) {
  const app = express();
  
  // Basic middleware
  app.use(express.json({ limit: '10mb' }));
  app.use(express.urlencoded({ extended: true }));
  
  // Add CORS if needed
  app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    next();
  });
  
  // Basic health check
  app.get('/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
  });
  
  // Start the server
  startServerWithPortManagement(app);
}