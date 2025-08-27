# Universe Chain Explorer Backend API

This is the backend API for the Universe Chain Explorer, providing real-time data from the Universe Chain EVM Testnet.

## Features

- Real-time data from the blockchain using Web3.js
- WebSocket support for live updates
- Rate limiting with three packages (Free, Basic, Premium)
- Smart contract verification
- Comprehensive API documentation

## Technologies Used

- Node.js
- Express.js
- Web3.js
- Socket.IO
- CORS for cross-origin requests
- Dotenv for environment configuration

## API Endpoints

### Network Information
- `GET /api/network` - Get network information

### Blocks
- `GET /api/blocks` - Get latest blocks (paginated)
- `GET /api/blocks/:number` - Get block by number

### Transactions
- `GET /api/transactions` - Get latest transactions (paginated)
- `GET /api/transactions/:hash` - Get transaction by hash

### Addresses
- `GET /api/address/:address` - Get address information
- `POST /api/verify-contract` - Verify a smart contract

### Search
- `GET /api/search/:query` - Search for blocks, transactions, or addresses

### Tokens & Validators
- `GET /api/tokens` - Get token information
- `GET /api/validators` - Get validator information

### API Documentation
- `GET /api/docs` - Get API documentation

## Rate Limiting

The API implements rate limiting with three packages:

### Free Tier
- 100 requests per minute
- Suitable for basic exploration and testing

### Basic Tier
- 1,000 requests per minute
- Suitable for small applications and services

### Premium Tier
- 10,000 requests per minute
- Suitable for production applications and services

To access higher rate limits, include an API key in your requests:
```
-H "X-API-Key: YOUR_API_KEY"
```

## WebSocket Support

The API provides real-time updates through WebSocket connections:

- Endpoint: `ws://localhost:3001`
- Event: `latestData`
- Data: Latest block and transaction information

## Smart Contract Verification

The API supports smart contract verification:

- Endpoint: `POST /api/verify-contract`
- Parameters: 
  - `address`: Contract address
  - `sourceCode`: Contract source code
  - `compilerVersion`: Compiler version used
  - `optimization`: Whether optimization was enabled

## Installation

1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd universe-chain-explorer
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Start the development server:
   ```bash
   npm run dev
   ```

4. The API will be available at [http://localhost:3001](http://localhost:3001)

## Environment Variables

Create a `.env` file in the root directory with the following variables:

```env
PORT=3001
NODE_ENV=development
```

## Project Structure

```
universe-chain-explorer/
├── package.json
├── server.js
└── README.md
```

## Contributing

1. Fork the repository
2. Create a new branch for your feature
3. Make your changes
4. Submit a pull request

## License

This project is licensed under the MIT License.