// ./ContractVerifier.js
const BlockchainService = require('./BlockchainService');
const SolcManager = require('./SolcManager');
const ContractModel = require('./ContractModel');

class ContractVerifier {
  constructor(blockchainService, solcManager) {
    this.blockchainService = blockchainService;
    this.solcManager = solcManager;
  }

  async verifyContract(request) {
    try {
      this.validateVerificationRequest(request);

      const { address, solSource, version, optimize = false, runs = 200 } = request;
      const normalizedAddress = this.blockchainService.normalizeAddress(address);

      console.log(`Starting verification for ${normalizedAddress}`);
      console.log(`Solidity version: ${version}, optimize: ${optimize}, runs: ${runs}`);

      const compilationResult = await this.solcManager.compile(solSource, version, optimize, runs);

      const contractFile = compilationResult.contracts['Contract.sol'];
      if (!contractFile) {
        throw new Error('No contracts found in the compilation result for Contract.sol');
      }

      const contractNames = Object.keys(contractFile);
      if (contractNames.length === 0) {
        throw new Error('No contracts found in the source code');
      }

      const contractName = contractNames[0];
      const contract = contractFile[contractName];

      if (!contract || !contract.evm || !contract.evm.deployedBytecode || !contract.evm.deployedBytecode.object) {
        throw new Error('No deployed bytecode found in compilation result');
      }

      const compiledBytecode = contract.evm.deployedBytecode.object;
      const abi = contract.abi;

      const onchainBytecodeRaw = await this.blockchainService.getOnchainBytecode(normalizedAddress);
      if (!onchainBytecodeRaw || onchainBytecodeRaw === '0x') {
        throw new Error('No bytecode found at the specified address. Address may not be a contract.');
      }

      const compiledStripped = this.stripMetadata(this.remove0x(compiledBytecode));
      const onchainStripped = this.stripMetadata(this.blockchainService.remove0xPrefix(onchainBytecodeRaw));

      console.log(`Compiled stripped length: ${compiledStripped.length}`);
      console.log(`On-chain stripped length: ${onchainStripped.length}`);

      const isMatch = this.compareBytecodes(compiledStripped, onchainStripped);
      const matchPercentage = this.calculateMatchPercentage(compiledStripped, onchainStripped);

      console.log(`Bytecode match: ${isMatch}, matchPercentage: ${matchPercentage}%`);

      const response = {
        success: true,
        verified: isMatch,
        message: isMatch
          ? `Verification succeeded! Contract matches on-chain bytecode.\nMatch Percentage: ${matchPercentage}%`
          : `Verification failed! Compiled bytecode does not match on-chain code.\nMatch Percentage: ${matchPercentage}%`,
        matchPercentage,
        abi: isMatch ? abi : undefined,
        metadata: {
          contractName: contractName || "",
          solcVersion: version,
          optimizationEnabled: !!optimize,
          optimizationRuns: runs,
          compiledBytecodeLength: compiledStripped.length,
          onchainBytecodeLength: onchainStripped.length
        }
      };

      // Persist basic contract info (upsert) & verification result
      try {
        await ContractModel.upsertContractBasic({
          address: normalizedAddress,
          solSource,
          version,
          optimize,
          runs,
        });

        await ContractModel.saveVerificationResult(normalizedAddress, {
          verified: isMatch,
          matchPercentage,
          abi,
          compiledBytecodeLength: compiledStripped.length,
          onchainBytecodeLength: onchainStripped.length,
          message: response.message,
        });
      } catch (persistErr) {
        console.warn('Failed to persist verification result:', persistErr && persistErr.message);
      }

      return response;
    } catch (error) {
      console.error('Contract verification error:', error && (error.stack || error.message || error));
      return {
        success: false,
        verified: false,
        message: `Error during verification: ${error && error.message ? error.message : 'Unknown error'}`,
        error: error && error.message ? error.message : 'Unknown error occurred'
      };
    }
  }

  validateVerificationRequest(request) {
    if (!request || !request.address || !request.address.trim()) {
      throw new Error('Contract address is required');
    }
    if (!this.blockchainService.isValidAddress(request.address)) {
      throw new Error('Invalid Ethereum address format');
    }
    if (!request.solSource || !request.solSource.trim()) {
      throw new Error('Solidity source code is required');
    }
    if (!request.version || !request.version.trim()) {
      throw new Error('Solidity version is required');
    }
    if (typeof request.runs === 'number' && (request.runs < 1 || request.runs > 10000)) {
      throw new Error('Optimization runs must be between 1 and 10000');
    }
    if (!request.solSource.includes('contract ') && !request.solSource.includes('library ')) {
      throw new Error('Source code must contain at least one contract or library');
    }
  }

  stripMetadata(bytecode) {
    try {
      if (!bytecode || bytecode.length < 4) return bytecode;
      // last 2 bytes (4 hex chars) indicate metadata length
      const last4 = bytecode.slice(-4);
      const metadataLength = parseInt(last4, 16);
      if (!isNaN(metadataLength) && metadataLength > 0 && metadataLength < bytecode.length / 2) {
        const stripped = bytecode.slice(0, -(2 * (metadataLength + 2)));
        return stripped;
      }
      return bytecode;
    } catch (err) {
      console.warn('Error stripping metadata, returning original bytecode:', err && err.message);
      return bytecode;
    }
  }

  remove0x(hex) {
    if (!hex) return hex;
    return hex.startsWith('0x') ? hex.slice(2) : hex;
  }

  compareBytecodes(compiled, onchain) {
    if (!compiled || !onchain) return false;
    if (compiled === onchain) return true;
    if (onchain.includes(compiled)) return true;
    const similarity = this.calculateSimilarity(compiled, onchain);
    return similarity > 0.95;
  }

  calculateMatchPercentage(compiled, onchain) {
    if (!compiled || !onchain) return 0;
    if (compiled === onchain) return 100;
    if (onchain.includes(compiled)) {
      return Math.round((compiled.length / onchain.length) * 100);
    }
    const similarity = this.calculateSimilarity(compiled, onchain);
    return Math.round(similarity * 100);
  }

  calculateSimilarity(str1, str2) {
    const longer = str1.length >= str2.length ? str1 : str2;
    const shorter = str1.length >= str2.length ? str2 : str1;
    if (longer.length === 0) return 1.0;
    const editDistance = this.levenshteinDistance(longer, shorter);
    return (longer.length - editDistance) / longer.length;
  }

  levenshteinDistance(str1, str2) {
    const matrix = Array.from({ length: str2.length + 1 }, () => Array.from({ length: str1.length + 1 }, () => 0));
    for (let i = 0; i <= str1.length; i++) matrix[0][i] = i;
    for (let j = 0; j <= str2.length; j++) matrix[j][0] = j;
    for (let j = 1; j <= str2.length; j++) {
      for (let i = 1; i <= str1.length; i++) {
        const indicator = str1[i - 1] === str2[j - 1] ? 0 : 1;
        matrix[j][i] = Math.min(
          matrix[j][i - 1] + 1, // deletion
          matrix[j - 1][i] + 1, // insertion
          matrix[j - 1][i - 1] + indicator // substitution
        );
      }
    }
    return matrix[str2.length][str1.length];
  }
}

module.exports = ContractVerifier;
