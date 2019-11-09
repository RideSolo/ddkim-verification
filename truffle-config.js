
module.exports = {
  networks: {
    testrpc: {
      host: "127.0.0.1",
      port: 7545,
      network_id: "*" // Match any network id
    }
  },

  mocha: {
    reporter: 'eth-gas-reporter',
    reporterOptions: {
      currency: 'USD',
      gasPrice: 1
    }
  },
  // solc: {
  //    settings: {          // See the solidity docs for advice about optimization and evmVersion
  //      optimizer: {
  //        enabled: true,
  //        runs: 400
  //      }
  //   }
  // }
  solc: {
    optimizer: {
      enabled: true,
      runs: 200
    }
  }
}
