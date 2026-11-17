// CSC8214 - Hardhat configuration used to compile and test Crowdfunding.sol.
// The contract itself was written and tested in the Remix online IDE
// (https://remix.ethereum.org) as used in the lab; this local setup simply
// reproduces those tests in a form that can be re-run from the command line.
require("@nomicfoundation/hardhat-ethers");

module.exports = {
  solidity: {
    version: "0.8.26",
    settings: {
      optimizer: { enabled: true, runs: 200 },
    },
  },
  paths: {
    sources: "./contracts",
    tests: "./contracts/test",
    cache: "./.hardhat-cache",
    artifacts: "./.hardhat-artifacts",
  },
};
