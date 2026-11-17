// CSC8214 - Hardhat configuration used to compile and test Crowdfunding.sol.
// The contract is written to compile in the Remix online IDE
// (https://remix.ethereum.org) used in the lab; this local setup runs the
// same tests from the command line.
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
