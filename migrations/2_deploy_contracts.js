var DkimChecker = artifacts.require("DkimChecker.sol");

module.exports = (deployer, network, accounts) => {
	deployer.deploy(DkimChecker,accounts[0]);
}