var DkimChecker = artifacts.require("DkimChecker.sol");
var ed25519     = artifacts.require("Ed25519.sol");

module.exports = (deployer, network, accounts) => {
	deployer.deploy(DkimChecker,accounts[0]);
	deployer.deploy(ed25519,accounts[0]);
}