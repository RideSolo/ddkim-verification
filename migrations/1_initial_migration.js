const Migrations = artifacts.require("Migrations");

module.exports = function(deployer) {
	return deployer.then(async () => {
	  await deployer.deploy(Migrations);
	});
 
};
