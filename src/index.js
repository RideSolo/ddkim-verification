

var dkim = require("./src/dkim-lib");
var fs = require("fs");
var nodersa = require("node-rsa");
var gmail   = fs.readFileSync('./eml/ed25519.eml','utf-8');
var ed = require('./src/noble-ed25519/index')

var obj = dkim.parse(gmail);
var key = dkim.getKeySync(obj);

console.log(dkim.verifySig(obj,key))
