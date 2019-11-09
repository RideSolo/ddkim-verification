
var path = require("path");
var fs   = require("fs");
var dkim = require("../src/dkim-lib");

const dkimchecker = artifacts.require("DkimChecker.sol");

var files = fs.readdirSync("./eml/");
files = files.filter((str) => { return /\.eml$/.test(str);});

files.forEach((str) => {
    var eml = fs.readFileSync("./eml/" + str,'utf-8');
    
    try {
        var obj = dkim.parse(eml);
        var key = dkim.getKeySync(obj);
        var result = dkim.verifySig(obj,key);
        console.log(obj.algo)

        contract("DkimChecker "  + str, function(accounts) {
            let instance;

            it('Oracle key Writting Simulation' , async function() {

                instance = await dkimchecker.deployed();
                let val,bl;
                
                switch(obj.algo) {
                    case 'RSA':
                        await instance.setDkimKeyRsa(
                            obj.signature.selector,
                            obj.signature.domain,
                            key.rsa.exponent,
                            key.rsa.modulus
                        );

                        val = await instance.getDkimKeyRsa(
                            obj.signature.selector,
                            obj.signature.domain
                        );

                        bl = (key.rsa.exponent === val[0] && val[1] === key.rsa.modulus);
                    break;
                    case 'ED25519':
                        await instance.setDkimKeyEd(
                            obj.signature.selector,
                            obj.signature.domain,
                            key.ed.pxh ,
                            key.ed.pyh
                        );

                        val = await instance.getDkimKeyEd(
                            obj.signature.selector,
                            obj.signature.domain
                        );
                        bl = (key.ed.px.toString() === val[0].toString() && val[1].toString() === key.ed.py.toString());
                    break;
                    default:
                }

                assert.equal(bl,true);
            });

            it('On-chain Body Hash Verification : ' + str  + ' Expected: ' + String(obj.bhHex == obj.canonicalizedBodyHash) , async function() {
                var tx;
                switch(obj.hashingAlgo) {
                    case 'SHA256':
                        tx = await instance.checkBodySHA256(
                            obj.canonicalizedBodyHex,
                            obj.bhHex
                        );
                    break;
                    case 'SHA1':
                        tx = await instance.checkBodySHA1(
                            obj.canonicalizedBodyHex,
                            obj.bhHex
                        );
                    break;
                    default:
                        throw Error('Undefined Hash Algorithm')
                }
                assert.equal(
                     tx.logs[0].args[0],
                     obj.bhHex == obj.canonicalizedBodyHash
                 );
            });

            it('On-chain DKIM Signature Verification : ' + str + ' Expected: ' + String(result) , async function() {
                var tx;
                switch(obj.signatureAlgo) {
                    case 'RSA-SHA256':
                        tx = await instance.verifyRSASHA256(
                            obj.signature.selector,
                            obj.signature.domain,
                            obj.signatureHex,
                            obj.canonicalizedHeaderHex,

                        );
                    break;
                    case 'RSA-SHA1':
                        tx = await instance.verifyRSASHA1(
                            obj.signature.selector,
                            obj.signature.domain,
                            obj.signatureHex, // hexadecimal string of the signature
                            obj.canonicalizedHeaderHex, // 
                        );
                    break;
                    case 'ED25519-SHA256':
                        tx = await instance.verifyED25519(
                            obj.signature.selector,
                            obj.signature.domain,
                            [ obj.signature.ed.r.x , obj.signature.ed.r.y ], // hexadecimal value of R point contained in the signature 
                            [ key.ed.lhs.x , key.ed.lhs.y], // hexadecimal value of s contained in the signature
                            key.ed.headerHash); // sha-2 512/256 hash value of hashing function used for Ed25519 algo 'H(x)' https://tools.ietf.org/html/rfc8032#section-5.1.7
                    break;
                    default:
                } 
                assert.equal(
                    tx.logs[0].args[0],
                    result
                );
            });
        });
    } catch(error) {
        console.log(error);
        console.log(error.code);
    }
});