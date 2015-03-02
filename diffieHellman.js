///////////////////////////
// 密钥验证算法
///////////////////////////

var crypto = require("crypto");

//var dh1 = crypto.createDiffieHellman(256);
//var prime1 = dh1.getPrime('base64');
//var dh2 = crypto.createDiffieHellman(prime1, 'base64');
//var key1 = dh1.generateKeys();
//var key2 = dh2.generateKeys('hex');
//var secret1 = dh1.computeSecret(key2, 'hex', 'base64');
//var secret2 = dh2.computeSecret(key1, 'binary', 'base64');
//
//console.log(secret1);
//console.log(secret2);

var crypto = require('crypto');
var alice = crypto.getDiffieHellman('modp5');
var bob = crypto.getDiffieHellman('modp5');

alice.generateKeys();
bob.generateKeys();

var aliceSecret = alice.computeSecret(bob.getPublicKey(), 'binary', 'hex');
var bobSecret = bob.computeSecret(alice.getPublicKey(), 'binary', 'hex');
console.log(alice_secret == bob_secret);
