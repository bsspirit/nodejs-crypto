///////////////////////////
// 签名验证算法
// openssl genrsa  -out server.pem 1024
// openssl req -key server.pem -new -x509 -out cert.pem
///////////////////////////

var crypto = require('crypto')
    ,fs = require('fs');

function signer(algorithm,key,data){
    var sign = crypto.createSign(algorithm);
    sign.update(data);
    sig = sign.sign(key, 'hex');
    return sig;
}

function verify(algorithm,pub,sig,data){
    var verify = crypto.createVerify(algorithm);
    verify.update(data);
    return verify.verify(pubkey, sig, 'hex')
}

var algorithm = 'RSA-SHA256';
var data = "abcdef"
var privatePem = fs.readFileSync('server.pem');
var key = privatePem.toString();
var sig = signer(algorithm,key,data);

var publicPem = fs.readFileSync('cert.pem');
var pubkey = publicPem.toString();
console.log(verify(algorithm,pubkey,sig,data));

//var privatePem = fs.readFileSync('server.pem');
//var publicPem = fs.readFileSync('cert.pem');
//var key = privatePem.toString();
//var pubkey = publicPem.toString();
//
//var algorithm = 'RSA-SHA256';
//var data = "abcdef"
//var sign = crypto.createSign(algorithm);
//sign.update(data);
//var sig = sign.sign(key, 'hex');
//
//var verify = crypto.createVerify(algorithm);
//verify.update(data);
//console.log(verify.verify(pubkey, sig, 'hex'));



