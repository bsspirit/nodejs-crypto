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
var data = "abcdef";   //传输的数据
var privatePem = fs.readFileSync('server.pem');
var key = privatePem.toString();
var sig = signer(algorithm,key,data); //数字签名

var publicPem = fs.readFileSync('cert.pem');
var pubkey = publicPem.toString();
console.log(verify(algorithm,pubkey,sig,data));         //验证数据，通过公钥、数字签名 =》是原始数据
console.log(verify(algorithm,pubkey,sig,data+"2"));    //验证数据，通过公钥、数字签名  =》不是原始数据




