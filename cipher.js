///////////////////////////
// 加密解密算法
///////////////////////////
var crypto = require('crypto')
    ,fs = require('fs');

//加密
function cipher(algorithm, key, buf ,cb){
    var encrypted = "";
    var cip = crypto.createCipher(algorithm, key);
    encrypted += cip.update(buf, 'binary', 'hex');
    encrypted += cip.final('hex');
    cb(encrypted);
}

//解密
function decipher(algorithm, key, encrypted,cb){
    var decrypted = "";
    var decipher = crypto.createDecipher(algorithm, key);
    decrypted += decipher.update(encrypted, 'hex', 'binary');
    decrypted += decipher.final('binary');
    cb(decrypted);
}

function cipherDecipherFile(filename,algorithm, key){
    fs.readFile(filename, "utf-8",function (err, data) {
        if (err) throw err;
        var s1 = new Date();

        cipher(algorithm, key,data,function(encrypted){
            var s2 = new Date();
            console.log('cipher:'+algorithm+','+(s2-s1) +'ms');

            decipher(algorithm, key,encrypted,function(txt){
                var s3 = new Date();
                console.log('decipher:'+algorithm+','+(s3-s2) +'ms');
//                console.log(txt);
            });
        });
    });
}

//console.log(crypto.getCiphers());
var algs = ['blowfish','aes-256-cbc','cast','des','des3','idea','rc2','rc4','seed'];
var key = "abc";
var filename = "book.pdf";//"package.json";
algs.forEach(function(name){
    cipherDecipherFile(filename,name,key);
})













