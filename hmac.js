///////////////////////////
// Hmac算法
///////////////////////////

var crypto = require('crypto')
    ,fs = require('fs');

function hmacAlgorithm(algorithm,key){
    var s1 = new Date();

    var filename = "package.json";
    var txt = fs.ReadStream(filename);

    var shasum = crypto.createHmac(algorithm,key);
    txt.on('data', function(d) {
        shasum.update(d);
    });

    txt.on('end', function() {
        var d = shasum.digest('hex');
        var s2 = new Date();

        console.log(algorithm+','+(s2-s1) +'ms,'+ d);
    });
}

function doHmac(hashs,key){
    console.log("\nKey : %s", key);
    console.log("============================");
    hashs.forEach(function(name){
        hmacAlgorithm(name,key);
    })
}

//var algs = crypto.getHashes();
var algs = [ 'md5','sha','sha1','sha256','sha512','RSA-SHA','RSA-SHA1','RSA-SHA256','RSA-SHA512'];
setTimeout(function(){
    doHmac(algs,"abc");
},1)

setTimeout(function(){
    var key = "jifdkd;adkfaj^&fjdifefdafda,ijjifdkd;adkfaj^&fjdifefdafdaljifdkd;adkfaj^&fjdifefdafda";
    doHmac(algs,key);
},2*1000)



