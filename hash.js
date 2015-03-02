///////////////////////////
// Hash算法
///////////////////////////

var crypto = require('crypto')
    ,fs = require('fs');

function hashAlgorithm(algorithm){
    var s1 = new Date();

    var filename = "package.json";
    var txt = fs.ReadStream(filename);

    var shasum = crypto.createHash(algorithm);
    txt.on('data', function(d) {
        shasum.update(d);
    });

    txt.on('end', function() {
        var d = shasum.digest('hex');
        var s2 = new Date();

        console.log(algorithm+','+(s2-s1) +'ms,'+ d);
    });
}

function doHash(hashs){
    hashs.forEach(function(name){
        hashAlgorithm(name);
    })
}

//var algs = crypto.getHashes();
var algs = [ 'md5','sha','sha1','sha256','sha512','RSA-SHA','RSA-SHA1','RSA-SHA256','RSA-SHA512'];
doHash(algs);





