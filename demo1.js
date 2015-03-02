var crypto = require('crypto')
    ,fs = require('fs');

//Returns an array with the names of the supported ciphers.
function ciphers(){
    console.log(crypto.getCiphers());
    return crypto.getCiphers();
}
ciphers();

//Returns an array with the names of the supported hash algorithms.
function hashes(){
    console.log(crypto.getHashes());
    return crypto.getHashes();
}

// hash
function hash(){
    var sha1 = crypto.createHash('sha1');
    sha1.update('foo');
    sha1.update('bar');
    console.log(sha1.digest('hex')); //8843d7f92416211de9ebb963ff4ce28125932878

    var sha1 = crypto.createHash('sha1');
    sha1.update('foobar');
    console.log(sha1.digest('hex'));//8843d7f92416211de9ebb963ff4ce28125932878
}
//hash();

// hmac
function hmac(){
    var pem = fs.readFileSync('key.pem');
    var key = pem.toString('ascii');

    var sha1 = crypto.createHmac('sha1',key);
    sha1.update('foo');
    sha1.update('bar');
    console.log(sha1.digest('hex')); //902002dd485de0872151dfbb6d518f0bea476fe4

    var sha1 = crypto.createHmac('sha1',key);
    sha1.update('foobar');
    console.log(sha1.digest('hex'));//902002dd485de0872151dfbb6d518f0bea476fe4
}
//hmac();

function create(algorithm,key){
    var filename = "package.json";
    var shasum = null;
    switch(algorithm){
        case 'sha1':
        case 'sha256':
        case 'sha512':
        case 'md5':
            shasum = crypto.createHash(algorithm);
            break;
    }
    // crypto.createHash(algorithm)
    // crypto.createHmac(algorithm, key);
    // crypto.createCipher(algorithm, password)
    //crypto.createCipheriv(algorithm, key, iv)
    //crypto.createDecipher(algorithm, password)
    //crypto.createDecipheriv(algorithm, key, iv)
    //crypto.createSign(algorithm)
    //crypto.createVerify(algorithm)
    //crypto.createDiffieHellman(prime_length[, generator])
    //crypto.createDiffieHellman(prime[, prime_encoding][, generator][, generator_encoding])
    //crypto.getDiffieHellman(group_name)
    //crypto.createECDH(curve_name)
    //crypto.pbkdf2(password, salt, iterations, keylen[, digest], callback)
    //crypto.pbkdf2Sync(password, salt, iterations, keylen[, digest])
    //crypto.randomBytes(size[, callback])
    //crypto.pseudoRandomBytes(size[, callback])
    //crypto.publicEncrypt(public_key, buffer)
    //crypto.privateDecrypt(private_key, buffer)


    var s = fs.ReadStream(filename);
    s.on('data', function(d) {
        shasum.update(d);
    });

    s.on('end', function() {
        var d = shasum.digest('hex');
        console.log(d + '  '+ algorithm  +'  '+ filename);
    });
}

//var hashs = ['sha1','sha256','sha512','md5'];
//hashs.forEach(function(hash){
//    create(hash);
//});

function cipher(){
    var pem = fs.readFileSync('key.pem');
    var key = pem.toString('ascii');
    var cipher = crypto.createCipher('blowfish', key);
    cipher.update(new Buffer(4), 'binary', 'hex');
    cipher.update(new Buffer(4), 'binary', 'hex');
    cipher.update(new Buffer(4), 'binary', 'hex');
    console.log(cipher.final('hex'));
}
//cipher();

function decipher(){
    var cipher = crypto.createCipher('aes-256-cbc','InmbuvP6Z8')
    var text = "123|123123123123123";
    var crypted = cipher.update(text,'utf8','hex')
    crypted += cipher.final('hex')
    console.log(crypted);

    var decipher = crypto.createDecipher('aes-256-cbc','InmbuvP6Z8')
    var dec = decipher.update(crypted,'hex','utf8')
    dec += decipher.final('utf8')
    console.log(dec);
}
//decipher();

function decipher2(){
    var pem = fs.readFileSync('key.pem');
    var key = pem.toString('ascii');

    var plaintext = new Buffer('abcdefghijklmnopqrstuv');
    console.log(plaintext);

    var encrypted = "";
    var cipher = crypto.createCipher('blowfish', key);
    encrypted += cipher.update(plaintext, 'binary', 'hex');
    encrypted += cipher.final('hex');
    console.log(encrypted);

    var decrypted = "";
    var decipher = crypto.createDecipher('blowfish', key);
    decrypted += decipher.update(encrypted, 'hex', 'binary');
    decrypted += decipher.final('binary');
    var output = new Buffer(decrypted);
    console.log(output);
}
//decipher2();

function verify(){    //没有测试
    var privatePem = fs.readFileSync('server.pem');
    var publicPem = fs.readFileSync('cert.pem');
    var key = privatePem.toString();
    var pubkey = publicPem.toString();

    var data = "abcdef"
    var sign = crypto.createSign('RSA-SHA256');
    sign.update(data);
    var sig = sign.sign(key, 'hex');
    var verify = crypto.createVerify('RSA-SHA256');
    verify.update(data);
    verify.update(data);
    verify.verify(pubkey, sig, 'hex');
}
//verify();

function diffieHellman(){
    var alice = crypto.getDiffieHellman('modp5');
    var bob = crypto.getDiffieHellman('modp5');

    alice.generateKeys();
    bob.generateKeys();

    var alice_secret = alice.computeSecret(bob.getPublicKey(), 'binary', 'hex');
    var bob_secret = bob.computeSecret(alice.getPublicKey(), 'binary', 'hex');

    /* alice_secret and bob_secret should be the same */
    console.log(alice_secret == bob_secret);
}
//diffieHellman();

var assert = require("assert");
function diffieHellman2(){
    var diffieHellman1 = crypto.createDiffieHellman(256);
    var prime1 = diffieHellman1.getPrime('base64');
    var diffieHellman2 = crypto.createDiffieHellman(prime1, 'base64');
    var key1 = diffieHellman1.generateKeys();
    var key2 = diffieHellman2.generateKeys('hex');
    var secret1 = diffieHellman1.computeSecret(key2, 'hex', 'base64');
    var secret2 = diffieHellman2.computeSecret(key1, 'binary', 'base64');
    assert.equal(secret1, secret2);
}
//diffieHellman2();










