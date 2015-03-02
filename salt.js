//////////////////////////////
// salt算法
//////////////////////////////

var crypto = require('crypto');
var md5 = crypto.createHash('md5');
var txt = "123465";

//md5.update(txt);
//console.log(md5.digest('hex'));
//
//md5 = crypto.createHash('md5');
//var salt = "abcdefghijklmnopqrstuvwxyz";
//md5.update(txt+salt);
//console.log(md5.digest('hex'));
//
//// 生成密文，默认HMAC函数是sha1算法
//crypto.pbkdf2(txt, salt, 4096, 256, function (err,hash) {
//    if (err) { throw err; }
//    console.log(hash.toString('hex'));
//})

//通过伪随机码生成salt，进行加密
crypto.randomBytes(128, function (err, salt) {
    if (err) { throw err;}
    salt = salt.toString('hex');
    console.log(salt); //生成salt

    crypto.pbkdf2(txt, salt, 4096, 256, function (err,hash) {
        if (err) { throw err; }
        hash = hash.toString('hex');
        console.log(hash);//生成密文
    })
})
