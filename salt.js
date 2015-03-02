//////////////////////////////
// salt算法
//////////////////////////////

var crypto = require('crypto');

//生成加密用的伪随机码
// async
crypto.randomBytes(256, function(ex, buf) {
    if (ex) throw ex;
//    console.log('Have %d bytes of random data: %s', buf.length, buf);
    console.log(buf);
    console.log(buf.toString('hex'));
});
//
//// sync
//try {
//    var buf = crypto.randomBytes(256);
//    console.log('Have %d bytes of random data: %s', buf.length, buf);
//} catch (ex) {
//    console.log(ex);
//}

//通过伪随机码来加密迭代数次，利用sha1算法生成一个更加强壮的加密串
crypto.randomBytes(128, function (err, salt) {
    if (err) { throw err;}
    salt = new Buffer(salt).toString('hex');
    crypto.pbkdf2('123456', salt, 7000, 256, function (err,hash) {
        if (err) { throw err; }
        hash = new Buffer(hash).toString('hex');
        console.log(hash);
    })
})