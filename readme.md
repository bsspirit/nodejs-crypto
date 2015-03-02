Crypto Demo
=======================

密码技术是互联网应用的一项最基本的技术之一，主要保证了数据的安全。安全定义是多维度的，通过不可逆的hash算法可以保证登陆密码的安全；通过非对称的加密算法，可以保证数据存储的安全性；通过数字签名，可以验证数据在传输过程中是否被篡改。

我们要做互联网应用，数据安全性一个是不容忽视的问题。不然可能会造成，如CSDN的100万用户明文密码被泄露事情；携程网，100万用户个人信息泄露事情等。

Node.js的Crypto库就提供各种加密算法，可以非常方便地让我们使用密码技术，解决应用开发中的问题。

## 关于作者

+ 张丹(Conan), 创业者、程序员(Java,R,Javacript/Node.js)
+ weibo：@Conan_Z
+ blog: http://blog.fens.me
+ email: bsspirit@gmail.com

## 项目文件

+ hash.js 哈希算法测试
+ hmac.js hmac算法测试
+ cipher.js 加密、解密
+ signer.js 签名、验证
+ diffieHellman.js 迪菲－赫尔曼密钥交换算法
+ salt.js 加salt算法

## 使用说明

Node.js加密算法库Crypto

http://blog.fens.me/nodejs-crypto/