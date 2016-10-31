const assert = require('assert');
const crypto = require('crypto');
const test_vector= require('./tests/test_vectors.js');
const fs = require('fs');
const rsa_secret = fs.readFileSync('./tests/vectors/key.pem');
const rsa_pub = fs.readFileSync('./tests/vectors/pub.pem');
const example11 = test_vector.example11;
const message = new Buffer(example11.message, 'hex');
const salt = new Buffer(example11.salt, 'hex');
const sLen = salt.length
const mLen = message.length;
const signature = new Buffer(example11.signature, 'hex');
const emBits = 1024;
const emLen = Math.ceil((emBits -1 )/8);;
const hash_algorithm = 'sha1';
const hLen = 20;
const private_key = {
  key: rsa_secret,
  padding: crypto.constants.RSA_NO_PADDING
};

const padding1 = Buffer.alloc(8);
const hash1 = crypto.createHash(hash_algorithm);

hash1.update(message);
const mHash = hash1.digest();

if (emLen < hLen + sLen + 2) {
  throw new Error('encoding error');
}

var padding2 = Buffer.alloc(emLen - sLen - hLen - 2);
const DB = Buffer.concat([padding2, new Buffer('01', 'hex'), salt]);

const hash2 = crypto.createHash(hash_algorithm);
hash2.update(Buffer.concat([padding1, mHash, salt]));

const H = hash2.digest();
const dbMask = MGF1(H, emLen - hLen - 1)
var maskedDB = BufferXOR(DB, dbMask);
var b = Buffer.concat([maskedDB, H, new Buffer('bc', 'hex')]);
var sig = crypto.privateEncrypt(private_key, b);
console.log(sig.equals(signature));

function MGF1(mgfSeed, maskLen) {
  if (maskLen > 0xffffffff * hLen) {
    throw new Error('mask too long');
  }
  var T = [];
  for(var i = 0; i <= Math.ceil(maskLen / hLen) - 1 ; i++) {
    var C = Buffer.alloc(4);
    C.writeUInt32BE(i);
    const hash3 = crypto.createHash(hash_algorithm);
    hash3.update(Buffer.concat([mgfSeed, C]));
    T.push(hash3.digest());
  }
  return Buffer.concat(T).slice(0, maskLen);
}

function BufferXOR(a, b) {
  assert(Buffer.isBuffer(a));
  assert(Buffer.isBuffer(b));
  assert.strictEqual(a.length, b.length);
  var c = Buffer.alloc(a.length);
  for(var i = 0; i < a.length; i++) {
    c[i] = a[i] ^ b[i];
  }
  return c;
}
