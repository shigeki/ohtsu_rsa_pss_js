const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');

const hashLength = {
  'sha1' : 20,
  'sha256': 32,
  'sha384': 46,
  'sha512': 64
};

exports.RSAPSS = RSAPSS;

function RSAPSS() {

}

RSAPSS.prototype.sign = function(rsa_secret, keylen, hash_algorithm, message, saltlen, salt) {
  assert(Buffer.isBuffer(rsa_secret));
  assert.strictEqual(typeof keylen, 'number');
  assert.strictEqual(typeof hash_algorithm, 'string');
  assert(Buffer.isBuffer(message));
  assert.strictEqual(typeof saltlen, 'number');
  if (salt) {
    assert(Buffer.isBuffer(salt));
    assert.strictEqual(saltlen, salt.length);
  } else {
    salt = crypto.randomBytes(saltlen);
  }
  const emBits = keylen - 1;
  const sLen = saltlen;
  const hLen = hashLength[hash_algorithm];
  assert(hLen);
  const mLen = message.length;
  const emLen = Math.ceil(emBits/8);
  const padding1 = Buffer.alloc(8);
  const hash1 = crypto.createHash(hash_algorithm);
  hash1.update(message);
  const mHash = hash1.digest();

  if (emLen < hLen + sLen + 2)
    throw new Error('encoding error');

  var padding2 = Buffer.alloc(emLen - sLen - hLen - 2);
  const DB = Buffer.concat([padding2, new Buffer('01', 'hex'), salt]);

  const hash2 = crypto.createHash(hash_algorithm);
  hash2.update(Buffer.concat([padding1, mHash, salt]));

  const H = hash2.digest();
  const dbMask = MGF1(H, emLen - hLen - 1, hash_algorithm);
  var maskedDB = BufferXOR(DB, dbMask);
  var b = Buffer.concat([maskedDB, H, new Buffer('bc', 'hex')]);
  const private_key = {
    key: rsa_secret,
    padding: crypto.constants.RSA_NO_PADDING
  };
  b[0] = b[0] & 0x7f;
  var signature = crypto.privateEncrypt(private_key, b);

  return signature;
};

RSAPSS.prototype.verify = function(rsa_public, keylen, hash_algorithm, message, sLen, signature) {
  assert(Buffer.isBuffer(rsa_public));
  assert.strictEqual(typeof keylen, 'number');
  assert.strictEqual(typeof hash_algorithm, 'string');
  assert(Buffer.isBuffer(message));
  assert.strictEqual(typeof sLen, 'number');
  assert(Buffer.isBuffer(signature));
  const public_key = {
    key: rsa_public,
    padding: crypto.constants.RSA_NO_PADDING
  };
  var m = crypto.publicDecrypt(public_key, signature);

  const emBits = keylen -1;
  const hLen = hashLength[hash_algorithm];
  assert(hLen);
  const mLen = message.length;
  const emLen = Math.ceil(emBits/8);

  const hash1 = crypto.createHash(hash_algorithm);
  hash1.update(message);
  const mHash = hash1.digest();

  if (emLen < hLen + sLen + 2)
    throw new Error("inconsistent");

  if (m[m.length-1] !== 0xbc)
    throw new Error("inconsistent");

  const maskedDB = m.slice(0,  emLen - hLen - 1);
  const H = m.slice(emLen - hLen - 1, emLen -1);

  if ((maskedDB[0] & 0x80) !== 0x00)
    throw new Error("inconsistent");

  const dbMask = MGF1(H, emLen - hLen - 1, hash_algorithm);
  const  DB = BufferXOR(maskedDB, dbMask);
  DB[0] = DB[0] & 0x7f;
  for(var i = 0; i < emLen - hLen - sLen - 2; i++) {
    assert.strictEqual(DB[i], 0x00);
  }
  assert.strictEqual(DB[emLen - hLen - sLen - 2], 0x01);
  const salt = DB.slice(-sLen);
  const MDash = Buffer.concat([Buffer.alloc(8), mHash, salt]);
  const hash2 = crypto.createHash(hash_algorithm);
  hash2.update(MDash);
  const HDash = hash2.digest();
  return HDash.equals(H);
};

function MGF1(mgfSeed, maskLen, hash_algorithm) {
  const hLen = hashLength[hash_algorithm];
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
