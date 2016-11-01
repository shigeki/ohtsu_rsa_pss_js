const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const asn = require('asn1.js');
const BN = require('bn.js');

const hashLength = {
  'sha1' : 20,
  'sha256': 32,
  'sha384': 46,
  'sha512': 64
};

exports.RSAPSS = RSAPSS;

function RSAPSS() {

}

RSAPSS.prototype.sign = function(rsa_secret, hash_algorithm, message, saltlen, salt) {
  assert(Buffer.isBuffer(rsa_secret));
  assert.strictEqual(typeof hash_algorithm, 'string');
  assert(Buffer.isBuffer(message));
  assert.strictEqual(typeof saltlen, 'number');
  if (salt) {
    assert(Buffer.isBuffer(salt));
    assert.strictEqual(saltlen, salt.length);
  } else {
    salt = crypto.randomBytes(saltlen);
  }
  const sLen = saltlen;
  const hLen = hashLength[hash_algorithm];
  assert(hLen);
  const mLen = message.length;
  const secret = ParseRSAPrivateKey(rsa_secret);
  const emLen = secret.modulus.toBuffer().length;

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
  var signature = crypto.privateEncrypt(private_key, b);

  return signature;
};

RSAPSS.prototype.verify = function(public_key, signature) {

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


/*
RSAPrivateKey ::= SEQUENCE {
          version           Version,
          modulus           INTEGER,  -- n
          publicExponent    INTEGER,  -- e
          privateExponent   INTEGER,  -- d
          prime1            INTEGER,  -- p
          prime2            INTEGER,  -- q
          exponent1         INTEGER,  -- d mod (p-1)
          exponent2         INTEGER,  -- d mod (q-1)
          coefficient       INTEGER,  -- (inverse of q) mod p
          otherPrimeInfos   OtherPrimeInfos OPTIONAL
      }
Version ::= INTEGER { two-prime(0), multi(1) }
            (CONSTRAINED BY
            {-- version must be multi if otherPrimeInfos present --})
OtherPrimeInfos ::= SEQUENCE SIZE(1..MAX) OF OtherPrimeInfo
         OtherPrimeInfo ::= SEQUENCE {
             prime             INTEGER,  -- ri
             exponent          INTEGER,  -- di
             coefficient       INTEGER   -- ti
         }
*/

const RSAPrivateKey = asn.define('RSAPrivateKey', function() {
  this.seq().obj(
    this.key('version').int(),
    this.key('modulus').int(),
    this.key('publicExponent').int(),
    this.key('privateExponent').int(),
    this.key('prime1').int(),
    this.key('prime2').int(),
    this.key('exponent1').int(),
    this.key('exponent2').int(),
    this.key('coefficient').int(),
    this.optional('otherPrimeInfos').seq().obj(
      this.key('prime').int(),
      this.key('exponent').int(),
      this.key('coefficient').int()
    )
  );
});

function ParseRSAPrivateKey(rsa_secret) {
  return RSAPrivateKey.decode(rsa_secret, 'pem');
}

/*
RSAPublicKey ::= SEQUENCE {
          modulus           INTEGER,  -- n
          publicExponent    INTEGER   -- e
      }
*/
const RSAPublicKey = asn.define('RSAPublicKey', function() {
  this.seq().obj(
    this.key('modulus').int(),
    this.key('publicExponent').int()
  );
});

function ParseRSAPublicKey(rsa_public) {
  return RSAPublicKey.decode(rsa_public, 'pem');
}
