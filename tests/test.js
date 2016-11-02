const assert = require('assert');
const fs = require('fs');
const RSAPSS = require('../index.js').RSAPSS;
const test_vector= require('./test_vectors.js');

function TestSign(example, rsa_secret, keylen) {
  const message = new Buffer(example.message, 'hex');
  const salt = new Buffer(example.salt, 'hex');
  const signature = new Buffer(example.signature, 'hex');
  const hash_algorithm = 'sha1';
  const rsapss = new RSAPSS();
  const output_sig = rsapss.sign(rsa_secret, keylen, hash_algorithm, message, salt.length, salt);
  assert(output_sig.equals(signature));
}


function TestVerify(example, rsa_public, keylen) {
  const message = new Buffer(example.message, 'hex');
  const salt = new Buffer(example.salt, 'hex');
  const signature = new Buffer(example.signature, 'hex');
  const hash_algorithm = 'sha1';
  const rsapss = new RSAPSS();
  const ret = rsapss.verify(rsa_public, keylen, hash_algorithm, message, salt.length, signature);
  assert(ret);
}

describe('test vector', function() {
  const rsa_secret = fs.readFileSync(__dirname + '/vectors/key.pem');
  const rsa_public = fs.readFileSync(__dirname + '/vectors/pub-pkcs1.pem');
  const keylen = 1024;
  it('should be example11', function() {
    TestSign(test_vector.example11, rsa_secret, keylen);
    TestVerify(test_vector.example11, rsa_public, keylen);
  });
  it('should be example12', function() {
    TestSign(test_vector.example12, rsa_secret, keylen);
    TestVerify(test_vector.example12, rsa_public, keylen);
  });
  it('should be example13', function() {
    TestSign(test_vector.example13, rsa_secret, keylen);
    TestVerify(test_vector.example13, rsa_public, keylen);
  });
});
