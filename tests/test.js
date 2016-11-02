const assert = require('assert');
const fs = require('fs');
const RSAPSS = require('../index.js').RSAPSS;
const test_vector= require('./test_vectors.js');
const rsa_secret = fs.readFileSync(__dirname + '/vectors/key.pem');
const rsa_pub = fs.readFileSync(__dirname + '/vectors/pub-pkcs1.pem');
const keylen = 1024;

function Test(example, kenlen) {
  const message = new Buffer(example.message, 'hex');
  const salt = new Buffer(example.salt, 'hex');
  const signature = new Buffer(example.signature, 'hex');
  const hash_algorithm = 'sha1';
  const rsapss = new RSAPSS();
  const output_sig = rsapss.sign(rsa_secret, keylen, hash_algorithm, message, salt.length, salt);
  assert(output_sig.equals(signature));
}

describe('test vector', function() {
  it('should be example11', function() {
    Test(test_vector.example11, keylen)
  });
  it('should be example12', function() {
    Test(test_vector.example12, keylen)
  });
  it('should be example13', function() {
    Test(test_vector.example13, keylen)
  });
});
