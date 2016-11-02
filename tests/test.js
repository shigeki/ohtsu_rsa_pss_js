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

describe('test vector example 1', function() {
  const rsa_secret = fs.readFileSync(__dirname + '/example1_key.pem');
  const rsa_public = fs.readFileSync(__dirname + '/example1_pub.pem');
  const keylen = 1024;
  it('should be example 1.1', function() {
    TestSign(test_vector.example11, rsa_secret, keylen);
    TestVerify(test_vector.example11, rsa_public, keylen);
  });
  it('should be example 1.2', function() {
    TestSign(test_vector.example12, rsa_secret, keylen);
    TestVerify(test_vector.example12, rsa_public, keylen);
  });
  it('should be example 1.3', function() {
    TestSign(test_vector.example13, rsa_secret, keylen);
    TestVerify(test_vector.example13, rsa_public, keylen);
  });
  it('should be example 1.4', function() {
    TestSign(test_vector.example14, rsa_secret, keylen);
    TestVerify(test_vector.example14, rsa_public, keylen);
  });
  it('should be example 1.5', function() {
    TestSign(test_vector.example15, rsa_secret, keylen);
    TestVerify(test_vector.example15, rsa_public, keylen);
  });
  it('should be example 1.6', function() {
    TestSign(test_vector.example16, rsa_secret, keylen);
    TestVerify(test_vector.example16, rsa_public, keylen);
  });
});

describe('test vector example 10', function() {
  const rsa_secret = fs.readFileSync(__dirname + '/example10_key.pem');
  const rsa_public = fs.readFileSync(__dirname + '/example10_pub.pem');
  const keylen = 2048;
  it('should be example 10.1', function() {
    TestSign(test_vector.example101, rsa_secret, keylen);
    TestVerify(test_vector.example101, rsa_public, keylen);
  });
  it('should be example 10.2', function() {
    TestSign(test_vector.example102, rsa_secret, keylen);
    TestVerify(test_vector.example102, rsa_public, keylen);
  });
  it('should be example 10.3', function() {
    TestSign(test_vector.example103, rsa_secret, keylen);
    TestVerify(test_vector.example103, rsa_public, keylen);
  });
  it('should be example 10.4', function() {
    TestSign(test_vector.example104, rsa_secret, keylen);
    TestVerify(test_vector.example104, rsa_public, keylen);
  });
  it('should be example 10.5', function() {
    TestSign(test_vector.example105, rsa_secret, keylen);
    TestVerify(test_vector.example105, rsa_public, keylen);
  });
  it('should be example 10.6', function() {
    TestSign(test_vector.example106, rsa_secret, keylen);
    TestVerify(test_vector.example106, rsa_public, keylen);
  });
});
