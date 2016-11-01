const fs = require('fs');
const RSAPSS = require('../index.js').RSAPSS;
const test_vector= require('./test_vectors.js');
const rsa_secret = fs.readFileSync(__dirname + '/vectors/key.der');
const rsa_pub = fs.readFileSync(__dirname + '/vectors/pub-pkcs1.der');

describe('test vector', function() {
  it('should be example11', function() {
    const example11 = test_vector.example11;
    const message = new Buffer(example11.message, 'hex');
    const salt = new Buffer(example11.salt, 'hex');
    const signature = new Buffer(example11.signature, 'hex');
    const hash_algorithm = 'sha1';
    const rsapss = new RSAPSS();
    const output_sig = rsapss.sign(rsa_secret, hash_algorithm, message, salt.length, salt);
  });
});