const r = require('jsrsasign');
const KEYUTIL = r.KEYUTIL;
const RSAKey = r.RSAKey;
const BigInteger = r.BigInteger;

function derivePKCS1(modulus, public_exponent, resolved_prime) {
  var rsa = new RSAKey();
  var N = new BigInteger(modulus, 16);  // PxQ
  var E = new BigInteger(public_exponent, 16);
  var P = new BigInteger(resolved_prime, 16);
  var Q = N.divide(P);
  var P1 = P.subtract(BigInteger.ONE); // P-1
  var Q1 = Q.subtract(BigInteger.ONE); // Q-1
  var phi = P1.multiply(Q1);           // (P-1)*(Q-1)
  var D = E.modInverse(phi);           // E^-1 mod(phi)
  var DP = D.mod(P1);                  // D mod(P-1)
  var DQ = D.mod(Q1);                  // D mod(Q-1)
  var C = Q.modInverse(P);             // Q^-1 mode(P)
  rsa.setPrivateEx(N.toString(16), E.toString(16), D.toString(16),
                   P.toString(16), Q.toString(16), DP.toString(16),
                   DQ.toString(16), C.toString(16));
  var pkey = KEYUTIL.getKey(rsa);
  var pem = KEYUTIL.getPEM(pkey, "PKCS8PRV");
  return pem;
}

var modulus = 'a56e4a0e701017589a5187dc7ea841d1' +
    '56f2ec0e36ad52a44dfeb1e61f7ad991' +
    'd8c51056ffedb162b4c0f283a12a88a3' +
    '94dff526ab7291cbb307ceabfce0b1df' +
    'd5cd9508096d5b2b8b6df5d671ef6377' +
    'c0921cb23c270a70e2598e6ff89d19f1' +
    '05acc2d3f0cb35f29280e1386b6f64c4' +
    'ef22e1e1f20d0ce8cffb2249bd9a2137';

var public_exponent = '010001';

var resolved_prime = 'e7e8942720a877517273a356053ea2a1' +
    'bc0c94aa72d55c6e86296b2dfc967948' +
    'c0a72cbccca7eacb35706e09a1df55a1' +
    '535bd9b3cc34160b3b6dcd3eda8e6443';

var pem = derivePKCS1(modulus, public_exponent, resolved_prime);

console.log(pem);