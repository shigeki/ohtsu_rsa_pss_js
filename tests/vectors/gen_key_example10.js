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

var modulus = 'a5dd867ac4cb02f90b9457d48c14a770' +
    'ef991c56c39c0ec65fd11afa8937cea5' +
    '7b9be7ac73b45c0017615b82d622e318' +
    '753b6027c0fd157be12f8090fee2a7ad' +
    'cd0eef759f88ba4997c7a42d58c9aa12' +
    'cb99ae001fe521c13bb5431445a8d5ae' +
    '4f5e4c7e948ac227d3604071f20e577e' +
    '905fbeb15dfaf06d1de5ae6253d63a6a' +
    '2120b31a5da5dabc9550600e20f27d37' +
    '39e2627925fea3cc509f21dff04e6eea' +
    '4549c540d6809ff9307eede91fff5873' +
    '3d8385a237d6d3705a33e39190099207' +
    '0df7adf1357cf7e3700ce3667de83f17' +
    'b8df1778db381dce09cb4ad058a51100' +
    '1a738198ee27cf55a13b754539906582' +
    'ec8b174bd58d5d1f3d767c613721ae05';

var public_exponent = '010001';

var resolved_prime = 'cfd50283feeeb97f6f08d73cbc7b3836' +
    'f82bbcd499479f5e6f76fdfcb8b38c4f' +
    '71dc9e88bd6a6f76371afd65d2af1862' +
    'b32afb34a95f71b8b132043ffebe3a95' +
    '2baf7592448148c03f9c69b1d68e4ce5' +
    'cf32c86baf46fed301ca1ab403069b32' +
    'f456b91f71898ab081cd8c4252ef5271' +
    '915c9794b8f295851da7510f99cb73eb';

var pem = derivePKCS1(modulus, public_exponent, resolved_prime);

console.log(pem);