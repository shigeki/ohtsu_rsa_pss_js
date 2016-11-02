const fs = require('fs');
const rsa_secret = fs.readFileSync('./tests/vectors/key.pem');
const rsa_secret_der = fs.readFileSync('./tests/vectors/key.der');
console.log(rsa_secret_der);
const rsa_public = fs.readFileSync('./tests/vectors/pub-pkcs1.pem');
const asn = require('asn1.js');
const BN = require('bn.js');


function readRSAPrivateKeyFile (filename) {
  var file = fs.readFileSync(filename, 'utf8');
  file = file.replace(/\n|\r/g, "");
  return Buffer.from(file);
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

var RSAPrivateKey = asn.define('RSAPrivateKey', function() {
  this.seq().obj(
    this.key('version').int(),
    this.seq().obj(
      this.key('algorithm').objid(),
      this.any('parameters').any()
    ),
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
    )
  );
});


/*
RSAPublicKey ::= SEQUENCE {
          modulus           INTEGER,  -- n
          publicExponent    INTEGER   -- e
      }
*/
var RSAPublicKey = asn.define('RSAPublicKey', function() {
  this.seq().obj(
    this.key('modulus').int(),
    this.key('publicExponent').int()
  );
});

var priv = RSAPrivateKey.decode(rsa_secret, 'pem', {label: 'PRIVATE KEY'});
console.log(priv.modulus.toBuffer().length);

//var pub = RSAPublicKey.decode(rsa_public, 'pem');
//console.log(pub);
