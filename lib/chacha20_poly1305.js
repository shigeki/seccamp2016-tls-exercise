const assert = require('assert');
const ChaCha20 = require('./chacha20.js');
const ChaCha20Encrypt = ChaCha20.ChaCha20Encrypt;
const Poly1305 = require('./poly1305.js');
const Poly1305Mac = Poly1305.Poly1305Mac;
const Poly1305KeyGeneration = Poly1305.Poly1305KeyGeneration;

function Pad16(x) {
  assert(Buffer.isBuffer(x));
  if (x.length % 16 === 0) {
    return new Buffer(0);
  } else {
    var buf = new Buffer(16 - x.length % 16);
    buf.fill(0);
    return buf;
  }
}


exports.ChaCha20Poly1305 = ChaCha20Poly1305;
function ChaCha20Poly1305(aad, key, nonce, plaintext) {
  assert(Buffer.isBuffer(aad));
  assert(0xffffffff > aad.length);
  assert(Buffer.isBuffer(key));
  assert(key.length === 32);
  assert(Buffer.isBuffer(nonce));
  assert(nonce.length === 12);
  assert(Buffer.isBuffer(plaintext));
  assert(0xffffffff > plaintext.length);

  var otk = Poly1305KeyGeneration(key, nonce);
  var ciphertext = ChaCha20Encrypt(key, 1, nonce, plaintext);
  var aad_length = new Buffer(8);
  aad_length.fill(0x00);
  aad_length.writeUInt32LE(aad.length);
  var ciphertext_length = new Buffer(8);
  ciphertext_length.fill(0x00);
  ciphertext_length.writeUInt32LE(ciphertext.length);
  var mac_data = Buffer.concat([aad, Pad16(aad), ciphertext, Pad16(ciphertext), aad_length, ciphertext_length]);
  var tag = Poly1305Mac(mac_data, otk);
  return {ciphertext: ciphertext, tag: tag};
}
