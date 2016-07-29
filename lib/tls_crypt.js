const assert = require('assert');
const common = require('./common.js');
const DataReader = require('./data_reader.js').DataReader;
const TLS_RecordLayer = require('./tls_recordlayer.js');
const RecordLayer = TLS_RecordLayer.RecordLayer;
const ChaCha20Poly1305 = require('./crypto/chacha20_poly1305.js');
const ChaCha20Poly1305Encrypt = ChaCha20Poly1305.ChaCha20Poly1305Encrypt;
const ChaCha20Poly1305Decrypt = ChaCha20Poly1305.ChaCha20Poly1305Decrypt;
const RecordLayerLength = common.RecordLayerLength;
const HandshakeHeaderLength = common.HandshakeHeaderLength;

const BufferXOR = common.BufferXOR;
const ContentType = common.ContentType;

function Encrypt(cipher, key, write_iv, frame, seq) {
  assert(cipher === "chacha20", "cipher only supports chacha20");
  var data_reader = new DataReader(frame);
  const record_layer = RecordLayer.decode(data_reader.readBytes(RecordLayerLength));
  var length = record_layer.Length.readUInt16BE();
  var plain_data = data_reader.readBytes(length);
  var encrypted_record_header = Buffer.concat([record_layer.ContentType, record_layer.ProtocolVersion, new Buffer('0000', 'hex')]);
  encrypted_record_header.writeUInt16BE(plain_data.length, 3);
  var aad = Buffer.concat([seq, encrypted_record_header]);
  var nonce = BufferXOR(Buffer.concat([new Buffer('00000000', 'hex'), seq]), write_iv);
  var encrypted = ChaCha20Poly1305Encrypt(aad, key, nonce, frame.slice(5));
  var new_encrypted_record_header = new Buffer('1603030000', 'hex');
  new_encrypted_record_header.writeUInt16BE(encrypted.ciphertext.length + ChaCha20Poly1305Encrypt.taglength, 3);
  var encrypted_frame = Buffer.concat([new_encrypted_record_header, encrypted.ciphertext, encrypted.tag]);
  return encrypted_frame;
}

function Decrypt(cipher, key, write_iv, buf, seq) {
  assert(cipher === "chacha20", "cipher only supports chacha20");
  var data_reader = new DataReader(buf);
  const record_layer = RecordLayer.decode(data_reader.readBytes(RecordLayerLength));
  var length = record_layer.Length.readUInt16BE();
  var encrypted_data_and_tag = data_reader.readBytes(length);
  var tag = encrypted_data_and_tag.slice(-ChaCha20Poly1305Decrypt.taglength);
  var encrypted_record_header = Buffer.concat([record_layer.ContentType, record_layer.ProtocolVersion, (new Buffer(2))]);
  encrypted_record_header.writeUInt16BE(HandshakeHeaderLength + encrypted_data.length, 3);
  var aad = Buffer.concat([seq, encrypted_record_header]);
  var nonce = BufferXOR(Buffer.concat([(new Buffer(4)).fill(0), seq]), write_iv);
  var unencrypted_data = ChaCha20Poly1305Decrypt(aad, key, nonce, encrypted_data_and_tag);
  assert(tag.equals(unencrypted_data.tag), 'Auth Tag is not matched');
  var new_length = (new Buffer(2));
  new_length.writeUInt16BE(unencrypted_data.plaintext.length);
  var unencrypted_record_header = Buffer.concat([
    record_layer.ContentType,
    record_layer.ProtocolVersion,
    new_length
  ]);
  var decrypted_buf = Buffer.concat([unencrypted_record_header, unencrypted_data.plaintext]);
  return decrypted_buf;
}

exports.TLS_CRYPT = {
  encrypt: Encrypt,
  decrypt: Decrypt
};
