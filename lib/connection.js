const assert = require('assert');
const EventEmitter = require('events');
const util = require('util');
const RecordLayer = require('./tls.js').RecordLayer;
const TLS_ST_BEFORE = require('./tls_state.js').TLS_ST_BEFORE;
const DataReader = require('./data_reader.js').DataReader;
const DataWriter = require('./data_writer.js').DataWriter;
const common = require('./common.js');
const ChaCha20Poly1305 = require('./crypto/chacha20_poly1305.js');
const ChaCha20Poly1305Encrypt = ChaCha20Poly1305.ChaCha20Poly1305Encrypt;
const ChaCha20Poly1305Decrypt = ChaCha20Poly1305.ChaCha20Poly1305Decrypt;
const incSeq = common.incSeq;

exports.Connection = Connection;
function Connection(is_server) {
  this.encrypt_read = false;
  this.encrypt_write = false;
  this.is_server = is_server;
  this.state = new TLS_ST_BEFORE(this);
  this.handshake_list = [];
  this.cipher = "chacha20";
  this.client_write_key = null;
  this.server_write_key = null;
  this.client_write_iv = null;
  this.server_write_iv = null;
  this.seq_write = new Buffer('0000000000000000', 'hex');
  this.seq_read = new Buffer('0000000000000000', 'hex');
  this.on('rawFrame', function(frame, type) {
    const RecordLayerLength = 5;
    const HandshakeHeaderLength = 4;
    const BufferXOR = common.BufferXOR;
    const write_iv = this.is_server ? this.server_write_iv: this.client_write_iv;
    const key = this.is_server ? this.server_write_key: this.client_write_key;
    if(this.encrypt_write) {
      assert(this.cipher === "chacha20", "cipher only supports chacha20");
      var data_reader = new DataReader(frame);
      const record_layer = RecordLayer.decode(data_reader.readBytes(RecordLayerLength));
      var length = record_layer.Length.readUInt16BE();
      var plain_data = data_reader.readBytes(length);
      var encrypted_record_header = Buffer.concat([record_layer.ContentType, record_layer.ProtocolVersion, new Buffer('0000', 'hex')]);
      encrypted_record_header.writeUInt16BE(plain_data.length, 3);
      var seq = this.seq_write;
      var aad = Buffer.concat([seq, encrypted_record_header]);
      var nonce = BufferXOR(Buffer.concat([new Buffer('00000000', 'hex'), seq]), write_iv);
      var encrypted = ChaCha20Poly1305Encrypt(aad, key, nonce, frame.slice(5));
      incSeq(seq);
      var new_encrypted_record_header = new Buffer('1603030000', 'hex');
      new_encrypted_record_header.writeUInt16BE(encrypted.ciphertext.length + ChaCha20Poly1305Encrypt.taglength, 3);
      var encrypted_frame = Buffer.concat([new_encrypted_record_header, encrypted.ciphertext, encrypted.tag]);
      this.emit('frame', encrypted_frame, type);
    } else {
      this.emit('frame', frame, type);
    }
  });
}
util.inherits(Connection, EventEmitter);
Connection.prototype.enableEncryptRead = function() {
  this.encrypt_read = true;
};
Connection.prototype.enableEncryptWrite = function() {
  this.encrypt_write = true;
};
Connection.prototype.addHandshakeBuf = function(buf) {
  this.handshake_list.push(buf);
};

Connection.prototype.setState = function(state) {
  this.state = state;
};

Connection.prototype.read = function(buf, cb) {
  const RecordLayerLength = 5;
  const HandshakeHeaderLength = 4;
  const BufferXOR = common.BufferXOR;
  const ContentType = {
    ChangeCipherSpec: new Buffer('14', 'hex'),
    Alert: new Buffer('15', 'hex'),
    Handshake: new Buffer('16', 'hex'),
    ApplicationData: new Buffer('17', 'hex')
  };
  const key = this.is_server ? this.client_write_key: this.server_write_key;
  const write_iv = this.is_server ? this.client_write_iv: this.server_write_iv;

  if (this.encrypt_read) {
    assert(this.cipher === "chacha20", "cipher only supports chacha20");
    var data_reader = new DataReader(buf);
    const record_layer = RecordLayer.decode(data_reader.readBytes(RecordLayerLength));
    var length = record_layer.Length.readUInt16BE();
    var encrypted_data_and_tag = data_reader.readBytes(length);
    var encrypted_data = encrypted_data_and_tag.slice(0, -ChaCha20Poly1305Decrypt.taglength);
    var tag = encrypted_data_and_tag.slice(-ChaCha20Poly1305Decrypt.taglength);

    var encrypted_record_header = new Buffer('1603030000', 'hex');
    encrypted_record_header.writeUInt16BE(HandshakeHeaderLength + encrypted_data.length, 3);
    const seq = this.seq_read;
    var aad = Buffer.concat([seq, encrypted_record_header]);
    var nonce = BufferXOR(Buffer.concat([new Buffer('00000000', 'hex'), seq]), write_iv);
    var unencrypted_data = ChaCha20Poly1305Decrypt(aad, key, nonce, encrypted_data);
    incSeq(seq);
    var new_length = (new Buffer(2));
    new_length.writeUInt16BE(unencrypted_data.plaintext.length);
    var unencrypted_record_header = Buffer.concat([
      record_layer.ContentType,
      record_layer.ProtocolVersion,
      new_length
    ]);
    var decrypted_buf = Buffer.concat([unencrypted_record_header, unencrypted_data.plaintext]);
    this.state.read(decrypted_buf, cb);
  } else {
    this.state.read(buf, cb);
  }
};

Connection.prototype.write = function(buf, cb) {
  this.state.write(buf, cb);
};