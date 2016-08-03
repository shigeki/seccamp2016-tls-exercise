const crypto = require('crypto');
const assert = require('assert');
const EventEmitter = require('events');
const util = require('util');
const TLS_ST_BEFORE = require('./tls_state.js').TLS_ST_BEFORE;
const TLS_CRYPT = require('./tls_crypt.js').TLS_CRYPT;
const TLS = require('./tls.js').TLS;
const common = require('./common.js');
const incSeq = common.incSeq;

exports.Connection = Connection;
function Connection(is_server, stub) {
  this.version = new Buffer('0303', 'hex');
  this.frame_creator = stub ? require('./stub_tls_frame_creator.js') : require('./tls_frame_creator.js');
  this.client_random = null;
  this.server_random = null;
  this.key_block = null;
  this.peerPublicKey = null;
  this.localEphemeralKey = null;
  this.pre_master_secret = null;
  this.master_secret = null;
  this.certificates = null;
  this.encrypt_read = false;
  this.encrypt_write = false;
  this.is_server = is_server;
  this.state = new TLS_ST_BEFORE(this);
  this.handshake_list = [];
  this.cipher = "chacha20";
  this.key_block = {};
  this.seq_write = (new Buffer(8)).fill(0);
  this.seq_read = (new Buffer(8)).fill(0);
  this.on('rawFrame', function(frame, type) {
    if(this.encrypt_write) {
      const write_iv = this.is_server ? this.key_block.server_write_iv: this.key_block.client_write_iv;
      const key = this.is_server ? this.key_block.server_write_key: this.key_block.client_write_key;
      var seq = this.seq_write;
      var encrypted_frame = TLS_CRYPT.encrypt(this.cipher, key, write_iv, frame, seq);
      incSeq(seq);
      this.emit('frame', encrypted_frame, type);
    } else {
      this.emit('frame', frame, type);
    }
  });
}
util.inherits(Connection, EventEmitter);

Connection.prototype.setCertificates = function(certificates) {
  this.certificates = certificates;
};

Connection.prototype.enableEncryptRead = function() {
  if (!this.pre_master_secret) {
    this.pre_master_secret = this.localEphemeralKey.computeSecret(this.peerPublicKey);
    this.master_secret = TLS.DeriveMasterSecret(this.pre_master_secret, this.client_random, this.server_random);
    this.key_block = TLS.DeriveKeyBlock(this.cipher, this.master_secret, this.client_random, this.server_random);
  }
  this.encrypt_read = true;
};

Connection.prototype.enableEncryptWrite = function() {
  if (!this.pre_master_secret) {
    this.pre_master_secret = this.localEphemeralKey.computeSecret(this.peerPublicKey);
    this.master_secret = TLS.DeriveMasterSecret(this.pre_master_secret, this.client_random, this.server_random);
    this.key_block = TLS.DeriveKeyBlock(this.cipher, this.master_secret, this.client_random, this.server_random);
  }
  this.encrypt_write = true;
};

Connection.prototype.addHandshakeBuf = function(buf) {
  this.handshake_list.push(buf);
};

Connection.prototype.setState = function(state) {
  this.state = state;
};

Connection.prototype.read = function(buf, cb) {
  if (this.encrypt_read) {
    const key = this.is_server ? this.key_block.client_write_key: this.key_block.server_write_key;
    const write_iv = this.is_server ? this.key_block.client_write_iv: this.key_block.server_write_iv;
    var seq = this.seq_read;
    var decrypted_buf = TLS_CRYPT.decrypt(this.cipher, key, write_iv, buf, seq);
    incSeq(seq);
    this.state.read(decrypted_buf, cb);
  } else {
    this.state.read(buf, cb);
  }
};

Connection.prototype.write = function(buf, cb) {
  this.state.write(buf, cb);
};
