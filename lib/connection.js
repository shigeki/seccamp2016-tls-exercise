const crypto = require('crypto');
const assert = require('assert');
const EventEmitter = require('events');
const util = require('util');
const TLS_ST_BEFORE = require('./tls_state.js').TLS_ST_BEFORE;
const TLS_CRYPT = require('./tls_crypt.js').TLS_CRYPT;
const common = require('./common.js');
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
  this.seq_write = (new Buffer(8)).fill(0);
  this.seq_read = (new Buffer(8)).fill(0);
  this.on('rawFrame', function(frame, type) {
    if(this.encrypt_write) {
      const write_iv = this.is_server ? this.server_write_iv: this.client_write_iv;
      const key = this.is_server ? this.server_write_key: this.client_write_key;
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
  if (this.encrypt_read) {
    const key = this.is_server ? this.client_write_key: this.server_write_key;
    const write_iv = this.is_server ? this.client_write_iv: this.server_write_iv;
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

Connection.prototype.createHelloRequest = function() {
  return { ContentType: new Buffer('16', 'hex'),
           ProtocolVersion: new Buffer('0303', 'hex'),
           Length: new Buffer('0004', 'hex'),
           Handshake: {
             HandshakeType: new Buffer('00', 'hex'),
             Length: new Buffer('000000', 'hex')
           }
         };
};

Connection.prototype.createClientHello = function() {
  var obj = {
    ContentType: new Buffer('16', 'hex'),
    ProtocolVersion: new Buffer('0303', 'hex'),
    Length: null,
    Handshake:
    { HandshakeType: new Buffer('01', 'hex'),
      Length: null,
      ProtocolVersion: new Buffer('0303', 'hex'),
      Random: crypto.randomBytes(32),
      SessionID: new Buffer(0),
      CipherSuites: [new Buffer('cca8', 'hex')],
      CompressionMethods: new Buffer('00', 'hex'),
      Extensions: [
        { Type: new Buffer('000b', 'hex'), Data: new Buffer('0100', 'hex')},     // ec_point_formats(000b), uncompress(00)
        { Type: new Buffer('000a', 'hex'), Data: new Buffer('00020017', 'hex')}, // elliptic_curve(000a), secp256r1(0017)
        { Type: new Buffer('000d', 'hex'), Data: new Buffer('00020401', 'hex')}
      ]
    }
  };
  return obj;
};
Connection.prototype.createServerHello = function() {};
Connection.prototype.createCertificate = function() {};
Connection.prototype.createServerKeyExchange = function() {};
Connection.prototype.createServerHelloDone = function() {};
Connection.prototype.createClientKeyExchange = function() {};
Connection.prototype.createChangeCipherSpec = function() {};
Connection.prototype.createClientFinished = function() {};
Connection.prototype.createServerFinished = function() {};
