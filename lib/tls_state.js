const util = require('util');
const assert = require('assert');
const TLS = require('./tls.js').TLS;
const common = require('./common.js');
const ContentType = common.ContentType;
const RevContentType = common.RevContentType;
const HandshakeType = common.HandshakeType;
const RevHandshakeType = common.RevHandshakeType;

// Server State Transition
//
// TLS_ST_BEFORE
//     | read(client_hello)
// TLS_ST_SR_CLNT_HELLO
//     | write(server_hello)
// TLS_ST_SW_SRVR_HELLO
//     | write(certificates)
// TLS_ST_SW_CERT
//     | write(server_key_exchange)
// TLS_ST_SW_KEY_EXCH
//     | write(server_hello_done)
// TLS_ST_SW_SRVR_DONE
//     | read(client_key_exchange)
// TLS_ST_SR_KEY_EXH
//     | read(change_cipher_spec)
// TLS_ST_SR_CHANGE
//     | read(client_finished)
// TLS_ST_SR_FINISHED
//     | write(change_cipher_spec)
// TLS_ST_SW_CHANGE
//     | write(server_finished)
// TLS_ST_SW_FINISHED
//     |
// TLS_ST_OK
//

function checkContentTypeBuf(buf) {
  assert(Buffer.isBuffer(buf), buf + 'is not Buffer');
  assert(buf.length >= 5, 'buf length is too short');
  var content_type = RevContentType[buf[0]];
  assert(content_type !== undefined, 'unknown content_type of ' + buf);
  return content_type;
}

function checkHandshakeBuf(buf) {
  assert(Buffer.isBuffer(buf), buf + 'is not Buffer');
  assert(buf.length >= 9, 'buf length is too short');
  assert(buf[0] === ContentType.Handshake, buf + 'is not Handshake');
  var handshake_type = RevHandshakeType[buf[5]];
  assert(handshake_type !== undefined, 'unknown handshake type of ' + handshake_type);
  return handshake_type;
}

function TLS_STATE(connection) {
  this.connection = connection;
}
TLS_STATE.prototype.read = function(buf, cb) {
  this.connection.emit('error', new Error('Not Allowed to Receive ' + buf));
};
TLS_STATE.prototype.write = function(buf, cb) {
  this.connection.emit('error', new Error('Not Allowed to Write ' + buf));
};

function TLS_ST_OK(connection) {
  TLS_STATE.call(this, connection);
}
util.inherits(TLS_ST_OK, TLS_STATE);
TLS_ST_OK.prototype.read = function(buf, cb) {
  var content_type = checkContentTypeBuf(buf);
  if (content_type === 'ApplicationData') {
    var clear_text = buf.slice(5);
    this.connection.emit('clearText', clear_text);
  }
  cb(null);
};
TLS_ST_OK.prototype.write = function(buf, cb) {
  var content_type = checkContentTypeBuf(buf);
  cb(null);
};

exports.TLS_ST_BEFORE = TLS_ST_BEFORE;
function TLS_ST_BEFORE(connection) {
  TLS_STATE.call(this, connection);
}
util.inherits(TLS_ST_BEFORE, TLS_STATE);

TLS_ST_BEFORE.prototype.read = function(buf, cb) {
  var handshake_type = checkHandshakeBuf(buf);
  if (!this.connection.is_server && handshake_type === 'HelloRequest') {
    throw new Error('Need to be implemented');
    return true;
  }
  if (this.connection.is_server && handshake_type === 'ClientHello') {
    this.connection.addHandshakeBuf(buf.slice(5));
    this.connection.setState(new TLS_ST_SR_CLNT_HELLO(this.connection));
    this.connection.write(buf, cb);
    return true;
  }
  this.connection.emit('error', new Error('Not Allowed to Receive ' + buf));
  return false;
};

// Server State
function TLS_ST_SW_HELLO_REQ() {
  TLS_STATE.call(this, connection);
}
util.inherits(TLS_ST_SW_HELLO_REQ, TLS_STATE);

function TLS_ST_SR_CLNT_HELLO(connection) {
  TLS_STATE.call(this, connection);
}
util.inherits(TLS_ST_SR_CLNT_HELLO, TLS_STATE);

TLS_ST_SR_CLNT_HELLO.prototype.write = function(buf, cb) {
  var handshake_type = checkHandshakeBuf(buf);
  if (handshake_type === 'ClientHello') {
    var obj = this.connection.createServerHello();
    var server_hello = TLS.Handshake.ServerHello.encode(obj);
    this.connection.setState(new TLS_ST_SW_SRVR_HELLO(this.connection));
    this.connection.addHandshakeBuf(server_hello.slice(5));
    this.connection.emit('rawFrame', server_hello, 'ServerHello');
    this.connection.write(server_hello, cb);
    return true;
  }
  this.connection.emit('error', new Error('Not Allowed to Receive ' + buf));
  return false;
};

function TLS_ST_SW_SRVR_HELLO(connection) {
  TLS_STATE.call(this, connection);
}
util.inherits(TLS_ST_SW_SRVR_HELLO, TLS_STATE);

TLS_ST_SW_SRVR_HELLO.prototype.write = function(buf, cb) {
  var handshake_type = checkHandshakeBuf(buf);
  if (handshake_type === 'ServerHello') {
    this.connection.setState(new TLS_ST_SW_CERT(this.connection));
    var obj = this.connection.createCertificate();
    var certificate = TLS.Handshake.Certificate.encode(obj);
    this.connection.addHandshakeBuf(certificate.slice(5));
    this.connection.emit('rawFrame', certificate, 'Certificate');
    this.connection.write(certificate, cb);
    return true;
  }
  this.connection.emit('error', new Error('Not Allowed to Receive ' + buf + ' on ' + this.constructor.name));
  return false;
};

function TLS_ST_SW_CERT(connection) {
  TLS_STATE.call(this, connection);
}
util.inherits(TLS_ST_SW_CERT, TLS_STATE);

TLS_ST_SW_CERT.prototype.read = function(buf, cb) {
};
TLS_ST_SW_CERT.prototype.write = function(buf, cb) {
  var handshake_type = checkHandshakeBuf(buf);
  if (handshake_type === 'Certificate') {
    this.connection.setState(new TLS_ST_SW_KEY_EXCH(this.connection));
    var obj = this.connection.createServerKeyExchange();
    var server_key_exchange = TLS.Handshake.ServerKeyExchange.encode(obj);
    this.connection.addHandshakeBuf(server_key_exchange.slice(5));
    this.connection.emit('rawFrame', server_key_exchange, 'ServerKeyExchange');
    this.connection.write(server_key_exchange, cb);
    return true;
  }
  this.connection.emit('error', new Error('Not Allowed to Receive ' + buf + ' on ' + this.constructor.name));
  return false;
};

function TLS_ST_SW_KEY_EXCH(connection) {
  TLS_STATE.call(this, connection);
}
util.inherits(TLS_ST_SW_KEY_EXCH, TLS_STATE);

TLS_ST_SW_KEY_EXCH.prototype.write = function(buf, cb) {
  var handshake_type = checkHandshakeBuf(buf);
  if (handshake_type === 'ServerKeyExchange') {
    this.connection.setState(new TLS_ST_SW_SRVR_DONE(this.connection));
    var obj = this.connection.createServerHelloDone();
    var server_hello_done = TLS.Handshake.ServerHelloDone.encode(obj);
    this.connection.addHandshakeBuf(server_hello_done.slice(5));
    this.connection.emit('rawFrame', server_hello_done, 'ServerHelloDone');
    this.connection.setState(new TLS_ST_SW_SRVR_DONE(this.connection));
    // no more read and write
    if (cb) cb(null);
    return true;
  }
  this.connection.emit('error', new Error('Not Allowed to Receive ' + buf + ' on ' + this.constructor.name));
  return false;
};

// TLS_ST_SW_CERT_REQ

function TLS_ST_SW_SRVR_DONE(connection) {
  TLS_STATE.call(this, connection);
}
util.inherits(TLS_ST_SW_SRVR_DONE, TLS_STATE);

TLS_ST_SW_SRVR_DONE.prototype.read = function(buf, cb) {
  var handshake_type = checkHandshakeBuf(buf);
  if (handshake_type === 'ClientKeyExchange') {
    this.connection.addHandshakeBuf(buf.slice(5));
    this.connection.setState(new TLS_ST_SR_KEY_EXCH(this.connection));
    // no more read and write
    if (cb) cb(null);
    return true;
  }
  this.connection.emit('error', new Error('Not Allowed to Receive ' + buf + ' on ' + this.constructor.name));
  return false;
};

// TLS_ST_SR_CERT

function TLS_ST_SR_KEY_EXCH(connection) {
  this.connection = connection;
}
TLS_ST_SR_KEY_EXCH.prototype.read = function(buf, cb) {
  var content_type = checkContentTypeBuf(buf);
  if (content_type === 'ChangeCipherSpec') {
    this.connection.enableEncryptRead();
    this.connection.setState(new TLS_ST_SR_CHANGE(this.connection));
    // no more read and write
    if (cb) cb(null);
    return true;
  }
  this.connection.emit('error', new Error('Not Allowed to Receive ' + buf + ' on ' + this.constructor.name));
  return false;
};

// TLS_ST_SR_CERT_VRFY
// TLS_ST_SR_NEXT_PROTO

function TLS_ST_SR_CHANGE(connection) {
  TLS_STATE.call(this, connection);
}
util.inherits(TLS_ST_SR_CHANGE, TLS_STATE);

TLS_ST_SR_CHANGE.prototype.read = function(buf, cb) {
  var handshake_type = checkHandshakeBuf(buf);
  if (handshake_type === 'Finished') {
    this.connection.setState(new TLS_ST_SR_FINISHED(this.connection));
    this.connection.write(null, cb);
    return true;
  }
  this.connection.emit('error', new Error('Not Allowed to Receive ' + buf + ' on ' + this.constructor.name));
  return false;
};

function TLS_ST_SR_FINISHED(connection) {
  TLS_STATE.call(this, connection);
}
util.inherits(TLS_ST_SR_FINISHED, TLS_STATE);

TLS_ST_SR_FINISHED.prototype.write = function(buf, cb) {
  this.connection.setState(new TLS_ST_SW_SRVR_DONE(this.connection));
  var obj = this.connection.createChangeCipherSpec();
  var change_cipher_spec = TLS.ChangeCipherSpec.encode(obj);
  this.connection.emit('rawFrame', change_cipher_spec, 'ChangeCipherSpec');
  this.connection.setState(new TLS_ST_SW_CHANGE(this.connection));
  this.connection.write(change_cipher_spec, cb);
  return true;
};

// TLS_ST_SW_SESSION_TICKET
// TLS_ST_SW_CERT_STATUS

function TLS_ST_SW_CHANGE(connection) {
  TLS_STATE.call(this, connection);
}
util.inherits(TLS_ST_SW_CHANGE, TLS_STATE);

TLS_ST_SW_CHANGE.prototype.write = function(buf, cb) {
  var content_type = checkContentTypeBuf(buf);
  if (content_type === 'ChangeCipherSpec') {
    this.connection.enableEncryptWrite();
    var obj = this.connection.createServerFinished();
    var server_finished = TLS.Handshake.UnencryptedFinished.encode(obj);
    this.connection.emit('rawFrame', server_finished, 'ServerFinished');
    this.connection.setState(new TLS_ST_SW_FINISHED(this.connection));
    this.connection.write(server_finished, cb);
    return true;
  }
  this.connection.emit('error', new Error('Not Allowed to Receive ' + buf + ' on ' + this.constructor.name));
  return false;
};

function TLS_ST_SW_FINISHED(connection) {
  TLS_STATE.call(this, connection);
}
util.inherits(TLS_ST_SW_FINISHED, TLS_STATE);

TLS_ST_SW_FINISHED.prototype.write = function(buf, cb) {
  var handshake_type = checkHandshakeBuf(buf);
  if (handshake_type === 'Finished') {
    this.connection.setState(new TLS_ST_OK(this.connection));
    // no more read and write
    if (cb) cb(null);
    return true;
  }
  this.connection.emit('error', new Error('Not Allowed to Receive ' + buf + ' on ' + this.constructor.name));
  return false;
};

// Client State Transition
// TLS_ST_BEFORE
//     |
// TLS_ST_CW_CLNT_HELLO
//     |
// TLS_ST_CR_SRVR_HELLO
//     |
// TLS_ST_CR_CERT
//     |
// TLS_ST_CR_KEY_EXCH
//     |
// TLS_ST_CR_SRVR_DONE
//     |
// TLS_ST_CW_KEY_EXH
//     |
// TLS_ST_CW_CHANGE
//     |
// TLS_ST_CW_FINISHED
//     |
// TLS_ST_CR_CHANGE
//     |
// TLS_ST_CR_FINISHED
//     |
// TLS_ST_OK
function TLS_ST_CW_CLT_HELLO() {
}
TLS_ST_CW_CLT_HELLO.prototype.read = function() {
};
TLS_ST_CW_CLT_HELLO.prototype.write = function() {
};

function TLS_ST_CR_SRVR_HELLO() {
}
function TLS_ST_CR_CERT() {
}
// TLS_ST_CR_CERT_STATUS
function TLS_ST_CR_KEY_EXCH() {
}
// TLS_ST_CR_CERT_REQ

function TLS_ST_CR_SRVR_DONE() {
}
// TLS_ST_CR_SESSION_TICKET
function TLS_ST_CR_CHANGE() {
}
function TLS_ST_CR_FINISHED() {
}
// TLS_ST_CW_CERT
function TLS_ST_CW_KEY_EXCH() {
}
// TLS_ST_CW_CERT_VRFY
function TLS_ST_CW_CHANGE() {
}
// TLS_ST_CW_NEXT_PROTO
function TLS_ST_CW_FINISHED() {
}
