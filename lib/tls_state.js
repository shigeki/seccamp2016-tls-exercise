const crypto = require('crypto');
const util = require('util');
const assert = require('assert');
const rfc5280 = require('asn1.js-rfc5280');
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
  assert(content_type !== undefined, 'unknown content_type of ' + buf.toString('hex'));
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
  this.connection.emit('error', new Error('Not Allowed to Receive ' + buf.toString('hex')) + ' in ' + this.constructor.name);
};
TLS_STATE.prototype.write = function(buf, cb) {
  this.connection.emit('error', new Error('Not Allowed to Write ' + buf.toString('hex')) + ' in ' + this.constructor.name);
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
  if (cb) cb(null, this.connection);
};
TLS_ST_OK.prototype.write = function(buf, cb) {
  var content_type = checkContentTypeBuf(buf);

  if (content_type === 'ApplicationData') {
    this.connection.emit('rawFrame', buf, 'ApplicationData');
  }
  if (cb) cb(null, this.connection);
};

exports.TLS_ST_BEFORE = TLS_ST_BEFORE;
function TLS_ST_BEFORE(connection) {
  TLS_STATE.call(this, connection);
}
util.inherits(TLS_ST_BEFORE, TLS_STATE);

TLS_ST_BEFORE.prototype.read = function(buf, cb) {
  var handshake_type = checkHandshakeBuf(buf);
  if (!this.connection.is_server && handshake_type === 'HelloRequest') {
    // HelloRequest is not included in Handshake Hash
    var obj = this.connection.frame_creator.createClientHello(this.connection);
    this.connection.client_random = obj.Handshake.Random;
    var client_hello = TLS.Handshake.ClientHello.encode(obj);
    this.connection.addHandshakeBuf(client_hello.slice(5));
    this.connection.setState(new TLS_ST_CW_CLNT_HELLO(this.connection));
    this.connection.emit('rawFrame', client_hello, 'ClientHello');
    if (cb) cb(null, this.connection);
    return true;
  }
  if (this.connection.is_server && handshake_type === 'ClientHello') {
    this.connection.addHandshakeBuf(buf.slice(5));
    var obj = TLS.Handshake.ClientHello.decode(buf);
    this.connection.client_random = obj.Handshake.Random;
    this.connection.setState(new TLS_ST_SR_CLNT_HELLO(this.connection));
    this.connection.write(buf, cb);
    return true;
  }
  this.connection.emit('error', new Error('Not Allowed to Read ' + buf.toString('hex') + ' on ' + this.constructor.name));
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
    var obj = this.connection.frame_creator.createServerHello(this.connection);
    this.connection.localEphemeralKey = crypto.createECDH('prime256v1');;
    this.connection.localEphemeralKey.generateKeys();
    this.connection.server_random = obj.Handshake.Random;
    var server_hello = TLS.Handshake.ServerHello.encode(obj);
    this.connection.setState(new TLS_ST_SW_SRVR_HELLO(this.connection));
    this.connection.addHandshakeBuf(server_hello.slice(5));
    this.connection.emit('rawFrame', server_hello, 'ServerHello');
    this.connection.write(server_hello, cb);
    return true;
  }
  this.connection.emit('error', new Error('Not Allowed to Write ' + buf.toString('hex') + ' on ' + this.constructor.name));
  return false;
};

function TLS_ST_SW_SRVR_HELLO(connection) {
  TLS_STATE.call(this, connection);
  this.connection.localEphemeralKey = crypto.createECDH('prime256v1');;
  this.connection.localEphemeralKey.generateKeys();
}
util.inherits(TLS_ST_SW_SRVR_HELLO, TLS_STATE);

TLS_ST_SW_SRVR_HELLO.prototype.write = function(buf, cb) {
  var handshake_type = checkHandshakeBuf(buf);
  if (handshake_type === 'ServerHello') {
    this.connection.setState(new TLS_ST_SW_CERT(this.connection));
    var obj = this.connection.frame_creator.createCertificate(this.connection);
    var certificate = TLS.Handshake.Certificate.encode(obj);
    this.connection.addHandshakeBuf(certificate.slice(5));
    this.connection.emit('rawFrame', certificate, 'Certificate');
    this.connection.write(certificate, cb);
    return true;
  }
  this.connection.emit('error', new Error('Not Allowed to Write ' + buf.toString('hex') + ' on ' + this.constructor.name));
  return false;
};

function TLS_ST_SW_CERT(connection) {
  TLS_STATE.call(this, connection);
}
util.inherits(TLS_ST_SW_CERT, TLS_STATE);

TLS_ST_SW_CERT.prototype.write = function(buf, cb) {
  var handshake_type = checkHandshakeBuf(buf);
  if (handshake_type === 'Certificate') {
    this.connection.setState(new TLS_ST_SW_KEY_EXCH(this.connection));
    var obj = this.connection.frame_creator.createServerKeyExchange(this.connection);
    var server_key_exchange = TLS.Handshake.ServerKeyExchange.encode(obj);
    this.connection.addHandshakeBuf(server_key_exchange.slice(5));
    this.connection.emit('rawFrame', server_key_exchange, 'ServerKeyExchange');
    this.connection.write(server_key_exchange, cb);
    return true;
  }
  this.connection.emit('error', new Error('Not Allowed to Write ' + buf.toString('hex') + ' on ' + this.constructor.name));
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
    var obj = this.connection.frame_creator.createServerHelloDone(this.connection);
    var server_hello_done = TLS.Handshake.ServerHelloDone.encode(obj);
    this.connection.addHandshakeBuf(server_hello_done.slice(5));
    this.connection.emit('rawFrame', server_hello_done, 'ServerHelloDone');
    this.connection.setState(new TLS_ST_SW_SRVR_DONE(this.connection));
    // no more read and write
    if (cb) cb(null, this.connection);
    return true;
  }
  this.connection.emit('error', new Error('Not Allowed to Write ' + buf.toString('hex') + ' on ' + this.constructor.name));
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
    var obj = TLS.Handshake.ClientKeyExchange.decode(buf);
    this.connection.peerPublicKey = obj.Handshake.ECPublic;
    this.connection.setState(new TLS_ST_SR_KEY_EXCH(this.connection));
    // no more read and write
    if (cb) cb(null, this.connection);
    return true;
  }
  this.connection.emit('error', new Error('Not Allowed to Read ' + buf.toString('hex') + ' on ' + this.constructor.name));
  return false;
};

// TLS_ST_SR_CERT

function TLS_ST_SR_KEY_EXCH(connection) {
  TLS_STATE.call(this, connection);
}
util.inherits(TLS_ST_SR_KEY_EXCH, TLS_STATE);
TLS_ST_SR_KEY_EXCH.prototype.read = function(buf, cb) {
  var content_type = checkContentTypeBuf(buf);
  if (content_type === 'ChangeCipherSpec') {
    this.connection.setState(new TLS_ST_SR_CHANGE(this.connection));
    this.connection.enableEncryptRead();
    // no more read and write
    if (cb) cb(null, this.connection);
    return true;
  }
  this.connection.emit('error', new Error('Not Allowed to Read ' + buf.toString('hex') + ' on ' + this.constructor.name));
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
    var shasum = crypto.createHash('sha256');
    shasum.update(Buffer.concat(this.connection.handshake_list));
    var handshake_hash = shasum.digest();
    var client_verified_data = TLS.PRF12(this.connection.master_secret, "client finished", handshake_hash, 12);
    assert(client_verified_data.equals(buf.slice(-12)), 'VerifiedData Mismatch in ClientFinished');
    this.connection.addHandshakeBuf(buf.slice(5));
    this.connection.setState(new TLS_ST_SR_FINISHED(this.connection));
    this.connection.write(null, cb);
    return true;
  }
  this.connection.emit('error', new Error('Not Allowed to Read ' + buf.toString('hex') + ' on ' + this.constructor.name));
  return false;
};

function TLS_ST_SR_FINISHED(connection) {
  TLS_STATE.call(this, connection);
}
util.inherits(TLS_ST_SR_FINISHED, TLS_STATE);

TLS_ST_SR_FINISHED.prototype.write = function(buf, cb) {
  this.connection.setState(new TLS_ST_SW_SRVR_DONE(this.connection));
  var obj = this.connection.frame_creator.createChangeCipherSpec(this.connection);
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
    var obj = this.connection.frame_creator.createServerFinished(this.connection);
    var server_finished = TLS.Handshake.UnencryptedFinished.encode(obj);
    this.connection.addHandshakeBuf(server_finished.slice(5));
    this.connection.emit('rawFrame', server_finished, 'ServerFinished');
    this.connection.setState(new TLS_ST_SW_FINISHED(this.connection));
    this.connection.write(server_finished, cb);
    return true;
  }
  this.connection.emit('error', new Error('Not Allowed to Write ' + buf.toString('hex') + ' on ' + this.constructor.name));
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
    if (cb) cb(null, this.connection);
    return true;
  }
  this.connection.emit('error', new Error('Not Allowed to Write ' + buf.toString('hex') + ' on ' + this.constructor.name));
  return false;
};

// Client State Transition
// TLS_ST_BEFORE
//     | write(client_hello)
// TLS_ST_CW_CLNT_HELLO
//     | read(server_hello)
// TLS_ST_CR_SRVR_HELLO
//     | read(certificate)
// TLS_ST_CR_CERT
//     | read(server_key_exchange)
// TLS_ST_CR_KEY_EXCH
//     | read(server_hello_done)
// TLS_ST_CR_SRVR_DONE
//     | write(client_key_exchange)
// TLS_ST_CW_KEY_EXH
//     | write(change_cipher_spec)
// TLS_ST_CW_CHANGE
//     | write(client_finished)
// TLS_ST_CW_FINISHED
//     | read(change_cipher_spec)
// TLS_ST_CR_CHANGE
//     | read(server_finished)
// TLS_ST_CR_FINISHED
//     |
// TLS_ST_OK

function TLS_ST_CW_CLNT_HELLO(connection) {
  TLS_STATE.call(this, connection);
}
util.inherits(TLS_ST_CW_CLNT_HELLO, TLS_STATE);
TLS_ST_CW_CLNT_HELLO.prototype.read = function(buf, cb) {
  var handshake_type = checkHandshakeBuf(buf);
  if (handshake_type === 'ServerHello') {
    this.connection.addHandshakeBuf(buf.slice(5));
    var obj = TLS.Handshake.ServerHello.decode(buf);
    this.connection.server_random = obj.Handshake.Random;
    this.connection.setState(new TLS_ST_CR_SRVR_HELLO(this.connection));
    // no more read and write
    if (cb) cb(null, this.connection);
    return true;
  }
  this.connection.emit('error', new Error('Not Allowed to Read ' + buf.toString('hex') + ' on ' + this.constructor.name));
  return false;
};

function TLS_ST_CR_SRVR_HELLO(connection) {
    TLS_STATE.call(this, connection);
}
util.inherits(TLS_ST_CR_SRVR_HELLO, TLS_STATE);
TLS_ST_CR_SRVR_HELLO.prototype.read = function(buf, cb) {
  var handshake_type = checkHandshakeBuf(buf);
  if (handshake_type === 'Certificate') {
    this.connection.addHandshakeBuf(buf.slice(5));
    var obj = TLS.Handshake.Certificate.decode(buf);
    this.connection.certificates = obj.Handshake.Certificates;
    try {
      var res = rfc5280.Certificate.decode(this.connection.certificates[0], 'der');
    } catch(e) {
      throw new Error('Certificate parse Error:', cert);
    }
    var server_cert = res.tbsCertificate;
    var SubjectPublicKeyInfo = rfc5280.SubjectPublicKeyInfo;
    var spk = SubjectPublicKeyInfo.encode(server_cert.subjectPublicKeyInfo, 'der');
    this.connection.leafcert_publickey = common.toPEM(spk, 'public_key');
    this.connection.setState(new TLS_ST_CR_CERT(this.connection));
    // no more read and write
    if (cb) cb(null, this.connection);
    return true;
  }
  this.connection.emit('error', new Error('Not Allowed to Read ' + buf.toString('hex') + ' on ' + this.constructor.name));
  return false;
};

function TLS_ST_CR_CERT(connection) {
  TLS_STATE.call(this, connection);
}
util.inherits(TLS_ST_CR_CERT, TLS_STATE);
TLS_ST_CR_CERT.prototype.read = function(buf, cb) {
  var handshake_type = checkHandshakeBuf(buf);
  if (handshake_type === 'ServerKeyExchange') {
    this.connection.addHandshakeBuf(buf.slice(5));
    var obj = TLS.Handshake.ServerKeyExchange.decode(buf);
    var verify = crypto.createVerify('RSA-SHA256');
    var ECParameters = Buffer.concat([obj.Handshake.ECCurveType, obj.Handshake.ECNamedCurve]);
    var public_key_length = new Buffer(1);
    public_key_length.writeUInt8(obj.Handshake.ECPublic.length, 0);
    var ECPoint =Buffer.concat([public_key_length, obj.Handshake.ECPublic]);
    var ServerECDHParams = Buffer.concat([ECParameters, ECPoint]);
    var buf1 = Buffer.concat([this.connection.client_random, this.connection.server_random, ServerECDHParams]);
    verify.update(buf1);
    var server_cert = common.toPEM(this.connection.certificates[0], 'certificate');
    var r = verify.verify(server_cert, obj.Handshake.ECSignature);
    assert(r, 'ECSignature in ServerKeyExchange cannot be verifed.');
    this.connection.peerPublicKey = obj.Handshake.ECPublic;
    this.connection.setState(new TLS_ST_CR_KEY_EXCH(this.connection));
    // no more read and write
    if (cb) cb(null, this.connection);
    return true;
  }
  this.connection.emit('error', new Error('Not Allowed to Read ' + buf.toString('hex') + ' on ' + this.constructor.name));
  return false;
};

function TLS_ST_CR_KEY_EXCH(connection) {
  TLS_STATE.call(this, connection);
  connection.localEphemeralKey = crypto.createECDH('prime256v1');
  connection.localEphemeralKey.generateKeys();
}
util.inherits(TLS_ST_CR_KEY_EXCH, TLS_STATE);
TLS_ST_CR_KEY_EXCH.prototype.read = function(buf, cb) {
  var handshake_type = checkHandshakeBuf(buf);
  if (handshake_type === 'ServerHelloDone') {
    this.connection.addHandshakeBuf(buf.slice(5));
    this.connection.setState(new TLS_ST_CR_SRVR_DONE(this.connection));
    this.connection.write(null, cb);
    return true;
  }
  this.connection.emit('error', new Error('Not Allowed to Read ' + buf.toString('hex') + ' on ' + this.constructor.name));
  return false;
};

function TLS_ST_CR_SRVR_DONE(connection) {
  TLS_STATE.call(this, connection);
}
util.inherits(TLS_ST_CR_SRVR_DONE, TLS_STATE);
TLS_ST_CR_SRVR_DONE.prototype.write = function(buf, cb) {
  var publicKey = this.connection.localEphemeralKey.getPublicKey();
  var obj = this.connection.frame_creator.createClientKeyExchange(this.connection);
  var client_key_exchange = TLS.Handshake.ClientKeyExchange.encode(obj);
  this.connection.addHandshakeBuf(client_key_exchange.slice(5));
  this.connection.setState(new TLS_ST_CW_KEY_EXCH(this.connection));
  this.connection.emit('rawFrame', client_key_exchange, 'ClientKeyExchange');
  this.connection.write(client_key_exchange, cb);
  return true;
};

function TLS_ST_CW_KEY_EXCH(connection) {
  TLS_STATE.call(this, connection);
}
util.inherits(TLS_ST_CW_KEY_EXCH, TLS_STATE);
TLS_ST_CW_KEY_EXCH.prototype.write = function(buf, cb) {
  var handshake_type = checkHandshakeBuf(buf);
  if (handshake_type === 'ClientKeyExchange') {
    var obj = this.connection.frame_creator.createChangeCipherSpec(this.connection);
    var change_cipher_spec = TLS.ChangeCipherSpec.encode(obj);
    this.connection.emit('rawFrame', change_cipher_spec, 'ChangeCipherSpec');
    this.connection.setState(new TLS_ST_CW_CHANGE(this.connection));
    this.connection.write(change_cipher_spec, cb);
    return true;
  }
  this.connection.emit('error', new Error('Not Allowed to Write ' + buf.toString('hex') + ' on ' + this.constructor.name));
  return false;
};


function TLS_ST_CW_CHANGE(connection) {
  TLS_STATE.call(this, connection);
}
util.inherits(TLS_ST_CW_CHANGE, TLS_STATE);
TLS_ST_CW_CHANGE.prototype.write = function(buf, cb) {
  var content_type = checkContentTypeBuf(buf);
  if (content_type === 'ChangeCipherSpec') {
    this.connection.enableEncryptWrite();
    var obj = this.connection.frame_creator.createClientFinished(this.connection);
    var client_finished = TLS.Handshake.UnencryptedFinished.encode(obj);
    this.connection.setState(new TLS_ST_CW_FINISHED(this.connection));
    this.connection.addHandshakeBuf(client_finished.slice(5));
    this.connection.emit('rawFrame', client_finished, 'ClientFinished');
    // no more read and write
    if (cb) cb(null, this.connection);
    return true;
  }
  this.connection.emit('error', new Error('Not Allowed to Write ' + buf.toString('hex') + ' on ' + this.constructor.name));
  return false;
};

function TLS_ST_CW_FINISHED(connection) {
  TLS_STATE.call(this, connection);
}
util.inherits(TLS_ST_CW_FINISHED, TLS_STATE);
TLS_ST_CW_FINISHED.prototype.read = function(buf, cb) {
  var content_type = checkContentTypeBuf(buf);
  if (content_type === 'ChangeCipherSpec') {
    this.connection.enableEncryptRead();
    this.connection.setState(new TLS_ST_CR_CHANGE(this.connection));
    // no more read and write
    if (cb) cb(null, this.connection);
    return true;
  }
  this.connection.emit('error', new Error('Not Allowed to Write ' + buf.toString('hex') + ' on ' + this.constructor.name));
  return false;
};

function TLS_ST_CR_CHANGE(connection) {
  TLS_STATE.call(this, connection);
}
util.inherits(TLS_ST_CR_CHANGE, TLS_STATE);
TLS_ST_CR_CHANGE.prototype.read = function(buf, cb) {
  var handshake_type = checkHandshakeBuf(buf);
  if (handshake_type === 'Finished') {
    var shasum = crypto.createHash('sha256');
    shasum.update(Buffer.concat(this.connection.handshake_list));
    var handshake_hash = shasum.digest();
    var server_verified_data = TLS.PRF12(this.connection.master_secret, "server finished", handshake_hash, 12);
    assert(server_verified_data.equals(buf.slice(-12)), 'VerifiedData Mismatch in ServerFinished');
    this.connection.setState(new TLS_ST_CR_FINISHED(this.connection));
    this.connection.write(null, cb);
    return true;
  }
  this.connection.emit('error', new Error('Not Allowed to Read ' + buf.toString('hex') + ' on ' + this.constructor.name));
  return false;
};

function TLS_ST_CR_FINISHED(connection) {
  TLS_STATE.call(this, connection);
}
util.inherits(TLS_ST_CR_FINISHED, TLS_STATE);
TLS_ST_CR_FINISHED.prototype.write = function(buf, cb) {
  this.connection.setState(new TLS_ST_OK(this.connection));
  if (cb) cb(null, this.connection);
};
