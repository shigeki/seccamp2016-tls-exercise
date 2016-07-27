const assert = require('assert');
const TLS = require('./tls.js').TLS;
const common = require('./common.js');
const ContentType = common.ContentType;
const RevContentType = common.RevContentType;
const HandshakeType = common.HandshakeType;
const RevHandshakeType = common.RevHandshakeType;
const Certificates = require('./cert_data.js').Certificates;

// Server State Transition
//
// TLS_ST_BEFORE
//     | read()
// TLS_ST_SR_CLNT_HELLO
//     | write()
// TLS_ST_SW_SRVR_HELLO
//     | write()
// TLS_ST_SW_CERT
//     | write()
// TLS_ST_SW_KEY_EXCH
//     | write()
// TLS_ST_SW_SRVR_DONE
//     | write()
// TLS_ST_SR_KEY_EXH
//     | read()
// TLS_ST_SR_CHANGE
//     | read()
// TLS_ST_SR_FINISHED
//     | read()
// TLS_ST_SW_CHANGE
//     | write()
// TLS_ST_SW_FINISHED
//     | write()
// TLS_ST_OK
//
function createServerHello() {
  return { ContentType: new Buffer('16', 'hex'),
           ProtocolVersion: new Buffer('0303', 'hex'),
           Length: new Buffer('0032', 'hex'),
           Handshake:
           { HandshakeType: new Buffer('02', 'hex'),
             Length: new Buffer('00002e', 'hex'),
             ProtocolVersion: new Buffer('0303', 'hex'),
             Random: new Buffer('72726da6005ccfd4519cffe5ef9432432e9290fa59b2cb01a078ee7ad6329072', 'hex'),
             SessionID: new Buffer(0),
             CipherSuite: new Buffer('cca8', 'hex'),
             CompressionMethod: new Buffer('00', 'hex'),
             Extensions: [{ Type: new Buffer('000b', 'hex'), Data: new Buffer('0100', 'hex') }]
           }
         };
}

function createCertificate() {
  return {
    ContentType: new Buffer('16', 'hex'),
    ProtocolVersion: new Buffer('0303', 'hex'),
    Length: new Buffer('09ee', 'hex'),
    Handshake:
    { HandshakeType: new Buffer('0b', 'hex'),
      Length: new Buffer('0009ea', 'hex'),
      Certificates: Certificates
    }
  };
}

function createServerKeyExchange() {
  return {
    ContentType: new Buffer('16', 'hex'),
    ProtocolVersion: new Buffer('0303', 'hex'),
    Length: new Buffer('014d', 'hex'),
    Handshake:
    { HandshakeType: new Buffer('0c', 'hex'),
      Length: new Buffer('000149', 'hex'),
      ECCurveType: new Buffer('03', 'hex'),
      ECNamedCurve: new Buffer('0017', 'hex'),
      ECPublic: new Buffer('049bd0753c790905e58b679dc20178a8a6f7e15bc9cb47ec55ade59d33874e49f89ffb24ba3663ec66346ada47438e8ab7d5275676cd326d8c885c20736a76e8fd', 'hex'),
      ECSignatureHashAlgorithm: new Buffer('0401', 'hex'),
      ECSignature: new Buffer('2aa90d54a36e88b047f3729a516a4a5c63fc76740c306112832340c69263434a229fa2904e9c28289e4e144b0ead1c271d2626c061298c69e8d8b0afdd7601206f3316fef7e620e273cf61a2196e56c842bc3901237d1fad89ec376df4acb28c69bfb5a9fad46bd6a90b6f5f5f80d35fab2fc72d26c75053b56a6efac7a56c82c73c3d8e4d7acc5178aef643156a8e789f6980d116853b7f06d5c0871fdfdb7f0b4340cb3bc7ad0fe7cd62f41edce90f96736f98f9f2624bd539c7db4f5b8c1e4614b9a23c4d3272919fbea5f83b8b11fced70ea50408e0256c62a4ff44eb1c725b32f1628670ad6a79970c4cacdd5a3276444d0565233d674b54863cca12d08', 'hex')
    }
  };
}

function createServerHelloDone() {
  return {
    ContentType: new Buffer('16', 'hex'),
    ProtocolVersion: new Buffer('0303', 'hex'),
    Length: new Buffer('0004', 'hex'),
    Handshake: {
      HandshakeType: new Buffer('0e', 'hex'),
      Length: new Buffer('000000', 'hex')
    }
  };
}

function createChangeCipherSpec() {
  return {
    ContentType: new Buffer('14', 'hex'),
    ProtocolVersion: new Buffer('0303', 'hex'),
    Length: new Buffer('0001', 'hex'),
    ChangeCipherSpecMessage: new Buffer('01', 'hex')
  };
}

function createServerFinished() {
  return {
    ContentType: new Buffer('16', 'hex'),
    ProtocolVersion: new Buffer('0303', 'hex'),
    Length: new Buffer('0010', 'hex'),
    Handshake:
    {
      HandshakeType: new Buffer('14', 'hex'),
      Length: new Buffer('00000c', 'hex'),
      VerifyData: new Buffer('c168baf6af5b865b12e8e810', 'hex')
    }
  };
}

function checkHandshakeBuf(buf) {
  assert(Buffer.isBuffer(buf), buf + 'is not Buffer');
  assert(buf.length >= 9, 'buf length is too short');
  assert(buf[0] === ContentType.Handshake, buf + 'is not Handshake');
  var handshake_type = RevHandshakeType[buf[5]];
  assert(handshake_type !== undefined, 'unknown handshake type of ' + handshake_type);
  return handshake_type;
}

exports.TLS_ST_BEFORE = TLS_ST_BEFORE;
function TLS_ST_BEFORE(connection, is_server) {
  this.is_server = is_server;
  this.connection = connection;
  this.connection._handshake_list = [];
}

TLS_ST_BEFORE.prototype.read = function(buf) {
  var handshake_type = checkHandshakeBuf(buf);
  if (!this.is_server && handshake_type === 'HelloRequest') {
    throw new Error('Need to be implemented');
    return true;
  }
  if (this.is_server && handshake_type === 'ClientHello') {
    this.connection._handshake_list.push(buf.slice(5));
    this.connection.state = new TLS_ST_SR_CLNT_HELLO(this.connection);
    this.connection.state.write(buf);
    return true;
  }
  var error = new Error('Not Allowed to Receive ' + handshake_type);
  cb(error);
  return false;
};

TLS_ST_BEFORE.prototype.write = function(buf) {
  throw new Error('Need to be Impemented');
};

// Server State
function TLS_ST_SW_HELLO_REQ() {
}

function TLS_ST_SR_CLNT_HELLO(connection) {
  this.connection = connection;
}
TLS_ST_SR_CLNT_HELLO.prototype.read = function(buf) {
};
TLS_ST_SR_CLNT_HELLO.prototype.write = function(buf) {
  var handshake_type = checkHandshakeBuf(buf);
  if (handshake_type === 'ClientHello') {
    var obj = createServerHello();
    var server_hello = TLS.Handshake.ServerHello.encode(obj);
    this.connection.state = new TLS_ST_SW_SRVR_HELLO(this.connection);
    this.connection._handshake_list.push(server_hello.slice(5));
    this.connection.emit('frame', server_hello, 'ServerHello');
    this.connection.state.write(server_hello);
    return true;
  }
  return false;
};

function TLS_ST_SW_SRVR_HELLO(connection) {
  this.connection = connection;
}
TLS_ST_SW_SRVR_HELLO.prototype.read = function(buf) {
};
TLS_ST_SW_SRVR_HELLO.prototype.write = function(buf) {
  var handshake_type = checkHandshakeBuf(buf);
  if (handshake_type === 'ServerHello') {
    this.connection.state = new TLS_ST_SW_CERT(this.connection);
    var obj = createCertificate();
    var certificate = TLS.Handshake.Certificate.encode(obj);
    this.connection._handshake_list.push(certificate.slice(5));
    this.connection.emit('frame', certificate, 'Certificate');
    this.connection.state.write(certificate);
    return true;
  }
  return false;
};

function TLS_ST_SW_CERT(connection) {
  this.connection = connection;
}
TLS_ST_SW_CERT.prototype.read = function(buf) {
};
TLS_ST_SW_CERT.prototype.write = function(buf) {
  var handshake_type = checkHandshakeBuf(buf);
  if (handshake_type === 'Certificate') {
    this.connection.state = new TLS_ST_SW_KEY_EXCH(this.connection);
    var obj = createServerKeyExchange();
    var server_key_exchange = TLS.Handshake.ServerKeyExchange.encode(obj);
    this.connection._handshake_list.push(server_key_exchange.slice(5));
    this.connection.emit('frame', server_key_exchange, 'ServerKeyExchange');
    this.connection.state.write(server_key_exchange);
    return true;
  }
  return false;
};

function TLS_ST_SW_KEY_EXCH(connection) {
  this.connection = connection;
}
TLS_ST_SW_KEY_EXCH.prototype.read = function(buf) {
};
TLS_ST_SW_KEY_EXCH.prototype.write = function(buf) {
  var handshake_type = checkHandshakeBuf(buf);
  if (handshake_type === 'ServerKeyExchange') {
    this.connection.state = new TLS_ST_SW_SRVR_DONE(this.connection);
    var obj = createServerHelloDone();
    var server_hello_done = TLS.Handshake.ServerHelloDone.encode(obj);
    this.connection._handshake_list.push(server_hello_done.slice(5));
    this.connection.emit('frame', server_hello_done, 'ServerHelloDone');
    this.connection.state.write(server_hello_done);
    return true;
  }
  return false;
};

// TLS_ST_SW_CERT_REQ

function TLS_ST_SW_SRVR_DONE(connection) {
  this.connection = connection;
}
TLS_ST_SW_SRVR_DONE.prototype.read = function(buf) {
  var handshake_type = checkHandshakeBuf(buf);
  if (handshake_type === 'ClientKeyExchange') {
    this.connection._handshake_list.push(buf.slice(5));
    this.connection.state = new TLS_ST_SR_KEY_EXCH(this.connection);
    this.connection.state.write(buf);
    return true;
  }
  return false;
};
TLS_ST_SW_SRVR_DONE.prototype.write = function(buf) {
  var handshake_type = checkHandshakeBuf(buf);
  if (handshake_type === 'ServerHelloDone') {
    return true;
  }
  return false;
};

// TLS_ST_SR_CERT

function TLS_ST_SR_KEY_EXCH(connection) {
  this.connection = connection;
}
TLS_ST_SR_KEY_EXCH.prototype.read = function(buf) {
};
TLS_ST_SR_KEY_EXCH.prototype.write = function(buf, cb) {
  var handshake_type = checkHandshakeBuf(buf);
  if (handshake_type === 'ClientKeyExchange') {
    var obj = createChangeCipherSpec();
    var change_cipher_spec = TLS.ChangeCipherSpec.encode(obj);
    this.connection.state = new TLS_ST_SR_CHANGE(this.connection);
    this.connection.state.write(change_cipher_spec);
    return true;
  }
  return false;
};


// TLS_ST_SR_CERT_VRFY
// TLS_ST_SR_NEXT_PROTO

function TLS_ST_SR_CHANGE(connection) {
  this.connection = connection;
}
TLS_ST_SR_CHANGE.prototype.read = function(buf) {
};
TLS_ST_SR_CHANGE.prototype.write = function(buf) {
  var content_type = RevContentType[buf[0]];
  if (content_type === 'ChangeCipherSpec') {
    this.connection.encrypt = true;
    return true;
  }
  return false;
};

function TLS_ST_SR_FINISHED(connection) {
  this.connection = connection;
}
TLS_ST_SR_FINISHED.prototype.read = function(buf, cb) {
};
TLS_ST_SR_FINISHED.prototype.write = function(buf, cb) {
};

// TLS_ST_SW_SESSION_TICKET
// TLS_ST_SW_CERT_STATUS

function TLS_ST_SW_CHANGE(connection) {
  this.connection = connection;
}
TLS_ST_SW_CHANGE.prototype.read = function(buf, cb) {
};
TLS_ST_SW_CHANGE.prototype.write = function(buf, cb) {
};

function TLS_ST_SW_FINISHED(connection) {
  this.connection = connection;
}
TLS_ST_SW_FINISHED.prototype.read = function(buf, cb) {
};
TLS_ST_SW_FINISHED.prototype.write = function(buf, cb) {
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
