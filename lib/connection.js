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
function Connection(is_server) {
  this.certificates = null;
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

Connection.prototype.setCertificates = function(certificates) {
  this.certificates = certificates;
};

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
        { Type: new Buffer('000d', 'hex'), Data: new Buffer('00020401', 'hex')}  // signature_algorithms(000d), SHA256(04), RSA(01)
      ]
    }
  };
  return TLS.Handshake.ClientHello.decode(TLS.Handshake.ClientHello.encode(obj));
};
Connection.prototype.createServerHello = function() {
  var obj = { ContentType: new Buffer('16', 'hex'),
              ProtocolVersion: new Buffer('0303', 'hex'),
              Length: null,
              Handshake:
              { HandshakeType: new Buffer('02', 'hex'),
                Length: null,
                ProtocolVersion: new Buffer('0303', 'hex'),
                Random: crypto.randomBytes(32),
                SessionID: new Buffer(0),
                CipherSuite: new Buffer('cca8', 'hex'),
                CompressionMethod: new Buffer('00', 'hex'),
                Extensions: [{ Type: new Buffer('000b', 'hex'), Data: new Buffer('0100', 'hex') }]
              }
            };
  return TLS.Handshake.ServerHello.decode(TLS.Handshake.ServerHello.encode(obj));
};
Connection.prototype.createCertificate = function(Certificates) {
  var obj = {
    ContentType: new Buffer('16', 'hex'),
    ProtocolVersion: new Buffer('0303', 'hex'),
    Length: null,
    Handshake:
    { HandshakeType: new Buffer('0b', 'hex'),
      Length: null,
      Certificates: this.certificates
    }
  };
  return TLS.Handshake.Certificate.decode(TLS.Handshake.Certificate.encode(obj));
};
Connection.prototype.createServerKeyExchange = function() {
  var obj = {
    ContentType: new Buffer('16', 'hex'),
    ProtocolVersion: new Buffer('0303', 'hex'),
    Length: null,
    Handshake:
    { HandshakeType: new Buffer('0c', 'hex'),
      Length: null,
      ECCurveType: new Buffer('03', 'hex'),
      ECNamedCurve: new Buffer('0017', 'hex'),
      ECPublic: new Buffer('049bd0753c790905e58b679dc20178a8a6f7e15bc9cb47ec55ade59d33874e49f89ffb24ba3663ec66346ada47438e8ab7d5275676cd326d8c885c20736a76e8fd', 'hex'),
      ECSignatureHashAlgorithm: new Buffer('0401', 'hex'),
      ECSignature: new Buffer('2aa90d54a36e88b047f3729a516a4a5c63fc76740c306112832340c69263434a229fa2904e9c28289e4e144b0ead1c271d2626c061298c69e8d8b0afdd7601206f3316fef7e620e273cf61a2196e56c842bc3901237d1fad89ec376df4acb28c69bfb5a9fad46bd6a90b6f5f5f80d35fab2fc72d26c75053b56a6efac7a56c82c73c3d8e4d7acc5178aef643156a8e789f6980d116853b7f06d5c0871fdfdb7f0b4340cb3bc7ad0fe7cd62f41edce90f96736f98f9f2624bd539c7db4f5b8c1e4614b9a23c4d3272919fbea5f83b8b11fced70ea50408e0256c62a4ff44eb1c725b32f1628670ad6a79970c4cacdd5a3276444d0565233d674b54863cca12d08', 'hex')
    }
  };
  return TLS.Handshake.ServerKeyExchange.decode(TLS.Handshake.ServerKeyExchange.encode(obj));
};
Connection.prototype.createServerHelloDone = function() {
  var obj = {
    ContentType: new Buffer('16', 'hex'),
    ProtocolVersion: new Buffer('0303', 'hex'),
    Length: null,
    Handshake: {
      HandshakeType: new Buffer('0e', 'hex'),
      Length: null
    }
  };
  return TLS.Handshake.ServerHelloDone.decode(TLS.Handshake.ServerHelloDone.encode(obj));
};
Connection.prototype.createClientKeyExchange = function() {
  var obj = { ContentType: new Buffer('16', 'hex'),
              ProtocolVersion: new Buffer('0303', 'hex'),
              Length: null,
              Handshake:
              { HandshakeType: new Buffer('10', 'hex'),
                Length: null,
                ECPublic: new Buffer('04af273855f9d93a5827c3aa168598b04d904a02b50ae9d13c05c0332c43ff0d4a9fd96c6c7af8a61e4bb788f8f2f09da693faec42a343449d4b70ed4336208794', 'hex')
              }
            };
  return TLS.Handshake.ClientKeyExchange.decode(TLS.Handshake.ClientKeyExchange.encode(obj));

};

Connection.prototype.createClientFinished = function() {
  var obj = { ContentType: new Buffer('16', 'hex'),
              ProtocolVersion: new Buffer('0303', 'hex'),
              Length: null,
              Handshake:
              { HandshakeType: new Buffer('14', 'hex'),
                Length: null,
                VerifyData: new Buffer('e6dbb0f3db2ccb11fb86e9f5', 'hex')}
            };
  return TLS.Handshake.UnencryptedFinished.decode(TLS.Handshake.UnencryptedFinished.encode(obj));
};

Connection.prototype.createServerFinished = function() {
  var obj = {
    ContentType: new Buffer('16', 'hex'),
    ProtocolVersion: new Buffer('0303', 'hex'),
    Length: null,
    Handshake:
    {
      HandshakeType: new Buffer('14', 'hex'),
      Length: null,
      VerifyData: new Buffer('c168baf6af5b865b12e8e810', 'hex')
    }
  };
  return TLS.Handshake.UnencryptedFinished.decode(TLS.Handshake.UnencryptedFinished.encode(obj));
};
