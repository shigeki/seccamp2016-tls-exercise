const TLS = require('./tls.js').TLS;
const PRF12 = TLS.PRF12;
const crypto = require('crypto');

exports.createHelloRequest = createHelloRequest;
function createHelloRequest(connection) {
  return { ContentType: new Buffer('16', 'hex'),
           ProtocolVersion: connection.version,
           Length: new Buffer('0004', 'hex'),
           Handshake: {
             HandshakeType: new Buffer('00', 'hex'),
             Length: new Buffer('000000', 'hex')
           }
         };
}


exports.createClientHello = createClientHello;
function createClientHello(connection) {
  var obj = {
    ContentType: new Buffer('16', 'hex'),
    ProtocolVersion: connection.version,
    Length: null,
    Handshake:
    { HandshakeType: new Buffer('01', 'hex'),
      Length: null,
      ProtocolVersion: connection.version,
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
}


exports.createServerHello = createServerHello;
function createServerHello(connection) {
  var obj = { ContentType: new Buffer('16', 'hex'),
              ProtocolVersion: connection.version,
              Length: null,
              Handshake:
              { HandshakeType: new Buffer('02', 'hex'),
                Length: null,
                ProtocolVersion: connection.version,
                Random: crypto.randomBytes(32),
                SessionID: new Buffer(0),
                CipherSuite: new Buffer('cca8', 'hex'),
                CompressionMethod: new Buffer('00', 'hex'),
                Extensions: [{ Type: new Buffer('000b', 'hex'), Data: new Buffer('0100', 'hex') }]
              }
            };
  return TLS.Handshake.ServerHello.decode(TLS.Handshake.ServerHello.encode(obj));
}


exports.createCertificate = createCertificate;
function createCertificate(connection) {
  var obj = {
    ContentType: new Buffer('16', 'hex'),
    ProtocolVersion: connection.version,
    Length: null,
    Handshake:
    { HandshakeType: new Buffer('0b', 'hex'),
      Length: null,
      Certificates: connection.certificates
    }
  };
  return TLS.Handshake.Certificate.decode(TLS.Handshake.Certificate.encode(obj));
}


exports.createServerKeyExchange = createServerKeyExchange;
function createServerKeyExchange(connection) {
  var publicKey = connection.localEphemeralKey.getPublicKey();
  var obj = {
    ContentType: new Buffer('16', 'hex'),
    ProtocolVersion: connection.version,
    Length: null,
    Handshake:
    { HandshakeType: new Buffer('0c', 'hex'),
      Length: null,
      ECCurveType: new Buffer('03', 'hex'),
      ECNamedCurve: new Buffer('0017', 'hex'),
      ECPublic: publicKey,
      ECSignatureHashAlgorithm: new Buffer('0401', 'hex'),
      ECSignature: new Buffer('2aa90d54a36e88b047f3729a516a4a5c63fc76740c306112832340c69263434a229fa2904e9c28289e4e144b0ead1c271d2626c061298c69e8d8b0afdd7601206f3316fef7e620e273cf61a2196e56c842bc3901237d1fad89ec376df4acb28c69bfb5a9fad46bd6a90b6f5f5f80d35fab2fc72d26c75053b56a6efac7a56c82c73c3d8e4d7acc5178aef643156a8e789f6980d116853b7f06d5c0871fdfdb7f0b4340cb3bc7ad0fe7cd62f41edce90f96736f98f9f2624bd539c7db4f5b8c1e4614b9a23c4d3272919fbea5f83b8b11fced70ea50408e0256c62a4ff44eb1c725b32f1628670ad6a79970c4cacdd5a3276444d0565233d674b54863cca12d08', 'hex')
    }
  };
  return TLS.Handshake.ServerKeyExchange.decode(TLS.Handshake.ServerKeyExchange.encode(obj));
}


exports.createServerHelloDone = createServerHelloDone;
function createServerHelloDone(connection) {
  var obj = {
    ContentType: new Buffer('16', 'hex'),
    ProtocolVersion: connection.version,
    Length: null,
    Handshake: {
      HandshakeType: new Buffer('0e', 'hex'),
      Length: null
    }
  };
  return TLS.Handshake.ServerHelloDone.decode(TLS.Handshake.ServerHelloDone.encode(obj));
}

exports.createChangeCipherSpec = createChangeCipherSpec;
function createChangeCipherSpec(connection) {
  return {
    ContentType: new Buffer('14', 'hex'),
    ProtocolVersion: new Buffer('0303', 'hex'),
    Length: new Buffer('0001', 'hex'),
    ChangeCipherSpecMessage: new Buffer('01', 'hex')
  };
}


exports.createClientKeyExchange = createClientKeyExchange;
function createClientKeyExchange(connection) {
  var publicKey = connection.localEphemeralKey.getPublicKey();
  var obj = { ContentType: new Buffer('16', 'hex'),
              ProtocolVersion: connection.version,
              Length: null,
              Handshake:
              { HandshakeType: new Buffer('10', 'hex'),
                Length: null,
                ECPublic: publicKey
              }
            };
  return TLS.Handshake.ClientKeyExchange.decode(TLS.Handshake.ClientKeyExchange.encode(obj));
}


exports.createClientFinished = createClientFinished;
function createClientFinished(connection) {
  var shasum = crypto.createHash('sha256');
  shasum.update(Buffer.concat(connection.handshake_list));
  var handshake_hash = shasum.digest();
  var client_verified_data = PRF12(connection.master_secret, "client finished", handshake_hash, 12);
  var obj = { ContentType: new Buffer('16', 'hex'),
              ProtocolVersion: connection.version,
              Length: null,
              Handshake:
              { HandshakeType: new Buffer('14', 'hex'),
                Length: null,
                VerifyData: new Buffer('e6dbb0f3db2ccb11fb86e9f5', 'hex')}
            };
  return TLS.Handshake.UnencryptedFinished.decode(TLS.Handshake.UnencryptedFinished.encode(obj));
};

exports.createServerFinished = createServerFinished;
function createServerFinished(connection) {
  var shasum = crypto.createHash('sha256');
  shasum.update(Buffer.concat(connection.handshake_list));
  var handshake_hash = shasum.digest();
  var server_verified_data = PRF12(connection.master_secret, "server finished", handshake_hash, 12);
  var obj = {
    ContentType: new Buffer('16', 'hex'),
    ProtocolVersion: connection.version,
    Length: null,
    Handshake:
    {
      HandshakeType: new Buffer('14', 'hex'),
      Length: null,
      VerifyData: server_verified_data
    }
  };
  return TLS.Handshake.UnencryptedFinished.decode(TLS.Handshake.UnencryptedFinished.encode(obj));
};
