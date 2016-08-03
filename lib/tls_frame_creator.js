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
  var public_key = connection.localEphemeralKey.getPublicKey();
  var public_key_length = new Buffer(1);
  public_key_length.writeUInt8(public_key.length, 0);

  var obj = {
    ContentType: new Buffer('16', 'hex'),
    ProtocolVersion: connection.version,
    Length: null,
    Handshake:
    { HandshakeType: new Buffer('0c', 'hex'),
      Length: null,
      ECCurveType: new Buffer('03', 'hex'),
      ECNamedCurve: new Buffer('0017', 'hex'),
      ECPublic: public_key,
      ECSignatureHashAlgorithm: new Buffer('0401', 'hex'),  // SHA256-RSA
      ECSignature: null
    }
  };

  var ECParameters = Buffer.concat([obj.Handshake.ECCurveType, obj.Handshake.ECNamedCurve]);
  var ECPoint =Buffer.concat([public_key_length, public_key]);
  var ServerECDHParams = Buffer.concat([ECParameters, ECPoint]);
  var signature_hash_algo = obj.Handshake.ECSignatureHashAlgorithm;
  var buf = Buffer.concat([connection.client_random, connection.server_random, ServerECDHParams]);
  console.log('foo0', buf.toString('hex'));
  var sign = crypto.createSign('RSA-SHA256');
  sign.update(buf);
  var signature = Buffer.concat([new Buffer('0100', 'hex'), sign.sign(connection.leafcert_privatekey)]);
  obj.Handshake.ECSignature = signature;
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
  var public_key = connection.localEphemeralKey.getPublicKey();
  var obj = { ContentType: new Buffer('16', 'hex'),
              ProtocolVersion: connection.version,
              Length: null,
              Handshake:
              { HandshakeType: new Buffer('10', 'hex'),
                Length: null,
                ECPublic: public_key
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
                VerifyData: client_verified_data
              }
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
