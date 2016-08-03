const Certificates = require('./stub_cert_data.js').Certificates;
exports.createClientHello = createClientHello;
function createClientHello(connection) {
  return {
    ContentType: new Buffer('16', 'hex'),
    ProtocolVersion: new Buffer('0301', 'hex'),
    Length: new Buffer('006d', 'hex'),
    Handshake:
    { HandshakeType: new Buffer('01', 'hex'),
      Length: new Buffer('000069', 'hex'),
      ProtocolVersion: new Buffer('0303', 'hex'),
      Random: new Buffer('52b8baaf7028996cb7352c66a600b0ae3582a66c0214234517a76963cc932eff', 'hex'),
      SessionID: new Buffer(0),
      CipherSuites: [ new Buffer('cca8', 'hex'), Buffer('00ff', 'hex')],
      CompressionMethods: new Buffer('00', 'hex'),
      Extensions: [
        { Type: new Buffer('000b', 'hex'), Data: new Buffer('03000102', 'hex')},
        { Type: new Buffer('000a', 'hex'), Data: new Buffer('00020017', 'hex')},
        { Type: new Buffer('000d', 'hex'), Data: new Buffer('001e060106020603050105020503040104020403030103020303020102020203', 'hex')},
        { Type: new Buffer('0016', 'hex'), Data: new Buffer(0)},
        { Type: new Buffer('0017', 'hex'), Data: new Buffer(0)}
      ]
    }
  };
}

exports.createServerHello = createServerHello;
function createServerHello(connection) {
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

exports.createCertificate = createCertificate;
function createCertificate(connection) {
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

exports.createServerKeyExchange = createServerKeyExchange;
function createServerKeyExchange(connection) {
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

exports.createServerHelloDone = createServerHelloDone;
function createServerHelloDone(connection) {
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
  return { ContentType: new Buffer('16', 'hex'),
           ProtocolVersion: new Buffer('0303', 'hex'),
           Length: new Buffer('0046', 'hex'),
           Handshake:
           { HandshakeType: new Buffer('10', 'hex'),
             Length: new Buffer('000042', 'hex'),
             ECPublic: new Buffer('04af273855f9d93a5827c3aa168598b04d904a02b50ae9d13c05c0332c43ff0d4a9fd96c6c7af8a61e4bb788f8f2f09da693faec42a343449d4b70ed4336208794', 'hex')
           }
         };
}


exports.createClientFinished = createClientFinished;
function createClientFinished(connection) {
  return { ContentType: new Buffer('16', 'hex'),
           ProtocolVersion: new Buffer('0303', 'hex'),
           Length: new Buffer('0010', 'hex'),
           Handshake:
           { HandshakeType: new Buffer('14', 'hex'),
             Length: new Buffer('00000c', 'hex'),
             VerifyData: new Buffer('e6dbb0f3db2ccb11fb86e9f5', 'hex')}
         };
}


exports.createServerFinished = createServerFinished;
function createServerFinished(connection) {
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
