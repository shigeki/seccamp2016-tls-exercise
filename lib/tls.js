const assert = require('assert');
const crypto = require('crypto');
const DataReader = require('./data_reader.js').DataReader;
const DataWriter = require('./data_writer.js').DataWriter;
const common = require('./common.js');
const TLS_CRYPT = require('./tls_crypt.js').TLS_CRYPT;
const TLS_RecordLayer = require('./tls_recordlayer.js');
const RecordLayer = TLS_RecordLayer.RecordLayer;
const RecordLayerLength = TLS_RecordLayer.RecordLayerLength;
const ChaCha20Poly1305 = require('./crypto/chacha20_poly1305.js');
const ChaCha20Poly1305Encrypt = ChaCha20Poly1305.ChaCha20Poly1305Encrypt;
const ChaCha20Poly1305Decrypt = ChaCha20Poly1305.ChaCha20Poly1305Decrypt;
const checkBuffer = common.checkBuffer;
const BufferXOR = common.BufferXOR;
const HandshakeHeaderLength = 4;
const VerifyDataLength = 12;

function makeVectorBuffer(buf, ceil) {
  assert(Buffer.isBuffer(buf));
  assert(typeof ceil === 'number');
  var data_writer = new DataWriter(ceil);
  data_writer.writeVector(buf, buf.length, ceil);
  return data_writer.take();
}

const HandshakeType = {
  HelloRequest: new Buffer('00', 'hex'),
  ClientHello: new Buffer('01', 'hex'),
  ServerHello: new Buffer('02', 'hex'),
  Certificate: new Buffer('0B', 'hex'),
  ServerKeyExchange: new Buffer('0C', 'hex'),
  CertificateRequest: new Buffer('0D', 'hex'),
  ServerHelloDone: new Buffer('0E', 'hex'),
  CertificateVerify: new Buffer('0F', 'hex'),
  ClientKeyExchange: new Buffer('10', 'hex'),
  Finished: new Buffer('14', 'hex')
};

const ContentType = {
  ChangeCipherSpec: new Buffer('14', 'hex'),
  Alert: new Buffer('15', 'hex'),
  Handshake: new Buffer('16', 'hex'),
  ApplicationData: new Buffer('17', 'hex')
};

var ChangeCipherSpec = {
  encode: function() {
    // only TLS1.2
    return new Buffer('140303000101', 'hex');
  },
  decode: function(buf) {
    checkBuffer(buf);
    var record_layer = RecordLayer.decode(buf.slice(0, RecordLayerLength));
    assert(record_layer.ContentType.equals(ContentType.ChangeCipherSpec));
    var length = record_layer.Length.readUInt16BE();
    assert(length === 1);
    var ccs_message = buf.slice(RecordLayerLength, RecordLayerLength + length);
    assert(ccs_message.equals(new Buffer('01', 'hex')));
    return {
      ContentType: record_layer.ContentType,
      ProtocolVersion: record_layer.ProtocolVersion,
      Length: record_layer.Length,
      ChangeCipherSpecMessage: ccs_message,
      remaining_buffer: buf.slice(RecordLayerLength + length)
    };
  }
};

var Alert = {
  // To be implement
  encode: function() {throw new Error('To be implemented');},
  decode: function() {throw new Error('To be implemented');}
};

var HandshakeHeader = {
  decode: function(buf) {
    checkBuffer(buf);
    assert(buf.length >= 4);
    var data_reader = new DataReader(buf);
    return {
      Type: data_reader.readBytes(1),
      Length: data_reader.readBytes(3),
      remaining_buffer: data_reader.peekRemainingPayload()
    };
  },
  encode: function(obj) {
    checkBuffer(obj.Type);
    assert(obj.Type.length === 1);
    checkBuffer(obj.Length);
    assert(obj.Length === 3);
  }
};

var HelloRequest = {
  decode: function(buf) {
    checkBuffer(buf);
    var data_reader = new DataReader(buf);
    const record_layer = RecordLayer.decode(data_reader.readBytes(RecordLayerLength));
    assert(record_layer.ContentType.equals(ContentType.Handshake));
    var length = record_layer.Length.readUInt16BE();
    assert(length === 4);

    var handshake_header = HandshakeHeader.decode(data_reader.readBytes(length));
    assert(handshake_header.Type.equals(HandshakeType.HelloRequest));
    assert(handshake_header.Length.equals(new Buffer('000000', 'hex')));

    return {
      ContentType: record_layer.ContentType,
      ProtocolVersion: record_layer.ProtocolVersion,
      Length: record_layer.Length,
      Handshake: {
        HandshakeType:  handshake_header.Type,
        Length: handshake_header.Length
      },
      remaining_buffer: data_reader.peekRemainingPayload()
    };
  },
  encode: function(obj) {
    // TODO: version tolerance only TLS1.2
    return new Buffer('160303000400000000', 'hex');
  }
};

var ClientHello = {
  decode: function(buf) {
    checkBuffer(buf);
    var data_reader = new DataReader(buf);
    const record_layer = RecordLayer.decode(data_reader.readBytes(RecordLayerLength));
    assert(record_layer.ContentType.equals(ContentType.Handshake));
    var length = record_layer.Length.readUInt16BE();

    var handshake_header = HandshakeHeader.decode(data_reader.readBytes(length));
    assert(handshake_header.Type.equals(HandshakeType.ClientHello));

    var handshake_data_reader = new DataReader(handshake_header.remaining_buffer);
    var protocol_version = handshake_data_reader.readBytes(2);
    var random = handshake_data_reader.readBytes(32);
    var session_id = handshake_data_reader.readVector(0, 32);
    var cipher_suites = handshake_data_reader.readVector(2, (1 << 16) - 2);
    var cipher_suites_list = [];
    for(var i = 0; i < cipher_suites.length; i += 2) {
      cipher_suites_list.push(cipher_suites.slice(i, i+2));
    }
    var compression_methods = handshake_data_reader.readVector(1, (1 << 8) - 1);
    var extension_list = [];
    if (handshake_data_reader.bytesRemaining() > 0) {
      var extensions = handshake_data_reader.readVector(0, (1 << 16) - 1);
      var extensions_data_reader = new DataReader(extensions);
      while(extensions_data_reader.bytesRemaining() > 0) {
        var extension_type = extensions_data_reader.readBytes(2);
        var extension_data = extensions_data_reader.readVector(0, (1 << 16) - 1);
        extension_list.push({
          Type: extension_type,
          Data: extension_data
        });
      }
    }
    return {
      ContentType: record_layer.ContentType,
      ProtocolVersion: record_layer.ProtocolVersion,
      Length: record_layer.Length,
      Handshake: {
        HandshakeType:  handshake_header.Type,
        Length: handshake_header.Length,
        ProtocolVersion: protocol_version,
        Random: random,
        SessionID: session_id,
        CipherSuites: cipher_suites_list,
        CompressionMethods: compression_methods,
        Extensions: extension_list
      },
      remaining_buffer: data_reader.peekRemainingPayload()
    };
  },
  encode: function(obj) {
    var record_layer_content_type = checkBuffer(obj.ContentType);
    var record_layer_protocol_version = checkBuffer(obj.ProtocolVersion);
    var record_layer_length = checkBuffer(obj.Length);
    var handshake = obj.Handshake;
    var handshake_handshake_type = checkBuffer(handshake.HandshakeType);
    var handshake_length = checkBuffer(handshake.Length);
    var handshake_protocol_version = checkBuffer(handshake.ProtocolVersion);
    var handshake_random = checkBuffer(handshake.Random);
    checkBuffer(handshake.SessionID);
    var handshake_session_id = makeVectorBuffer(handshake.SessionID, 32);
    assert(Array.isArray(handshake.CipherSuites));
    var handshake_cipher_suites = makeVectorBuffer(Buffer.concat(handshake.CipherSuites), (1 << 16) - 1);
    checkBuffer(handshake.CompressionMethods);
    var handshake_compression_methods = makeVectorBuffer(handshake.CompressionMethods, (1 << 8) - 1);
    assert(Array.isArray(handshake.Extensions));
    var extension_list = [];
    handshake.Extensions.forEach(function(e) {
      checkBuffer(e.Type);
      checkBuffer(e.Data);
      extension_list.push(e.Type);
      extension_list.push(makeVectorBuffer(e.Data, (1 << 16) - 1));
    });
    var handshake_extensions = makeVectorBuffer(Buffer.concat(extension_list), (1 << 16) - 1);
    var handshake_buf = Buffer.concat([
      handshake_handshake_type,
      handshake_length,
      handshake_protocol_version,
      handshake_random,
      handshake_session_id,
      handshake_cipher_suites,
      handshake_compression_methods,
      handshake_extensions
    ]);
    var record_layer_buf = Buffer.concat([
      record_layer_content_type,
      record_layer_protocol_version,
      record_layer_length
    ]);
    var buf = Buffer.concat([record_layer_buf, handshake_buf]);
    return buf;
  }
};

var  ServerHello = {
  decode: function(buf) {
    checkBuffer(buf);
    var data_reader = new DataReader(buf);
    const record_layer = RecordLayer.decode(data_reader.readBytes(RecordLayerLength));
    assert(record_layer.ContentType.equals(ContentType.Handshake));
    var length = record_layer.Length.readUInt16BE();

    var handshake_header = HandshakeHeader.decode(data_reader.readBytes(length));
    assert(handshake_header.Type.equals(HandshakeType.ServerHello));

    var handshake_data_reader = new DataReader(handshake_header.remaining_buffer);
    var protocol_version = handshake_data_reader.readBytes(2);
    var random = handshake_data_reader.readBytes(32);
    var session_id = handshake_data_reader.readVector(0, 32);
    var cipher_suite = handshake_data_reader.readBytes(2);
    var compression_method = handshake_data_reader.readBytes(1);
    var extension_list = [];
    if (handshake_data_reader.bytesRemaining() > 0) {
      var extensions = handshake_data_reader.readVector(0, (1 << 16) - 1);
      var extensions_data_reader = new DataReader(extensions);
      while(extensions_data_reader.bytesRemaining() > 0) {
        var extension_type = extensions_data_reader.readBytes(2);
        var extension_data = extensions_data_reader.readVector(0, (1 << 16) - 1);
        extension_list.push({
          Type: extension_type,
          Data: extension_data
        });
      }
    }
    return {
      ContentType: record_layer.ContentType,
      ProtocolVersion: record_layer.ProtocolVersion,
      Length: record_layer.Length,
      Handshake: {
        HandshakeType:  handshake_header.Type,
        Length: handshake_header.Length,
        ProtocolVersion: protocol_version,
        Random: random,
        SessionID: session_id,
        CipherSuite: cipher_suite,
        CompressionMethod: compression_method,
        Extensions: extension_list
      },
      remaining_buffer: data_reader.peekRemainingPayload()
    };
  },
  encode: function(obj) {
    var record_layer_content_type = checkBuffer(obj.ContentType);
    var record_layer_protocol_version = checkBuffer(obj.ProtocolVersion);
    var record_layer_length = checkBuffer(obj.Length);
    var handshake = obj.Handshake;
    var handshake_handshake_type = checkBuffer(handshake.HandshakeType);
    var handshake_length = checkBuffer(handshake.Length);
    var handshake_protocol_version = checkBuffer(handshake.ProtocolVersion);
    var handshake_random = checkBuffer(handshake.Random);
    checkBuffer(handshake.SessionID);
    var handshake_session_id = makeVectorBuffer(handshake.SessionID, 32);
    var handshake_cipher_suite = checkBuffer(handshake.CipherSuite);
    var handshake_compression_method = checkBuffer(handshake.CompressionMethod);
    assert(Array.isArray(handshake.Extensions));
    var extension_list = [];
    handshake.Extensions.forEach(function(e) {
      checkBuffer(e.Type);
      checkBuffer(e.Data);
      extension_list.push(e.Type);
      extension_list.push(makeVectorBuffer(e.Data, (1 << 16) - 1));
    });
    var handshake_extensions = makeVectorBuffer(Buffer.concat(extension_list), (1 << 16) - 1);
    var handshake_buf = Buffer.concat([
      handshake_handshake_type,
      handshake_length,
      handshake_protocol_version,
      handshake_random,
      handshake_session_id,
      handshake_cipher_suite,
      handshake_compression_method,
      handshake_extensions
    ]);
    var record_layer_buf = Buffer.concat([
      record_layer_content_type,
      record_layer_protocol_version,
      record_layer_length
    ]);
    var buf = Buffer.concat([record_layer_buf, handshake_buf]);
    return buf;
  }
};

var Certificate = {
  decode: function(buf) {
    checkBuffer(buf);
    var data_reader = new DataReader(buf);
    const record_layer = RecordLayer.decode(data_reader.readBytes(RecordLayerLength));
    assert(record_layer.ContentType.equals(ContentType.Handshake));
    var length = record_layer.Length.readUInt16BE();

    var handshake_header = HandshakeHeader.decode(data_reader.readBytes(length));
    assert(handshake_header.Type.equals(HandshakeType.Certificate));

    var handshake_data_reader = new DataReader(handshake_header.remaining_buffer);
    var certificates = handshake_data_reader.readVector(0, (1 << 24) - 1);
    var certificates_reader = new DataReader(certificates);
    var certificate_list = [];
    while(certificates_reader.bytesRemaining() > 0) {
      var certificate = certificates_reader.readVector(1, (1 << 24) -1);
      certificate_list.push(certificate);
    }
    return {
      ContentType: record_layer.ContentType,
      ProtocolVersion: record_layer.ProtocolVersion,
      Length: record_layer.Length,
      Handshake: {
        HandshakeType:  handshake_header.Type,
        Length: handshake_header.Length,
        Certificates: certificate_list
      }
    };
  },
  encode: function(obj) {
    var record_layer_content_type = checkBuffer(obj.ContentType);
    var record_layer_protocol_version = checkBuffer(obj.ProtocolVersion);
    var record_layer_length = checkBuffer(obj.Length);
    var handshake = obj.Handshake;
    var handshake_handshake_type = checkBuffer(handshake.HandshakeType);
    var handshake_length = checkBuffer(handshake.Length);
    assert(Array.isArray(handshake.Certificates));
    var certificate_list = [];
    handshake.Certificates.forEach(function(e) {
      certificate_list.push(makeVectorBuffer(e, (1 << 24) - 1));
    });
    var handshake_certificates = makeVectorBuffer(Buffer.concat(certificate_list), (1 << 24) - 1);
    var handshake_buf = Buffer.concat([
      handshake_handshake_type,
      handshake_length,
      handshake_certificates
    ]);
    var record_layer_buf = Buffer.concat([
      record_layer_content_type,
      record_layer_protocol_version,
      record_layer_length
    ]);
    var buf = Buffer.concat([record_layer_buf, handshake_buf]);
    return buf;
  }
};

var ServerKeyExchange = {
  // only ecdhe_rsa with named curve is supported
  decode: function(buf) {
    checkBuffer(buf);
    var data_reader = new DataReader(buf);
    const record_layer = RecordLayer.decode(data_reader.readBytes(RecordLayerLength));
    assert(record_layer.ContentType.equals(ContentType.Handshake));
    var length = record_layer.Length.readUInt16BE();

    var handshake_header = HandshakeHeader.decode(data_reader.readBytes(length));
    assert(handshake_header.Type.equals(HandshakeType.ServerKeyExchange));

    var handshake_data_reader = new DataReader(handshake_header.remaining_buffer);

    var ec_curve_type = handshake_data_reader.readBytes(1);
    assert(ec_curve_type[0] === 0x03, 'Only echde_rsa with named curve is supported');

    var ec_named_curve = handshake_data_reader.readBytes(2);
    var ec_public = handshake_data_reader.readVector(1, (1 << 8) - 1);
    var ec_signature_hash_algorithm = handshake_data_reader.readBytes(2);
    var ec_signature = handshake_data_reader.readVector(0, (1 << 16) -1 );
    return {
      ContentType: record_layer.ContentType,
      ProtocolVersion: record_layer.ProtocolVersion,
      Length: record_layer.Length,
      Handshake: {
        HandshakeType:  handshake_header.Type,
        Length: handshake_header.Length,
        ECCurveType: ec_curve_type,
        ECNamedCurve: ec_named_curve,
        ECPublic: ec_public,
        ECSignatureHashAlgorithm: ec_signature_hash_algorithm,
        ECSignature: ec_signature
      }
    };
  },
  encode: function(obj) {
    var record_layer_content_type = checkBuffer(obj.ContentType);
    var record_layer_protocol_version = checkBuffer(obj.ProtocolVersion);
    var record_layer_length = checkBuffer(obj.Length);
    var handshake = obj.Handshake;
    var handshake_handshake_type = checkBuffer(handshake.HandshakeType);
    var handshake_length = checkBuffer(handshake.Length);
    var handshake_ec_curve_type = checkBuffer(handshake.ECCurveType);
    var handshake_ec_named_curve = checkBuffer(handshake.ECNamedCurve);
    checkBuffer(handshake.ECPublic);
    var handshake_ec_public = makeVectorBuffer(handshake.ECPublic, (1 << 8) - 1);
    var handshake_ec_signature_hash_algorithm = checkBuffer(handshake.ECSignatureHashAlgorithm);
    checkBuffer(handshake.ECSignature);
    var handshake_ec_signature = makeVectorBuffer(handshake.ECSignature, (1 << 16) - 1);

    var handshake_buf = Buffer.concat([
      handshake_handshake_type,
      handshake_length,
      handshake_ec_curve_type,
      handshake_ec_named_curve,
      handshake_ec_public,
      handshake_ec_signature_hash_algorithm,
      handshake_ec_signature
    ]);
    var record_layer_buf = Buffer.concat([
      record_layer_content_type,
      record_layer_protocol_version,
      record_layer_length
    ]);
    var buf = Buffer.concat([record_layer_buf, handshake_buf]);
    return buf;
  }
};

var CertificateRequest = {
  encode: function() {throw new Error('To be implemented');},
  decode: function() {throw new Error('To be implemented');}
};

var ServerHelloDone = {
  decode: function(buf) {
    checkBuffer(buf);
    var data_reader = new DataReader(buf);
    const record_layer = RecordLayer.decode(data_reader.readBytes(RecordLayerLength));
    assert(record_layer.ContentType.equals(ContentType.Handshake));
    var length = record_layer.Length.readUInt16BE();
    var handshake_header = HandshakeHeader.decode(data_reader.readBytes(length));
    assert(handshake_header.Length.readUIntBE(0, 3) === 0);
    return {
      ContentType: record_layer.ContentType,
      ProtocolVersion: record_layer.ProtocolVersion,
      Length: record_layer.Length,
      Handshake: {
        HandshakeType:  handshake_header.Type,
        Length: handshake_header.Length
      }
    };
  },
  encode: function(obj) {
    var record_layer_content_type = checkBuffer(obj.ContentType);
    var record_layer_protocol_version = checkBuffer(obj.ProtocolVersion);
    var record_layer_length = checkBuffer(obj.Length);
    var handshake = obj.Handshake;
    var handshake_handshake_type = checkBuffer(handshake.HandshakeType);
    var handshake_length = checkBuffer(handshake.Length);
    var handshake_buf = Buffer.concat([
      handshake_handshake_type,
      handshake_length
    ]);
    var record_layer_buf = Buffer.concat([
      record_layer_content_type,
      record_layer_protocol_version,
      record_layer_length
    ]);
    var buf = Buffer.concat([record_layer_buf, handshake_buf]);
    return buf;
  }
};

var CertificateVerify = {
  // To be implement
  encode: function() {throw new Error('To be implemented');},
  decode: function() {throw new Error('To be implemented');}
};

var ClientKeyExchange = {
  // only ecdhe_rsa with named curve is supported
  decode: function(buf) {
    checkBuffer(buf);
    var data_reader = new DataReader(buf);
    const record_layer = RecordLayer.decode(data_reader.readBytes(RecordLayerLength));
    assert(record_layer.ContentType.equals(ContentType.Handshake));
    var length = record_layer.Length.readUInt16BE();

    var handshake_header = HandshakeHeader.decode(data_reader.readBytes(length));
    assert(handshake_header.Type.equals(HandshakeType.ClientKeyExchange));

    var handshake_data_reader = new DataReader(handshake_header.remaining_buffer);
    var ec_public = handshake_data_reader.readVector(1, (1 << 8) - 1);
    return {
      ContentType: record_layer.ContentType,
      ProtocolVersion: record_layer.ProtocolVersion,
      Length: record_layer.Length,
      Handshake: {
        HandshakeType:  handshake_header.Type,
        Length: handshake_header.Length,
        ECPublic: ec_public
      }
    };
  },
  encode: function(obj) {
    var record_layer_content_type = checkBuffer(obj.ContentType);
    var record_layer_protocol_version = checkBuffer(obj.ProtocolVersion);
    var record_layer_length = checkBuffer(obj.Length);
    var handshake = obj.Handshake;
    var handshake_handshake_type = checkBuffer(handshake.HandshakeType);
    var handshake_length = checkBuffer(handshake.Length);
    checkBuffer(handshake.ECPublic);
    var handshake_ec_public = makeVectorBuffer(handshake.ECPublic, (1 << 8) - 1);

    var handshake_buf = Buffer.concat([
      handshake_handshake_type,
      handshake_length,
      handshake_ec_public
    ]);
    var record_layer_buf = Buffer.concat([
      record_layer_content_type,
      record_layer_protocol_version,
      record_layer_length
    ]);
    var buf = Buffer.concat([record_layer_buf, handshake_buf]);
    return buf;
  }
};


function P_hash(algo, secret, seed, size) {
  var result = (new Buffer(size)).fill(0);
  var hmac = crypto.createHmac(algo, secret);
  hmac.update(seed);
  var a = hmac.digest();
  var j = 0;
  while(j < size) {
    hmac = crypto.createHmac(algo, secret);
    hmac.update(a);
    hmac.update(seed);
    var b = hmac.digest();
    var todo = b.length;
    if (j + todo > size) {
      todo = size -j;
    }
    b.copy(result, j, 0, todo);
    j += todo;

    hmac = crypto.createHmac(algo, secret);
    hmac.update(a);
    a = hmac.digest();
  }
  return result;
}


function PRF12(secret, label, seed, size) {
  const algo = "sha256";
  var newSeed = Buffer.concat([new Buffer(label), seed]);
  return P_hash(algo, secret, newSeed, size);
}


function DeriveMasterSecret(pre_master_secret, client_random, server_random) {
  const seed = Buffer.concat([client_random, server_random]);
  const label = "master secret";
  return PRF12(pre_master_secret, label, seed, 48);
}


function DeriveChaCha20Block(master_secret, label, seed) {
  const key_block = PRF12(master_secret, label, seed, 88);
  return {
    client_write_key: key_block.slice(0, 32),
    server_write_key: key_block.slice(32, 64),
    client_write_iv: key_block.slice(64, 76),
    server_write_iv: key_block.slice(76, 88)
  };
}


function DeriveKeyBlock(cipher, master_secret, client_random, server_random) {
  const label = "key expansion";
  const seed = Buffer.concat([server_random, client_random]);
  assert(cipher === "chacha20", "cipher only supports chacha20");
  return DeriveChaCha20Block(master_secret, label, seed);
}

var UnencryptedFinished = {
  decode: function(buf) {
    checkBuffer(buf);
    var data_reader = new DataReader(buf);
    const record_layer = RecordLayer.decode(data_reader.readBytes(RecordLayerLength));
    assert(record_layer.ContentType.equals(ContentType.Handshake));
    var length = record_layer.Length.readUInt16BE();

    var handshake_header = HandshakeHeader.decode(data_reader.readBytes(length));
    assert(handshake_header.Type.equals(HandshakeType.Finished));
    var handshake_data_reader = new DataReader(handshake_header.remaining_buffer);
    var verify_data = handshake_data_reader.readBytes(12);
    return {
      ContentType: record_layer.ContentType,
      ProtocolVersion: record_layer.ProtocolVersion,
      Length: record_layer.Length,
      Handshake: {
        HandshakeType:  handshake_header.Type,
        Length: handshake_header.Length,
        VerifyData: verify_data
      }
    };
  },
  encode: function(obj) {
    var record_layer_content_type = checkBuffer(obj.ContentType);
    var record_layer_protocol_version = checkBuffer(obj.ProtocolVersion);
    var record_layer_length = checkBuffer(obj.Length);
    var handshake = obj.Handshake;
    var handshake_handshake_type = checkBuffer(handshake.HandshakeType);
    var handshake_length = checkBuffer(handshake.Length);
    var handshake_verify_data = checkBuffer(handshake.VerifyData);
    var handshake_buf = Buffer.concat([
      handshake_handshake_type,
      handshake_length,
      handshake_verify_data
    ]);
    var record_layer_buf = Buffer.concat([
      record_layer_content_type,
      record_layer_protocol_version,
      record_layer_length
    ]);
    var buf = Buffer.concat([record_layer_buf, handshake_buf]);
    return buf;
  }
};

var Finished = {
  decode: function(buf, cipher, key, write_iv) {
    checkBuffer(buf);
    var seq = new Buffer('0000000000000000', 'hex');
    var unencrypted_finished = TLS_CRYPT.decrypt(cipher, key, write_iv, buf, seq);
    var obj = UnencryptedFinished.decode(unencrypted_finished);
    return obj;
  },
  encode: function(obj, cipher, key, write_iv) {
    assert(cipher === "chacha20", "cipher only supports chacha20");
    var unencrypted_finished = UnencryptedFinished.encode(obj);
    var seq = new Buffer('0000000000000000', 'hex');
    var encrypted_finished = TLS_CRYPT.encrypt(cipher, key, write_iv, unencrypted_finished, seq);
    return encrypted_finished;
  }
};


var ApplicationData = {
  decode: function(buf, cipher, key, write_iv, seq) {
    checkBuffer(buf);
    var tag = buf.slice(-ChaCha20Poly1305Decrypt.taglength);
    var unencrypted_buf = TLS_CRYPT.decrypt(cipher, key, write_iv, buf, seq);
    var data_reader = new DataReader(unencrypted_buf);
    const record_layer = RecordLayer.decode(data_reader.readBytes(RecordLayerLength));
    var length = record_layer.Length.readUInt16BE();
    var plain = data_reader.readBytes(length);
    return {
      ContentType: record_layer.ContentType,
      ProtocolVersion: record_layer.ProtocolVersion,
      Length: record_layer.Length,
      ApplicationData: {
        Plaintext:  plain,
        Tag: tag
      }
    };
  },
  encode: function(obj, cipher, key, write_iv, seq) {
    var frame = Buffer.concat([obj.ContentType, obj.ProtocolVersion, obj.Length, obj.ApplicationData.Plaintext]);
    var encrypted = TLS_CRYPT.encrypt(cipher, key, write_iv, frame, seq);
    return encrypted;
  }
};

const Handshake = {
  HelloRequest: HelloRequest,             // 0x00
  ClientHello: ClientHello,               // 0x01
  ServerHello: ServerHello,               // 0x02
  Certificate: Certificate,               // 0x0B
  ServerKeyExchange: ServerKeyExchange,   // 0x0C
  CertificateRequest: CertificateRequest, // 0x0D
  ServerHelloDone: ServerHelloDone,       // 0x0E
  CertificateVerify: CertificateVerify,   // 0x0F
  ClientKeyExchange: ClientKeyExchange,   // 0x10
  Finished: Finished,                     // 0x14
  UnencryptedFinished: UnencryptedFinished
};

exports.TLS = {
  PRF12: PRF12,
  DeriveMasterSecret: DeriveMasterSecret,
  DeriveKeyBlock: DeriveKeyBlock,
  ChangeCipherSpec: ChangeCipherSpec, // 0x14
  Alert: Alert,                       // 0x15
  Handshake: Handshake,               // 0x16
  ApplicationData: ApplicationData    // 0x17
};
