const assert = require('assert');
const DataReader = require('./data_reader.js').DataReader;
const DataWriter = require('./data_reader.js').DataWriter;

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
  Finished: Finished                      // 0x14
};

const ContentType = {
  ChangeCipherSpec: new Buffer('14', 'hex'),
  Alert: new Buffer('15', 'hex'),
  Handshake: new Buffer('16', 'hex'),
  ApplicationData: new Buffer('17', 'hex')
};

exports.TLS = {
  ChangeCipherSpec: ChangeCipherSpec, // 0x14
  Alert: Alert,                       // 0x15
  Handshake: Handshake,               // 0x16
  ApplicationData: ApplicationData    // 0x17
};


const RecordLayerLength = 5;
function RecordLayer() {
  this.encode = function(obj) {
    assert(Buffer.isBuffer(obj.ContentType));
    assert(obj.ContentType.length === 1);
    assert(Buffer.isBuffer(obj.ProtocolVersion));
    assert(obj.ProtocolVersion.length === 2);
    assert(Buffer.isBuffer(obj.Length));
    assert(obj.Length == 2);
    return Buffer.concat([obj.ContentType, obj.ProtocolVersion, obj.Length]);
  };
  this.decode = function(buf) {
    assert(Buffer.isBuffer(buf));
    assert(buf.length === RecordLayerLength);
    var data_reader = new DataReader(buf);
    return {
      ContentType: data_reader.readBytes(1),
      ProtocolVersion: data_reader.readBytes(2),
      Length: data_reader.readBytes(2)
    };
  };
}



function ChangeCipherSpec() {
  this.encode = function() {
    return new Buffer('140303000101', 'hex');
  };
  this.decode = function(buf) {
    assert(Buffer.isBuffer(buf));
    var record_layer = (new RecordLayer()).decode(buf.slice(0, RecordLayerLength));
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
  };
}


function Alert() {
  // To be implement
  assert(false);
}


function HandshakeHeader() {
  this.decode = function(buf) {
    assert(Buffer.isBuffer(buf));
    assert(buf.length >= 4);
    var data_reader = new DataReader(buf);
    return {
      Type: data_reader.readBytes(1),
      Length: data_reader.readBytes(3),
      remaining_buffer: data_reader.peekRemainingPayload()
    };
  };
  this.encode = function(obj) {
    assert(Buffer.isBuffer(obj.Type));
    assert(obj.Type.length === 1);
    assert(Buffer.isBuffer(obj.Length));
    assert(obj.Length === 3);
  };
}


function HelloRequest() {
  this.decode = function(buf) {
    assert(Buffer.isBuffer(buf));
    var data_reader = new DataReader(buf);
    const record_layer = (new RecordLayer()).decode(data_reader.readBytes(RecordLayerLength));
    assert(record_layer.ContentType.equals(ContentType.Handshake));
    var length = record_layer.Length.readUInt16BE();
    assert(length === 4);

    var handshake_header = (new HandshakeHeader()).decode(data_reader.readBytes(length));
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
  };

  this.encode = function(obj) {
    // TODO: version tolerance
    return new Buffer('160303000400000000', 'hex');
  };
}


function  ClientHello() {
  this.decode = function(buf) {
    assert(Buffer.isBuffer(buf));
    var data_reader = new DataReader(buf);
    const record_layer = (new RecordLayer()).decode(data_reader.readBytes(RecordLayerLength));
    assert(record_layer.ContentType.equals(ContentType.Handshake));
    var length = record_layer.Length.readUInt16BE();

    var handshake_header = (new HandshakeHeader()).decode(data_reader.readBytes(length));
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
          type: extension_type,
          data: extension_data
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
  };
  this.encode = function(obj) {
    // Need Implement
    assert(false);
    return;
  };
}


function  ServerHello() {}
function  Certificate() {}
function  ServerKeyExchange() {}
function  CertificateRequest() {}
function  ServerHelloDone() {}
function  CertificateVerify() {}
function  ClientKeyExchange() {}
function  Finished() {}

function ApplicationData() {}