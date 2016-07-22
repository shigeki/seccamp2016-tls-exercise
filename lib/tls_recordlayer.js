const assert = require('assert');
const common = require('./common.js');
const DataReader = require('./data_reader.js').DataReader;
const checkBuffer = common.checkBuffer;
const RecordLayerLength = 5;
var RecordLayer = {
  encode: function(obj) {
    checkBuffer(obj.ContentType);
    assert(obj.ContentType.length === 1);
    checkBuffer(obj.ProtocolVersion);
    assert(obj.ProtocolVersion.length === 2);
    checkBuffer(obj.Length);
    assert(obj.Length == 2);
    return Buffer.concat([obj.ContentType, obj.ProtocolVersion, obj.Length]);
  },
  decode: function(buf) {
    checkBuffer(buf);
    assert(buf.length === RecordLayerLength);
    var data_reader = new DataReader(buf);
    return {
      ContentType: data_reader.readBytes(1),
      ProtocolVersion: data_reader.readBytes(2),
      Length: data_reader.readBytes(2)
    };
  }
};
exports.RecordLayer = RecordLayer;
exports.RecordLayerLength = RecordLayerLength;