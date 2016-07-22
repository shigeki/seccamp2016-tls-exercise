const assert = require('assert');

try {
  var SecCamp2016 = require('seccamp2016-tls-exercise');
} catch(e) {
  var SecCamp2016 = require(__dirname + '/../index.js');
}

var input = process.argv[2].trim().replace(/\r?\n/g,"");
var buf = new Buffer(input, 'hex');

assert(buf.length >= 5, "Buffer length is too short");

var record_length = buf.readUInt16BE(3);

assert(buf.length === (5 + record_length), 'Record length is not matched');

console.log(record_length);
