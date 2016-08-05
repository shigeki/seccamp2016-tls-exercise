const DataReader = require('../../lib/data_reader.js').DataReader;
const Connection = require('../../lib/connection.js').Connection;
const TLS = require('../../lib/tls.js').TLS;
const net = require('net');
const fs = require('fs');
const privatekey = fs.readFileSync('/home/ohtsu/tmp/cert/iijplus/iijplus.jp.key');
var port = 8443;
var host = 'demo.iijplus.jp';

var client = net.connect({host: host, port: port});
client.on('error', function(e) {
  console.log(e);
});
var connection = new Connection(false);
client.on('connect', function(s) {
  connection.on('frame', function(frame, type) {
    client.write(frame);
  });

  var remaining_buffer = [];
  client.on('data', function(buf) {
    if (remaining_buffer.length > 0) {
      remaining_buffer.push(buf);
      buf = Buffer.concat(remaining_buffer);
      remaining_buffer = [];
    }

    if (buf.length < 5) {
      if (buf.length) remaining_buffer.push(buf);
      return;
    }

    var record_length = buf.readUInt16BE(3);

    if (buf.length <  record_length + 5) {
      if (buf.length) remaining_buffer.push(buf);
      return;
    }

    var frame = buf.slice(0, record_length + 5);
    var remain = buf.slice(record_length + 5);
    if (remain.length) remaining_buffer.push(remain);

    connection.read(frame);

    while(remaining_buffer.length > 0){
      buf = Buffer.concat(remaining_buffer);
      remaining_buffer = [];
      if (buf.length < 5)
        break;
      record_length = buf.readUInt16BE(3);
      if (buf.length < record_length + 5)
        break;

      frame = buf.slice(0, record_length + 5);

      remain = buf.slice(record_length + 5);
      if (remain.length) remaining_buffer.push(remain);
      connection.read(frame);
    }
  });
});

connection.on('frame', function(frame, type) {
  if (type === 'ClientHello')
    client.write(frame);
});
var hello_request_obj = connection.frame_creator.createHelloRequest(connection);
var hello_request_buf = TLS.Handshake.HelloRequest.encode(hello_request_obj);
connection.read(hello_request_buf);
