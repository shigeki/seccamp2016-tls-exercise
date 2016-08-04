const DataReader = require('../../lib/data_reader.js').DataReader;
const Connection = require('../../lib/connection.js').Connection;
const net = require('net');
const fs = require('fs');
const privatekey = fs.readFileSync('/home/ohtsu/tmp/cert/iijplus/iijplus.jp.key');
var port = 8443;
var server = net.createServer();
server.on('error', function(e) {
  console.log(e);
});
server.on('connection', function(s) {
  var connection = new Connection(true);
  connection.setPrivateKey(privatekey);
  connection.setCertificates(require('../../lib/stub_cert_data.js').Certificates);
  connection.on('rawFrame', function(frame, type) {
    console.log('rawFrame', type, frame);
  });
  connection.on('frame', function(frame, type) {
    console.log('frame write', type, frame);
    s.write(frame);
  });

  var remaining_buffer = [];
  s.on('data', function(buf) {
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
server.listen(port, function() {
  console.log('Listening on ' + port);
});
