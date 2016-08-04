const readline = require('readline');
const DataReader = require('../../lib/data_reader.js').DataReader;
const Connection = require('../../lib/connection.js').Connection;
const TLS = require('../../lib/tls.js').TLS;
const fs = require('fs');
const privatekey = fs.readFileSync('./self_signed_server.key');
const server_cert = [fs.readFileSync('./self_signed_server.der')];
var connection = new Connection(true);
connection.setPrivateKey(privatekey);
connection.setCertificates(server_cert);
const rl = readline.createInterface(process.stdin, process.stdout);

rl.setPrompt('TLS Server> ');
rl.prompt();

connection.on('frame', function(frame, type) {
  console.log(type, ':', frame.toString('hex'));
});

rl.on('line', function (line) {
  var input = line.trim();
  try {
    var buf = new Buffer(input, 'hex');
    connection.read(buf);
  } catch(e) {
    console.log('Error: input hex string' + e);
  }
  rl.prompt();
}).on('close', function () {
  console.log('Done');
  process.exit(0);
});