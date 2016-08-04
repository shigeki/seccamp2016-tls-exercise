const readline = require('readline');
const DataReader = require('../../lib/data_reader.js').DataReader;
const Connection = require('../../lib/connection.js').Connection;
const TLS = require('../../lib/tls.js').TLS;
const fs = require('fs');
const privatekey = fs.readFileSync('./self_signed_server.key');
const server_cert = [fs.readFileSync('./self_signed_server.der')];
const red     = '\u001b[31m';
const cyan    = '\u001b[36m';
const green   = '\u001b[32m';
const reset   = '\u001b[0m';

const is_server = process.argv[1].match(/tls_server_bot\.js$/) ? true: false;

const mycolor = is_server ? red: cyan;
const yourcolor = is_server ? cyan: red;

var connection = new Connection(is_server);
connection.setPrivateKey(privatekey);
connection.setCertificates(server_cert);
const rl = readline.createInterface(process.stdin, process.stdout);

if (!is_server)
  console.log('Start with HelloRequest: 160303000400000000');

var prompt = is_server ? 'TLS Server> ': 'TLS Client> ';

rl.setPrompt(prompt);
rl.prompt();

connection.on('frame', function(frame, type) {
  console.log(mycolor + type + reset, '=>', frame.toString('hex'));
});

connection.on('received', function(type, clear_text) {
  if (type === 'ApplicationData') {
    console.log('<=', yourcolor + type + reset, clear_text.toString('utf8'));
  } else {
    console.log('<=', yourcolor + type + reset);
  }
});

connection.on('HandshakeFinished', function() {
  console.log(green + '==== Handshake Verified and Completed ====' + reset);
});

connection.on('EncryptStart', function(msg) {
  console.log(green + '==== ' + msg + ' ====' + reset);
});

rl.on('line', function (line) {
  var input = line.trim();
  input = input.replace(/\r?\n/g,"");
  try {
    if (!input.match(/^(\'|\")/)) {
      var buf = new Buffer(input, 'hex');
      connection.read(buf);
    } else {
      input = input.replace(/\'|\"/g,"");
      var obj = {
        ContentType: new Buffer('17', 'hex'),
        ProtocolVersion: connection.version,
        Length: null,
        ApplicationData: {
          Plaintext:  new Buffer(input, 'utf8')
        }
      };
      var frame = TLS.UnencryptedApplicationData.encode(obj);
      connection.write(frame);
    }
  } catch(e) {
    console.log('Error: ' + e);
  }
  rl.prompt();
}).on('close', function () {
  console.log('Done');
  process.exit(0);
});