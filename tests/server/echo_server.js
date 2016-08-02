var DataReader = require('../../lib/data_reader.js').DataReader;
var net = require('net');
var port = 8443;
var server = net.createServer();
server.on('connection', function(s) {
  s.on('data', function(buf) {
    var reader = new DataReader(buf);
    console.log(buf);
  });
});
server.listen(port, function() {
  console.log('Listening on ' + port);
});
