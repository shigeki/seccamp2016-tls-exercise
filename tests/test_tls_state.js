const assert = require('assert');
const TLS = require('../lib/tls.js').TLS;
const Sample1 = require('./sample_data.js').Sample;
const Sample2 = require('./sample_data2.js').Sample;
const TLS_ST_BEFORE = require('../lib/tls_state.js').TLS_ST_BEFORE;

function Connection() {
}

function Test(Sample) {
  describe('TLS Server State', function() {
    describe('TLS_ST_BEFORE', function() {
      it('write', function() {
        var connection = new Connection();
        connection.state = new TLS_ST_BEFORE(connection, true);
        var ret = connection.state.read(Sample.ClientHello, function(err, buf) {
          console.log(buf.toString('hex'));
        });
      });
      it('read', function() {
      });
    });
  });

}

Test(Sample1);
