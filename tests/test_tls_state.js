const assert = require('assert');
const EventEmitter = require('events');
const util = require('util');
const TLS = require('../lib/tls.js').TLS;
const Sample1 = require('./sample_data.js').Sample;
const Sample2 = require('./sample_data2.js').Sample;
const TLS_ST_BEFORE = require('../lib/tls_state.js').TLS_ST_BEFORE;

function Connection() {
}
util.inherits(Connection, EventEmitter);

function Test(Sample) {
  describe('TLS Server State', function() {
    describe('TLS_ST_BEFORE', function() {
      it('write', function() {
        var connection = new Connection();
        connection.state = new TLS_ST_BEFORE(connection, true);
        connection.on('frame', function(frame, type) {
          console.log(type, frame);
          if (type === 'ServerHelloDone') {
            connection.state.read(Sample.ClientKeyExchange);
          }
        });
        var ret = connection.state.read(Sample.ClientHello);
      });
      it('read', function() {
      });
    });
  });

}

Test(Sample1);
