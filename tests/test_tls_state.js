const assert = require('assert');
const EventEmitter = require('events');
const util = require('util');
const TLS = require('../lib/tls.js').TLS;
const Sample1 = require('./sample_data.js').Sample;
const Sample2 = require('./sample_data2.js').Sample;
const Connection = require('../lib/connection.js').Connection;

function Test(Sample) {
  describe('TLS Server State', function() {
    it('TLS_ST_BEFORE=>TLS_ST_OK', function() {
      var connection = new Connection(true);
      connection.on('frameError', function(err) {
        console.log('hoho', err);
      });
      connection.on('frame', function(frame, type) {
        console.log(type, frame);
        if (type === 'ServerHelloDone') {
          connection.state.read(Sample.ClientKeyExchange);
        }
      });
      console.log('Listerners', connection.listeners('frameError'));
//      var ret = connection.state.read(Sample.ClientHello);
    });
  });
}

Test(Sample1);
