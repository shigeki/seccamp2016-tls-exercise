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
      connection.client_write_key = Sample.ClientWriteKey;
      connection.server_write_key = Sample.ServerWriteKey;
      connection.client_write_iv = Sample.ClientWriteIV;
      connection.server_write_iv = Sample.ServerWriteIV;
      connection.on('error', function(e) {
        console.log(e);
      });
      connection.on('frame', function(frame, type) {
        assert(Sample[type].equals(frame));
      });
      connection.on('clearText', function(data) {
        assert(data.equals(Sample.ClientPlainApplicationData.shift()));
      });
      var ret = connection.read(Sample.ClientHello, function(e) {
        connection.read(Sample.ClientKeyExchange, function(e) {
          connection.read(Sample.ChangeCipherSpec, function(e) {
            connection.read(Sample.ClientFinished, function(e) {
              connection.read(Sample.ClientEncryptedApplicationData[0], function(e) {
                connection.read(Sample.ClientEncryptedApplicationData[1], function(e) {
                  console.log('DONE!');
                });
              });
            });
          });
        });
      });
    });
  });
}

Test(Sample2);
