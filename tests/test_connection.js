const assert = require('assert');
const EventEmitter = require('events');
const util = require('util');
const TLS = require('../lib/tls.js').TLS;
const Sample1 = require('./sample_data.js').Sample;
const Sample2 = require('./sample_data2.js').Sample;
const Connection = require('../lib/connection.js').Connection;
const Dummy = require('./dummy_create_frame.js');

function addDummy(connection) {
  connection.createClientHello = Dummy.createClientHello;
  connection.createServerHello = Dummy.createServerHello;
  connection.createCertificate = Dummy.createCertificate;
  connection.createServerKeyExchange = Dummy.createServerKeyExchange;
  connection.createServerHelloDone = Dummy.createServerHelloDone;
  connection.createChangeCipherSpec = Dummy.createChangeCipherSpec;
  connection.createClientKeyExchange = Dummy.createClientKeyExchange;
  connection.createClientFinished = Dummy.createClientFinished;
  connection.createServerFinished = Dummy.createServerFinished;
}


function Test(Sample) {
  describe('TLS Server State', function() {
    it('TLS_ST_BEFORE=>TLS_ST_OK', function() {
      var connection = new Connection(true);
      addDummy(connection);
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
      var index = 0;
      connection.on('clearText', function(data) {
        assert(data.equals(Sample.ClientPlainApplicationData[index++]));
      });
      var ret = connection.read(Sample.ClientHello, function(e) {
        connection.read(Sample.ClientKeyExchange, function(e) {
          connection.read(Sample.ChangeCipherSpec, function(e) {
            connection.read(Sample.ClientFinished, function(e) {
              connection.read(Sample.ClientEncryptedApplicationData[0], function(e) {
                connection.read(Sample.ClientEncryptedApplicationData[1], function(e) {
                  console.log('DONE!', connection.state.constructor.name);
                });
              });
            });
          });
        });
      });
    });
  });
  describe.only('TLS Client State', function() {
    it('TLS_ST_BEFORE=>TLS_ST_OK', function() {
      var connection = new Connection(false);
      addDummy(connection);
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
      var index = 0;
      connection.on('clearText', function(data) {
        assert(data.equals(Sample.ServerPlainApplicationData[index++]));
      });
      var ret = connection.read(Sample.HelloRequest, function(e) {
        connection.read(Sample.ServerHello, function(e) {
          connection.read(Sample.Certificate, function(e) {
            connection.read(Sample.ServerKeyExchange, function(e) {
              connection.read(Sample.ServerHelloDone, function(e) {
                connection.read(Sample.ChangeCipherSpec, function(e) {
                  connection.read(Sample.ServerFinished, function(e) {
                    connection.read(Sample.ServerEncryptedApplicationData[0], function(e) {
                      console.log('DONE', connection.state.constructor.name);
                    });
                  });
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
