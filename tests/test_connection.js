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
      var tls_read_frames = [Sample.ClientHello,
                             Sample.ServerHello,
                             Sample.Certificate,
                             Sample.ServerKeyExchange,
                             Sample.ServerHelloDone,
                             Sample.ClientKeyExchange,
                             Sample.ChangeCipherSpec,
                             Sample.ClientFinished,
                             Sample.ChangeCipherSpec,
                             Sample.ServerFinished,
                             Sample.ClientEncryptedApplicationData[0],
                             Sample.ClientEncryptedApplicationData[1]
                            ];
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
        assert(tls_read_frames.shift().equals(frame));
      });
      var index = 0;
      connection.on('clearText', function(data) {
        assert(data.equals(Sample.ClientPlainApplicationData[index++]));
      });
      function ConnectionRead() {
        connection.read(tls_read_frames.shift(), function(e) {
          if (tls_read_frames.length > 0) {
            ConnectionRead();
            return;
          }
          console.log('DONE', connection.state.constructor.name);
        });
      }
      ConnectionRead();
    });
  });
  describe('TLS Client State', function() {
    it('TLS_ST_BEFORE=>TLS_ST_OK', function() {
      var tls_read_frames = [Sample.HelloRequest,
                             Sample.ClientHello,
                             Sample.ServerHello,
                             Sample.Certificate,
                             Sample.ServerKeyExchange,
                             Sample.ServerHelloDone,
                             Sample.ClientKeyExchange,
                             Sample.ChangeCipherSpec,
                             Sample.ClientFinished,
                             Sample.ChangeCipherSpec,
                             Sample.ServerFinished,
                             Sample.ServerEncryptedApplicationData[0]
                            ];
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
        assert(tls_read_frames.shift().equals(frame));
      });
      var index = 0;
      connection.on('clearText', function(data) {
        assert(data.equals(Sample.ServerPlainApplicationData[index++]));
      });
      function ConnectionRead() {
        connection.read(tls_read_frames.shift(), function(e) {
          if (tls_read_frames.length > 0) {
            ConnectionRead();
            return;
          }
          console.log('DONE', connection.state.constructor.name);
        });
      }
      ConnectionRead();
    });
  });
  describe.only('ClientTest', function() {
    var client_connection = new Connection(false);
    var client_hello_obj = client_connection.createClientHello();
    var client_hello_buf = TLS.Handshake.ClientHello.encode(client_hello_obj);
    var server_connection = new Connection(true);
    server_connection.setCertificates(require('./cert_data.js').Certificates);
    server_connection.read(client_hello_buf, function(e) {
      var client_key_exchange_obj = client_connection.createClientKeyExchange();
      var client_key_exchange_buf = TLS.Handshake.ClientKeyExchange.encode(client_key_exchange_obj);
      server_connection.read(client_key_exchange_buf, function(e) {
        var change_cipher_spec_buf = TLS.ChangeCipherSpec.encode();
        server_connection.read(change_cipher_spec_buf, function(e) {
          var client_finished_obj = client_connection.createClientFinished();
          var client_finished_buf = TLS.Handshake.ClientFinished.encode(client_finished_obj);
          server_connection.read(change_finished_buf, function(e) {
            console.log('DONE');
          });
        });
      });
    });
  });
}

Test(Sample2);
