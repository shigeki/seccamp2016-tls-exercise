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
      var connection = new Connection(true, true);
      connection.key_block = {
        client_write_key: Sample.ClientWriteKey,
        server_write_key: Sample.ServerWriteKey,
        client_write_iv: Sample.ClientWriteIV,
        server_write_iv: Sample.ServerWriteIV
      };
      connection.pre_master_secret = Sample.PreMasterSecret;
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
      var connection = new Connection(false, true);
      connection.key_block = {
        client_write_key: Sample.ClientWriteKey,
        server_write_key: Sample.ServerWriteKey,
        client_write_iv: Sample.ClientWriteIV,
        server_write_iv: Sample.ServerWriteIV
      };
      connection.pre_master_secret = Sample.PreMasterSecret;
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
  describe('ClientTest', function() {
    it('ClientTest', function() {
      var client_connection = new Connection(false, true);
      var client_hello_obj = client_connection.frame_creator.createClientHello(client_connection);
      var client_hello_buf = TLS.Handshake.ClientHello.encode(client_hello_obj);
      var server_connection = new Connection(true);
      server_connection.setCertificates(require('../lib/stub_cert_data.js').Certificates);
      server_connection.read(client_hello_buf, function(e, conn) {
        var client_key_exchange_obj = client_connection.frame_creator.createClientKeyExchange(conn);
        var client_key_exchange_buf = TLS.Handshake.ClientKeyExchange.encode(client_key_exchange_obj);
        server_connection.read(client_key_exchange_buf, function(e, conn) {
          var change_cipher_spec_buf = TLS.ChangeCipherSpec.encode();
          server_connection.read(change_cipher_spec_buf, function(e, conn) {
            var client_finished_obj = client_connection.frame_creator.createClientFinished(conn);
            var client_finished_buf = TLS.Handshake.Finished.encode(client_finished_obj, conn.cipher, conn.key_block.client_write_key, conn.key_block.client_write_iv);
            server_connection.read(client_finished_buf, function(e) {
              console.log('DONE', conn.state.constructor.name);
            });
          });
        });
      });
    });
  });
}

Test(Sample2);
