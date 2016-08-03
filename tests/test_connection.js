const assert = require('assert');
const EventEmitter = require('events');
const util = require('util');
const fs = require('fs');
const TLS = require('../lib/tls.js').TLS;
const Sample1 = require('./sample_data.js').Sample;
const Sample2 = require('./sample_data2.js').Sample;
const Connection = require('../lib/connection.js').Connection;
const privatekey = fs.readFileSync('/home/ohtsu/tmp/cert/iijplus//iijplus.jp.key');
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
      connection.setPrivateKey(privatekey);
      connection.key_block = {
        client_write_key: Sample.ClientWriteKey,
        server_write_key: Sample.ServerWriteKey,
        client_write_iv: Sample.ClientWriteIV,
        server_write_iv: Sample.ServerWriteIV
      };
      connection.pre_master_secret = Sample.PreMasterSecret;
      connection.master_secret = Sample.MasterSecret;
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
      connection.setPrivateKey(privatekey);
      connection.key_block = {
        client_write_key: Sample.ClientWriteKey,
        server_write_key: Sample.ServerWriteKey,
        client_write_iv: Sample.ClientWriteIV,
        server_write_iv: Sample.ServerWriteIV
      };
      connection.pre_master_secret = Sample.PreMasterSecret;
      connection.master_secret = Sample.MasterSecret;
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
  describe.only('Handshake', function() {
    it('Handshake', function() {
      var server_connection = new Connection(true);
      server_connection.setPrivateKey(privatekey);
      server_connection.setCertificates(require('../lib/stub_cert_data.js').Certificates);
      var hello_request_obj = server_connection.frame_creator.createHelloRequest(server_connection);
      var hello_request_buf = TLS.Handshake.HelloRequest.encode(hello_request_obj);
      var client_connection = new Connection(false);
      server_connection.on('frame', function(frame, type) {
        client_connection.read(frame);
      });
      client_connection.on('frame', function(frame, type) {
        server_connection.read(frame);
      });
      client_connection.read(hello_request_buf, function(e, conn) {
        assert.strictEqual(conn.state.constructor.name, 'TLS_ST_OK');
        console.log('DONE', conn.state.constructor.name);
      });
    });
  });
}

Test(Sample2);
