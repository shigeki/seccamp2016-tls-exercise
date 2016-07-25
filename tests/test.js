const assert = require('assert');
const crypto = require('crypto');
const TLS = require('../index.js').TLS;
const ChaCha20Poly1305 = require('../lib/crypto/chacha20_poly1305.js');
const ChaCha20Poly1305Encrypt = ChaCha20Poly1305.ChaCha20Poly1305Encrypt;
const ChaCha20Poly1305Decrypt = ChaCha20Poly1305.ChaCha20Poly1305Decrypt;
const PRF12 = TLS.PRF12;
const Sample = require('./sample_data.js').Sample;

function BufferXOR(a, b) {
  assert(Buffer.isBuffer(a));
  assert(Buffer.isBuffer(b));
  assert(a.length === b.length);
  var c = new Buffer(a.length);
  for(var i = 0; i < a.length; i++) {
    c[i] = a[i] ^ b[i];
  }
  return c;
}

describe('ChangeCipherSpec', function() {
  const ccs_obj = { ContentType: new Buffer('14', 'hex'),
                    ProtocolVersion: new Buffer('0303', 'hex'),
                    Length: new Buffer('0001', 'hex'),
                    ChangeCipherSpecMessage: new Buffer('01', 'hex')};
  const ccs = TLS.ChangeCipherSpec;
  it('decode', function() {
    var rand = crypto.randomBytes(32);
    const obj = ccs.decode(Buffer.concat([Sample.ChangeCipherSpec, rand]));
    assert(obj.ContentType.equals(ccs_obj.ContentType));
    assert(obj.ProtocolVersion.equals(ccs_obj.ProtocolVersion));
    assert(obj.Length.equals(ccs_obj.Length));
    assert(obj.ChangeCipherSpecMessage.equals(ccs_obj.ChangeCipherSpecMessage));
    assert(obj.remaining_buffer.equals(rand));
  });
  it('encode', function() {
    assert(Sample.ChangeCipherSpec.equals(ccs.encode()));
  });
});

describe('Handshake', function() {
  describe('HelloRequest', function() {
    const hello_request_obj = { ContentType: new Buffer('16', 'hex'),
                                ProtocolVersion: new Buffer('0303', 'hex'),
                                Length: new Buffer('0004', 'hex'),
                                Handshake: {
                                  HandshakeType: new Buffer('00', 'hex'),
                                  Length: new Buffer('000000', 'hex')
                                }
                               };
    const hello_request = TLS.Handshake.HelloRequest;
    it('decode', function() {
      var rand = crypto.randomBytes(32);
      const obj = hello_request.decode(Buffer.concat([Sample.HelloRequest, rand]));
      assert(obj.ContentType.equals(hello_request_obj.ContentType));
      assert(obj.ProtocolVersion.equals(hello_request_obj.ProtocolVersion));
      assert(obj.Length.equals(hello_request_obj.Length));
      assert(obj.Handshake.HandshakeType.equals(hello_request_obj.Handshake.HandshakeType));
      assert(obj.Handshake.Length.equals(hello_request_obj.Handshake.Length));
      assert(obj.remaining_buffer.equals(rand));
    });

    it('encode', function() {
      assert(Sample.HelloRequest.equals(hello_request.encode()));
    });
  });

  describe('ClientHello', function() {
    const client_hello = TLS.Handshake.ClientHello;
    it('decode', function() {
      var rand = crypto.randomBytes(32);
      const obj = client_hello.decode(Buffer.concat([Sample.ClientHello, rand]));
    });
    it('encode', function() {
      var rand = crypto.randomBytes(32);
      const obj = client_hello.decode(Buffer.concat([Sample.ClientHello, rand]));
      const buf = client_hello.encode(obj);
      assert(Sample.ClientHello.equals(buf));
    });
  });

  describe('ServerHello', function() {
    const server_hello = TLS.Handshake.ServerHello;
    it('encode', function() {
      var rand = crypto.randomBytes(32);
      const obj = server_hello.decode(Buffer.concat([Sample.ServerHello, rand]));
    });
    it('decode', function() {
      var rand = crypto.randomBytes(32);
      const obj = server_hello.decode(Buffer.concat([Sample.ServerHello, rand]));
      const buf = server_hello.encode(obj);
      assert(Sample.ServerHello.equals(buf));
    });
  });

  describe('Certificate', function() {
    const certificate = TLS.Handshake.Certificate;
    it('encode', function() {
      var rand = crypto.randomBytes(32);
      const obj = certificate.decode(Buffer.concat([Sample.Certificate, rand]));
    });
    it('decode', function() {
      var rand = crypto.randomBytes(32);
      const obj = certificate.decode(Buffer.concat([Sample.Certificate, rand]));
      const buf = certificate.encode(obj);
      assert(Sample.Certificate.equals(buf));
    });
  });

  describe('ServerKeyExchange', function() {
    const server_key_exchange = TLS.Handshake.ServerKeyExchange;
    it('encode', function() {
      var rand = crypto.randomBytes(32);
      const obj = server_key_exchange.decode(Buffer.concat([Sample.ServerKeyExchange, rand]));
    });
    it('decode', function() {
      var rand = crypto.randomBytes(32);
      const obj = server_key_exchange.decode(Buffer.concat([Sample.ServerKeyExchange, rand]));
      const buf = server_key_exchange.encode(obj);
      assert(Sample.ServerKeyExchange.equals(buf));
    });
  });

  describe('ServerHelloDone', function() {
    const server_hello_done = TLS.Handshake.ServerHelloDone;
    it('encode', function() {
      var rand = crypto.randomBytes(32);
      const obj = server_hello_done.decode(Buffer.concat([Sample.ServerHelloDone, rand]));
    });
    it('decode', function() {
      var rand = crypto.randomBytes(32);
      const obj = server_hello_done.decode(Buffer.concat([Sample.ServerHelloDone, rand]));
      const buf = server_hello_done.encode(obj);
      assert(Sample.ServerHelloDone.equals(buf));
    });
  });


  describe('ClientKeyExchange', function() {
    const client_key_exchange = TLS.Handshake.ClientKeyExchange;
    it('encode', function() {
      var rand = crypto.randomBytes(32);
      const obj = client_key_exchange.decode(Buffer.concat([Sample.ClientKeyExchange, rand]));
    });
    it('decode', function() {
      var rand = crypto.randomBytes(32);
      const obj = client_key_exchange.decode(Buffer.concat([Sample.ClientKeyExchange, rand]));
      const buf = client_key_exchange.encode(obj);
      assert(Sample.ClientKeyExchange.equals(buf));
    });
  });

  describe('MasterSecret KeyBlock', function() {
    it('PRF12', function() {
      const client_random = TLS.Handshake.ClientHello.decode(Sample.ClientHello).Handshake.Random;
      const server_random = TLS.Handshake.ServerHello.decode(Sample.ServerHello).Handshake.Random;
      var master_secret = TLS.DeriveMasterSecret(Sample.PreMasterSecret, client_random, server_random);
      assert(Sample.MasterSecret.equals(master_secret));

      var key_block = TLS.DeriveKeyBlock("chacha20", master_secret, client_random, server_random);
      assert(Sample.ClientWriteKey.equals(key_block.client_write_key));
      assert(Sample.ServerWriteKey.equals(key_block.server_write_key));
      assert(Sample.ClientWriteIV.equals(key_block.client_write_iv));
      assert(Sample.ServerWriteIV.equals(key_block.server_write_iv));
    });
  });

  describe('Finished', function() {
    it("ClientFinished", function() {
      var handshake_buf = Buffer.concat([
        Sample.ClientHello.slice(5),
        Sample.ServerHello.slice(5),
        Sample.Certificate.slice(5),
        Sample.ServerKeyExchange.slice(5),
        Sample.ServerHelloDone.slice(5),
        Sample.ClientKeyExchange.slice(5)
      ]);
      var shasum = crypto.createHash('sha256');
      shasum.update(handshake_buf);
      var handshake_hash = shasum.digest();
      var client_verified_data = PRF12(Sample.MasterSecret, "client finished", handshake_hash, 12);
      var seq = new Buffer('0000000000000000', 'hex');
      var handshake_header = new Buffer('1400000C', 'hex');
      var nonce = BufferXOR(Buffer.concat([seq, new Buffer('00000000', 'hex')]), Sample.ClientWriteIV);
      var unencrypted_record_header = new Buffer('1603030000', 'hex');
      unencrypted_record_header.writeUInt16BE(handshake_header.length+client_verified_data.length, 3);
      var aad = Buffer.concat([seq, unencrypted_record_header]);
      var cipher= ChaCha20Poly1305Encrypt(aad, Sample.ClientWriteKey, nonce, Buffer.concat([handshake_header, client_verified_data]));
      var encrypted_client_verified_data = Buffer.concat([cipher.ciphertext, cipher.tag]);
      var encrypted_record_header = new Buffer('1603030000', 'hex');
      encrypted_record_header.writeUInt16BE(encrypted_client_verified_data.length, 3);
      var client_finished = Buffer.concat([encrypted_record_header, encrypted_client_verified_data]);
      assert(Sample.ClientFinished.equals(client_finished));
    });
    it("ClientFinishedDecode", function() {
      var handshake_buf = Buffer.concat([
        Sample.ClientHello.slice(5),
        Sample.ServerHello.slice(5),
        Sample.Certificate.slice(5),
        Sample.ServerKeyExchange.slice(5),
        Sample.ServerHelloDone.slice(5),
        Sample.ClientKeyExchange.slice(5)
      ]);
      var shasum = crypto.createHash('sha256');
      shasum.update(handshake_buf);
      var handshake_hash = shasum.digest();
      var client_verify_data = PRF12(Sample.MasterSecret, "client finished", handshake_hash, 12);

      var obj = TLS.Handshake.Finished.decode(Sample.ClientFinished, "chacha20", Sample.ClientWriteKey, Sample.ClientWriteIV);
      assert(client_verify_data.equals(obj.Handshake.VerifyData));
    });
    it("ClientFinishedEncode", function() {
      var handshake_buf = Buffer.concat([
        Sample.ClientHello.slice(5),
        Sample.ServerHello.slice(5),
        Sample.Certificate.slice(5),
        Sample.ServerKeyExchange.slice(5),
        Sample.ServerHelloDone.slice(5),
        Sample.ClientKeyExchange.slice(5)
      ]);
      var shasum = crypto.createHash('sha256');
      shasum.update(handshake_buf);
      var handshake_hash = shasum.digest();
      var client_verified_data = PRF12(Sample.MasterSecret, "client finished", handshake_hash, 12);
      var obj = { ContentType: new Buffer('16', 'hex'),
                  ProtocolVersion: new Buffer('0303', 'hex'),
                  Length: new Buffer('0010', 'hex'),
                  Handshake: { HandshakeType: new Buffer('14', 'hex'),
                               Length: new Buffer('00000c', 'hex'),
                               VerifyData: client_verified_data}
                };
      var buf = TLS.Handshake.Finished.encode(obj, "chacha20", Sample.ClientWriteKey, Sample.ClientWriteIV);
      assert(Sample.ClientFinished.equals(buf));
    });
  });
});