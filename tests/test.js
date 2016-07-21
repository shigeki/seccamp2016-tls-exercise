const assert = require('assert');
const crypto = require('crypto');
const TLS = require('../index.js').TLS;
const ChaCha20Poly1305 = require('../lib/chacha20_poly1305.js').ChaCha20Poly1305;
const PRF12 = TLS.PRF12;
const ccs_buf = new Buffer('140303000101', 'hex');
const hello_request_buf = new Buffer('160303000400000000', 'hex');
const client_hello_buf = new Buffer('16030100710100006d0303bec25e82264d03c5ac970057da8db036fed9e09f6ca0478bdb03ad8b81d4a9c9000004cca800ff01000040000b000403000102000a00040002001700230000000d0020001e0601060206030501050205030401040204030301030203030201020202030016000000170000', 'hex');
const server_hello_buf = new Buffer('160303003d02000039030347fc43999a049b1b26b115e88de53af8f1efa310611f448f20cda7db35bc4ef200cca8000011ff01000100000b00040300010200230000', 'hex');
const certificate_buf = new Buffer('16030309a90b0009a50009a200050630820502308203eaa0030201020212034ebd836a58519d3af2033cee29347330c0300d06092a864886f70d01010b0500304a310b300906035504061302555331163014060355040a130d4c6574277320456e6372797074312330210603550403131a4c6574277320456e637279707420417574686f72697479205833301e170d3136303632383036353630305a170d3136303932363036353630305a301a311830160603550403130f68746d6c352e6f687473752e6f726730820122300d06092a864886f70d01010105000382010f003082010a0282010100cc03d81f61ea225ceb0330f2b980c29a79c140dd334cc8cd8dca2e862e1f5697636b6f66137c4b86a952e9192805853a46493d3235a2905891c8caa99fed441c72f9abd2536cee57ae7e8e4f1b4dca0b53855133af11b9c212b12d6a24203883d6861da3446e430a8160cc7d3f834539eb669b128e36b24c21252d85e52b2f597ca9299376137cbdf764e4883bcbaa75ca22b8e75421969eaf3f8e1d12c451bcfd7f1d0c0c9e9503b073a205eafa4cfcab771ef801c94436479ebf64002a66337382030f53ed41e8ad76a61a32c228b9b38ceda6d6debeac59063ac4f19cd75b79e822e741d28d07432be45232e79b7c2a692199679f9af19838c80daadda8010203010001a38202103082020c300e0603551d0f0101ff0404030205a0301d0603551d250416301406082b0601050507030106082b06010505070302300c0603551d130101ff04023000301d0603551d0e04160414b88e6d5d02c77ab330897bc4a8304b878fa4b4c2301f0603551d23041830168014a84a6a63047dddbae6d139b7a64565eff3a8eca1307006082b0601050507010104643062302f06082b060105050730018623687474703a2f2f6f6373702e696e742d78332e6c657473656e63727970742e6f72672f302f06082b060105050730028623687474703a2f2f636572742e696e742d78332e6c657473656e63727970742e6f72672f301a0603551d1104133011820f68746d6c352e6f687473752e6f72673081fe0603551d200481f63081f33008060667810c0102013081e6060b2b0601040182df130101013081d6302606082b06010505070201161a687474703a2f2f6370732e6c657473656e63727970742e6f72673081ab06082b0601050507020230819e0c819b54686973204365727469666963617465206d6179206f6e6c792062652072656c6965642075706f6e2062792052656c79696e67205061727469657320616e64206f6e6c7920696e206163636f7264616e636520776974682074686520436572746966696361746520506f6c69637920666f756e642061742068747470733a2f2f6c657473656e63727970742e6f72672f7265706f7369746f72792f300d06092a864886f70d01010b0500038201010021c878f65fd465472f7aae3a72949887699a5fd1bd4b101716ca39b278e29b34d6e96d1d5487c56dccce3fa382df807271a816951bef2dc8f9264d8db70ce4c94fe6a7a02a9dc5e7cfc43180281a54409d71d826c5f2be1c1505c91d843ca682547e056811858a06eed897a9cb88c7bb2250376a3ddd780f93ffdf3e5b79af2a6b28c322425f76b608dc4f22f83b00ffed85193ffed2ff02a65e76ceeb928ca3bd19478f0e90c5f45d2af8ed2b9a06d6fe2fbfa658270c4d18881178c0d249c223dcc070fd340f0f96b566ccbac5db61b7c626c2c55b2b36b7ad656620769bdc207129b98aa80cc5f83723da3f0f1ce9fece0b061cb9adeb809d2aa5e5fca9dd000496308204923082037aa00302010202100a0141420000015385736a0b85eca708300d06092a864886f70d01010b0500303f31243022060355040a131b4469676974616c205369676e617475726520547275737420436f2e311730150603550403130e44535420526f6f74204341205833301e170d3136303331373136343034365a170d3231303331373136343034365a304a310b300906035504061302555331163014060355040a130d4c6574277320456e6372797074312330210603550403131a4c6574277320456e637279707420417574686f7269747920583330820122300d06092a864886f70d01010105000382010f003082010a02820101009cd30cf05ae52e47b7725d3783b3686330ead735261925e1bdbe35f170922fb7b84b4105aba99e350858ecb12ac468870ba3e375e4e6f3a76271ba7981601fd7919a9ff3d0786771c8690e9591cffee699e9603c48cc7eca4d7712249d471b5aebb9ec1e37001c9cac7ba705eace4aebbd41e53698b9cbfd6d3c9668df232a42900c867467c87fa59ab8526114133f65e98287cbdbfa0e56f68689f3853f9786afb0dc1aef6b0d95167dc42ba065b299043675806bac4af31b9049782fa2964f2a20252904c674c0d031cd8f31389516baa833b843f1b11fc3307fa27931133d2d36f8e3fcf2336ab93931c5afc48d0d1d641633aafa8429b6d40bc0d87dc3930203010001a382017d3082017930120603551d130101ff040830060101ff020100300e0603551d0f0101ff040403020186307f06082b0601050507010104733071303206082b060105050730018626687474703a2f2f697372672e747275737469642e6f6373702e6964656e74727573742e636f6d303b06082b06010505073002862f687474703a2f2f617070732e6964656e74727573742e636f6d2f726f6f74732f647374726f6f74636178332e703763301f0603551d23041830168014c4a7b1a47b2c71fadbe14b9075ffc4156085891030540603551d20044d304b3008060667810c010201303f060b2b0601040182df130101013030302e06082b060105050702011622687474703a2f2f6370732e726f6f742d78312e6c657473656e63727970742e6f7267303c0603551d1f043530333031a02fa02d862b687474703a2f2f63726c2e6964656e74727573742e636f6d2f445354524f4f544341583343524c2e63726c301d0603551d0e04160414a84a6a63047dddbae6d139b7a64565eff3a8eca1300d06092a864886f70d01010b05000382010100dd33d711f3635838dd1815fb0955be7656b97048a56947277bc2240892f15a1f4a1229372474511c6268b8cd957067e5f7a4bc4e2851cd9be8ae879dead8ba5aa1019adcf0dd6a1d6ad83e57239ea61e04629affd705cab71f3fc00a48bc94b0b66562e0c154e5a32aad20c4e9e6bbdcc8f6b5c332a398cc77a8e67965072bcb28fe3a165281ce520c2e5f83e8d50633fb776cce40ea329e1f925c41c1746c5b5d0a5f33cc4d9fac38f02f7b2c629dd9a3916f251b2f90b119463df67e1ba67a87b9a37a6d18fa25a5918715e0f2162f58b0062f2c6826c64b98cdda9f0cf97f90ed434a12444e6f737a28eaa4aa6e7b4c7d87dde0c90244a787afc3345bb442', 'hex');
const server_key_exchange_buf = new Buffer('160303014d0c00014903001741049f720bfe2049529ae2926d4601193479d82d4c120af3743c98415e9b5144f6ae220f2917713aa09474cb79a612600479896715f7fe14172e040484df7507bbc60601010065daf06a99130d4476de8e37e94c6140067833b09094cde8f3231e28077bc9ee8ccd16a1c1d2c201534f9b9329db9aa40342a14ea34474a470e5e3ea352b5ac2d8e7a96ea322b66c0a37e9bb1b9c4f28089e4902b73bb05805c2bef4e3561fb051ae66e4f0e666e015ae8f290d2828c9364851ef88c64c4a0b0f173756c94e28c0b685848053df39c73706affc1cd304cc1f8d163d4ab6cf8c7973099c3666b11bb93cc11ca33129fde1092a62f1350d677e232e74f5dc2fb5d3855e347d2142453729416b139ed5323c62643449ea072acd128884c3c0e0318dbb59d27c69c9f80c11df0fba2b26fa2a6c0b8a07c262fc935d34ed6dadb6b4b0f6439be54ca9', 'hex');
const server_hello_done_buf = new Buffer('16030300040e000000', 'hex');
const client_key_exchange_buf = new Buffer('1603030046100000424104eb278f8fda253a1ebf56a92215ca1e8676c735a3f0dce23f3fa40b62631dfe951d3c725dd32bf2df39874b5e80d86294b0cd934f07a49db4760f6ac30ed6c2be', 'hex');
const client_finished_buf = new Buffer('16030300203a15815bfe65833217c409f511060160b36a97d1e9d5a4c9dd7f7a5dc8f694ed', 'hex');
const server_finished_buf = new Buffer('1603030020a3a898ddd6752e5c4cec41683465e7aa24d828bb22da6d12ae70c37603976517', 'hex');
const client_encrypted_application_data = [
  new Buffer('1703030020e30acd58836124618a4383c883b7f64475e2dfeb9090b2744c02140d881a08f9', 'hex'),
  new Buffer('1703030011d40a702fad163f88110f452cae5ef71bff', 'hex')
];
const server_encrypted_application_data = [
  new Buffer('17030301312f04ee684267fe299998ecadcdf696795468d8d07c7508d4cd25ab61b3c07ab1cc9593af7701a8f4527b7beca6eda674e5b06ca91c4e57592886838e38efaef80f8cff9fddac884ff6c86b4535baf5d0529d35ae6774b361ea4d873a0e4b6b59f8a485096f0d47f2bce3731bff730826da2209e5dbfeff2fe7c971b0c90de77e1433374965249d8a40f23ab438a050f783a648e74f5d190bd396457aa3768de4821f9cb18b5b18e690c2b8f6d70eb5e8d4920af3e8621eae71986dbb1a95661857da1a506561cd0b6f98e68e48f59bb74ce4046fab90f3a39930fc9267f413cfb80af22564705c285abcfb944760668b737d578210306db219789f0b681f758b44c3150cdd387fd927c4b02397afc765e08d888830c0c3e9d80aa7243e938bb3cc0c5f9c8b76a5f19c9d0986767160b6d3', 'hex')
];
const pre_master_secret_buf = new Buffer('c88dbde80e860b33147abf21aecdbb0ec0d27dc0598f7ac58a0f26d58f065ad1', 'hex');
const master_secret_buf = new Buffer('de27d9e2d1d728874abf4e42902bd7fa8dc7de2ad8c867fe850584df18e91d9db3257d3fc806a75d580e99aa16775026', 'hex');
const key_block_buf = new Buffer('7DA3DD7F1BE92A6F3D1CA86697B76779F645F923132023A8CD772E5C5FB61069E9C2897C5AC8780241FA66D4A80EA790797DB2102587BA32DE958F6973F2ED1F018D76459A36AA1EF078AC1810129B988B37B926D48B9E65', 'hex');
const client_write_key_buf = new Buffer('7DA3DD7F1BE92A6F3D1CA86697B76779F645F923132023A8CD772E5C5FB61069', 'hex');
const server_write_key_buf = new Buffer('E9C2897C5AC8780241FA66D4A80EA790797DB2102587BA32DE958F6973F2ED1F', 'hex');
const client_write_iv_buf = new Buffer('018D76459A36AA1EF078AC18', 'hex');
const server_write_iv_buf = new Buffer('10129B988B37B926D48B9E65', 'hex');

describe('ChangeCipherSpec', function() {
  const ccs_obj = { ContentType: new Buffer('14', 'hex'),
                    ProtocolVersion: new Buffer('0303', 'hex'),
                    Length: new Buffer('0001', 'hex'),
                    ChangeCipherSpecMessage: new Buffer('01', 'hex')};
  const ccs = new TLS.ChangeCipherSpec();
  it('decode', function() {
    var rand = crypto.randomBytes(32);
    const obj = ccs.decode(Buffer.concat([ccs_buf, rand]));
    assert(obj.ContentType.equals(ccs_obj.ContentType));
    assert(obj.ProtocolVersion.equals(ccs_obj.ProtocolVersion));
    assert(obj.Length.equals(ccs_obj.Length));
    assert(obj.ChangeCipherSpecMessage.equals(ccs_obj.ChangeCipherSpecMessage));
    assert(obj.remaining_buffer.equals(rand));
  });
  it('encode', function() {
    assert(ccs_buf.equals(ccs.encode()));
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
    const hello_request = new TLS.Handshake.HelloRequest();
    it('decode', function() {
      var rand = crypto.randomBytes(32);
      const obj = hello_request.decode(Buffer.concat([hello_request_buf, rand]));
      assert(obj.ContentType.equals(hello_request_obj.ContentType));
      assert(obj.ProtocolVersion.equals(hello_request_obj.ProtocolVersion));
      assert(obj.Length.equals(hello_request_obj.Length));
      assert(obj.Handshake.HandshakeType.equals(hello_request_obj.Handshake.HandshakeType));
      assert(obj.Handshake.Length.equals(hello_request_obj.Handshake.Length));
      assert(obj.remaining_buffer.equals(rand));
    });

    it('encode', function() {
      assert(hello_request_buf.equals(hello_request.encode()));
    });
  });

  describe('ClientHello', function() {
    const client_hello = new TLS.Handshake.ClientHello();
    it('decode', function() {
      var rand = crypto.randomBytes(32);
      const obj = client_hello.decode(Buffer.concat([client_hello_buf, rand]));
    });
    it('encode', function() {
      var rand = crypto.randomBytes(32);
      const obj = client_hello.decode(Buffer.concat([client_hello_buf, rand]));
      const buf = client_hello.encode(obj);
      assert(client_hello_buf.equals(buf));
    });
  });

  describe('ServerHello', function() {
    const server_hello = new TLS.Handshake.ServerHello();
    it('encode', function() {
      var rand = crypto.randomBytes(32);
      const obj = server_hello.decode(Buffer.concat([server_hello_buf, rand]));
    });
    it('decode', function() {
      var rand = crypto.randomBytes(32);
      const obj = server_hello.decode(Buffer.concat([server_hello_buf, rand]));
      const buf = server_hello.encode(obj);
      assert(server_hello_buf.equals(buf));
    });
  });
  describe('Certificate', function() {
    const certificate = new TLS.Handshake.Certificate();
    it('encode', function() {
      var rand = crypto.randomBytes(32);
      const obj = certificate.decode(Buffer.concat([certificate_buf, rand]));
    });
    it('decode', function() {
      var rand = crypto.randomBytes(32);
      const obj = certificate.decode(Buffer.concat([certificate_buf, rand]));
      const buf = certificate.encode(obj);
      assert(certificate_buf.equals(buf));
    });
  });

  describe('ServerKeyExchange', function() {
    const server_key_exchange = new TLS.Handshake.ServerKeyExchange();
    it('encode', function() {
      var rand = crypto.randomBytes(32);
      const obj = server_key_exchange.decode(Buffer.concat([server_key_exchange_buf, rand]));
    });
    it('decode', function() {
      var rand = crypto.randomBytes(32);
      const obj = server_key_exchange.decode(Buffer.concat([server_key_exchange_buf, rand]));
      const buf = server_key_exchange.encode(obj);
      assert(server_key_exchange_buf.equals(buf));
    });
  });
  describe('ServerHelloDone', function() {
    const server_hello_done = new TLS.Handshake.ServerHelloDone();
    it('encode', function() {
      var rand = crypto.randomBytes(32);
      const obj = server_hello_done.decode(Buffer.concat([server_hello_done_buf, rand]));
    });
    it('decode', function() {
      var rand = crypto.randomBytes(32);
      const obj = server_hello_done.decode(Buffer.concat([server_hello_done_buf, rand]));
      const buf = server_hello_done.encode(obj);
      assert(server_hello_done_buf.equals(buf));
    });
  });

  describe('ClientKeyExchange', function() {
    const client_key_exchange = new TLS.Handshake.ClientKeyExchange();
    it('encode', function() {
      var rand = crypto.randomBytes(32);
      const obj = client_key_exchange.decode(Buffer.concat([client_key_exchange_buf, rand]));
    });
    it('decode', function() {
      var rand = crypto.randomBytes(32);
      const obj = client_key_exchange.decode(Buffer.concat([client_key_exchange_buf, rand]));
      const buf = client_key_exchange.encode(obj);
      assert(client_key_exchange_buf.equals(buf));
    });
  });

  describe('MasterSecret KeyBlock', function() {
    it('PRF12', function() {
      const client_hello = (new TLS.Handshake.ClientHello()).decode(client_hello_buf);
      const server_hello = (new TLS.Handshake.ServerHello()).decode(server_hello_buf);
      var seed = Buffer.concat([client_hello.Handshake.Random, server_hello.Handshake.Random]);
      var master_secret = PRF12("sha256", pre_master_secret_buf, "master secret", seed, 48);
      assert(master_secret_buf.equals(master_secret));
      seed = Buffer.concat([server_hello.Handshake.Random, client_hello.Handshake.Random]);
      var key_block = PRF12("sha256", master_secret, "key expansion", seed, 88);
      assert(key_block_buf.equals(key_block));
      var client_write_key = key_block.slice(0, 32);
      assert(client_write_key_buf.equals(client_write_key));
      var server_write_key = key_block.slice(32, 64);
      assert(client_write_key_buf.equals(client_write_key));
      var client_write_iv = key_block.slice(64, 76);
      assert(client_write_iv_buf.equals(client_write_iv));
      var server_write_iv = key_block.slice(76, 88);
      assert(server_write_iv_buf.equals(server_write_iv));
    });
  });

  describe('Finished', function() {
    it("ClientFinished", function() {
      var handshake_buf = Buffer.concat([
        client_hello_buf.slice(5),
        server_hello_buf.slice(5),
        certificate_buf.slice(5),
        server_key_exchange_buf.slice(5),
        server_hello_done_buf.slice(5),
        client_key_exchange_buf.slice(5)
      ]);
      var shasum = crypto.createHash('sha256');
      shasum.update(handshake_buf);
      var handshake_hash = shasum.digest();
      var client_verified_data = PRF12("sha256", master_secret_buf, "client finished", handshake_hash, 12);
      var seq = new Buffer('0000000000000000', 'hex');
      var handshake_header = new Buffer('1400000C', 'hex');
      var nonce = BufferXOR(Buffer.concat([seq, new Buffer('00000000', 'hex')]), client_write_iv_buf);
      var unencrypted_record_header = new Buffer('1603030000', 'hex');
      unencrypted_record_header.writeUInt16BE(handshake_header.length+client_verified_data.length, 3);
      var aad = Buffer.concat([seq, unencrypted_record_header]);
      var cipher= ChaCha20Poly1305(aad, client_write_key_buf, nonce, Buffer.concat([handshake_header, client_verified_data]));
      var encrypted_client_verified_data = Buffer.concat([cipher.ciphertext, cipher.tag]);
      var encrypted_record_header = new Buffer('1603030000', 'hex');
      encrypted_record_header.writeUInt16BE(encrypted_client_verified_data.length, 3);
      var client_finished = Buffer.concat([encrypted_record_header, encrypted_client_verified_data]);
      assert(client_finished_buf.equals(client_finished));
    });
  });

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
});
