try {
  var SecCamp2016 = require('seccamp2016-tls-exercise');
} catch(e) {
  var SecCamp2016 = require(__dirname + '/../index.js');
}

SecCamp2016.TLSBot(true);
