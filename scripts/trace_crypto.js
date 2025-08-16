// Logs crypto algorithm/mode and buffer sizes (no key/plaintext dumps)
'use strict';

rpc.exports = { };

Java.perform(function () {
  var Cipher = Java.use('javax.crypto.Cipher');

  function safeLen(bArr) {
    try { return bArr ? bArr.length : 0; } catch (_) { return -1; }
  }

  // getInstance
  Cipher.getInstance.overload('java.lang.String').implementation = function (trans) {
    var obj = this.getInstance(trans);
    send({ type: 'crypto', cls: 'javax.crypto.Cipher', fn: 'getInstance', algo: String(trans) });
    return obj;
  };

  // init variants
  var initOverloads = [
    ['int', 'java.security.Key'],
    ['int', 'java.security.Key', 'java.security.spec.AlgorithmParameterSpec'],
    ['int', 'java.security.Key', 'java.security.spec.AlgorithmParameterSpec', 'java.security.SecureRandom']
  ];
  initOverloads.forEach(function (sig) {
    if (Cipher.init.overload.apply(Cipher.init, sig)) {
      Cipher.init.overload.apply(Cipher.init, sig).implementation = function () {
        var mode = arguments[0];
        var keyClass = arguments[1] ? arguments[1].$className : 'unknown';
        send({ type: 'crypto', cls: 'javax.crypto.Cipher', fn: 'init', mode: mode, keyClass: keyClass });
        return this.init.apply(this, arguments);
      };
    }
  });

  // update
  ['update', 'doFinal'].forEach(function (fn) {
    var overloads = Cipher[fn].overloads;
    overloads.forEach(function (ovl) {
      ovl.implementation = function () {
        var inLen = -1;
        try {
          for (var i = 0; i < arguments.length; i++) {
            if (arguments[i] && arguments[i] instanceof Array) {
              inLen = safeLen(arguments[i]);
              break;
            }
          }
        } catch (_) {}
        var out = ovl.apply(this, arguments);
        var outLen = -1;
        try { outLen = safeLen(out); } catch (_) {}
        send({ type: 'crypto', cls: 'javax.crypto.Cipher', fn: fn, in_len: inLen, out_len: outLen });
        return out;
      };
    });
  });
});
