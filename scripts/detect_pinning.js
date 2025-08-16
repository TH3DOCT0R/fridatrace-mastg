// Detects certificate pinning/trust manager usage WITHOUT bypassing anything
'use strict';

Java.perform(function () {
  // okhttp3.CertificatePinner.check(String hostname, List<Certificate>)
  try {
    var CertPinner = Java.use('okhttp3.CertificatePinner');
    CertPinner.check.overload('java.lang.String', 'java.util.List').implementation = function (host, certs) {
      send({ type: 'pinning', lib: 'okhttp3', fn: 'CertificatePinner.check', host: String(host), cert_count: certs ? certs.size() : 0 });
      return this.check(host, certs); // no bypass
    };
  } catch (_) {}

  // TrustManager: log invocations
  try {
    var X509TM = Java.use('javax.net.ssl.X509TrustManager');
  } catch (_) {}

  var classes = Java.enumerateLoadedClassesSync();
  classes.forEach(function (cls) {
    try {
      var k = Java.use(cls);
      if (k && k.class && k.class.isInterface()) return;
      // rough heuristic: custom trust managers
      if (cls.indexOf('TrustManager') >= 0 && cls.indexOf('javax.net.ssl') === -1) {
        send({ type: 'pinning', fn: 'TrustManager.detected', class: cls });
      }
    } catch (_) {}
  });
});
