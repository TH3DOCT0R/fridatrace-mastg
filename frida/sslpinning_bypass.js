Java.perform(function() {
  var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
var SSLContext = Java.use('javax.net.ssl.SSLContext');

  var TrustAll = Java.registerClass({
    name: 'com.k9.TrustAll',
    implements: [X509TrustManager],
    methods: {
      checkClientTrusted: function(chain, authType) {},
      checkServerTrusted: function(chain, authType) {},
      getAcceptedIssuers: function() { return []; }
    }
  });

  var tm = TrustAll.$new();
  var TrustManagerArray = Java.array('javax.net.ssl.X509TrustManager', [tm]);
  var sc = SSLContext.getInstance('TLS');
  sc.init(null, TrustManagerArray, null);
  SSLContext.setDefault(sc);
  console.log('[*] SSL pinning bypass installed');
});
