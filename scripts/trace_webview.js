// Logs WebView URL loads and evaluateJavascript lengths
'use strict';

Java.perform(function () {
  try {
    var WebView = Java.use('android.webkit.WebView');

    WebView.loadUrl.overload('java.lang.String').implementation = function (u) {
      send({ type: 'webview', fn: 'loadUrl', url: String(u) });
      return this.loadUrl(u);
    };

    WebView.evaluateJavascript.overload('java.lang.String', 'android.webkit.ValueCallback').implementation = function (src, cb) {
      send({ type: 'webview', fn: 'evaluateJavascript', len: src ? src.length : 0 });
      return this.evaluateJavascript(src, cb);
    };
  } catch (e) {
    // Older API levels may vary
  }
});
