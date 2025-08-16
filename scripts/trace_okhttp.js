// Logs OkHttp Request method + URL + header NAMES (no bodies/values)
'use strict';

Java.perform(function () {
  try {
    var Request = Java.use('okhttp3.Request');
    var RealCall = Java.use('okhttp3.internal.connection.RealCall'); // may vary across versions
  } catch (e) {
    // Fallback: just hook Request$Builder.build
  }

  var Builder = Java.use('okhttp3.Request$Builder');
  if (Builder && Builder.build) {
    Builder.build.implementation = function () {
      var req = this.build();
      try {
        var url = req.url().toString();
        var method = req.method();
        var headers = req.headers();
        var names = [];
        for (var i = 0; i < headers.size(); i++) { names.push(headers.name(i)); }
        send({ type: 'http', stack: false, lib: 'okhttp3', fn: 'Request.build',
               method: method, url: url, header_names: names });
      } catch (_) {}
      return req;
    };
  }

  // If RealCall is present, log execute/enqueue lifecycles
  try {
    var RealCall = Java.use('okhttp3.RealCall');
    if (RealCall && RealCall.execute) {
      RealCall.execute.implementation = function () {
        var req = this.request();
        send({ type: 'http', lib: 'okhttp3', fn: 'RealCall.execute', url: req ? req.url().toString() : '?' });
        return this.execute();
      };
    }
  } catch (_) {}
});
