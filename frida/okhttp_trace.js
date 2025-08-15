Java.perform(function() {
  try {
    var Request = Java.use('okhttp3.Request');
    Request.method.overload('java.lang.String', 'okhttp3.RequestBody').implementation = function(m, b) {
      var req = this.method(m, b);
      try {
        var url = req.url().toString();
        var headers = req.headers().toString();
        console.log('[OKHTTP] ' + m + ' ' + url + '\n' + headers);
      } catch (e) {}
      return req;
    };
    console.log('[*] OkHttp trace installed');
  } catch (e) {
    console.log('[!] OkHttp classes not found');
  }
});
