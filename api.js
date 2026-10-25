/*!
 * Study LEAP - API client (v6.2)
 * Sends form / OTP requests to the custom API domain first and, only if that host cannot be
 * reached at all (DNS, TLS, network or CORS failure), automatically retries on the original
 * workers.dev address. This lets the domain be switched on without any risk of lost leads.
 */
(function () {
  'use strict';
  var PRIMARY  = 'https://api.studyleap.in';
  var FALLBACK = 'https://education.studyleapbnl.workers.dev';
  window.SL_API_HOSTS = [PRIMARY, FALLBACK];
  window.slApiFetch = function (path, init) {
    return window.fetch(PRIMARY + path, init).catch(function (err) {
      if (err && err.name === 'AbortError') throw err;       // user/timeout abort: do not retry
      return window.fetch(FALLBACK + path, init);
    });
  };
})();
