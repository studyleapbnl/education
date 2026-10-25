/*!
 * Study LEAP - Cloudflare Turnstile guard (v6)
 * Adds a Turnstile token to lead-form and OTP requests sent to the Worker, on every page,
 * without changing each form. A visible challenge appears only if Cloudflare needs one
 * (appearance: interaction-only). If the check cannot load (ad-blocker, offline) the request is
 * still sent without a token and the server decides (monitor or strict mode).
 */
(function () {
  'use strict';
  var SITE_KEY = '0x4AAAAAAFgKteCHGoM2uIpw';
  var HOSTS    = window.SL_API_HOSTS || ['https://education.studyleapbnl.workers.dev'];
  if (!window.fetch || window.__slTsGuard) return;
  window.__slTsGuard = true;
  var nativeFetch = window.fetch.bind(window);
  var apiPromise = null;

  function loadApi() {
    if (window.turnstile && window.turnstile.render) return Promise.resolve();
    if (apiPromise) return apiPromise;
    apiPromise = new Promise(function (resolve, reject) {
      function waitReady() {
        var n = 0;
        (function check() {
          if (window.turnstile && window.turnstile.render) return resolve();
          if (++n > 100) return reject(new Error('turnstile timeout'));
          setTimeout(check, 100);
        })();
      }
      if (document.querySelector('script[src*="challenges.cloudflare.com/turnstile"]')) return waitReady();
      var s = document.createElement('script');
      s.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit';
      s.async = true;
      s.onerror = function () { reject(new Error('turnstile blocked')); };
      s.onload = waitReady;
      document.head.appendChild(s);
    });
    return apiPromise;
  }

  function getToken() {
    return loadApi().then(function () {
      return new Promise(function (resolve) {
        var box = document.createElement('div');
        box.setAttribute('data-sl-turnstile', '1');
        box.style.cssText = 'position:fixed;left:50%;bottom:20px;transform:translateX(-50%);z-index:2147483000;';
        document.body.appendChild(box);
        var done = false, wid, timer;
        function finish(tok) {
          if (done) return;
          done = true;
          clearTimeout(timer);
          setTimeout(function () {
            try { window.turnstile.remove(wid); } catch (e) {}
            if (box.parentNode) box.parentNode.removeChild(box);
          }, 0);
          resolve(tok || '');
        }
        timer = setTimeout(function () { finish(''); }, 45000);
        try {
          wid = window.turnstile.render(box, {
            sitekey: SITE_KEY,
            appearance: 'interaction-only',
            theme: 'light',
            callback: finish,
            'error-callback': function () { finish(''); return true; },
            'timeout-callback': function () { finish(''); },
            'expired-callback': function () { finish(''); }
          });
        } catch (e) { finish(''); }
      });
    }).catch(function () { return ''; });
  }

  var spare = null;   // a token obtained for a request that failed before reaching the server
  function acquire() {
    if (spare && Date.now() - spare.at < 25000) { var t = spare.tok; spare = null; return Promise.resolve(t); }
    spare = null;
    return getToken();
  }

  function needsToken(url, init) {
    if (!init || String(init.method || 'GET').toUpperCase() !== 'POST') return false;
    for (var i = 0; i < HOSTS.length; i++) {
      if (url.indexOf(HOSTS[i]) === 0) {
        var path = url.slice(HOSTS[i].length).split('?')[0];
        return path === '' || path === '/' || path === '/otp/send';
      }
    }
    return false;
  }

  window.fetch = function (input, init) {
    var url = typeof input === 'string' ? input : ((input && input.url) || '');
    if (!needsToken(url, init) || typeof init.body !== 'string') return nativeFetch(input, init);
    var payload;
    try { payload = JSON.parse(init.body); } catch (e) { return nativeFetch(input, init); }
    if (!payload || typeof payload !== 'object' || payload.turnstileToken) return nativeFetch(input, init);
    return acquire().then(function (tok) {
      payload.turnstileToken = tok;
      var next = {};
      for (var k in init) if (Object.prototype.hasOwnProperty.call(init, k)) next[k] = init[k];
      next.body = JSON.stringify(payload);
      // the page's own timeout started before the check ran; give the request a fresh one
      if (typeof AbortSignal !== 'undefined' && AbortSignal.timeout) next.signal = AbortSignal.timeout(15000);
      return nativeFetch(input, next).catch(function (err) {
        // The request never reached the server, so the token is still unused: keep it for the
        // automatic retry on the fallback host (avoids a second challenge for the visitor).
        if (tok && !(err && err.name === 'AbortError')) spare = { tok: tok, at: Date.now() };
        throw err;
      });
    });
  };
})();
