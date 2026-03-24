fetch("/api/telemetry", {
  method: "POST",
  headers: {"Content-Type": "application/json"},
  body: JSON.stringify({
    user_agent: navigator.userAgent,
    screen: screen.width + "x" + screen.height,
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
    ts: Date.now()
  })
}).catch(function() {});
