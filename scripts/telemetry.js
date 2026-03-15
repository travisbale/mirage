"use strict";

// Collects browser fingerprinting signals and POSTs them to the telemetry
// endpoint. The session ID is injected at runtime by replacing __MIRAGE_SID__.
(function () {
  var sid = "__MIRAGE_SID__";
  var data = {};

  // WebGL renderer/vendor — strong fingerprinting signal.
  try {
    var canvas = document.createElement("canvas");
    var gl = canvas.getContext("webgl");
    if (gl) {
      var ext = gl.getExtension("WEBGL_debug_renderer_info");
      if (ext) {
        data.webgl_renderer = gl.getParameter(ext.WEBGL_RENDERER);
        data.webgl_vendor = gl.getParameter(ext.WEBGL_VENDOR);
      }
    }
  } catch (e) {}

  // Screen and display properties.
  data.screen_width = screen.width;
  data.screen_height = screen.height;
  data.color_depth = screen.colorDepth;
  data.pixel_ratio = window.devicePixelRatio || 1;

  // Locale and timezone.
  data.timezone_offset = new Date().getTimezoneOffset();
  data.language = navigator.language;

  // Hardware hints.
  data.platform = navigator.platform;
  data.hardware_concurrency = navigator.hardwareConcurrency || 0;
  data.device_memory = navigator.deviceMemory || 0;
  data.touch_points = navigator.maxTouchPoints || 0;

  // Plugin count — distinguishes real browsers from headless ones.
  data.plugins_hash =
    navigator.plugins && navigator.plugins.length > 0
      ? String(navigator.plugins.length)
      : "";

  // Behavioural signals — bots don't move mice or press keys.
  data.mouse_move_count = 0;
  data.key_press_count = 0;
  data.scroll_count = 0;
  document.addEventListener("mousemove", function () {
    data.mouse_move_count++;
  });
  document.addEventListener("keydown", function () {
    data.key_press_count++;
  });
  document.addEventListener("scroll", function () {
    data.scroll_count++;
  });

  // Collect for 2.5 seconds then submit.
  var start = Date.now();
  setTimeout(function () {
    data.collection_ms = Date.now() - start;
    data.session_id = sid;
    fetch("/t/" + sid, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(data),
      credentials: "include",
    }).catch(function () {});
  }, 2500);
})();
