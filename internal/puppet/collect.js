// POC telemetry collection script — collects trivial signals to validate the
// pipeline end-to-end. Replace with site-specific collection once research
// identifies what targets actually check.
(() => {
  return {
    userAgent: navigator.userAgent,
    screenWidth: screen.width,
    screenHeight: screen.height,
    platform: navigator.platform,
    language: navigator.language,
    hardwareConcurrency: navigator.hardwareConcurrency,
    deviceMemory: navigator.deviceMemory || null,
    colorDepth: screen.colorDepth,
  };
})();
