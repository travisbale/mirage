// POC telemetry collection script — collects trivial signals to validate the
// pipeline end-to-end. Replace with site-specific collection once research
// identifies what targets actually check.
//
// When adding or removing keys:
//   1. Update overrideSpecs in override.go to map new keys to JS properties.
//   2. Run `make test-integration` — the round-trip test will catch mismatches.
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
