"use strict";

// Sidecar process for Mirage JS obfuscation.
// Communicates with the Go daemon via newline-delimited JSON on stdin/stdout.
//
// Request:  {"id": "req-1", "js": "function hello() { return 42; }"}
// Response: {"id": "req-1", "result": "var _0x1a2b=...;", "error": ""}
//
// Send {"id": "__shutdown__", "js": ""} to exit cleanly.

const JavaScriptObfuscator = require("javascript-obfuscator");
const readline = require("readline");

const rl = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });

rl.on("line", (line) => {
    let req;
    try {
        req = JSON.parse(line);
    } catch (e) {
        process.stdout.write(
            JSON.stringify({ id: "", result: "", error: "JSON parse error: " + e.message }) + "\n"
        );
        return;
    }

    if (req.id === "__shutdown__") {
        process.exit(0);
    }

    try {
        const result = JavaScriptObfuscator.obfuscate(req.js, {
            compact: true,
            controlFlowFlattening: true,
            controlFlowFlatteningThreshold: 0.75,
            deadCodeInjection: true,
            deadCodeInjectionThreshold: 0.4,
            debugProtection: false,
            disableConsoleOutput: false,
            identifierNamesGenerator: "hexadecimal",
            numbersToExpressions: true,
            renameGlobals: false,              // don't rename globals — breaks API calls
            renameProperties: false,           // don't rename properties — breaks DOM calls
            rotateStringArray: true,
            selfDefending: false,              // adds bulk; not needed
            shuffleStringArray: true,
            simplify: true,
            splitStrings: true,
            splitStringsChunkLength: 5,
            stringArray: true,
            stringArrayCallsTransform: true,
            stringArrayCallsTransformThreshold: 0.75,
            stringArrayEncoding: ["base64", "rc4"],
            stringArrayIndexShift: true,
            stringArrayRotate: true,
            stringArrayShuffle: true,
            stringArrayWrappersCount: 2,
            stringArrayWrappersChainedCalls: true,
            stringArrayWrappersParametersMaxCount: 4,
            stringArrayWrappersType: "function",
            stringArrayThreshold: 0.75,
            transformObjectKeys: true,
            unicodeEscapeSequence: false,
            seed: Math.floor(Math.random() * 2147483647), // different output every call
        });
        process.stdout.write(
            JSON.stringify({ id: req.id, result: result.getObfuscatedCode(), error: "" }) + "\n"
        );
    } catch (e) {
        process.stdout.write(
            JSON.stringify({ id: req.id, result: "", error: e.message }) + "\n"
        );
    }
});

rl.on("close", () => {
    process.exit(0);
});
