// CommonJS package entry point. The native binary is built by node-gyp during
// `npm install`; keeping this tiny wrapper tracked makes `require("tundialer-native")`
// work outside the TypeScript application's explicit `.ts` import as well.
module.exports = require("./build/Release/tundialer.node");
