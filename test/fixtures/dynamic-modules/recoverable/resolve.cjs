const resolved = require.resolve('../runtime/' + 'runner.js')
const viaTemplate = require.resolve(`../runtime/runner.js`)
module.exports = { resolved, viaTemplate }
