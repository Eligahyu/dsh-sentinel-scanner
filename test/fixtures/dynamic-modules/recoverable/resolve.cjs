const resolved = require.resolve('../lib/' + 'runner.js')
const viaTemplate = require.resolve(`../lib/runner.js`)
module.exports = { resolved, viaTemplate }
