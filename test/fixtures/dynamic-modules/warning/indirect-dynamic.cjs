function load(name, notRequire) {
  const viaName = (0, require)(name)
  const viaOther = (0, notRequire)('../lib/runner.js')
  return [viaName, viaOther]
}
module.exports = { load }
