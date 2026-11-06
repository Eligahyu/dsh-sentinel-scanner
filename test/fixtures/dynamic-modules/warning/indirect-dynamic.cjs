function load(name, notRequire) {
  const viaName = (0, require)(name)
  const viaOther = (0, notRequire)('../runtime/runner.js')
  return [viaName, viaOther]
}
module.exports = { load }
