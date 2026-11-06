function one() {
  const target = '../lib/runner.js'
  return import(target)
}
function two(target) {
  return import(target)
}
export { one, two }
