function one() {
  const target = '../runtime/runner.js'
  return import(target)
}
function two(target) {
  return import(target)
}
export { one, two }
