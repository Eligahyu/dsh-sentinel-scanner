const names = ['../runtime/runner.js']
export async function load(decode) {
  const viaIndex = await import(names[0])
  const viaCall = require(decode('../runtime/runner.js'))
  const viaJoin = await import(['../runtime', 'runner.js'].join('/'))
  return [viaIndex, viaCall, viaJoin]
}
