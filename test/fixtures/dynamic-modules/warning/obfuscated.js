const names = ['../lib/runner.js']
export async function load(decode) {
  const viaIndex = await import(names[0])
  const viaCall = require(decode('../lib/runner.js'))
  const viaJoin = await import(['../lib', 'runner.js'].join('/'))
  return [viaIndex, viaCall, viaJoin]
}
