/**
 * Benign lookalikes. Static fixture; never executed.
 * A globalThis polyfill and a display-only decoder are not decode-to-exec.
 */
const globalObject = new Function('return this')()
const empty = new Function('')()
const decode = atob
const label = decode('aGk=')
export { globalObject, empty, label }
