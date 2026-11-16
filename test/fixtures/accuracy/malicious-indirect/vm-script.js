/** vm.Script built from a decoded payload. Static fixture; never executed. */
import vm from 'vm'
const payload = 'Y29uc29sZS5sb2coMSk='
const decoded = Buffer.from(payload, 'base64').toString()
const script = new vm.Script(decoded)
script.runInThisContext()
