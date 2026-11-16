/** Function constructor reached through the prototype. Static fixture; never executed. */
const payload = 'Y29uc29sZS5sb2coMSk='
const run = Function.prototype.constructor
run(Buffer.from(payload, 'base64').toString())()
