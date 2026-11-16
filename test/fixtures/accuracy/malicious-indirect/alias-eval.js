/** Indirect eval of a decoded payload. Static fixture; never executed. */
const payload = 'Y29uc29sZS5sb2coMSk='
const run = eval
const decoded = Buffer.from(payload, 'base64').toString()
run(decoded)
