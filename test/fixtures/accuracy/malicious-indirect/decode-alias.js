/** Decoder stored in a local and then eval'd. Static fixture; never executed. */
const blob = 'Y29uc29sZS5sb2coMSk='
const decode = atob
eval(decode(blob))
