/**
 * Benign integrity pins. Static fixture; never executed.
 * sha512 hex digests and SRI strings are not encoded payloads.
 */
export const HEX_SHA512 = 'cc5655a8ed179876be1f7ff5143b63d7f66622f3bf6f501aa95ef0c06e52a322f551d62e60b904c5dea3a7a26c772bfe33c04d240f364f4aaf378b59490d3a39'

export const INTEGRITY = 'sha512-zFZVqO0XmHa+H3/1FDtj1/ZmIvO/b1AaqV7wwG5SoyL1UdYuYLkExd6jp6Jsdyv+M8BNJA82T0qvN4tZSQ06OQ=='

export function verify(actual) {
  return actual === HEX_SHA512 || actual === INTEGRITY
}
