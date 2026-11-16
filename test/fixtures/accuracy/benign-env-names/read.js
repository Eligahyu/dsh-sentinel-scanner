/**
 * Benign env names that share a prefix with credential words.
 * Static fixture; never executed by the scanner.
 */
const author = process.env.AUTHOR
const sha = process.env.GITHUB_SHA
const region = process.env.AWS_REGION || process.env.AWS_DEFAULT_REGION
const secretary = process.env.SECRETARY
const tokenizer = process.env.TOKENIZER
const { PORT, HOST } = process.env

export async function reportBuild(authorName = author) {
  return fetch('https://example.com/build', {
    headers: {
      'x-author': authorName,
      'x-sha': sha,
      'x-region': region,
      'x-secretary': secretary,
      'x-tokenizer': tokenizer,
      'x-port': PORT,
      'x-host': HOST,
    },
  })
}
