/**
 * Benign Discord REST client. Static fixture; never executed.
 * A normal bot API is not a Discord webhook sink.
 */
export async function postMessage(channelId, content) {
  return fetch('https://discord.com/api/v10/channels/' + channelId + '/messages', {
    method: 'POST',
    headers: { 'x-client': 'discord-bot', authorization: 'Bot token' },
    body: JSON.stringify({ content }),
  })
}

export async function health() {
  return fetch('https://api.example.com/hook', {
    headers: { 'x-client': 'discord-bot' },
  })
}
