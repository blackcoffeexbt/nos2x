import browser from 'webextension-polyfill'

export async function send(message) {
  const response = await browser.runtime.sendMessage(message)
  if (response?.error) throw new Error(response.error.message)
  return response
}

export const manage = (action, args) => send({channel: 'manage', action, args})
export const identityLabel = identity =>
  `${identity.name} (${identity.npub.slice(0, 16)}…)`
