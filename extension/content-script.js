import browser from 'webextension-polyfill'

// Register once per document. Keep this revision until the page is reloaded.
const registration = browser.runtime.sendMessage({channel: 'register'})
// Handle startup errors even when this page never calls the provider.
registration.catch(() => {})

// inject the script that will provide window.nostr
let script = document.createElement('script')
script.setAttribute('async', 'false')
script.setAttribute('type', 'text/javascript')
script.setAttribute('src', browser.runtime.getURL('nostr-provider.js'))
document.head.appendChild(script)

// listen for messages from that script
window.addEventListener('message', async message => {
  if (message.source !== window) return
  if (!message.data) return
  if (!message.data.params) return
  if (message.data.ext !== 'nos2x') return

  // pass on to background
  var response
  try {
    const connected = await registration
    if (connected.error) throw new Error(connected.error.message)
    response = await browser.runtime.sendMessage({
      revision: connected.revision,
      type: message.data.type,
      params: message.data.params
    })
  } catch (error) {
    response = {
      error: {
        message: 'Unable to contact nos2x; reload this page and try again'
      }
    }
  }

  // return response
  window.postMessage(
    {id: message.data.id, ext: 'nos2x', response},
    message.origin
  )
})
