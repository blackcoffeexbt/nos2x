import browser from 'webextension-polyfill'
import {createSigner} from './signer'

const signer = createSigner(browser)
browser.runtime.onInstalled.addListener(({reason}) => {
  if (reason === 'install') browser.runtime.openOptionsPage()
})
browser.runtime.onMessage.addListener((message, sender) =>
  signer.handle(message, sender)
)
browser.runtime.onMessageExternal.addListener((message, sender) =>
  signer.handle(message, sender, true)
)
browser.windows.onRemoved.addListener(id => signer.windowRemoved(id))
browser.tabs.onRemoved.addListener(id => {
  signer.tabRemoved(id).catch(() => {})
})
