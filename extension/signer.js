import {SafeError, errorResponse} from './errors'
import {Mutex} from 'async-mutex'
import {hexToBytes} from '@noble/hashes/utils.js'
import {finalizeEvent, validateEvent} from 'nostr-tools/pure'
import * as nip19 from 'nostr-tools/nip19'
import * as nip04 from 'nostr-tools/nip04'
import * as nip44 from 'nostr-tools/nip44'
import {
  IdentityStore,
  permissionStatus,
  publicState,
  updatePermission,
  RELOAD_ERROR
} from './identities'

const METHODS = [
  'getPublicKey',
  'signEvent',
  'nip04.encrypt',
  'nip04.decrypt',
  'nip44.encrypt',
  'nip44.decrypt'
]
const fail = message => {
  throw new SafeError(message)
}

export function createSigner(browser) {
  const store = new IdentityStore(browser.storage.local)
  // Do not read keys or answer requests unless untrusted contexts are excluded.
  const ready = Promise.resolve().then(() =>
    browser.storage.local.setAccessLevel({accessLevel: 'TRUSTED_CONTEXTS'})
  )
  ready.catch(() => {})
  const requests = new Mutex()
  const documents = new Mutex()
  const secrets = new Map()
  let pending = null
  const extensionURL = browser.runtime.getURL('')
  const ownSender = sender =>
    sender.id === browser.runtime.id &&
    (sender.frameId === undefined || sender.frameId === 0)
  const trustedPage = sender =>
    ownSender(sender) &&
    ['options.html', 'popup.html', 'prompt.html'].some(
      page => sender.url?.split('?')[0] === extensionURL + page
    )
  const hostFor = sender => {
    if (
      !sender.tab ||
      !sender.url ||
      !/^https?:$/.test(new URL(sender.url).protocol)
    )
      fail('Unsupported website')
    return new URL(sender.url).host
  }
  const documentKey = sender => {
    if (!sender.documentId)
      fail('Reload this page in a supported Chromium browser')
    return `document:${sender.tab.id}:${sender.documentId}`
  }
  const revision = (state, host) => state.sites[host]?.revision || 0
  const assertCurrent = (state, host, expected) => {
    if (revision(state, host) !== expected) fail(RELOAD_ERROR)
  }

  async function documentRevision(sender, register = false) {
    const host = hostFor(sender)
    const key = documentKey(sender)
    return documents.runExclusive(async () => {
      const existing = (await browser.storage.session.get(key))[key]
      if (existing !== undefined) return existing
      if (!register) fail('Reload this page to connect your identity')
      const current = await store.read(state => revision(state, host))
      await browser.storage.session.set({[key]: current})
      return current
    })
  }

  async function operation(identity, id, type, params) {
    const sk = hexToBytes(identity.privateKey)
    switch (type) {
      case 'getPublicKey':
        return id
      case 'signEvent': {
        if (params.event?.pubkey && params.event.pubkey !== id)
          fail('Event public key does not match this website’s identity')
        const event = finalizeEvent({...params.event}, sk)
        if (!validateEvent(event)) fail('Invalid event')
        return event
      }
      case 'nip04.encrypt':
        return nip04.encrypt(sk, params.peer, params.plaintext)
      case 'nip04.decrypt':
        return nip04.decrypt(sk, params.peer, params.ciphertext)
      case 'nip44.encrypt':
      case 'nip44.decrypt': {
        const cacheId = `${id}:${params.peer}`
        let key = secrets.get(cacheId)
        if (!key) {
          key = nip44.v2.utils.getConversationKey(sk, params.peer)
          if (secrets.size >= 100) secrets.delete(secrets.keys().next().value)
          secrets.set(cacheId, key)
        }
        return type === 'nip44.encrypt'
          ? nip44.v2.encrypt(params.plaintext, key)
          : nip44.v2.decrypt(params.ciphertext, key)
      }
      default:
        fail('Unknown operation')
    }
  }

  async function execute(host, expected, id, type, params) {
    const identity = await store.read(state => {
      assertCurrent(state, host, expected)
      if (!state.identities[id]) fail(RELOAD_ERROR)
      return state.identities[id]
    })
    const result = await operation(identity, id, type, params)
    await store.read(state => {
      assertCurrent(state, host, expected)
      if (!state.identities[id]) fail(RELOAD_ERROR)
    })
    return result
  }

  async function notify(host, id, answer, type) {
    try {
      const {notifications} = await browser.storage.local.get('notifications')
      const identity = await store.read(state => state.identities[id])
      if (notifications)
        await browser.notifications.create(undefined, {
          type: 'basic',
          title: `${type} ${answer ? 'allowed' : 'denied'} for ${host}`,
          message: `${identity?.name || 'Removed identity'} (${id.slice(
            0,
            12
          )}…)`,
          iconUrl: 'icons/48x48.png'
        })
    } catch (_) {
      /* Notifications must not break signing. */
    }
  }

  async function ask(host, expected, type, params, assignedId) {
    const p = {
      id: crypto.randomUUID(),
      host,
      expected,
      type,
      params,
      assignedId,
      windowId: null
    }
    const answer = new Promise((resolve, reject) =>
      Object.assign(p, {resolve, reject})
    )
    // Attach the rejection handler before window creation can fail or be cancelled.
    answer.catch(() => {})
    pending = p
    const timeout = setTimeout(
      () => p.reject(new SafeError('Approval expired; try again')),
      240000
    )
    try {
      p.ready = browser.windows
        .create({
          url: `${extensionURL}prompt.html?id=${p.id}`,
          type: 'popup',
          width: 480,
          height: 680
        })
        .then(window => {
          p.windowId = window.id
        })
      await p.ready
      return await answer
    } finally {
      clearTimeout(timeout)
      if (pending === p) pending = null
      if (p.windowId !== null) {
        try {
          await browser.windows.remove(p.windowId)
        } catch (_) {
          /* Already closed. */
        }
      }
    }
  }

  async function promptMessage(message, sender) {
    const p = pending
    if (
      !p ||
      !ownSender(sender) ||
      message.id !== p.id ||
      sender.url?.split('?')[0] !== extensionURL + 'prompt.html'
    )
      fail('Approval request expired')
    await p.ready
    if (
      new URL(sender.url).searchParams.get('id') !== p.id ||
      (sender.tab?.windowId ?? message.windowId) !== p.windowId
    )
      fail('Invalid approval window')
    if (!sender.tab) {
      const window = await browser.windows.get(p.windowId, {populate: true})
      if (!window.tabs?.some(tab => tab.url === sender.url))
        fail('Invalid approval window')
    }
    await store.read(state => {
      assertCurrent(state, p.host, p.expected)
      if (p.assignedId && !state.identities[p.assignedId]) fail(RELOAD_ERROR)
    })
    if (message.action === 'ping') return true
    if (message.action === 'get')
      return store.read(state => ({
        ...publicState(state),
        host: p.host,
        type: p.type,
        params: p.params,
        assignedId: p.assignedId
      }))
    if (message.action === 'preview') {
      if (p.assignedId && message.identityId !== p.assignedId)
        fail('Identity does not match this request')
      p.selectedId = message.identityId
      if (p.type === 'signEvent') return null
      return execute(p.host, p.expected, message.identityId, p.type, p.params)
    }
    if (message.action !== 'answer' || typeof message.accept !== 'boolean')
      fail('Invalid approval response')
    const id = p.assignedId || message.identityId
    if (!id && message.accept) fail('Choose an identity')
    if (p.assignedId && id !== p.assignedId)
      fail('Identity does not match this request')
    if (
      message.conditions &&
      (typeof message.conditions !== 'object' ||
        Array.isArray(message.conditions))
    )
      fail('Invalid permission conditions')
    if (pending !== p || p.answering || p.finished)
      fail('Approval request expired')
    p.answering = true
    try {
      const result = await store.mutate(state => {
        if (pending !== p) fail('Approval request expired')
        assertCurrent(state, p.host, p.expected)
        if (id && !state.identities[id]) fail(RELOAD_ERROR)
        if (message.accept && !p.assignedId)
          state.sites[p.host] = {identityId: id, revision: p.expected}
        if (message.conditions && id) {
          // Derive permission scope from the original request, not the reply.
          const conditions =
            p.type === 'signEvent' ? {kinds: {[p.params.event.kind]: true}} : {}
          updatePermission(
            state,
            id,
            p.host,
            p.type,
            message.accept,
            conditions
          )
        }
        return message.accept
      })
      p.finished = true
      p.resolve({accept: result, id})
    } finally {
      p.answering = false
    }
    return true
  }

  async function replaceURL(params) {
    const {protocol_handler: template} = await browser.storage.local.get(
      'protocol_handler'
    )
    if (!template) return false
    const raw = params.url.split('nostr:')[1]
    const {type, data} = nip19.decode(raw)
    const values = {
      raw,
      hrp: type,
      hex: ['npub', 'note'].includes(type)
        ? data
        : type === 'nprofile'
        ? data.pubkey
        : type === 'nevent'
        ? data.id
        : null,
      p_or_e: {npub: 'p', note: 'e', nprofile: 'p', nevent: 'e'}[type],
      u_or_n: {npub: 'u', note: 'n', nprofile: 'u', nevent: 'n'}[type],
      relay0: data.relays?.[0],
      relay1: data.relays?.[1],
      relay2: data.relays?.[2]
    }
    return template.replace(/\{\s*(\w+)\s*\}/g, (match, name) =>
      name in values ? String(values[name] ?? '') : match
    )
  }

  async function request(message, sender, external) {
    const host = external ? `extension:${sender.id}` : hostFor(sender)
    const expected = external
      ? await store.read(state => revision(state, host))
      : await documentRevision(sender)
    if (!external && message.revision !== expected) fail(RELOAD_ERROR)
    const {type, params = {}} = message
    if (type === 'replaceURL') return replaceURL(params)
    if (type !== 'peekPublicKey' && !METHODS.includes(type))
      fail('Unknown operation')
    if (
      type === 'signEvent' &&
      !validateEvent({...params.event, pubkey: '0'.repeat(64)})
    )
      fail('Invalid event')
    return requests.runExclusive(async () => {
      const state = await store.read(state => {
        assertCurrent(state, host, expected)
        return state
      })
      const id = state.sites[host]?.identityId
      if (type === 'peekPublicKey')
        return id && permissionStatus(state, id, host, 'getPublicKey') === true
          ? id
          : ''
      if (!Object.keys(state.identities).length)
        fail('No identities found; add an identity in extension options')
      const allowed = id
        ? permissionStatus(state, id, host, type, params.event)
        : undefined
      if (allowed === false) {
        await notify(host, id, false, type)
        fail('denied')
      }
      let chosen = id
      if (allowed !== true) {
        const answer = await ask(host, expected, type, params, id)
        if (!answer.accept) fail('denied')
        chosen = answer.id
      }
      const result = await execute(host, expected, chosen, type, params)
      await notify(host, chosen, true, type)
      await store.read(state => assertCurrent(state, host, expected))
      return result
    })
  }

  async function handle(message, sender, external = false) {
    try {
      await ready
      if (external) {
        if (!sender.id) fail('Missing extension caller')
        return await request(message, sender, true)
      }
      if (message.channel === 'prompt')
        return await promptMessage(message, sender)
      if (message.channel === 'manage') {
        if (
          !trustedPage(sender) ||
          sender.url?.split('?')[0] === extensionURL + 'prompt.html'
        )
          fail('Only extension management pages can manage identities')
        if (
          message.action === 'export' &&
          sender.url?.split('?')[0] !== extensionURL + 'options.html'
        )
          fail('Private keys can only be exported from the options page')
        const result = await store.manage(message.action, message.args)
        if (message.action === 'remove')
          for (const key of secrets.keys())
            if (key.startsWith(message.args.id + ':')) secrets.delete(key)
        const p = pending
        if (p && ['assign', 'remove'].includes(message.action)) {
          const stale = await store.read(
            state =>
              revision(state, p.host) !== p.expected ||
              (p.assignedId && !state.identities[p.assignedId]) ||
              (p.selectedId && !state.identities[p.selectedId])
          )
          if (stale) p.reject(new SafeError(RELOAD_ERROR))
        }
        return result === undefined ? true : result
      }
      if (message.channel === 'register')
        return {revision: await documentRevision(sender, true)}
      return await request(message, sender, false)
    } catch (error) {
      return errorResponse(error)
    }
  }

  return {
    handle,
    store,
    windowRemoved(id) {
      if (pending?.windowId === id) pending.reject(new SafeError('denied'))
    },
    async tabRemoved(id) {
      const data = await browser.storage.session.get(null)
      await browser.storage.session.remove(
        Object.keys(data).filter(key => key.startsWith(`document:${id}:`))
      )
    }
  }
}
