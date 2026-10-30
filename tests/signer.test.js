import test from 'node:test'
import assert from 'node:assert/strict'
import {readFileSync} from 'node:fs'
import {runInNewContext} from 'node:vm'
import {hexToBytes} from '@noble/hashes/utils.js'
import {getPublicKey, verifyEvent, finalizeEvent} from 'nostr-tools/pure'
import * as nip19 from 'nostr-tools/nip19'
import {encrypt} from 'nostr-tools/nip49'
import * as nip04 from 'nostr-tools/nip04'
import * as nip44 from 'nostr-tools/nip44'
import {
  IdentityStore,
  STORAGE_KEY,
  parseSecret,
  permissionStatus,
  updatePermission,
  RELOAD_ERROR
} from '../extension/identities'
import {createSigner} from '../extension/signer'
import {
  RemoteSession,
  remoteOperation,
  newPairing,
  bunkerPointer,
  relayURLs,
  DEFAULT_RELAY
} from '../extension/remote'

const keyA = '01'.repeat(32)
const keyB = '02'.repeat(32)
const keyPeer = '03'.repeat(32)
const idA = getPublicKey(hexToBytes(keyA))
const idB = getPublicKey(hexToBytes(keyB))
const peer = getPublicKey(hexToBytes(keyPeer))
const clone = value =>
  value === undefined ? undefined : JSON.parse(JSON.stringify(value))
const event = {kind: 1, created_at: 1700000000, content: 'hello', tags: []}

function memory(initial = {}) {
  const data = clone(initial)
  return {
    data,
    failSet: false,
    failRemove: false,
    async setAccessLevel({accessLevel}) {
      this.accessLevel = accessLevel
    },
    async get(keys) {
      if (keys === null) return clone(data)
      return Object.fromEntries(
        (Array.isArray(keys) ? keys : [keys])
          .filter(key => key in data)
          .map(key => [key, clone(data[key])])
      )
    },
    async set(values) {
      if (this.failSet) throw new Error('Storage unavailable')
      Object.assign(data, clone(values))
    },
    async remove(keys) {
      if (this.failRemove) throw new Error('Removal interrupted')
      for (const key of Array.isArray(keys) ? keys : [keys]) delete data[key]
    }
  }
}
function mock(initial, dependencies = {}) {
  let nextWindow = 100
  const windows = new Map()
  const api = {
    storage: {local: memory(initial), session: memory()},
    runtime: {id: 'nos2x', getURL: path => `chrome-extension://nos2x/${path}`},
    windows: {
      failCreate: false,
      async create(options) {
        if (this.failCreate) throw new Error('Window unavailable')
        const id = nextWindow++
        windows.set(id, {id, tabs: [{url: options.url}]})
        return {id}
      },
      async get(id) {
        return windows.get(id)
      },
      async remove(id) {
        windows.delete(id)
        signer.windowRemoved(id)
      }
    },
    tabs: {},
    notifications: {async create() {}}
  }
  let signer = createSigner(api, dependencies)
  const ui = {id: api.runtime.id, url: api.runtime.getURL('options.html')}
  return {
    api,
    windows,
    ui,
    get signer() {
      return signer
    },
    restart() {
      signer = createSigner(api, dependencies)
    },
    async manage(action, args) {
      const response = await signer.handle(
        {channel: 'manage', action, args},
        ui
      )
      if (response?.error) throw new Error(response.error.message)
      return response
    },
    async page(host, documentId = `${host}-document`, tabId = 1, frameId = 0) {
      const sender = {
        url: `https://${host}/`,
        tab: {id: tabId},
        documentId,
        frameId
      }
      const registration = await signer.handle({channel: 'register'}, sender)
      assert.equal(registration.error, undefined)
      return {
        sender,
        registration,
        call: (type, params = {}) =>
          signer.handle({type, params, revision: registration.revision}, sender)
      }
    },
    async prompt() {
      for (let i = 0; i < 100; i++) {
        const first = windows.values().next().value
        if (first) {
          const url = first.tabs[0].url
          const id = new URL(url).searchParams.get('id')
          const sender = {id: api.runtime.id, url, tab: {windowId: first.id}}
          return {
            id,
            sender,
            windowId: first.id,
            call: (action, args = {}) =>
              signer.handle({channel: 'prompt', id, action, ...args}, sender)
          }
        }
        await new Promise(resolve => setImmediate(resolve))
      }
      throw new Error('Prompt did not open')
    }
  }
}
async function setup() {
  const m = mock()
  await m.manage('add', {key: keyA, name: 'Personal'})
  await m.manage('add', {key: keyB, name: 'Work'})
  return m
}
async function allow(m, id, host, type, conditions = {}) {
  await m.signer.store.mutate(state =>
    updatePermission(state, id, host, type, true, conditions)
  )
}

test('migration preserves key, host assignments, and kind permissions without exposing secrets', async () => {
  const policies = {
    'old.test': {
      true: {signEvent: {conditions: {kinds: {1: true}}, created_at: 1}}
    }
  }
  const storage = memory({private_key: keyA, policies, notifications: true})
  const store = new IdentityStore(storage)
  const state = await store.read()
  assert.equal(state.identities[idA].privateKey, keyA)
  assert.deepEqual(clone(state.policies[idA]), policies)
  assert.equal(state.sites['old.test'].identityId, idA)
  assert.equal(storage.data.private_key, undefined)
  assert.equal(storage.data.policies, undefined)
  assert.equal(storage.data.notifications, true)
  assert.deepEqual(await store.read(), state)
  assert.ok(!JSON.stringify(await store.manage('state')).includes(keyA))
})

test('migration resumes after legacy removal fails', async () => {
  const storage = memory({private_key: keyA, policies: {}})
  storage.failRemove = true
  const store = new IdentityStore(storage)
  await assert.rejects(store.read(), /interrupted/)
  assert.equal(storage.data.private_key, keyA)
  assert.equal(storage.data[STORAGE_KEY].identities[idA].privateKey, keyA)
  storage.failRemove = false
  await new IdentityStore(storage).read()
  assert.equal(storage.data.private_key, undefined)
})

test('migration failures preserve legacy data and invalid records are not overwritten', async () => {
  for (const initial of [
    {private_key: 'invalid', policies: {a: {}}},
    {private_key: null},
    {private_key: false},
    {private_key: 0},
    {policies: {a: {}}},
    {[STORAGE_KEY]: {version: 9}, private_key: keyA}
  ]) {
    const storage = memory(initial)
    await assert.rejects(new IdentityStore(storage).read())
    assert.deepEqual(storage.data, initial)
  }
  const storage = memory({private_key: keyA})
  storage.failSet = true
  await assert.rejects(new IdentityStore(storage).read(), /Storage/)
  assert.equal(storage.data.private_key, keyA)
})

test('empty storage creates an empty store and missing keys produce a useful error', async () => {
  const m = mock()
  assert.deepEqual((await m.manage('state')).identities, [])
  const page = await m.page('empty.test')
  assert.match((await page.call('getPublicKey')).error.message, /No identities/)
})

test('imports validate nsec, hex, encrypted keys, invalid scalars, and duplicates', async () => {
  assert.equal(parseSecret(nip19.nsecEncode(hexToBytes(keyA))).id, idA)
  assert.equal(parseSecret(` ${keyA.toUpperCase()} `).id, idA)
  const encrypted = encrypt(hexToBytes(keyB), 'password', 10)
  assert.equal(parseSecret(encrypted, 'password').id, idB)
  assert.throws(() => parseSecret(encrypted, 'wrong'))
  assert.throws(() => parseSecret(encrypted))
  for (const invalid of [
    '00'.repeat(32),
    'ff'.repeat(32),
    peer.slice(1),
    nip19.npubEncode(idA),
    'nsec1invalid'
  ])
    assert.throws(() => parseSecret(invalid))
  const m = await setup()
  await assert.rejects(
    m.manage('add', {key: nip19.nsecEncode(hexToBytes(keyA))}),
    /already/
  )
  const before = await m.manage('state')
  await assert.rejects(m.manage('add', {key: encrypted, password: 'wrong'}))
  assert.deepEqual(await m.manage('state'), before)
  const nsec = await m.manage('export', {id: idA})
  assert.equal(parseSecret(nsec).id, idA)
  const exported = await m.manage('export', {id: idA, password: 'secret'})
  assert.equal(parseSecret(exported, 'secret').id, idA)
})

test('concurrent management writes preserve all identities', async () => {
  const m = mock()
  await Promise.all([
    m.manage('add', {key: keyA}),
    m.manage('add', {key: keyB})
  ])
  assert.equal((await m.manage('state')).identities.length, 2)
})

test('first approval chooses and remembers identity only on acceptance', async () => {
  const m = await setup()
  const page = await m.page('new.test')
  const result = page.call('getPublicKey')
  const prompt = await m.prompt()
  const data = await prompt.call('get')
  assert.equal(data.assignedId, undefined)
  assert.ok(!JSON.stringify(data).includes(keyA))
  assert.equal((await m.manage('state')).sites['new.test'], undefined)
  assert.equal(await prompt.call('preview', {identityId: idB}), idB)
  assert.equal(
    await prompt.call('answer', {
      identityId: idB,
      accept: true,
      conditions: {}
    }),
    true
  )
  assert.equal(await result, idB)
  assert.equal((await m.manage('state')).sites['new.test'].identityId, idB)
  assert.equal(await page.call('getPublicKey'), idB)
})

test('first rejection does not assign a website', async () => {
  const m = await setup()
  const page = await m.page('new.test')
  const result = page.call('getPublicKey')
  const prompt = await m.prompt()
  await prompt.call('answer', {identityId: idA, accept: false})
  assert.equal((await result).error.message, 'denied')
  assert.equal((await m.manage('state')).sites['new.test'], undefined)
})

test('two websites sign with distinct keys and reject mismatched event pubkeys', async () => {
  const m = await setup()
  for (const [host, id] of [
    ['a.test', idA],
    ['b.test', idB]
  ]) {
    await m.manage('assign', {host, id})
    await allow(m, id, host, 'signEvent', {kinds: {1: true}})
    await allow(m, id, host, 'getPublicKey')
    const page = await m.page(host)
    assert.equal(await page.call('getPublicKey'), id)
    const signed = await page.call('signEvent', {event})
    assert.equal(signed.pubkey, id)
    assert.ok(verifyEvent(signed))
    assert.match(
      (
        await page.call('signEvent', {
          event: {...event, pubkey: id === idA ? idB : idA}
        })
      ).error.message,
      /does not match/
    )
  }
})

test('permissions and previews remain tied to assigned identity', async () => {
  const m = await setup()
  await m.manage('assign', {host: 'a.test', id: idB})
  await allow(m, idA, 'a.test', 'getPublicKey')
  const page = await m.page('a.test')
  assert.equal(await page.call('peekPublicKey'), '')
  const result = page.call('getPublicKey')
  const prompt = await m.prompt()
  assert.equal((await prompt.call('get')).assignedId, idB)
  assert.match(
    (await prompt.call('preview', {identityId: idA})).error.message,
    /does not match/
  )
  await prompt.call('answer', {identityId: idB, accept: false})
  assert.equal((await result).error.message, 'denied')
})

test('kind-specific allow/deny rules merge, revoke, and override conflicting choices', async () => {
  const m = await setup()
  await m.signer.store.mutate(state => {
    updatePermission(state, idA, 'a', 'signEvent', true, {kinds: {1: true}})
    updatePermission(state, idA, 'a', 'signEvent', true, {kinds: {2: true}})
    updatePermission(state, idA, 'a', 'signEvent', false, {kinds: {1: true}})
  })
  let state = await m.signer.store.read()
  assert.equal(permissionStatus(state, idA, 'a', 'signEvent', {kind: 1}), false)
  assert.equal(permissionStatus(state, idA, 'a', 'signEvent', {kind: 2}), true)
  assert.equal(
    permissionStatus(state, idB, 'a', 'signEvent', {kind: 2}),
    undefined
  )
  assert.equal(
    permissionStatus(state, idA, 'a', 'signEvent', {kind: 3}),
    undefined
  )
  await m.manage('revoke', {
    id: idA,
    host: 'a',
    accept: true,
    type: 'signEvent'
  })
  state = await m.signer.store.read()
  assert.equal(
    permissionStatus(state, idA, 'a', 'signEvent', {kind: 2}),
    undefined
  )
})

test('switching blocks every old tab/frame, survives restart, and reload uses the new key', async () => {
  const m = await setup()
  await m.manage('assign', {host: 'a.test', id: idA})
  await allow(m, idA, 'a.test', 'getPublicKey')
  await allow(m, idB, 'a.test', 'getPublicKey')
  const pages = await Promise.all([
    m.page('a.test', 'tab1', 1),
    m.page('a.test', 'frame', 1, 2),
    m.page('a.test', 'tab2', 2)
  ])
  await m.manage('assign', {host: 'a.test', id: idB})
  for (const page of pages)
    assert.equal((await page.call('getPublicKey')).error.message, RELOAD_ERROR)
  m.restart()
  for (const page of pages) {
    const registration = await m.signer.handle(
      {channel: 'register'},
      page.sender
    )
    assert.equal(registration.revision, page.registration.revision)
    assert.equal((await page.call('getPublicKey')).error.message, RELOAD_ERROR)
  }
  assert.equal(
    await (await m.page('a.test', 'reloaded', 1)).call('getPublicKey'),
    idB
  )
})

test('switching cancels pending approvals and deletion never falls back', async () => {
  const m = await setup()
  await m.manage('assign', {host: 'a.test', id: idA})
  const page = await m.page('a.test')
  const result = page.call('getPublicKey')
  const prompt = await m.prompt()
  await m.manage('assign', {host: 'a.test', id: idB})
  assert.equal((await result).error.message, RELOAD_ERROR)
  assert.ok(
    (await prompt.call('answer', {identityId: idA, accept: true})).error
  )
  await m.manage('assign', {host: 'b.test', id: idA})
  await allow(m, idA, 'b.test', 'getPublicKey')
  await m.manage('remove', {id: idA})
  const state = await m.manage('state')
  assert.equal(state.sites['b.test'].identityId, null)
  assert.equal(state.sites['a.test'].identityId, idB)
  assert.equal(state.policies[idA], undefined)
  assert.deepEqual(
    state.identities.map(item => item.id),
    [idB]
  )
})

for (const protocol of ['nip04', 'nip44'])
  test(`${protocol} isolates two identities communicating with the same peer`, async () => {
    const m = await setup()
    for (const [host, id] of [
      ['a.test', idA],
      ['b.test', idB]
    ]) {
      await m.manage('assign', {host, id})
      for (const action of ['encrypt', 'decrypt'])
        await allow(m, id, host, `${protocol}.${action}`)
      const page = await m.page(host)
      const ciphertext = await page.call(`${protocol}.encrypt`, {
        peer,
        plaintext: host
      })
      let incoming
      if (protocol === 'nip04') {
        assert.equal(
          await nip04.decrypt(hexToBytes(keyPeer), id, ciphertext),
          host
        )
        incoming = await nip04.encrypt(hexToBytes(keyPeer), id, 'reply')
      } else {
        const key = nip44.v2.utils.getConversationKey(hexToBytes(keyPeer), id)
        assert.equal(nip44.v2.decrypt(ciphertext, key), host)
        incoming = nip44.v2.encrypt('reply', key)
      }
      assert.equal(
        await page.call(`${protocol}.decrypt`, {peer, ciphertext: incoming}),
        'reply'
      )
      const wrong =
        protocol === 'nip44'
          ? nip44.v2.encrypt(
              'wrong',
              nip44.v2.utils.getConversationKey(
                hexToBytes(keyPeer),
                id === idA ? idB : idA
              )
            )
          : 'invalid'
      assert.ok(
        (await page.call(`${protocol}.decrypt`, {peer, ciphertext: wrong}))
          .error
      )
    }
  })

test('forged approvals and website management attempts cannot authorize requests', async () => {
  const m = await setup()
  const page = await m.page('evil.test')
  assert.ok(
    (
      await m.signer.handle(
        {channel: 'manage', action: 'export', args: {id: idA}},
        page.sender
      )
    ).error
  )
  const result = page.call('getPublicKey')
  const prompt = await m.prompt()
  assert.ok(
    (
      await m.signer.handle(
        {
          channel: 'prompt',
          id: prompt.id,
          action: 'answer',
          accept: true,
          identityId: idA
        },
        page.sender
      )
    ).error
  )
  assert.ok(
    (
      await m.signer.handle(
        {channel: 'prompt', id: 'stale', action: 'answer', accept: true},
        prompt.sender
      )
    ).error
  )
  assert.ok(
    (
      await m.signer.handle(
        {channel: 'prompt', id: prompt.id, action: 'answer', accept: true},
        {...prompt.sender, tab: {windowId: 999}}
      )
    ).error
  )
  m.signer.windowRemoved(999)
  assert.equal((await prompt.call('get')).host, 'evil.test')
  await prompt.call('answer', {identityId: idA, accept: true})
  assert.equal(await result, idA)
})

test('closing the correct window cancels the request and releases the queue', async () => {
  const m = await setup()
  const page = await m.page('a.test')
  const first = page.call('getPublicKey')
  const second = page.call('getPublicKey')
  const prompt = await m.prompt()
  await m.api.windows.remove(prompt.windowId)
  assert.equal((await first).error.message, 'denied')
  const next = await m.prompt()
  await next.call('answer', {identityId: idA, accept: true})
  assert.equal(await second, idA)
})

test('window/storage/operation failures do not leave request queue locked', async () => {
  const m = await setup()
  const page = await m.page('a.test')
  m.api.windows.failCreate = true
  assert.match(
    (await page.call('getPublicKey')).error.message,
    /Operation failed/
  )
  m.api.windows.failCreate = false
  const result = page.call('getPublicKey')
  const prompt = await m.prompt()
  m.api.storage.local.failSet = true
  assert.match(
    (await prompt.call('answer', {identityId: idA, accept: true})).error
      .message,
    /Operation failed/
  )
  assert.equal(m.api.storage.local.data[STORAGE_KEY].sites['a.test'], undefined)
  m.api.storage.local.failSet = false
  await prompt.call('answer', {identityId: idA, accept: true})
  assert.equal(await result, idA)
  await allow(m, idA, 'a.test', 'nip44.decrypt')
  assert.ok(
    (await page.call('nip44.decrypt', {peer, ciphertext: 'invalid'})).error
  )
  await allow(m, idA, 'a.test', 'getPublicKey')
  assert.equal(await page.call('getPublicKey'), idA)
})

test('external extension callers are separate from websites and cannot manage keys', async () => {
  const m = await setup()
  await m.manage('assign', {host: 'extension:other', id: idB})
  await allow(m, idB, 'extension:other', 'getPublicKey')
  assert.equal(
    await m.signer.handle({type: 'getPublicKey'}, {id: 'other'}, true),
    idB
  )
  assert.ok(
    (
      await m.signer.handle(
        {channel: 'manage', action: 'export', args: {id: idA}},
        {id: 'other'},
        true
      )
    ).error
  )
})

test('a migration verification mismatch never deletes legacy policies on retry', async () => {
  const policies = {
    'a.test': {true: {getPublicKey: {conditions: {}, created_at: 1}}}
  }
  const storage = memory({private_key: keyA, policies})
  const set = storage.set.bind(storage)
  storage.set = async values => {
    const altered = clone(values)
    altered[STORAGE_KEY].policies[idA] = {}
    await set(altered)
  }
  await assert.rejects(new IdentityStore(storage).read(), /verify migration/)
  await assert.rejects(new IdentityStore(storage).read(), /Unmigrated/)
  assert.equal(storage.data.private_key, keyA)
  assert.deepEqual(storage.data.policies, policies)
})

test('invalid versioned storage is preserved even when null or an array', async () => {
  for (const record of [
    null,
    [],
    {version: 1, identities: [], sites: {}, policies: {}}
  ]) {
    const storage = memory({[STORAGE_KEY]: record})
    await assert.rejects(new IdentityStore(storage).read())
    assert.deepEqual(storage.data[STORAGE_KEY], record)
  }
})

test('removing an identity selected in an unassigned prompt cancels the request', async () => {
  const m = await setup()
  const page = await m.page('new.test')
  const result = page.call('getPublicKey')
  const prompt = await m.prompt()
  assert.equal(await prompt.call('preview', {identityId: idA}), idA)
  await m.manage('remove', {id: idA})
  assert.equal((await result).error.message, RELOAD_ERROR)
  assert.equal((await m.manage('state')).sites['new.test'], undefined)
})

test('extension approval pages without sender.tab authenticate against their window', async () => {
  const m = await setup()
  const page = await m.page('new.test')
  const result = page.call('getPublicKey')
  const prompt = await m.prompt()
  const sender = {id: m.api.runtime.id, url: prompt.sender.url}
  const message = {channel: 'prompt', id: prompt.id, windowId: prompt.windowId}
  assert.equal(
    (await m.signer.handle({...message, action: 'get'}, sender)).host,
    'new.test'
  )
  assert.equal(
    await m.signer.handle(
      {...message, action: 'answer', identityId: idB, accept: true},
      sender
    ),
    true
  )
  assert.equal(await result, idB)
})

test('duplicate approval replies cannot overwrite the accepted choice', async () => {
  const m = await setup()
  const page = await m.page('new.test')
  const result = page.call('getPublicKey')
  const prompt = await m.prompt()
  const replies = await Promise.all([
    prompt.call('answer', {identityId: idA, accept: true}),
    prompt.call('answer', {identityId: idB, accept: true})
  ])
  assert.equal(replies.filter(reply => reply === true).length, 1)
  assert.equal(await result, idA)
  assert.equal((await m.manage('state')).sites['new.test'].identityId, idA)
})

test('remembered approval derives kind restrictions from the original event', async () => {
  const m = await setup()
  const page = await m.page('new.test')
  const result = page.call('signEvent', {event})
  const prompt = await m.prompt()
  await prompt.call('answer', {
    identityId: idA,
    accept: true,
    conditions: {kinds: {99: true}}
  })
  assert.ok(verifyEvent(await result))
  const state = await m.signer.store.read()
  assert.equal(
    permissionStatus(state, idA, 'new.test', 'signEvent', {kind: 1}),
    true
  )
  assert.equal(
    permissionStatus(state, idA, 'new.test', 'signEvent', {kind: 99}),
    undefined
  )
})

test('tab cleanup removes only that tab’s document registrations', async () => {
  const m = await setup()
  await m.page('a.test', 'first', 1)
  await m.page('b.test', 'second', 2)
  await m.signer.tabRemoved(1)
  const keys = Object.keys(m.api.storage.session.data)
  assert.equal(keys.length, 1)
  assert.ok(keys[0].startsWith('document:2:'))
})

test('generated identities get unique default names and can be renamed without changing their keys', async () => {
  const m = mock()
  const first = await m.manage('add', {generate: true})
  const second = await m.manage('add', {generate: true})
  assert.notEqual(first, second)
  let state = await m.manage('state')
  assert.deepEqual(state.identities.map(identity => identity.name).sort(), [
    'Identity 1',
    'Identity 2'
  ])
  const exported = await m.manage('export', {id: first})
  assert.equal(parseSecret(exported).id, first)
  await m.manage('rename', {id: first, name: '  Personal  '})
  state = await m.manage('state')
  assert.equal(
    state.identities.find(identity => identity.id === first).name,
    'Personal'
  )
  assert.equal(await m.manage('export', {id: first}), exported)
  await assert.rejects(m.manage('rename', {id: first, name: ' '}), /name/)
})

test('website identity comes from the browser sender, ignoring a forged host field', async () => {
  const m = await setup()
  await m.manage('assign', {host: 'trusted.test', id: idA})
  await allow(m, idA, 'trusted.test', 'getPublicKey')
  const page = await m.page('other.test')
  const result = m.signer.handle(
    {
      type: 'getPublicKey',
      host: 'trusted.test',
      revision: page.registration.revision
    },
    page.sender
  )
  const prompt = await m.prompt()
  assert.equal((await prompt.call('get')).host, 'other.test')
  await prompt.call('answer', {accept: false})
  assert.equal((await result).error.message, 'denied')
})

test('storage is restricted to trusted extension contexts before requests are answered', async () => {
  const m = await setup()
  assert.equal(m.api.storage.local.accessLevel, 'TRUSTED_CONTEXTS')
})

test('failure to restrict storage fails closed without reading private keys', async () => {
  const m = mock({private_key: keyA})
  let reads = 0
  m.api.storage.local.setAccessLevel = async () => {
    throw new Error(`Failed for ${keyA}`)
  }
  m.api.storage.local.get = async () => {
    reads++
    throw new Error('Should not read')
  }
  const response = await m.signer.handle(
    {channel: 'manage', action: 'state'},
    m.ui
  )
  assert.match(response.error.message, /Operation failed/)
  assert.ok(!JSON.stringify(response).includes(keyA))
  assert.equal(reads, 0)
})

test('invalid stored nsec errors never echo key material to website or external callers', async () => {
  const nsec = nip19.nsecEncode(hexToBytes(keyA))
  const damaged = nsec.slice(0, -1) + (nsec.endsWith('q') ? 'p' : 'q')
  const initial = {
    [STORAGE_KEY]: {
      version: 1,
      identities: {[idA]: {name: 'Test', privateKey: damaged}},
      sites: {},
      policies: {}
    }
  }
  const m = mock(initial)
  const sender = {url: 'https://evil.test/', documentId: 'evil', tab: {id: 1}}
  for (const response of [
    await m.signer.handle({channel: 'register'}, sender),
    await m.signer.handle({type: 'getPublicKey'}, {id: 'other'}, true),
    await m.signer.handle({channel: 'manage', action: 'state'}, m.ui)
  ]) {
    assert.ok(response.error)
    for (const secret of [keyA, nsec, damaged, damaged.slice(0, -1)])
      assert.ok(!JSON.stringify(response).includes(secret))
    assert.deepEqual(Object.keys(response.error), ['message'])
  }
})

test('unexpected storage exceptions cannot send secrets through any runtime response', async () => {
  const m = await setup()
  const page = await m.page('evil.test')
  const nsec = nip19.nsecEncode(hexToBytes(keyA))
  m.api.storage.local.get = async () => {
    throw new Error(`Internal state: ${keyA} ${nsec}`)
  }
  for (const response of [
    await page.call('getPublicKey'),
    await m.signer.handle({type: 'getPublicKey'}, {id: 'other'}, true),
    await m.signer.handle({channel: 'manage', action: 'state'}, m.ui)
  ]) {
    assert.match(response.error.message, /Operation failed/)
    assert.ok(!JSON.stringify(response).includes(keyA))
    assert.ok(!JSON.stringify(response).includes(nsec))
  }
})

test('only the own top-level options page can export a key', async () => {
  const m = await setup()
  const message = {channel: 'manage', action: 'export', args: {id: idA}}
  const senders = [
    {id: m.api.runtime.id, url: m.api.runtime.getURL('popup.html')},
    {id: m.api.runtime.id, url: m.api.runtime.getURL('prompt.html')},
    {id: 'other-extension', url: m.ui.url},
    {...m.ui, frameId: 1},
    {id: m.api.runtime.id, url: 'https://evil.test/options.html'},
    {id: m.api.runtime.id, url: m.ui.url + '.evil'}
  ]
  for (const sender of senders) {
    const response = await m.signer.handle(message, sender)
    assert.ok(response.error)
    assert.ok(!JSON.stringify(response).includes(keyA))
    assert.ok(!JSON.stringify(response).includes('nsec1'))
  }
  assert.equal(parseSecret(await m.manage('export', {id: idA})).id, idA)
})

test('hostile webpage parameters cannot reach key exports even with preapproved signing', async () => {
  const m = await setup()
  await m.manage('assign', {host: 'evil.test', id: idA})
  await allow(m, idA, 'evil.test', 'signEvent')
  const page = await m.page('evil.test')
  const responses = []
  for (const type of [
    'export',
    'getPrivateKey',
    'privateKey',
    'private_key',
    'identityStore',
    '__proto__',
    'constructor'
  ])
    responses.push(
      await page.call(type, {channel: 'manage', action: 'export', id: idA})
    )
  responses.push(
    await page.call('signEvent', {
      event: {...event, channel: 'manage', action: 'export', identityId: idA}
    })
  )
  const text = JSON.stringify(responses)
  assert.ok(!text.includes(keyA))
  assert.ok(!text.includes(nip19.nsecEncode(hexToBytes(keyA))))
  for (const response of responses.slice(0, -1)) assert.ok(response.error)
  assert.ok(verifyEvent(responses.at(-1)))
})

test('normal responses, notifications, and approval URLs do not contain stored private keys', async () => {
  const m = await setup()
  const notifications = []
  m.api.notifications.create = async (_, value) => {
    notifications.push(value)
  }
  await m.api.storage.local.set({notifications: true})
  await m.manage('assign', {host: 'a.test', id: idA})
  for (const type of ['getPublicKey', 'signEvent', 'nip44.encrypt'])
    await allow(m, idA, 'a.test', type)
  const page = await m.page('a.test')
  const values = [
    await m.manage('state'),
    await page.call('getPublicKey'),
    await page.call('peekPublicKey'),
    await page.call('signEvent', {event}),
    await page.call('nip44.encrypt', {peer, plaintext: 'A public test message'})
  ]
  const result = page.call('nip04.encrypt', {
    peer,
    plaintext: 'Another public test message'
  })
  const prompt = await m.prompt()
  values.push(
    await prompt.call('get'),
    await prompt.call('preview', {identityId: idA}),
    prompt.sender.url
  )
  await prompt.call('answer', {identityId: idA, accept: true})
  values.push(await result, notifications)
  const serialized = JSON.stringify(values)
  for (const key of [keyA, keyB]) {
    assert.ok(!serialized.includes(key))
    assert.ok(!serialized.includes(nip19.nsecEncode(hexToBytes(key))))
  }
})

// A controllable relay/signer: transport envelopes and RPC results use real
// signatures and NIP-44 encryption, without external network dependencies.
class RemoteNetwork {
  constructor() {
    this.subscriptions = new Set()
    this.requests = []
    this.pools = []
    this.auto = true
    this.holdMethods = new Set()
    this.failOpen = false
    this.failPublish = false
    this.switchTo = null
    this.transform = event => event
    this.sessionFactory = (credentials, options) => {
      const pool = this.pool()
      return new RemoteSession(credentials, {...options, pool})
    }
  }
  pool() {
    const subscriptions = []
    const network = this
    const pool = {
      destroyed: false,
      async ensureRelay(url) {
        if (network.failOpen)
          throw new Error('Network failure with secret payload')
        return {
          subscribe(filters, handlers) {
            const sub = {
              filters,
              handlers,
              close() {
                network.subscriptions.delete(sub)
                handlers.onclose?.()
              }
            }
            subscriptions.push(sub)
            network.subscriptions.add(sub)
            return sub
          },
          async publish(envelope) {
            if (network.failPublish)
              throw new Error('Publish failed with secret payload')
            assert.ok(verifyEvent(envelope))
            const key = nip44.v2.utils.getConversationKey(
              hexToBytes(keyB),
              envelope.pubkey
            )
            const rpc = JSON.parse(nip44.v2.decrypt(envelope.content, key))
            const request = {...rpc, client: envelope.pubkey, relay: url}
            network.requests.push(request)
            if (network.auto && !network.holdMethods.has(rpc.method))
              setImmediate(async () => {
                let result
                switch (rpc.method) {
                  case 'connect':
                    result = 'ack'
                    break
                  case 'get_public_key':
                    result = idA
                    break
                  case 'switch_relays':
                    result = JSON.stringify(network.switchTo)
                    break
                  case 'logout':
                    result = 'ack'
                    break
                  case 'ping':
                    result = 'pong'
                    break
                  case 'sign_event':
                    result = JSON.stringify(
                      network.transform(
                        finalizeEvent(
                          JSON.parse(rpc.params[0]),
                          hexToBytes(keyA)
                        )
                      )
                    )
                    break
                  case 'nip04_encrypt':
                    result = await nip04.encrypt(
                      keyA,
                      rpc.params[0],
                      rpc.params[1]
                    )
                    break
                  case 'nip04_decrypt':
                    result = await nip04.decrypt(
                      keyA,
                      rpc.params[0],
                      rpc.params[1]
                    )
                    break
                  case 'nip44_encrypt':
                    result = nip44.v2.encrypt(
                      rpc.params[1],
                      nip44.v2.utils.getConversationKey(
                        hexToBytes(keyA),
                        rpc.params[0]
                      )
                    )
                    break
                  case 'nip44_decrypt':
                    result = nip44.v2.decrypt(
                      rpc.params[1],
                      nip44.v2.utils.getConversationKey(
                        hexToBytes(keyA),
                        rpc.params[0]
                      )
                    )
                    break
                  default:
                    network.reply(request, {
                      error:
                        'Unsupported remote method including sensitive payload'
                    })
                    return
                }
                network.reply(request, {result})
              })
            return 'ok'
          }
        }
      },
      destroy() {
        this.destroyed = true
        subscriptions.forEach(sub => sub.close())
      }
    }
    this.pools.push(pool)
    return pool
  }
  reply(request, payload, signingKey = keyB, changes = {}) {
    const key = nip44.v2.utils.getConversationKey(
      hexToBytes(signingKey),
      request.client
    )
    const envelope = clone(
      finalizeEvent(
        {
          kind: 24133,
          created_at: Math.floor(Date.now() / 1000),
          tags: [['p', request.client]],
          content: nip44.v2.encrypt(
            JSON.stringify({id: request.id, ...payload}),
            key
          ),
          ...changes
        },
        hexToBytes(signingKey)
      )
    )
    this.emit(envelope)
    return envelope
  }
  emit(envelope) {
    for (const sub of [...this.subscriptions])
      sub.handlers.onevent(clone(envelope))
  }
  deviceScans(uri, secret) {
    const url = new URL(uri)
    return this.reply(
      {id: 'connect-response', client: url.hostname},
      {result: secret ?? url.searchParams.get('secret')}
    )
  }
}
const bunker = `bunker://${idB}?relay=${encodeURIComponent(
  DEFAULT_RELAY
)}&secret=one-use`
const credentials = () => ({
  clientKey: keyPeer,
  signerPubkey: idB,
  relays: [DEFAULT_RELAY],
  userPubkey: idA,
  type: 'remote',
  name: 'Device'
})
async function until(check) {
  for (let i = 0; i < 300; i++) {
    if (await check()) return
    await new Promise(resolve => setImmediate(resolve))
  }
  throw new Error('Expected asynchronous state was not reached')
}
async function remoteSetup() {
  const network = new RemoteNetwork()
  const m = mock(undefined, {sessionFactory: network.sessionFactory})
  await m.signer.store.addRemote(idA, credentials(), 'Device')
  return {m, network}
}

test('NIP-46 validates connection strings and secure relay URLs', () => {
  assert.equal(DEFAULT_RELAY, 'wss://relay.nostr.com')
  assert.equal(bunkerPointer(bunker).signerPubkey, idB)
  for (const input of [
    '',
    'https://example.com',
    `bunker://${idB}`,
    `bunker://${idB}?relay=ws://localhost`,
    `bunker://${idB}/invalid?relay=wss://example.com`
  ])
    assert.throws(() => bunkerPointer(input), /valid bunker/)
  for (const urls of [
    [],
    ['https://example.com'],
    ['wss://name:password@example.com'],
    ['wss://example.com/#secret']
  ])
    assert.throws(() => relayURLs(urls))
  const first = newPairing([DEFAULT_RELAY])
  const second = newPairing([DEFAULT_RELAY])
  assert.notEqual(first.credentials.clientKey, second.credentials.clientKey)
  assert.notEqual(
    new URL(first.uri).searchParams.get('secret'),
    new URL(second.uri).searchParams.get('secret')
  )
})

test('both NIP-46 pairing directions discover the user key separately from signer key', async () => {
  for (const display of [false, true]) {
    const network = new RemoteNetwork()
    const pair = newPairing([DEFAULT_RELAY], display ? '' : bunker)
    const session = network.sessionFactory(pair.credentials, {})
    try {
      const result = session.pair(display)
      if (display) {
        await until(() => network.subscriptions.size)
        network.deviceScans(pair.uri, 'incorrect-secret')
        assert.equal(session.credentials.signerPubkey, undefined)
        network.deviceScans(pair.uri)
      }
      assert.equal(await result, idA)
      assert.equal(session.credentials.signerPubkey, idB)
      assert.equal(session.credentials.secret, undefined)
      if (!display)
        assert.deepEqual(network.requests[0].params.slice(0, 3), [
          idB,
          'one-use',
          ''
        ])
    } finally {
      session.close()
    }
    assert.ok(network.pools.every(pool => pool.destroyed))
  }
})

test('pairing management persists credentials, rejects duplicates, and restricts callers', async () => {
  const {m, network} = await remoteSetup()
  const first = await m.manage('pairStart', {bunker})
  await until(() => m.signer.remote.pairing?.status === 'error')
  assert.match(
    (await m.manage('pairState', {id: first.id})).errorMessage,
    /already been added/
  )
  await m.manage('remove', {id: idA})
  const next = await m.manage('pairStart', {
    relays: [DEFAULT_RELAY],
    name: 'Hardware'
  })
  await until(() => network.subscriptions.size)
  network.deviceScans(next.uri)
  await until(() => m.signer.remote.pairing?.status === 'paired')
  const saved = await m.signer.store.read(state => state.identities[idA])
  assert.equal(saved.name, 'Hardware')
  assert.equal(saved.signerPubkey, idB)
  assert.equal(saved.userPubkey, idA)
  assert.equal(saved.secret, undefined)
  const publicData = JSON.stringify(await m.manage('state'))
  assert.ok(!publicData.includes(saved.clientKey))
  assert.ok(!publicData.includes('privateKey'))
  await assert.rejects(
    m.manage('export', {id: idA}),
    /stay on the signing device/
  )
  const page = await m.page('untrusted.test')
  for (const sender of [
    page.sender,
    {...m.ui, frameId: 1},
    {...m.ui, url: m.api.runtime.getURL('popup.html')}
  ]) {
    const response = await m.signer.handle(
      {channel: 'manage', action: 'pairStart', args: {bunker}},
      sender
    )
    assert.ok(response.error)
  }
  m.restart()
  assert.equal((await m.manage('state')).identities[0].type, 'remote')
})

test('cancelled, expired, and unreachable pairings leave no identity or live session', async t => {
  const network = new RemoteNetwork()
  const m = mock(undefined, {sessionFactory: network.sessionFactory})
  const pair = await m.manage('pairStart', {relays: [DEFAULT_RELAY]})
  await until(() => network.subscriptions.size)
  await m.manage('pairCancel', {id: pair.id})
  network.deviceScans(pair.uri)
  assert.deepEqual((await m.manage('state')).identities, [])
  assert.equal(network.subscriptions.size, 0)
  t.mock.timers.enable({apis: ['setTimeout']})
  const expired = await m.manage('pairStart', {relays: [DEFAULT_RELAY]})
  t.mock.timers.tick(240000)
  await until(() => m.signer.remote.pairing?.status === 'error')
  assert.match(
    (await m.manage('pairState', {id: expired.id})).errorMessage,
    /expired/
  )
  t.mock.timers.reset()
  network.failOpen = true
  await m.manage('pairStart', {bunker})
  await until(() => m.signer.remote.pairing?.status === 'error')
  assert.match(m.signer.remote.pairing.error, /Unable to connect/)
  assert.deepEqual((await m.manage('state')).identities, [])
  assert.ok(network.pools.every(pool => pool.destroyed))
})

test('remote website permissions block transmission and previews do not invoke device operations', async () => {
  const {m, network} = await remoteSetup()
  const page = await m.page('remote.test')
  const result = page.call('nip44.encrypt', {
    peer,
    plaintext: 'private message'
  })
  const approval = await m.prompt()
  assert.equal(await approval.call('preview', {identityId: idA}), null)
  assert.equal(network.requests.length, 0)
  await approval.call('answer', {identityId: idA, accept: false})
  assert.match((await result).error.message, /denied/)
  await m.manage('assign', {id: idA, host: 'remote.test'})
  const reloaded = await m.page('remote.test', 'new-document')
  await m.signer.store.mutate(state =>
    updatePermission(state, idA, 'remote.test', 'signEvent', false, {})
  )
  assert.match(
    (await reloaded.call('signEvent', {event})).error.message,
    /denied/
  )
  assert.equal(network.requests.length, 0)
})

test('all cryptographic NIP-07 methods use the remote user key and survive a worker restart', async () => {
  const {m, network} = await remoteSetup()
  await m.manage('assign', {id: idA, host: 'remote.test'})
  for (const type of [
    'getPublicKey',
    'signEvent',
    'nip04.encrypt',
    'nip04.decrypt',
    'nip44.encrypt',
    'nip44.decrypt'
  ])
    await allow(m, idA, 'remote.test', type)
  m.restart()
  const page = await m.page('remote.test')
  assert.equal(await page.call('getPublicKey'), idA)
  assert.equal(network.requests.length, 0)
  const signed = await page.call('signEvent', {event})
  assert.equal(signed.pubkey, idA)
  assert.ok(verifyEvent(signed))
  for (const nip of ['nip04', 'nip44']) {
    const encrypted = await page.call(`${nip}.encrypt`, {
      peer,
      plaintext: 'hello remote'
    })
    const plaintext =
      nip === 'nip04'
        ? await nip04.decrypt(keyPeer, idA, encrypted)
        : nip44.v2.decrypt(
            encrypted,
            nip44.v2.utils.getConversationKey(hexToBytes(keyPeer), idA)
          )
    assert.equal(plaintext, 'hello remote')
    const incoming =
      nip === 'nip04'
        ? await nip04.encrypt(keyPeer, idA, 'hello extension')
        : nip44.v2.encrypt(
            'hello extension',
            nip44.v2.utils.getConversationKey(hexToBytes(keyPeer), idA)
          )
    assert.equal(
      await page.call(`${nip}.decrypt`, {peer, ciphertext: incoming}),
      'hello extension'
    )
  }
  assert.ok(network.pools.every(pool => pool.destroyed))
  assert.equal(m.signer.remote.jobs.size, 0)
})

test('remote signing rejects valid signatures on changed fields or another user key', async () => {
  const {m, network} = await remoteSetup()
  await m.manage('assign', {id: idA, host: 'remote.test'})
  await allow(m, idA, 'remote.test', 'signEvent')
  const page = await m.page('remote.test')
  for (const field of [
    'content',
    'kind',
    'created_at',
    'tags',
    'pubkey',
    'sig'
  ]) {
    network.transform = signed => {
      if (field === 'pubkey') return finalizeEvent({...event}, hexToBytes(keyB))
      if (field === 'sig') return {...signed, sig: '00'.repeat(64)}
      const value =
        field === 'content'
          ? 'tampered'
          : field === 'tags'
          ? [['x', 'changed']]
          : signed[field] + 1
      return finalizeEvent({...signed, [field]: value}, hexToBytes(keyA))
    }
    assert.match(
      (await page.call('signEvent', {event})).error.message,
      /invalid or changed/
    )
  }
})

test('response correlation, authentication challenges, forged and duplicate responses', async () => {
  const network = new RemoteNetwork()
  network.auto = false
  const auth = []
  const session = network.sessionFactory(credentials(), {
    onauth: url => auth.push(url)
  })
  try {
    await session.open()
    const first = session.request('first')
    const second = session.request('second')
    const [a, b] = network.requests
    let settled = false
    first.then(() => {
      settled = true
    })
    network.reply(a, {result: 'wrong author'}, keyA)
    const bad = network.reply(
      {...a, id: 'unknown'},
      {result: 'unknown request'}
    )
    network.emit({...bad, id: '0'.repeat(64)})
    network.reply(a, {result: 'old'}, keyB, {created_at: session.started - 1})
    network.reply(a, {result: 'wrong recipient'}, keyB, {tags: [['p', idB]]})
    network.reply(a, {result: 'auth_url', error: 'javascript:alert(1)'})
    network.reply(a, {result: 'auth_url', error: 'https://signer.example/auth'})
    assert.deepEqual(auth, ['https://signer.example/auth'])
    await new Promise(resolve => setImmediate(resolve))
    assert.equal(settled, false)
    network.reply(b, {result: 'two'})
    network.reply(a, {result: 'one'})
    network.reply(a, {result: 'duplicate'})
    assert.deepEqual(await Promise.all([first, second]), ['one', 'two'])
    const denied = session.request('denied')
    network.reply(network.requests.at(-1), {error: `sensitive ${keyA}`})
    await assert.rejects(
      denied,
      error => !error.message.includes(keyA) && /denied/.test(error.message)
    )
    assert.equal(session.pending.size, 0)
  } finally {
    session.close()
  }
})

test('request timeout, malformed requests, publication failure and abort clean up RPC listeners', async () => {
  const network = new RemoteNetwork()
  network.auto = false
  const controller = new AbortController()
  const session = network.sessionFactory(credentials(), {
    signal: controller.signal
  })
  try {
    await session.open()
    await assert.rejects(session.request('ping', [], 5), /timed out/)
    assert.equal(session.pending.size, 0)
    await assert.rejects(session.request('invalid', [1n]))
    assert.equal(session.pending.size, 0)
    network.failPublish = true
    await assert.rejects(session.request('ping'), /Unable to send/)
    network.failPublish = false
    const waiting = session.request('ping')
    controller.abort()
    await assert.rejects(waiting, /cancelled/)
    assert.equal(session.pending.size, 0)
    assert.equal(network.subscriptions.size, 0)
  } finally {
    session.close()
  }
})

test('relay switching persists secure replacements before forwarding requests', async () => {
  const {m, network} = await remoteSetup()
  network.switchTo = ['wss://replacement.example']
  await m.manage('assign', {id: idA, host: 'remote.test'})
  await allow(m, idA, 'remote.test', 'signEvent')
  const page = await m.page('remote.test')
  assert.ok(verifyEvent(await page.call('signEvent', {event})))
  assert.equal(
    network.requests.find(request => request.method === 'sign_event').relay,
    'wss://replacement.example/'
  )
  assert.deepEqual((await m.signer.store.read()).identities[idA].relays, [
    'wss://replacement.example/'
  ])
  network.switchTo = ['https://unsafe.example']
  assert.match((await page.call('signEvent', {event})).error.message, /wss/)
})

test('removal, reassignment and closing remote waiting windows cancel outstanding requests', async () => {
  for (const action of ['remove', 'assign', 'close']) {
    const {m, network} = await remoteSetup()
    await m.manage('add', {key: keyB})
    await m.manage('assign', {id: idA, host: 'remote.test'})
    await allow(m, idA, 'remote.test', 'signEvent')
    const page = await m.page('remote.test')
    network.holdMethods.add('sign_event')
    const result = page.call('signEvent', {event})
    await until(() =>
      network.requests.some(item => item.method === 'sign_event')
    )
    const request = network.requests.find(item => item.method === 'sign_event')
    if (action === 'close') {
      const job = [...m.signer.remote.jobs.values()][0]
      network.reply(request, {
        result: 'auth_url',
        error: 'https://signer.example/auth'
      })
      await until(() => job.windowId !== undefined)
      m.signer.windowRemoved(job.windowId)
    } else
      await m.manage(action, {
        id: action === 'assign' ? idB : idA,
        host: 'remote.test'
      })
    network.reply(request, {
      result: JSON.stringify(finalizeEvent({...event}, hexToBytes(keyA)))
    })
    assert.ok((await result).error)
    assert.equal(m.signer.remote.jobs.size, 0)
    if (action === 'remove') {
      assert.ok(!JSON.stringify(m.api.storage.local.data).includes(keyPeer))
      // Finish courtesy logout without waiting on its bounded timeout.
      await until(() => network.requests.some(item => item.method === 'logout'))
      network.reply(
        network.requests.find(item => item.method === 'logout'),
        {result: 'ack'}
      )
    }
  }
})

test('version-one migration preserves local identities and permissions when adding remote identities', async () => {
  const policies = {
    [idB]: {
      'local.test': {true: {getPublicKey: {conditions: {}, created_at: 1}}}
    }
  }
  const original = {
    version: 1,
    identities: {[idB]: {privateKey: keyB, name: 'Existing'}},
    sites: {'local.test': {identityId: idB, revision: 4}},
    policies
  }
  const m = mock({[STORAGE_KEY]: original})
  await m.signer.store.addRemote(idA, credentials(), 'Device')
  const stored = await m.signer.store.read()
  assert.equal(stored.version, 2)
  assert.deepEqual(clone(stored.sites), original.sites)
  assert.deepEqual(clone(stored.policies), original.policies)
  assert.equal(stored.identities[idB].privateKey, keyB)
  assert.equal(stored.identities[idB].type, 'local')
})

test('migration verification tolerates Chrome storage reordering object properties', async () => {
  const storage = memory({private_key: keyB})
  const get = storage.get.bind(storage)
  const reordered = value =>
    Array.isArray(value)
      ? value.map(reordered)
      : value && typeof value === 'object'
      ? Object.fromEntries(
          Object.keys(value)
            .sort()
            .map(key => [key, reordered(value[key])])
        )
      : value
  storage.get = async keys => reordered(await get(keys))
  const store = new IdentityStore(storage)
  assert.equal((await store.read()).identities[idB].privateKey, keyB)
  assert.equal(storage.data.private_key, undefined)
})

test('remote authentication window status and cancellation require the exact trusted window', async () => {
  const {m, network} = await remoteSetup()
  await m.manage('assign', {id: idA, host: 'remote.test'})
  await allow(m, idA, 'remote.test', 'signEvent')
  const page = await m.page('remote.test')
  network.holdMethods.add('sign_event')
  const result = page.call('signEvent', {event})
  await until(() =>
    network.requests.some(request => request.method === 'sign_event')
  )
  const job = [...m.signer.remote.jobs.values()][0]
  network.reply(
    network.requests.find(request => request.method === 'sign_event'),
    {result: 'auth_url', error: 'https://signer.example/auth'}
  )
  await until(() => job.windowId !== undefined)
  const sender = {
    id: m.api.runtime.id,
    url: `${m.api.runtime.getURL('remote.html')}?id=${job.id}`,
    tab: {windowId: job.windowId}
  }
  const message = {channel: 'remote-work', id: job.id, action: 'state'}
  for (const untrusted of [
    page.sender,
    m.ui,
    {...sender, frameId: 1},
    {...sender, tab: {windowId: -1}},
    {...sender, id: 'other-extension'}
  ])
    assert.ok((await m.signer.handle(message, untrusted)).error)
  const state = await m.signer.handle(message, sender)
  assert.equal(state.host, 'remote.test')
  assert.ok(!JSON.stringify(state).includes(keyPeer))
  assert.ok(!JSON.stringify(state).includes(event.content))
  assert.ok(
    (
      await m.signer.handle(
        {channel: 'manage', action: 'export', args: {id: idA}},
        sender
      )
    ).error
  )
  assert.equal(
    await m.signer.handle({...message, action: 'cancel'}, sender),
    true
  )
  assert.match((await result).error.message, /cancelled/)
})

test('website bridge expires interrupted requests and ignores late responses', async () => {
  const timers = new Map()
  let next = 1
  let receive
  const window = {
    postMessage() {},
    addEventListener(type, callback) {
      receive = callback
    }
  }
  runInNewContext(readFileSync('extension/nostr-provider.js', 'utf8'), {
    window,
    document: {addEventListener() {}},
    crypto: {randomUUID: () => String(next++)},
    setTimeout(callback, duration) {
      const id = next++
      timers.set(id, {callback, duration})
      return id
    },
    clearTimeout(id) {
      timers.delete(id)
    }
  })
  const pending = window.nostr.getPublicKey()
  const failure = assert.rejects(pending, /Request expired/)
  const id = Object.keys(window.nostr._requests)[0]
  const timer = [...timers.values()][0]
  assert.equal(timer.duration, 600000)
  timer.callback()
  await failure
  assert.equal(Object.keys(window.nostr._requests).length, 0)
  receive({source: window, data: {id, ext: 'nos2x', response: idA}})
  assert.equal(Object.keys(window.nostr._requests).length, 0)
  const normal = window.nostr.getPublicKey()
  const normalId = Object.keys(window.nostr._requests)[0]
  const normalTimer = window.nostr._requests[normalId].timer
  receive({source: window, data: {id: normalId, ext: 'nos2x', response: idA}})
  assert.equal(await normal, idA)
  assert.equal(timers.has(normalTimer), false)
})

test('approved remote requests run without opening a waiting window', async () => {
  const {m, network} = await remoteSetup()
  await m.manage('assign', {id: idA, host: 'quiet.test'})
  await allow(m, idA, 'quiet.test', 'signEvent')
  await allow(m, idA, 'quiet.test', 'nip44.encrypt')
  let opened = 0
  m.api.windows.create = async () => {
    opened++
    throw new Error('Unexpected window')
  }
  const page = await m.page('quiet.test')
  assert.ok(verifyEvent(await page.call('signEvent', {event})))
  assert.equal(
    typeof (await page.call('nip44.encrypt', {
      peer,
      plaintext: 'quiet encryption'
    })),
    'string'
  )
  assert.equal(opened, 0)
  assert.ok(network.pools.every(pool => pool.destroyed))
})

test('authentication challenges open one window and clean it up after signing', async () => {
  const {m, network} = await remoteSetup()
  await m.manage('assign', {id: idA, host: 'auth.test'})
  await allow(m, idA, 'auth.test', 'signEvent')
  network.holdMethods.add('sign_event')
  const page = await m.page('auth.test')
  const result = page.call('signEvent', {event})
  await until(() =>
    network.requests.some(request => request.method === 'sign_event')
  )
  assert.equal(m.windows.size, 0)
  const request = network.requests.find(
    request => request.method === 'sign_event'
  )
  const challenge = {result: 'auth_url', error: 'https://signer.example/auth'}
  network.reply(request, challenge)
  network.reply(request, challenge)
  await until(() => m.windows.size === 1)
  const job = [...m.signer.remote.jobs.values()][0]
  assert.equal(job.authURL, challenge.error)
  network.reply(request, {
    result: JSON.stringify(finalizeEvent({...event}, hexToBytes(keyA)))
  })
  assert.ok(verifyEvent(await result))
  assert.equal(m.windows.size, 0)
})

test('authentication windows created after a response are still closed', async () => {
  const {m, network} = await remoteSetup()
  await m.manage('assign', {id: idA, host: 'auth.test'})
  await allow(m, idA, 'auth.test', 'signEvent')
  network.holdMethods.add('sign_event')
  const create = m.api.windows.create.bind(m.api.windows)
  let completeCreation
  m.api.windows.create = options =>
    new Promise(resolve => {
      completeCreation = async () => resolve(await create(options))
    })
  const page = await m.page('auth.test')
  const result = page.call('signEvent', {event})
  await until(() =>
    network.requests.some(request => request.method === 'sign_event')
  )
  const request = network.requests.find(
    request => request.method === 'sign_event'
  )
  network.reply(request, {
    result: 'auth_url',
    error: 'https://signer.example/auth'
  })
  network.reply(request, {
    result: JSON.stringify(finalizeEvent({...event}, hexToBytes(keyA)))
  })
  await completeCreation()
  assert.ok(verifyEvent(await result))
  assert.equal(m.windows.size, 0)
})
