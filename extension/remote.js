import {bytesToHex, hexToBytes} from '@noble/hashes/utils.js'
import {
  generateSecretKey,
  getPublicKey,
  finalizeEvent,
  validateEvent,
  verifyEvent
} from 'nostr-tools/pure'
import {SimplePool} from 'nostr-tools/pool'
import * as nip44 from 'nostr-tools/nip44'
import {SafeError} from './errors'

export const DEFAULT_RELAY = 'wss://relay.nostr.com'
export const REMOTE_TIMEOUT = 240000
export const isPublicKey = value =>
  typeof value === 'string' && /^[a-f0-9]{64}$/.test(value)
export function relayURLs(values) {
  if (!Array.isArray(values) || !values.length || values.length > 10)
    throw new SafeError('Enter between one and ten secure WebSocket relays')
  return [
    ...new Set(
      values.map(value => {
        try {
          const url = new URL(value)
          if (
            url.protocol !== 'wss:' ||
            !url.hostname ||
            url.username ||
            url.password ||
            url.hash
          )
            throw new Error()
          return url.href
        } catch (_) {
          throw new SafeError(
            'Relay URLs must use wss:// without credentials or fragments'
          )
        }
      })
    )
  ]
}
export function bunkerPointer(input) {
  try {
    const url = new URL(input.trim())
    if (
      url.protocol !== 'bunker:' ||
      !isPublicKey(url.hostname) ||
      (url.pathname && url.pathname !== '/') ||
      url.username ||
      url.password ||
      url.port ||
      url.hash
    )
      throw new Error()
    return {
      signerPubkey: url.hostname,
      relays: relayURLs(url.searchParams.getAll('relay')),
      secret: url.searchParams.get('secret') || ''
    }
  } catch (_) {
    throw new SafeError(
      'Enter a valid bunker:// connection string with secure relays'
    )
  }
}
export function newPairing(relays, bunker) {
  const clientKey = bytesToHex(generateSecretKey())
  const secret = crypto.randomUUID()
  const pointer = bunker
    ? bunkerPointer(bunker)
    : {relays: relayURLs(relays), secret}
  const query = new URLSearchParams({secret, name: 'nos2x'})
  pointer.relays.forEach(url => query.append('relay', url))
  return {
    credentials: {clientKey, ...pointer},
    uri: bunker
      ? ''
      : `nostrconnect://${getPublicKey(hexToBytes(clientKey))}?${query}`
  }
}

// Each session owns its sockets and subscriptions. Closing it rejects every RPC,
// including requests interrupted by identity changes, timeouts, and cancellation.
export class RemoteSession {
  constructor(
    credentials,
    {
      signal,
      onauth = () => {},
      pool = new SimplePool({enableReconnect: false})
    } = {}
  ) {
    this.credentials = credentials
    this.pool = pool
    this.onauth = onauth
    this.pending = new Map()
    this.subscriptions = []
    this.relays = []
    this.closed = false
    this.started = Math.floor(Date.now() / 1000) - 5
    this.sk = hexToBytes(credentials.clientKey)
    this.pubkey = getPublicKey(this.sk)
    this.signal = signal
    this.abort = () =>
      this.close(
        signal?.reason instanceof SafeError
          ? signal.reason
          : new SafeError('Remote request cancelled; try again')
      )
    signal?.addEventListener('abort', this.abort, {once: true})
    if (signal?.aborted) this.abort()
  }
  async open() {
    const outcomes = await Promise.allSettled(
      relayURLs(this.credentials.relays).map(async url => {
        const relay = await this.pool.ensureRelay(url, {
          connectionTimeout: 5000,
          abort: this.signal
        })
        if (this.closed) return
        // Relay notices are untrusted text and must not enter application logs.
        relay.onnotice = () => {}
        const subscription = relay.subscribe(
          [{kinds: [24133], '#p': [this.pubkey], since: this.started}],
          {
            onevent: event => this.receive(event),
            onclose: () => {
              this.relays = this.relays.filter(item => item !== relay)
              if (!this.relays.length && this.opened)
                this.close(
                  new SafeError('Remote relay disconnected; try again')
                )
            }
          }
        )
        this.subscriptions.push(subscription)
        this.relays.push(relay)
      })
    )
    this.opened = true
    if (this.closed) throw new SafeError('Remote request cancelled; try again')
    if (
      !outcomes.some(item => item.status === 'fulfilled') ||
      !this.relays.length
    )
      throw new SafeError('Unable to connect to remote signer relays')
  }
  receive(event) {
    if (
      this.closed ||
      !validateEvent(event) ||
      event.kind !== 24133 ||
      event.created_at < this.started ||
      !event.tags.some(tag => tag[0] === 'p' && tag[1] === this.pubkey) ||
      !verifyEvent(event)
    )
      return
    const expected = this.credentials.signerPubkey
    if (expected && event.pubkey !== expected) return
    try {
      const key = nip44.v2.utils.getConversationKey(this.sk, event.pubkey)
      const response = JSON.parse(nip44.v2.decrypt(event.content, key))
      if (!expected) {
        if (
          response.result === this.credentials.secret &&
          !response.error &&
          this.connection
        ) {
          this.credentials.signerPubkey = event.pubkey
          this.connection.resolve()
        }
        return
      }
      const request = this.pending.get(response.id)
      if (!request) return
      if (response.result === 'auth_url') {
        if (typeof response.error !== 'string') return
        const url = new URL(response.error)
        if (url.protocol !== 'https:' || url.username || url.password) return
        this.onauth(url.href)
        return
      }
      if (response.error != null && response.error !== '')
        request.reject(
          new SafeError(
            'Remote signer denied or could not complete this request'
          )
        )
      else if (typeof response.result === 'string')
        request.resolve(response.result)
    } catch (_) {
      // Untrusted relay payloads and remote errors must never escape or be logged.
    }
  }
  wait(register, timeout = REMOTE_TIMEOUT) {
    if (this.closed)
      return Promise.reject(new SafeError('Remote session is closed'))
    return new Promise((resolve, reject) => {
      const timer = setTimeout(
        () =>
          reject(
            new SafeError(
              'Remote signer timed out; check the device and try again'
            )
          ),
        timeout
      )
      register({
        resolve: value => {
          clearTimeout(timer)
          resolve(value)
        },
        reject: error => {
          clearTimeout(timer)
          reject(error)
        }
      })
    })
  }
  async request(method, params = [], timeout = REMOTE_TIMEOUT) {
    const id = crypto.randomUUID()
    const promise = this.wait(
      handlers => this.pending.set(id, handlers),
      timeout
    )
    // Publication may fail before the caller awaits the response.
    promise.catch(() => {})
    try {
      if (this.closed) return await promise
      const content = nip44.v2.encrypt(
        JSON.stringify({id, method, params}),
        nip44.v2.utils.getConversationKey(
          this.sk,
          this.credentials.signerPubkey
        )
      )
      const event = finalizeEvent(
        {
          kind: 24133,
          created_at: Math.floor(Date.now() / 1000),
          tags: [['p', this.credentials.signerPubkey]],
          content
        },
        this.sk
      )
      Promise.any(this.relays.map(relay => relay.publish(event))).catch(() => {
        this.pending
          .get(id)
          ?.reject(new SafeError('Unable to send request to remote signer'))
      })
      return await promise
    } finally {
      this.pending.get(id)?.reject(new SafeError('Remote request ended'))
      this.pending.delete(id)
    }
  }
  async pair(displayQR) {
    if (displayQR) {
      try {
        // Register before opening relays, so a fast device cannot beat the listener.
        const connected = this.wait(handlers => {
          this.connection = handlers
        })
        connected.catch(() => {})
        await this.open()
        await connected
      } finally {
        this.connection?.reject(new SafeError('Pairing ended'))
        this.connection = null
      }
    } else {
      await this.open()
      const result = await this.request('connect', [
        this.credentials.signerPubkey,
        this.credentials.secret,
        '',
        JSON.stringify({name: 'nos2x'})
      ])
      if (
        result !== 'ack' &&
        (!this.credentials.secret || result !== this.credentials.secret)
      )
        throw new SafeError(
          'Remote signer returned an invalid pairing response'
        )
    }
    const userPubkey = await this.request('get_public_key')
    if (!isPublicKey(userPubkey))
      throw new SafeError('Remote signer returned an invalid public key')
    // Single-use pairing secrets are not needed to resume an established session.
    delete this.credentials.secret
    return userPubkey
  }
  async switchRelays() {
    let response
    try {
      response = await this.request('switch_relays', [], 3000)
    } catch (_) {
      return null
    }
    let value
    try {
      value = JSON.parse(response)
    } catch (_) {
      throw new SafeError('Remote signer returned invalid relays')
    }
    if (value === null) return null
    return relayURLs(value)
  }
  close(error = new SafeError('Remote session closed')) {
    if (this.closed) return
    this.closed = true
    this.signal?.removeEventListener('abort', this.abort)
    this.connection?.reject(error)
    for (const handlers of this.pending.values()) handlers.reject(error)
    this.pending.clear()
    this.subscriptions.forEach(sub => sub.close())
    this.pool.destroy()
    this.sk.fill(0)
    delete this.credentials.clientKey
    delete this.credentials.secret
  }
}

export async function remoteOperation(session, userPubkey, type, params) {
  if (type === 'signEvent') {
    if (params.event?.pubkey && params.event.pubkey !== userPubkey)
      throw new SafeError(
        'Event public key does not match this website’s identity'
      )
    const template = Object.fromEntries(
      ['kind', 'created_at', 'content', 'tags'].map(key => [
        key,
        params.event[key]
      ])
    )
    const response = await session.request('sign_event', [
      JSON.stringify(template)
    ])
    let signed
    try {
      signed = JSON.parse(response)
    } catch (_) {
      /* Rejected below. */
    }
    if (
      !signed ||
      signed.pubkey !== userPubkey ||
      !verifyEvent(signed) ||
      Object.keys(template).some(
        key => JSON.stringify(template[key]) !== JSON.stringify(signed[key])
      )
    )
      throw new SafeError(
        'Remote signer returned an invalid or changed signed event'
      )
    return signed
  }
  const methods = {
    'nip04.encrypt': 'nip04_encrypt',
    'nip04.decrypt': 'nip04_decrypt',
    'nip44.encrypt': 'nip44_encrypt',
    'nip44.decrypt': 'nip44_decrypt'
  }
  if (!methods[type]) throw new SafeError('Unknown remote operation')
  const input = type.endsWith('encrypt') ? params.plaintext : params.ciphertext
  if (!isPublicKey(params.peer) || typeof input !== 'string')
    throw new SafeError('Invalid encryption or decryption request')
  return session.request(methods[type], [params.peer, input])
}
