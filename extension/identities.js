import {SafeError} from './errors'
import {Mutex} from 'async-mutex'
import {bytesToHex, hexToBytes} from '@noble/hashes/utils.js'
import {generateSecretKey, getPublicKey} from 'nostr-tools/pure'
import * as nip19 from 'nostr-tools/nip19'
import {decrypt, encrypt} from 'nostr-tools/nip49'

export const STORAGE_KEY = 'identityStore'
export const RELOAD_ERROR = 'Identity changed; reload this page'
const copy = value => JSON.parse(JSON.stringify(value))

export function parseSecret(input, password = '') {
  try {
    const value = input.trim().toLowerCase()
    let secret
    if (value.startsWith('ncryptsec1')) {
      if (!password)
        throw new SafeError('Enter the password for this encrypted key')
      secret = decrypt(value, password)
    } else if (value.startsWith('nsec1')) {
      const decoded = nip19.decode(value)
      if (decoded.type !== 'nsec') throw new SafeError('Expected an nsec')
      secret = decoded.data
    } else {
      if (!/^[a-f0-9]{64}$/.test(value))
        throw new SafeError('Enter a valid nsec, hex, or ncryptsec private key')
      secret = hexToBytes(value)
    }
    const id = getPublicKey(secret) // Also rejects zero and out-of-range scalars.
    return {id, privateKey: bytesToHex(secret)}
  } catch (error) {
    if (error instanceof SafeError) throw error
    throw new SafeError('Invalid private key or incorrect import password')
  }
}

function validate(record) {
  const isMap = value =>
    value && typeof value === 'object' && !Array.isArray(value)
  if (
    record?.version !== 1 ||
    !isMap(record.identities) ||
    !isMap(record.sites) ||
    !isMap(record.policies)
  ) {
    throw new SafeError(
      'Identity storage cannot be read. Preserve your extension data before attempting recovery.'
    )
  }
  // Website names must never resolve to inherited object properties.
  Object.setPrototypeOf(record.identities, null)
  Object.setPrototypeOf(record.sites, null)
  Object.setPrototypeOf(record.policies, null)
  for (const [id, identity] of Object.entries(record.identities)) {
    if (
      parseSecret(identity.privateKey).id !== id ||
      typeof identity.name !== 'string'
    ) {
      throw new SafeError(
        'Invalid identity storage. Your data has not been removed.'
      )
    }
  }
  for (const site of Object.values(record.sites)) {
    if (
      !isMap(site) ||
      !Number.isSafeInteger(site.revision) ||
      site.revision < 0 ||
      (site.identityId !== null && !record.identities[site.identityId])
    ) {
      throw new SafeError(
        'Invalid website assignment. Your data has not been removed.'
      )
    }
  }
  for (const [id, hosts] of Object.entries(record.policies)) {
    if (!record.identities[id] || !isMap(hosts))
      throw new SafeError('Invalid permission storage; data was preserved')
    Object.setPrototypeOf(hosts, null)
    for (const answers of Object.values(hosts)) {
      if (!isMap(answers))
        throw new SafeError('Invalid permission storage; data was preserved')
      for (const [answer, rules] of Object.entries(answers)) {
        if (!['true', 'false'].includes(answer) || !isMap(rules))
          throw new SafeError('Invalid permission storage; data was preserved')
        for (const rule of Object.values(rules)) {
          if (
            !isMap(rule?.conditions) ||
            !Number.isFinite(rule.created_at) ||
            (rule.conditions.kinds && !isMap(rule.conditions.kinds))
          )
            throw new SafeError(
              'Invalid permission storage; data was preserved'
            )
        }
      }
    }
  }
  return record
}

export function publicState(state) {
  return {
    identities: Object.entries(state.identities).map(([id, identity]) => ({
      id,
      name: identity.name,
      npub: nip19.npubEncode(id)
    })),
    sites: copy(state.sites),
    policies: copy(state.policies)
  }
}

export function permissionStatus(state, identityId, host, type, event) {
  for (const answer of [true, false]) {
    const conditions =
      state.policies[identityId]?.[host]?.[answer]?.[type]?.conditions
    if (
      conditions &&
      (!conditions.kinds ||
        (type === 'signEvent' && conditions.kinds[event?.kind]))
    )
      return answer
  }
  return undefined
}

export function updatePermission(
  state,
  identityId,
  host,
  type,
  accept,
  conditions
) {
  const policies =
    state.policies[identityId] ||
    (state.policies[identityId] = Object.create(null))
  const site = policies[host] || (policies[host] = {})
  const rules = site[accept] || (site[accept] = {})
  const existing = rules[type]?.conditions
  let merged = conditions.kinds ? {kinds: {...conditions.kinds}} : {}
  if (existing && !existing.kinds) merged = {}
  else if (existing?.kinds && merged.kinds)
    Object.assign(merged.kinds, existing.kinds)
  const reverse = site[!accept]?.[type]
  if (reverse) {
    if (!merged.kinds) delete site[!accept][type]
    else if (reverse.conditions.kinds) {
      for (const kind of Object.keys(merged.kinds))
        delete reverse.conditions.kinds[kind]
      if (!Object.keys(reverse.conditions.kinds).length)
        delete site[!accept][type]
    } else {
      // A new kind-specific choice overrides an older catch-all answer.
      delete site[!accept][type]
    }
  }
  rules[type] = {conditions: merged, created_at: Math.floor(Date.now() / 1000)}
}

export class IdentityStore {
  constructor(storage) {
    this.storage = storage
    this.mutex = new Mutex()
  }

  async load() {
    const data = await this.storage.get([
      STORAGE_KEY,
      'private_key',
      'policies'
    ])
    const hasLegacyKey =
      data.private_key !== undefined && data.private_key !== ''
    if (data[STORAGE_KEY] !== undefined) {
      const state = validate(data[STORAGE_KEY])
      // An interrupted migration may leave legacy values behind.
      if (hasLegacyKey) {
        const legacy = parseSecret(data.private_key)
        if (
          state.identities[legacy.id]?.privateKey !== legacy.privateKey ||
          JSON.stringify(state.policies[legacy.id] || {}) !==
            JSON.stringify(data.policies || {}) ||
          Object.keys(data.policies || {}).some(
            host => state.sites[host]?.identityId !== legacy.id
          )
        ) {
          throw new SafeError(
            'Unmigrated legacy key found. Preserve your extension data before recovery.'
          )
        }
        await this.storage.remove(['private_key', 'policies'])
      }
      return state
    }
    const state = {
      version: 1,
      identities: Object.create(null),
      sites: Object.create(null),
      policies: Object.create(null)
    }
    if (hasLegacyKey) {
      let legacy
      try {
        legacy = parseSecret(data.private_key)
      } catch (_) {
        throw new SafeError(
          'The existing private key is invalid. Legacy data was preserved; restore a valid key before migrating.'
        )
      }
      state.identities[legacy.id] = {
        name: 'Identity 1',
        privateKey: legacy.privateKey
      }
      state.policies[legacy.id] = data.policies || {}
      for (const host of Object.keys(data.policies || {})) {
        state.sites[host] = {identityId: legacy.id, revision: 0}
      }
    } else if (data.policies && Object.keys(data.policies).length) {
      throw new SafeError(
        'Legacy permissions exist without a key. Legacy data was preserved for recovery.'
      )
    }
    validate(state)
    await this.storage.set({[STORAGE_KEY]: state})
    const saved = (await this.storage.get(STORAGE_KEY))[STORAGE_KEY]
    if (JSON.stringify(validate(saved)) !== JSON.stringify(state))
      throw new SafeError(
        'Could not verify migration; legacy data was preserved'
      )
    await this.storage.remove(['private_key', 'policies'])
    return state
  }

  async read(fn = state => state) {
    return this.mutex.runExclusive(async () => fn(await this.load()))
  }

  async mutate(fn) {
    return this.mutex.runExclusive(async () => {
      const state = await this.load()
      const result = await fn(state)
      validate(state)
      await this.storage.set({[STORAGE_KEY]: state})
      return result
    })
  }

  async manage(action, args = {}) {
    if (action === 'state') return this.read(publicState)
    if (action === 'export')
      return this.read(state => {
        const identity = state.identities[args.id]
        if (!identity) throw new SafeError('Identity not found')
        const secret = hexToBytes(identity.privateKey)
        return args.password
          ? encrypt(secret, args.password, 16, 0x00)
          : nip19.nsecEncode(secret)
      })
    return this.mutate(state => {
      switch (action) {
        case 'add': {
          const identity = args.generate
            ? parseSecret(bytesToHex(generateSecretKey()))
            : parseSecret(args.key || '', args.password)
          if (state.identities[identity.id])
            throw new SafeError('This identity has already been added')
          let number = 1
          while (
            Object.values(state.identities).some(
              item => item.name === `Identity ${number}`
            )
          )
            number++
          state.identities[identity.id] = {
            privateKey: identity.privateKey,
            name: args.name?.trim() || `Identity ${number}`
          }
          return identity.id
        }
        case 'rename':
          if (!state.identities[args.id])
            throw new SafeError('Identity not found')
          if (!args.name?.trim()) throw new SafeError('Enter an identity name')
          state.identities[args.id].name = args.name.trim()
          break
        case 'assign': {
          if (!args.host || !state.identities[args.id])
            throw new SafeError('Website or identity not found')
          const site = state.sites[args.host]
          if (site?.identityId !== args.id)
            state.sites[args.host] = {
              identityId: args.id,
              revision: (site?.revision || 0) + 1
            }
          break
        }
        case 'remove':
          if (!state.identities[args.id])
            throw new SafeError('Identity not found')
          delete state.identities[args.id]
          delete state.policies[args.id]
          for (const site of Object.values(state.sites)) {
            if (site.identityId === args.id) {
              site.identityId = null
              site.revision++
            }
          }
          break
        case 'revoke':
          delete state.policies[args.id]?.[args.host]?.[args.accept]?.[
            args.type
          ]
          break
        default:
          throw new SafeError('Unknown identity action')
      }
    })
  }
}
