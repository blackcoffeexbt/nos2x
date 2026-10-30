import {
  RemoteSession,
  newPairing,
  remoteOperation,
  REMOTE_TIMEOUT
} from './remote'
import {SafeError} from './errors'

export class RemoteManager {
  constructor(
    browser,
    store,
    sessionFactory = (credentials, options) =>
      new RemoteSession(credentials, options)
  ) {
    this.browser = browser
    this.store = store
    this.sessionFactory = sessionFactory
    this.jobs = new Map()
    this.pairing = null
  }
  job(fields = {}) {
    const controller = new AbortController()
    const job = {
      id: crypto.randomUUID(),
      controller,
      status: 'waiting',
      authURL: '',
      ...fields
    }
    job.timer = setTimeout(
      () =>
        controller.abort(
          new SafeError(
            'Remote signer timed out; check the device and try again'
          )
        ),
      REMOTE_TIMEOUT
    )
    job.heartbeat = setInterval(() => {
      this.browser.runtime.getPlatformInfo?.().catch(() => {})
    }, 20000)
    this.jobs.set(job.id, job)
    return job
  }
  session(job, credentials) {
    const session = this.sessionFactory(
      {...credentials},
      {
        signal: job.controller.signal,
        onauth: url => {
          job.authURL = url
          if (job !== this.pairing) this.showAuthentication(job)
        }
      }
    )
    job.session = session
    return session
  }
  showAuthentication(job) {
    if (job.windowReady || job.controller.signal.aborted || job.finished) return
    job.windowReady = this.browser.windows
      .create({
        url: `${this.browser.runtime.getURL('remote.html')}?id=${job.id}`,
        type: 'popup',
        width: 480,
        height: 440
      })
      .then(window => {
        job.windowId = window.id
      })
      .catch(() => {
        job.controller.abort(
          new SafeError(
            'Unable to open remote signer authentication; try again'
          )
        )
      })
  }
  finish(job) {
    job.finished = true
    clearTimeout(job.timer)
    clearInterval(job.heartbeat)
    job.session?.close()
    delete job.session
  }
  state(job) {
    return {
      id: job.id,
      status: job.status,
      authURL: job.authURL,
      errorMessage: job.error,
      identityId: job.identityId,
      expires: job.expires,
      uri: job.uri,
      host: job.host,
      type: job.type
    }
  }
  startPairing(args) {
    if (this.pairing) this.cancelPairing(this.pairing.id)
    const {credentials, uri} = newPairing(args.relays, args.bunker)
    const job = this.job({uri, expires: Date.now() + REMOTE_TIMEOUT})
    this.pairing = job
    const session = this.session(job, credentials)
    ;(async () => {
      try {
        const id = await session.pair(!!uri)
        const relays = await session.switchRelays()
        if (relays) session.credentials.relays = relays
        if (job.controller.signal.aborted)
          throw new SafeError('Pairing cancelled or expired')
        await this.store.addRemote(
          id,
          session.credentials,
          args.name,
          job.controller.signal
        )
        job.identityId = id
        job.status = 'paired'
      } catch (error) {
        job.status = 'error'
        job.error = job.controller.signal.aborted
          ? 'Pairing cancelled or expired; generate a new code'
          : error instanceof SafeError
          ? error.message
          : 'Unable to pair with remote signer'
      } finally {
        job.uri = ''
        job.authURL = ''
        this.finish(job)
        this.jobs.delete(job.id)
        // The retained UI status contains no communication credentials.
      }
    })()
    return this.state(job)
  }
  pairingState(id) {
    if (this.pairing?.id !== id)
      throw new SafeError('Pairing expired; start again')
    return this.state(this.pairing)
  }
  cancelPairing(id) {
    if (this.pairing?.id !== id) return true
    const job = this.pairing
    job.controller.abort()
    this.finish(job)
    this.jobs.delete(id)
    this.pairing = null
    return true
  }
  async useRelays(session, id) {
    const relays = await session.switchRelays()
    if (!relays) return session
    await this.store.mutate(state => {
      const identity = state.identities[id]
      if (!identity || identity.type !== 'remote')
        throw new SafeError('Identity changed; reload this page')
      identity.relays = relays
    })
    const credentials = {...session.credentials, relays}
    session.close()
    return credentials
  }
  async operation(identity, id, type, params, host) {
    const job = this.job({identityId: id, host, type})
    let session = this.session(job, identity)
    try {
      await session.open()
      const next = await this.useRelays(session, id)
      if (next !== session) {
        session = this.session(job, next)
        await session.open()
      }
      if (job.controller.signal.aborted)
        throw new SafeError('Remote request cancelled')
      return await remoteOperation(session, id, type, params)
    } finally {
      this.finish(job)
      this.jobs.delete(job.id)
      // Authentication may finish while the browser is still creating its window.
      await job.windowReady
      if (job.windowId !== undefined) {
        try {
          await this.browser.windows.remove(job.windowId)
        } catch (_) {
          /* Already closed. */
        }
      }
    }
  }
  workMessage(message, sender) {
    const job = this.jobs.get(message.id)
    if (
      !job ||
      job === this.pairing ||
      job.windowId === undefined ||
      sender.id !== this.browser.runtime.id ||
      (sender.frameId !== undefined && sender.frameId !== 0) ||
      sender.url !==
        `${this.browser.runtime.getURL('remote.html')}?id=${job.id}` ||
      (sender.tab && sender.tab.windowId !== job.windowId)
    )
      throw new SafeError('Remote request expired')
    if (message.action === 'cancel') {
      job.controller.abort()
      return true
    }
    if (message.action !== 'state')
      throw new SafeError('Invalid remote request action')
    return this.state(job)
  }
  cancel({id, host}) {
    for (const job of this.jobs.values())
      if (
        job !== this.pairing &&
        ((id && job.identityId === id) || (host && job.host === host))
      )
        job.controller.abort()
  }
  windowRemoved(id) {
    for (const job of this.jobs.values())
      if (job.windowId === id) job.controller.abort()
  }
  async logout(identity) {
    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), 2000)
    const session = this.sessionFactory(
      {...identity},
      {signal: controller.signal}
    )
    try {
      await session.open()
      await session.request('logout', [], 1500)
    } catch (_) {
      /* Courtesy only. */
    } finally {
      clearTimeout(timer)
      session.close()
    }
  }
}
