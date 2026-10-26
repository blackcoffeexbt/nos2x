import browser from 'webextension-polyfill'
import {createRoot} from 'react-dom/client'
import React, {useEffect, useState} from 'react'
import {PERMISSION_NAMES} from './common'
import {send, identityLabel} from './ui'

const id = new URLSearchParams(location.search).get('id')
async function prompt(action, args = {}) {
  const window = await browser.windows.getCurrent()
  return send({channel: 'prompt', id, action, windowId: window.id, ...args})
}

function Prompt() {
  const [request, setRequest] = useState(null)
  const [identityId, setIdentityId] = useState('')
  const [preview, setPreview] = useState(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [loadingPreview, setLoadingPreview] = useState(false)
  useEffect(() => {
    prompt('get')
      .then(data => {
        setRequest(data)
        setIdentityId(
          data.assignedId ||
            (data.identities.length === 1 ? data.identities[0].id : '')
        )
      })
      .catch(e => setError(e.message))
  }, [])
  useEffect(() => {
    let active = true
    setPreview(null)
    if (!identityId || !request) return
    setLoadingPreview(true)
    setError('')
    prompt('preview', {identityId})
      .then(result => {
        if (active) setPreview(result)
      })
      .catch(e => {
        if (active) setError(e.message)
      })
      .finally(() => {
        if (active) setLoadingPreview(false)
      })
    return () => {
      active = false
    }
  }, [identityId, request])
  useEffect(() => {
    if (!request) return
    // Keep the worker alive while an approval is visible, up to its expiry.
    const timer = setInterval(() => {
      prompt('ping').catch(e => {
        setError(e.message)
        clearInterval(timer)
      })
    }, 20000)
    return () => clearInterval(timer)
  }, [request])
  async function answer(accept, remember) {
    setBusy(true)
    setError('')
    try {
      await prompt('answer', {
        identityId,
        accept,
        conditions: remember ? {} : undefined
      })
    } catch (e) {
      setError(e.message)
      setBusy(false)
    }
  }
  const event = request?.params?.event
  return (
    <div className="approval">
      <h2>{request?.host || 'nos2x'}</h2>
      {error && <p role="alert">{error}</p>}
      {request && (
        <>
          <p>
            Requests permission to <b>{PERMISSION_NAMES[request.type]}</b>.
          </p>
          <label>
            Identity
            <select
              value={identityId}
              disabled={!!request.assignedId || busy}
              onChange={e => setIdentityId(e.target.value)}
            >
              <option value="" disabled>
                Choose an identity
              </option>
              {request.identities.map(identity => (
                <option key={identity.id} value={identity.id}>
                  {identityLabel(identity)}
                </option>
              ))}
            </select>
          </label>
          {!request.assignedId && (
            <p>
              Your choice will be remembered for this website when you approve.
            </p>
          )}
          {!!Object.keys(request.params || {}).length && (
            <>
              <p>Request</p>
              <pre className="request-data">
                {JSON.stringify(event || request.params, null, 2)}
              </pre>
            </>
          )}
          {loadingPreview && <p>Preparing preview…</p>}
          {preview !== null && (
            <>
              <p>Result for this identity</p>
              <pre className="request-data">{preview}</pre>
            </>
          )}
          <div className="actions">
            <button
              disabled={busy || !identityId || loadingPreview || !!error}
              onClick={() => answer(true, false)}
            >
              Authorize once
            </button>
            <button
              disabled={busy || !identityId || loadingPreview || !!error}
              onClick={() => answer(true, true)}
            >
              {event
                ? `Authorize kind ${event.kind} forever`
                : 'Authorize forever'}
            </button>
            <button disabled={busy} onClick={() => answer(false, false)}>
              Reject
            </button>
            <button
              disabled={busy || !identityId}
              onClick={() => answer(false, true)}
            >
              {event ? `Reject kind ${event.kind} forever` : 'Reject forever'}
            </button>
          </div>
        </>
      )}
    </div>
  )
}
createRoot(document.getElementById('main')).render(<Prompt />)
