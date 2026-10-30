import React, {useCallback, useEffect, useRef, useState} from 'react'
import {createRoot} from 'react-dom/client'
import QRCode from 'react-qr-code'
import {Pairing} from './pairing'
import browser from 'webextension-polyfill'
import {manage, identityLabel} from './ui'

function Options() {
  const sensitiveGeneration = useRef(0)
  const [state, setState] = useState(null)
  const [selected, setSelected] = useState('')
  const [name, setName] = useState('')
  const [key, setKey] = useState('')
  const [password, setPassword] = useState('')
  const [exportPassword, setExportPassword] = useState('')
  const [revealed, setRevealed] = useState('')
  const [message, setMessage] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [removing, setRemoving] = useState(false)
  const [notifications, setNotifications] = useState(false)
  const [handlerEnabled, setHandlerEnabled] = useState(false)
  const [handler, setHandler] = useState('https://njump.me/{raw}')
  const clearSensitive = useCallback(() => {
    sensitiveGeneration.current++
    setRevealed('')
    setPassword('')
    setExportPassword('')
    setKey('')
  }, [])
  useEffect(() => {
    if (!revealed) return
    const timer = setTimeout(clearSensitive, 60000)
    return () => clearTimeout(timer)
  }, [revealed, clearSensitive])
  const identity = state?.identities.find(item => item.id === selected)
  const sites = Object.entries(state?.sites || {})
    .filter(([, site]) => site.identityId === selected)
    .map(([host]) => host)
  async function refresh() {
    const data = await manage('state')
    setState(data)
    return data
  }
  useEffect(() => {
    refresh().catch(e => setError(e.message))
    browser.storage.local
      .get(['notifications', 'protocol_handler'])
      .then(data => {
        setNotifications(!!data.notifications)
        setHandlerEnabled(!!data.protocol_handler)
        if (data.protocol_handler) setHandler(data.protocol_handler)
      })
      .catch(e => setError(e.message))
    const clear = () => {
      if (document.visibilityState === 'hidden') clearSensitive()
    }
    document.addEventListener('visibilitychange', clear)
    window.addEventListener('blur', clearSensitive)
    window.addEventListener('pagehide', clearSensitive)
    return () => {
      document.removeEventListener('visibilitychange', clear)
      window.removeEventListener('blur', clearSensitive)
      window.removeEventListener('pagehide', clearSensitive)
    }
  }, [clearSensitive])

  function choose(id) {
    setSelected(id)
    setName(state.identities.find(item => item.id === id)?.name || '')
    clearSensitive()
    setRemoving(false)
    setError('')
    setMessage('')
  }
  async function run(fn, success) {
    setBusy(true)
    setError('')
    setMessage('')
    try {
      await fn()
      await refresh()
      if (success) setMessage(success)
    } catch (e) {
      setError(e.message)
    } finally {
      setBusy(false)
    }
  }
  async function add(generate) {
    await run(async () => {
      const id = await manage('add', {key, password, generate, name})
      setSelected(id)
      setRevealed('')
      setKey('')
      setPassword('')
      setExportPassword('')
      setRemoving(false)
      const data = await refresh()
      setName(data.identities.find(item => item.id === id).name)
    }, 'Identity added')
  }
  const policies = Object.entries(state?.policies[selected] || {}).flatMap(
    ([host, answers]) =>
      Object.entries(answers).flatMap(([accept, rules]) =>
        Object.entries(rules).map(([type, rule]) => ({
          host,
          accept,
          type,
          ...rule
        }))
      )
  )
  return (
    <main className="options">
      <h1>nos2x</h1>
      <p>Nostr signer extension</p>
      {error && <p role="alert">{error}</p>}
      {message && <p role="status">{message}</p>}
      <h2>Identities</h2>
      {!state && !error && <p>Loading…</p>}
      {state && (
        <>
          <select
            aria-label="Manage identity"
            value={selected}
            disabled={busy}
            onChange={e => choose(e.target.value)}
          >
            <option value="">Add an identity</option>
            {state.identities.map(item => (
              <option key={item.id} value={item.id}>
                {identityLabel(item)}
              </option>
            ))}
          </select>
          <fieldset disabled={busy}>
            <label>
              Name
              <input
                value={name}
                onChange={e => setName(e.target.value)}
                placeholder="Optional identity name"
              />
            </label>
            {!identity ? (
              <>
                <Pairing
                  onPaired={async id => {
                    const data = await refresh()
                    setSelected(id)
                    setName(
                      data.identities.find(item => item.id === id)?.name || ''
                    )
                    setMessage('Remote signer connected')
                  }}
                />
                <label>
                  Private key
                  <input
                    type="password"
                    autoComplete="off"
                    value={key}
                    onChange={e => setKey(e.target.value)}
                    placeholder="nsec, hex, or ncryptsec"
                  />
                </label>
                {key.trim().toLowerCase().startsWith('ncryptsec1') && (
                  <label>
                    Import password
                    <input
                      type="password"
                      autoComplete="off"
                      value={password}
                      onChange={e => setPassword(e.target.value)}
                    />
                  </label>
                )}
                <div className="actions">
                  <button disabled={!key.trim()} onClick={() => add(false)}>
                    Import identity
                  </button>
                  <button onClick={() => add(true)}>Generate identity</button>
                </div>
              </>
            ) : (
              <>
                <button
                  disabled={!name.trim()}
                  onClick={() =>
                    run(
                      () => manage('rename', {id: selected, name}),
                      'Identity renamed'
                    )
                  }
                >
                  Save name
                </button>
                <p>Public key</p>
                <pre className="key">{identity.npub}</pre>
                <QRCode size={180} value={identity.npub.toUpperCase()} />
                <p>
                  <a
                    href={`https://nosta.me/${identity.npub}`}
                    target="_blank"
                    rel="noreferrer"
                  >
                    Browse profile
                  </a>
                  {' · '}
                  <a
                    href="https://nosta.me/login/options"
                    target="_blank"
                    rel="noreferrer"
                  >
                    Edit profile
                  </a>
                </p>
                <p>Assigned websites: {sites.join(', ') || 'none'}</p>
                {identity.type === 'remote' ? (
                  <p>
                    Remote signer · Relays: {identity.relays.join(', ')}. Your
                    private key stays on the signing device.
                  </p>
                ) : (
                  <>
                    <h3>Reveal or export private key</h3>
                    <label>
                      Export password (optional)
                      <input
                        type="password"
                        autoComplete="off"
                        value={exportPassword}
                        onChange={e => {
                          setExportPassword(e.target.value)
                          setRevealed('')
                        }}
                      />
                    </label>
                    <div className="actions">
                      <button
                        onClick={() =>
                          run(async () => {
                            const generation = sensitiveGeneration.current
                            const result = await manage('export', {
                              id: selected,
                              password: exportPassword
                            })
                            if (
                              generation === sensitiveGeneration.current &&
                              document.visibilityState === 'visible' &&
                              document.hasFocus()
                            )
                              setRevealed(result)
                            setExportPassword('')
                          })
                        }
                      >
                        {exportPassword
                          ? 'Show encrypted key'
                          : 'Show private key'}
                      </button>
                      {revealed && (
                        <button
                          onClick={() => {
                            clearSensitive()
                          }}
                        >
                          Hide key
                        </button>
                      )}
                    </div>
                    {revealed && (
                      <>
                        <pre className="key">{revealed}</pre>
                        <QRCode size={224} value={revealed.toUpperCase()} />
                      </>
                    )}
                  </>
                )}
                <p>
                  <button
                    onClick={() => {
                      setRemoving(true)
                      setRevealed('')
                      setExportPassword('')
                    }}
                  >
                    Remove identity…
                  </button>
                </p>
                {removing && (
                  <div role="alert" className="confirmation">
                    <p>
                      Remove {identityLabel(identity)} and its permissions?
                      Affected websites: {sites.join(', ') || 'none'}.{' '}
                      {identity.type === 'remote'
                        ? 'This removes the pairing from this browser.'
                        : 'Back up the private key first.'}{' '}
                      These websites will need another identity and a reload.
                    </p>
                    <button
                      onClick={() =>
                        run(async () => {
                          await manage('remove', {id: selected})
                          choose('')
                        }, 'Identity removed')
                      }
                    >
                      Confirm removal
                    </button>
                    <button onClick={() => setRemoving(false)}>Cancel</button>
                  </div>
                )}
                <h3>Permissions for {identityLabel(identity)}</h3>
                {!policies.length ? (
                  <p>No saved permissions.</p>
                ) : (
                  <table>
                    <thead>
                      <tr>
                        <th>Website</th>
                        <th>Operation</th>
                        <th>Answer</th>
                        <th>Conditions</th>
                        <th>Since</th>
                        <th>Revoke</th>
                      </tr>
                    </thead>
                    <tbody>
                      {policies.map(rule => (
                        <tr key={`${rule.host}:${rule.accept}:${rule.type}`}>
                          <td>{rule.host}</td>
                          <td>{rule.type}</td>
                          <td>{rule.accept === 'true' ? 'Allow' : 'Deny'}</td>
                          <td>
                            {rule.conditions.kinds
                              ? `Kinds: ${Object.keys(
                                  rule.conditions.kinds
                                ).join(', ')}`
                              : 'Always'}
                          </td>
                          <td>
                            {new Date(rule.created_at * 1000).toLocaleString()}
                          </td>
                          <td>
                            <button
                              onClick={() =>
                                run(
                                  () =>
                                    manage('revoke', {id: selected, ...rule}),
                                  'Permission revoked'
                                )
                              }
                            >
                              Revoke
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </>
            )}
          </fieldset>
        </>
      )}
      <h2>General settings</h2>
      <fieldset disabled={busy}>
        <label className="checkbox">
          <input
            type="checkbox"
            checked={handlerEnabled}
            onChange={e => setHandlerEnabled(e.target.checked)}
          />
          Handle nostr: links
        </label>
        {handlerEnabled && (
          <>
            <label>
              URL template
              <input
                value={handler}
                onChange={e => setHandler(e.target.value)}
              />
            </label>
            <p>
              Available placeholders:{' '}
              {
                '{raw}, {hex}, {hrp}, {p_or_e}, {u_or_n}, {relay0}, {relay1}, {relay2}'
              }
              . Example: {'https://njump.me/{raw}'}
            </p>
          </>
        )}
        <label className="checkbox">
          <input
            type="checkbox"
            checked={notifications}
            onChange={e => setNotifications(e.target.checked)}
          />
          Show notifications when permissions are used
        </label>
        <button
          onClick={() =>
            run(async () => {
              if (
                notifications &&
                !(await browser.permissions.request({
                  permissions: ['notifications']
                }))
              ) {
                setNotifications(false)
                throw new Error('Notification permission was not granted')
              }
              await browser.storage.local.set({
                notifications,
                protocol_handler: handlerEnabled ? handler : ''
              })
            }, 'General settings saved')
          }
        >
          Save settings
        </button>
      </fieldset>
    </main>
  )
}
createRoot(document.getElementById('main')).render(<Options />)
