import browser from 'webextension-polyfill'
import {createRoot} from 'react-dom/client'
import * as nip19 from 'nostr-tools/nip19'
import React, {useState, useEffect} from 'react'
import QRCode from 'react-qr-code'
import {manage, identityLabel} from './ui'

function Popup() {
  const [state, setState] = useState(null)
  const [host, setHost] = useState('')
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [format, setFormat] = useState('npub')
  const [busy, setBusy] = useState(false)
  const [relays, setRelays] = useState([])
  useEffect(() => {
    async function load() {
      const [data, tabs, relaySettings] = await Promise.all([
        manage('state'),
        browser.tabs.query({active: true, currentWindow: true}),
        browser.storage.local.get('relays')
      ])
      setState(data)
      setRelays(
        Object.entries(relaySettings.relays || {})
          .filter(([, policy]) => policy.write)
          .slice(0, 3)
          .map(([url]) => url)
      )
      const url = tabs[0]?.url
      if (url && /^https?:/.test(url)) setHost(new URL(url).host)
    }
    load().catch(e => setError(e.message))
  }, [])
  const identity = state?.identities.find(
    item => item.id === state.sites[host]?.identityId
  )
  const key =
    identity &&
    (format === 'hex'
      ? identity.id
      : format === 'nprofile'
      ? nip19.nprofileEncode({pubkey: identity.id, relays})
      : identity.npub)
  async function change(id) {
    if (!id) return
    setBusy(true)
    setError('')
    try {
      await manage('assign', {host, id})
      setState(await manage('state'))
      setNotice(
        'Identity changed. Reload this website’s open pages before continuing; you may need to sign in again.'
      )
    } catch (e) {
      setError(e.message)
    } finally {
      setBusy(false)
    }
  }
  return (
    <div className="popup">
      <h2>nos2x</h2>
      {error && <p role="alert">{error}</p>}
      {state && (
        <>
          {host ? (
            <>
              <p>
                Identity for <b>{host}</b>
              </p>
              <select
                aria-label="Website identity"
                value={identity?.id || ''}
                disabled={busy}
                onChange={e => change(e.target.value)}
              >
                <option value="" disabled>
                  Choose an identity
                </option>
                {state.identities.map(item => (
                  <option key={item.id} value={item.id}>
                    {identityLabel(item)}
                  </option>
                ))}
              </select>
              {!identity && (
                <p>
                  This website has no identity assigned. Choose one here or when
                  it first requests access.
                </p>
              )}
            </>
          ) : (
            <p>Open a website to choose its identity.</p>
          )}
          {!state.identities.length && <p>Add an identity to get started.</p>}
          {notice && <p role="status">{notice}</p>}
          {identity && (
            <>
              <p>{identity.name} — public key</p>
              <select
                aria-label="Public key format"
                value={format}
                onChange={e => setFormat(e.target.value)}
              >
                <option value="npub">npub</option>
                <option value="hex">hex</option>
                <option value="nprofile">nprofile</option>
              </select>
              <pre className="key">{key}</pre>
              <QRCode
                size={224}
                value={format === 'hex' ? key : key.toUpperCase()}
              />
            </>
          )}
        </>
      )}
      <p>
        <button onClick={() => browser.runtime.openOptionsPage()}>
          Manage identities
        </button>
      </p>
    </div>
  )
}
createRoot(document.getElementById('main')).render(<Popup />)
