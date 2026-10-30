import React, {useEffect, useRef, useState} from 'react'
import QRCode from 'react-qr-code'
import jsQR from 'jsqr'
import {manage} from './ui'
import {DEFAULT_RELAY} from './remote'

export function Pairing({onPaired}) {
  const [enabled, setEnabled] = useState(false)
  const [relays, setRelays] = useState(DEFAULT_RELAY)
  const [bunker, setBunker] = useState('')
  const [name, setName] = useState('')
  const [pair, setPair] = useState(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [scanning, setScanning] = useState(false)
  const [copied, setCopied] = useState(false)
  const video = useRef(null)
  const camera = useRef(null)
  const generation = useRef(0)
  const pairId = useRef(null)
  const received = useRef(onPaired)
  received.current = onPaired
  function stopCamera() {
    generation.current++
    camera.current?.getTracks().forEach(track => track.stop())
    camera.current = null
    setScanning(false)
  }
  useEffect(() => {
    const cleanup = () => {
      stopCamera()
      if (pairId.current)
        manage('pairCancel', {id: pairId.current}).catch(() => {})
      pairId.current = null
    }
    window.addEventListener('pagehide', cleanup)
    return () => {
      window.removeEventListener('pagehide', cleanup)
      cleanup()
    }
  }, [])
  useEffect(() => {
    if (!pair?.id || pair.status !== 'waiting') return
    let active = true
    let polling = false
    const timer = setInterval(async () => {
      if (polling) return
      polling = true
      try {
        const next = await manage('pairState', {id: pair.id})
        if (!active) return
        setPair(next)
        if (next.status === 'paired') {
          pairId.current = null
          Promise.resolve(received.current(next.identityId)).catch(e => {
            if (active) setError(e.message)
          })
        }
      } catch (e) {
        if (active) {
          setError(e.message)
          setPair(current => ({
            ...current,
            status: 'error',
            uri: '',
            authURL: ''
          }))
          pairId.current = null
        }
      } finally {
        polling = false
      }
    }, 750)
    return () => {
      active = false
      clearInterval(timer)
    }
  }, [pair?.id, pair?.status])
  useEffect(() => {
    if (!scanning) return
    let decoding = false
    const timer = setInterval(async () => {
      if (decoding || !video.current?.videoWidth) return
      decoding = true
      const current = generation.current
      try {
        const canvas = document.createElement('canvas')
        canvas.width = video.current.videoWidth
        canvas.height = video.current.videoHeight
        const context = canvas.getContext('2d', {willReadFrequently: true})
        context.drawImage(video.current, 0, 0)
        const pixels = context.getImageData(0, 0, canvas.width, canvas.height)
        const result = jsQR(pixels.data, canvas.width, canvas.height)?.data
        if (current !== generation.current) return
        if (
          typeof result === 'string' &&
          result.trim().startsWith('bunker://')
        ) {
          setBunker(result.trim())
          stopCamera()
          setError('')
        } else setError('This QR is not a bunker:// connection code')
      } catch (_) {
        /* Frames without a decodable QR are expected. */
      } finally {
        decoding = false
      }
    }, 500)
    return () => clearInterval(timer)
  }, [scanning])
  async function scan() {
    stopCamera()
    setError('')
    const current = generation.current
    try {
      const stream = await navigator.mediaDevices.getUserMedia({
        video: {facingMode: 'environment'},
        audio: false
      })
      if (current !== generation.current) {
        stream.getTracks().forEach(track => track.stop())
        return
      }
      camera.current = stream
      setScanning(true)
      // The video stays mounted, including while camera permission is pending.
      video.current.srcObject = stream
      await video.current.play()
    } catch (_) {
      if (current !== generation.current) return
      stopCamera()
      setError(
        'Camera unavailable or permission denied. Paste the bunker connection string instead.'
      )
    }
  }
  async function start(fromBunker) {
    setBusy(true)
    setError('')
    setCopied(false)
    stopCamera()
    try {
      const next = await manage('pairStart', {
        name,
        bunker: fromBunker ? bunker : '',
        relays: relays.split(/[\s,]+/).filter(Boolean)
      })
      pairId.current = next.id
      setPair(next)
      setBunker('')
    } catch (e) {
      setError(e.message)
    } finally {
      setBusy(false)
    }
  }
  async function cancel() {
    stopCamera()
    const id = pairId.current
    pairId.current = null
    setPair(null)
    if (id) {
      try {
        await manage('pairCancel', {id})
      } catch (e) {
        setError(e.message)
      }
    }
  }
  if (!enabled)
    return (
      <button onClick={() => setEnabled(true)}>Connect remote signer</button>
    )
  return (
    <section aria-label="Connect remote signer">
      <h3>Connect remote signer</h3>
      <p>
        Your Nostr private key stays on the remote device. Website permissions
        still apply in nos2x.
      </p>
      {error && <p role="alert">{error}</p>}
      {pair?.errorMessage && <p role="alert">{pair.errorMessage}</p>}
      {pair?.status === 'paired' && (
        <p role="status">Remote signer connected.</p>
      )}
      {pair?.status === 'waiting' ? (
        <>
          <p role="status">
            Waiting for your signing device. This pairing expires in four
            minutes.
          </p>
          {pair.uri && (
            <>
              <p>Scan this QR with your signing device.</p>
              <div className="pairing-qr">
                <QRCode size={260} value={pair.uri} />
              </div>
              <textarea
                aria-label="Pairing connection string"
                readOnly
                value={pair.uri}
              />
              <button
                onClick={async () => {
                  try {
                    await navigator.clipboard.writeText(pair.uri)
                    setCopied(true)
                  } catch (_) {
                    setError(
                      'Unable to copy. Select and copy the connection string above.'
                    )
                  }
                }}
              >
                {copied ? 'Copied' : 'Copy connection string'}
              </button>
            </>
          )}
          {pair.authURL && (
            <a href={pair.authURL} target="_blank" rel="noreferrer">
              Authenticate with remote signer
            </a>
          )}
          <button onClick={cancel}>Cancel pairing</button>
        </>
      ) : (
        <fieldset disabled={busy}>
          <label>
            Remote identity name
            <input
              value={name}
              onChange={e => setName(e.target.value)}
              placeholder="Remote signer"
            />
          </label>
          <h4>Scan with your device</h4>
          <label>
            Pairing relays
            <textarea
              value={relays}
              onChange={e => setRelays(e.target.value)}
            />
          </label>
          <button onClick={() => start(false)}>Show pairing QR</button>
          <h4>Connect using a device code</h4>
          <label>
            Bunker connection string
            <textarea
              autoComplete="off"
              value={bunker}
              onChange={e => setBunker(e.target.value)}
              placeholder="bunker://…?relay=wss://…"
            />
          </label>
          <video
            ref={video}
            muted
            playsInline
            hidden={!scanning}
            style={{width: '100%', maxWidth: 400}}
          />
          {scanning ? (
            <button onClick={stopCamera}>Stop camera</button>
          ) : (
            <button onClick={scan}>Scan device QR</button>
          )}
          <button disabled={!bunker.trim()} onClick={() => start(true)}>
            Connect device
          </button>
          <button
            onClick={async () => {
              await cancel()
              setEnabled(false)
              setBunker('')
            }}
          >
            Close remote setup
          </button>
        </fieldset>
      )}
    </section>
  )
}
