import React, {useEffect, useState} from 'react'
import {createRoot} from 'react-dom/client'
import {send} from './ui'

const id = new URLSearchParams(location.search).get('id')
function RemoteWork() {
  const [state, setState] = useState(null)
  const [error, setError] = useState('')
  useEffect(() => {
    let active = true
    const refresh = () =>
      send({channel: 'remote-work', id, action: 'state'})
        .then(value => {
          if (active) {
            setState(value)
            setError('')
          }
        })
        .catch(e => {
          if (active) setError(e.message)
        })
    refresh()
    const timer = setInterval(refresh, 750)
    return () => {
      active = false
      clearInterval(timer)
    }
  }, [])
  return (
    <main className="approval">
      <h2>Remote signer needs authentication</h2>
      {error && <p role="alert">{error}</p>}
      {state && (
        <>
          <p>
            <b>{state.host}</b> requested {state.type}.
          </p>
          <p>
            Use the link below to authenticate. This request expires after four
            minutes.
          </p>
          {state.authURL && (
            <p>
              <a href={state.authURL} target="_blank" rel="noreferrer">
                Authenticate with remote signer
              </a>
            </p>
          )}
          <button
            onClick={() =>
              send({channel: 'remote-work', id, action: 'cancel'}).catch(e =>
                setError(e.message)
              )
            }
          >
            Cancel request
          </button>
        </>
      )}
    </main>
  )
}
createRoot(document.getElementById('main')).render(<RemoteWork />)
