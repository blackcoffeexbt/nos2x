# Private-key boundaries

Local identity private keys stay in the extension's local storage and background worker, except
when the user explicitly reveals or exports a key in the options page. Websites
receive public keys, signatures, and authorized encryption/decryption results.
The extension does not upload keys or sync them through Chrome storage.sync.

## Protections

- The worker restricts local storage to `TRUSTED_CONTEXTS` before servicing any
  requests. If that restriction fails, requests fail without reading keys.
  Content scripts use the message bridge instead of accessing storage.
- Management messages require the extension's own sender ID, an exact permitted
  extension-page URL, and a top-level frame. Raw and encrypted key exports are
  restricted further to the options page. Websites, content scripts, external
  extensions, approval windows, and the toolbar popup cannot export keys.
- Public metadata omits private-key fields. Private keys and operation inputs are
  not placed in approval URLs, notifications, application logs, or website DOM.
- Only fixed application error messages cross runtime boundaries. Dependency or
  browser exceptions are replaced with a generic error. Invalid-key decoder
  errors can contain key material and must never be forwarded verbatim.
- Extension-page CSP allows secure WebSocket relay connections for remote signing
  and blocks ordinary HTTP(S) fetches, remote scripts, embedded frames, objects,
  and form submissions. Links to external profiles contain public keys
  only and suppress referrers. Only the website provider script is web accessible.
- Revealed keys clear on identity changes, page hiding, focus loss, and after 60
  seconds. Import keys and password fields clear when leaving the view. A late
  export response cannot restore a key after the view was cleared.

Chrome documents the storage access boundary at
[Storage API](https://developer.chrome.com/docs/extensions/reference/api/storage).

## Limits

This is not an encrypted vault. Keys are stored unencrypted in the browser
profile, and JavaScript cannot guarantee erasure of strings or every memory
copy. Someone with access to the profile, a compromised browser/device, a
malicious change to trusted extension code, or privileged debugging access may
read keys. A user who reveals/exports a key can expose it through screenshots,
copying, screen sharing, or subsequent sharing outside the extension.

CSP and sender checks do not protect against a fully compromised trusted
extension. Dependency advisory results do not prove that every dependency is
free from defects or malicious changes. Review permission prompts: permission
to sign is authority to act as that identity even without knowing its key.

## Validation

`npm test` covers blocked export callers, forged channels and sender metadata,
secret-bearing exception sanitization, malformed stored keys, and failing storage
restrictions, in addition to identity/permission/cryptography checks. `npm run
lint` and `npm run build` validate the source and production bundles.

The October 26, 2026 review additionally used a disposable Chromium profile and a
real test content script with a dummy key. It confirmed blocked storage reads,
blocked website/content-script/popup exports, permitted explicit options export,
blocked extension-page fetches, and reveal clearing by timeout and the blur
handler. npm's advisory check reported zero known vulnerabilities at that time.

## Remote signer boundaries

Remote identities keep their Nostr signing key on the remote signer. A distinct
client communication key is stored unencrypted in trusted local extension
storage for each pairing; it authorizes access to the paired remote session.
Treat access to that key as access to the remote session, subject to the device's
own policies. Communication keys are never included in public identity metadata
or offered for export. Existing local identity storage migrates to version 2
without changing website assignments or permissions.

Pairing and relay transport run in the background worker. Only the own top-level
options page can start, inspect, or cancel pairing. Extension-generated QR codes
contain a fresh random secret, which must match the signed, encrypted device
response. Bunker connections pin the signer communication public key from the
code. The user public key is requested separately. Cancelled and expired pairing
credentials are discarded; successful pairing secrets are not persisted.

NIP-46 messages use NIP-44 encryption inside signed kind-24133 events. Relays see
communication public keys, timestamps, routing tags, and encrypted traffic; the
remote device receives authorized event contents and encryption/decryption
inputs. Only secure WebSocket relay URLs are accepted. Relay-provided events
are checked for signatures, recipient, timestamp, signer author, and matching
request ID. Returned signed events must match the paired user public key and
all requested event fields. Invalid results and raw remote errors are not
forwarded to websites. Authentication challenges expose HTTPS links only, opened
explicitly by the user with referrers suppressed. Normal remote requests open
no waiting window; a window appears only for authentication challenges.

Website permission checks run before remote cryptographic operations. Remote
encryption/decryption previews do not execute on the device. Removal or website
reassignment cancels pending remote work, and the existing revision checks
discard stale results. Requests are bounded, sockets close after work finishes,
and interrupted requests are not automatically resubmitted. A request already
delivered to a device cannot be recalled by local cancellation; the extension
discards its eventual response. Logout is best effort, so revoke sessions on
the device when stronger revocation is needed.

Camera scanning runs only in the options page after an explicit action. Frames
are decoded locally without uploading images. Camera tracks stop after a code
is found, when cancelled, and when the view closes. Pairing codes and clipboard
copies can grant connection access; handle them as temporary credentials.

Tests cover both pairing directions with real encrypted/signed protocol
messages through a controllable relay, forwarding, changed-event rejection,
forged responses, authentication challenges, relay switching, migration,
restarts, timeouts, cancellation, and credential isolation.

The October 30, 2026 browser checks used a disposable Chromium profile and a
local simulated NIP-46 signer over a secure WebSocket relay. They verified both
pairing directions, QR decoding from simulated camera frames, camera-track
cleanup, simulated camera denial, NIP-07 website approvals, remote signing and
NIP-44 encryption, omitted remote previews, and reconnection after stopping the
extension worker. These checks did not use a physical signing device.
