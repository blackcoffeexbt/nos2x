# Private-key boundaries

Private keys stay in the extension's local storage and background worker, except
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
- Extension-page CSP blocks outbound fetches, remote scripts, embedded frames,
  objects, and form submissions. Links to external profiles contain public keys
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
