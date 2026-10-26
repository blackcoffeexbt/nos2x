# nos2x

### notes and other stuff signed by an extension

## Nostr Signer Extension

Use this to sign [Nostr](https://github.com/nostr-protocol/nostr) events on web-apps without having to give them your keys.

It implements [NIP-07](https://github.com/nostr-protocol/nips/blob/master/07.md), i.e. provides a `window.nostr` object which has the following methods:

```
async window.nostr.getPublicKey(): string // returns your public key as hex
async window.nostr.signEvent(event): Event // returns the full event object signed
async window.nostr.nip04.encrypt(pubkey, plaintext): string // returns ciphertext+iv as specified in nip04
async window.nostr.nip04.decrypt(pubkey, ciphertext): string // takes ciphertext+iv as specified in nip04
async window.nostr.nip44.encrypt(pubkey, plaintext): string // takes pubkey, plaintext, returns ciphertext as specified in nip-44
async window.nostr.nip44.decrypt(pubkey, ciphertext): string // takes pubkey, ciphertext, returns plaintext as specified in nip-44
```

This extension is Chromium-only. For a maintained Firefox fork, see [nos2x-fox](https://diegogurpegui.com/nos2x-fox/).

## Demo Video

https://user-images.githubusercontent.com/1653275/149637382-65d50a85-fe30-4259-b7de-99c88b089b53.mp4

## Install

- [Chrome Extension](https://chrome.google.com/webstore/detail/nos2x/kpgefcfmnafjgpblomihpgmejjdanjjp)

## Develop

To run the plugin from this code:

```
git clone https://github.com/fiatjaf/nos2x
cd nos2x
yarn
./build.js prod
```

then

1. go to `chrome://extensions`;
2. ensure "developer mode" is enabled on the top right;
3. click on "Load unpackaged";
4. select the `extension/` folder of this repository.

---

LICENSE: public domain.

Icon made by <a href="https://www.freepik.com" title="Freepik">Freepik</a> from <a href="https://www.flaticon.com/" title="Flaticon">www.flaticon.com</a>.

## Multiple identities

Open **Manage identities** from the extension popup to import an `nsec`, a
64-character hex private key, or a password-encrypted `ncryptsec`. You can also
generate a key, give each identity a name, and reveal or export an individual
key as text and a QR code. Enter an export password to produce an encrypted
`ncryptsec`; leave it empty to reveal the `nsec`. Revealed keys and password
fields are cleared when you switch identities or leave the options tab/window.
Revealed keys also hide automatically after 60 seconds. See [SECURITY.md](SECURITY.md)
for the trust boundaries and local-storage limitations.

When a website first requests access, select the identity to use in the approval
window. A single saved identity is preselected. Approving remembers the identity
for that hostname and port, across its tabs. Permissions remain separate for
each identity and website, including event-kind-specific signing permissions.
Rejecting the first request does not assign an identity. Different websites can
use different identities simultaneously.

To change a website's identity, open the extension popup while visiting it and
choose another identity. Reload all of that website's open pages before making
further requests. You may also need to sign out and sign in again in the website.
The extension blocks requests from old pages rather than silently signing with
a different identity. `window.nostr` methods keep their existing signatures.

Removing an identity requires confirmation showing its assigned websites. Its
permissions and assignments are removed, and another key is never substituted
automatically. Back up keys before removing them. Keys are stored locally in
plaintext, as in earlier versions; encrypted export does not lock the extension
or encrypt its local storage. No keys or profiles are sent to remote services by
the identity management screens. Opening the profile link visits nosta.me.

On upgrade, the existing key becomes **Identity 1**, retaining its permissions
and the website assignments inferred from those permissions. The extension
verifies the migrated record before removing the old storage fields. If legacy
data is invalid or cannot be migrated, it remains intact and the options page
shows a recovery error. Preserve the extension's data before attempting recovery;
do not uninstall it to resolve a migration error.

Chromium 106 or later is required for document-specific request tracking. Identity
choices match hostname and port, as permissions did previously; HTTP and HTTPS
on the same hostname and port share the choice. External extension callers use
a separate `extension:<extension-id>` namespace. Notification preferences and
`nostr:` URL handling remain global settings. Approval windows expire after four
minutes; retry the request if an approval expires or the background worker was
restarted while it was open.

## Checks

Install dependencies with `npm ci`, then run:

```sh
npm test
npm run lint
npm run build
```

The tests use mocked browser APIs and real Nostr cryptography to check migration,
permissions, concurrent requests, approval validation, identity switching, and
NIP-04/NIP-44 isolation. Load `extension/` unpacked in Chromium to check the actual
options, approval, and toolbar popup screens. Generated build files are ignored
by Git and must be rebuilt after source changes.
