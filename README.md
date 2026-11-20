# Herdr Vault

An ESM library for Herdr mods. Copy this directory into each mod and import
`vault.js`. Ship the license and third-party notices with the library.

`seal` and `unseal` use AES-GCM and PBKDF2-SHA256. Passwords use 600,000
iterations. Random 192-bit codes from `generateVaultCode` use one iteration.
Pass a `VaultState` to retain a successful derivation for subsequent writes.
Call `close()` when a session ends, and use a fresh state for a new password.
Pass `{ legacy: true }` as the final argument to `unseal` to read older Music
records. Writes always use v2 hex encoding.

Derivation accepts a runtime with `check()`, a custom `derive()` or a yielding
`steps()` scheduler. Check cancellation again immediately before committing
storage. On Windows pass the installed worker path to `deriveOnWindows` and
use it for the standard password iteration count. The worker exchanges proofs
before sending vault material over loopback. Its per-run challenge is a
process argument and assumes other processes running as the same user are
trusted. Each mod owns storage, write ordering and reset.
