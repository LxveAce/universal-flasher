# THREAT MODEL

## What this protects, and for whom

**Asset:** the data on a single ESP32 Marauder that the operator owns — captured PCAPs, Evil-Portal
templates/results, wardrive logs, SSID lists, and the firmware's own configuration — plus the
contents of an SD card inserted in that device.

**Owner:** an individual conducting *authorized* security testing who wants their own field device
to be confidentiality-protected if it is lost, stolen, or taken from them. This is a **defensive,
owner-only, single-device** control. It is the embedded-hardware analogue of full-disk encryption
with a duress/nuke password (Kali LUKS Nuke), a duress PIN (GrapheneOS), or a dead-man cable
(BusKill / USBKill).

**Explicit non-goal / prohibited use:** destroying data to obstruct a lawful investigation or to
defeat a valid legal order. That is illegal in most jurisdictions (e.g. US 18 U.S.C. §1519
obstruction; analogous statutes elsewhere) and is **not** a supported use case. Use this only on
your own device, for confidentiality, within the law that applies to you.

## Adversaries considered

| # | Adversary | Capability | What we do about it |
|---|-----------|-----------|---------------------|
| A1 | Casual finder / thief | Powers it on, pokes the UI | Boot password gate; wrong attempts → lock/backoff (disarmed) or wipe (armed). |
| A2 | Opportunist with a laptop | Tries to read/flash over USB | T2: Flash Encryption makes a dump meaningless; Secure Boot + disabled UART download stop reflash-past-gate. T1: **not** protected — selective `guardcfg` erase, `armed=0`/`cfg_ver`/`att_ct`/`kdf_iter` NVS tamper, otadata rewrite, or a full reflash (incl. via this project's own flasher) all bypass the gate; enumerated in "Residual risks" below. |
| A3 | Tamper / snatch | Opens the case or yanks the device | Dead-man arming line (armed): case-open/cut/**disconnect** reads NOT-ARMED → wipe. Best-effort given power-loss timing. **Limit:** the single-ended line detects open/cut/disconnect, **not** an attacker who *clamps* the pin to the armed level (see "stuck-at" note below). |
| A4 | Coercion ("unlock it") | Demands the password | Duress: entering a wrong password the configured number of times wipes instead of unlocking. (Owner's choice; understand local law on compelled passwords.) Note: a *recovered* real password also enables the authenticated serial **host-wipe** (a force-wipe DoS), not only unlock — see "Residual risks." |
| A5 | Forensics lab | Chip-off, JTAG, FTL spare-area recovery | T2 (encryption) is the only real defense. SD remanence and a *removed* SD card are out of scope. Honestly documented as a limit. |

## Trust boundaries

- **Provisioning host** (the flasher running `provision.py`) is trusted at flash time. The password
  is typed there, hashed with PBKDF2-HMAC-SHA256 + a random salt, and only `{salt, hash, params}`
  ever reach the device. The host zeroizes the plaintext; it is never logged or passed as an argv.
- **NVS `guardcfg`** is trusted storage *on* the device. The salted hash is safe in plaintext NVS.
  Hiding `arm_pin`/`arm_level` from a chip-reader requires NVS encryption (T2).
- **The Marauder app** is *not* part of the gate's TCB in the GUARDIAN variant (it runs only after
  the gate passes). In the FORK variant the gate shares the image with Marauder; the gate code runs
  first in `setup()` and must complete before any Marauder subsystem starts.

## Failure-mode posture (fail safe = do not destroy)

The design deliberately biases away from accidental destruction:

- **Unprovisioned ⇒ cannot wipe.** **Master-disarmed (default) ⇒ cannot wipe.** Both are required
  before any trigger is even evaluated.
- **Correct password always wins** and never wipes, regardless of the arming line (except the
  dead-man pre-check, which is a hard hardware gate the owner explicitly enabled).
- **Brownout/undervoltage boot SUPPRESSES destruction (never wipes), but the CORRECT PASSWORD IS
  STILL REQUIRED to boot (no bypass).** A flaky rail must never fire an irreversible erase or read the
  arming line, so the destruct-capable armed flow is suppressed — but the gate itself is **not**
  skipped: the password is still demanded before boot (see "Brownout weaponization" below). A
  brownout boot can at most degrade an armed board to "locked, password still required," never to
  "open."
- The one fail-*toward*-destruction behavior — a cut arming wire wiping an **armed** board — is the
  dead-man feature itself, is opt-out (`deadman=0`), and is loudly documented.

## Residual risks (accepted / documented, not solved)

- **T1 builds are bypassable by a capable attacker — and the disarm is cheaper than a chip-pull.**
  "T1 reflashable" is not just "reflash the whole app"; because T1 has **no Secure Boot / Flash
  Encryption**, an attacker with USB/JTAG access can read and rewrite `guardcfg` NVS and the boot
  chain directly. The specific T1 disarm primitives we have identified (several **CONFIRMED on
  hardware**) are:
  - **Selective `guardcfg` erase — CONFIRMED on hardware.** Erasing *only* the `guardcfg` partition
    (e.g. `esptool erase_region <guardcfg off> <size>`, offset readable from the partition table at
    0x8000) drops the board to **unprovisioned** → `BootGate::run()` returns `GATE_PASS` and the
    board boots plain Marauder **with all captured data intact**. The fail-safe "unprovisioned never
    wipes" invariant is exactly what the attacker exploits: wiping the *gate config* is not wiping
    the *data*. This is the cheapest full bypass and needs no reflash of the app at all.
  - **`armed=0` downgrade.** Rewriting the single `armed` byte in `guardcfg` NVS to 0 → master
    DISARMED → boot proceeds, destruct physically impossible. (Provisioned + disarmed still requires
    nothing to read the data, since disarmed only suppresses *wiping*, not reading.)
  - **`cfg_ver` corruption.** Setting `cfg_ver` to any value the firmware does not recognize trips
    the fail-safe "unknown schema ⇒ NOT provisioned" path (§4.1) → `GATE_PASS`, data intact. Same
    "fail-safe is the bypass" shape as the selective erase.
  - **`att_ct` reset.** Rewriting `sgate_rt.att_ct` back to 0 between guesses defeats the
    monotonic/power-cycle-safe counter, restoring effectively unlimited offline guessing against the
    (dumpable) hash.
  - **`kdf_iter` downgrade.** Lowering `kdf_iter` in NVS (then re-deriving) cheapens an online
    re-guess; combined with the dumpable hash this only matters alongside a weak passphrase, but it
    is one more T1 NVS-tamper primitive.
  - **Wipe-tombstone (`sgate_rt.wipe_armed`) — round-2 hardened.** The runtime tombstone the
    firmware uses to make an interrupted wipe **resume** on the next boot is, on T1, just another
    writable plaintext-NVS byte. Hand-setting it on a board that is **disarmed or unprovisioned** is
    *not* a way to force a wipe: round 2 closes this — a tombstone found on a board that is not
    `provisioned + master-armed` is treated as **CLEANUP-ONLY** (clear the stale tombstone and boot
    normally), **never** a destructive trigger. A destructive *resume* requires the full destruct
    preconditions all over again: **provisioned + master-armed + a good supply rail** (an
    undervoltage/brownout boot suppresses the destruct-capable path per "Brownout weaponization"
    below). So while an attacker can still *write* the byte on T1, on a disarmed/unprovisioned board
    it can only cause a harmless cleanup, not data loss — it is listed here as a tamper *surface*,
    not a bypass. (T2 makes it unwritable off-device like the rest of `guardcfg`/`sgate_rt`.)

  All of the above are **write/erase attacks on plaintext T1 NVS + flash**. **T2 (Secure Boot v2 +
  Flash Encryption) is the real mitigation:** it makes `guardcfg` unreadable/unwritable off-device,
  authenticates the boot chain so a tampered NVS/app will not boot, and is the only tier that turns
  these from "trivial" into "infeasible".
- **The project's own flasher is a turnkey reflash-past-gate on T1.** `headless-marauder-gui`'s
  `flash_suicide()` / app-mode `flash()` (`marauder_core/flasher.py`) will, on a **T1** board,
  cheerfully write a fresh bootloader + partitions + app + a benign/attacker-chosen `guardcfg.bin`
  over the top — i.e. it is a ready-made tool to reflash *past* the gate (or to drop a new
  unprovisioned/disarmed config). This is inherent to T1 (no Secure Boot to reject the image), not a
  flaw in the flasher; it is called out so nobody assumes "you'd need custom tooling." On **T2** the
  same flasher cannot reflash past the gate (Secure Boot rejects the unsigned image / Flash
  Encryption garbles it). Separately, suicide **bundles** were originally **trust-on-first-build**
  (the flasher wrote whatever `.bin`s were in the bundle dir with no integrity check); the flasher
  **now recomputes each image's SHA-256 and enforces it against the manifest** (`_sha256_file` +
  the per-entry `sha256` check in `flash_suicide`), aborting on mismatch. **Round-2: every suicide
  bundle entry now REQUIRES a `sha256`** — the old back-compat path that flashed a no-`sha256` entry
  with only a TOFU *warning* is **closed**, so the "just strip the `sha256` field to downgrade to
  trust-on-first-build" bypass no longer exists (a missing digest is now a hard abort; regenerate the
  bundle with `provision.py` so every entry carries one).
  - **What this `sha256` actually buys (corrected — it is NOT attacker-integrity).** The digest is
    **co-located in the same `bundle.json`** that the bundle dir ships, and `bundle.json` is just as
    tamperable as the `.bin`s it describes. So enforcing it protects against **corruption / accident /
    a partial or swapped file** — it does **not** stop a *determined attacker* who simply edits a
    `.bin` **and** regenerates the matching digest in `bundle.json` (the manifest is not signed). Real
    image integrity requires an **out-of-band / signed manifest** (a signature the flasher verifies
    against a key it did not get from the same bundle, or an externally published digest) — see the
    supply-chain note in `SPEC.md` §14. The in-manifest `sha256` is an anti-corruption / anti-fumble
    check and a TOFU floor, not a defense against a host or bundle that is already hostile.
- **A recovered/cracked password is not just an unlock — it is also a force-wipe.** On a headless
  (`GATE_INPUT_SERIAL`) **armed** build the authenticated serial host-wipe (`wipe` → password →
  `REASON_HOST_WIPE`) triggers `SelfDestruct` on a **correct** password. So an attacker who recovers
  the passphrase (offline crack of a dumped T1 hash, shoulder-surf, coercion) can both **unlock** and
  **deliberately destroy** the data over USB — a **force-wipe DoS** against the owner, not only a
  confidentiality break. This is by design (the owner wanted a panic-wipe), but it widens the impact
  of any password compromise. T2 (hash not dumpable) plus a strong passphrase is the mitigation;
  there is no separate wipe-only vs unlock-only credential.
- SD overwrite cannot guarantee destruction of FTL-remapped cells; encryption-at-rest is the fix.
  (The stock-SD path is also **file + free-space overwrite only — no guaranteed format/secure-erase**;
  see SPEC §8.)
- **Brownout weaponization (CONFIRMED, on hardware).** The "undervoltage boot ⇒ treat as DISARMED"
  reliability rule was a fail-safe (don't fire an irreversible erase on a sagging rail). **Risk (as
  originally written):** a forced brownout boot — an attacker deliberately under-volting the rail at
  power-on — took the disarmed branch and returned `GATE_PASS` **before the password was ever
  requested**, i.e. a brownout was a free gate bypass on any board (armed or not). **Fix:** the
  undervoltage path now still **requires a correct password to boot** — it only suppresses the
  *destruct-capable* armed flow (no arming-line read, no wipe on a flaky rail), it does **not** skip
  the gate. A brownout can therefore at most degrade an armed board to "locked, password still
  required," never to "open." (T2 additionally prevents the attacker from reflashing around the gate
  if they give up on the brownout route.)
- **GUARDIAN otadata-rewrite "skip the Guardian" bypass.** In the GUARDIAN variant the gate is the
  **factory** app and boots Marauder in `ota_0` only after passing. On **T1**, an attacker can simply
  rewrite **`otadata`** (set the boot partition to `ota_0`, or write a normal `boot_app0`-style seed
  at the otadata offset) so the bootloader boots the **unmodified Marauder in `ota_0` directly,
  skipping the Guardian gate entirely** — the data in `ota_0`/spiffs is then served with no password.
  This is the same plaintext-flash-tamper class as the `guardcfg` primitives above. Mitigations:
  **T2** (Secure Boot authenticates the boot selection / Flash Encryption protects it) is the real
  fix; defense-in-depth `CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE` + having Marauder never mark itself
  valid causes a fall-back to the Guardian factory app, but on T1 a determined attacker who controls
  `otadata` can still force the `ota_0` boot. Treat GUARDIAN-on-T1 as defense-in-depth only, not a
  boundary.
- A device snatched **while powered and mid-wipe** may not finish the bulk erase (no instant
  crypto-erase on ESP32).
- **Dead-man "stuck-at-armed" defeat (A3).** The arming line is **single-ended**, so it can only
  detect that the line has left the armed level — i.e. an OPEN/CUT/DISCONNECT (the wire reads
  NOT-ARMED ⇒ wipe when armed). It **cannot** detect an attacker who physically **clamps** the pin
  to the armed level (e.g. a probe/jumper holding it at `arm_level` while the case is opened): the
  read stays ARMED and the dead-man never fires. Detecting a stuck-at fault would require a
  **differential or actively-toggling** arming signal (the firmware verifying an expected
  edge/pattern rather than a static level), which this single-pin design does not implement.
  Accepted limit, not solved.
- Compelled-password law varies by jurisdiction; the duress feature is a personal-risk decision.
- The boot-chain self-erase ("brick") is unverified until the hardware spike passes.
- **T1 leaves the running app image — "data-wiped" is not "trace-free".** Stage 2 cannot erase the
  *currently-running* app partition (doing so crashes the CPU mid-wipe), so on a T1 (`brick=0`) board
  the firmware **binary survives** a successful wipe: on FORK that is the Marauder image with the
  compiled-in `BootGate`/`SelfDestruct`/`GateCrypto` code; on **GUARDIAN** it is the whole `factory`
  gate image (`wipeInternal` now enumerates `factory`, but when factory IS the running gate it is
  deferred to the brick stage). A chip dump therefore still reveals "this device ran anti-forensic
  duress firmware." **Trace-free operation requires `brick=1` (or T2 Flash Encryption making the image
  ciphertext).** Do not read "data-wiped" as "no recoverable trace" on T1.
- **RTC slow memory / PSRAM are out of scope of the flash wipe.** The flash scrub does not clear RTC
  RAM (survives some resets / deep sleep) or PSRAM. The plaintext password buffer is zeroized in
  `BootGate`, and `SelfDestruct::trigger` now volatile-zeros the in-RAM `salt`+`pwhash` before the
  halt/brick, but any key material that *transited* PSRAM or RTC RAM is only guaranteed gone on
  power-off. Power the board off after a T1 wipe.
- **The wipe overwrite is defense-in-depth, not the guarantee.** A single NOR erase is forensically
  sufficient (no remanence); `flash_passes` random overwrite is optional polish that the `fast_wipe`
  and resume paths skip for reliability. The load-bearing step is the final erase + raw-read verify.
