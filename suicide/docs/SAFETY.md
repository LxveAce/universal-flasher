# SAFETY — read before you flash, arm, or test

Suicide Marauder can **permanently and irrecoverably destroy data** — by design. This document is
about not destroying *the wrong* data (yours, by accident). It is as important as the source code.

> **Scope & ethics.** This is an **owner-only, defensive** anti-forensic layer for an ESP32
> Marauder *you own*, to protect *your own* data against device theft, loss, or coercion — the same
> category as Kali's LUKS Nuke, GrapheneOS's duress PIN, and BusKill. It is **not** a tool for
> destroying evidence to obstruct a lawful investigation; doing so is a crime in most
> jurisdictions (e.g. US 18 U.S.C. §1519). You are responsible for lawful use. See
> [`THREAT-MODEL.md`](THREAT-MODEL.md) and [`LICENSING.md`](LICENSING.md).

## The layered safety model (why an accident is hard)

A wipe is only possible when **all** of these are true at once:

1. **Provisioned** — the board was flashed with a Suicide build *and* a password was set. A plain
   Marauder, or a Suicide build with no password provisioned, **cannot wipe** (`BootGate` returns
   `GATE_PASS` immediately).
2. **Master-armed** — the `armed` flag in `guardcfg` NVS is `1`. **Default is `0` (DISARMED).** You
   must deliberately arm the device. A disarmed board never runs the destruct logic.
3. **A trigger fires** — *either* the dead-man line is not in its armed position (dead-man mode)
   *or* the wrong password is entered `max_att` times (default 2).

Steps 1–2 are the two-factor safety: a fresh, lost-then-found, or bench device is safe. Step 3 is
the thing you actually armed it to do.

## Non-negotiable rules

- **Always build and test in `SUICIDE_SAFE_MODE` first.** In safe mode the *entire* chain —
  arming read, password attempts, trigger, and erase — runs against a **scratch partition with a
  dummy key** and only **logs** what it *would* destroy. Nothing real is touched. Do every dry run
  here.
- **Never arm a board that still holds data you have not backed up elsewhere.** Recovery from a real
  wipe is, by design, *re-flashing a blank device* — your data is gone. There is no "undo".
- **Keep the master `armed` flag off until the device is deployed** for its protective purpose.
- **The dead-man switch defaults to fail-toward-wipe (when armed).** A cut, unplugged, or floating
  arming wire reads NOT-ARMED and, on an armed board, **triggers the wipe**. If you do not want a
  loose wire to wipe, provision `deadman=0`: the arming line is then **ignored entirely** — the
  password alone gates boot and the line can **never** cause a wipe (it has *no* effect, not even to
  "keep the device locked"). The arming line only matters when `deadman=1`. Decide this consciously
  per device.
- **A brownout / undervoltage / low-battery boot SUPPRESSES destruction (never wipes), but the
  CORRECT PASSWORD IS STILL REQUIRED to boot** (no bypass — reliability-first). This stops a sagging
  rail from spuriously reading the arming line and wiping, while never opening the device: the gate
  still demands the password. Do not defeat this. (See `THREAT-MODEL.md` "Brownout weaponization.")
- **The brick (boot-chain self-erase) is UNVERIFIED on hardware.** Do not enable `brick=1` on a board
  you care about until the spike in [`SPIKE-PLAN.md`](SPIKE-PLAN.md) has passed on a *sacrificial*
  board of the same chip/flash size. SAFE_MODE never performs the real brick.
- **T2 (Secure Boot + Flash Encryption) burns eFuses IRREVERSIBLY.** A mistake there bricks the board
  with no recovery and is not undoable. It is behind a separate, explicitly-warned flasher checkbox.
  Only enable it when you understand the one-way consequences.

## Known limits (stated honestly)

- **SD destruction is best-effort.** Managed-NAND wear-leveling/over-provisioning can retain copies
  in remapped cells that overwrite cannot reach. The only strong guarantee is at-rest encryption of
  the SD (T2). A card physically removed before the trigger is unreachable.
- **Without T2, the gate is cosmetic against a capable attacker** — they can pull the chip or
  re-flash past Guardian over UART. T1 protects against a casual finder, not a forensics lab.
- **No runtime crypto-erase exists on ESP32**, so a wipe is bulk erase (seconds to ~a minute on a
  large part), not the instant key-destroy that BusKill/LUKS-Nuke use. A device snatched while
  powered may not finish. This is a hardware limit, not a bug.
- **The dead-man line catches cut/disconnect, not "stuck-at-armed".** The arming pin is
  single-ended: it reliably detects an OPEN / CUT / DISCONNECTED wire (reads NOT-ARMED ⇒ wipe when
  armed), but it **cannot** detect an attacker who *clamps* the pin to the armed level (a probe or
  jumper holding it at `arm_level`). A stuck-at-armed pin defeats the dead-man — the gate just sees
  "armed" and falls through to the password prompt. Catching that would require a differential or
  actively-toggling arming signal; this design uses a static level read. See `THREAT-MODEL.md` (A3).

## Pre-arm checklist

- [ ] Data on this board/SD is backed up elsewhere (or you accept its loss).
- [ ] You tested the full chain in `SUICIDE_SAFE_MODE` and saw the simulated-wipe logs.
- [ ] You chose `deadman` (1=cut-wire-wipes / 0=arming-line-ignored, password-only) deliberately.
- [ ] You confirmed the arming pin is correct for this board and is **not** a strapping pin.
- [ ] If `brick=1`: the SPIKE-PLAN test passed on a sacrificial twin board.
- [ ] If T2: you accept irreversible eFuse burns and no recovery.
- [ ] You understand and accept the legal posture in `THREAT-MODEL.md`.
