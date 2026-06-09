# LICENSING — posture for the Suicide Marauder fork

> **Not legal advice.** This is an engineering summary of the license obligations the project inherits,
> so the operator can make an informed decision before distributing any binary. Confirm the actual
> upstream `LICENSE` files (they can change between Marauder versions) and, if you intend to
> distribute binaries to third parties, get a real legal review. **Recommendation up front: keep this
> repository private until that review is done.**

This concerns the **FORK** variant (default, SPEC §1), which compiles the gate **into** a fork of
ESP32Marauder. Forking + modifying upstream source and shipping the resulting firmware creates a
**derivative work**, so the produced binary inherits the upstream components' license terms. The
table below is the load-bearing summary; the sections expand each row.

| Component | License (verified) | Linking | Obligation if you distribute the binary to third parties |
|-----------|--------------------|---------|-----------------------------------------------------------|
| ESP32Marauder app (justcallmekoko) | **MIT** © 2020 koko | source-incorporated (you fork it) | Keep the MIT copyright + permission notice. MIT does **not** require publishing your source. |
| ESPAsyncWebServer (me-no-dev) | **LGPL-3.0** | **statically linked** into the single firmware image | LGPL-3.0 relink + notice obligations are triggered (see §3). |
| `esp-idf-nvs-partition-gen` / `nvs_partition_gen.py` (Espressif) | **Apache-2.0** | host build tool, not linked into firmware | Preserve Apache-2.0 NOTICE/attribution if you redistribute the tool. Does not affect the firmware binary. |
| Your gate code (`firmware/bootgate/*`, `host/*`) | your choice | new code | Pick and state a license; it sits atop the above. |

> **Trigger condition for everything copyleft below: *distribution* of the binary to third parties.**
> Building and running the firmware on your own device, privately, triggers **none** of the LGPL
> redistribution obligations. The obligations attach when you hand the compiled image to someone else.

---

## 1. The fork creates a derivative work

The Suicide build is a fork of ESP32Marauder with the boot-gate (`BootGate::run()`) hooked into
`setup()` and the gate modules compiled in (SPEC §1, FORK variant). That is, by definition, a
modified/derivative work of the upstream firmware: **the binary inherits the upstream components'
license terms.** You cannot escape an upstream library's license by forking around it — whatever the
linked components require, the shipped image must honor.

The GUARDIAN variant (SPEC §1, 8 MB+) keeps Marauder as an *unmodified* image in `ota_0` and gates
from a separate tiny factory app. That gives a cleaner license boundary (the gate is its own binary
that chainloads an unmodified Marauder), but it does **not** remove the LGPL obligation if the
Marauder image you ship still statically links ESPAsyncWebServer. GUARDIAN improves the *structural*
separation, not the underlying obligation.

---

## 2. ESP32Marauder app — MIT

Verified upstream: the ESP32Marauder `LICENSE` is **MIT, © 2020 koko**
([`RESEARCH-DIGEST.md`](RESEARCH-DIGEST.md), integration section). MIT is permissive:

- You may fork, modify, and ship binaries.
- You must **retain the MIT copyright notice and permission text** in distributions.
- MIT does **not** require you to publish your modified source. So the gate source can stay private
  as far as Marauder's own license is concerned — the constraint that follows comes from
  ESPAsyncWebServer, not from Marauder.

> ⚠ The "MIT, only LGPL file is ESPAsyncWebServer" finding was rated **UNCERTAIN** in the digest
> only because the auditor could not inspect the user's *private* firmware repo to confirm no other
> copyleft component had been added. **Action: confirm the upstream `LICENSE` file and scan the
> fork's actual dependency tree** (every bundled library/`library.json`) before relying on "MIT +
> one LGPL lib." If a GPL-licensed component has been pulled in anywhere, the whole-binary posture
> changes to GPL and this document must be revised.

---

## 3. ESPAsyncWebServer — LGPL-3.0, statically linked (the real obligation)

Verified upstream: `me-no-dev/ESPAsyncWebServer` declares **`"license": "LGPL-3.0"`** in its
`library.json`. ESP32 firmware is a single statically-linked image — there is no dynamic linking on
the device — so ESPAsyncWebServer is **statically linked into the Marauder/Suicide binary.**

LGPL-3.0's relink/notice obligations are weakest under *dynamic* linking (where a user can swap the
shared library). With **static** linking, **if you distribute the binary to third parties**, LGPL-3.0
still imposes obligations, in essence:

1. **Provide the means to relink.** The recipient must be able to replace the LGPL component with a
   modified version and rebuild a working binary. In practice for static firmware this means shipping
   the object files / sufficient build materials (or the corresponding source + linkable objects) so
   the LGPL part can be swapped and the image relinked.
2. **Give prominent notice** that the work uses ESPAsyncWebServer under LGPL-3.0, and include a copy
   of the LGPL-3.0 (and GPL-3.0, which it references) license text.
3. **Make the LGPL component's source available** (including any modifications you made to *that*
   component).

These obligations attach **only on distribution to third parties.** Private, owner-only use (which is
this tool's entire stated purpose — SAFETY.md, THREAT-MODEL.md) does **not** trigger them. The
"no source publication needed" shorthand is **only safe if the binary is never distributed.** The
moment you publish a release `.bin` or hand a flashed board to someone else, the static-link LGPL
obligations above apply.

> Practical option if distribution is desired and the relink burden is unwelcome: see whether
> ESPAsyncWebServer can be a build option that is **excluded** from the Suicide build (if the gate +
> the Marauder features you ship do not require the async web server), removing the LGPL component
> entirely. Confirm against the actual feature set before assuming it can be dropped.

---

## 4. `nvs_partition_gen` — Apache-2.0 (host tool only)

The host provisioner (`host/provision.py`, SPEC §10) uses Espressif's NVS partition generator —
either the `esp-idf-nvs-partition-gen` PyPI package or the vendored `nvs_partition_gen.py`. Verified
license: **Apache-2.0** (the digest corrects an earlier "BSD/Apache" wording — it is Apache-2.0,
no BSD).

- Apache-2.0 is permissive and **does not** copyleft your code.
- It is a **host build tool**; it is not linked into the firmware, so it places **no** obligation on
  the device binary.
- If you **vendor** the tool into this repo or redistribute it, preserve its `LICENSE`/`NOTICE` and
  attribution. (Note: on current ESP-IDF, vendoring "the NVS generator" means including the
  `esp_idf_nvs_partition_gen` package, not a single standalone `.py` — the upstream script is now a
  thin shim that delegates to that module.)

`esptool` itself (GPL-2.0) is invoked as a separate host process by the flasher; invoking a program
is not linking, and it produces no firmware-binary obligation either.

---

## 5. Recommended posture

1. **Confirm the upstream `LICENSE` files** for the exact ESP32Marauder commit you fork and for
   ESPAsyncWebServer — licenses change between versions, and the MIT-vs-other determination is
   load-bearing. Scan the full dependency tree for any GPL component.
2. **Keep this repository private until reviewed.** It is an owner-only defensive tool; there is no
   need to publish binaries. Staying private side-steps every redistribution obligation in §3 while
   the legal review happens.
3. **If you decide to distribute binaries to third parties**, before doing so: include the MIT notice
   (Marauder), satisfy the LGPL-3.0 static-link relink + notice + source-availability obligations for
   ESPAsyncWebServer (§3) *or* drop that component from the build, and preserve Apache-2.0 attribution
   for any vendored Espressif tooling. Get the LGPL relink/notice mechanics reviewed by someone
   qualified — static-link LGPL compliance is the easiest thing here to get subtly wrong.
4. **State a license for your own new code** (`firmware/bootgate/*`, `host/*`, docs). It sits on top
   of the inherited terms; the most restrictive linked component (LGPL-3.0) sets the floor for the
   distributed *binary* regardless of what you pick for your sources.
5. **Re-run this analysis** whenever you bump the Marauder fork or its libraries, or switch FORK ↔
   GUARDIAN — the linked-component set is what determines the obligation, and it changes with the
   build.
