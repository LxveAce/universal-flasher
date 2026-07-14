"""S1 port (hmg 2f7ad9d / 63d3b78) — suicide self-wipe NUL-safe password + u8-bounded arm_pin/max_att.

universal-flasher's `suicide/provision.py` carried the earlier password-parity guards (empty / >63
bytes / leading-ws / `unlock ` prefix) and the fail-safe arm_level/arm_pull pairs + max_att>=1, but
was missing two hardening checks the headless-marauder-gui sibling already shipped:

  * validate_password: never rejected an EMBEDDED NUL byte. The firmware stores the secret in a
    char[64] C-string and truncates at the first NUL before hashing, so a password containing a NUL
    hashes to something the device can NEVER reproduce -- and on an ARMED board the *correct* password
    is then counted as a failed attempt and can trigger the self-wipe.
  * validate_args: never bounded arm_pin / max_att to the NVS u8 (guardcfg) range. A fat-fingered
    arm_pin=300 (or a negative from a UI that skipped range-checking), or max_att>255, can't round-trip
    the u8 field -> a corrupt nvs-gen or an ARMED board baked with an unusable dead-man pin the owner
    can never trigger to disarm.

Discriminating (fail on buggy HEAD, pass on the fix):
  - test_embedded_nul_password_rejected
  - test_max_att_over_u8_rejected
  - test_arm_pin_over_u8_rejected
  - test_arm_pin_negative_rejected
Guards (pass on both HEAD and the fix):
  - test_clean_password_still_accepted
  - test_valid_args_still_accepted
  - test_u8_boundary_values_accepted  (max_att=255, arm_pin=255 are IN range)
"""
import argparse

import pytest

import suicide

prov = suicide._get_provisioner()
ProvisionError = prov.ProvisionError


def _args(**over):
    ns = dict(kdf_iter=10000, max_att=2, arm_level=1, arm_pull=2, arm_pin=27, chip="esp32",
              sd_passes=1, flash_passes=1)
    ns.update(over)
    return argparse.Namespace(**ns)


# ── discriminating ─────────────────────────────────────────────────────────────────────────────
def test_embedded_nul_password_rejected():
    with pytest.raises(ProvisionError):
        prov.validate_password(b"good\x00secret")


def test_max_att_over_u8_rejected():
    with pytest.raises(ProvisionError):
        prov.validate_args(_args(max_att=300))


def test_arm_pin_over_u8_rejected():
    with pytest.raises(ProvisionError):
        prov.validate_args(_args(arm_pin=300))


def test_arm_pin_negative_rejected():
    with pytest.raises(ProvisionError):
        prov.validate_args(_args(arm_pin=-1))


# ── guards (unchanged behavior on both HEAD and fix) ─────────────────────────────────────────────
def test_clean_password_still_accepted():
    # A normal password with no NUL / whitespace / reserved prefix must still pass.
    assert prov.validate_password(b"correct horse") is None


def test_valid_args_still_accepted():
    assert prov.validate_args(_args()) is None


def test_u8_boundary_values_accepted():
    # 255 is the top of the u8 range -> IN bounds; must not raise for the bound itself.
    assert prov.validate_args(_args(max_att=255, arm_pin=255)) is None


# ── S7 sweep (bound sd_passes / flash_passes to the NVS u8, same class as arm_pin/max_att) ────────
# validate_args did not bound the overwrite-pass counts. The CLI coerces them via the _u8 argparse
# type, but suicide.build_bundle (web/tk/tui/Qt front-ends + cyber-controller) constructs the
# Namespace directly and bypasses that, so an out-of-range sd_passes/flash_passes reached the u8 NVS
# row. Kept in parity with the headless-marauder-gui sibling.
def test_sd_passes_over_u8_rejected():
    with pytest.raises(ProvisionError):
        prov.validate_args(_args(sd_passes=300))


def test_flash_passes_over_u8_rejected():
    with pytest.raises(ProvisionError):
        prov.validate_args(_args(flash_passes=300))


def test_passes_negative_rejected():
    with pytest.raises(ProvisionError):
        prov.validate_args(_args(sd_passes=-1))


def test_passes_boundary_and_zero_accepted():
    # 0 = skip that overwrite stage (valid); 255 = top of the u8 range (in bounds). Neither raises.
    assert prov.validate_args(_args(sd_passes=0, flash_passes=255)) is None


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
