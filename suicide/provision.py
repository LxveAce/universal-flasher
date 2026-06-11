#!/usr/bin/env python3
# provision.py - Suicide Marauder host-side provisioner.
#
# Owner-only, DEFENSIVE anti-forensic ("duress") tooling for an ESP32 Marauder the operator owns.
# This script bakes a per-device `guardcfg` NVS partition image plus a blank otadata blob and a
# flash bundle manifest. See docs/SPEC.md sections 4, 9, and 10 (the canonical contract).
#
# SECURITY INVARIANTS (docs/SPEC.md section 4 / section 9):
#   * The plaintext password is NEVER stored, NEVER logged, and is NEVER a CLI argument.
#     It is read with getpass and held only in a bytearray that is zeroized after hashing.
#   * Only {salt, pwhash, kdf_iter, kdf_dklen} ever reach the device.
#   * salt = os.urandom(16); pwhash = pbkdf2_hmac('sha256', pw, salt, iter, dklen).  Stdlib only.
#   * Argon2id is intentionally NOT used (OWASP 19 MiB minimum is impossible on ESP32 RAM).
#   * Partition offsets/sizes are READ from the chosen partitions CSV -- never hardcoded.
#     (Marauder's otadata lives at 0xe000, not the stock 0xd000; we must not assume either.)
#
# Python 3.9+. Standard library only, except the NVS image generator which is provided by the
# `esp-idf-nvs-partition-gen` package (pip) or a vendored copy.  The dependency is guarded: if it
# is missing, this script prints an actionable message and exits non-zero instead of crashing.

import argparse
import csv
import hashlib
import importlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
from contextlib import contextmanager

# ----------------------------------------------------------------------------------------------
# Canonical schema constants -- MUST match docs/SPEC.md section 4 and firmware/bootgate/GateConfig.h
# ----------------------------------------------------------------------------------------------

NVS_NAMESPACE = "sgate"          # config namespace (GateConfig.h: NVS_NS_CFG)
CFG_VERSION = 1                  # GateConfig.h: CFG_VERSION
SALT_LEN = 16                    # GateConfig.h: SALT_LEN
KDF_DKLEN = 32                   # GateConfig.h: KDF_DKLEN
DEFAULT_KDF_ITER = 10000         # SPEC section 9: ~1s verify on classic ESP32 (150000 ~= 16.7s, measured)

OTADATA_FILL_BYTE = 0xFF         # SPEC section 10: otadata_blank = all 0xFF -> first boot factory

# The canonical partition that holds the gate config. Host + firmware both key off this name.
GUARDCFG_PART = "guardcfg"       # SPEC section 3 / section 4 (subtype nvs)
OTADATA_PART = "otadata"         # SPEC section 10 (subtype ota)

# NVS namespace-row sentinel used by nvs_partition_gen CSV format.
_NS_TYPE = "namespace"

# ----------------------------------------------------------------------------------------------
# Chip / flash facts the toolchain MUST branch on (SPEC section 2)
# ----------------------------------------------------------------------------------------------

# Supported chip families (esptool --chip names).
CHIPS = ("esp32", "esp32s2", "esp32s3", "esp32c3", "esp32c6", "esp32h2")

# Chips whose 2nd-stage bootloader lives at 0x0 (S3 + RISC-V) vs 0x1000 (classic ESP32 / S2).
# SPEC section 2: "2nd-stage bootloader offset | classic ESP32 / S2 = 0x1000 | S3/C3/C6/H2 = 0x0".
_BOOTLOADER_AT_0 = {"esp32s3", "esp32c3", "esp32c6", "esp32h2"}

# Fixed offsets (SPEC section 2 / section 10): partition table @0x8000, app @0x10000.
PARTITIONS_OFFSET = 0x8000
APP_OFFSET = 0x10000

# Per-chip strapping/boot pins (SPEC section 7). Chip-aware so we don't warn about a pin that is
# forbidden on one family but the documented default on another (e.g. GPIO2 is a C3 strap but the
# documented S3 default). Falls back to the classic-ESP32 set for unknown chips.
_STRAPPING_PINS = {
    "esp32":   {0, 2, 5, 12, 15},
    "esp32s2": {0, 45, 46},
    "esp32s3": {0, 3, 45, 46},
    "esp32c3": {2, 8, 9},
    "esp32c6": {8, 9, 15},
    "esp32h2": {8, 9, 25},
}


def bootloader_offset(chip):
    """Return the 2nd-stage bootloader flash offset for `chip` (SPEC section 2)."""
    return 0x0 if chip in _BOOTLOADER_AT_0 else 0x1000


def _strapping_pins_for_chip(chip):
    """Return the set of known strapping/boot pins for `chip` (SPEC section 7).

    Chip-aware so GPIO2 (a C3 strap) does not trip a warning on S3 where it is the documented
    default. Unknown chips fall back to the classic-ESP32 set (conservative).
    """
    return _STRAPPING_PINS.get(chip, _STRAPPING_PINS["esp32"])


# ----------------------------------------------------------------------------------------------
# Errors
# ----------------------------------------------------------------------------------------------

class ProvisionError(Exception):
    """User-facing, actionable provisioning error (printed without a traceback)."""


# ----------------------------------------------------------------------------------------------
# Partition-table parsing (offsets are READ here, never hardcoded -- SPEC section 2 / section 10)
# ----------------------------------------------------------------------------------------------

def _parse_size_token(tok):
    """Parse an ESP-IDF partition size/offset token.

    Accepts hex ('0x1F0000'), decimal ('8192'), and the K/M suffixes ('8K', '1M') that
    gen_esp32part.py supports. Returns an int (bytes) or None for an empty/auto field.
    """
    tok = (tok or "").strip()
    if not tok:
        return None
    mult = 1
    if tok[-1] in "kKmM":
        mult = 1024 if tok[-1] in "kK" else 1024 * 1024
        tok = tok[:-1].strip()
    try:
        val = int(tok, 0)  # base 0 -> handles 0x.. and plain decimal
    except ValueError as exc:
        raise ProvisionError(
            "could not parse partition size/offset token %r in the partitions CSV" % tok
        ) from exc
    return val * mult


def parse_partitions_csv(path):
    """Parse an ESP-IDF / gen_esp32part.py partition CSV.

    Columns: Name, Type, SubType, Offset, Size, Flags (offset may be blank = auto, which we
    cannot resolve here, so such tables are rejected for the partitions we care about).

    Returns: dict name -> {"type","subtype","offset","size"} with offset/size as ints (or None).
    """
    if not os.path.isfile(path):
        raise ProvisionError("partitions CSV not found: %s" % path)

    parts = {}
    # ESP-IDF partition tables allow auto offsets: each unspecified offset follows the previous
    # entry's end, aligned (apps to 0x10000, data to 0x1000). We resolve them so a table that
    # omits explicit offsets still yields concrete numbers for guardcfg/otadata.
    cursor = 0x9000  # conventional start after the partition table at 0x8000 (0x1000 long)
    with open(path, "r", encoding="utf-8", newline="") as fh:
        for raw in fh:
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            cols = [c.strip() for c in line.split(",")]
            # tolerate trailing empty column from the canonical SPEC CSV (lines end with a comma)
            while cols and cols[-1] == "":
                cols.pop()
            if len(cols) < 3:
                continue
            name = cols[0]
            ptype = cols[1]
            subtype = cols[2]
            offset = _parse_size_token(cols[3]) if len(cols) > 3 else None
            size = _parse_size_token(cols[4]) if len(cols) > 4 else None

            if offset is None:
                # auto offset: align cursor (apps 64K, data 4K) then place here
                align = 0x10000 if ptype == "app" else 0x1000
                if cursor % align:
                    cursor += align - (cursor % align)
                offset = cursor
            if size is not None:
                cursor = offset + size

            parts[name] = {
                "type": ptype,
                "subtype": subtype,
                "offset": offset,
                "size": size,
            }
    if not parts:
        raise ProvisionError("partitions CSV %s contained no partition rows" % path)
    return parts


def require_partition(parts, name):
    if name not in parts:
        raise ProvisionError(
            "partition %r not found in the partitions CSV. Present: %s"
            % (name, ", ".join(sorted(parts)))
        )
    p = parts[name]
    if p["offset"] is None:
        raise ProvisionError("partition %r has no resolvable offset in the CSV" % name)
    if p["size"] is None:
        raise ProvisionError("partition %r has no size in the CSV" % name)
    return p


# ----------------------------------------------------------------------------------------------
# Password hashing (PBKDF2-HMAC-SHA256, stdlib). Plaintext is zeroized after use.
# ----------------------------------------------------------------------------------------------

@contextmanager
def _zeroized(buf):
    """Context manager that zeroizes a mutable bytearray on exit (best effort)."""
    try:
        yield buf
    finally:
        try:
            for i in range(len(buf)):
                buf[i] = 0
        except TypeError:
            pass


def read_password_securely(confirm=True):
    """Read the password via getpass (never echoed, never argv, never logged).

    Returns a bytearray (mutable so the caller can zeroize it). The caller MUST zeroize.
    """
    import getpass

    pw1 = getpass.getpass("Gate password (input hidden): ")
    if not pw1:
        raise ProvisionError("empty password rejected")
    if confirm:
        pw2 = getpass.getpass("Confirm password: ")
        if pw1 != pw2:
            # do not leak which differed; just fail
            del pw1
            del pw2
            raise ProvisionError("passwords did not match")
        # overwrite the str copy reference (Python strs are immutable; best effort)
        pw2 = None
    buf = bytearray(pw1.encode("utf-8"))
    pw1 = None
    return buf


def derive_pwhash(pw_bytes, salt, iterations, dklen=KDF_DKLEN):
    """PBKDF2-HMAC-SHA256(password, salt, iterations, dklen). Matches GateCrypto.derive()."""
    # bytes(pw_bytes) copies into an immutable buffer for hashlib; the source bytearray remains
    # the caller's responsibility to zeroize.
    return hashlib.pbkdf2_hmac("sha256", bytes(pw_bytes), salt, iterations, dklen)


# ----------------------------------------------------------------------------------------------
# NVS CSV generation (namespace sgate; EXACT keys/types from SPEC section 4)
# ----------------------------------------------------------------------------------------------

def build_nvs_rows(args, salt, pwhash):
    """Return the ordered list of (key, type, encoding, value) rows for namespace `sgate`.

    Key names, NVS value types, and the namespace string are canonical (SPEC section 4 /
    GateConfig.h). The runtime namespace `sgate_rt` is NOT written here -- the device creates it
    (att_ct / lock_until) so a freshly provisioned board starts with a clean, zeroed counter.
    """
    rows = [
        # First row MUST be the namespace declaration for nvs_partition_gen.
        (NVS_NAMESPACE, _NS_TYPE, "", ""),
        ("cfg_ver", "data", "u8", str(CFG_VERSION)),
        ("salt", "data", "hex2bin", salt.hex()),
        ("pwhash", "data", "hex2bin", pwhash.hex()),
        ("kdf_iter", "data", "u32", str(args.kdf_iter)),
        ("kdf_dklen", "data", "u8", str(KDF_DKLEN)),
        ("armed", "data", "u8", str(args.armed)),
        ("arm_pin", "data", "u8", str(args.arm_pin)),
        ("arm_level", "data", "u8", str(args.arm_level)),
        ("arm_pull", "data", "u8", str(args.arm_pull)),
        ("deadman", "data", "u8", str(args.deadman)),
        ("max_att", "data", "u8", str(args.max_att)),
        ("wipe_ota", "data", "u8", str(args.wipe_ota)),
        ("wipe_nvs", "data", "u8", str(args.wipe_nvs)),
        ("wipe_spiffs", "data", "u8", str(args.wipe_spiffs)),
        ("wipe_sd", "data", "u8", str(args.wipe_sd)),
        ("brick", "data", "u8", str(args.brick)),
        ("sd_passes", "data", "u8", str(args.sd_passes)),
        ("flash_passes", "data", "u8", str(args.flash_passes)),
        ("fast_wipe", "data", "u8", str(args.fast_wipe)),
    ]
    return rows


def write_nvs_csv(rows, path):
    """Write the nvs_partition_gen CSV with the exact header `key,type,encoding,value`."""
    with open(path, "w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh, lineterminator="\n")
        writer.writerow(["key", "type", "encoding", "value"])
        for row in rows:
            writer.writerow(row)


# ----------------------------------------------------------------------------------------------
# nvs_partition_gen invocation (dependency-guarded; never receives the password)
# ----------------------------------------------------------------------------------------------

_MISSING_NVS_GEN_MSG = (
    "Could not find the NVS partition generator (esp-idf-nvs-partition-gen).\n"
    "This tool is NOT bundled with esptool, so install it (or vendor it):\n"
    "\n"
    "    pip install esp-idf-nvs-partition-gen\n"
    "\n"
    "Alternatively, vendor the IDF release-branch nvs_partition_gen.py (Apache-2.0) and put it\n"
    "on PYTHONPATH or pass its directory via --nvs-gen-dir.\n"
)


def _find_nvs_gen(nvs_gen_dir=None):
    """Locate a way to run nvs_partition_gen.

    Returns one of:
        ("module", module_object)          -- the pip package esp_idf_nvs_partition_gen
        ("script", "/abs/path/nvs_partition_gen.py")  -- a vendored standalone script
    Raises ProvisionError with an actionable message if nothing is available.
    """
    # 1) explicit vendored directory
    if nvs_gen_dir:
        cand = os.path.join(nvs_gen_dir, "nvs_partition_gen.py")
        if os.path.isfile(cand):
            return ("script", cand)
        raise ProvisionError(
            "--nvs-gen-dir %r does not contain nvs_partition_gen.py" % nvs_gen_dir
        )

    # 2) repo-local vendored copy: host/vendor/nvs_partition_gen.py
    here = os.path.dirname(os.path.abspath(__file__))
    vendored = os.path.join(here, "vendor", "nvs_partition_gen.py")
    if os.path.isfile(vendored):
        return ("script", vendored)

    # 3) pip package esp-idf-nvs-partition-gen exposes module esp_idf_nvs_partition_gen
    for mod_name in ("esp_idf_nvs_partition_gen.nvs_partition_gen",
                     "esp_idf_nvs_partition_gen",
                     "nvs_partition_gen"):
        try:
            mod = importlib.import_module(mod_name)
            return ("module", mod)
        except Exception:
            continue

    raise ProvisionError(_MISSING_NVS_GEN_MSG)


def generate_nvs_bin(csv_path, out_bin, size_bytes, nvs_gen_dir=None):
    """Generate the NVS partition image from `csv_path` sized to `size_bytes`.

    The password never appears in argv: the CSV references only salt/hash/params. The CSV path
    is fine to log; the password is not in it (only the salted hash).
    """
    kind, target = _find_nvs_gen(nvs_gen_dir)
    size_hex = "0x%X" % size_bytes
    # nvs_partition_gen requires the size be a multiple of 4096 and large enough for the data.
    if size_bytes % 0x1000:
        raise ProvisionError(
            "guardcfg partition size %s is not a multiple of 0x1000 (4096)" % size_hex
        )

    if kind == "script":
        cmd = [
            sys.executable, target, "generate",
            csv_path, out_bin, size_hex,
        ]
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if proc.returncode != 0:
            raise ProvisionError(
                "nvs_partition_gen failed (exit %d):\n%s"
                % (proc.returncode, proc.stdout.decode("utf-8", "replace"))
            )
        return

    # kind == "module": call the package's generate entry point in-process.
    mod = target
    if hasattr(mod, "nvs_part_gen") and hasattr(mod.nvs_part_gen, "generate"):
        mod = mod.nvs_part_gen
    # The IDF package exposes `generate(args)` taking an argparse-like namespace; build it.
    gen = getattr(mod, "generate", None)
    if gen is None:
        # fall back to invoking it as a module via subprocess (still no password in argv)
        cmd = [sys.executable, "-m", mod.__name__, "generate", csv_path, out_bin, size_hex]
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if proc.returncode != 0:
            raise ProvisionError(
                "nvs_partition_gen module failed (exit %d):\n%s"
                % (proc.returncode, proc.stdout.decode("utf-8", "replace"))
            )
        return

    ns = argparse.Namespace(
        input=csv_path,
        output=out_bin,
        size=size_hex,
        version=2,
        outdir=os.path.dirname(os.path.abspath(out_bin)) or ".",
    )
    # Some versions print to stdout; swallow it to keep our console clean (no password is present).
    buf = io.StringIO()
    old = sys.stdout
    try:
        sys.stdout = buf
        gen(ns)
    except Exception:  # intentional broad fall-through to the stable CLI path (see comment)
        # The in-process entry point varies wildly across nvs_partition_gen releases: signature
        # mismatch (TypeError), missing attributes on the Namespace it expects (AttributeError),
        # and assorted internal failures (e.g. SystemExit subclasses, argparse quirks, version-
        # specific exceptions). Any of these is a cue to FALL THROUGH to the well-defined CLI
        # ('-m ... generate') path, which every release supports. The password is never in argv.
        sys.stdout = old
        cmd = [sys.executable, "-m", mod.__name__, "generate", csv_path, out_bin, size_hex]
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if proc.returncode != 0:
            raise ProvisionError(
                "nvs_partition_gen module failed (exit %d):\n%s"
                % (proc.returncode, proc.stdout.decode("utf-8", "replace"))
            )
    finally:
        sys.stdout = old


# ----------------------------------------------------------------------------------------------
# otadata blank blob
# ----------------------------------------------------------------------------------------------

def write_otadata_blank(out_path, size_bytes):
    """Write `size_bytes` of OTADATA_FILL_BYTE (0xFF). SPEC section 10."""
    with open(out_path, "wb") as fh:
        fh.write(bytes([OTADATA_FILL_BYTE]) * size_bytes)


# ----------------------------------------------------------------------------------------------
# Bundle manifest assembly (SPEC section 10 -- the COMPLETE flash list the flasher consumes)
# ----------------------------------------------------------------------------------------------

def _sha256_file(path):
    """Return the lowercase hex SHA-256 of a file's bytes (streamed, constant memory).

    Defense-in-depth: the flasher recomputes this and ABORTS on mismatch, so a tampered bundle
    .bin cannot be flashed. No password material is ever in these images (only the salted hash),
    so hashing/logging the digest is safe.
    """
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _manifest_entry(file_name, offset, partition=None, size=None, out_dir=None):
    """Build a single manifest `files[]` entry. offset is stored both as int and hex string.

    When `out_dir` is given and `out_dir/file_name` exists, a "sha256" of the actual image bytes
    is recorded so the flasher can verify integrity before flashing (defense-in-depth vs a
    tampered bundle). If the artifact is not present yet (absent build artifact — a warning is
    emitted elsewhere) the entry simply carries no "sha256"; the flasher treats a missing digest
    as TOFU (warn-but-allow) for back-compat with older bundles.
    """
    entry = {
        "file": file_name,
        "offset": offset,
        "offset_hex": "0x%X" % offset,
    }
    if partition is not None:
        entry["partition"] = partition
    if size is not None:
        entry["size"] = size
    if out_dir is not None:
        src = os.path.join(out_dir, file_name)
        if os.path.isfile(src):
            entry["sha256"] = _sha256_file(src)
    return entry


def build_manifest_files(args, parts, guardcfg, otadata):
    """Build the COMPLETE ordered `files` list for the flash bundle (SPEC section 10).

    The flasher writes EXACTLY this list in a single write_flash pass:
        bootloader.bin   @ 0x0 (s3/c3/c6/h2) or 0x1000 (classic/S2)   -- chip-derived
        partitions.bin   @ 0x8000                                     -- fixed
        app.bin          @ 0x10000                                    -- fixed
        guardcfg.bin     @ <guardcfg offset from CSV>                 -- READ from CSV
        otadata seed     @ <otadata offset from CSV>                  -- READ from CSV
            FORK     -> boot_app0.bin       (normal seed -> boots app0)
            GUARDIAN -> otadata_blank.bin   (all 0xFF    -> boots factory/Guardian)

    Exactly ONE otadata seed is emitted (no collision at the otadata offset).

    Build artifacts (bootloader/partitions/boot_app0/app) are referenced by name. If --build-dir
    is given and the file is present there it is COPIED into the bundle so the flasher has a single
    self-contained dir; if it is absent the manifest entry is STILL written (with the right offset)
    and a warning is emitted. guardcfg/otadata offsets come from `guardcfg`/`otadata` (read from
    the partition CSV) and are NEVER hardcoded.

    Returns (files_list, warnings_list).
    """
    bl_off = bootloader_offset(args.chip)
    otadata_off = otadata["offset"]

    files = []
    warnings = []

    # ---- chip/fixed-offset build artifacts (bootloader, partitions, app(s)) ----
    build_artifacts = [
        ("bootloader.bin", bl_off, None),
        ("partitions.bin", PARTITIONS_OFFSET, None),
    ]
    if args.variant == "guardian":
        # GUARDIAN (SPEC section 3.3): TWO app images -- the factory Guardian gate, then the
        # UNMODIFIED Marauder in ota_0. Both offsets are READ from the CSV (factory is conventionally
        # 0x10000 and ota_0 follows it, but do NOT assume -- a 16MB guardian table puts ota_0 well
        # past 0x10000). Without this second entry a guardian flash would never seed Marauder.
        factory = require_partition(parts, "factory")
        ota0 = require_partition(parts, "ota_0")
        build_artifacts.append(("guardian.bin", factory["offset"], "factory"))
        build_artifacts.append(("marauder.bin", ota0["offset"], "ota_0"))
    else:
        # FORK: a single forked-Marauder app at the fixed app offset (0x10000).
        build_artifacts.append(("app.bin", APP_OFFSET, None))

    # ---- the single otadata seed (variant-selected, written at the otadata offset) ----
    if args.variant == "guardian":
        # GUARDIAN: blank otadata (all 0xFF) forces first boot into factory/Guardian. This file is
        # minted by provision.py itself (write_otadata_blank), so it always exists in the bundle.
        otadata_seed = "otadata_blank.bin"
    else:
        # FORK: boot_app0.bin is the normal IDF otadata seed that selects app0. It comes from the
        # build (it is NOT minted here), so it is treated like the other build artifacts below.
        otadata_seed = "boot_app0.bin"
        build_artifacts.append(("boot_app0.bin", otadata_off, OTADATA_PART))

    # Resolve / copy each build artifact, warning (not failing) when one is absent.
    build_dir = os.path.abspath(args.build_dir) if args.build_dir else None
    out_dir = os.path.abspath(args.out)
    for name, offset, partition in build_artifacts:
        present = False
        if build_dir:
            src = os.path.join(build_dir, name)
            if os.path.isfile(src):
                dst = os.path.join(out_dir, name)
                # Don't copy a file onto itself if --build-dir == --out.
                if os.path.abspath(src) != os.path.abspath(dst):
                    shutil.copyfile(src, dst)
                present = True
        if not present:
            where = ("--build-dir %s" % build_dir) if build_dir else "no --build-dir given"
            warnings.append(
                "build artifact %r not found (%s); manifest entry written at offset 0x%X but the "
                "bundle will be INCOMPLETE until you drop %r in next to bundle.json."
                % (name, where, offset, name)
            )
        # sha256 is recorded from the copied-in artifact when present; an absent artifact gets no
        # digest (the flasher treats that as TOFU). Hashing happens against out_dir.
        files.append(_manifest_entry(name, offset, partition=partition, out_dir=out_dir))

    # ---- guardcfg (minted here; offset/size READ from the partition CSV) ----
    files.append(_manifest_entry(
        "guardcfg.bin", guardcfg["offset"], partition=GUARDCFG_PART, size=guardcfg["size"],
        out_dir=out_dir,
    ))

    # ---- GUARDIAN otadata seed (minted here; offset/size READ from the CSV) ----
    if args.variant == "guardian":
        files.append(_manifest_entry(
            otadata_seed, otadata_off, partition=OTADATA_PART, size=otadata["size"],
            out_dir=out_dir,
        ))

    # Sanity: exactly one image lands on the otadata offset (no collision -- SPEC section 10).
    on_otadata = [f["file"] for f in files if f["offset"] == otadata_off]
    if len(on_otadata) != 1:
        raise ProvisionError(
            "internal error: expected exactly one otadata seed at offset 0x%X, found %d (%s)"
            % (otadata_off, len(on_otadata), ", ".join(on_otadata) or "none")
        )

    return files, warnings


# ----------------------------------------------------------------------------------------------
# Argument parsing / validation
# ----------------------------------------------------------------------------------------------

def _u8(name):
    def conv(v):
        iv = int(v, 0)
        if not (0 <= iv <= 255):
            raise argparse.ArgumentTypeError("%s must be 0..255" % name)
        return iv
    return conv


def build_arg_parser():
    p = argparse.ArgumentParser(
        prog="provision.py",
        description=(
            "Suicide Marauder host provisioner. Bakes the per-device guardcfg NVS image, a blank "
            "otadata blob, and a flash bundle manifest. The password is read interactively via "
            "getpass and is NEVER accepted on the command line or logged."
        ),
        epilog=(
            "Defaults are DISARMED (armed=0) and follow docs/SPEC.md section 4. A disarmed or "
            "unprovisioned board can never wipe."
        ),
    )
    p.add_argument(
        "--partitions", required=True, metavar="CSV",
        help="path to the chosen partitions CSV (e.g. firmware/partitions/suicide_4MB.csv). "
             "guardcfg + otadata offsets/sizes are READ from this file, never hardcoded.",
    )
    p.add_argument(
        "--out", default="build/bundle", metavar="DIR",
        help="output bundle directory (default: build/bundle).",
    )
    p.add_argument(
        "--variant", choices=("fork", "guardian"), default="fork",
        help="build variant (SPEC section 1). 'fork' (default) seeds otadata with boot_app0.bin so "
             "the bootloader boots app0; 'guardian' seeds otadata_blank.bin (all 0xFF) so first "
             "boot lands in the factory Guardian. Exactly one otadata seed is emitted.",
    )
    p.add_argument(
        "--chip", choices=CHIPS, default="esp32",
        help="target chip family (default esp32). Selects the bootloader offset (0x0 on "
             "s3/c3/c6/h2, else 0x1000) and chip-aware strapping-pin warnings (SPEC section 2/7).",
    )
    p.add_argument(
        "--build-dir", default=None, metavar="DIR",
        help="directory holding the build artifacts (bootloader.bin, partitions.bin, app.bin, and "
             "boot_app0.bin for the fork variant). If a file is absent, its manifest entry is still "
             "written (with the correct offset) and a warning is emitted.",
    )
    p.add_argument(
        "--nvs-gen-dir", default=None, metavar="DIR",
        help="directory containing a vendored nvs_partition_gen.py (overrides auto-discovery).",
    )
    p.add_argument(
        "--no-confirm", action="store_true",
        help="do not ask to confirm the password a second time.",
    )

    # ---- gate config (SPEC section 4 / GateConfig.h defaults) ----
    g = p.add_argument_group("gate config (written to NVS namespace 'sgate')")
    g.add_argument("--arm-pin", dest="arm_pin", type=_u8("arm_pin"), default=27,
                   help="dead-man GPIO number (default 27, classic ESP32; never a strapping pin).")
    g.add_argument("--arm-level", dest="arm_level", type=int, choices=(0, 1), default=1,
                   help="logic level meaning ARMED (1=HIGH default).")
    g.add_argument("--arm-pull", dest="arm_pull", type=int, choices=(0, 1, 2), default=2,
                   help="0=none,1=pullup,2=pulldown (default 2=pulldown).")
    g.add_argument("--max-att", dest="max_att", type=_u8("max_att"), default=2,
                   help="wrong-password attempts before wipe (default 2).")
    g.add_argument("--deadman", type=int, choices=(0, 1), default=1,
                   help="1=cut/disarmed line wipes (default); 0=line only keeps device locked.")
    g.add_argument("--armed", type=int, choices=(0, 1), default=0,
                   help="MASTER ARM. 0=DISARMED (safe default), 1=ARMED. Default 0.")
    g.add_argument("--wipe-ota", dest="wipe_ota", type=int, choices=(0, 1), default=1,
                   help="erase Marauder app slot (default 1).")
    g.add_argument("--wipe-nvs", dest="wipe_nvs", type=int, choices=(0, 1), default=1,
                   help="erase Marauder NVS (default 1).")
    g.add_argument("--wipe-spiffs", dest="wipe_spiffs", type=int, choices=(0, 1), default=1,
                   help="erase SPIFFS (default 1).")
    g.add_argument("--wipe-sd", dest="wipe_sd", type=int, choices=(0, 1), default=1,
                   help="overwrite + erase SD (default 1).")
    g.add_argument("--brick", type=int, choices=(0, 1), default=0,
                   help="erase boot chain last for a true brick. Default 0 (T1). T2 sets 1.")
    g.add_argument("--sd-passes", dest="sd_passes", type=_u8("sd_passes"), default=1,
                   help="SD overwrite passes (default 1; 2+ = secure-erase: random then zeros).")
    g.add_argument("--flash-passes", dest="flash_passes", type=_u8("flash_passes"), default=1,
                   help="internal-flash OVERWRITE passes (random) before the final clean erase "
                        "(default 1; 0=erase-only/legacy). Forced to 0 by --fast-wipe at wipe time.")
    g.add_argument("--fast-wipe", dest="fast_wipe", type=int, choices=(0, 1), default=0,
                   help="1=skip SD on wipe, only flash erase + boot brick (brownout-safe). Default 0.")
    g.add_argument("--kdf-iter", dest="kdf_iter", type=int, default=DEFAULT_KDF_ITER,
                   help="PBKDF2 iteration count (default %d). Must match the device." %
                        DEFAULT_KDF_ITER)
    return p


def validate_args(args):
    if args.kdf_iter < 1:
        raise ProvisionError("--kdf-iter must be >= 1")
    # max_att MUST be >= 1, always (SPEC section 4.1 fail-closed clamp). A max_att of 0 would mean
    # "wipe on the zeroth attempt", i.e. wipe before any password is even tried -- the firmware
    # treats a stored 0 as the safe default, but the host must never *emit* a 0 in the first place.
    if args.max_att < 1:
        raise ProvisionError(
            "--max-att must be >= 1 (SPEC section 4.1: max_att is clamped >= 1, always; a value of "
            "0 would arm a wipe with zero failed attempts)"
        )
    if args.kdf_iter < 2000:
        # not fatal, but warn loudly to stderr (no password involved)
        sys.stderr.write(
            "WARNING: --kdf-iter %d is very low. On a classic ESP32 ~10000 iters is about 1 s verify "
            "(150000 measured ~16.7 s, too slow). With the 2-attempt wipe, online brute-force is moot; "
            "offline-hash resistance comes from T2 flash-encryption + a strong passphrase, not "
            "iteration count.\n" % args.kdf_iter
        )
    # Fail-safe arming pull/level pair (SPEC section 4.1). A NON-fail-safe combo idles the pin
    # TOWARD the armed level, so a cut/unplugged/floating wire reads ARMED and defeats the dead-man.
    # Reject the two unsafe pairs outright (this is a safety invariant, not advisory):
    #   arm_level==1 (ARMED=HIGH) with arm_pull==1 (pullup)   -> idles HIGH  -> idles ARMED  (UNSAFE)
    #   arm_level==0 (ARMED=LOW)  with arm_pull==2 (pulldown)  -> idles LOW   -> idles ARMED  (UNSAFE)
    # The fail-safe pairs are level=1 + pulldown(2) and level=0 + pullup(1) (pin idles NOT-ARMED).
    if args.arm_level == 1 and args.arm_pull == 1:
        raise ProvisionError(
            "non-fail-safe arming pair rejected (SPEC section 4.1): arm_level=1 (ARMED=HIGH) with "
            "arm_pull=1 (pullup) idles the pin HIGH/ARMED, so a cut wire reads ARMED and defeats the "
            "dead-man. Use the fail-safe pair: arm_level=1 + arm_pull=2 (pulldown)."
        )
    if args.arm_level == 0 and args.arm_pull == 2:
        raise ProvisionError(
            "non-fail-safe arming pair rejected (SPEC section 4.1): arm_level=0 (ARMED=LOW) with "
            "arm_pull=2 (pulldown) idles the pin LOW/ARMED, so a cut wire reads ARMED and defeats "
            "the dead-man. Use the fail-safe pair: arm_level=0 + arm_pull=1 (pullup)."
        )
    # Strapping-pin guard (SPEC section 7). Advisory only -- the operator may know their board.
    # Chip-aware: the forbidden set differs per family. GPIO2, for instance, is a C3 strapping pin
    # but is the DOCUMENTED S3 default (Grove G2), so we must NOT warn about it on S3.
    forbidden = _strapping_pins_for_chip(args.chip)
    if args.arm_pin in forbidden:
        sys.stderr.write(
            "WARNING: arm_pin %d is a known strapping/boot pin on %s (SPEC section 7). "
            "Verify it is free on your board.\n" % (args.arm_pin, args.chip)
        )
    if 34 <= args.arm_pin <= 39:
        sys.stderr.write(
            "NOTE: GPIO%d is input-only; it needs an EXTERNAL 10k pulldown (arm_pull is ignored "
            "in hardware for these pins).\n" % args.arm_pin
        )


# ----------------------------------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------------------------------

def main(argv=None):
    args = build_arg_parser().parse_args(argv)
    try:
        validate_args(args)

        # 1) Read offsets/sizes from the partition table (never hardcoded -- SPEC section 2/10).
        parts = parse_partitions_csv(args.partitions)
        guardcfg = require_partition(parts, GUARDCFG_PART)
        otadata = require_partition(parts, OTADATA_PART)
        if guardcfg["subtype"] != "nvs":
            raise ProvisionError(
                "partition %r must have subtype 'nvs' (found %r) -- host + firmware key off this"
                % (GUARDCFG_PART, guardcfg["subtype"])
            )

        out_dir = os.path.abspath(args.out)
        os.makedirs(out_dir, exist_ok=True)
        guardcfg_bin = os.path.join(out_dir, "guardcfg.bin")
        otadata_bin = os.path.join(out_dir, "otadata_blank.bin")
        manifest_path = os.path.join(out_dir, "bundle.json")

        # 2) Read the password securely, hash it, and ZEROIZE the plaintext immediately.
        salt = os.urandom(SALT_LEN)
        pw_buf = read_password_securely(confirm=not args.no_confirm)
        with _zeroized(pw_buf):
            pwhash = derive_pwhash(pw_buf, salt, args.kdf_iter, KDF_DKLEN)
        # pw_buf is now zeroized. The plaintext is gone; only salt + pwhash remain.
        del pw_buf

        # 3) Build the NVS CSV (only salt/hash/params + config -- no plaintext) and the image.
        #    Write the CSV into a temp dir so it is not left lying around in the bundle.
        tmp_dir = tempfile.mkdtemp(prefix="sgate_nvs_")
        try:
            nvs_csv = os.path.join(tmp_dir, "nvs_config.csv")
            rows = build_nvs_rows(args, salt, pwhash)
            write_nvs_csv(rows, nvs_csv)
            generate_nvs_bin(nvs_csv, guardcfg_bin, guardcfg["size"], args.nvs_gen_dir)
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

        # 4) The otadata seed (SPEC section 10): exactly ONE image lands on the otadata offset.
        #    GUARDIAN -> we MINT otadata_blank.bin (all 0xFF) here. FORK -> the seed is the build's
        #    boot_app0.bin, so nothing is minted (it is pulled from --build-dir by the manifest).
        if args.variant == "guardian":
            write_otadata_blank(otadata_bin, otadata["size"])

        # 5) Bundle manifest: the COMPLETE flash list (SPEC section 10). guardcfg/otadata offsets
        #    are READ from the CSV (never hardcoded 0xe000); bootloader offset is chip-derived;
        #    partitions/app are fixed. Build artifacts are copied in from --build-dir when present.
        files, file_warnings = build_manifest_files(args, parts, guardcfg, otadata)
        for w in file_warnings:
            sys.stderr.write("WARNING: %s\n" % w)

        manifest = {
            "schema": "suicide-marauder/bundle@1",
            "variant": args.variant,
            "chip": args.chip,
            "namespace": NVS_NAMESPACE,
            "cfg_ver": CFG_VERSION,
            "kdf": {
                "algo": "pbkdf2-hmac-sha256",
                "iter": args.kdf_iter,
                "dklen": KDF_DKLEN,
                "salt_len": SALT_LEN,
            },
            "partitions_csv": os.path.abspath(args.partitions),
            "bootloader_offset": "0x%X" % bootloader_offset(args.chip),
            "files": files,
        }
        with open(manifest_path, "w", encoding="utf-8") as fh:
            json.dump(manifest, fh, indent=2, sort_keys=False)
            fh.write("\n")

        # 6) Report. NOTE: salt/hash are device-safe (no plaintext); never print the password.
        print("Provisioned bundle written to: %s" % out_dir)
        print("  variant=%s chip=%s (bootloader @ %s)"
              % (args.variant, args.chip, manifest["bootloader_offset"]))
        print("  full flash manifest (%d images, one write_flash pass):" % len(files))
        for f in files:
            extra = " (size 0x%X)" % f["size"] if "size" in f else ""
            print("    %-18s -> %s%s" % (f["file"], f["offset_hex"], extra))
        print("  bundle.json        -> manifest of {file, offset} (the flasher writes EXACTLY this)")
        print("  KDF: PBKDF2-HMAC-SHA256, iter=%d, dklen=%d, salt=%d bytes"
              % (args.kdf_iter, KDF_DKLEN, SALT_LEN))
        print("  armed=%d (0=DISARMED safe) arm_pin=%d arm_level=%d arm_pull=%d deadman=%d max_att=%d"
              % (args.armed, args.arm_pin, args.arm_level, args.arm_pull, args.deadman, args.max_att))
        if args.fast_wipe:
            print("  fast_wipe=1 (SD wipe SKIPPED on trigger — flash erase + brick only)")
        if args.armed == 1:
            print("  *** WARNING: armed=1. This board WILL self-destruct on trigger conditions. ***")
        return 0

    except ProvisionError as exc:
        sys.stderr.write("error: %s\n" % exc)
        return 2
    except KeyboardInterrupt:
        sys.stderr.write("\naborted\n")
        return 130


if __name__ == "__main__":
    sys.exit(main())
