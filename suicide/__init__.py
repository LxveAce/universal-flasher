"""
Suicide-build integration — provision + flash anti-forensic Marauder bundles.

This package vendors the Suicide-Marauder provisioner so the headless Marauder
GUI can build and flash suicide bundles without requiring the separate repo.

The provisioner creates a per-device guardcfg NVS image (password hash + config)
and a flash bundle manifest.  The flasher (uf_core.flasher.flash_suicide)
writes the bundle to the board.

SECURITY INVARIANTS (inherited from Suicide-Marauder docs/SPEC.md):
  * The plaintext password is NEVER stored, NEVER logged, NEVER in argv.
  * Only {salt, pwhash, kdf_iter, kdf_dklen} reach the device.
  * Password bytes are zeroized after hashing.

The firmware source (bootgate C++) and build scripts are bundled under
suicide/firmware/ and suicide/scripts/ for users who want to compile locally.
"""

import argparse
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))


def _partitions_dir():
    return os.path.join(_HERE, "partitions")


def available_partitions():
    """Return [(filename, path), ...] for all bundled partition CSVs."""
    d = _partitions_dir()
    return sorted(
        (f, os.path.join(d, f))
        for f in os.listdir(d) if f.endswith(".csv")
    )


def default_partitions_csv(flash_size_mb=4, variant="fork"):
    """Pick the right bundled partition CSV for a flash size + variant."""
    if variant == "guardian":
        name = "suicide_guardian_16MB.csv"
    else:
        name = f"suicide_{flash_size_mb}MB.csv"
    path = os.path.join(_partitions_dir(), name)
    if not os.path.isfile(path):
        avail = [f for f, _ in available_partitions()]
        raise FileNotFoundError(
            f"{name} not found. Available: {', '.join(avail)}"
        )
    return path


def _get_provisioner():
    """Import the vendored provision module."""
    prov_path = os.path.join(_HERE, "provision.py")
    if not os.path.isfile(prov_path):
        raise ImportError(f"provision.py not found at {prov_path}")
    # Add to path temporarily so provision.py can be imported
    if _HERE not in sys.path:
        sys.path.insert(0, _HERE)
    import importlib.util
    spec = importlib.util.spec_from_file_location("suicide.provision", prov_path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def build_bundle(
    password,
    chip="esp32",
    out_dir=None,
    partitions_csv=None,
    build_dir=None,
    variant="fork",
    arm_pin=27,
    arm_level=1,
    arm_pull=2,
    deadman=1,
    armed=0,
    max_att=2,
    wipe_ota=1,
    wipe_nvs=1,
    wipe_spiffs=1,
    wipe_sd=1,
    brick=0,
    sd_passes=1,
    flash_passes=1,
    fast_wipe=0,
    kdf_iter=10000,
    on_line=None,
):
    """Provision a suicide bundle programmatically.

    Takes the password as a string (will be converted to bytearray and zeroized
    after hashing).  Returns the absolute path to the bundle directory.

    If `partitions_csv` is None, auto-selects from the bundled CSVs based on
    variant (guardian -> 16MB, else 4MB default).

    If `build_dir` is given and contains compiled firmware (bootloader.bin,
    partitions.bin, app.bin, boot_app0.bin), those are copied into the bundle.
    Otherwise the manifest entries are written with correct offsets but the
    bundle will be incomplete until the firmware binaries are added.
    """
    if on_line is None:
        on_line = lambda s: None

    prov = _get_provisioner()

    if partitions_csv is None:
        partitions_csv = default_partitions_csv(variant=variant)

    if out_dir is None:
        import tempfile
        out_dir = os.path.join(tempfile.gettempdir(), "suicide_bundle")
    os.makedirs(out_dir, exist_ok=True)

    # Build an argparse-like namespace matching what provision.main() expects
    args = argparse.Namespace(
        partitions=partitions_csv,
        out=out_dir,
        variant=variant,
        chip=chip,
        build_dir=build_dir,
        nvs_gen_dir=None,
        no_confirm=True,
        arm_pin=arm_pin,
        arm_level=arm_level,
        arm_pull=arm_pull,
        deadman=deadman,
        armed=armed,
        max_att=max_att,
        wipe_ota=wipe_ota,
        wipe_nvs=wipe_nvs,
        wipe_spiffs=wipe_spiffs,
        wipe_sd=wipe_sd,
        brick=brick,
        sd_passes=sd_passes,
        flash_passes=flash_passes,
        fast_wipe=fast_wipe,
        kdf_iter=kdf_iter,
    )

    on_line("[suicide] validating config...")
    prov.validate_args(args)

    on_line("[suicide] reading partition table...")
    parts = prov.parse_partitions_csv(args.partitions)
    guardcfg = prov.require_partition(parts, prov.GUARDCFG_PART)
    otadata = prov.require_partition(parts, prov.OTADATA_PART)
    if guardcfg["subtype"] != "nvs":
        raise ValueError(
            f"partition '{prov.GUARDCFG_PART}' must have subtype 'nvs' "
            f"(found '{guardcfg['subtype']}')"
        )

    # Hash the password (zeroize immediately after)
    on_line("[suicide] hashing password (PBKDF2-HMAC-SHA256)...")
    salt = os.urandom(prov.SALT_LEN)
    pw_buf = bytearray(password.encode("utf-8"))
    with prov._zeroized(pw_buf):
        pwhash = prov.derive_pwhash(pw_buf, salt, args.kdf_iter, prov.KDF_DKLEN)
    del pw_buf

    # Generate the NVS image (guardcfg.bin)
    on_line("[suicide] generating guardcfg NVS image...")
    import tempfile as _tf
    import shutil
    guardcfg_bin = os.path.join(out_dir, "guardcfg.bin")
    tmp_dir = _tf.mkdtemp(prefix="sgate_nvs_")
    try:
        nvs_csv = os.path.join(tmp_dir, "nvs_config.csv")
        rows = prov.build_nvs_rows(args, salt, pwhash)
        prov.write_nvs_csv(rows, nvs_csv)
        prov.generate_nvs_bin(nvs_csv, guardcfg_bin, guardcfg["size"], args.nvs_gen_dir)
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)

    # Guardian variant: mint blank otadata
    if args.variant == "guardian":
        on_line("[suicide] writing blank otadata (guardian)...")
        prov.write_otadata_blank(
            os.path.join(out_dir, "otadata_blank.bin"), otadata["size"]
        )

    # Build the manifest
    on_line("[suicide] building bundle manifest...")
    files, warnings = prov.build_manifest_files(args, parts, guardcfg, otadata)
    for w in warnings:
        on_line(f"[WARNING] {w}")

    import json
    manifest = {
        "schema": "suicide-marauder/bundle@1",
        "variant": args.variant,
        "chip": args.chip,
        "namespace": prov.NVS_NAMESPACE,
        "cfg_ver": prov.CFG_VERSION,
        "kdf": {
            "algo": "pbkdf2-hmac-sha256",
            "iter": args.kdf_iter,
            "dklen": prov.KDF_DKLEN,
            "salt_len": prov.SALT_LEN,
        },
        "partitions_csv": os.path.abspath(args.partitions),
        "bootloader_offset": "0x%X" % prov.bootloader_offset(args.chip),
        "files": files,
    }
    manifest_path = os.path.join(out_dir, "bundle.json")
    with open(manifest_path, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2, sort_keys=False)
        fh.write("\n")

    on_line(f"[suicide] bundle ready: {out_dir}")
    on_line(f"  variant={args.variant} chip={args.chip} files={len(files)}")
    on_line(f"  armed={args.armed} arm_pin={args.arm_pin} max_att={args.max_att}")
    if args.armed:
        on_line("  *** WARNING: armed=1 — board WILL self-destruct on trigger ***")

    return out_dir


def firmware_dir():
    """Path to the bundled bootgate firmware source."""
    return os.path.join(_HERE, "firmware", "bootgate")


def scripts_dir():
    """Path to the bundled build scripts."""
    return os.path.join(_HERE, "scripts")


def docs_dir():
    """Path to the bundled Suicide-Marauder docs."""
    return os.path.join(_HERE, "docs")


def safety_doc():
    """Path to SAFETY.md — must be read before using suicide builds."""
    return os.path.join(_HERE, "docs", "SAFETY.md")
