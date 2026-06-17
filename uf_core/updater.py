"""
Self-update from the git repo: `git pull --ff-only` + reinstall deps.

Only works when the app was installed via `git clone` (the package's parent dir is a git
checkout). The installer does exactly that, so the in-app "Check for Updates" works for the
shipped product. Streams output through an on_line callback like the flasher.
"""

import os
import subprocess
import sys
from typing import Callable

Line = Callable[[str], None]


def repo_root() -> str:
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def is_git_checkout() -> bool:
    return os.path.isdir(os.path.join(repo_root(), ".git"))


def current_revision() -> str:
    try:
        r = subprocess.run(["git", "-C", repo_root(), "rev-parse", "--short", "HEAD"],
                           capture_output=True, text=True, timeout=10)
        return r.stdout.strip() or "unknown"
    except Exception:
        return "unknown"


def _git_env() -> dict:
    # never block on a credential or SSH host-key prompt (the GUI has no terminal)
    env = dict(os.environ)
    env["GIT_TERMINAL_PROMPT"] = "0"
    env.setdefault("GIT_SSH_COMMAND", "ssh -oBatchMode=yes -oStrictHostKeyChecking=accept-new")
    return env


def _run(argv, on_line: Line, env=None, timeout=180) -> int:
    on_line("$ " + " ".join(argv))
    try:
        p = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                             stdin=subprocess.DEVNULL, text=True, bufsize=1, env=env)
    except FileNotFoundError as e:
        on_line(f"[error] {e}")
        return 127
    try:
        for ln in p.stdout:                   # type: ignore[union-attr]
            on_line(ln.rstrip("\n"))
        p.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        on_line("[error] timed out — killing")
        try:
            p.kill(); p.wait(timeout=5)
        except Exception:
            pass
        return -1
    except Exception as e:
        on_line(f"[error] {e}")
        try:
            p.kill(); p.wait(timeout=5)
        except Exception:
            pass
        return -1
    finally:
        try:
            if p.stdout:
                p.stdout.close()
        except Exception:
            pass
    return p.returncode


def update(on_line: Line) -> bool:
    """Pull latest + reinstall requirements. Returns True on success."""
    root = repo_root()
    if not is_git_checkout():
        on_line("[update] not a git checkout — install via `git clone` to enable updates.")
        return False
    # tolerate root-owned clones run by a normal user (Kali sudo-install flow)
    _run(["git", "config", "--global", "--add", "safe.directory", root], on_line)
    on_line(f"[update] current revision: {current_revision()}")
    if _run(["git", "-C", root, "pull", "--ff-only"], on_line, env=_git_env()) != 0:
        on_line("[update] git pull failed (local changes, auth, or no network?). Aborted.")
        return False
    req = os.path.join(root, "requirements.txt")
    if os.path.exists(req):
        rc = _run([sys.executable, "-m", "pip", "install", "-q", "-r", req], on_line, timeout=600)
        if rc != 0:
            on_line("[update] code updated, but dependency install FAILED — fix deps before restarting.")
            return False
    on_line(f"[update] now at {current_revision()} — restart the app to apply.")
    return True
