# Security Policy

Only the latest release (1.2.x) gets security patches. If you're on an older version, update first.

## Reporting a vulnerability

**Don't open a public issue.** Instead:

1. Use [GitHub Security Advisories](https://github.com/LxveAce/headless-marauder-gui/security/advisories) (preferred), or
2. Email **extrafadexd@gmail.com** with `[SECURITY] headless-marauder-gui` in the subject.

Include what you found, how to reproduce it, and which version you're running. I'll acknowledge it within a couple days and try to get a patch out within two weeks for anything serious.

## What counts

Bugs in this project's Python code — command injection, path traversal in logging/flashing, XSS or access issues in the web UI, unsafe data handling, that kind of thing.

What doesn't count: bugs in the Marauder firmware itself (report those [upstream](https://github.com/justcallmekoko/ESP32Marauder)), issues in third-party deps that we can't realistically mitigate, social engineering, physical access to the ESP32, or stuff that requires the attacker to already have code execution on the host.

## A note about the web UI

The browser UI binds to `127.0.0.1:5000` by default — localhost only, no auth. That's intentional. If you pass `--host 0.0.0.0` to expose it on your LAN, anyone on the network can control the board. That's a documented tradeoff, not a vulnerability. If you need LAN access with auth, stick a reverse proxy in front of it.

## Disclosure

I follow coordinated disclosure. Once a fix ships, the vulnerability gets documented in the release notes. I'd appreciate a heads-up before going public — ideally give me two weeks to patch.
