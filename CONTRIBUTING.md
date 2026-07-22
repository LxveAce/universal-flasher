# Contributing

Bug reports, feature requests, and PRs are all welcome.

## Setup

1. Fork and clone
2. Set up a venv:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate        # Linux/macOS
   # .venv\Scripts\activate         # Windows
   pip install -r requirements.txt
   pip install PyQt5
   ```
3. Run with `--mock` to develop without hardware:
   ```bash
   python gui_qt/app.py --mock
   python tui/app.py --mock
   python web/app.py --mock
   ```

## Reporting bugs

Open a [GitHub issue](https://github.com/LxveAce/universal-flasher/issues). Include your OS, Python version, steps to reproduce, and any tracebacks. If it's hardware-related, mention your board type (classic ESP32, S3, etc.).

## Pull requests

- Branch off `main`, keep commits focused
- If your change touches `uf_core/`, test it across all four UIs (Qt, Tk, TUI, Web)
- Update `GUIDE.md` if you add or change commands
- Open a PR with a clear description

## Code style

Python 3.9+. Follow whatever patterns are already in the code; it's kept pretty straightforward on purpose. Don't over-engineer things or add dependencies for stuff the stdlib handles fine.

## Adding commands

New Marauder commands go in `uf_core/commands.py`. Add a `Command(...)` to the right category in `build()`. All four UIs pick it up automatically from there.

## Project layout

```
uf_core/           Shared library (controller, parser, commands, flasher, capture, updater)
gui_qt/            PyQt5 desktop GUI
gui/               Tkinter GUI
tui/               Textual terminal UI
web/               Flask + SocketIO browser UI
```

All four front-ends import from `uf_core` and follow the same pattern. Core features should work across all UIs; UI-specific stuff stays in that UI's folder.

## Security issues

Don't open a public issue for security bugs. See [SECURITY.md](SECURITY.md).

## License

Contributions are licensed under [MIT](LICENSE).
