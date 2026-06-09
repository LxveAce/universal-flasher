# Disclaimer

## Use responsibly

Headless Marauder is a security research tool. Use it on networks and devices you own or have explicit permission to test. A lot of what Marauder can do — deauth, evil portals, beacon spam, BLE spam — is illegal if aimed at someone else's stuff. Laws like the CFAA (US), Computer Misuse Act (UK), and equivalents in other countries apply. Know what's legal where you are before you start.

## No warranty

This software is provided "as is" with no warranty of any kind. I'm not responsible for what you do with it, any damage it causes, or any legal trouble you get into. If you use it, you accept that risk.

## Firmware

This app is just a serial controller — it sends text commands to an ESP32 running [Marauder firmware](https://github.com/justcallmekoko/ESP32Marauder). The firmware is a separate project (GPL, by justcallmekoko). The built-in flasher downloads binaries from the official Marauder GitHub releases. It doesn't verify firmware signatures, so check what you're flashing.

## Privacy

The app doesn't phone home or collect any data. Logs, captures, JSON snapshots — everything stays on your machine in a folder you pick. The web UI runs on localhost by default.

## Dependencies

This project uses open-source libraries (PyQt5, Flask, pyserial, esptool, Textual, etc.). I'm not responsible for bugs or vulnerabilities in upstream packages. See `requirements.txt` for the full list.
