# Freedom

## Wi-Fi device scanner

`wifi_scanner.py` finds every device on your Wi-Fi, works out what each one is
(name, maker, model, why it thinks so), groups them — Security & Cameras, Computers,
Phones & Tablets, TVs & Media, Printers, Game Consoles, Smart Home, Network Gear —
and shows it all on a phone-friendly web page with a live signal finder.
Python 3 only, nothing to install. Only scan networks you own.

A web page alone cannot scan a network (browsers have no access to it), so a small
program does the scanning and your phone's browser is the screen.

**Android phone, everything on the phone**

1. Install *Termux* and *Termux:API* (F-Droid), then in Termux:
   `pkg install python termux-api` and copy `wifi_scanner.py` over.
2. `python wifi_scanner.py` → open the printed `http://127.0.0.1:8737/…/` link in Chrome.

The Signal tab then measures from the phone itself: walk around, stronger = closer.

**iPhone, or any phone, with a computer on the same Wi-Fi**

1. On the computer: `python3 wifi_scanner.py`
2. Open the printed "From phone" link in the phone's browser.

Here the Signal tab measures from the computer (Linux/Windows), not the phone.

**Limits**

- The signal finder can only range devices that broadcast their own Wi-Fi radio
  (routers, extenders, many printers/cameras/TVs). Ordinary clients are invisible
  to a phone or laptop without special monitor-mode hardware.
- Android hides MAC addresses from apps, so on-phone scans identify devices by
  name and services only; a computer scan also gets the hardware maker.
- Each device shows a confidence tag; "low" means it is a guess from the maker alone.
- The link contains a random key; anyone you give it to (on your Wi-Fi) can see the list.

`python3 wifi_scanner.py --once` prints the scan as JSON instead.

### Download page

`site/` is the public download page served at https://radar.ackerworks.com (a Cloudflare
Worker that serves `site/index.html` and `wifi_scanner.py`). Redeploy after changes with
`CLOUDFLARE_API_TOKEN=… site/deploy.sh`.
