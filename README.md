# netDiag
Local-only Windows tool for field techs: listen for CDP/LLDP neighbors on the
laptop NIC, and talk to a switch over a local serial COM port (login,
transceivers, MAC table grab/compare, live CLI).

## Run on a field laptop

Needs Python 3.10+ installed once (https://www.python.org/downloads/ — check
"Add python.exe to PATH"). Then:

1. Copy or `git pull` this folder.
2. Double-click `run_netdiag.bat`.

First run creates `.venv` in this folder, installs `requirements.txt`
(pyserial, scapy), and places a **netDiag** shortcut on the Desktop (8-pin
network icon, launches `netdiag.py` through the local venv). Later runs skip
setup and start the GUI.

Do not run `python netdiag.py` from a random interpreter on first launch — use
the bat so the venv exists. `.venv` is gitignored; each laptop builds its own.

For CDP/LLDP: install Npcap from https://npcap.com with WinPcap API-compatible
mode, and do not restrict the driver to Administrators. If capture still wants
UAC, run `allow_npcap_nonadmin.bat` once.

## Credentials

Customer names go in `settings.json` next to the script. Usernames and passwords
live in a DPAPI-protected `secrets.bin` under the Windows user profile (not in
`settings.json`, not in the repo). There is no admin/admin default — credentials
stay empty until you set a customer profile.

Serial → **Add customer...** and **Add device...** save through that store.
**Save to this customer** writes the default username/password. **Connect** uses
saved (and optional this-session) credentials; it does not overwrite the stored
default.

Auto-try uses the selected device login if you picked a hostname, then the
customer default. It does not try every other device password on that customer.

Do not copy `secrets.bin` to another PC or user; DPAPI will not open it there.
Secret persistence is Windows-only.

Serial connects only to local COM ports — no `socket://` or remote console.
