# netDiag
Local-only Windows tool for field techs: listen for CDP/LLDP neighbors on the
laptop NIC, and talk to a switch over a local serial COM port (login,
transceivers, MAC table grab/compare, live CLI).

## Run on a field laptop

Needs Python 3 (tkinter is stdlib). pyserial is required for serial. Scapy +
Npcap are optional and only used for CDP/LLDP listen.

```
python -m venv .venv
.venv\Scripts\pip install -r requirements.txt
run_netdiag.bat
```

Or, with Python already on PATH: `python netdiag.py`

`run_netdiag.bat` uses this folder's `.venv` when present, otherwise `pythonw` /
`python` on PATH.

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
