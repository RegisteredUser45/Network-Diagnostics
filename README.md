# netDiag
Local-only tool for field techs: listen for CDP/LLDP neighbors on the laptop NIC,
and talk to a switch over a local serial COM port (login, transceivers, MAC table
grab/compare, live CLI).

Run:  python netdiag.py
Needs: Python 3, tkinter (stdlib), pyserial. Scapy + Npcap optional for CDP/LLDP.

Credentials stay on this machine. Customer names go in settings.json next to the
script; passwords live in a DPAPI-protected secrets.bin under the Windows user
profile (not in settings.json, not in the repo). There is no admin/admin default —
credentials stay empty until you set a customer profile. Secret persistence is
Windows-only (DPAPI); off Windows the app refuses to write secrets rather than
store them in the clear. Serial connects only to local COM ports — no socket://
or remote console.

Do not copy secrets.bin to another PC or user; DPAPI will not open it there.

Run on Windows: `python netdiag.py`
