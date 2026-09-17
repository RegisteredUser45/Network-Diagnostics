#!/usr/bin/env python3
"""
netDiag — CDP/LLDP neighbor discovery and serial console tool.

Standalone program (former main.py backend + gui.py Tkinter UI).
Run:  python netdiag.py

Third-party deps: pyserial (local COM console). tkinter is stdlib.
Scapy is optional for live CDP/LLDP capture (Npcap on Windows).
"""

import json
import os
import sys
import subprocess
import threading
import queue
import time
import re
import importlib.util
from pathlib import Path
from datetime import datetime

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from tkinter import font as tkfont

# ====================== CUSTOMER PROFILES / SERIAL AUTH ======================

USERNAME = ""
PASSWORD = ""
PROFILES = []  # alias: host exceptions on the active customer
CUSTOMERS = []
ACTIVE_CUSTOMER = "Default"
# "auto" = try this customer's secrets
# "manual" = one selected hostname's secret
# "skip" = do not drive login; open a raw terminal
LOGIN_MODES = ("auto", "manual", "skip")
LOGIN_MODE = "auto"
LAST_SUCCESS_USERNAME = ""
LAST_SUCCESS_PASSWORD = ""
LAST_SUCCESS_CUSTOMER = ""
_MAX_SEEN_HOSTNAMES = 200

_PROMPT_HOST_RE = re.compile(
    r"^([A-Za-z0-9][A-Za-z0-9._:-]{0,62})(?:\([^)]+\))?[>#$]\s*$"
)
_PROMPT_HOST_BLOCKLIST = {
    "username", "user", "login", "password", "pass",
}


# Secrets never go in settings.json. They live in a DPAPI blob that can only
# be opened by this Windows user + this app's entropy. Off Windows, persist fails closed.
_SECRETS_USE_DPAPI = os.name == "nt"
_SECRETS_ENTROPY = b"netDiag-local-secrets-v1"
_DPAPI_UI_FORBIDDEN = 0x01
_STATE_LOCK = threading.RLock()


def settings_file():
    """Non-secret UI state (customer names, login mode, seen hostnames)."""
    override = os.environ.get("NETDIAG_SETTINGS")
    if override:
        return Path(override)
    return Path(__file__).parent / "settings.json"


def secrets_file():
    """Encrypted secret store. Stays on this Windows user, not in the project folder."""
    override = os.environ.get("NETDIAG_SECRETS")
    if override:
        return Path(override)
    root = os.environ.get("LOCALAPPDATA") or str(Path.home())
    return Path(root) / "netDiag" / "secrets.bin"


def _project_dir() -> Path:
    return Path(__file__).resolve().parent


def _local_venv_pythonw() -> Path:
    return _project_dir() / ".venv" / "Scripts" / "pythonw.exe"


def _local_venv_python() -> Path:
    return _project_dir() / ".venv" / "Scripts" / "python.exe"


def _running_from_local_venv() -> bool:
    exe = Path(sys.executable).resolve()
    for candidate in (_local_venv_pythonw(), _local_venv_python()):
        try:
            if candidate.exists() and exe == candidate.resolve():
                return True
        except OSError:
            continue
    return False


def _reexec_local_venv():
    """If a project venv exists, run this file with it (desktop .py shortcut)."""
    if os.name != "nt" or _running_from_local_venv():
        return
    target = _local_venv_pythonw()
    if not target.exists():
        target = _local_venv_python()
    if not target.exists():
        return
    os.execv(str(target), [str(target), str(Path(__file__).resolve()), *sys.argv[1:]])


def ensure_desktop_shortcut():
    """Place netDiag.lnk on this user's Desktop, pointing at netdiag.py."""
    if os.name != "nt":
        return
    def ps_lit(value):
        return "'" + str(value).replace("'", "''") + "'"

    here = ps_lit(_project_dir())
    script = ps_lit(_project_dir() / "netdiag.py")
    ico = ps_lit(_project_dir() / "netdiag.ico")
    pythonw = ps_lit(_local_venv_pythonw())
    ps = (
        "$desktop = [Environment]::GetFolderPath('Desktop'); "
        "if (-not $desktop) { exit 0 }; "
        "$lnk = Join-Path $desktop 'netDiag.lnk'; "
        "$ws = New-Object -ComObject WScript.Shell; "
        "$s = $ws.CreateShortcut($lnk); "
        f"$script = {script}; "
        f"$here = {here}; "
        f"$ico = {ico}; "
        f"$pythonw = {pythonw}; "
        "if (Test-Path -LiteralPath $pythonw) { "
        "  $s.TargetPath = $pythonw; "
        "  $s.Arguments = ('\"{0}\"' -f $script); "
        "} else { "
        "  $s.TargetPath = $script; "
        "  $s.Arguments = ''; "
        "} "
        "$s.WorkingDirectory = $here; "
        "$s.WindowStyle = 1; "
        "$s.Description = 'netDiag'; "
        "if (Test-Path -LiteralPath $ico) { $s.IconLocation = $ico }; "
        "$s.Save()"
    )
    try:
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-STA",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                ps,
            ],
            check=False,
            capture_output=True,
            creationflags=flags,
        )
    except Exception:
        pass


def is_local_com_port(port) -> bool:
    """True only for a local COM device. Rejects socket://, rfc2217, etc."""
    name = str(port or "").strip()
    if not name or "://" in name:
        return False
    upper = name.upper()
    if upper.startswith("\\\\.\\COM") and upper[7:].isdigit():
        return True
    if upper.startswith("COM") and upper[3:].isdigit():
        return True
    return False


def _restrict_to_current_user(path: Path):
    """Drop inherited ACLs so only this Windows user can read the file."""
    user = os.environ.get("USERNAME") or os.environ.get("USER")
    if not user or os.name != "nt":
        return
    try:
        import subprocess
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        subprocess.run(
            ["icacls", str(path), "/inheritance:r", "/grant:r", f"{user}:(R,W)"],
            check=False,
            capture_output=True,
            creationflags=flags,
        )
    except Exception:
        pass


def _dpapi_protect(plain: bytes) -> bytes:
    import ctypes
    from ctypes import wintypes

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [
            ("cbData", wintypes.DWORD),
            ("pbData", ctypes.POINTER(ctypes.c_char)),
        ]

    in_buf = ctypes.create_string_buffer(plain, len(plain))
    in_blob = DATA_BLOB(len(plain), in_buf)
    entropy_buf = ctypes.create_string_buffer(_SECRETS_ENTROPY, len(_SECRETS_ENTROPY))
    entropy_blob = DATA_BLOB(len(_SECRETS_ENTROPY), entropy_buf)
    out_blob = DATA_BLOB()
    if not ctypes.windll.crypt32.CryptProtectData(
        ctypes.byref(in_blob),
        "netDiag",
        ctypes.byref(entropy_blob),
        None,
        None,
        _DPAPI_UI_FORBIDDEN,
        ctypes.byref(out_blob),
    ):
        raise OSError("CryptProtectData failed")
    try:
        return ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(out_blob.pbData)


def _dpapi_unprotect(blob: bytes) -> bytes:
    import ctypes
    from ctypes import wintypes

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [
            ("cbData", wintypes.DWORD),
            ("pbData", ctypes.POINTER(ctypes.c_char)),
        ]

    in_buf = ctypes.create_string_buffer(blob, len(blob))
    in_blob = DATA_BLOB(len(blob), in_buf)
    entropy_buf = ctypes.create_string_buffer(_SECRETS_ENTROPY, len(_SECRETS_ENTROPY))
    entropy_blob = DATA_BLOB(len(_SECRETS_ENTROPY), entropy_buf)
    out_blob = DATA_BLOB()
    if not ctypes.windll.crypt32.CryptUnprotectData(
        ctypes.byref(in_blob),
        None,
        ctypes.byref(entropy_blob),
        None,
        None,
        _DPAPI_UI_FORBIDDEN,
        ctypes.byref(out_blob),
    ):
        raise OSError("CryptUnprotectData failed")
    try:
        return ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(out_blob.pbData)


def _protect_bytes(plain: bytes) -> bytes:
    # Off-Windows: fail closed — never write plaintext secrets to disk.
    if not _SECRETS_USE_DPAPI:
        raise OSError("Secret store requires Windows DPAPI; refusing plaintext persist")
    return _dpapi_protect(plain)


def _unprotect_bytes(blob: bytes) -> bytes:
    if not _SECRETS_USE_DPAPI:
        raise OSError("Secret store requires Windows DPAPI")
    return _dpapi_unprotect(blob)


def _secret_payload():
    payload = {}
    for customer in CUSTOMERS:
        payload[customer["name"]] = {
            "username": customer["username"],
            "password": customer["password"],
            "host_secrets": list(customer.get("host_secrets") or []),
        }
    return payload


def _write_secret_store() -> bool:
    path = secrets_file()
    tmp = path.with_name(path.name + ".tmp")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        blob = _protect_bytes(json.dumps(_secret_payload()).encode("utf-8"))
        tmp.write_bytes(blob)
        os.replace(tmp, path)
        _restrict_to_current_user(path)
        return True
    except OSError:
        try:
            if tmp.exists():
                tmp.unlink()
        except OSError:
            pass
        return False


def _load_secret_store() -> dict:
    path = secrets_file()
    if not path.exists():
        return {}
    try:
        raw = _unprotect_bytes(path.read_bytes())
        data = json.loads(raw.decode("utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError, json.JSONDecodeError, UnicodeDecodeError):
        return {}


def _merge_secret_blob(customer, blob):
    if not isinstance(blob, dict):
        return
    username = str(blob.get("username", "")).strip()
    password = str(blob.get("password", "")).strip()
    if username:
        customer["username"] = username
    if password:
        customer["password"] = password
    secrets = []
    seen = set()
    for item in blob.get("host_secrets") or []:
        secret = _sanitize_host_secret(item)
        if not secret:
            continue
        key = normalize_hostname(secret["hostname"])
        if key in seen:
            continue
        seen.add(key)
        secrets.append(secret)
    if secrets or "host_secrets" in blob:
        customer["host_secrets"] = secrets


def _public_customers():
    return [
        {
            "name": c["name"],
            "seen_hostnames": list(c.get("seen_hostnames") or []),
        }
        for c in CUSTOMERS
    ]


def _json_has_plaintext_secrets(data) -> bool:
    if not isinstance(data, dict):
        return False
    if str(data.get("password", "")).strip():
        return True
    for item in data.get("customers") or []:
        if not isinstance(item, dict):
            continue
        if str(item.get("password", "")).strip():
            return True
        if item.get("host_secrets") or item.get("profiles"):
            return True
    if data.get("profiles"):
        return True
    return False


def normalize_hostname(hostname) -> str:
    return str(hostname or "").strip().lower()


def normalize_customer_name(name) -> str:
    return str(name or "").strip().lower()


def parse_cli_hostname(line) -> str | None:
    """Extract a device hostname from a CLI prompt line, or None."""
    if not line:
        return None
    match = _PROMPT_HOST_RE.match(str(line).strip())
    if not match:
        return None
    host = match.group(1)
    if host.lower() in _PROMPT_HOST_BLOCKLIST:
        return None
    return host


def _sanitize_host_secret(item):
    if not isinstance(item, dict):
        return None
    hostname = str(item.get("hostname", "")).strip()
    username = str(item.get("username", "")).strip()
    password = str(item.get("password", "")).strip()
    if not hostname or not username or not password:
        return None
    return {"hostname": hostname, "username": username, "password": password}


def _make_customer(name, username, password, host_secrets=None, seen_hostnames=None):
    name = str(name or "").strip() or "Default"
    username = str(username or "").strip()
    password = str(password or "").strip()
    secrets = []
    seen_secret = set()
    for item in host_secrets or []:
        secret = _sanitize_host_secret(item)
        if not secret:
            continue
        key = normalize_hostname(secret["hostname"])
        if key in seen_secret:
            continue
        seen_secret.add(key)
        secrets.append(secret)
    seen = []
    seen_keys = set()
    for host in seen_hostnames or []:
        host = str(host or "").strip()
        key = normalize_hostname(host)
        if not host or key in seen_keys:
            continue
        seen_keys.add(key)
        seen.append(host)
    return {
        "name": name,
        "username": username,
        "password": password,
        "host_secrets": secrets,
        "seen_hostnames": seen,
    }


def _sanitize_customer(item):
    """Public fields only. Secrets never come from settings.json."""
    if not isinstance(item, dict):
        return None
    name = str(item.get("name", "")).strip()
    if not name:
        return None
    return _make_customer(
        name,
        "",
        "",
        host_secrets=None,
        seen_hostnames=item.get("seen_hostnames"),
    )


def _find_customer_index(name):
    key = normalize_customer_name(name)
    if not key:
        return None
    for idx, customer in enumerate(CUSTOMERS):
        if normalize_customer_name(customer["name"]) == key:
            return idx
    return None


def _sync_active_aliases():
    """USERNAME/PASSWORD/PROFILES always reflect the active customer."""
    global USERNAME, PASSWORD, PROFILES, ACTIVE_CUSTOMER
    if not CUSTOMERS:
        CUSTOMERS.append(_make_customer("Default", "", ""))
        ACTIVE_CUSTOMER = "Default"
    idx = _find_customer_index(ACTIVE_CUSTOMER)
    if idx is None:
        ACTIVE_CUSTOMER = CUSTOMERS[0]["name"]
        idx = 0
    customer = CUSTOMERS[idx]
    USERNAME = customer["username"]
    PASSWORD = customer["password"]
    PROFILES = customer["host_secrets"]


def load_settings():
    """Load public customer names from settings.json and secrets from DPAPI.

    settings.json is never a secret source. If an old file still has username,
    password, or host_secrets, those fields are ignored (not imported, not
    rewritten on load).
    """
    global USERNAME, PASSWORD, CUSTOMERS, ACTIVE_CUSTOMER, LOGIN_MODE

    path = settings_file()
    try:
        if not path.exists():
            secret_map = _load_secret_store()
            if secret_map:
                loaded = []
                for name, blob in secret_map.items():
                    customer = _make_customer(name, "", "")
                    _merge_secret_blob(customer, blob)
                    loaded.append(customer)
                if loaded:
                    CUSTOMERS = loaded
                    ACTIVE_CUSTOMER = CUSTOMERS[0]["name"]
            _sync_active_aliases()
            return

        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        mode = str(data.get("login_mode", "auto")).strip().lower()
        LOGIN_MODE = mode if mode in LOGIN_MODES else "auto"

        loaded = []
        seen_names = set()
        raw_customers = data.get("customers")
        if isinstance(raw_customers, list) and raw_customers:
            for item in raw_customers:
                customer = _sanitize_customer(item)
                if not customer:
                    continue
                key = normalize_customer_name(customer["name"])
                if key in seen_names:
                    continue
                seen_names.add(key)
                loaded.append(customer)
        else:
            loaded.append(_make_customer("Default", "", ""))

        CUSTOMERS = loaded or [_make_customer("Default", "", "")]
        active = str(data.get("active_customer", "")).strip()
        if _find_customer_index(active) is not None:
            ACTIVE_CUSTOMER = CUSTOMERS[_find_customer_index(active)]["name"]
        else:
            ACTIVE_CUSTOMER = CUSTOMERS[0]["name"]

        secret_map = _load_secret_store()
        if secret_map:
            for customer in CUSTOMERS:
                blob = secret_map.get(customer["name"])
                if blob is None:
                    for key, value in secret_map.items():
                        if normalize_customer_name(key) == normalize_customer_name(
                            customer["name"]
                        ):
                            blob = value
                            break
                if blob:
                    _merge_secret_blob(customer, blob)

        _sync_active_aliases()
        # Leftover plaintext in settings.json is ignored. Do not rewrite on
        # load — that would persist empty secrets and drop a good DPAPI store.

    except (json.JSONDecodeError, OSError, TypeError, ValueError):
        _sync_active_aliases()


def get_login_mode():
    return LOGIN_MODE if LOGIN_MODE in LOGIN_MODES else "auto"


def set_login_mode(mode) -> bool:
    global LOGIN_MODE
    mode = str(mode or "").strip().lower()
    if mode not in LOGIN_MODES:
        return False
    with _STATE_LOCK:
        LOGIN_MODE = mode
        return _write_settings()


def get_customers():
    return [json.loads(json.dumps(c)) for c in CUSTOMERS]


def get_customer_names():
    return [c["name"] for c in CUSTOMERS]


def get_active_customer_name():
    _sync_active_aliases()
    return ACTIVE_CUSTOMER


def get_active_customer():
    _sync_active_aliases()
    idx = _find_customer_index(ACTIVE_CUSTOMER)
    if idx is None:
        return None
    return CUSTOMERS[idx]


def set_active_customer(name) -> bool:
    global ACTIVE_CUSTOMER
    idx = _find_customer_index(name)
    if idx is None:
        return False
    with _STATE_LOCK:
        ACTIVE_CUSTOMER = CUSTOMERS[idx]["name"]
        _sync_active_aliases()
        return _write_settings()


def upsert_customer(name, username, password) -> bool:
    """Create or update a customer (site) profile. Makes it active.

    Username/password may be empty until the user sets them.
    """
    global ACTIVE_CUSTOMER
    name = str(name or "").strip()
    username = str(username or "").strip()
    password = str(password or "").strip()
    if not name:
        return False
    with _STATE_LOCK:
        idx = _find_customer_index(name)
        if idx is None:
            CUSTOMERS.append(_make_customer(name, username, password))
            ACTIVE_CUSTOMER = CUSTOMERS[-1]["name"]
        else:
            CUSTOMERS[idx]["name"] = name
            CUSTOMERS[idx]["username"] = username
            CUSTOMERS[idx]["password"] = password
            ACTIVE_CUSTOMER = name
        _sync_active_aliases()
        return _write_settings()


def rename_customer(old_name, new_name) -> bool:
    """Rename a customer in place. Fails if the new name is already used."""
    global ACTIVE_CUSTOMER
    new_name = str(new_name or "").strip()
    with _STATE_LOCK:
        idx = _find_customer_index(old_name)
        if idx is None or not new_name:
            return False
        other = _find_customer_index(new_name)
        if other is not None and other != idx:
            return False
        CUSTOMERS[idx]["name"] = new_name
        if idx == _find_customer_index(ACTIVE_CUSTOMER) or normalize_customer_name(
            ACTIVE_CUSTOMER
        ) == normalize_customer_name(old_name):
            ACTIVE_CUSTOMER = new_name
        _sync_active_aliases()
        return _write_settings()


def delete_customer(name) -> bool:
    """Remove a customer profile. Keeps at least one customer."""
    global ACTIVE_CUSTOMER
    with _STATE_LOCK:
        if len(CUSTOMERS) <= 1:
            return False
        idx = _find_customer_index(name)
        if idx is None:
            return False
        removing_active = idx == _find_customer_index(ACTIVE_CUSTOMER)
        CUSTOMERS.pop(idx)
        if removing_active:
            ACTIVE_CUSTOMER = CUSTOMERS[0]["name"]
        _sync_active_aliases()
        return _write_settings()


def get_credentials():
    """Return the active customer's default local credentials."""
    _sync_active_aliases()
    return USERNAME, PASSWORD


def get_profiles():
    """Host-exception secrets on the active customer."""
    customer = get_active_customer()
    if not customer:
        return []
    return [dict(p) for p in customer["host_secrets"]]


def get_profile_hostnames():
    """Hostnames known for the active customer (exceptions + previously seen)."""
    customer = get_active_customer()
    if not customer:
        return []
    names = []
    seen = set()
    for secret in customer["host_secrets"]:
        key = normalize_hostname(secret["hostname"])
        if key in seen:
            continue
        seen.add(key)
        names.append(secret["hostname"])
    for host in customer.get("seen_hostnames") or []:
        key = normalize_hostname(host)
        if key in seen:
            continue
        seen.add(key)
        names.append(host)
    return names


def credentials_for_hostname(hostname):
    """Return (username, password) for a host exception on the active customer."""
    customer = get_active_customer()
    if not customer:
        return None
    key = normalize_hostname(hostname)
    if not key:
        return None
    for secret in customer["host_secrets"]:
        if normalize_hostname(secret["hostname"]) == key:
            return secret["username"], secret["password"]
    return None


def _write_settings() -> bool:
    """Persist names/mode in settings.json and secrets in the DPAPI store.

    If the secret store cannot be written, public settings are left unchanged
    so we never rewrite settings.json unless secrets are already in the store.
    """
    with _STATE_LOCK:
        _sync_active_aliases()
        if not _write_secret_store():
            return False
        path = settings_file()
        data = {
            "active_customer": ACTIVE_CUSTOMER,
            "login_mode": get_login_mode(),
            "customers": _public_customers(),
        }
        tmp = path.with_name(path.name + ".tmp")
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
                f.write("\n")
            os.replace(tmp, path)
            _restrict_to_current_user(path)
            return True
        except OSError:
            try:
                if tmp.exists():
                    tmp.unlink()
            except OSError:
                pass
            return False


load_settings()


def save_settings(username: str, password: str) -> bool:
    """Update the active customer's default local account."""
    customer = get_active_customer()
    if not customer:
        return False
    return upsert_customer(customer["name"], username, password)


def save_profiles(profiles) -> bool:
    """Replace host-exception secrets on the active customer."""
    with _STATE_LOCK:
        customer = get_active_customer()
        if not customer:
            return False
        cleaned = []
        seen = set()
        for item in profiles or []:
            secret = _sanitize_host_secret(item)
            if not secret:
                continue
            key = normalize_hostname(secret["hostname"])
            if key in seen:
                continue
            seen.add(key)
            cleaned.append(secret)
        customer["host_secrets"] = cleaned
        _sync_active_aliases()
        return _write_settings()


def upsert_hostname_profile(hostname, username, password) -> bool:
    """Create or update a host-exception secret on the active customer."""
    hostname = str(hostname or "").strip()
    username = str(username or "").strip()
    password = str(password or "").strip()
    if not hostname or not username or not password:
        return False
    with _STATE_LOCK:
        customer = get_active_customer()
        if not customer:
            return False
        key = normalize_hostname(hostname)
        for secret in customer["host_secrets"]:
            if normalize_hostname(secret["hostname"]) == key:
                secret["hostname"] = hostname
                secret["username"] = username
                secret["password"] = password
                break
        else:
            customer["host_secrets"].append(
                {"hostname": hostname, "username": username, "password": password}
            )
        _sync_active_aliases()
        return _write_settings()


def record_seen_hostname(hostname) -> bool:
    """Remember a hostname on the active customer without storing a new secret."""
    hostname = str(hostname or "").strip()
    with _STATE_LOCK:
        customer = get_active_customer()
        if not customer or not hostname:
            return False
        key = normalize_hostname(hostname)
        for existing in customer["seen_hostnames"]:
            if normalize_hostname(existing) == key:
                return True
        customer["seen_hostnames"].append(hostname)
        if len(customer["seen_hostnames"]) > _MAX_SEEN_HOSTNAMES:
            customer["seen_hostnames"] = customer["seen_hostnames"][-_MAX_SEEN_HOSTNAMES:]
        return _write_settings()


def remember_successful_login(username, password, hostname=None):
    """Keep last-good secrets for the active customer.

    Fleet-wide local accounts are not cloned per hostname. The hostname is
    recorded on the customer so manual host selection has a list to pick from.
    A host-exception secret is stored only when it differs from the customer default.
    """
    global LAST_SUCCESS_USERNAME, LAST_SUCCESS_PASSWORD, LAST_SUCCESS_CUSTOMER
    username = str(username or "").strip()
    password = str(password or "").strip()
    if not username or not password:
        return
    with _STATE_LOCK:
        LAST_SUCCESS_USERNAME = username
        LAST_SUCCESS_PASSWORD = password
        LAST_SUCCESS_CUSTOMER = get_active_customer_name()
        if hostname:
            record_seen_hostname(hostname)
            existing = credentials_for_hostname(hostname)
            if existing == (username, password):
                return
            if (username, password) == get_credentials():
                return
            upsert_hostname_profile(hostname, username, password)


def list_login_attempts(hostname_hint=None, extra=None, mode=None):
    """Credential tries for the *active customer only*.

    auto: host hint (if any) → extra → last success (this customer) →
          customer default.
    manual: host hint exception (if any) → extra → customer default.
    Other customers' secrets are never tried. Other devices on this customer
    are not tried unless that hostname is the hint — walking every host
    password can lock a local account.
    """
    attempts = []
    seen = set()
    mode = (mode or get_login_mode()).strip().lower()
    if mode not in LOGIN_MODES:
        mode = "auto"
    if mode == "skip":
        return attempts
    customer = get_active_customer()
    cust_name = customer["name"] if customer else "Default"
    default_user = customer["username"] if customer else USERNAME
    default_pass = customer["password"] if customer else PASSWORD
    host_secrets = list(customer["host_secrets"]) if customer else []

    def add(reason, user, password):
        user = str(user or "").strip()
        password = str(password or "")
        if not user or not password:
            return
        key = (user, password)
        if key in seen:
            return
        seen.add(key)
        attempts.append((reason, user, password))

    hint = normalize_hostname(hostname_hint)
    if hint:
        for secret in host_secrets:
            if normalize_hostname(secret["hostname"]) == hint:
                add(
                    f"{cust_name} host {secret['hostname']}",
                    secret["username"],
                    secret["password"],
                )
                break

    if extra:
        add("selected credentials", extra[0], extra[1])

    if mode == "manual":
        add(f"{cust_name} default", default_user, default_pass)
        return attempts

    if (
        LAST_SUCCESS_USERNAME
        and normalize_customer_name(LAST_SUCCESS_CUSTOMER)
        == normalize_customer_name(cust_name)
    ):
        add("last successful login", LAST_SUCCESS_USERNAME, LAST_SUCCESS_PASSWORD)

    add(f"{cust_name} default", default_user, default_pass)
    return attempts


# ====================== IMPORT GUARDS (logic owns the dependencies) ======================

# Do not import scapy at module load. Importing scapy.all on Windows enumerates
# Npcap adapters (pcap_findalldevs). If Npcap is still Admin-only, Packet.dll
# launches NpcapHelper.exe with a UAC prompt — even when the user only wanted
# the serial console.
SCAPY_AVAILABLE = importlib.util.find_spec("scapy") is not None
SCAPY_ERROR = None
_SCAPY_LOADED = False


def is_process_elevated():
    """True when this process already has an Administrator token."""
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def npcap_would_prompt_uac():
    """True when opening a capture handle would spawn NpcapHelper.exe (UAC)."""
    admin_only = npcap_admin_only_enabled()
    if admin_only is None:
        return False
    return bool(admin_only) and not is_process_elevated()


def _disable_scapy_elevation():
    """Stop Scapy from wrapping Windows commands in PowerShell -Verb RunAs."""
    try:
        from scapy.config import conf as scapy_conf
        scapy_conf.interactive = False
    except Exception:
        pass
    try:
        import scapy.arch.windows as winarch

        winarch._encapsulate_admin = lambda cmd: cmd

        def _start_pcap_no_uac(askadmin=False):
            return winarch._pcap_service_control("sc start", askadmin=False)

        def _stop_pcap_no_uac(askadmin=False):
            return winarch._pcap_service_control("sc stop", askadmin=False)

        winarch.pcap_service_start = _start_pcap_no_uac
        winarch.pcap_service_stop = _stop_pcap_no_uac
    except Exception:
        pass


def _load_scapy():
    """Import scapy on first capture use and disable its UAC wrappers."""
    global _SCAPY_LOADED, SCAPY_AVAILABLE, SCAPY_ERROR
    global AsyncSniffer, conf, get_if_addr, get_if_list, load_contrib
    global Ether, Dot3, Dot1Q, SNAP
    global CDPMsgDeviceID, CDPMsgPortID, CDPv2_HDR
    global LLDPDUChassisID, LLDPDUPortID, LLDPDUSystemName, LLDPDUPortDescription
    global resolve_iface, ETH_P_ALL

    if _SCAPY_LOADED:
        return True

    try:
        from scapy.all import (
            AsyncSniffer as _AsyncSniffer,
            conf as _conf,
            get_if_addr as _get_if_addr,
            get_if_list as _get_if_list,
            load_contrib as _load_contrib,
            Ether as _Ether,
            Dot3 as _Dot3,
            Dot1Q as _Dot1Q,
            SNAP as _SNAP,
        )
        from scapy.contrib.cdp import (
            CDPMsgDeviceID as _CDPMsgDeviceID,
            CDPMsgPortID as _CDPMsgPortID,
            CDPv2_HDR as _CDPv2_HDR,
        )
        from scapy.contrib.lldp import (
            LLDPDUChassisID as _LLDPDUChassisID,
            LLDPDUPortID as _LLDPDUPortID,
            LLDPDUSystemName as _LLDPDUSystemName,
            LLDPDUPortDescription as _LLDPDUPortDescription,
        )
        from scapy.interfaces import resolve_iface as _resolve_iface
        from scapy.data import ETH_P_ALL as _ETH_P_ALL

        AsyncSniffer = _AsyncSniffer
        conf = _conf
        get_if_addr = _get_if_addr
        get_if_list = _get_if_list
        load_contrib = _load_contrib
        Ether = _Ether
        Dot3 = _Dot3
        Dot1Q = _Dot1Q
        SNAP = _SNAP
        CDPMsgDeviceID = _CDPMsgDeviceID
        CDPMsgPortID = _CDPMsgPortID
        CDPv2_HDR = _CDPv2_HDR
        LLDPDUChassisID = _LLDPDUChassisID
        LLDPDUPortID = _LLDPDUPortID
        LLDPDUSystemName = _LLDPDUSystemName
        LLDPDUPortDescription = _LLDPDUPortDescription
        resolve_iface = _resolve_iface
        ETH_P_ALL = _ETH_P_ALL

        _disable_scapy_elevation()
        try:
            if hasattr(conf, "contribs") and "LLDP" in conf.contribs:
                conf.contribs["LLDP"].strict_mode_disable()
        except Exception:
            pass

        _SCAPY_LOADED = True
        SCAPY_AVAILABLE = True
        return True
    except ImportError as e:
        SCAPY_AVAILABLE = False
        SCAPY_ERROR = str(e)
        return False

try:
    import serial
    from serial.tools import list_ports
    SERIAL_AVAILABLE = True
except ImportError as e:
    SERIAL_AVAILABLE = False
    SERIAL_ERROR = str(e)


# MAC table snapshots (module level / outside SerialSession scope).
# This allows collecting "old" from one switch/session and "new" from
# a different switch/session, then comparing across them.
old_mac_table = {}
new_mac_table = {}


# ====================== CORE LOGIC: SerialSession ======================

class SerialSession:
    """Handles serial connection, login, and communication for console ports.
    This is pure logic / I/O. The GUI only owns the display of its output queue.
    """

    RELOGIN_COOLDOWN_SEC = 5
    READ_ERROR_LOG_INTERVAL_SEC = 3

    def __init__(self, port, baudrate=9600):
        self.port = port
        self.baudrate = baudrate
        self.ser = None
        self.connected = False
        self.auto_login = True
        self.prompt_char = ">"
        self.read_queue = queue.Queue()
        self._sub_lock = threading.Lock()
        self._subscribers = [self.read_queue]
        self._cmd_lock = threading.Lock()
        self._capturing = False
        self._capture_lines = []
        self._capture_prompt = threading.Event()
        self._capture_echo_seen = True
        self._capture_await_echo = ""
        self.stop_event = threading.Event()
        self.reader_thread = None
        self.output_callback = None
        self.login_lock = threading.Lock()
        self._relogin_in_progress = False
        self._last_relogin_attempt = 0.0
        self._last_read_error_logged = 0.0
        self._disconnect_announced = False
        self.hostname = None
        self.login_user = None

    def open(self):
        if not SERIAL_AVAILABLE:
            raise RuntimeError("pyserial is not available")
        if not is_local_com_port(self.port):
            raise RuntimeError(
                f"Refusing non-local serial target {self.port!r}. "
                "Only local COM ports are allowed."
            )
        try:
            self.ser = serial.Serial(
                port=self.port,
                baudrate=self.baudrate,
                bytesize=serial.EIGHTBITS,
                parity=serial.PARITY_NONE,
                stopbits=serial.STOPBITS_ONE,
                timeout=0.5,
                write_timeout=2
            )
            return True
        except serial.SerialException as e:
            raise RuntimeError(f"Failed to open {self.port}: {e}")

    def close(self):
        self.stop_event.set()
        if self.reader_thread and self.reader_thread.is_alive():
            self.reader_thread.join(timeout=2)
        if self.ser and self.ser.is_open:
            self.ser.close()
        self.connected = False

    def _reader_loop(self):
        """Background reader thread. Pushes complete lines into the shared queue."""
        buffer = ""
        while not self.stop_event.is_set():
            if not self.login_lock.acquire(timeout=0.15):
                continue

            try:
                if self.ser and self.ser.is_open:
                    data = self.ser.read(1024)
                    if data:
                        text = data.decode('ascii', errors='replace')
                        buffer += text
                        while '\n' in buffer or '\r' in buffer:
                            line, buffer = self._split_line(buffer)
                            if line.strip():
                                self._emit_line(line.rstrip('\r\n'))

                        detect_window = buffer[-512:] if len(buffer) > 512 else buffer
                        if self.auto_login and self._detect_new_device(detect_window):
                            buffer = ""
                            self._relogin_unlocked(
                                reason="New device detected — logging in"
                            )
                else:
                    time.sleep(0.2)
            except Exception as e:
                if not self.stop_event.is_set():
                    self._mark_disconnected(
                        "[SERIAL] Cable disconnected — waiting for new device..."
                    )
                    if self._should_log_read_error():
                        self._emit_line(f"[READ ERROR] {e}")
                    time.sleep(0.5)
            finally:
                self.login_lock.release()

    def _split_line(self, buf):
        for sep in ('\r\n', '\n', '\r'):
            if sep in buf:
                idx = buf.find(sep)
                return buf[:idx + len(sep)], buf[idx + len(sep):]
        return buf, ""

    def _enqueue_login_text(self, text):
        """Push login-phase serial output to the GUI as line-oriented chunks."""
        for line in text.splitlines():
            stripped = line.rstrip('\r\n')
            if stripped:
                self._emit_line(stripped)

    def subscribe(self):
        """Extra display queue so a second window does not steal the main console feed."""
        q = queue.Queue()
        with self._sub_lock:
            self._subscribers.append(q)
        return q

    def unsubscribe(self, q):
        if q is self.read_queue:
            return
        with self._sub_lock:
            if q in self._subscribers:
                self._subscribers.remove(q)

    def _line_is_cli_prompt(self, line):
        text = (line or "").strip()
        if not text:
            return False
        if parse_cli_hostname(text):
            return True
        if text[-1] in "><#$" and " " not in text[:-1] and text[:-1]:
            return True
        return False

    def _emit_line(self, line):
        """Fan-out one serial line to every display queue and the capture buffer."""
        text = line if isinstance(line, str) else str(line)
        if not text:
            return
        with self._sub_lock:
            if self._capturing:
                self._capture_lines.append(text)
                if not self._capture_echo_seen:
                    await_echo = (self._capture_await_echo or "").lower()
                    if self._line_is_cli_prompt(text):
                        pass  # leftover UART prompt — ignore until command echo
                    elif await_echo and await_echo in text.lower():
                        self._capture_echo_seen = True
                    else:
                        self._capture_echo_seen = True
                elif self._line_is_cli_prompt(text):
                    self._capture_prompt.set()
            subs = list(self._subscribers)
        for q in subs:
            q.put(text)

    def _looks_like_device_prompt(self, buffer):
        """True when the last non-empty line ends with a typical CLI prompt character."""
        lines = [ln.strip() for ln in buffer.splitlines() if ln.strip()]
        if not lines:
            return False
        last = lines[-1]
        return last.endswith(('>', '#', '$'))

    def _hostname_from_prompt_buffer(self, buffer):
        lines = [ln.strip() for ln in buffer.splitlines() if ln.strip()]
        if not lines:
            return None
        return parse_cli_hostname(lines[-1])

    def _looks_like_auth_failure(self, text):
        lower = (text or "").lower()
        return (
            "authentication failed" in lower
            or "login invalid" in lower
            or "% access denied" in lower
            or "bad secrets" in lower
            or "bad password" in lower
        )

    def _detect_login_required(self, text):
        """True when recent console output indicates an unauthenticated session."""
        lines = [ln.strip().lower() for ln in text.splitlines() if ln.strip()]
        for line in lines[-6:]:
            if line.endswith(("username:", "user name:", "login:")):
                return True
            if line.endswith("password:"):
                return True
            if "press return" in line or "press enter" in line:
                return True
            if "user access verification" in line:
                return True
        return False

    def _detect_session_reset(self, text):
        """Strong unauthenticated-console signals (cable move), not 'Username:' in show output."""
        lines = [ln.strip().lower() for ln in text.splitlines() if ln.strip()]
        for line in lines[-6:]:
            if "user access verification" in line:
                return True
            if "press return" in line or "press enter" in line:
                return True
        return False

    def _detect_new_device(self, text):
        """True when a new switch is present and ready for login (not just disconnected).

        While already logged in, ignore a bare Username:/Password: line — banners and
        'show users' would otherwise kick off another login.
        """
        if self.connected:
            return self._detect_session_reset(text)
        return self._detect_login_required(text)

    def _mark_disconnected(self, message=None):
        """Mark session disconnected and wait for the reader to spot a new device."""
        was_connected = self.connected
        self.connected = False
        if message and (was_connected or not self._disconnect_announced):
            self._emit_line(message)
            self._disconnect_announced = True
        # Clear cooldown so the next detected device can log in immediately.
        self._last_relogin_attempt = 0.0

    def _should_log_read_error(self):
        """Rate-limit serial read errors while re-login is retrying."""
        now = time.time()
        if now - self._last_relogin_attempt < self.RELOGIN_COOLDOWN_SEC:
            return False
        if now - self._last_read_error_logged < self.READ_ERROR_LOG_INTERVAL_SEC:
            return False
        self._last_read_error_logged = now
        return True

    def _perform_login(self, username, password, timeout=25):
        """Drive username/password login on the open port. Returns True on prompt detection."""
        if not self.ser or not self.ser.is_open:
            raise RuntimeError("Serial port not open")

        self.ser.write(b"\r")
        time.sleep(0.6)

        start_time = time.time()
        buffer = ""
        sent_user = False
        sent_pass = False

        while time.time() - start_time < timeout:
            try:
                data = self.ser.read(1024)
                if data:
                    text = data.decode('ascii', errors='replace')
                    buffer += text
                    self._enqueue_login_text(text)

                    lower_buf = buffer.lower()

                    if "press return" in lower_buf or "press enter" in lower_buf:
                        self.ser.write(b"\r")
                        buffer = ""
                        time.sleep(0.4)
                        continue

                    if not sent_user and (
                        "username:" in lower_buf
                        or "user name:" in lower_buf
                        or "login:" in lower_buf
                    ):
                        self.ser.write(f"{username}\r".encode('ascii'))
                        sent_user = True
                        buffer = ""
                        time.sleep(0.3)

                    elif not sent_pass and "password:" in lower_buf:
                        self.ser.write(f"{password}\r".encode('ascii'))
                        sent_pass = True
                        buffer = ""
                        time.sleep(0.5)

                    if sent_pass and self._looks_like_auth_failure(buffer):
                        self.connected = False
                        return False

                    if sent_pass and self._detect_login_required(buffer):
                        # Password rejected — back at Username:
                        self.connected = False
                        return False

                    if self._looks_like_device_prompt(buffer):
                        lines = [ln.strip() for ln in buffer.splitlines() if ln.strip()]
                        self.connected = True
                        self.prompt_char = lines[-1][-1]
                        self.hostname = self._hostname_from_prompt_buffer(buffer)
                        self.login_user = username
                        return True

            except Exception as e:
                self._emit_line(f"[LOGIN ERROR] {e}")

            time.sleep(0.15)

        self.connected = False
        return False

    def _try_credential_attempts(
        self, hostname_hint=None, extra=None, timeout=10, login_mode=None
    ):
        """Try secrets from the active customer only (auto or manual)."""
        attempts = list_login_attempts(
            hostname_hint=hostname_hint, extra=extra, mode=login_mode
        )
        if not attempts:
            return False

        for reason, username, password in attempts:
            self._emit_line(
                f"[SERIAL] Trying {reason} (user {username!r})..."
            )
            if self._perform_login(username, password, timeout=timeout):
                remember_successful_login(username, password, self.hostname)
                if self.hostname:
                    self._emit_line(
                        f"[SERIAL] Logged in as {username!r} on {self.hostname}."
                    )
                else:
                    self._emit_line(
                        f"[SERIAL] Logged in as {username!r}."
                    )
                return True
        return False

    def _relogin_unlocked(self, reason="New device detected — logging in"):
        """Attempt login with hostname profiles. Caller must hold login_lock."""
        if not self.auto_login:
            return self.connected
        if self._relogin_in_progress:
            return self.connected

        now = time.time()
        if now - self._last_relogin_attempt < self.RELOGIN_COOLDOWN_SEC:
            return False

        self._relogin_in_progress = True
        self._last_relogin_attempt = now
        self.connected = False
        self.hostname = None
        cust = get_active_customer_name()
        mode = get_login_mode()
        self._emit_line(
            f"[SERIAL] {reason} — customer {cust!r} ({mode} login)..."
        )

        try:
            if self._try_credential_attempts(hostname_hint=None, timeout=10):
                self._disconnect_announced = False
                self._emit_line("[SERIAL] Re-login successful.")
                time.sleep(0.3)
                self._send_raw("terminal length 0")
                return True

            self._emit_line(
                "[SERIAL] Re-login failed — no secret for this customer worked. "
                "Check the active customer in Settings."
            )
            return False
        finally:
            self._relogin_in_progress = False

    def login(
        self, username, password, timeout=25, hostname_hint=None, login_mode=None
    ):
        """Login using the active customer's secrets.

        Starts the continuous reader thread on successful prompt detection.
        """
        extra = None
        if username and password:
            extra = (username, password)
        with self.login_lock:
            ok = self._try_credential_attempts(
                hostname_hint=hostname_hint,
                extra=extra,
                timeout=min(timeout, 12),
                login_mode=login_mode,
            )
            if not ok:
                return False

            self.start_reader()
            return True

    def start_reader(self):
        """Start the background UART reader if it is not already running."""
        if not self.reader_thread or not self.reader_thread.is_alive():
            self.stop_event.clear()
            self.reader_thread = threading.Thread(target=self._reader_loop, daemon=True)
            self.reader_thread.start()

    def attach_console(self):
        """Live terminal on the open port. Does not type username/password."""
        self.auto_login = False
        self.connected = True
        self.start_reader()
        self._emit_line(
            "[SERIAL] Terminal open — automatic login is off. "
            "Type at the CLI (Enter at Username:/Password: yourself)."
        )
        return True

    def _drain_uart_display_only(self):
        """Flush leftover UART into display queues before arming command capture.

        Caller must hold login_lock so the reader cannot interleave.
        """
        if not self.ser or not self.ser.is_open:
            return
        leftover = b""
        try:
            waiting = int(getattr(self.ser, "in_waiting", 0) or 0)
            leftover = self.ser.read(waiting or 1024)
        except Exception:
            return
        if not leftover:
            return
        text = leftover.decode("ascii", errors="replace")
        for line in text.splitlines():
            stripped = line.rstrip("\r\n")
            if stripped:
                self._emit_line(stripped)

    def _send_raw(self, line):
        """Write a line to the port without connection checks (used during login/re-login)."""
        if self.ser and self.ser.is_open:
            self.ser.write((line.rstrip() + "\r").encode('ascii'))

    def send_line(self, line):
        """Send a command line (adds carriage return). Echo comes back via the reader."""
        with self.login_lock:
            if not self.ser or not self.ser.is_open:
                self._emit_line("[SEND] Serial port is not open")
                return
            if self.auto_login and not self.connected:
                self._emit_line(
                    "[SEND] Not connected — waiting for new device login prompt"
                )
                return

            try:
                self._send_raw(line)
            except Exception as e:
                self._mark_disconnected(
                    "[SERIAL] Send failed — cable may have moved. "
                    "Waiting for new device..."
                )
                self._emit_line(f"[SEND ERROR] {e}")

    def execute_command(self, cmd, wait_prompt=True, timeout=15):
        """Send a command and wait for the next CLI prompt.

        Live output still fans out to display queues. Capture uses a side
        buffer so the GUI (and a second window) cannot steal MAC/show output.
        """
        if not self.ser:
            return "Not connected"

        if not self.connected:
            return "Not connected — waiting for new device"

        with self._cmd_lock:
            try:
                with self.login_lock:
                    if not self.connected:
                        return "Not connected — waiting for new device"
                    self._drain_uart_display_only()
                    with self._sub_lock:
                        self._capturing = True
                        self._capture_lines = []
                        self._capture_prompt.clear()
                        self._capture_await_echo = str(cmd).strip()
                        self._capture_echo_seen = not bool(self._capture_await_echo)
                    if self.ser and self.ser.is_open:
                        self._send_raw(cmd)
                if wait_prompt:
                    self._capture_prompt.wait(timeout=timeout)
                else:
                    time.sleep(0.15)
                with self._sub_lock:
                    return "\n".join(self._capture_lines)
            finally:
                with self._sub_lock:
                    self._capturing = False
                    self._capture_echo_seen = True

    def execute_commands(self, cmds, timeout=20):
        """Run commands one at a time, waiting for a prompt after each."""
        chunks = []
        for cmd in cmds:
            chunks.append(
                self.execute_command(cmd, wait_prompt=True, timeout=timeout)
            )
        return "\n".join(chunks)


# ====================== SEGMENTED LOGIC FUNCTIONS (individual actions) ======================

def execute_show_version(session: SerialSession):
    """Logic for 'Show Version' button."""
    session.send_line("show version")


def execute_show_inventory(session: SerialSession):
    session.send_line("show inventory")


def execute_show_environment(session: SerialSession):
    session.send_line("show environment")


def execute_show_interfaces(session: SerialSession):
    session.send_line("show ip interface brief")


def execute_show_neighbors(session: SerialSession):
    """One function for the combined CDP + LLDP neighbors (per menu map)."""
    session.execute_commands(
        ["show cdp neighbors", "show lldp neighbors"],
        timeout=25,
    )


def execute_transceiver_details(session: SerialSession):
    """Transceiver details (dBm) - matches 'Show transceiver details' in the menu map."""
    session.execute_commands(
        ["show interfaces transceiver", "show interfaces transceiver detail"],
        timeout=30,
    )


def execute_show_running_config(session: SerialSession):
    """Long command - the GUI is responsible for any confirmation dialog."""
    session.send_line("show running-config")


def execute_show_users(session: SerialSession):
    session.send_line("show users")


def execute_terminal_length_zero(session: SerialSession):
    session.send_line("terminal length 0")


# --- Mac address table logic (menu map: Grab old / Grab new / Compare) ---

def _capture_mac_table(session: SerialSession) -> str:
    """Wait for prompt after paging-off, then capture 'show mac address-table'."""
    session.execute_command("terminal length 0", wait_prompt=True, timeout=8)
    return session.execute_command(
        "show mac address-table", wait_prompt=True, timeout=30
    )


def _parse_mac_table(output: str) -> dict:
    """Best-effort parser for typical 'show mac address-table' output.

    Returns: {normalized_mac_12hex_lowercase: port_string}
    Works with common 'show mac address-table' formats.
    """
    table = {}
    for line in output.splitlines():
        # Find a MAC address pattern (supports xxxx.xxxx.xxxx or xx:xx:xx:xx:xx:xx etc.)
        mac_m = re.search(r'([0-9a-fA-F]{2,4}([.:-][0-9a-fA-F]{2,4}){2,5})', line, re.I)
        if not mac_m:
            continue
        mac_raw = mac_m.group(1)
        # Find a port-like token at the end of the line
        port_m = re.search(r'([A-Za-z]{2,}[0-9/.,-]+)\s*$', line)
        port = port_m.group(1).strip() if port_m else None
        if not port:
            continue
        # Normalize: remove separators, lowercase, keep last 12 hex chars
        mac = re.sub(r'[^0-9a-fA-F]', '', mac_raw).lower()
        if len(mac) > 12:
            mac = mac[-12:]
        if len(mac) == 12:
            table[mac] = port
    return table


def grab_old_mac_table(session: SerialSession):
    """Collect 'old' MAC address table snapshot.

    Captures output from the given session, parses it, stores into the
    module-level old_mac_table (so it can come from a different session/switch
    than the 'new' one), and returns the dict for the GUI to display.
    """
    output = _capture_mac_table(session)
    parsed = _parse_mac_table(output)
    global old_mac_table
    old_mac_table = parsed
    return parsed


def grab_new_mac_table(session: SerialSession):
    """Collect 'new' MAC address table snapshot.

    Same as above but for new_mac_table.
    """
    output = _capture_mac_table(session)
    parsed = _parse_mac_table(output)
    global new_mac_table
    new_mac_table = parsed
    return parsed


def compare_mac_tables(session: SerialSession = None):
    """Compare old vs new MAC snapshots.

    Reports MACs that disappeared from the new table, and MACs that stayed
    but moved port. Format:
      "4455 was on Gi0/1"
      "4455 moved from Gi0/1 to Gi0/2"
    """
    global old_mac_table, new_mac_table

    results = []
    for mac, old_port in old_mac_table.items():
        last_four = mac[-4:] if len(mac) >= 4 else mac
        if mac not in new_mac_table:
            results.append(f"{last_four} was on {old_port}")
        elif new_mac_table[mac] != old_port:
            results.append(f"{last_four} moved from {old_port} to {new_mac_table[mac]}")
    return results


# --- Packet parsing logic (pure function, no GUI) ---

# Dest MACs used by CDP / LLDP. Matching dest is VLAN-safe (802.1Q does not
# change the Ethernet destination). Kernel BPF is intentionally not used:
# Npcap + `ether proto 0x88cc` misses VLAN-tagged LLDP, and mixing `vlan`
# into a BPF expression shifts offsets for the rest of the filter.
CDP_MULTICAST = "01:00:0c:cc:cc:cc"
LLDP_MULTICASTS = (
    "01:80:c2:00:00:0e",  # nearest bridge
    "01:80:c2:00:00:03",  # nearest non-TPMR bridge
    "01:80:c2:00:00:00",  # nearest customer bridge
)
LLDP_ETHERTYPE = 0x88CC
CDP_ETHERTYPE = 0x2000
VLAN_ETHERTYPES = (0x8100, 0x88A8, 0x9100)

# Adapters that cannot receive a neighbor advertisement from a switch port.
_SKIP_IFACE_TOKENS = (
    "loopback",
    "wan miniport",
    "bluetooth",
    "isatap",
    "teredo",
    "wi-fi direct",
    "microsoft kernel debug",
    "pseudo-interface",
)
_USB_ETHERNET_TOKENS = (
    "usb ethernet",
    "usb gigabit",
    "usb 10/100",
    "usb3",
    "asix",
    "rndis",
    "usb-to-ethernet",
    "usb to ethernet",
    "realtek usb",
)
_WIFI_TOKENS = ("wi-fi", "wifi", "wireless", "wlan", "802.11")


def _decode_scapy_field(value):
    """Normalize Scapy string/bytes fields to a stripped Python str."""
    if value is None:
        return None
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    text = str(value).strip()
    return text or None


def _iface_search_blob(iface) -> str:
    parts = [
        str(getattr(iface, "name", "") or ""),
        str(getattr(iface, "description", "") or ""),
        str(getattr(iface, "network_name", "") or ""),
        str(iface),
    ]
    return " ".join(parts).lower()


def _is_skipped_capture_iface(blob: str) -> bool:
    """True for virtual/utility adapters that never carry CDP/LLDP from a switch."""
    return any(token in blob for token in _SKIP_IFACE_TOKENS)


def _iface_kind(iface) -> str:
    """usb_ethernet | ethernet | wifi | other — used to prefer the USB dongle."""
    blob = _iface_search_blob(iface)
    is_wifi = any(token in blob for token in _WIFI_TOKENS)
    if is_wifi:
        return "wifi"
    if "usb" in blob or any(token in blob for token in _USB_ETHERNET_TOKENS):
        return "usb_ethernet"
    return "ethernet"


def select_discovery_interfaces(ifaces):
    """Pick L2 adapters for CDP/LLDP.

    Prefer USB Ethernet (the dongle just plugged into the switch), then other
    wired Ethernet, then Wi-Fi as a noisy fallback.
    """
    chosen = []
    seen = set()
    for iface in ifaces:
        if getattr(iface, "dummy", False):
            continue
        if _is_skipped_capture_iface(_iface_search_blob(iface)):
            continue
        key = (
            getattr(iface, "network_name", None)
            or getattr(iface, "name", None)
            or str(iface)
        )
        if key in seen:
            continue
        seen.add(key)
        chosen.append(iface)

    usb = [i for i in chosen if _iface_kind(i) == "usb_ethernet"]
    wired = [i for i in chosen if _iface_kind(i) == "ethernet"]
    wifi = [i for i in chosen if _iface_kind(i) == "wifi"]
    if usb:
        return usb
    if wired:
        return wired
    return wifi or chosen


def get_discovery_capture_interfaces():
    """Return interfaces to sniff for CDP/LLDP (NetworkInterface objects or names)."""
    if not _load_scapy():
        return []
    # USB Ethernet dongles often appear after the process started. Re-scan NPF.
    try:
        conf.ifaces.reload()
    except Exception:
        pass
    sources = []
    if hasattr(conf, "ifaces") and conf.ifaces:
        sources = list(conf.ifaces.values())
    if not sources:
        sources = list(get_if_list())
    chosen = select_discovery_interfaces(sources)
    if chosen:
        return chosen
    return list(get_if_list()) or [conf.iface]


def npcap_admin_only_enabled():
    """True if Npcap is restricted to Administrators (capture then needs UAC).

    Returns None if Npcap is missing or the key cannot be read.
    """
    try:
        import winreg
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Services\npcap\Parameters",
        ) as key:
            value, _ = winreg.QueryValueEx(key, "AdminOnly")
        return int(value) != 0
    except Exception:
        return None


def describe_capture_interface(iface) -> str:
    """Human-readable one-liner for the capture log."""
    if not _SCAPY_LOADED:
        _load_scapy()
    desc = (
        getattr(iface, "description", None)
        or getattr(iface, "name", None)
        or str(iface)
    )
    try:
        addr = get_if_addr(iface)
    except Exception:
        addr = None
    if not addr or addr == "0.0.0.0":
        ip_note = "no IPv4 — still capturing L2"
    elif addr.startswith("169.254."):
        ip_note = f"{addr} (link-local)"
    else:
        ip_note = addr
    return f"{desc}  [{ip_note}]"


def _raw_bytes(pkt):
    original = getattr(pkt, "original", None)
    if original:
        return original
    return bytes(pkt)


def _dst_mac(pkt):
    raw = _raw_bytes(pkt)
    if len(raw) >= 6:
        return ":".join(f"{b:02x}" for b in raw[:6])
    return None


def _payload_after_l2(pkt):
    """Return (payload_bytes, ethertype) after Ethernet and any VLAN tags."""
    raw = _raw_bytes(pkt)
    if len(raw) < 14:
        return b"", None
    ethertype = int.from_bytes(raw[12:14], "big")
    offset = 14
    while ethertype in VLAN_ETHERTYPES and offset + 4 <= len(raw):
        ethertype = int.from_bytes(raw[offset + 2:offset + 4], "big")
        offset += 4
    return raw[offset:], ethertype


def is_discovery_frame(pkt) -> bool:
    """Software filter: CDP or LLDP, including VLAN-tagged frames.

    Destination MAC is checked from raw bytes first so the hot path does not
    force a full Scapy dissection of every frame on a busy NIC.
    """
    if not _SCAPY_LOADED and not _load_scapy():
        return False
    try:
        dst = _dst_mac(pkt)
        if dst == CDP_MULTICAST or dst in LLDP_MULTICASTS:
            return True
        _payload, ethertype = _payload_after_l2(pkt)
        if ethertype in (LLDP_ETHERTYPE, CDP_ETHERTYPE):
            return True
    except Exception:
        return False
    return False


def _parse_cdp_tlvs(data: bytes):
    """Parse Device ID / Port ID from a CDP PDU (after the 4-byte CDP header)."""
    hostname = None
    port = None
    offset = 0
    while offset + 4 <= len(data):
        tlv_type = int.from_bytes(data[offset:offset + 2], "big")
        tlv_len = int.from_bytes(data[offset + 2:offset + 4], "big")
        if tlv_len < 4 or offset + tlv_len > len(data):
            break
        value = data[offset + 4:offset + tlv_len]
        if tlv_type == 0x0001:
            hostname = hostname or _decode_scapy_field(value)
        elif tlv_type == 0x0003:
            port = port or _decode_scapy_field(value)
        offset += tlv_len
    return hostname, port


def _format_lldp_id(subtype, rest: bytes, *, chassis: bool):
    """Turn an LLDP Chassis ID or Port ID TLV value into display text."""
    if not rest:
        return None
    mac_subtype = 4 if chassis else 3
    if subtype == mac_subtype and len(rest) >= 6:
        return ":".join(f"{b:02x}" for b in rest[:6])
    return _decode_scapy_field(rest)


def _parse_lldp_tlvs(data: bytes):
    """Parse system name / chassis / port from raw LLDPDU bytes."""
    hostname = None
    chassis = None
    port = None
    port_desc = None
    offset = 0
    while offset + 2 <= len(data):
        header = int.from_bytes(data[offset:offset + 2], "big")
        tlv_type = header >> 9
        tlv_len = header & 0x1FF
        if tlv_type == 0:
            break
        if offset + 2 + tlv_len > len(data):
            break
        value = data[offset + 2:offset + 2 + tlv_len]
        if tlv_type == 1 and value:
            chassis = chassis or _format_lldp_id(value[0], value[1:], chassis=True)
        elif tlv_type == 2 and value:
            port = port or _format_lldp_id(value[0], value[1:], chassis=False)
        elif tlv_type == 4:
            port_desc = port_desc or _decode_scapy_field(value)
        elif tlv_type == 5:
            hostname = hostname or _decode_scapy_field(value)
        offset += 2 + tlv_len
    return hostname or chassis, port or port_desc


def _cdp_payload_bytes(l2_payload: bytes, ethertype):
    """Locate the CDP header inside Ethernet II or 802.3 SNAP frames."""
    if ethertype == CDP_ETHERTYPE:
        return l2_payload
    if len(l2_payload) >= 8 and l2_payload[0:3] == b"\xaa\xaa\x03":
        oui = l2_payload[3:6]
        proto = l2_payload[6:8]
        if oui == b"\x00\x00\x0c" and proto == b"\x20\x00":
            return l2_payload[8:]
    if len(l2_payload) >= 4 and l2_payload[0] in (1, 2):
        return l2_payload
    return None


def _extract_cdp(pkt):
    hostname = None
    port = None
    try:
        if CDPMsgDeviceID in pkt:
            hostname = _decode_scapy_field(pkt[CDPMsgDeviceID].val)
        if CDPMsgPortID in pkt:
            port_layer = pkt[CDPMsgPortID]
            port = _decode_scapy_field(
                getattr(port_layer, "iface", None) or getattr(port_layer, "val", None)
            )
    except Exception:
        pass
    if hostname and port:
        return hostname, port
    payload, ethertype = _payload_after_l2(pkt)
    cdp = _cdp_payload_bytes(payload, ethertype)
    if cdp and len(cdp) >= 4:
        raw_host, raw_port = _parse_cdp_tlvs(cdp[4:])
        hostname = hostname or raw_host
        port = port or raw_port
    return hostname, port


def _extract_lldp(pkt):
    hostname = None
    port = None
    try:
        if LLDPDUSystemName in pkt:
            hostname = _decode_scapy_field(pkt[LLDPDUSystemName].system_name)
        if not hostname and LLDPDUChassisID in pkt:
            chassis = pkt[LLDPDUChassisID]
            # Chassis ID subtype 4 is MAC; 3 is "port component". Always usable.
            hostname = _decode_scapy_field(getattr(chassis, "id", None))
        if LLDPDUPortID in pkt:
            port = _decode_scapy_field(getattr(pkt[LLDPDUPortID], "id", None))
        if not port and LLDPDUPortDescription in pkt:
            port = _decode_scapy_field(
                getattr(pkt[LLDPDUPortDescription], "description", None)
            )
    except Exception:
        pass
    if hostname and port:
        return hostname, port
    payload, ethertype = _payload_after_l2(pkt)
    if ethertype == LLDP_ETHERTYPE or _dst_mac(pkt) in LLDP_MULTICASTS:
        raw_host, raw_port = _parse_lldp_tlvs(payload)
        hostname = hostname or raw_host
        port = port or raw_port
    return hostname, port


def extract_neighbor_from_packet(pkt):
    """Extract hostname + reported port from a CDP or LLDP packet.

    Returns a dict ready for the GUI queue, {"error": ...} on exception, or
    None if the frame is not a neighbor advertisement.
    Missing TLVs no longer drop the whole packet — unknown is shown instead.
    """
    if not _SCAPY_LOADED and not _load_scapy():
        return {"error": SCAPY_ERROR or "scapy is not available"}
    try:
        dst = _dst_mac(pkt)
        payload, ethertype = _payload_after_l2(pkt)
        looks_cdp = (
            dst == CDP_MULTICAST
            or ethertype == CDP_ETHERTYPE
            or (SNAP in pkt and getattr(pkt[SNAP], "code", None) == CDP_ETHERTYPE)
            or CDPv2_HDR in pkt
            or CDPMsgDeviceID in pkt
        )
        looks_lldp = (
            dst in LLDP_MULTICASTS
            or ethertype == LLDP_ETHERTYPE
            or LLDPDUChassisID in pkt
            or LLDPDUSystemName in pkt
        )

        if looks_cdp:
            hostname, port = _extract_cdp(pkt)
            if hostname or port:
                return {
                    "hostname": hostname or "unknown",
                    "port": port or "unknown",
                    "protocol": "CDP",
                }

        if looks_lldp:
            hostname, port = _extract_lldp(pkt)
            if hostname or port:
                return {
                    "hostname": hostname or "unknown",
                    "port": port or "unknown",
                    "protocol": "LLDP",
                }

        if looks_cdp:
            return {"hostname": "unknown", "port": "unknown", "protocol": "CDP"}
        if looks_lldp:
            return {"hostname": "unknown", "port": "unknown", "protocol": "LLDP"}
    except Exception as e:
        return {"error": str(e)}

    return None


def _open_l2_listen_socket(iface):
    """Open a Windows/Npcap L2 listen handle on one adapter.

    L2pcapListenSocket does not accept `nofilter` (that kwarg belongs to the
    send/recv L2pcapSocket). Omitting `filter` already skips kernel BPF, which
    is required so VLAN-tagged LLDP is not dropped.
    Promiscuous is preferred for CDP/LLDP multicast; some NICs refuse it, so
    we retry without if the first open fails.
    """
    resolved = resolve_iface(iface)
    sock_cls = resolved.l2listen()
    last_err = None
    for promisc in (True, False):
        try:
            return sock_cls(iface=resolved, type=ETH_P_ALL, promisc=promisc)
        except Exception as e:
            last_err = e
    raise last_err


def create_discovery_sniffer(prn_callback):
    """Build an AsyncSniffer on every usable L2 NIC.

    Opens each adapter on its own so a single bad NPF device does not abort
    capture. No kernel BPF — software-filter CDP/LLDP (VLAN-safe).

    Returns (sniffer, listening_ifaces, skipped_messages).
    """
    if npcap_would_prompt_uac():
        raise RuntimeError(
            "Npcap is still in Admin-only mode. Starting capture would pop a UAC "
            "prompt (NpcapHelper.exe) for each network adapter.\n\n"
            "Run allow_npcap_nonadmin.bat once (approve that single prompt), then "
            "start netDiag normally.\n"
            "Capture capability is unchanged — this only stops Npcap from demanding "
            "Administrator on every listen."
        )
    if not _load_scapy():
        raise RuntimeError(f"Scapy is not available: {SCAPY_ERROR or 'unknown import error'}")

    load_contrib("cdp")
    load_contrib("lldp")

    if hasattr(conf, "contribs") and "LLDP" in conf.contribs:
        conf.contribs["LLDP"].strict_mode_disable()

    ifaces = get_discovery_capture_interfaces()
    sockets = []
    listening = []
    skipped = []

    for iface in ifaces:
        label = describe_capture_interface(iface)
        try:
            sockets.append(_open_l2_listen_socket(iface))
            listening.append(iface)
        except Exception as e:
            skipped.append(f"{label}: {e}")

    if not sockets:
        detail = "\n".join(skipped) if skipped else "no capture adapters found"
        raise RuntimeError(f"Could not open any capture interface:\n{detail}")

    sniffer = AsyncSniffer(
        opened_socket=sockets,
        prn=prn_callback,
        lfilter=is_discovery_frame,
        store=False,
    )
    return sniffer, listening, skipped


# ====================== SERIAL CONNECTION ORCHESTRATION ======================

def start_serial_session(
    port,
    username,
    password,
    on_success,
    on_log,
    on_failure,
    hostname_hint=None,
    login_mode=None,
):
    """Background worker extracted from the old GUI login flow.
    Calls the provided callbacks so the GUI can react without owning the logic.
    Only the active customer's secrets are used.
    """
    def worker():
        if not is_local_com_port(port):
            on_failure(f"non-local serial target {port!r}")
            return
        session = SerialSession(port)
        try:
            session.open()
            on_log(f"[SERIAL] Opened {port}")
            mode = (login_mode or get_login_mode() or "auto").strip().lower()
            on_log(
                f"[SERIAL] Customer {get_active_customer_name()!r} "
                f"({mode} login)"
            )
            if hostname_hint:
                on_log(f"[SERIAL] Hostname: {hostname_hint}")

            if mode == "skip":
                session.attach_console()
                on_success(session, port)
                return

            success = session.login(
                username,
                password,
                hostname_hint=hostname_hint,
                login_mode=mode,
            )
            if success:
                on_success(session, port)
            else:
                on_log(
                    f"[SERIAL] Login failed on {port} — "
                    "opening the terminal anyway so you can type."
                )
                session.attach_console()
                on_success(session, port)
        except Exception as e:
            try:
                session.close()
            except Exception:
                pass
            on_log(f"[SERIAL ERROR] {e}")
            on_failure(str(e))

    threading.Thread(target=worker, daemon=True).start()

# ====================== ENTRY POINT ======================

def main():
    """Primary entry point. Starts the netDiag GUI application."""
    _reexec_local_venv()
    ensure_desktop_shortcut()
    root = tk.Tk()
    app = CDP_LLDP_GUI(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()


# ====================== GUI (Tkinter presentation) ======================

class SerialWindow:
    """Serial sub-window structured directly from the menu map (netDiag_Menu_Map.txt).
    Sections follow the exact hierarchy under "Serial":
      - Show transceiver details
      - Show cdp & lldp neighbors
      - Mac address table (with Grab old / Grab new / Compare nested)
      - Open terminal > Cli terminal  (launches dedicated manual sub-window)
    Live output area is shared. Real command logic comes later.
    """

    def __init__(self, master, session: "SerialSession", port_name: str):
        self.master = master
        self.session = session
        self.port_name = port_name
        self.window = tk.Toplevel(master)
        self.window.title(f"Serial Console - {port_name}")
        self.window.geometry("950x680")
        self.window.minsize(780, 520)

        self.poll_after_id = None
        self.mac_tree = None  # placeholder for Mac address table results (structure only)

        self.setup_ui()

        # Start polling the session's read queue
        self.poll_serial_output()

        # Auto-disable paging and show we're live
        self.window.after(600, self._init_session)

    def _init_session(self):
        if not getattr(self.session, "auto_login", True):
            return
        if not self.session.connected:
            return
        self.session.send_line("terminal length 0")
        self.window.after(400, lambda: self.session.send_line(""))

    def setup_ui(self):
        """Build UI sections that follow the exact structure in netDiag_Menu_Map.txt under Serial.
        This is layout/structure only — buttons are wired to either working senders (where logic already
        existed) or stub methods. The nested Mac address table gets its own button row + results treeview.
        """
        content = ttk.Frame(self.window, padding=8)
        content.pack(fill=tk.BOTH, expand=True)

        # Header
        header = ttk.Frame(content)
        header.pack(fill=tk.X, pady=(0, 6))
        self.header_var = tk.StringVar()
        self._refresh_header()
        ttk.Label(
            header,
            textvariable=self.header_var,
            font=("Segoe UI", 11, "bold")
        ).pack(side=tk.LEFT)

        # ========== Serial menu map sections (order + nesting from the map) ==========

        # Show transceiver details
        tx_frame = ttk.LabelFrame(content, text="Show transceiver details", padding=6)
        tx_frame.pack(fill=tk.X, pady=3)
        ttk.Button(tx_frame, text="Show Transceiver Details (dBm)",
                   command=self.run_transceivers, width=34).pack(anchor=tk.W)
        ttk.Label(tx_frame, text="sends: show interfaces transceiver  +  show interfaces transceiver detail   → Live Output",
                  foreground="#555", font=("Segoe UI", 9)).pack(anchor=tk.W, pady=(3, 0))

        # Show cdp & lldp neighbors
        nei_frame = ttk.LabelFrame(content, text="Show cdp & lldp neighbors", padding=6)
        nei_frame.pack(fill=tk.X, pady=3)
        ttk.Button(nei_frame, text="Show CDP & LLDP Neighbors",
                   command=self.run_neighbors, width=34).pack(anchor=tk.W)
        ttk.Label(nei_frame, text="sends: show cdp neighbors  +  show lldp neighbors   → Live Output",
                  foreground="#555", font=("Segoe UI", 9)).pack(anchor=tk.W, pady=(3, 0))

        # Mac address table  (nested sub-items per map)
        mac_frame = ttk.LabelFrame(content, text="Mac address table", padding=6)
        mac_frame.pack(fill=tk.X, pady=3)

        mac_btns = ttk.Frame(mac_frame)
        mac_btns.pack(fill=tk.X)
        ttk.Button(mac_btns, text="Grab old table", command=self.grab_old_mac, width=18).pack(side=tk.LEFT, padx=2)
        ttk.Button(mac_btns, text="Grab new table", command=self.grab_new_mac, width=18).pack(side=tk.LEFT, padx=2)
        ttk.Button(mac_btns, text="Compare tables", command=self.compare_mac, width=18).pack(side=tk.LEFT, padx=2)

        ttk.Label(mac_frame, text="MAC table results (populated by Grab Old / Grab New):",
                  foreground="#555", font=("Segoe UI", 9)).pack(anchor=tk.W, pady=(6, 2))

        mac_cols = ("vlan", "mac", "type", "port", "age")
        self.mac_tree = ttk.Treeview(mac_frame, columns=mac_cols, show="headings", height=5)
        for col, head in zip(mac_cols, ["VLAN", "MAC Address", "Type", "Port", "Age"]):
            self.mac_tree.heading(col, text=head)
            self.mac_tree.column(col, width=85, anchor=tk.CENTER)
        self.mac_tree.pack(fill=tk.X)

        # Open terminal  (with Cli terminal sub per map)
        term_frame = ttk.LabelFrame(content, text="Open terminal", padding=6)
        term_frame.pack(fill=tk.X, pady=3)
        ttk.Button(term_frame, text="Cli terminal  —  Open dedicated manual commands window",
                   command=self.open_manual_terminal_window, width=48).pack(anchor=tk.W)
        ttk.Label(term_frame, text="Launches the dedicated CLI terminal (shares the live feed from the SerialSession).",
                  foreground="#555", font=("Segoe UI", 9)).pack(anchor=tk.W, pady=(3, 0))

        # Shared live output console (receives everything)
        ttk.Label(content, text="Live Serial Console Output (shared by all sections above + manual terminal):").pack(anchor=tk.W, pady=(8, 2))
        self.output = scrolledtext.ScrolledText(
            content, wrap=tk.WORD, font=("Consolas", 10), state=tk.DISABLED, height=14
        )
        self.output.pack(fill=tk.BOTH, expand=True, pady=(2, 6))

        cmd_frame = ttk.Frame(content)
        cmd_frame.pack(fill=tk.X, pady=(0, 6))
        ttk.Label(cmd_frame, text="Send:").pack(side=tk.LEFT)
        self.cmd_entry = ttk.Entry(cmd_frame)
        self.cmd_entry.pack(side=tk.LEFT, padx=6, fill=tk.X, expand=True)
        self.cmd_entry.bind("<Return>", lambda e: self.send_command())
        ttk.Button(cmd_frame, text="Send", command=self.send_command, width=10).pack(
            side=tk.LEFT
        )

        bottom = ttk.Frame(content)
        bottom.pack(fill=tk.X)

        self.status_var = tk.StringVar(value="Ready — type in Send or open Cli terminal.")
        ttk.Label(bottom, textvariable=self.status_var, foreground="#333").pack(side=tk.LEFT)

        ttk.Button(bottom, text="Disconnect", command=self.disconnect).pack(side=tk.RIGHT)

    # ============== Delegated to logic (individual functions) ==============

    def run_show_version(self):
        execute_show_version(self.session)

    def run_show_inventory(self):
        execute_show_inventory(self.session)

    def run_show_environment(self):
        execute_show_environment(self.session)

    def run_show_interfaces(self):
        execute_show_interfaces(self.session)

    def _run_serial_job(self, fn):
        """Run a blocking serial job off the Tk thread so the live console can still paint."""
        def work():
            try:
                fn()
            except Exception as exc:
                err = str(exc)
                self.window.after(0, lambda m=err: self.append_output(f"[SERIAL] {m}"))
        threading.Thread(target=work, daemon=True).start()

    def run_neighbors(self):
        """Matches menu map item 'Show cdp & lldp neighbors'."""
        self._run_serial_job(lambda: execute_show_neighbors(self.session))

    def run_transceivers(self):
        """Matches menu map item 'Show transceiver details'."""
        self._run_serial_job(lambda: execute_transceiver_details(self.session))

    def run_show_running_config(self):
        if not messagebox.askyesno("Warning", "show running-config can be very long. Continue?"):
            return
        execute_show_running_config(self.session)

    def run_show_users(self):
        execute_show_users(self.session)

    def run_terminal_length(self):
        execute_terminal_length_zero(self.session)

    # --- Mac address table (menu map) - delegates to real logic ---
    def grab_old_mac(self):
        self.status_var.set("Collecting old MAC table...")
        self._grab_mac_async("old", grab_old_mac_table)

    def grab_new_mac(self):
        self.status_var.set("Collecting new MAC table...")
        self._grab_mac_async("new", grab_new_mac_table)

    def _grab_mac_async(self, label, grab_fn):
        def work():
            try:
                parsed = grab_fn(self.session)
                err = None
            except Exception as exc:
                parsed, err = {}, exc
            def done():
                if err:
                    self.append_output(f"[MAC] {err}")
                else:
                    self._populate_mac_tree(parsed)
                    self.append_output(
                        f"[MAC] {label.capitalize()} table collected: {len(parsed)} entries"
                    )
                self.status_var.set("Ready")
            try:
                self.window.after(0, done)
            except Exception:
                pass
        threading.Thread(target=work, daemon=True).start()

    def compare_mac(self):
        self.status_var.set("Comparing tables...")
        reports = compare_mac_tables()
        gone = [r for r in reports if " was on " in r and " moved from " not in r]
        moved = [r for r in reports if " moved from " in r]
        if gone:
            self.append_output("[MAC Compare] Gone (in old, not in new):")
            for line in gone:
                self.append_output(f"  {line}")
        if moved:
            self.append_output("[MAC Compare] Moved port:")
            for line in moved:
                self.append_output(f"  {line}")
        if not reports:
            self.append_output("[MAC Compare] No missing or moved MACs.")
        self.window.after(600, lambda: self.status_var.set("Ready"))

    def _populate_mac_tree(self, data: dict):
        """Populate the MAC results treeview from a parsed {normalized_mac: port} dict."""
        if not hasattr(self, "mac_tree") or self.mac_tree is None:
            return
        try:
            self.mac_tree.delete(*self.mac_tree.get_children())
            for mac, port in sorted(data.items()):
                # Pretty display for the 12-hex mac
                if len(mac) == 12:
                    pretty = f"{mac[0:4]}.{mac[4:8]}.{mac[8:12]}"
                else:
                    pretty = mac
                # Use available columns: vlan, mac, type, port, age
                self.mac_tree.insert("", "end", values=("", pretty, "DYNAMIC", port, ""))
        except Exception as e:
            self.append_output(f"[MAC tree error] {e}")

    def send_command(self):
        """Send whatever is in the bar, including a bare Enter (Press RETURN)."""
        cmd = self.cmd_entry.get()
        self.session.send_line(cmd)
        self.cmd_entry.delete(0, tk.END)

    def open_manual_terminal_window(self):
        """Opens the dedicated sub-sub window for manual commands (fulfills 'Open terminal / Cli terminal')."""
        ManualTerminalWindow(self.window, self.session, self.port_name)

    # ============== Output + polling ==============

    def append_output(self, text):
        if not text:
            return
        self.output.config(state=tk.NORMAL)
        self.output.insert(tk.END, text + "\n")
        self.output.see(tk.END)
        self.output.config(state=tk.DISABLED)

    def _refresh_header(self):
        host = getattr(self.session, "hostname", None) or "hostname unknown"
        user = getattr(self.session, "login_user", None) or get_credentials()[0]
        customer = get_active_customer_name()
        self.header_var.set(
            f"{self.port_name}  |  {customer}  |  {host}  |  {user}"
        )

    def poll_serial_output(self):
        """Pull lines from the SerialSession read_queue and display them."""
        try:
            while True:
                line = self.session.read_queue.get_nowait()
                self.append_output(line)
        except queue.Empty:
            pass
        self._refresh_header()

        self.poll_after_id = self.window.after(120, self.poll_serial_output)

    def disconnect(self):
        try:
            self.session.close()
        except Exception:
            pass
        if self.poll_after_id:
            self.window.after_cancel(self.poll_after_id)
        self.window.destroy()
        messagebox.showinfo("Serial", "Serial connection closed.")


class ManualTerminalWindow:
    """Dedicated CLI terminal sub-window (the "Cli terminal" under Serial > Open terminal per the menu map).
    Shares the SerialSession and its read_queue so output appears live here *and* in the parent SerialWindow.
    """

    def __init__(self, master, session: "SerialSession", port_name: str):
        self.master = master
        self.session = session
        self.port_name = port_name
        self.window = tk.Toplevel(master)
        self.window.title(f"Manual Terminal - {port_name}")
        self.window.geometry("850x480")
        self.window.minsize(650, 350)

        self.poll_after_id = None
        self.output_q = session.subscribe()

        self.setup_ui()
        self.poll_serial_output()
        self.window.protocol("WM_DELETE_WINDOW", self.close_window)

    def setup_ui(self):
        content = ttk.Frame(self.window, padding=8)
        content.pack(fill=tk.BOTH, expand=True)

        ttk.Label(
            content,
            text=f"Cli terminal — Manual Commands - {self.port_name} (live output, shares session with parent Serial window)",
            font=("Segoe UI", 10, "bold")
        ).pack(anchor=tk.W, pady=(0, 4))

        # Output
        self.output = scrolledtext.ScrolledText(
            content, wrap=tk.WORD, font=("Consolas", 10), state=tk.DISABLED, height=18
        )
        self.output.pack(fill=tk.BOTH, expand=True)

        # Manual input
        cmd_frame = ttk.Frame(content)
        cmd_frame.pack(fill=tk.X, pady=(6, 0))

        ttk.Label(cmd_frame, text="Command:").pack(side=tk.LEFT)
        self.cmd_entry = ttk.Entry(cmd_frame, width=70)
        self.cmd_entry.pack(side=tk.LEFT, padx=6, fill=tk.X, expand=True)
        self.cmd_entry.bind("<Return>", lambda e: self.send_command())

        ttk.Button(cmd_frame, text="Send", command=self.send_command).pack(side=tk.LEFT, padx=4)
        ttk.Button(cmd_frame, text="Clear Output", command=self.clear_output).pack(side=tk.LEFT, padx=4)
        ttk.Button(cmd_frame, text="Close Window", command=self.close_window).pack(side=tk.RIGHT)
        self.cmd_entry.focus_set()

        self.status_var = tk.StringVar(value="Type commands above. Output appears here and in the Auto Commands window.")
        ttk.Label(content, textvariable=self.status_var, foreground="#555").pack(anchor=tk.W, pady=(4, 0))

        # Seed with current time
        self.append_output("=== Manual terminal ready. Commands sent here will execute on the device. ===")

    def append_output(self, text):
        if not text:
            return
        self.output.config(state=tk.NORMAL)
        self.output.insert(tk.END, text + "\n")
        self.output.see(tk.END)
        self.output.config(state=tk.DISABLED)

    def poll_serial_output(self):
        try:
            while True:
                line = self.output_q.get_nowait()
                self.append_output(line)
        except queue.Empty:
            pass

        self.poll_after_id = self.window.after(120, self.poll_serial_output)

    def send_command(self):
        cmd = self.cmd_entry.get()
        self.status_var.set("Sent" if cmd.strip() else "Sent Enter")
        self.session.send_line(cmd)
        self.cmd_entry.delete(0, tk.END)
        self.window.after(300, lambda: self.status_var.set("Type commands above..."))

    def clear_output(self):
        self.output.config(state=tk.NORMAL)
        self.output.delete("1.0", tk.END)
        self.output.config(state=tk.DISABLED)

    def close_window(self):
        if self.poll_after_id:
            self.window.after_cancel(self.poll_after_id)
        try:
            self.session.unsubscribe(self.output_q)
        except Exception:
            pass
        self.window.destroy()


class CDP_LLDP_GUI:
    def __init__(self, root):
        self.root = root
        self.root.title("netDiag - CDP/LLDP Listener + Serial Console")
        self.root.geometry("920x620")
        self.root.minsize(720, 480)

        # Thread-safe queues
        self.queue = queue.Queue()
        self.stop_event = threading.Event()
        self.sniffer = None
        self.is_listening = False
        self.neighbors = {}
        self.discovery_frames = 0
        self.last_capture_info = None

        # Serial session / window (if active)
        self.current_serial = None
        self.serial_window = None

        self.setup_ui()
        self.process_queue()

        if not SCAPY_AVAILABLE:
            self.show_error_dialog(
                "Scapy Missing",
                f"Scapy import failed: {SCAPY_ERROR}\n\n"
                "Install with: pip install scapy"
            )
        elif npcap_would_prompt_uac():
            self.status_var.set("Npcap Admin-only is ON — run allow_npcap_nonadmin.bat once")

    def setup_ui(self):
        # === Menu bar directly structured from netDiag_Menu_Map.txt ===
        menubar = tk.Menu(self.root)

        # Serial (top level per map)
        serial_menu = tk.Menu(menubar, tearoff=0)
        serial_menu.add_command(label="Show transceiver details", command=self.menu_serial_transceiver)
        serial_menu.add_command(label="Show cdp & lldp neighbors", command=self.menu_serial_neighbors)

        # Mac address table (nested submenu per map)
        mac_menu = tk.Menu(serial_menu, tearoff=0)
        mac_menu.add_command(label="Grab old table", command=self.menu_grab_old_mac)
        mac_menu.add_command(label="Grab new table", command=self.menu_grab_new_mac)
        mac_menu.add_command(label="Compare tables", command=self.menu_compare_mac)
        serial_menu.add_cascade(label="Mac address table", menu=mac_menu)

        serial_menu.add_separator()
        serial_menu.add_command(label="Open terminal > Cli terminal", command=self.open_serial_cli_terminal)
        menubar.add_cascade(label="Serial", menu=serial_menu)

        # cdp & lldp search (top level per map) - hostname and port inf is the main table content
        cdp_menu = tk.Menu(menubar, tearoff=0)
        cdp_menu.add_command(label="Start CDP/LLDP Listening", command=self.start_listening)
        cdp_menu.add_command(label="Stop CDP/LLDP Listening", command=self.stop_listening)
        cdp_menu.add_command(label="Clear Neighbors", command=self.clear_list)
        cdp_menu.add_command(label="Open Log Window", command=self.open_log_window)
        cdp_menu.add_separator()
        cdp_menu.add_command(label="hostname and port inf (main view)", command=self.focus_hostname_port_view)
        menubar.add_cascade(label="cdp & lldp search", menu=cdp_menu)

        settings_menu = tk.Menu(menubar, tearoff=0)
        settings_menu.add_command(
            label="Usernames & Passwords...",
            command=self.open_serial_credentials_dialog,
        )
        menubar.add_cascade(label="Settings", menu=settings_menu)

        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="Menu Map (netDiag_Menu_Map.txt)", command=self.show_menu_map_info)
        menubar.add_cascade(label="Help", menu=help_menu)

        self.root.config(menu=menubar)

        main_frame = ttk.Frame(self.root, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Header
        header = ttk.Frame(main_frame)
        header.pack(fill=tk.X, pady=(0, 8))

        title_font = tkfont.Font(size=16, weight="bold")
        ttk.Label(header, text="netDiag — Main window", font=title_font).pack(side=tk.LEFT)
        self.customer_var = tk.StringVar()
        ttk.Label(header, textvariable=self.customer_var, foreground="#555").pack(
            side=tk.LEFT, padx=12
        )
        self._refresh_customer_label()

        self.status_var = tk.StringVar(value="Stopped")
        ttk.Label(header, textvariable=self.status_var, foreground="red").pack(side=tk.RIGHT, padx=10)

        # Control bar
        control_frame = ttk.Frame(main_frame)
        control_frame.pack(fill=tk.X, pady=5)

        self.start_btn = ttk.Button(control_frame, text="▶ Start CDP/LLDP", command=self.start_listening)
        self.start_btn.pack(side=tk.LEFT, padx=4)

        self.stop_btn = ttk.Button(control_frame, text="⏹ Stop CDP/LLDP", command=self.stop_listening, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=4)

        ttk.Button(control_frame, text="Clear Neighbors", command=self.clear_list).pack(side=tk.LEFT, padx=4)

        # === The requested sub-window button for CDP/LLDP log ===
        ttk.Button(control_frame, text="Open Log Window", command=self.open_log_window).pack(side=tk.LEFT, padx=12)

        # === Serial button (per map) ===
        serial_btn = ttk.Button(control_frame, text="Serial", command=self.open_serial_connection, width=10)
        serial_btn.pack(side=tk.LEFT, padx=8)

        # CDP & LLDP Search table — "hostname and port inf" (main content per map)
        search_frame = ttk.LabelFrame(main_frame, text="cdp & lldp search — hostname and port inf", padding=6)
        search_frame.pack(fill=tk.BOTH, expand=True, pady=8)

        columns = ("hostname", "port", "protocol", "last_seen")
        self.tree = ttk.Treeview(search_frame, columns=columns, show="headings", height=16)

        self.tree.heading("hostname", text="Hostname / Device ID")
        self.tree.heading("port", text="Port / Interface (reported)")
        self.tree.heading("protocol", text="Protocol")
        self.tree.heading("last_seen", text="Last Seen")

        self.tree.column("hostname", width=280)
        self.tree.column("port", width=240)
        self.tree.column("protocol", width=80, anchor=tk.CENTER)
        self.tree.column("last_seen", width=150, anchor=tk.CENTER)

        vsb = ttk.Scrollbar(search_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)

        self.tree.bind("<Double-1>", self.on_tree_double_click)

        # Status bar
        info = ttk.Frame(main_frame)
        info.pack(fill=tk.X)
        self.count_var = tk.StringVar(value="Unique neighbors: 0  |  CDP/LLDP frames: 0")
        ttk.Label(info, textvariable=self.count_var).pack(side=tk.LEFT)
        if npcap_would_prompt_uac():
            hint = "Npcap Admin-only ON — run allow_npcap_nonadmin.bat once (NpcapHelper UAC otherwise)"
        else:
            hint = "CDP/LLDP uses Npcap  |  Serial uses pyserial"
        ttk.Label(info, text=hint, foreground="#666").pack(side=tk.RIGHT)

    # ================= CDP/LLDP methods (mostly unchanged) =================

    def packet_callback(self, pkt):
        """Thin GUI callback. All actual CDP/LLDP parsing logic is now in extract_neighbor_from_packet."""
        if self.stop_event.is_set():
            return
        self.queue.put({"type": "discovery_frame"})
        result = extract_neighbor_from_packet(pkt)
        if result is None:
            summary = "?"
            try:
                summary = pkt.summary()
            except Exception:
                pass
            self.queue.put({
                "type": "log",
                "message": f"[CDP/LLDP] captured a discovery-like frame but could not parse it: {summary}",
            })
            return
        if "error" in result:
            self.queue.put({"type": "log", "message": f"[PARSE ERROR] {result['error']}"})
            return
        ts = datetime.now().strftime("%H:%M:%S")
        self.queue.put({
            "type": "neighbor",
            "hostname": result["hostname"],
            "port": result["port"],
            "protocol": result["protocol"],
            "timestamp": ts
        })

    def start_listening(self):
        if not SCAPY_AVAILABLE:
            self.show_error_dialog("Scapy Missing", "Please install scapy first.")
            return
        if self.is_listening:
            return

        self.stop_event.clear()
        self.is_listening = True
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.status_var.set("Listening for CDP/LLDP...")

        try:
            self.sniffer, ifaces, skipped = create_discovery_sniffer(
                prn_callback=self.packet_callback
            )
            self.sniffer.start()
            iface_lines = [f"  - {describe_capture_interface(iface)}" for iface in ifaces]
            message = (
                "[INFO] Started CDP/LLDP capture (all usable L2 adapters, no kernel BPF).\n"
                "Listening on:\n" + "\n".join(iface_lines)
            )
            if skipped:
                message += "\nSkipped (could not open):\n" + "\n".join(
                    f"  - {item}" for item in skipped
                )
            self.last_capture_info = message
            self.status_var.set(f"Listening on {len(ifaces)} adapter(s)")
            self.queue.put({"type": "log", "message": message})
        except Exception as e:
            self._stop_cdp_lldp()
            msg = str(e)
            if "admin" in msg.lower() or "pcap" in msg.lower() or "npcap" in msg.lower():
                admin_only = npcap_admin_only_enabled()
                if admin_only:
                    msg += (
                        "\n\nNpcap is in Admin-only mode, which is why capture wants elevation.\n"
                        "Run allow_npcap_nonadmin.bat once (UAC that one time), then start "
                        "netDiag normally. Capture capability is unchanged.\n"
                        "Fallback: right-click run_netdiag.bat → Run as administrator."
                    )
                else:
                    msg += (
                        "\n\nInstall Npcap from https://npcap.com with "
                        "\"WinPcap API-compatible Mode\" enabled and "
                        "\"Restrict Npcap driver's access to Administrators only\" unchecked.\n"
                        "If capture still fails, run allow_npcap_nonadmin.bat once, or "
                        "right-click run_netdiag.bat → Run as administrator."
                    )
            self.show_error_dialog("Capture Failed", msg)

    def stop_listening(self):
        self._stop_cdp_lldp()

    def _stop_cdp_lldp(self):
        self.stop_event.set()
        self.is_listening = False
        if self.sniffer:
            try:
                self.sniffer.stop()
            except Exception:
                pass
            self.sniffer = None
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.status_var.set("Stopped")

    def clear_list(self):
        self.neighbors.clear()
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.discovery_frames = 0
        self.count_var.set("Unique neighbors: 0  |  CDP/LLDP frames: 0")

    def refresh_treeview(self):
        for item in self.tree.get_children():
            self.tree.delete(item)

        for (hostname, port, proto), ts in sorted(self.neighbors.items(), key=lambda x: x[1], reverse=True):
            self.tree.insert("", tk.END, values=(hostname, port, proto, ts))
        self.count_var.set(
            f"Unique neighbors: {len(self.neighbors)}  |  CDP/LLDP frames: {self.discovery_frames}"
        )

    def open_log_window(self):
        """CDP/LLDP sub window (user is happy with this one)."""
        if hasattr(self, "log_window") and self.log_window.winfo_exists():
            self.log_window.lift()
            return

        self.log_window = tk.Toplevel(self.root)
        self.log_window.title("CDP/LLDP Capture Log")
        self.log_window.geometry("720x380")

        frame = ttk.Frame(self.log_window, padding=8)
        frame.pack(fill=tk.BOTH, expand=True)

        self.log_text = scrolledtext.ScrolledText(frame, wrap=tk.WORD, font=("Consolas", 10), state=tk.DISABLED)
        self.log_text.pack(fill=tk.BOTH, expand=True)

        btns = ttk.Frame(frame)
        btns.pack(fill=tk.X, pady=6)
        ttk.Button(btns, text="Clear Log", command=self.clear_log).pack(side=tk.LEFT)
        ttk.Button(btns, text="Close", command=self.log_window.destroy).pack(side=tk.RIGHT)

        self.append_log("=== CDP/LLDP capture log started ===")
        if self.last_capture_info:
            self.append_log(self.last_capture_info)

    def append_log(self, text):
        if not hasattr(self, "log_text") or not self.log_text:
            return
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, text + "\n")
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)

    def clear_log(self):
        if hasattr(self, "log_text"):
            self.log_text.config(state=tk.NORMAL)
            self.log_text.delete("1.0", tk.END)
            self.log_text.config(state=tk.DISABLED)

    def on_tree_double_click(self, event):
        sel = self.tree.selection()
        if not sel:
            return
        vals = self.tree.item(sel[0], "values")
        win = tk.Toplevel(self.root)
        win.title("Neighbor Details")
        win.geometry("420x180")
        for i, (label, val) in enumerate(zip(["Hostname", "Port", "Protocol", "Last Seen"], vals)):
            ttk.Label(win, text=label + ":", font=("Segoe UI", 10, "bold")).grid(row=i, column=0, sticky=tk.W, padx=12, pady=4)
            ttk.Label(win, text=val).grid(row=i, column=1, sticky=tk.W, padx=8)

        ttk.Button(win, text="Close", command=win.destroy).grid(row=5, column=0, columnspan=2, pady=12)

    # ==================== NEW SERIAL FUNCTIONALITY ====================

    def _refresh_customer_label(self):
        if not hasattr(self, "customer_var"):
            return
        name = get_active_customer_name()
        mode = get_login_mode()
        self.customer_var.set(f"Customer: {name}  |  login: {mode}")

    def open_serial_credentials_dialog(self):
        """Settings > Usernames & Passwords — one customer per site, secrets stay segregated."""
        dlg = tk.Toplevel(self.root)
        dlg.title("Usernames & Passwords")
        dlg.geometry("760x560")
        dlg.minsize(680, 500)
        dlg.transient(self.root)
        dlg.grab_set()

        frame = ttk.Frame(dlg, padding=12)
        frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(
            frame,
            text=(
                "Edit and save the username and password for each customer. "
                "Close or Save writes them to this Windows user's secret store. "
                "Auto-try uses these secrets; Skip login opens the serial terminal "
                "without typing them."
            ),
            wraplength=720,
        ).pack(anchor=tk.W, pady=(0, 8))

        mode_frame = ttk.Frame(frame)
        mode_frame.pack(fill=tk.X, pady=(0, 8))
        mode_var = tk.StringVar(value=get_login_mode())
        ttk.Label(mode_frame, text="Login method:").pack(side=tk.LEFT)
        ttk.Radiobutton(
            mode_frame, text="Auto-try this customer", variable=mode_var, value="auto"
        ).pack(side=tk.LEFT, padx=8)
        ttk.Radiobutton(
            mode_frame, text="Manual host selection", variable=mode_var, value="manual"
        ).pack(side=tk.LEFT, padx=8)
        ttk.Radiobutton(
            mode_frame, text="Skip login — open terminal", variable=mode_var, value="skip"
        ).pack(side=tk.LEFT, padx=8)

        body = ttk.Frame(frame)
        body.pack(fill=tk.BOTH, expand=True)
        body.columnconfigure(1, weight=1)
        body.rowconfigure(0, weight=1)

        left = ttk.LabelFrame(body, text="Customers", padding=6)
        left.grid(row=0, column=0, sticky=tk.NSEW, padx=(0, 8))
        cust_list = tk.Listbox(left, height=14, exportselection=False, width=22)
        cust_list.pack(fill=tk.BOTH, expand=True)

        new_name_var = tk.StringVar()
        ttk.Entry(left, textvariable=new_name_var).pack(fill=tk.X, pady=(6, 2))
        left_btns = ttk.Frame(left)
        left_btns.pack(fill=tk.X)

        right = ttk.LabelFrame(body, text="Active customer", padding=8)
        right.grid(row=0, column=1, sticky=tk.NSEW)

        name_var = tk.StringVar()
        user_var = tk.StringVar()
        pass_var = tk.StringVar()
        grid = ttk.Frame(right)
        grid.pack(fill=tk.X)
        ttk.Label(grid, text="Name:").grid(row=0, column=0, sticky=tk.W, pady=3)
        ttk.Entry(grid, textvariable=name_var, width=28).grid(row=0, column=1, sticky=tk.W, padx=6)
        ttk.Label(grid, text="Username:").grid(row=1, column=0, sticky=tk.W, pady=3)
        ttk.Entry(grid, textvariable=user_var, width=28).grid(row=1, column=1, sticky=tk.W, padx=6)
        ttk.Label(grid, text="Password:").grid(row=2, column=0, sticky=tk.W, pady=3)
        ttk.Entry(grid, textvariable=pass_var, width=28, show="*").grid(
            row=2, column=1, sticky=tk.W, padx=6
        )

        host_frame = ttk.LabelFrame(
            right, text="Host exceptions (different local account on one box)", padding=6
        )
        host_frame.pack(fill=tk.BOTH, expand=True, pady=(8, 0))
        cols = ("hostname", "username", "password")
        tree = ttk.Treeview(host_frame, columns=cols, show="headings", height=6)
        tree.heading("hostname", text="Hostname")
        tree.heading("username", text="Username")
        tree.heading("password", text="Password")
        tree.column("hostname", width=160)
        tree.column("username", width=110)
        tree.column("password", width=110)
        tree.pack(fill=tk.BOTH, expand=True)

        form = ttk.Frame(host_frame)
        form.pack(fill=tk.X, pady=(6, 0))
        host_var = tk.StringVar()
        puser_var = tk.StringVar()
        ppass_var = tk.StringVar()
        ttk.Label(form, text="Host:").grid(row=0, column=0, sticky=tk.W)
        ttk.Entry(form, textvariable=host_var, width=14).grid(row=0, column=1, padx=3)
        ttk.Label(form, text="User:").grid(row=0, column=2, sticky=tk.W)
        ttk.Entry(form, textvariable=puser_var, width=12).grid(row=0, column=3, padx=3)
        ttk.Label(form, text="Pass:").grid(row=0, column=4, sticky=tk.W)
        ttk.Entry(form, textvariable=ppass_var, width=12, show="*").grid(row=0, column=5, padx=3)

        def refresh_list(select_name=None):
            names = get_customer_names()
            cust_list.delete(0, tk.END)
            active = get_active_customer_name()
            pick = select_name or active
            for i, name in enumerate(names):
                cust_list.insert(tk.END, name)
                if normalize_customer_name(name) == normalize_customer_name(pick):
                    cust_list.selection_set(i)
                    cust_list.see(i)

        def load_selected():
            sel = cust_list.curselection()
            if not sel:
                return
            name = cust_list.get(sel[0])
            set_active_customer(name)
            customer = get_active_customer() or {}
            name_var.set(customer.get("name", ""))
            user_var.set(customer.get("username", ""))
            pass_var.set(customer.get("password", ""))
            tree.delete(*tree.get_children())
            for secret in customer.get("host_secrets") or []:
                tree.insert(
                    "",
                    "end",
                    values=(secret["hostname"], secret["username"], "••••••••"),
                )
            right.configure(text=f"Active customer — {customer.get('name', '')}")
            self._refresh_customer_label()

        def add_customer():
            name = new_name_var.get().strip()
            if not name:
                messagebox.showwarning("Usernames & Passwords", "Enter a customer name.", parent=dlg)
                return
            if _find_customer_index(name) is not None:
                messagebox.showwarning(
                    "Usernames & Passwords",
                    "That customer already exists. Select it in the list.",
                    parent=dlg,
                )
                return
            if not upsert_customer(name, "", ""):
                messagebox.showerror(
                    "Usernames & Passwords",
                    "Could not save credentials (Windows secret store).",
                    parent=dlg,
                )
                return
            new_name_var.set("")
            refresh_list(name)
            load_selected()

        def save_customer(quiet=False):
            name = name_var.get().strip()
            username = user_var.get().strip()
            password = pass_var.get()
            if not name:
                if not quiet:
                    messagebox.showwarning(
                        "Usernames & Passwords",
                        "Customer name is required.",
                        parent=dlg,
                    )
                return False
            sel = cust_list.curselection()
            old_name = cust_list.get(sel[0]) if sel else get_active_customer_name()
            if normalize_customer_name(old_name) != normalize_customer_name(name):
                if not rename_customer(old_name, name):
                    if not quiet:
                        messagebox.showwarning(
                            "Usernames & Passwords",
                            "Could not rename — that customer name may already exist.",
                            parent=dlg,
                        )
                    return False
            if not upsert_customer(name, username, password):
                if not quiet:
                    messagebox.showerror(
                        "Usernames & Passwords",
                        "Could not save credentials (Windows secret store).",
                        parent=dlg,
                    )
                return False
            set_login_mode(mode_var.get())
            refresh_list(name)
            load_selected()
            self._refresh_customer_label()
            return True

        def remove_customer():
            sel = cust_list.curselection()
            if not sel:
                return
            name = cust_list.get(sel[0])
            if not delete_customer(name):
                messagebox.showwarning(
                    "Usernames & Passwords",
                    "Keep at least one customer profile.",
                    parent=dlg,
                )
                return
            refresh_list()
            load_selected()

        def add_host():
            hostname = host_var.get().strip()
            username = puser_var.get().strip() or user_var.get().strip()
            password = ppass_var.get().strip() or pass_var.get().strip()
            if not hostname or not username or not password:
                messagebox.showwarning(
                    "Usernames & Passwords",
                    "Hostname, username, and password are required.",
                    parent=dlg,
                )
                return
            save_customer()
            if not upsert_hostname_profile(hostname, username, password):
                messagebox.showerror(
                    "Usernames & Passwords",
                    "Could not save credentials (Windows secret store).",
                    parent=dlg,
                )
                return
            host_var.set("")
            puser_var.set("")
            ppass_var.set("")
            load_selected()

        def remove_host():
            sel = tree.selection()
            if not sel:
                return
            hostname = tree.item(sel[0], "values")[0]
            remaining = [
                p for p in get_profiles()
                if normalize_hostname(p["hostname"]) != normalize_hostname(hostname)
            ]
            if not save_profiles(remaining):
                messagebox.showerror(
                    "Usernames & Passwords",
                    "Could not save credentials (Windows secret store).",
                    parent=dlg,
                )
                return
            load_selected()

        ttk.Button(left_btns, text="Add", command=add_customer).pack(side=tk.LEFT, pady=4)
        ttk.Button(left_btns, text="Remove", command=remove_customer).pack(side=tk.LEFT, padx=4)

        host_btns = ttk.Frame(host_frame)
        host_btns.pack(fill=tk.X, pady=(4, 0))
        ttk.Button(host_btns, text="Add / update host exception", command=add_host).pack(side=tk.LEFT)
        ttk.Button(host_btns, text="Remove host", command=remove_host).pack(side=tk.LEFT, padx=6)

        cust_list.bind("<<ListboxSelect>>", lambda e: load_selected())

        bottom = ttk.Frame(frame)
        bottom.pack(fill=tk.X, pady=(10, 0))

        def close_dialog():
            save_customer(quiet=True)
            set_login_mode(mode_var.get())
            self._refresh_customer_label()
            dlg.destroy()

        ttk.Button(
            bottom, text="Save usernames & passwords", command=save_customer, width=26
        ).pack(side=tk.RIGHT, padx=4)
        ttk.Button(bottom, text="Close", command=close_dialog, width=10).pack(side=tk.RIGHT)

        refresh_list()
        load_selected()
        dlg.protocol("WM_DELETE_WINDOW", close_dialog)

    def open_serial_connection(self):
        """Button handler for the 'Serial' button on main window."""
        if not SERIAL_AVAILABLE:
            self.show_error_dialog(
                "pyserial Missing",
                f"pyserial is not installed. Run: pip install pyserial\n\n{globals().get('SERIAL_ERROR', '')}",
            )
            return

        ports = [
            p for p in list_ports.comports()
            if is_local_com_port(p.device)
        ]
        if not ports:
            messagebox.showwarning("Serial", "No COM ports found on this machine.")
            return

        # Open a selection sub-dialog
        self._show_port_selection_dialog(ports)

    def _open_add_customer_dialog(self, parent, on_saved=None):
        """Serial helper: name + username + password → DPAPI store. Does not change login mode."""
        win = tk.Toplevel(parent)
        win.title("Add customer")
        win.geometry("440x240")
        win.minsize(400, 220)
        win.transient(parent)
        win.grab_set()

        frame = ttk.Frame(win, padding=12)
        frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(
            frame,
            text=(
                "Creates a customer profile and stores the username and password "
                "in this Windows user's secret store (DPAPI). Names stay in "
                "settings.json; passwords do not."
            ),
            wraplength=400,
        ).pack(anchor=tk.W, pady=(0, 10))

        name_var = tk.StringVar()
        user_var = tk.StringVar()
        pass_var = tk.StringVar()

        grid = ttk.Frame(frame)
        grid.pack(fill=tk.X)
        ttk.Label(grid, text="Customer name:").grid(row=0, column=0, sticky=tk.W, pady=4)
        name_entry = ttk.Entry(grid, textvariable=name_var, width=32)
        name_entry.grid(row=0, column=1, sticky=tk.W, padx=6)
        ttk.Label(grid, text="Username:").grid(row=1, column=0, sticky=tk.W, pady=4)
        ttk.Entry(grid, textvariable=user_var, width=32).grid(
            row=1, column=1, sticky=tk.W, padx=6
        )
        ttk.Label(grid, text="Password:").grid(row=2, column=0, sticky=tk.W, pady=4)
        ttk.Entry(grid, textvariable=pass_var, width=32, show="*").grid(
            row=2, column=1, sticky=tk.W, padx=6
        )

        def save():
            name = name_var.get().strip()
            username = user_var.get().strip()
            password = pass_var.get()
            if not name:
                messagebox.showwarning(
                    "Add customer", "Customer name is required.", parent=win
                )
                return
            if not username or not password:
                messagebox.showwarning(
                    "Add customer",
                    "Username and password are required.",
                    parent=win,
                )
                return
            if _find_customer_index(name) is not None:
                messagebox.showwarning(
                    "Add customer",
                    "That customer already exists. Select it in the dropdown.",
                    parent=win,
                )
                return
            if not upsert_customer(name, username, password):
                messagebox.showerror(
                    "Add customer",
                    "Could not save credentials (Windows secret store).",
                    parent=win,
                )
                return
            self._refresh_customer_label()
            win.destroy()
            if on_saved:
                on_saved(name)

        btns = ttk.Frame(frame)
        btns.pack(fill=tk.X, pady=(16, 0))
        ttk.Button(btns, text="Cancel", command=win.destroy).pack(side=tk.RIGHT)
        ttk.Button(btns, text="Save", command=save, width=10).pack(side=tk.RIGHT, padx=6)
        name_entry.focus_set()
        win.bind("<Return>", lambda e: save())

    def _open_add_device_dialog(
        self, parent, customer_name=None, hostname=None, on_saved=None
    ):
        """Serial helper: per-device user/pass on the active customer. Default is unchanged."""
        customer_name = (
            str(customer_name or "").strip() or get_active_customer_name()
        )
        if customer_name:
            set_active_customer(customer_name)
        preset = str(hostname or "").strip()
        if preset.startswith("(unknown"):
            preset = ""

        win = tk.Toplevel(parent)
        win.title("Add device login")
        win.geometry("460x270")
        win.minsize(420, 250)
        win.transient(parent)
        win.grab_set()

        frame = ttk.Frame(win, padding=12)
        frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(
            frame,
            text=(
                f"Customer: {customer_name}\n"
                "Saves a device-specific username and password for this customer. "
                "The customer default is not changed. Stored in this Windows user's "
                "secret store (DPAPI)."
            ),
            wraplength=420,
        ).pack(anchor=tk.W, pady=(0, 10))

        host_var = tk.StringVar(value=preset)
        user_var = tk.StringVar()
        pass_var = tk.StringVar()

        existing = credentials_for_hostname(preset) if preset else None
        if existing:
            user_var.set(existing[0] or "")
            pass_var.set(existing[1] or "")

        grid = ttk.Frame(frame)
        grid.pack(fill=tk.X)
        ttk.Label(grid, text="Device name:").grid(row=0, column=0, sticky=tk.W, pady=4)
        host_entry = ttk.Entry(grid, textvariable=host_var, width=32)
        host_entry.grid(row=0, column=1, sticky=tk.W, padx=6)
        ttk.Label(grid, text="Username:").grid(row=1, column=0, sticky=tk.W, pady=4)
        ttk.Entry(grid, textvariable=user_var, width=32).grid(
            row=1, column=1, sticky=tk.W, padx=6
        )
        ttk.Label(grid, text="Password:").grid(row=2, column=0, sticky=tk.W, pady=4)
        ttk.Entry(grid, textvariable=pass_var, width=32, show="*").grid(
            row=2, column=1, sticky=tk.W, padx=6
        )

        def save():
            host = host_var.get().strip()
            username = user_var.get().strip()
            password = pass_var.get()
            if not host:
                messagebox.showwarning(
                    "Add device login", "Device name is required.", parent=win
                )
                return
            if not username or not password:
                messagebox.showwarning(
                    "Add device login",
                    "Username and password are required.",
                    parent=win,
                )
                return
            if customer_name:
                set_active_customer(customer_name)
            if not upsert_hostname_profile(host, username, password):
                messagebox.showerror(
                    "Add device login",
                    "Could not save credentials (Windows secret store).",
                    parent=win,
                )
                return
            win.destroy()
            if on_saved:
                on_saved(host)

        btns = ttk.Frame(frame)
        btns.pack(fill=tk.X, pady=(16, 0))
        ttk.Button(btns, text="Cancel", command=win.destroy).pack(side=tk.RIGHT)
        ttk.Button(btns, text="Save", command=save, width=10).pack(side=tk.RIGHT, padx=6)
        host_entry.focus_set()
        win.bind("<Return>", lambda e: save())

    def _show_port_selection_dialog(self, ports):
        """Choose COM port, edit/save credentials, auto-login or skip to terminal."""
        dlg = tk.Toplevel(self.root)
        dlg.title("Serial connection")
        dlg.geometry("560x560")
        dlg.minsize(520, 500)
        dlg.transient(self.root)
        dlg.grab_set()

        ttk.Label(
            dlg, text="COM port:", font=("Segoe UI", 10, "bold")
        ).pack(anchor=tk.W, padx=10, pady=(10, 4))

        listbox = tk.Listbox(dlg, height=6)
        listbox.pack(fill=tk.BOTH, expand=True, padx=10)

        port_map = {}
        for p in ports:
            display = f"{p.device} — {p.description}"
            listbox.insert(tk.END, display)
            port_map[display] = p.device
        if port_map:
            listbox.selection_set(0)

        cust_frame = ttk.Frame(dlg)
        cust_frame.pack(fill=tk.X, padx=10, pady=(10, 0))
        ttk.Label(cust_frame, text="Customer:").pack(side=tk.LEFT)
        customer_var = tk.StringVar(value=get_active_customer_name())
        customer_combo = ttk.Combobox(
            cust_frame,
            textvariable=customer_var,
            values=get_customer_names(),
            state="readonly",
            width=28,
        )
        customer_combo.pack(side=tk.LEFT, padx=8)

        cred_frame = ttk.LabelFrame(dlg, text="Username & password", padding=8)
        cred_frame.pack(fill=tk.X, padx=10, pady=(10, 0))
        user_var = tk.StringVar()
        pass_var = tk.StringVar()
        ttk.Label(cred_frame, text="Username:").grid(row=0, column=0, sticky=tk.W, pady=3)
        ttk.Entry(cred_frame, textvariable=user_var, width=32).grid(
            row=0, column=1, sticky=tk.W, padx=6
        )
        ttk.Label(cred_frame, text="Password:").grid(row=1, column=0, sticky=tk.W, pady=3)
        ttk.Entry(cred_frame, textvariable=pass_var, width=32, show="*").grid(
            row=1, column=1, sticky=tk.W, padx=6
        )

        def load_creds():
            chosen = customer_var.get().strip()
            if chosen:
                set_active_customer(chosen)
            user, pwd = get_credentials()
            user_var.set(user or "")
            pass_var.set(pwd or "")
            self._refresh_customer_label()

        def save_creds():
            chosen = customer_var.get().strip() or get_active_customer_name()
            if chosen:
                set_active_customer(chosen)
            if not upsert_customer(chosen, user_var.get(), pass_var.get()):
                messagebox.showerror(
                    "Serial",
                    "Could not save credentials (Windows secret store).",
                    parent=dlg,
                )
                return False
            load_creds()
            return True

        ttk.Button(
            cred_frame, text="Save to this customer", command=save_creds
        ).grid(row=0, column=2, rowspan=2, padx=8)

        mode_frame = ttk.LabelFrame(dlg, text="When connecting", padding=8)
        mode_frame.pack(fill=tk.X, padx=10, pady=(10, 0))
        mode_var = tk.StringVar(value=get_login_mode())
        ttk.Radiobutton(
            mode_frame,
            text="Auto-try saved username/password",
            variable=mode_var,
            value="auto",
        ).pack(anchor=tk.W)
        ttk.Radiobutton(
            mode_frame,
            text="Manual host (use that host's saved secret)",
            variable=mode_var,
            value="manual",
        ).pack(anchor=tk.W)
        ttk.Radiobutton(
            mode_frame,
            text="Skip login — just open the terminal",
            variable=mode_var,
            value="skip",
        ).pack(anchor=tk.W)

        hint_frame = ttk.Frame(dlg)
        hint_frame.pack(fill=tk.X, padx=10, pady=(8, 0))
        ttk.Label(hint_frame, text="Hostname:").pack(side=tk.LEFT)
        hint_var = tk.StringVar()
        hint_combo = ttk.Combobox(hint_frame, textvariable=hint_var, width=28)
        hint_combo.pack(side=tk.LEFT, padx=8)

        def refresh_hosts():
            load_creds()
            hosts = ["(unknown)"]
            seen = set()
            for name in get_profile_hostnames():
                key = normalize_hostname(name)
                if key not in seen:
                    seen.add(key)
                    hosts.append(name)
            for hostname, _port, _proto in getattr(self, "neighbors", {}):
                key = normalize_hostname(hostname)
                if key and key not in seen:
                    seen.add(key)
                    hosts.append(hostname)
            hint_combo["values"] = hosts
            if not hint_var.get() or hint_var.get() not in hosts:
                hint_var.set(hosts[0])

        def sync_mode_widgets(*_args):
            skip = mode_var.get() == "skip"
            state = tk.DISABLED if skip else tk.NORMAL
            hint_combo.configure(state=state)

        customer_combo.bind("<<ComboboxSelected>>", lambda e: refresh_hosts())
        mode_var.trace_add("write", sync_mode_widgets)
        refresh_hosts()
        sync_mode_widgets()

        def add_customer_clicked():
            def after_add(name):
                customer_combo["values"] = get_customer_names()
                customer_var.set(name)
                refresh_hosts()

            self._open_add_customer_dialog(dlg, on_saved=after_add)

        ttk.Button(
            cust_frame, text="Add customer...", command=add_customer_clicked
        ).pack(side=tk.LEFT)

        def add_device_clicked():
            chosen_customer = customer_var.get().strip()
            if chosen_customer:
                set_active_customer(chosen_customer)

            def after_add(hostname):
                refresh_hosts()
                hint_var.set(hostname)

            self._open_add_device_dialog(
                dlg,
                customer_name=chosen_customer or get_active_customer_name(),
                hostname=hint_var.get(),
                on_saved=after_add,
            )

        ttk.Button(
            hint_frame, text="Add device...", command=add_device_clicked
        ).pack(side=tk.LEFT)

        def do_connect():
            sel = listbox.curselection()
            if not sel:
                messagebox.showwarning("Serial", "Select a COM port.", parent=dlg)
                return
            chosen_display = listbox.get(sel[0])
            chosen_port = port_map[chosen_display]
            chosen_customer = customer_var.get().strip()
            if chosen_customer:
                set_active_customer(chosen_customer)
            mode = mode_var.get().strip() or "auto"
            set_login_mode(mode)
            hint = hint_var.get().strip()
            if mode == "skip" or not hint or hint.startswith("(unknown"):
                hint = None
            session_user = user_var.get().strip()
            session_pass = pass_var.get()
            dlg.destroy()
            self._refresh_customer_label()
            self._start_serial_login(
                chosen_port,
                hostname_hint=hint,
                login_mode=mode,
                username=session_user,
                password=session_pass,
            )

        btn_frame = ttk.Frame(dlg)
        btn_frame.pack(pady=12)
        ttk.Button(btn_frame, text="Connect", command=do_connect).pack(side=tk.LEFT, padx=6)
        ttk.Button(btn_frame, text="Cancel", command=dlg.destroy).pack(side=tk.LEFT, padx=6)

        listbox.bind("<Double-1>", lambda e: do_connect())

    def _start_serial_login(
        self,
        port,
        hostname_hint=None,
        login_mode=None,
        username=None,
        password=None,
    ):
        """Thin GUI wrapper. Real login orchestration (worker, open, login, callbacks) is in start_serial_session.

        Form username/password are tried for this session only. They are not
        written unless the tech used Save to this customer.
        """
        self.status_var.set(f"Connecting to {port}...")

        form_user = str(username or "").strip()
        form_pass = password if password is not None else ""
        if form_user and form_pass:
            user, pwd = form_user, form_pass
        else:
            user, pwd = get_credentials()

        def on_success(session, port_name):
            # Put on the GUI queue so the existing process_queue path creates the window
            self.queue.put({
                "type": "serial_success",
                "session": session,
                "port": port_name
            })

        def on_log(msg):
            self.queue.put({"type": "log", "message": msg})

        def on_failure(reason):
            self.queue.put({"type": "log", "message": f"[SERIAL] Login/connection issue: {reason}"})
            self.queue.put({"type": "status", "text": "Serial login failed"})

        start_serial_session(
            port,
            user,
            pwd,
            on_success,
            on_log,
            on_failure,
            hostname_hint=hostname_hint,
            login_mode=login_mode,
        )

    def open_serial_window(self, session: "SerialSession", port_name: str):
        """Opens the serial actions sub-window after successful login."""
        # Close any previous serial window
        if self.current_serial:
            try:
                self.current_serial.close()
            except:
                pass

        self.current_serial = session
        self.serial_window = SerialWindow(self.root, session, port_name)
        self.status_var.set(f"Serial connected: {port_name}")
        if not getattr(session, "auto_login", True):
            self.serial_window.open_manual_terminal_window()

    # ==================== Queue processor (extended) ====================

    def process_queue(self):
        updated = False

        while not self.queue.empty():
            try:
                item = self.queue.get_nowait()

                if item.get("type") == "discovery_frame":
                    self.discovery_frames += 1
                    updated = True

                elif item.get("type") == "neighbor":
                    key = (item["hostname"], item["port"], item["protocol"])
                    self.neighbors[key] = item["timestamp"]
                    updated = True
                    if hasattr(self, "log_text") and self.log_text:
                        self.append_log(f"{item['timestamp']} - {item['protocol']} | {item['hostname']} on {item['port']}")

                elif item.get("type") == "log":
                    if hasattr(self, "log_text") and self.log_text:
                        self.append_log(item["message"])
                    else:
                        print(item["message"])  # fallback

                elif item.get("type") == "status":
                    self.status_var.set(item.get("text", ""))

                elif item.get("type") == "serial_success":
                    self.open_serial_window(item["session"], item["port"])

            except queue.Empty:
                break

        if updated:
            self.refresh_treeview()

        self.root.after(140, self.process_queue)

    def show_error_dialog(self, title, message):
        messagebox.showerror(title, message)

    def _live_serial_window(self):
        win = getattr(self, "serial_window", None)
        try:
            if win and win.window.winfo_exists():
                return win
        except Exception:
            return None
        return None

    def _with_serial_window(self, action):
        win = self._live_serial_window()
        if win:
            win.window.lift()
            action(win)
            return
        self.open_serial_connection()

    def menu_serial_transceiver(self):
        self._with_serial_window(lambda w: w.run_transceivers())

    def menu_serial_neighbors(self):
        self._with_serial_window(lambda w: w.run_neighbors())

    def open_serial_cli_terminal(self):
        self._with_serial_window(lambda w: w.open_manual_terminal_window())

    def focus_hostname_port_view(self):
        """Menu entry under cdp & lldp search pointing to the main table."""
        self.status_var.set("Main table = cdp & lldp search — hostname and port inf (passive discovery)")
        if hasattr(self, 'tree'):
            self.tree.focus_set()

    def show_menu_map_info(self):
        """Show the source menu map for reference."""
        map_text = (
            "Main window\n"
            "\tSerial\n"
            "\t\tShow transceiver details\n"
            "\t\tShow cdp & lldp neighbors\n"
            "\t\tMac address table\n"
            "\t\t\tGrab old table\n"
            "\t\t\tGrab new table\n"
            "\t\t\tCompare tables\n"
            "\t\tOpen terminal\n"
            "\t\t\tCli terminal\n"
            "cdp & lldp search\n"
            "\thostname and port inf\n\n"
            "This menubar + window sections follow netDiag_Menu_Map.txt."
        )
        messagebox.showinfo("netDiag Menu Map", map_text)

    def menu_grab_old_mac(self):
        self._with_serial_window(lambda w: w.grab_old_mac())

    def menu_grab_new_mac(self):
        self._with_serial_window(lambda w: w.grab_new_mac())

    def menu_compare_mac(self):
        win = self._live_serial_window()
        if win:
            win.window.lift()
            win.compare_mac()
            return
        reports = compare_mac_tables()
        if reports:
            messagebox.showinfo("MAC compare", "\n".join(reports))
        else:
            messagebox.showinfo("MAC compare", "No missing or moved MACs.")

    def toggle_listening(self):
        if self.is_listening:
            self.stop_listening()
        else:
            self.start_listening()

    def on_closing(self):
        self.stop_listening()
        if self.current_serial:
            try:
                self.current_serial.close()
            except:
                pass
        self.root.destroy()

def launch():
    """Convenience launcher (delegates to the real one in main)."""
    main()

if __name__ == "__main__":
    if "--install-shortcut" in sys.argv:
        ensure_desktop_shortcut()
        raise SystemExit(0)
    main()
