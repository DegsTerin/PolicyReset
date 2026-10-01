#!/usr/bin/env python3
"""
PolicyReset 4.3.4

Windows Local Group Policy diagnostic, backup, reset and verification utility.

The application is designed to run entirely in PowerShell. When launched by
Windows through the .pyw file association, it opens a PowerShell console for the application
and re-executes itself with python.exe. When started directly from an
existing PowerShell console with python.exe, it stays in that same console.

Scope:
    - Local Group Policy for the current Computer and User.
    - Backup before modification.
    - Verification after modification.
    - Group Policy refresh as a separate explicit operation.
    - Optional forced removal only for local Group Policy stores that failed
      normal removal.

PolicyReset does not remove or bypass Active Directory, Microsoft Entra ID,
MDM, Intune or other remote organisation-controlled policy.
"""

from __future__ import annotations

import ctypes
from ctypes import wintypes
import datetime as dt
import json
import locale
import os
from pathlib import Path
import shutil
import subprocess
import sys
import winreg
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass
from typing import Any


APP_NAME = "PolicyReset"
VERSION = "4.3.4"

DATA_ROOT = (
    Path(os.environ.get("ProgramData", r"C:\ProgramData"))
    / APP_NAME
)

SESSION_ROOT = DATA_ROOT / "Sessions"
LOG_ROOT = DATA_ROOT / "Logs"

LOCAL_GPO_DIRECTORIES = (
    Path(os.environ.get("WINDIR", r"C:\Windows"))
    / "System32"
    / "GroupPolicy",
    Path(os.environ.get("WINDIR", r"C:\Windows"))
    / "System32"
    / "GroupPolicyUsers",
)

BACKUP_ARTIFACT_NAMES = (
    "LocalGroupPolicy",
    "Registry",
    "backup-manifest.json",
)

POLICY_REGISTRY_ROOTS = (
    ("HKCU", r"Software\Policies"),
    (
        "HKCU",
        r"Software\Microsoft\Windows\CurrentVersion\Policies",
    ),
    ("HKLM", r"SOFTWARE\Policies"),
    (
        "HKLM",
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies",
    ),
)

MANAGEMENT_KEYS = (
    (
        r"HKLM\SOFTWARE\Microsoft\Enrollments",
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Enrollments",
    ),
    (
        r"HKLM\SOFTWARE\Microsoft\PolicyManager",
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\PolicyManager",
    ),
    (
        r"HKLM\SOFTWARE\Microsoft\Provisioning\OMADM\Accounts",
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Provisioning\OMADM\Accounts",
    ),
)


@dataclass(frozen=True)
class PolicyEntry:
    hive: str
    path: str
    value_name: str
    value: str

    @property
    def full_path(self) -> str:
        return f"{self.hive}\\{self.path}\\{self.value_name}"


@dataclass(frozen=True)
class ManagementState:
    domain_joined: bool
    entra_joined: bool
    enterprise_joined: bool
    mdm_discovery_url_present: bool
    registry_management_locations: tuple[str, ...]

    @property
    def organisation_managed_indicator(self) -> bool:
        return any(
            (
                self.domain_joined,
                self.entra_joined,
                self.enterprise_joined,
                self.mdm_discovery_url_present,
            )
        )


@dataclass(frozen=True)
class RemovalFailure:
    path: str
    reason: str


@dataclass
class Session:
    directory: Path
    log_file: Path


class PolicyResetError(RuntimeError):
    """Expected PolicyReset error."""


def is_windows() -> bool:
    return os.name == "nt"


def is_admin() -> bool:
    if not is_windows():
        return False

    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except OSError:
        return False


def configure_console() -> None:
    """Keep output readable in the existing PowerShell console."""
    preferred = locale.getpreferredencoding(False)

    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(
                encoding="utf-8",
                errors="replace",
            )
        except (AttributeError, OSError):
            continue

    if preferred:
        # Keep the preferred encoding available for diagnostics.
        pass


def timestamp() -> str:
    return dt.datetime.now().astimezone().strftime(
        "%Y-%m-%d %H:%M:%S %z"
    )


def session_timestamp() -> str:
    return dt.datetime.now().strftime("%Y%m%d_%H%M%S_%f")


def create_session() -> Session:
    session_directory = SESSION_ROOT / session_timestamp()
    session_directory.mkdir(parents=True, exist_ok=True)

    LOG_ROOT.mkdir(parents=True, exist_ok=True)

    log_file = (
        LOG_ROOT
        / f"PolicyReset_{session_directory.name}.log"
    )

    return Session(
        directory=session_directory,
        log_file=log_file,
    )


class Logger:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, level: str, message: str) -> None:
        line = f"[{timestamp()}] [{level}] {message}"
        print(line)
        with self.path.open(
            "a",
            encoding="utf-8",
        ) as handle:
            handle.write(line + "\n")

    def info(self, message: str) -> None:
        self.write("INFO", message)

    def warn(self, message: str) -> None:
        self.write("WARN", message)

    def error(self, message: str) -> None:
        self.write("ERROR", message)


def command_exists(command: str) -> bool:
    return shutil.which(command) is not None


def _windows_output_encodings() -> list[str]:
    """Return likely encodings for native Windows command output."""
    encodings: list[str] = []

    if is_windows():
        try:
            console_code_page = int(
                ctypes.windll.kernel32.GetConsoleOutputCP()
            )
        except (OSError, AttributeError):
            console_code_page = 0

        try:
            oem_code_page = int(
                ctypes.windll.kernel32.GetOEMCP()
            )
        except (OSError, AttributeError):
            oem_code_page = 0

        for code_page in (console_code_page, oem_code_page):
            if code_page:
                encodings.append(f"cp{code_page}")

    encodings.extend(
        [
            locale.getpreferredencoding(False),
            "cp850",
            "cp1252",
            "utf-8",
        ]
    )
    return encodings


def decode_output(data: bytes) -> str:
    """Decode native Windows command output without common mojibake."""
    seen: set[str] = set()

    for encoding in _windows_output_encodings():
        if not encoding:
            continue

        normalised = encoding.lower()
        if normalised in seen:
            continue
        seen.add(normalised)

        try:
            return data.decode(encoding)
        except (LookupError, UnicodeDecodeError):
            continue

    return data.decode("utf-8", errors="replace")


def run_command(
    command: list[str],
    *,
    timeout: int,
) -> tuple[int, str, str]:
    process = subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        creationflags=getattr(
            subprocess,
            "CREATE_NO_WINDOW",
            0,
        ),
    )

    return (
        process.returncode,
        decode_output(process.stdout),
        decode_output(process.stderr),
    )



def system_summary() -> dict[str, Any]:
    return {
        "computer": os.environ.get(
            "COMPUTERNAME",
            "Unknown",
        ),
        "user": os.environ.get(
            "USERNAME",
            "Unknown",
        ),
        "administrator": is_admin(),
        "windows_directory": os.environ.get(
            "WINDIR",
            r"C:\Windows",
        ),
        "python_version": sys.version.split()[0],
    }


def detect_management_state() -> ManagementState:
    domain_joined = False
    entra_joined = False
    enterprise_joined = False
    mdm_discovery = False

    if command_exists("dsregcmd.exe"):
        _, stdout, stderr = run_command(
            ["dsregcmd.exe", "/status"],
            timeout=30,
        )

        values: dict[str, str] = {}

        for line in f"{stdout}\n{stderr}".splitlines():
            if ":" not in line:
                continue

            key, value = line.split(":", 1)
            values[key.strip().lower()] = value.strip()

        domain_joined = (
            values.get("domainjoined", "").upper() == "YES"
        )
        entra_joined = (
            values.get("azureadjoined", "").upper() == "YES"
        )
        enterprise_joined = (
            values.get("enterprisejoined", "").upper() == "YES"
        )

        mdm_value = values.get("mdmurl", "")
        mdm_discovery = bool(
            mdm_value
            and mdm_value.lower() not in {
                "not set",
                "n/a",
            }
        )

    locations: list[str] = []

    for display, hive, path in MANAGEMENT_KEYS:
        try:
            with winreg.OpenKey(
                hive,
                path,
                0,
                winreg.KEY_READ,
            ):
                locations.append(display)
        except (FileNotFoundError, PermissionError, OSError):
            continue

    return ManagementState(
        domain_joined=domain_joined,
        entra_joined=entra_joined,
        enterprise_joined=enterprise_joined,
        mdm_discovery_url_present=mdm_discovery,
        registry_management_locations=tuple(locations),
    )


def enumerate_registry_tree(
    hive: int,
    root_path: str,
    display_hive: str,
) -> list[PolicyEntry]:
    entries: list[PolicyEntry] = []

    def walk(current_path: str) -> None:
        child_names: list[str] = []

        try:
            with winreg.OpenKey(
                hive,
                current_path,
                0,
                winreg.KEY_READ,
            ) as key:
                info = winreg.QueryInfoKey(key)
                value_count = info[1]
                child_count = info[0]

                for index in range(value_count):
                    try:
                        name, value, _ = winreg.EnumValue(
                            key,
                            index,
                        )
                    except OSError:
                        continue

                    entries.append(
                        PolicyEntry(
                            hive=display_hive,
                            path=current_path,
                            value_name=str(name),
                            value=repr(value),
                        )
                    )

                for index in range(child_count):
                    try:
                        child_names.append(
                            winreg.EnumKey(key, index)
                        )
                    except OSError:
                        continue

        except (
            FileNotFoundError,
            PermissionError,
            OSError,
        ):
            return

        for child in child_names:
            walk(
                f"{current_path}\\{child}"
            )

    walk(root_path)
    return entries


def scan_policy_registry(
    logger: Logger,
) -> list[PolicyEntry]:
    logger.info(
        "Scanning Registry-based policy locations..."
    )

    entries: list[PolicyEntry] = []

    for display_hive, root_path in POLICY_REGISTRY_ROOTS:
        hive = (
            winreg.HKEY_CURRENT_USER
            if display_hive == "HKCU"
            else winreg.HKEY_LOCAL_MACHINE
        )

        entries.extend(
            enumerate_registry_tree(
                hive,
                root_path,
                display_hive,
            )
        )

    logger.info(
        f"Registry scan found {len(entries)} policy value(s)."
    )

    return entries


def collect_gpresult(
    session: Session,
    logger: Logger,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "available": command_exists("gpresult.exe"),
        "return_code": None,
        "text_report": None,
        "html_report": None,
        "xml_report": None,
        "stdout": "",
        "stderr": "",
    }

    if not result["available"]:
        logger.warn(
            "gpresult.exe was not found."
        )
        return result

    text_report = session.directory / "gpresult.txt"
    html_report = session.directory / "gpresult.html"
    xml_report = session.directory / "gpresult.xml"

    code, stdout, stderr = run_command(
        ["gpresult.exe", "/r"],
        timeout=120,
    )

    text_report.write_text(
        f"Exit code: {code}\n\n"
        f"STDOUT:\n{stdout}\n\n"
        f"STDERR:\n{stderr}\n",
        encoding="utf-8",
    )

    result.update(
        {
            "return_code": code,
            "text_report": str(text_report),
            "stdout": stdout,
            "stderr": stderr,
        }
    )

    if code == 0:
        logger.info(
            f"gpresult text report saved to {text_report}."
        )
    else:
        logger.warn(
            f"gpresult /r returned exit code {code}."
        )

    html_code, _, html_stderr = run_command(
        [
            "gpresult.exe",
            "/h",
            str(html_report),
            "/f",
        ],
        timeout=120,
    )

    if (
        html_code == 0
        and html_report.exists()
    ):
        result["html_report"] = str(html_report)
        logger.info(
            f"gpresult HTML report saved to {html_report}."
        )
    else:
        logger.warn(
            "gpresult HTML report could not be generated: "
            f"{html_stderr.strip() or 'unknown error'}"
        )

    xml_code, _, xml_stderr = run_command(
        [
            "gpresult.exe",
            "/x",
            str(xml_report),
            "/f",
        ],
        timeout=120,
    )

    if (
        xml_code == 0
        and xml_report.exists()
    ):
        result["xml_report"] = str(xml_report)
        logger.info(
            f"gpresult XML report saved to {xml_report}."
        )
    else:
        logger.warn(
            "gpresult XML report could not be generated: "
            f"{xml_stderr.strip() or 'unknown error'}"
        )

    return result


def _xml_local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1].lower()


def _find_gpresult_name(element: ET.Element) -> str:
    """Return a GPO name from an attribute or direct child element."""
    name = (
        element.attrib.get("Name")
        or element.attrib.get("name")
        or ""
    ).strip()
    if name:
        return name

    for child in element:
        if _xml_local_name(str(child.tag)) == "name":
            return (child.text or "").strip()

    return ""


def parse_gpresult_xml_applied_objects(
    xml_report: str,
) -> tuple[list[str], str]:
    """Extract applied GPO names without relying on the Windows UI language."""
    path = Path(xml_report)

    try:
        root = ET.parse(path).getroot()
    except (ET.ParseError, OSError, ValueError):
        return [], "parse_failed"

    names: list[str] = []
    seen: set[str] = set()
    result_sections = {"computerresults", "userresults"}
    found_result_section = False

    for results in root.iter():
        if _xml_local_name(str(results.tag)) not in result_sections:
            continue

        found_result_section = True
        for element in results.iter():
            if _xml_local_name(str(element.tag)) != "gpo":
                continue

            name = _find_gpresult_name(element)
            if name and name not in seen:
                seen.add(name)
                names.append(name)

    if not found_result_section:
        return [], "no_result_sections"

    return names, "xml"


def extract_applied_group_policy_objects(
    gpresult: dict[str, Any],
) -> tuple[list[str], str]:
    """Extract applied GPO names from the structured gpresult XML report."""
    xml_report = gpresult.get("xml_report")

    if xml_report:
        return parse_gpresult_xml_applied_objects(xml_report)

    return [], "unavailable"


def _registry_backup_name(
    display_hive: str,
    root_path: str,
) -> str:
    safe_name = (
        root_path
        .replace("\\", "_")
        .replace(" ", "_")
    )
    return f"{display_hive}_{safe_name}"


def _registry_hive(
    display_hive: str,
) -> int:
    if display_hive == "HKCU":
        return winreg.HKEY_CURRENT_USER
    if display_hive == "HKLM":
        return winreg.HKEY_LOCAL_MACHINE
    raise ValueError(f"Unsupported Registry hive: {display_hive}")


def _enable_process_privileges(
    privilege_names: tuple[str, ...],
    logger: Logger,
) -> bool:
    """Enable required Windows token privileges for controlled Registry cleanup."""
    if not is_windows():
        return False

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    class _Luid(ctypes.Structure):
        _fields_ = [
            ("LowPart", wintypes.DWORD),
            ("HighPart", wintypes.LONG),
        ]

    class _LuidAndAttributes(ctypes.Structure):
        _fields_ = [
            ("Luid", _Luid),
            ("Attributes", wintypes.DWORD),
        ]

    class _TokenPrivileges(ctypes.Structure):
        _fields_ = [
            ("PrivilegeCount", wintypes.DWORD),
            ("Privileges", _LuidAndAttributes),
        ]

    advapi32.OpenProcessToken.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    advapi32.OpenProcessToken.restype = wintypes.BOOL
    advapi32.LookupPrivilegeValueW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        ctypes.POINTER(_Luid),
    ]
    advapi32.LookupPrivilegeValueW.restype = wintypes.BOOL
    advapi32.AdjustTokenPrivileges.argtypes = [
        wintypes.HANDLE,
        wintypes.BOOL,
        ctypes.POINTER(_TokenPrivileges),
        wintypes.DWORD,
        ctypes.POINTER(_TokenPrivileges),
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.AdjustTokenPrivileges.restype = wintypes.BOOL
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL

    token = wintypes.HANDLE()
    token_access = 0x0008 | 0x0020

    if not advapi32.OpenProcessToken(
        kernel32.GetCurrentProcess(),
        token_access,
        ctypes.byref(token),
    ):
        error = ctypes.get_last_error()
        logger.warn(
            f"Could not open the process token for privilege adjustment (WinError {error})."
        )
        return False

    success = True
    try:
        for privilege_name in privilege_names:
            luid = _Luid()
            if not advapi32.LookupPrivilegeValueW(
                None,
                privilege_name,
                ctypes.byref(luid),
            ):
                error = ctypes.get_last_error()
                logger.warn(
                    f"Could not resolve Windows privilege {privilege_name} (WinError {error})."
                )
                success = False
                continue

            token_privileges = _TokenPrivileges()
            token_privileges.PrivilegeCount = 1
            token_privileges.Privileges.Luid = luid
            token_privileges.Privileges.Attributes = 0x00000002

            if not advapi32.AdjustTokenPrivileges(
                token,
                False,
                ctypes.byref(token_privileges),
                0,
                None,
                None,
            ):
                error = ctypes.get_last_error()
                logger.warn(
                    f"Could not enable Windows privilege {privilege_name} (WinError {error})."
                )
                success = False
                continue

            error = ctypes.get_last_error()
            if error == 1300:
                logger.warn(
                    f"Windows privilege {privilege_name} was not assigned to the process."
                )
                success = False
    finally:
        kernel32.CloseHandle(token)

    return success


def _registry_security_api() -> dict[str, Any]:
    """Return configured Advapi32 and Kernel32 functions used for Registry security."""
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    advapi32.GetNamedSecurityInfoW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
    ]
    advapi32.GetNamedSecurityInfoW.restype = wintypes.DWORD

    advapi32.SetNamedSecurityInfoW.argtypes = [
        wintypes.LPWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    advapi32.SetNamedSecurityInfoW.restype = wintypes.DWORD

    advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = [
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_wchar_p),
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW.restype = (
        wintypes.BOOL
    )

    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = (
        wintypes.BOOL
    )

    advapi32.GetSecurityDescriptorOwner.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.BOOL),
    ]
    advapi32.GetSecurityDescriptorOwner.restype = wintypes.BOOL

    advapi32.GetSecurityDescriptorGroup.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.BOOL),
    ]
    advapi32.GetSecurityDescriptorGroup.restype = wintypes.BOOL

    advapi32.GetSecurityDescriptorDacl.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.BOOL),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.BOOL),
    ]
    advapi32.GetSecurityDescriptorDacl.restype = wintypes.BOOL

    advapi32.ConvertStringSidToSidW.argtypes = [
        wintypes.LPCWSTR,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    advapi32.ConvertStringSidToSidW.restype = wintypes.BOOL

    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p

    return {
        "advapi32": advapi32,
        "kernel32": kernel32,
    }


def _registry_native_path(
    display_hive: str,
    root_path: str,
) -> str:
    hive_name = {
        "HKCU": "CURRENT_USER",
        "HKLM": "MACHINE",
    }.get(display_hive)

    if hive_name is None:
        raise ValueError(f"Unsupported Registry hive: {display_hive}")

    return f"{hive_name}\\{root_path}"


def _registry_security_sddl(
    display_hive: str,
    root_path: str,
) -> str:
    """Read owner, group and DACL as an SDDL string."""
    if not is_windows():
        raise PolicyResetError("Registry security APIs are only available on Windows.")

    api = _registry_security_api()
    advapi32 = api["advapi32"]
    kernel32 = api["kernel32"]

    owner = ctypes.c_void_p()
    group = ctypes.c_void_p()
    dacl = ctypes.c_void_p()
    sacl = ctypes.c_void_p()
    security_descriptor = ctypes.c_void_p()

    security_information = (
        0x00000001  # OWNER_SECURITY_INFORMATION
        | 0x00000002  # GROUP_SECURITY_INFORMATION
        | 0x00000004  # DACL_SECURITY_INFORMATION
    )

    error = advapi32.GetNamedSecurityInfoW(
        _registry_native_path(display_hive, root_path),
        4,  # SE_REGISTRY_KEY
        security_information,
        ctypes.byref(owner),
        ctypes.byref(group),
        ctypes.byref(dacl),
        ctypes.byref(sacl),
        ctypes.byref(security_descriptor),
    )
    if error != 0:
        raise ctypes.WinError(error)

    string_descriptor = ctypes.c_wchar_p()
    descriptor_length = wintypes.DWORD()

    try:
        if not advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW(
            security_descriptor,
            1,  # SDDL_REVISION_1
            security_information,
            ctypes.byref(string_descriptor),
            ctypes.byref(descriptor_length),
        ):
            raise ctypes.WinError(ctypes.get_last_error())

        return string_descriptor.value or ""
    finally:
        if string_descriptor:
            kernel32.LocalFree(ctypes.cast(string_descriptor, ctypes.c_void_p))
        if security_descriptor:
            kernel32.LocalFree(security_descriptor)


def _registry_dacl_from_sddl(
    sddl: str,
) -> tuple[ctypes.c_void_p, ctypes.c_void_p]:
    """Convert SDDL into a self-relative security descriptor and return its DACL."""
    api = _registry_security_api()
    advapi32 = api["advapi32"]

    security_descriptor = ctypes.c_void_p()
    descriptor_size = wintypes.DWORD()

    if not advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl,
        1,  # SDDL_REVISION_1
        ctypes.byref(security_descriptor),
        ctypes.byref(descriptor_size),
    ):
        raise ctypes.WinError(ctypes.get_last_error())

    dacl = ctypes.c_void_p()
    dacl_present = wintypes.BOOL()
    dacl_defaulted = wintypes.BOOL()

    try:
        if not advapi32.GetSecurityDescriptorDacl(
            security_descriptor,
            ctypes.byref(dacl_present),
            ctypes.byref(dacl),
            ctypes.byref(dacl_defaulted),
        ):
            raise ctypes.WinError(ctypes.get_last_error())

        if not dacl_present.value or not dacl:
            raise PolicyResetError("The temporary Registry ACL did not contain a DACL.")

        return security_descriptor, dacl
    except Exception:
        api["kernel32"].LocalFree(security_descriptor)
        raise


def _registry_set_owner_and_dacl(
    display_hive: str,
    root_path: str,
) -> None:
    """Grant only Administrators and SYSTEM temporary full control on one Registry key."""
    api = _registry_security_api()
    advapi32 = api["advapi32"]
    kernel32 = api["kernel32"]

    admin_sid = ctypes.c_void_p()
    if not advapi32.ConvertStringSidToSidW(
        "S-1-5-32-544",
        ctypes.byref(admin_sid),
    ):
        raise ctypes.WinError(ctypes.get_last_error())

    temporary_sd, temporary_dacl = _registry_dacl_from_sddl(
        "D:(A;;KA;;;BA)(A;;KA;;;SY)"
    )

    security_path = _registry_native_path(display_hive, root_path)

    try:
        owner_error = advapi32.SetNamedSecurityInfoW(
            security_path,
            4,  # SE_REGISTRY_KEY
            0x00000001,  # OWNER_SECURITY_INFORMATION
            admin_sid,
            None,
            None,
            None,
        )
        if owner_error != 0:
            raise ctypes.WinError(owner_error)

        dacl_error = advapi32.SetNamedSecurityInfoW(
            security_path,
            4,  # SE_REGISTRY_KEY
            0x00000004,  # DACL_SECURITY_INFORMATION
            None,
            None,
            temporary_dacl,
            None,
        )
        if dacl_error != 0:
            raise ctypes.WinError(dacl_error)
    finally:
        kernel32.LocalFree(temporary_sd)
        kernel32.LocalFree(admin_sid)


def _registry_restore_security_sddl(
    display_hive: str,
    root_path: str,
    sddl: str,
) -> None:
    """Restore owner, group and DACL from a saved SDDL descriptor."""
    api = _registry_security_api()
    advapi32 = api["advapi32"]
    kernel32 = api["kernel32"]

    security_descriptor = ctypes.c_void_p()
    descriptor_size = wintypes.DWORD()

    if not advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl,
        1,  # SDDL_REVISION_1
        ctypes.byref(security_descriptor),
        ctypes.byref(descriptor_size),
    ):
        raise ctypes.WinError(ctypes.get_last_error())

    owner = ctypes.c_void_p()
    group = ctypes.c_void_p()
    dacl = ctypes.c_void_p()
    sacl = ctypes.c_void_p()
    owner_defaulted = wintypes.BOOL()
    group_defaulted = wintypes.BOOL()
    dacl_present = wintypes.BOOL()
    dacl_defaulted = wintypes.BOOL()

    try:
        if not advapi32.GetSecurityDescriptorOwner(
            security_descriptor,
            ctypes.byref(owner),
            ctypes.byref(owner_defaulted),
        ):
            raise ctypes.WinError(ctypes.get_last_error())

        if not advapi32.GetSecurityDescriptorGroup(
            security_descriptor,
            ctypes.byref(group),
            ctypes.byref(group_defaulted),
        ):
            raise ctypes.WinError(ctypes.get_last_error())

        if not advapi32.GetSecurityDescriptorDacl(
            security_descriptor,
            ctypes.byref(dacl_present),
            ctypes.byref(dacl),
            ctypes.byref(dacl_defaulted),
        ):
            raise ctypes.WinError(ctypes.get_last_error())

        security_information = (
            0x00000001  # OWNER_SECURITY_INFORMATION
            | 0x00000002  # GROUP_SECURITY_INFORMATION
            | 0x00000004  # DACL_SECURITY_INFORMATION
        )

        error = advapi32.SetNamedSecurityInfoW(
            _registry_native_path(display_hive, root_path),
            4,  # SE_REGISTRY_KEY
            security_information,
            owner,
            group,
            dacl if dacl_present.value else None,
            None,
        )
        if error != 0:
            raise ctypes.WinError(error)
    finally:
        kernel32.LocalFree(security_descriptor)


def enumerate_registry_key_paths(
    display_hive: str,
    root_path: str,
) -> list[str]:
    """Enumerate a fixed Registry key tree from parent to child."""
    hive = _registry_hive(display_hive)
    result: list[str] = []

    def walk(current_path: str) -> None:
        result.append(current_path)

        with winreg.OpenKey(
            hive,
            current_path,
            0,
            winreg.KEY_READ | winreg.KEY_ENUMERATE_SUB_KEYS,
        ) as key:
            child_names = [
                winreg.EnumKey(key, index)
                for index in range(winreg.QueryInfoKey(key)[0])
            ]

        for child_name in child_names:
            walk(f"{current_path}\\{child_name}")

    walk(root_path)
    return result


def _repair_registry_tree_permissions(
    display_hive: str,
    root_path: str,
    logger: Logger,
) -> tuple[bool, dict[str, str], str]:
    """Save original security and grant controlled access throughout one fixed tree."""
    backups: dict[str, str] = {}

    try:
        key_paths = enumerate_registry_key_paths(
            display_hive,
            root_path,
        )
    except (OSError, PolicyResetError) as exc:
        return False, backups, f"Could not enumerate Registry tree: {exc}"

    for key_path in key_paths:
        try:
            backups[key_path] = _registry_security_sddl(
                display_hive,
                key_path,
            )
            _registry_set_owner_and_dacl(
                display_hive,
                key_path,
            )
        except (OSError, PolicyResetError) as exc:
            return False, backups, (
                f"Permission repair failed for "
                f"{display_hive}\\{key_path}: {exc}"
            )

    logger.info(
        f"Controlled Registry permission repair applied to "
        f"{display_hive}\\{root_path} and {len(key_paths) - 1} child key(s)."
    )
    return True, backups, ""


def _restore_registry_tree_security(
    backups: dict[str, str],
    display_hive: str,
    logger: Logger,
) -> list[str]:
    """Restore saved Registry security descriptors for keys that remain."""
    failures: list[str] = []

    for key_path in sorted(
        backups,
        key=len,
        reverse=True,
    ):
        try:
            with winreg.OpenKey(
                _registry_hive(display_hive),
                key_path,
                0,
                winreg.KEY_READ,
            ):
                pass
        except FileNotFoundError:
            continue
        except OSError:
            # The key may still exist but be inaccessible; attempt restoration anyway.
            pass

        try:
            _registry_restore_security_sddl(
                display_hive,
                key_path,
                backups[key_path],
            )
        except (OSError, PolicyResetError) as exc:
            failures.append(
                f"{display_hive}\\{key_path}: {exc}"
            )

    if failures:
        logger.warn(
            "Some Registry security descriptors could not be restored: "
            + "; ".join(failures)
        )

    return failures

def registry_policy_root_access_state(
    display_hive: str,
    root_path: str,
) -> tuple[bool, str]:
    try:
        with winreg.OpenKey(
            _registry_hive(display_hive),
            root_path,
            0,
            winreg.KEY_READ | winreg.KEY_ENUMERATE_SUB_KEYS,
        ) as key:
            subkey_count, value_count, _ = winreg.QueryInfoKey(key)

        if subkey_count == 0 and value_count == 0:
            return False, "Empty"

        return True, "Present"
    except FileNotFoundError:
        return False, "Absent"
    except PermissionError as exc:
        return False, f"Access denied: {exc}"
    except OSError as exc:
        return False, str(exc)

def registry_policy_root_status() -> list[str]:
    present: list[str] = []

    for display_hive, root_path in POLICY_REGISTRY_ROOTS:
        exists, state = registry_policy_root_access_state(
            display_hive,
            root_path,
        )
        if exists or state not in {"Absent", "Empty"}:
            present.append(
                f"{display_hive}\\{root_path}"
            )

    return present


def remove_registry_key_tree(
    hive: int,
    subkey: str,
) -> None:
    """Delete a Registry key and all descendants."""
    with winreg.OpenKey(
        hive,
        subkey,
        0,
        winreg.KEY_ALL_ACCESS,
    ) as key:
        child_names: list[str] = []
        info = winreg.QueryInfoKey(key)

        for index in range(info[0]):
            child_names.append(
                winreg.EnumKey(key, index)
            )

    for child_name in child_names:
        remove_registry_key_tree(
            hive,
            f"{subkey}\\{child_name}",
        )

    winreg.DeleteKey(
        hive,
        subkey,
    )


def remove_registry_policy_root(
    display_hive: str,
    root_path: str,
    logger: Logger,
) -> tuple[bool, str]:
    full_path = f"{display_hive}\\{root_path}"
    hive = _registry_hive(display_hive)
    root_exists, state = registry_policy_root_access_state(
        display_hive,
        root_path,
    )

    if not root_exists and state in {"Absent", "Empty"}:
        return True, "Already absent"

    if not root_exists:
        return False, state

    try:
        remove_registry_key_tree(
            hive,
            root_path,
        )
    except (
        PermissionError,
        OSError,
    ) as exc:
        logger.warn(
            f"Normal Registry policy removal failed for {full_path}: {exc}"
        )
        return False, str(exc)

    verified, verification_state = registry_policy_root_access_state(
        display_hive,
        root_path,
    )
    if verified:
        return False, "The Registry policy root still exists after deletion."
    if verification_state != "Absent":
        return False, (
            "The Registry policy root could not be verified as absent: "
            f"{verification_state}"
        )

    logger.info(
        f"Removed Registry policy root: {full_path}"
    )
    return True, "Removed successfully"


def force_remove_registry_policy_root(
    display_hive: str,
    root_path: str,
    logger: Logger,
) -> tuple[bool, str]:
    full_path = f"{display_hive}\\{root_path}"
    root_exists, state = registry_policy_root_access_state(
        display_hive,
        root_path,
    )

    if not root_exists and state in {"Absent", "Empty"}:
        return True, "Already absent"

    if not root_exists:
        return False, state

    privilege_ok = _enable_process_privileges(
        (
            "SeTakeOwnershipPrivilege",
            "SeBackupPrivilege",
            "SeRestorePrivilege",
        ),
        logger,
    )
    if not privilege_ok:
        logger.warn(
            f"One or more Windows privileges could not be enabled for {full_path}."
        )

    repaired, security_backups, repair_reason = (
        _repair_registry_tree_permissions(
            display_hive,
            root_path,
            logger,
        )
    )
    if not repaired:
        restore_failures = _restore_registry_tree_security(
            security_backups,
            display_hive,
            logger,
        )
        restore_reason = repair_reason
        if restore_failures:
            restore_reason += (
                "; security restoration failures: "
                + "; ".join(restore_failures)
            )

        logger.error(
            f"Forced Registry permission repair failed for {full_path}: "
            f"{restore_reason}"
        )
        return False, restore_reason

    try:
        remove_registry_key_tree(
            _registry_hive(display_hive),
            root_path,
        )
    except (PermissionError, OSError) as exc:
        deletion_reason = str(exc)
        restore_failures = _restore_registry_tree_security(
            security_backups,
            display_hive,
            logger,
        )
        if restore_failures:
            deletion_reason += (
                "; security restoration failures: "
                + "; ".join(restore_failures)
            )

        logger.error(
            f"Forced Registry policy removal failed for {full_path}: "
            f"{deletion_reason}"
        )
        return False, deletion_reason

    verified, verification_state = registry_policy_root_access_state(
        display_hive,
        root_path,
    )
    if not verified and verification_state in {"Absent", "Empty"}:
        logger.info(
            f"Forced Registry policy removal succeeded: {full_path}"
        )
        return True, "Removed successfully after controlled permission repair"

    restore_failures = _restore_registry_tree_security(
        security_backups,
        display_hive,
        logger,
    )
    reason = (
        "The Registry policy root still contains policy data after "
        "permission-assisted deletion."
    )
    if verification_state != "Present":
        reason += f" Verification state: {verification_state}."
    if restore_failures:
        reason += (
            "; security restoration failures: "
            + "; ".join(restore_failures)
        )

    logger.error(
        f"Forced Registry policy removal failed for {full_path}: {reason}"
    )
    return False, reason

def backup_registry(
    session: Session,
    logger: Logger,
) -> tuple[bool, list[str]]:
    directory = (
        session.directory / "Registry"
    )
    directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    created: list[str] = []
    backup_ok = True

    if not command_exists("reg.exe"):
        logger.error(
            "reg.exe was not found. Registry backup cannot continue."
        )
        return False, created

    for display_hive, root_path in POLICY_REGISTRY_ROOTS:
        base_name = _registry_backup_name(
            display_hive,
            root_path,
        )
        destination = (
            directory
            / f"{base_name}.reg"
        )
        absent_marker = (
            directory
            / f"{base_name}.absent"
        )

        full_path = f"{display_hive}\\{root_path}"
        root_exists, state = registry_policy_root_access_state(
            display_hive,
            root_path,
        )

        if not root_exists and state == "Absent":
            absent_marker.write_text(
                f"Registry root was absent at backup time: {full_path}\\n",
                encoding="utf-8",
            )
            created.append(str(absent_marker))
            logger.info(
                f"Registry root already absent; recorded backup state: {full_path}"
            )
            continue

        if not root_exists:
            logger.error(
                f"Could not read Registry backup state for {full_path}: {state}"
            )
            backup_ok = False
            continue

        code, stdout, stderr = run_command(
            [
                "reg.exe",
                "export",
                full_path,
                str(destination),
                "/y",
            ],
            timeout=90,
        )

        if (
            code == 0
            and destination.exists()
        ):
            created.append(str(destination))
            logger.info(
                f"Registry backup created: {destination}"
            )
        else:
            logger.error(
                f"Registry backup failed for "
                f"{full_path}: "
                f"{stderr.strip() or stdout.strip() or 'unknown error'}"
            )
            backup_ok = False

    return backup_ok, created


def backup_local_group_policy(
    session: Session,
    logger: Logger,
) -> tuple[bool, list[str]]:
    directory = (
        session.directory / "LocalGroupPolicy"
    )
    directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    backed_up: list[str] = []

    for source in LOCAL_GPO_DIRECTORIES:
        destination = (
            directory / source.name
        )

        if not source.exists():
            # Record the absence because it is a valid state.
            marker = (
                destination.parent
                / f"{source.name}.absent"
            )
            marker.write_text(
                f"Source not present at backup time: {source}\n",
                encoding="utf-8",
            )
            continue

        try:
            shutil.copytree(
                source,
                destination,
            )
            backed_up.append(str(destination))
            logger.info(
                f"Local Group Policy backup created: {destination}"
            )
        except OSError as exc:
            logger.error(
                f"Could not back up {source}: {exc}"
            )
            return False, backed_up

    return True, backed_up


def create_backup(
    session: Session,
    logger: Logger,
) -> bool:
    logger.info(
        "Creating backup before policy removal..."
    )

    registry_backup_ok, registry_backups = backup_registry(
        session,
        logger,
    )

    gpo_backup_ok, gpo_backups = (
        backup_local_group_policy(
            session,
            logger,
        )
    )

    manifest = {
        "created_at": timestamp(),
        "registry_backups": registry_backups,
        "registry_backup_success": registry_backup_ok,
        "local_group_policy_backups": gpo_backups,
        "local_group_policy_backup_success": gpo_backup_ok,
        "backup_success": registry_backup_ok and gpo_backup_ok,
    }

    path = (
        session.directory
        / "backup-manifest.json"
    )
    path.write_text(
        json.dumps(
            manifest,
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    if not registry_backup_ok:
        logger.error(
            "Registry policy backup did not complete."
        )

    if not gpo_backup_ok:
        logger.error(
            "Local Group Policy backup did not complete."
        )

    if not registry_backup_ok or not gpo_backup_ok:
        return False

    logger.info(
        f"Backup manifest saved to {path}."
    )

    return True


def confirm_yes_no(
    question: str,
) -> bool:
    while True:
        answer = input(
            f"{question} (Y/N): "
        ).strip().lower()

        if answer in {"y", "yes"}:
            return True

        if answer in {"n", "no"}:
            return False

        print(
            "Please answer Yes (Y) or No (N)."
        )


def remove_directory_normal(
    directory: Path,
    logger: Logger,
) -> tuple[bool, str]:
    if not directory.exists():
        return True, "Already absent"

    try:
        shutil.rmtree(directory)
    except OSError as exc:
        logger.warn(
            f"Normal removal failed for {directory}: {exc}"
        )
        return False, str(exc)

    if directory.exists():
        return False, (
            "The directory still exists after deletion."
        )

    logger.info(
        f"Removed local Group Policy store: {directory}"
    )
    return True, "Removed successfully"


def force_remove_directory(
    directory: Path,
    logger: Logger,
) -> tuple[bool, str]:
    if not directory.exists():
        return True, "Already absent"

    errors: list[str] = []

    if command_exists("rmdir"):
        code, stdout, stderr = run_command(
            [
                "cmd.exe",
                "/d",
                "/c",
                "rmdir",
                "/s",
                "/q",
                str(directory),
            ],
            timeout=120,
        )

        if not directory.exists():
            logger.info(
                f"Forced local Group Policy removal succeeded: {directory}"
            )
            return True, "Removed successfully"

        errors.append(
            stderr.strip()
            or stdout.strip()
            or f"rmdir exit code {code}"
        )

    if command_exists("takeown.exe"):
        _, stdout, stderr = run_command(
            [
                "takeown.exe",
                "/f",
                str(directory),
                "/r",
                "/d",
                "Y",
            ],
            timeout=180,
        )
        if stderr.strip():
            errors.append(
                f"takeown: {stderr.strip()}"
            )
        elif stdout.strip():
            logger.info(
                stdout.strip()
            )

    if command_exists("icacls.exe"):
        _, stdout, stderr = run_command(
            [
                "icacls.exe",
                str(directory),
                "/grant",
                "*S-1-5-32-544:F",
                "/t",
                "/c",
            ],
            timeout=180,
        )
        if stderr.strip():
            errors.append(
                f"icacls: {stderr.strip()}"
            )
        elif stdout.strip():
            logger.info(
                stdout.strip()
            )

    code, stdout, stderr = run_command(
        [
            "cmd.exe",
            "/d",
            "/c",
            "rmdir",
            "/s",
            "/q",
            str(directory),
        ],
        timeout=120,
    )

    if not directory.exists():
        logger.info(
            "Forced removal succeeded after "
            f"permission repair: {directory}"
        )
        return True, "Removed successfully after forced permission repair"

    errors.append(
        stderr.strip()
        or stdout.strip()
        or f"final rmdir exit code {code}"
    )

    reason = "; ".join(
        item for item in errors if item
    ) or "Unknown deletion error"

    logger.error(
        f"Force removal failed for {directory}: {reason}"
    )

    return False, reason


def refresh_group_policy(
    session: Session,
    logger: Logger,
) -> bool:
    """Refresh both Computer and User Group Policy with gpupdate /force."""
    if not command_exists("gpupdate.exe"):
        logger.error("gpupdate.exe was not found.")
        return False

    code, stdout, stderr = run_command(
        ["gpupdate.exe", "/force"],
        timeout=300,
    )

    output_file = session.directory / "gpupdate.txt"
    output_file.write_text(
        f"Exit code: {code}\n\n"
        f"STDOUT:\n{stdout}\n\n"
        f"STDERR:\n{stderr}\n",
        encoding="utf-8",
    )
    logger.info(
        f"gpupdate output saved to {output_file}."
    )

    if code == 0:
        logger.info("gpupdate /force completed successfully.")
        return True

    logger.error(
        f"gpupdate /force failed with exit code {code}."
    )
    return False

def local_gpo_status() -> dict[str, Any]:
    present = [
        str(path)
        for path in LOCAL_GPO_DIRECTORIES
        if path.exists()
    ]

    return {
        "remaining_stores": present,
        "remaining_count": len(present),
    }


def write_reset_report(
    session: Session,
    before: dict[str, Any],
    after: dict[str, Any],
    failures: list[RemovalFailure],
    forced_removed: list[str],
    still_failed: list[RemovalFailure],
    gpupdate_ok: bool | None,
    management: ManagementState,
    applied_objects: list[str],
    applied_objects_source: str,
    already_absent: list[str],
    registry_before: list[PolicyEntry],
    registry_after: list[PolicyEntry],
    registry_removed: list[str],
    registry_already_absent: list[str],
    registry_failures: list[RemovalFailure],
    registry_forced_removed: list[str],
    registry_still_failed: list[RemovalFailure],
    registry_roots_before: list[str],
    registry_roots_after: list[str],
) -> Path:
    data = {
        "application": APP_NAME,
        "version": VERSION,
        "completed_at": timestamp(),
        "before": before,
        "after": after,
        "normal_removal_failures": [
            asdict(item)
            for item in failures
        ],
        "forced_removals": forced_removed,
        "already_absent": already_absent,
        "remaining_failures": [
            asdict(item)
            for item in still_failed
        ],
        "registry_policy_roots_before": registry_roots_before,
        "registry_policy_roots_removed": registry_removed,
        "registry_policy_roots_already_absent": registry_already_absent,
        "registry_policy_root_failures": [
            asdict(item)
            for item in registry_failures
        ],
        "registry_policy_roots_forced_removed": registry_forced_removed,
        "registry_policy_roots_still_failed": [
            asdict(item)
            for item in registry_still_failed
        ],
        "registry_policy_roots_after": registry_roots_after,
        "gpupdate_succeeded": gpupdate_ok,
        "gpupdate_scope": (
            "not_run_during_reset"
            if gpupdate_ok is None
            else "run_during_operation"
        ),
        "operation_succeeded": (
            not still_failed
            and not after["remaining_stores"]
            and not registry_still_failed
            and not registry_roots_after
        ),
        "management": asdict(management),
        "applied_group_policy_objects_reported": applied_objects,
        "applied_group_policy_objects_source": applied_objects_source,
        "registry_policy_values_before": [
            item.full_path for item in registry_before
        ],
        "registry_policy_values_after": [
            item.full_path for item in registry_after
        ],
        "registry_policy_values_remaining": [
            item.full_path for item in registry_after
        ],
        "restart_recommended": bool(
            (
                before["remaining_count"] > 0
                or registry_before
            )
            and not still_failed
            and not after["remaining_stores"]
            and not registry_still_failed
            and not registry_roots_after
        ),
    }

    path = (
        session.directory
        / "local_gpo_reset.json"
    )
    path.write_text(
        json.dumps(
            data,
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    return path


def show_removal_result(
    removed: list[str],
    failures: list[RemovalFailure],
    forced_removed: list[str],
    still_failed: list[RemovalFailure],
    gpupdate_ok: bool | None,
    remaining_stores: list[str],
    applied_objects: list[str],
    applied_objects_source: str,
    report: Path,
    before_count: int,
    already_absent: list[str],
    registry_before_count: int,
    registry_after_count: int,
    registry_removed: list[str],
    registry_already_absent: list[str],
    registry_failures: list[RemovalFailure],
    registry_forced_removed: list[str],
    registry_still_failed: list[RemovalFailure],
    registry_roots_after: list[str],
) -> None:
    print()
    print("=" * 78)

    operation_clear = (
        not still_failed
        and not remaining_stores
        and not registry_still_failed
        and not registry_roots_after
    )

    if before_count == 0 and registry_before_count == 0 and operation_clear:
        print("LOCAL GROUP POLICY ALREADY CLEAR")
    elif operation_clear:
        print("GROUP POLICIES REMOVED SUCCESSFULLY")
    elif still_failed or registry_still_failed or remaining_stores or registry_roots_after:
        print("GROUP POLICY REMOVAL COMPLETED WITH ERRORS")
    else:
        print("GROUP POLICY REMOVAL COMPLETED")

    print("=" * 78)

    print("\nLocal Group Policy")
    print(
        f"  Removed successfully: {len(removed) + len(forced_removed)}"
    )
    print(f"  Removal failed: {len(still_failed)}")
    print(
        "  Status: "
        + ("Already clear" if not remaining_stores else "Not clear")
    )
    print(f"  Stores remaining: {len(remaining_stores)}")

    if failures:
        print("\nNormal removal failures")
        for item in failures:
            print(f"  [FAIL] {item.path}")
            print(f"         {item.reason}")

    if forced_removed:
        print("\nForced Local Group Policy removal")
        for item in forced_removed:
            print(f"  [OK] {item}")

    if still_failed:
        print("\nLocal Group Policy stores still not removed")
        for item in still_failed:
            print(f"  [FAIL] {item.path}")
            print(f"         {item.reason}")

    print("\nRegistry policy roots")
    print(f"  Present before reset: {registry_before_count > 0}")
    print(f"  Removed successfully: {len(registry_removed) + len(registry_forced_removed)}")
    print(f"  Already absent: {len(registry_already_absent)}")
    print(f"  Removal failed: {len(registry_still_failed)}")

    if registry_failures:
        print("\nNormal Registry removal failures")
        for item in registry_failures:
            print(f"  [FAIL] {item.path}")
            print(f"         {item.reason}")

    if registry_forced_removed:
        print("\nForced Registry policy removal")
        for item in registry_forced_removed:
            print(f"  [OK] {item}")

    if registry_still_failed:
        print("\nRegistry policy roots still present")
        for item in registry_still_failed:
            print(f"  [FAIL] {item.path}")
            print(f"         {item.reason}")

    print(f"  Registry policy locations with data remaining: {len(registry_roots_after)}")

    print("\nGroup Policy refresh")
    if gpupdate_ok is None:
        print("  gpupdate /force: Not run during reset")
        print("  The reset deliberately does not reapply Group Policy.")
    else:
        print(
            "  gpupdate /force: "
            f"{'Successful' if gpupdate_ok else 'Failed'}"
        )

    print("\nVerification")
    if remaining_stores:
        for path in remaining_stores:
            print(f"  [FAIL] Local Group Policy store remains: {path}")
    else:
        print(
            "  [OK] Both local Group Policy stores are absent."
        )

    if registry_roots_after:
        for path in registry_roots_after:
            print(f"  [FAIL] Registry policy data remains at: {path}")
    else:
        print(
            "  [OK] All targeted Registry policy locations are clear of policy data."
        )

    if applied_objects:
        print("\nApplied Group Policy objects reported by gpresult:")
        for item in applied_objects:
            print(f"  - {item}")
        print(
            "\nRemote or organisation-controlled objects are "
            "outside the local reset scope."
        )
    elif applied_objects_source == "xml":
        print("\nApplied Group Policy objects reported by gpresult: 0")
    elif applied_objects_source == "not_collected":
        print("\nApplied Group Policy objects: Not collected during reset.")
        print("  Run DIAGNOSE GROUP POLICY for a current gpresult report.")
    elif applied_objects_source == "parse_failed":
        print("\nWARNING: The gpresult XML could not be parsed. Review gpresult.xml.")
    elif applied_objects_source == "no_result_sections":
        print("\nWARNING: gpresult.xml did not contain UserResults or ComputerResults.")
    else:
        print("\nApplied Group Policy objects could not be collected.")

    print("\nRegistry policy values")
    print(f"  Before reset: {registry_before_count}")
    print(f"  After reset: {registry_after_count}")

    print()
    operation_success = (
        not still_failed
        and not remaining_stores
        and not registry_still_failed
        and not registry_roots_after
    )

    if (
        before_count == 0
        and registry_before_count == 0
        and operation_success
    ):
        print("No targeted Local Group Policy data was present before the operation.")
    elif operation_success:
        print("Local Group Policy and targeted Registry policy roots removed successfully.")
        print("Restart Windows before final verification.")
    else:
        print("Some Local Group Policy or Registry policy data could not be fully removed.")
        print("Review the failure details above and retry the failed operation.")

    print(f"\nReport: {report}")


def diagnose(
    session: Session,
    logger: Logger,
) -> None:
    print()
    print("=" * 78)
    print("GROUP POLICY DIAGNOSIS")
    print("=" * 78)

    system = system_summary()
    management = detect_management_state()
    registry_entries = scan_policy_registry(logger)
    gpresult = collect_gpresult(
        session,
        logger,
    )

    print()
    print("System")
    print(
        f"  Computer: {system['computer']}"
    )
    print(
        f"  User: {system['user']}"
    )
    print(
        f"  Administrator: {system['administrator']}"
    )

    print()
    print("Management indicators")
    print(
        f"  Active Directory joined: "
        f"{management.domain_joined}"
    )
    print(
        f"  Microsoft Entra ID joined: "
        f"{management.entra_joined}"
    )
    print(
        f"  Enterprise joined: "
        f"{management.enterprise_joined}"
    )
    print(
        f"  MDM discovery URL present: "
        f"{management.mdm_discovery_url_present}"
    )
    print(
        f"  Management Registry locations: "
        f"{len(management.registry_management_locations)}"
    )

    print()
    print("Local Group Policy stores")
    status = local_gpo_status()
    if status["remaining_stores"]:
        for path in status["remaining_stores"]:
            print(f"  [PRESENT] {path}")
    else:
        print(
            "  [OK] Both local stores are absent."
        )

    print()
    print(
        f"Registry policy values found: "
        f"{len(registry_entries)}"
    )

    applied_objects, applied_objects_source = (
        extract_applied_group_policy_objects(gpresult)
    )

    if applied_objects:
        print("\nApplied Group Policy objects reported by gpresult:")
        for item in applied_objects:
            print(f"  - {item}")
    elif applied_objects_source == "xml":
        print("\nApplied Group Policy objects reported by gpresult: 0")
    elif applied_objects_source == "parse_failed":
        print("\nWARNING: The gpresult XML could not be parsed. Review gpresult.xml.")
    elif applied_objects_source == "no_result_sections":
        print("\nWARNING: gpresult.xml did not contain UserResults or ComputerResults.")
    else:
        print("\nApplied Group Policy objects could not be collected.")

    if management.organisation_managed_indicator:
        print()
        print(
            "WARNING: an organisation-management indicator "
            "was detected."
        )
        print(
            "The local reset cannot remove remote policy."
        )

    report = (
        session.directory
        / "diagnostic.json"
    )

    report.write_text(
        json.dumps(
            {
                "application": APP_NAME,
                "version": VERSION,
                "created_at": timestamp(),
                "system": system,
                "management": asdict(
                    management
                ),
                "local_gpo_status": status,
                "registry_policy_value_count": len(
                    registry_entries
                ),
                "gpresult": gpresult,
                "applied_group_policy_objects": applied_objects,
                "applied_group_policy_objects_source": applied_objects_source,
            },
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    logger.info(
        f"Diagnostic report saved to {report}."
    )

    input(
        "\nPress Enter to return to the main menu..."
    )


def remove_all_local_group_policy(
    session: Session,
    logger: Logger,
) -> None:
    print()
    print("=" * 78)
    print("REMOVE LOCAL GROUP POLICY")
    print("=" * 78)
    print()
    print(
        "This removes Local Group Policy and its targeted Registry policy roots for:"
    )
    print(
        "  - Computer"
    )
    print(
        "  - User"
    )
    print()
    print(
        "A backup will be created before any removal."
    )
    print(
        "The Registry cleanup targets the same four policy roots used by "
        "the original PolicyReset script."
    )
    print(
        "Remote Active Directory, Microsoft Entra ID and MDM "
        "policy are outside the scope of this operation."
    )
    print()
    print(
        "WARNING: Registry policy roots are deleted recursively after backup."
    )
    print(
        "Existing values under these four roots may be removed."
    )
    print()

    management = detect_management_state()

    if management.organisation_managed_indicator:
        print(
            "Warning: organisation-level management indicators "
            "were detected."
        )
        print(
            "Local removal may succeed while remote policy "
            "is later reapplied."
        )
        print()

    if not confirm_yes_no(
        "Continue with Local Group Policy removal and backup?"
    ):
        logger.info(
            "Local Group Policy removal cancelled."
        )
        print(
            "\nOperation cancelled."
        )
        input(
            "\nPress Enter to return to the main menu..."
        )
        return

    before = local_gpo_status()
    registry_before = scan_policy_registry(logger)
    registry_roots_before = registry_policy_root_status()

    if not create_backup(
        session,
        logger,
    ):
        print()
        print(
            "Backup failed. No Group Policy removal was performed."
        )
        input(
            "\nPress Enter to return to the main menu..."
        )
        return

    removed: list[str] = []
    already_absent: list[str] = []
    failures: list[RemovalFailure] = []

    for directory in LOCAL_GPO_DIRECTORIES:
        if not directory.exists():
            already_absent.append(str(directory))
            continue

        success, reason = remove_directory_normal(
            directory,
            logger,
        )

        if success:
            removed.append(str(directory))
        else:
            failures.append(
                RemovalFailure(
                    path=str(directory),
                    reason=reason,
                )
            )

    forced_removed: list[str] = []
    still_failed: list[RemovalFailure] = []

    if failures:
        print()
        print(
            f"{len(failures)} local Group Policy store(s) "
            "could not be removed normally."
        )

        if confirm_yes_no(
            "Force removal of the failed local Group Policy stores?"
        ):
            for failure in failures:
                success, reason = (
                    force_remove_directory(
                        Path(failure.path),
                        logger,
                    )
                )

                if success:
                    forced_removed.append(
                        failure.path
                    )
                else:
                    still_failed.append(
                        RemovalFailure(
                            path=failure.path,
                            reason=reason,
                        )
                    )
        else:
            still_failed = failures

    registry_removed: list[str] = []
    registry_already_absent: list[str] = []
    registry_failures: list[RemovalFailure] = []

    for display_hive, root_path in POLICY_REGISTRY_ROOTS:
        full_path = f"{display_hive}\\{root_path}"
        success, reason = remove_registry_policy_root(
            display_hive,
            root_path,
            logger,
        )

        if success and reason == "Already absent":
            registry_already_absent.append(full_path)
        elif success:
            registry_removed.append(full_path)
        else:
            registry_failures.append(
                RemovalFailure(
                    path=full_path,
                    reason=reason,
                )
            )

    registry_forced_removed: list[str] = []
    registry_still_failed: list[RemovalFailure] = []

    if registry_failures:
        print()
        print(
            f"{len(registry_failures)} Registry policy root(s) "
            "could not be removed normally."
        )

        if confirm_yes_no(
            "Force removal of the failed Registry policy roots?"
        ):
            for failure in registry_failures:
                hive, root_path = failure.path.split("\\", 1)
                success, reason = force_remove_registry_policy_root(
                    hive,
                    root_path,
                    logger,
                )

                if success:
                    registry_forced_removed.append(
                        failure.path
                    )
                else:
                    registry_still_failed.append(
                        RemovalFailure(
                            path=failure.path,
                            reason=reason,
                        )
                    )
        else:
            registry_still_failed = registry_failures

    print()
    print(
        "Verifying Local Group Policy and Registry policy roots..."
    )

    after = local_gpo_status()
    registry_after = scan_policy_registry(logger)
    registry_roots_after = registry_policy_root_status()

    report = write_reset_report(
        session,
        before,
        after,
        failures,
        forced_removed,
        still_failed,
        None,
        management,
        [],
        "not_collected",
        already_absent,
        registry_before,
        registry_after,
        registry_removed,
        registry_already_absent,
        registry_failures,
        registry_forced_removed,
        registry_still_failed,
        registry_roots_before,
        registry_roots_after,
    )

    show_removal_result(
        removed,
        failures,
        forced_removed,
        still_failed,
        None,
        after["remaining_stores"],
        [],
        "not_collected",
        report,
        before["remaining_count"],
        already_absent,
        len(registry_before),
        len(registry_after),
        registry_removed,
        registry_already_absent,
        registry_failures,
        registry_forced_removed,
        registry_still_failed,
        registry_roots_after,
    )

    input(
        "\nPress Enter to return to the main menu..."
    )


def write_json_report(
    session: Session,
    filename: str,
    data: dict[str, Any],
) -> Path:
    """Write an operation report as UTF-8 JSON."""
    path = session.directory / filename
    path.write_text(
        json.dumps(data, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    return path


def write_restore_report(
    session: Session,
    selected: Path,
    before: dict[str, Any],
    after: dict[str, Any],
    restore_errors: list[str],
    gpupdate_ok: bool,
    expected_present: list[str],
    expected_registry_roots: list[str],
    actual_registry_roots: list[str],
) -> Path:
    state_matches = set(after["remaining_stores"]) == set(expected_present)
    registry_state_matches = (
        set(actual_registry_roots) == set(expected_registry_roots)
    )
    operation_succeeded = (
        not restore_errors
        and state_matches
        and registry_state_matches
        and gpupdate_ok
    )
    data = {
        "application": APP_NAME,
        "version": VERSION,
        "operation": "restore_local_group_policy",
        "completed_at": timestamp(),
        "source_backup": str(selected),
        "expected_present_stores": expected_present,
        "before": before,
        "after": after,
        "expected_registry_policy_roots": expected_registry_roots,
        "actual_registry_policy_roots": actual_registry_roots,
        "restore_errors": restore_errors,
        "gpupdate_succeeded": gpupdate_ok,
        "verification_passed": state_matches and registry_state_matches,
        "local_gpo_verification_passed": state_matches,
        "registry_verification_passed": registry_state_matches,
        "operation_succeeded": operation_succeeded,
    }
    return write_json_report(session, "restore.json", data)


def write_refresh_report(
    session: Session,
    gpupdate_ok: bool,
) -> Path:
    data = {
        "application": APP_NAME,
        "version": VERSION,
        "operation": "refresh_group_policy",
        "completed_at": timestamp(),
        "gpupdate_succeeded": gpupdate_ok,
        "output_file": str(session.directory / "gpupdate.txt"),
    }
    return write_json_report(session, "gpupdate.json", data)


def find_backup_sessions() -> list[Path]:
    """Return PolicyReset sessions that contain backup artefacts."""
    if not SESSION_ROOT.exists():
        return []

    sessions: list[Path] = []

    for path in SESSION_ROOT.iterdir():
        if not path.is_dir():
            continue

        if any(
            (path / artefact).exists()
            for artefact in BACKUP_ARTIFACT_NAMES
        ):
            sessions.append(path)

    return sorted(
        sessions,
        key=lambda path: path.name,
        reverse=True,
    )


def delete_all_backups(
    logger: Logger,
) -> None:
    """Delete all PolicyReset backup artefacts while preserving reports and logs."""
    sessions = find_backup_sessions()

    print()
    print("=" * 78)
    print("DELETE ALL POLICYRESET BACKUPS")
    print("=" * 78)
    print()

    if not sessions:
        print("No PolicyReset backup sessions were found.")
        input("\nPress Enter to return to the main menu...")
        return

    print(
        f"Backup sessions found: {len(sessions)}"
    )
    print(
        "This operation deletes only the PolicyReset backup artefacts:"
    )
    print(
        "  - LocalGroupPolicy"
    )
    print(
        "  - Registry"
    )
    print(
        "  - backup-manifest.json"
    )
    print(
        "Diagnostic reports, operation reports and log files are preserved."
    )
    print()

    if not confirm_yes_no(
        "Delete all PolicyReset backup artefacts?"
    ):
        logger.info(
            "Deletion of all PolicyReset backups cancelled."
        )
        print(
            "\nOperation cancelled."
        )
        input(
            "\nPress Enter to return to the main menu..."
        )
        return

    removed_sessions = 0
    removed_artefacts = 0
    failures: list[str] = []

    for session in sessions:
        session_failed = False

        for artefact_name in BACKUP_ARTIFACT_NAMES:
            target = session / artefact_name

            if not target.exists():
                continue

            try:
                if target.is_dir():
                    shutil.rmtree(target)
                else:
                    target.unlink()

                removed_artefacts += 1
                logger.info(
                    f"Deleted backup artefact: {target}"
                )
            except OSError as exc:
                session_failed = True
                failures.append(
                    f"{target}: {exc}"
                )
                logger.error(
                    f"Could not delete backup artefact {target}: {exc}"
                )

        if not session_failed:
            try:
                if session.exists() and not any(session.iterdir()):
                    session.rmdir()
                    removed_sessions += 1
                    logger.info(
                        f"Removed empty backup session directory: {session}"
                    )
            except OSError as exc:
                failures.append(
                    f"{session}: {exc}"
                )
                logger.error(
                    f"Could not remove empty backup session directory {session}: {exc}"
                )

    print()
    print("=" * 78)
    if failures:
        print("BACKUP DELETION COMPLETED WITH ERRORS")
    else:
        print("ALL POLICYRESET BACKUPS DELETED")
    print("=" * 78)
    print()
    print(f"Backup artefacts deleted: {removed_artefacts}")
    print(f"Empty backup session directories removed: {removed_sessions}")
    print(f"Deletion failures: {len(failures)}")

    if failures:
        print()
        print("Failures")
        for failure in failures:
            print(f"  [FAIL] {failure}")

    print()
    if failures:
        print(
            "Some backup artefacts could not be deleted. "
            "The remaining reports and logs were preserved."
        )
    else:
        print(
            "All PolicyReset backup artefacts were removed. "
            "Diagnostic reports, operation reports and logs were preserved."
        )

    input(
        "\nPress Enter to return to the main menu..."
    )


def restore_backup(
    logger: Logger,
) -> None:
    sessions = (
        sorted(
            (
                path
                for path in SESSION_ROOT.iterdir()
                if path.is_dir()
                and (path / "LocalGroupPolicy").exists()
            ),
            key=lambda path: path.name,
            reverse=True,
        )
        if SESSION_ROOT.exists()
        else []
    )

    if not sessions:
        print("\nNo PolicyReset backup sessions were found.")
        input("\nPress Enter to return to the main menu...")
        return

    print()
    print("=" * 78)
    print("RESTORE GROUP POLICY BACKUP")
    print("=" * 78)
    print()

    for index, path in enumerate(sessions, start=1):
        print(f"[{index}] {path.name}")

    print()
    print("Press Enter to cancel.")
    raw = input("Select backup: ").strip()

    if not raw:
        logger.info("Backup restoration cancelled.")
        return

    try:
        selected = sessions[int(raw) - 1]
    except (ValueError, IndexError):
        print("\nInvalid selection.")
        input("\nPress Enter to return to the main menu...")
        return

    backup_root = selected / "LocalGroupPolicy"
    registry_backup_root = selected / "Registry"

    if not backup_root.exists():
        print("\nThe selected session does not contain a Local Group Policy backup.")
        input("\nPress Enter to return to the main menu...")
        return

    expected_present = [
        str(directory)
        for directory in LOCAL_GPO_DIRECTORIES
        if (backup_root / directory.name).is_dir()
    ]

    registry_backup_states: dict[str, Path] = {}

    if registry_backup_root.exists():
        for display_hive, root_path in POLICY_REGISTRY_ROOTS:
            base_name = _registry_backup_name(
                display_hive,
                root_path,
            )
            exported = registry_backup_root / f"{base_name}.reg"
            absent_marker = registry_backup_root / f"{base_name}.absent"

            if exported.exists():
                registry_backup_states[
                    f"{display_hive}\\{root_path}"
                ] = exported
            elif absent_marker.exists():
                registry_backup_states[
                    f"{display_hive}\\{root_path}"
                ] = absent_marker

    expected_registry_roots = [
        path
        for path, backup_state in registry_backup_states.items()
        if backup_state.suffix.lower() == ".reg"
    ]

    print()
    print(f"Backup selected: {selected.name}")
    if expected_present:
        print("Restoration will replace the current local Group Policy stores:")
        for path in expected_present:
            print(f"  - {path}")
    else:
        print(
            "The selected backup contains no Local Group Policy stores. "
            "Restoration will leave both stores absent."
        )

    print()
    print("Registry policy roots will be restored to the backup state.")
    print(f"  Exported roots available: {len(expected_registry_roots)}")
    print(
        "  Older backups without Registry state markers may not contain "
        "enough information for exact Registry restoration."
    )

    if not confirm_yes_no("Continue with backup restoration?"):
        logger.info("Backup restoration cancelled.")
        return

    session = create_session()
    before = local_gpo_status()

    if not create_backup(session, logger):
        print("\nSafety backup failed. Restoration was cancelled.")
        input("\nPress Enter to return to the main menu...")
        return

    restore_errors: list[str] = []

    for directory in LOCAL_GPO_DIRECTORIES:
        current = directory
        backup = backup_root / directory.name

        if current.exists():
            success, reason = remove_directory_normal(current, logger)
            if not success:
                restore_errors.append(
                    f"{current}: could not replace current store: {reason}"
                )
                continue

        if backup.exists():
            try:
                shutil.copytree(backup, current)
                logger.info(f"Restored local Group Policy store: {current}")
            except OSError as exc:
                restore_errors.append(f"{current}: {exc}")

    for display_hive, root_path in POLICY_REGISTRY_ROOTS:
        full_path = f"{display_hive}\\{root_path}"
        backup_state = registry_backup_states.get(full_path)

        if backup_state is None:
            restore_errors.append(
                f"{full_path}: Registry backup state is unavailable."
            )
            continue

        current_exists, current_state = registry_policy_root_access_state(
            display_hive,
            root_path,
        )
        if current_exists or current_state != "Absent":
            success, reason = remove_registry_policy_root(
                display_hive,
                root_path,
                logger,
            )
            if not success:
                success, reason = force_remove_registry_policy_root(
                    display_hive,
                    root_path,
                    logger,
                )
            if not success:
                restore_errors.append(
                    f"{full_path}: could not clear current Registry root: {reason}"
                )
                continue

        if backup_state.suffix.lower() == ".reg":
            if not command_exists("reg.exe"):
                restore_errors.append(
                    f"{full_path}: reg.exe was not found."
                )
                continue

            code, stdout, stderr = run_command(
                [
                    "reg.exe",
                    "import",
                    str(backup_state),
                ],
                timeout=120,
            )

            if code == 0:
                logger.info(
                    f"Restored Registry policy root from backup: {full_path}"
                )
            else:
                restore_errors.append(
                    f"{full_path}: Registry import failed: "
                    f"{stderr.strip() or stdout.strip() or f'reg import exit code {code}'}"
                )

    after = local_gpo_status()
    expected_set = set(expected_present)
    actual_set = set(after["remaining_stores"])

    if actual_set != expected_set:
        missing = sorted(expected_set - actual_set)
        unexpected = sorted(actual_set - expected_set)
        if missing:
            restore_errors.append(
                "Expected stores were not restored: " + "; ".join(missing)
            )
        if unexpected:
            restore_errors.append(
                "Unexpected stores remain: " + "; ".join(unexpected)
            )

    expected_registry_set = set(expected_registry_roots)
    actual_registry_set = set(registry_policy_root_status())

    if actual_registry_set != expected_registry_set:
        missing = sorted(expected_registry_set - actual_registry_set)
        unexpected = sorted(actual_registry_set - expected_registry_set)
        if missing:
            restore_errors.append(
                "Expected Registry policy roots were not restored: "
                + "; ".join(missing)
            )
        if unexpected:
            restore_errors.append(
                "Unexpected Registry policy roots remain: "
                + "; ".join(unexpected)
            )

    restored_state_matches = not restore_errors
    gpupdate_ok = refresh_group_policy(session, logger)
    report = write_restore_report(
        session,
        selected,
        before,
        after,
        restore_errors,
        gpupdate_ok,
        expected_present,
        expected_registry_roots,
        sorted(actual_registry_set),
    )

    print()
    print("=" * 78)
    if restored_state_matches and gpupdate_ok:
        print("GROUP POLICY BACKUP RESTORED SUCCESSFULLY")
    else:
        print("GROUP POLICY BACKUP RESTORATION COMPLETED WITH ERRORS")
    print("=" * 78)

    if restore_errors:
        print("\nErrors")
        for error in restore_errors:
            print(f"  [FAIL] {error}")

    print(
        "\nLocal Group Policy stores: "
        f"{'Verified' if set(after['remaining_stores']) == expected_set else 'Not verified'}"
    )
    print(
        "Registry policy roots: "
        f"{'Verified' if actual_registry_set == expected_registry_set else 'Not verified'}"
    )
    print(f"gpupdate /force: {'Successful' if gpupdate_ok else 'Failed'}")
    print(f"\nSafety backup created in: {session.directory}")
    print(f"Restore report: {report}")

    input("\nPress Enter to return to the main menu...")


def show_latest_report() -> None:
    candidates = (
        sorted(
            (
                path
                for pattern in ("diagnostic.json", "local_gpo_reset.json", "restore.json", "gpupdate.json")
                for path in SESSION_ROOT.glob(f"*/{pattern}")
            ),
            key=lambda path: (
                path.parent.name,
                path.name,
            ),
            reverse=True,
        )
        if SESSION_ROOT.exists()
        else []
    )

    if not candidates:
        print(
            "\nNo PolicyReset report is available."
        )
        input(
            "\nPress Enter to return to the main menu..."
        )
        return

    print()
    print(
        f"Latest report: {candidates[0]}"
    )
    print()

    try:
        report = json.loads(
            candidates[0].read_text(
                encoding="utf-8"
            )
        )
        print(
            json.dumps(
                report,
                indent=2,
                ensure_ascii=False,
            )
        )
    except (
        OSError,
        ValueError,
    ) as exc:
        print(
            f"Could not read the report: {exc}"
        )

    input(
        "\nPress Enter to return to the main menu..."
    )


def print_header() -> None:
    print()
    print("=" * 78)
    print(f"{APP_NAME} {VERSION}")
    print("Windows Local Group Policy Reset Utility")
    print("=" * 78)



def _powershell_quote(value: str) -> str:
    """Escape a value for a PowerShell single-quoted string."""
    return value.replace("'", "''")


def _find_python_console_executable() -> str:
    """Return python.exe matching the current interpreter installation."""
    current = Path(sys.executable)
    candidate = current.with_name("python.exe")

    if candidate.exists():
        return str(candidate)

    found = shutil.which("python.exe")
    if found:
        return found

    raise PolicyResetError(
        "python.exe could not be located."
    )


def _find_powershell_executable() -> str:
    """Prefer PowerShell 7 and fall back to Windows PowerShell."""
    for name in ("pwsh.exe", "powershell.exe"):
        found = shutil.which(name)
        if found:
            return found

    raise PolicyResetError(
        "PowerShell could not be located."
    )


def _launch_persistent_powershell() -> None:
    """Launch an elevated PowerShell console for PolicyReset."""
    python_exe = _powershell_quote(
        _find_python_console_executable()
    )
    script = _powershell_quote(
        str(Path(__file__).resolve())
    )
    command = (
        f"& '{python_exe}' '{script}' --console"
    )

    import base64

    encoded = base64.b64encode(
        command.encode("utf-16le")
    ).decode("ascii")

    powershell = _find_powershell_executable()
    working_directory = str(Path(__file__).resolve().parent)

    try:
        result = ctypes.windll.shell32.ShellExecuteW(
            None,
            "runas",
            powershell,
            f"-NoProfile -EncodedCommand {encoded}",
            working_directory,
            1,
        )
    except OSError as exc:
        raise PolicyResetError(
            f"Could not launch elevated PowerShell: {exc}"
        ) from exc

    if result <= 32:
        raise PolicyResetError(
            "Windows could not launch the elevated PowerShell console "
            f"(ShellExecuteW code {result})."
        )


def _bootstrap_pyw() -> None:
    """Ensure PolicyReset enters an elevated PowerShell console."""
    if "--console" in sys.argv:
        return

    if not is_windows():
        return

    # A .pyw launched by Explorer normally has no console. In that case,
    # request UAC elevation while launching the persistent PowerShell window.
    if sys.stdout is None:
        _launch_persistent_powershell()
        raise SystemExit(0)

    # A direct launch from a non-elevated PowerShell cannot elevate the same
    # process. Start a new elevated PowerShell and continue there instead of
    # asking the user to reopen PowerShell manually.
    if not is_admin():
        _launch_persistent_powershell()
        raise SystemExit(0)


def main() -> int:
    _bootstrap_pyw()

    if not is_windows():
        print(
            "PolicyReset can only run on Windows."
        )
        return 1

    configure_console()

    if not is_admin():
        print("Unable to obtain administrator privileges. PolicyReset cannot continue.")
        return 1

    print_header()

    application_session = create_session()
    logger = Logger(
        application_session.log_file
    )

    logger.info(
        f"{APP_NAME} {VERSION} started."
    )
    logger.info(
        f"Application session directory: {application_session.directory}"
    )

    while True:
        try:
            print()
            print(
                "[1] DIAGNOSE GROUP POLICY: Scan User and Computer and create report"
            )
            print(
                "[2] REMOVE ALL LOCAL GROUP POLICY AND BACKUP: Remove and verify"
            )
            print(
                "[3] RESTORE GROUP POLICY BACKUP: Restore a previous local policy backup"
            )
            print(
                "[4] VIEW LATEST POLICYRESET REPORT: Display the latest operation report"
            )
            print(
                "[5] REFRESH GROUP POLICY: Run gpupdate /force separately"
            )
            print(
                "[6] DELETE ALL POLICYRESET BACKUPS: Remove backup artefacts and preserve reports"
            )
            print(
                "[0] EXIT"
            )

            choice = input(
                "\nSelect an option: "
            ).strip()

            if choice == "1":
                operation_session = create_session()
                diagnose(
                    operation_session,
                    logger,
                )

            elif choice == "2":
                operation_session = create_session()
                remove_all_local_group_policy(
                    operation_session,
                    logger,
                )

            elif choice == "3":
                restore_backup(
                    logger,
                )

            elif choice == "4":
                show_latest_report()

            elif choice == "5":
                operation_session = create_session()
                print()
                print("=" * 78)
                print("REFRESH GROUP POLICY")
                print("=" * 78)
                print()
                print(
                    "This is a separate operation. It reapplies available "
                    "User and Computer Group Policy with gpupdate /force."
                )
                print(
                    "It is not part of Local Group Policy removal."
                )
                print()
                if confirm_yes_no("Continue with Group Policy refresh?"):
                    gpupdate_ok = refresh_group_policy(
                        operation_session,
                        logger,
                    )
                    report = write_refresh_report(
                        operation_session,
                        gpupdate_ok,
                    )
                    print(
                        "\nGroup Policy refresh: "
                        f"{'Successful' if gpupdate_ok else 'Failed'}"
                    )
                    print(f"Report: {report}")
                else:
                    logger.info("Group Policy refresh cancelled.")
                input("\nPress Enter to return to the main menu...")

            elif choice == "6":
                delete_all_backups(
                    logger,
                )

            elif choice == "0":
                logger.info(
                    "Application closed by the user."
                )
                print()
                return 0

            else:
                print(
                    "\nInvalid option."
                )

        except KeyboardInterrupt:
            print(
                "\n\nOperation cancelled. "
                "Returning to the main menu."
            )
            logger.warn(
                "Operation interrupted by the user."
            )

        except subprocess.TimeoutExpired:
            print(
                "\nWindows command timed out. "
                "Returning to the main menu."
            )
            logger.error(
                "Windows command timed out."
            )

        except PolicyResetError as exc:
            print(
                f"\nPolicyReset error: {exc}"
            )
            logger.error(str(exc))

        except (
            OSError,
            subprocess.SubprocessError,
        ) as exc:
            print(
                f"\nWindows operation failed: {exc}"
            )
            logger.error(
                f"Windows operation failed: {exc}"
            )

        except Exception as exc:
            print(
                f"\nUnexpected error: {exc}"
            )
            logger.error(
                f"Unexpected error: {exc}"
            )


if __name__ == "__main__":
    raise SystemExit(main())