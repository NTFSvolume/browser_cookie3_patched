import importlib.metadata
from collections.abc import Callable, Generator
from pathlib import Path

__version__ = importlib.metadata.version("browser_cookie3")

import base64
import configparser
import glob
import http.cookiejar
import json
import os
import shutil
import sqlite3
import struct
import subprocess
import sys
import tempfile
from abc import ABC, abstractmethod
from io import BufferedReader, BytesIO
from typing import Any, ClassVar, Literal, NamedTuple, NewType, Optional, TypeVar, Union, get_args

shadowcopy = None
_IS_LINUX = _IS_WINDOWS = _IS_MACOS = False
if sys.platform.startswith("linux") or "bsd" in sys.platform.lower():
    _IS_LINUX = True
    _CURRENT_OS = "linux"
    import jeepney
    from jeepney.io.blocking import open_dbus_connection

elif sys.platform == "win32":
    _IS_WINDOWS = True
    _CURRENT_OS = "windows"
    try:
        import shadowcopy
    except ImportError:
        pass
elif sys.platform == "darwin":
    _IS_MACOS = True
    _CURRENT_OS = "osx"
else:
    _CURRENT_OS = "unknown"

# external dependencies
import lz4.block
from Cryptodome.Cipher import AES
from Cryptodome.Protocol.KDF import PBKDF2
from Cryptodome.Util.Padding import unpad

__doc__ = "Load browser cookies into a cookiejar"

CHROMIUM_DEFAULT_PASSWORD = b"peanuts"


class BrowserCookieError(Exception): ...


class CookieDecryptionError(BrowserCookieError): ...


class UnsupportedOSError(BrowserCookieError): ...


SupportedOS = Literal["windows", "osx", "linux"]
_T = TypeVar("_T")
_CookieExtractor = Callable[..., http.cookiejar.CookieJar]
_ExpandedPath = NewType("_ExpandedPath", str)
_StrTuple = tuple[str, ...]
_StrDict = dict[str, _T]
_DictCookies = _StrDict[Any]
_Json = _StrDict[list[_T]]
_NestedJson = _Json[_Json[_T]]

_NEW_ISSUE_URL = "https://github.com/NTFSvolume/browser_cookie3_patched/issues/new"


class _WinPath(NamedTuple):
    env: str
    path: str


def _ExpandedOrNone(path: Optional[str]) -> Optional[_ExpandedPath]:  # noqa: N802
    return _ExpandedPath(path) if path else None


def _windows_group_policy_path() -> Optional[_ExpandedPath]:
    assert _IS_WINDOWS
    # we know that we're running under windows at this point so it's safe to do these imports
    from winreg import HKEY_LOCAL_MACHINE, REG_EXPAND_SZ, REG_SZ, ConnectRegistry, OpenKeyEx, QueryValueEx  # type: ignore  # noqa: I001

    try:
        root = ConnectRegistry(None, HKEY_LOCAL_MACHINE)
        policy_key = OpenKeyEx(root, r"SOFTWARE\Policies\Google\Chrome")
        user_data_dir, type_ = QueryValueEx(policy_key, "UserDataDir")
        if type_ == REG_EXPAND_SZ:
            user_data_dir = os.path.expandvars(user_data_dir)
        elif type_ != REG_SZ:
            return None
    except OSError:
        return None
    return _ExpandedPath(os.path.join(user_data_dir, "Default", "Cookies"))


# Code adapted slightly from https://github.com/Arnie97/chrome-cookies
def _crypt_unprotect_data(
    cipher_text: bytes = b"", entropy: bytes = b"", reserved=None, prompt_struct=None, is_key: bool = False
) -> Union[tuple[Optional[str], bytes], tuple[Optional[str], str]]:
    assert _IS_WINDOWS
    import ctypes
    import ctypes.wintypes

    class DataBlob(ctypes.Structure):
        _fields_: ClassVar = [("cbData", ctypes.wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

        def __init__(self, data: bytes):
            super().__init__(len(data), ctypes.create_string_buffer(data))

    blob_in, blob_entropy, blob_out = (DataBlob(data) for data in [cipher_text, entropy, b""])
    desc = ctypes.c_wchar_p()

    CRYPTPROTECT_UI_FORBIDDEN = 0x01

    if not ctypes.windll.crypt32.CryptUnprotectData(  # type: ignore
        ctypes.byref(blob_in),
        ctypes.byref(desc),
        ctypes.byref(blob_entropy),
        reserved,
        prompt_struct,
        CRYPTPROTECT_UI_FORBIDDEN,
        ctypes.byref(blob_out),
    ):
        raise RuntimeError("Failed to decrypt the cipher text with DPAPI")

    description = desc.value
    buffer_out = ctypes.create_string_buffer(int(blob_out.cbData))
    ctypes.memmove(buffer_out, blob_out.pbData, blob_out.cbData)
    map(ctypes.windll.kernel32.LocalFree, [desc, blob_out.pbData])  # type: ignore
    if is_key:
        return description, buffer_out.raw
    return description, buffer_out.value


def _get_osx_keychain_password(osx_key_service: str, osx_key_user: str) -> bytes:
    """Retrieve password used to encrypt cookies from OSX Keychain"""

    cmd = ["/usr/bin/security", "-q", "find-generic-password", "-w", "-a", osx_key_user, "-s", osx_key_service]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, _ = proc.communicate()
    if proc.returncode != 0:
        return CHROMIUM_DEFAULT_PASSWORD  # default password, probably won't work
    return out.strip()


def _expand_win_path(path: Union[_WinPath, str]) -> _ExpandedPath:
    if not isinstance(path, tuple):
        path = _WinPath("APPDATA", path)
    app_data = os.getenv(path.env, "")
    return _ExpandedPath(os.path.join(app_data, path.path))


def _expand_paths_impl(os_name: SupportedOS, *paths: Union[_WinPath, str]) -> Generator[_ExpandedPath]:
    """Expands user paths on Linux, OSX, and windows"""
    assert os_name in get_args(SupportedOS)
    if not paths:
        return

    if os_name == "windows":
        expand: Callable[..., Union[bytes, str]] = _expand_win_path
    else:
        assert not any(isinstance(p, _WinPath) for p in paths), "Windows paths are not supported in this platform"
        expand = os.path.expanduser

    for path in map(expand, paths):  # type: ignore
        # glob will return results in arbitrary order. sorted() is use to make output predictable.
        # can use return here without using `_expand_paths()` below.
        # but using generator can be useful if we plan to parse all `Cookies` files later.
        yield from sorted(_ExpandedPath(child) for child in glob.iglob(path))


def _expand_paths(os_name: SupportedOS, *paths: Union[_WinPath, str]) -> Optional[_ExpandedPath]:
    return next(_expand_paths_impl(os_name, *paths), None)


def _normalize_paths_chromium(paths: _StrTuple, channels: Optional[_StrTuple] = None) -> tuple[_StrTuple, _StrTuple]:
    channels = channels or ("",)
    return paths, channels


def _generate_nix_paths_chromium(paths: _StrTuple, channels: Optional[_StrTuple] = None) -> list[str]:
    """Generate paths for chromium based browsers on *nix systems."""

    paths, channels = _normalize_paths_chromium(paths, channels)
    generated_paths: list[str] = []
    for chan in channels:
        for path in paths:
            generated_paths.append(path.format(channel=chan))
    return generated_paths


def _generate_win_paths_chromium(paths: _StrTuple, channels: Optional[_StrTuple] = None) -> list[_WinPath]:
    """Generate paths for chromium based browsers on windows"""

    paths, channels = _normalize_paths_chromium(paths, channels)
    generated_paths: list[_WinPath] = []
    for chan in channels:
        for path in paths:
            full_path = path.format(channel=chan)
            generated_paths.append(_WinPath("APPDATA", "..\\Local\\" + full_path))
            generated_paths.append(_WinPath("LOCALAPPDATA", full_path))
            generated_paths.append(_WinPath("APPDATA", full_path))
    return generated_paths


def _text_factory(data: bytes) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data  # type: ignore


class _JeepneyConnection:
    def __init__(self, object_path: str, bus_name: str, interface: str) -> None:
        self.__dbus_address = jeepney.DBusAddress(object_path, bus_name, interface)

    def __enter__(self) -> "_JeepneyConnection":
        self.__connection = open_dbus_connection()
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.__connection.close()

    def close(self) -> None:
        self.__connection.close()

    def call_method(self, method_name: str, signature: Optional[str] = None, *args: Any) -> Any:
        method = jeepney.new_method_call(self.__dbus_address, method_name, signature, args)
        response = self.__connection.send_and_get_reply(method)
        if response.header.message_type == jeepney.MessageType.error:
            raise RuntimeError(response.body[0])
        return response.body[0] if len(response.body) == 1 else response.body


class _LinuxPasswordManager:
    """Retrieve password used to encrypt cookies from KDE Wallet or SecretService"""

    _APP_ID = "browser-cookie3"

    def get_password(self, os_crypt_name: str) -> bytes:
        try:
            return self.__get_secretstorage_password(os_crypt_name)
        except RuntimeError:
            pass
        try:
            return self.__get_kdewallet_password_jeepney(os_crypt_name)
        except RuntimeError:
            pass
        # try default peanuts password, probably won't work
        return CHROMIUM_DEFAULT_PASSWORD

    def __get_secretstorage_password(self, os_crypt_name: str):
        schemas = ["chrome_libsecret_os_crypt_password_v2", "chrome_libsecret_os_crypt_password_v1"]
        for schema in schemas:
            try:
                return self.__get_secretstorage_item_jeepney(schema, os_crypt_name)
            except RuntimeError:
                pass
        raise RuntimeError(f"Can not find secret for {os_crypt_name}")

    def __get_secretstorage_item_jeepney(self, schema: str, application: str) -> bytes:
        con_params = ["/org/freedesktop/secrets", "org.freedesktop.secrets", "org.freedesktop.Secret.Service"]
        with _JeepneyConnection(*con_params) as connection:
            params = {"xdg:schema": schema, "application": application}
            object_path_1 = connection.call_method("SearchItems", "a{ss}", params)
            object_path_list: list = [obj for obj in object_path_1 if len(obj) > 0]
            if len(object_path_list) == 0:
                raise RuntimeError(f"Can not find secret for {application}")
            object_path: str = object_path_list[0][0]
            connection.call_method("Unlock", "ao", [object_path])
            _, session = connection.call_method("OpenSession", "sv", "plain", ("s", ""))
            _, _, secret, _ = connection.call_method("GetSecrets", "aoo", [object_path], session)[object_path]
            return secret

    def __get_kdewallet_password_jeepney(self, os_crypt_name: str) -> bytes:
        folder = f"{os_crypt_name.capitalize()} Keys"
        key = f"{os_crypt_name.capitalize()} Safe Storage"
        con_params = ["/modules/kwalletd5", "org.kde.kwalletd5", "org.kde.KWallet"]
        with _JeepneyConnection(*con_params) as connection:
            network_wallet = connection.call_method("networkWallet")
            handle = connection.call_method("open", "sxs", network_wallet, 0, self._APP_ID)
            has_folder: bool = connection.call_method("hasFolder", "iss", handle, folder, self._APP_ID)
            if not has_folder:
                connection.call_method("close", "ibs", handle, False, self._APP_ID)
                raise RuntimeError(f"KDE Wallet folder {folder} not found.")
            password: str = connection.call_method("readPassword", "isss", handle, folder, key, self._APP_ID)
            connection.call_method("close", "ibs", handle, False, self._APP_ID)
            return password.encode("utf-8")


class _DatabaseConnetion:
    def __init__(self, database_file: str, try_legacy_first: bool = False) -> None:
        self.__database_file = database_file
        self.__temp_cookie_file: Optional[str] = None
        self.__connection = None
        self.__methods = [self.__sqlite3_connect_readonly]
        if try_legacy_first:
            self.__methods.insert(0, self.__get_connection_legacy)
        else:
            self.__methods.append(self.__get_connection_legacy)
        if shadowcopy:
            self.__methods.append(self.__get_connection_shadowcopy)

    def __enter__(self) -> sqlite3.Connection:
        return self.get_connection()

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.close()

    def __check_connection_ok(self, connection: sqlite3.Connection) -> bool:
        try:
            connection.cursor().execute("select 1 from sqlite_master")
            return True
        except sqlite3.OperationalError:
            return False

    def __sqlite3_connect_readonly(self) -> Optional[sqlite3.Connection]:
        uri: str = Path(self.__database_file).absolute().as_uri()
        for options in ("?mode=ro", "?mode=ro&nolock=1", "?mode=ro&immutable=1"):
            try:
                con = sqlite3.connect(uri + options, uri=True)
            except sqlite3.OperationalError:
                continue
            if self.__check_connection_ok(con):
                return con

    def __get_connection_legacy(self) -> Optional[sqlite3.Connection]:
        with tempfile.NamedTemporaryFile(suffix=".sqlite") as tf:
            self.__temp_cookie_file = tf.name
        try:
            shutil.copyfile(self.__database_file, self.__temp_cookie_file)
        except PermissionError:
            return
        con = sqlite3.connect(self.__temp_cookie_file)
        if self.__check_connection_ok(con):
            return con

    def __get_connection_shadowcopy(self) -> Optional[sqlite3.Connection]:
        if not shadowcopy:
            raise RuntimeError("shadowcopy is not available")

        self.__temp_cookie_file = tempfile.NamedTemporaryFile(suffix=".sqlite").name
        shadowcopy.shadow_copy(self.__database_file, self.__temp_cookie_file)
        con = sqlite3.connect(self.__temp_cookie_file)
        if self.__check_connection_ok(con):
            return con

    def get_connection(self) -> sqlite3.Connection:
        if self.__connection:
            return self.__connection
        for method in self.__methods:
            con = method()
            if con is not None:
                self.__connection = con
                return con
        raise BrowserCookieError("Unable to read database file")

    def close(self) -> None:
        if self.__connection:
            self.__connection.close()
        if self.__temp_cookie_file:
            try:
                os.remove(self.__temp_cookie_file)
            except Exception:
                pass


class _Browser(ABC):
    """Base class of all browsers

    Appart for the abstract methods, all subclasses most override NAME and SUPPORTED_OPERATING_SYSTEMS

    DO NOT Override __init__ in subclasses. Define custom logic for the browser in the `_post_init` method"""

    NAME: ClassVar[str] = ""
    SUPPORTED_OPERATING_SYSTEMS: ClassVar[tuple[SupportedOS, ...]] = ()

    LINUX_COOKIE_PATHS: ClassVar[_StrTuple] = ()
    WINDOWS_COOKIES_PATHS: ClassVar[Union[_StrTuple, tuple[_WinPath]]] = ()
    OSX_COOKIE_PATHS: ClassVar[_StrTuple] = ()

    def __init__(
        self,
        cookie_file: Optional[str] = None,  # path to plain text file or sqlite database, depends on the browser
        domain_name: Optional[str] = None,
        key_file: Optional[str] = None,
    ) -> None:
        assert self.NAME, "Subclasses must define a NAME"
        assert self.SUPPORTED_OPERATING_SYSTEMS, "Subclasses must define at least 1 supported OS"
        if not self.is_supported():
            msg = f"OS not recognized. {self.NAME} browser is supported on: {self.SUPPORTED_OPERATING_SYSTEMS}"
            raise UnsupportedOSError(msg)
        self.cookie_file: Optional[_ExpandedPath] = _ExpandedOrNone(cookie_file)
        self.key_file: Optional[_ExpandedPath] = _ExpandedOrNone(key_file)
        self.domain_name: str = domain_name or ""
        self._post_init()

    def __str__(self) -> str:
        return self.NAME

    @classmethod
    def is_supported(cls) -> bool:
        return _CURRENT_OS in cls.SUPPORTED_OPERATING_SYSTEMS

    @classmethod
    def supports_linux(cls) -> bool:
        return "linux" in cls.SUPPORTED_OPERATING_SYSTEMS

    @classmethod
    def supports_windows(cls) -> bool:
        return "windows" in cls.SUPPORTED_OPERATING_SYSTEMS

    @classmethod
    def supports_osx(cls) -> bool:
        return "osx" in cls.SUPPORTED_OPERATING_SYSTEMS

    @abstractmethod
    def load(self) -> http.cookiejar.CookieJar: ...

    @abstractmethod
    def _post_init(self) -> None: ...

    @abstractmethod
    def _get_default_cookie_file_for(self, os_name: SupportedOS) -> Optional[_ExpandedPath]: ...

    def _find_default_cookie_file(
        self,
    ) -> Optional[_ExpandedPath]:
        if _IS_MACOS:
            return self._get_default_cookie_file_for("osx")
        elif _IS_LINUX:
            return self._get_default_cookie_file_for("linux")
        elif _IS_WINDOWS:
            return self._get_default_cookie_file_for("windows")

    def _set_actual_cookie_file_to_use(self) -> None:
        cookie_file = self.cookie_file or self._find_default_cookie_file()
        if not cookie_file:
            raise BrowserCookieError(f"Failed to find cookies for {self.NAME} browser")
        self.cookie_file = cookie_file


class _SimpleBrowser(_Browser):
    """Simple abstract browser that just sets the default cookie file in _post_init"""

    def _post_init(self) -> None:  # Makes overriding _post_init optional
        self._set_actual_cookie_file_to_use()

    def _get_default_cookie_file_for(self, os_name: SupportedOS) -> Optional[_ExpandedPath]:
        if os_name not in self.SUPPORTED_OPERATING_SYSTEMS:
            return
        if os_name == "osx":
            return _expand_paths(os_name, *self.OSX_COOKIE_PATHS)
        if os_name == "linux":
            return _expand_paths(os_name, *self.LINUX_COOKIE_PATHS)
        if os_name == "windows":
            return _expand_paths(os_name, *self.WINDOWS_COOKIES_PATHS)

    @abstractmethod
    def load(self): ...


class ChromiumBased(_Browser):
    """Super class for all Chromium based browsers"""

    SUPPORTED_OPERATING_SYSTEMS: ClassVar[tuple[SupportedOS, ...]] = ("windows", "osx", "linux")
    UNIX_TO_NT_EPOCH_OFFSET: ClassVar[int] = 11644473600  # seconds from 1601-01-01T00:00:00Z to 1970-01-01T00:00:00Z

    LINUX_CHANNELS: ClassVar[_StrTuple] = ("",)
    LINUX_COOKIE_PATHS: ClassVar[_StrTuple] = ()
    LINUX_OS_CRYPT_NAME: ClassVar[str] = ""

    WINDOWS_CHANNELS: ClassVar[_StrTuple] = ("",)
    WINDOWS_COOKIES_PATHS: ClassVar[_StrTuple] = ()
    WINDOWS_KEYS_PATHS: ClassVar[_StrTuple] = ()

    OSX_CHANNELS: ClassVar[_StrTuple] = ("",)
    OSX_COOKIE_PATHS: ClassVar[_StrTuple] = ()
    OSX_KEY_SERVICE: ClassVar[str] = ""
    OSX_KEY_USER: ClassVar[str] = ""

    def _post_init(self):
        self.salt = b"saltysalt"
        self.iv = b" " * 16
        self.length = 16
        self.v10_key: Optional[bytes] = None
        self._set_actual_cookie_file_to_use()
        self.__add_decrypt_keys()

    def _get_default_cookie_file_for(self, os_name: str) -> Optional[_ExpandedPath]:
        if os_name == "osx":
            osx_cookies = _generate_nix_paths_chromium(self.OSX_COOKIE_PATHS, self.OSX_CHANNELS)
            return _expand_paths(os_name, *osx_cookies)
        if os_name == "linux":
            linux_cookies = _generate_nix_paths_chromium(self.LINUX_COOKIE_PATHS, self.LINUX_CHANNELS)
            return _expand_paths(os_name, *linux_cookies)
        if os_name == "windows":
            if self.NAME.lower() == "chrome" and (group_policy_path := _windows_group_policy_path()):
                return group_policy_path
            windows_cookies = _generate_win_paths_chromium(self.WINDOWS_COOKIES_PATHS, self.WINDOWS_CHANNELS)
            return _expand_paths(os_name, *windows_cookies)

    def __get_key_from_password(self, password: Union[bytes, str], iterations: int) -> bytes:
        """Derive one or more keys from a password (or passphrase)."""
        return PBKDF2(password, self.salt, self.length, iterations)  # type: ignore

    def __add_decrypt_keys(self):
        assert self.cookie_file is not None
        if _IS_MACOS:
            assert self.OSX_COOKIE_PATHS, "Cookies must be defined to support OSX"
            assert self.OSX_KEY_SERVICE, "Key service must be defined to support OSX"
            assert self.OSX_KEY_USER, "Key user must be defined to support OSX"
            password = _get_osx_keychain_password(self.OSX_KEY_SERVICE, self.OSX_KEY_USER)
            iterations = 1003  # number of pbkdf2 iterations on mac
            self.v10_key = self.__get_key_from_password(password, iterations)

        elif _IS_LINUX:
            assert self.LINUX_OS_CRYPT_NAME, "Crypt name must be defined to support Linux"
            assert self.LINUX_COOKIE_PATHS, "Cookies must be defined to support Linux"
            password = _LinuxPasswordManager().get_password(self.LINUX_OS_CRYPT_NAME)
            iterations = 1
            self.v10_key = self.__get_key_from_password(CHROMIUM_DEFAULT_PASSWORD, iterations)
            self.v11_key = self.__get_key_from_password(password, iterations)

            # Due to a bug in previous version of chromium,
            # the key used to encrypt the cookies in some linux systems was empty
            # After the bug was fixed, old cookies are still encrypted with an empty key
            self.v11_empty_key = self.__get_key_from_password(b"", iterations)  # type: ignore

        else:
            assert self.WINDOWS_KEYS_PATHS, "Windows keys must be defined to support Windows"
            assert self.WINDOWS_COOKIES_PATHS, "Windows cookies must be defined to support Windows"
            windows_keys = _generate_win_paths_chromium(self.WINDOWS_KEYS_PATHS, self.WINDOWS_CHANNELS)
            key_file = self.key_file or _expand_paths("windows", *windows_keys)
            if key_file:
                with Path(key_file).open("rb") as f:
                    key_file_json = json.load(f)
                    key64: bytes = key_file_json["os_crypt"]["encrypted_key"].encode("utf-8")

                    # Decode Key, get rid of DPAPI prefix, unprotect data
                    keydpapi = base64.standard_b64decode(key64)[5:]
                    _, v10_key = _crypt_unprotect_data(keydpapi, is_key=True)
                    assert isinstance(v10_key, bytes)
                    self.v10_key = v10_key

    def load(self) -> http.cookiejar.CookieJar:
        """Load sqlite cookies into a cookiejar"""
        cj = http.cookiejar.CookieJar()
        assert self.cookie_file is not None
        with _DatabaseConnetion(self.cookie_file) as con:
            con.text_factory = _text_factory
            cursor = con.cursor()
            has_integrity_check_for_cookie_domain = self._has_integrity_check_for_cookie_domain(cursor)
            try:
                # chrome <=55
                cursor.execute(
                    "SELECT host_key, path, secure, expires_utc, name, value, encrypted_value, is_httponly "
                    "FROM cookies WHERE host_key like ?;",
                    (f"%{self.domain_name}%",),
                )
            except sqlite3.OperationalError:
                try:
                    # chrome >=56
                    cursor.execute(
                        "SELECT host_key, path, is_secure, expires_utc, name, value, encrypted_value, is_httponly "
                        "FROM cookies WHERE host_key like ?;",
                        (f"%{self.domain_name}%",),
                    )
                except sqlite3.OperationalError as e:
                    if e.args[0].startswith(("no such table: ", "file is not a database")):
                        msg = f"File {self.cookie_file} is not a Chromium-based browser cookie file"
                        raise BrowserCookieError(msg) from None

            for item in cursor.fetchall():
                # Per https://github.com/chromium/chromium/blob/main/base/time/time.h#L5-L7,
                # Chromium-based browsers store cookies' expiration timestamps as MICROSECONDS elapsed
                # since the Windows NT epoch (1601-01-01 0:00:00 GMT), or 0 for session cookies.
                #
                # http.cookiejar stores cookies' expiration timestamps as SECONDS since the Unix epoch
                # (1970-01-01 0:00:00 GMT, or None for session cookies.
                host, path, secure, expires_nt_time_epoch, name, value, enc_value, http_only = item
                if expires_nt_time_epoch == 0:
                    expires = None
                else:
                    expires: Optional[int] = (expires_nt_time_epoch / 1000000) - self.UNIX_TO_NT_EPOCH_OFFSET

                value = self._decrypt(value, enc_value, has_integrity_check_for_cookie_domain)
                c = create_cookie(host, path, secure, expires, name, value, http_only)
                cj.set_cookie(c)
        return cj

    @staticmethod
    def _has_integrity_check_for_cookie_domain(con: sqlite3.Cursor) -> bool:
        """Starting from version 24, the sha256 of the domain is prepended to the encrypted value
        of the cookie.

        See:
            - https://issues.chromium.org/issues/40185252
            - https://chromium-review.googlesource.com/c/chromium/src/+/5792044
            - https://chromium.googlesource.com/chromium/src/net/+/master/extras/sqlite/sqlite_persistent_cookie_store.cc#193
        """
        try:
            (value,) = con.execute('SELECT value FROM meta WHERE key = "version";').fetchone()
        except sqlite3.OperationalError:
            return False

        try:
            version = int(value)
        except ValueError:
            return False

        return version >= 24

    @staticmethod
    def _decrypt_windows_chromium(value: str, encrypted_value: bytes) -> str:
        if len(value) != 0:
            return value

        if encrypted_value == b"":
            return ""

        _, data = _crypt_unprotect_data(encrypted_value)
        assert isinstance(data, bytes)
        return data.decode()

    def _decrypt(self, value: str, encrypted_value: bytes, has_integrity_check_for_cookie_domain: bool = False) -> str:
        """Decrypt encoded cookies"""

        if _IS_WINDOWS:
            try:
                return self._decrypt_windows_chromium(value, encrypted_value)

            # Fix for change in Chrome 80
            except RuntimeError:  # Failed to decrypt the cipher text with DPAPI
                if not self.v10_key:
                    msg = "Failed to decrypt the cipher text with DPAPI and no AES key."
                    raise CookieDecryptionError(msg) from None
                # Encrypted cookies should be prefixed with 'v10' according to the
                # Chromium code. Strip it off.
                encrypted_value = encrypted_value[3:]
                nonce, tag = encrypted_value[:12], encrypted_value[-16:]
                aes = AES.new(self.v10_key, AES.MODE_GCM, nonce=nonce)

                # will rise Value Error: MAC check failed byte if the key is wrong,
                # probably we did not got the key and used peanuts
                try:
                    data = aes.decrypt_and_verify(encrypted_value[12:-16], tag)
                except ValueError:
                    raise CookieDecryptionError("Unable to get key for cookie decryption") from None
                if has_integrity_check_for_cookie_domain:
                    data = data[32:]
                return data.decode()

        if value or (encrypted_value[:3] not in [b"v11", b"v10"]):
            return value

        # Encrypted cookies should be prefixed with 'v10' on mac,
        # 'v10' or 'v11' on Linux. Choose key based on this prefix.
        # Reference in chromium code: `OSCryptImpl::DecryptString` in
        # components/os_crypt/os_crypt_linux.cc
        if not hasattr(self, "v11_key"):
            assert encrypted_value[:3] != b"v11", "v11 keys should only appear on Linux."
        keys = (self.v11_key, self.v11_empty_key) if encrypted_value[:3] == b"v11" else (self.v10_key,)
        encrypted_value = encrypted_value[3:]

        for key in keys:
            assert key is not None
            cipher = AES.new(key, AES.MODE_CBC, self.iv)

            # will rise Value Error: invalid padding byte if the key is wrong,
            # probably we did not got the key and used peanuts
            try:
                decrypted = unpad(cipher.decrypt(encrypted_value), AES.block_size)
                if has_integrity_check_for_cookie_domain:
                    decrypted = decrypted[32:]
                return decrypted.decode("utf-8")
            except ValueError:
                pass
        raise CookieDecryptionError("Unable to get key for cookie decryption")


class Chrome(ChromiumBased):
    """Class for Google Chrome"""

    NAME = "Chrome"
    OSX_KEY_SERVICE = "Chrome Safe Storage"
    OSX_KEY_USER = "Chrome"
    OSX_CHANNELS = ("", " Beta", " Dev")
    WINDOWS_CHANNELS = ("", " Beta", " Dev")
    LINUX_CHANNELS = ("", "-beta", "-unstable")
    LINUX_OS_CRYPT_NAME = "chrome"

    LINUX_COOKIES_PATHS = (
        "~/.config/google-chrome{channel}/Default/Cookies",
        "~/.config/google-chrome{channel}/Profile */Cookies",
        "~/.var/app/com.google.Chrome/config/google-chrome{channel}/Default/Cookies",
        "~/.var/app/com.google.Chrome/config/google-chrome{channel}/Profile */Cookies",
    )

    OSX_COOKIES_PATHS = (
        "~/Library/Application Support/Google/Chrome{channel}/Default/Cookies",
        "~/Library/Application Support/Google/Chrome{channel}/Profile */Cookies",
    )

    WINDOWS_COOKIES_PATHS = (
        "Google\\Chrome{channel}\\User Data\\Default\\Cookies",
        "Google\\Chrome{channel}\\User Data\\Default\\Network\\Cookies",
        "Google\\Chrome{channel}\\User Data\\Profile *\\Cookies",
        "Google\\Chrome{channel}\\User Data\\Profile *\\Network\\Cookies",
    )

    WINDOWS_KEYS_PATHS = ("Google\\Chrome{channel}\\User Data\\Local State",)


class Arc(ChromiumBased):
    """Class for Arc"""

    NAME = "Arc"
    SUPPORTED_OPERATING_SYSTEMS = ("osx",)
    OSX_COOKIE_PATHS = (
        "~/Library/Application Support/Arc/User Data/Default/Cookies",
        "~/Library/Application Support/Arc/User Data/Profile */Cookies",
    )
    OSX_CHANNELS = ("",)
    LINUX_OS_CRYPT_NAME = "chrome"
    OSX_KEY_USER = "Arc"
    OSX_KEY_SERVICE = "Arc Safe Storage"


class Chromium(ChromiumBased):
    """Class for Chromium"""

    NAME = "Chromium"
    LINUX_COOKIE_PATHS = (
        "~/.config/chromium/Default/Cookies",
        "~/.config/chromium/Profile */Cookies",
        "~/.var/app/org.chromium.Chromium/config/chromium/Default/Cookies",
        "~/.var/app/org.chromium.Chromium/config/chromium/Profile */Cookies",
    )
    WINDOWS_COOKIES_PATHS = (
        "Chromium\\User Data\\Default\\Cookies",
        "Chromium\\User Data\\Default\\Network\\Cookies",
        "Chromium\\User Data\\Profile *\\Cookies",
        "Chromium\\User Data\\Profile *\\Network\\Cookies",
    )
    OSX_COOKIE_PATHS = (
        "~/Library/Application Support/Chromium/Default/Cookies",
        "~/Library/Application Support/Chromium/Profile */Cookies",
    )
    WINDOWS_KEYS_PATHS = ("Chromium\\User Data\\Local State",)
    LINUX_OS_CRYPT_NAME = "chromium"
    OSX_KEY_SERVICE = "Chromium Safe Storage"
    OSX_KEY_USER = "Chromium"


class Opera(ChromiumBased):
    """Class for Opera"""

    NAME = "Opera"
    LINUX_COOKIE_PATHS = (
        "~/.config/opera/Cookies",
        "~/.config/opera-beta/Cookies",
        "~/.config/opera-developer/Cookies",
        "~/.var/app/com.opera.Opera/config/opera/Cookies"
        "~/.var/app/com.opera.Opera/config/opera-beta/Cookies"
        "~/.var/app/com.opera.Opera/config/opera-developer/Cookies",
    )
    WINDOWS_COOKIES_PATHS = (
        "Opera Software\\Opera {channel}\\Cookies",
        "Opera Software\\Opera {channel}\\Network\\Cookies",
    )
    WINDOWS_CHANNELS = ("Stable", "Next", "Developer")

    OSX_COOKIE_PATHS = (
        "~/Library/Application Support/com.operasoftware.Opera/Cookies",
        "~/Library/Application Support/com.operasoftware.OperaNext/Cookies",
        "~/Library/Application Support/com.operasoftware.OperaDeveloper/Cookies",
    )
    WINDOWS_KEYS_PATHS = ("Opera Software\\Opera {channel}\\Local State",)
    LINUX_OS_CRYPT_NAME = "chromium"
    OSX_KEY_SERVICE = "Opera Safe Storage"
    OSX_KEY_USER = "Opera"


class OperaGX(ChromiumBased):
    """Class for Opera GX"""

    NAME = "Opera GX"
    SUPPORTED_OPERATING_SYSTEMS = ("osx", "windows")
    WINDOWS_COOKIES_PATHS = (
        "Opera Software\\Opera GX {channel}\\Cookies",
        "Opera Software\\Opera GX {channel}\\Network\\Cookies",
    )
    WINDOWS_CHANNELS = ("Stable",)
    OSX_COOKIE_PATHS = ("~/Library/Application Support/com.operasoftware.OperaGX/Cookies",)
    WINDOWS_COOKIES_PATHS = ("Opera Software\\Opera GX {channel}\\Local State",)
    LINUX_OS_CRYPT_NAME = "chromium"
    OSX_KEY_SERVICE = "Opera Safe Storage"
    OSX_KEY_USER = "Opera"


class Brave(ChromiumBased):
    NAME = "Brave"
    LINUX_COOKIE_PATHS = (
        "~/.config/BraveSoftware/Brave-Browser{channel}/Default/Cookies",
        "~/.config/BraveSoftware/Brave-Browser{channel}/Profile */Cookies",
        "~/.var/app/com.brave.Browser/config/BraveSoftware/Brave-Browser{channel}/Default/Cookies",
        "~/.var/app/com.brave.Browser/config/BraveSoftware/Brave-Browser{channel}/Profile */Cookies",
    )
    LINUX_CHANNELS = ("", "-Beta", "-Dev", "-Nightly")
    WINDOWS_COOKIE_PATHS = (
        "BraveSoftware\\Brave-Browser{channel}\\User Data\\Default\\Cookies",
        "BraveSoftware\\Brave-Browser{channel}\\User Data\\Default\\Network\\Cookies",
        "BraveSoftware\\Brave-Browser{channel}\\User Data\\Profile *\\Cookies",
        "BraveSoftware\\Brave-Browser{channel}\\User Data\\Profile *\\Network\\Cookies",
    )
    WINDOWS_CHANNELS = ("", "-Beta", "-Dev", "-Nightly")

    OSX_COOKIE_PATHS = (
        "~/Library/Application Support/BraveSoftware/Brave-Browser{channel}/Default/Cookies",
        "~/Library/Application Support/BraveSoftware/Brave-Browser{channel}/Profile */Cookies",
    )
    OSX_CHANNELS = ("", "-Beta", "-Dev", "-Nightly")
    WINDOWS_KEY_PATHS = ("BraveSoftware\\Brave-Browser{channel}\\User Data\\Local State",)
    LINUX_OS_CRYPT_NAME = "brave"
    OSX_KEY_SERVICE = "Brave Safe Storage"
    OSX_KEY_USER = "Brave"


class Edge(ChromiumBased):
    """Class for Microsoft Edge"""

    NAME = "Edge"

    LINUX_COOKIE_PATHS = (
        "~/.config/microsoft-edge{channel}/Default/Cookies",
        "~/.config/microsoft-edge{channel}/Profile */Cookies",
        "~/.var/app/com.microsoft.Edge/config/microsoft-edge{channel}/Default/Cookies",
        "~/.var/app/com.microsoft.Edge/config/microsoft-edge{channel}/Profile */Cookies",
    )
    LINUX_CHANNELS = ("", "-beta", "-dev")
    WINDOWS_COOKIES_PATHS = (
        "Microsoft\\Edge{channel}\\User Data\\Default\\Cookies",
        "Microsoft\\Edge{channel}\\User Data\\Default\\Network\\Cookies",
        "Microsoft\\Edge{channel}\\User Data\\Profile *\\Cookies",
        "Microsoft\\Edge{channel}\\User Data\\Profile *\\Network\\Cookies",
    )
    WINDOWS_CHANNELS = ("", " Beta", " Dev", " SxS")

    OSX_COOKIE_PATHS = (
        "~/Library/Application Support/Microsoft Edge{channel}/Default/Cookies",
        "~/Library/Application Support/Microsoft Edge{channel}/Profile */Cookies",
    )
    WINDOWS_CHANNELS = ("", " Beta", " Dev", " Canary")
    WINDOWS_COOKIES_PATHS = ("Microsoft\\Edge{channel}\\User Data\\Local State",)
    LINUX_OS_CRYPT_NAME = "chromium"
    OSX_KEY_SERVICE = "Microsoft Edge Safe Storage"
    OSX_KEY_USER = "Microsoft Edge"


class Vivaldi(ChromiumBased):
    """Class for Vivaldi Browser"""

    NAME = "Vivaldi"
    LINUX_COOKIE_PATHS = (
        "~/.config/vivaldi/Default/Cookies",
        "~/.config/vivaldi/Profile */Cookies",
        "~/.config/vivaldi-snapshot/Default/Cookies",
        "~/.config/vivaldi-snapshot/Profile */Cookies",
        "~/.var/app/com.vivaldi.Vivaldi/config/vivaldi/Default/Cookies",
        "~/.var/app/com.vivaldi.Vivaldi/config/vivaldi/Profile */Cookies",
    )
    WINDOWS_COOKIES_PATHS = (
        "Vivaldi\\User Data\\Default\\Cookies",
        "Vivaldi\\User Data\\Default\\Network\\Cookies",
        "Vivaldi\\User Data\\Profile *\\Cookies",
        "Vivaldi\\User Data\\Profile *\\Network\\Cookies",
    )
    OSX_COOKIE_PATHS = (
        "~/Library/Application Support/Vivaldi/Default/Cookies",
        "~/Library/Application Support/Vivaldi/Profile */Cookies",
    )
    WINDOWS_COOKIES_PATHS = ("Vivaldi\\User Data\\Local State",)
    LINUX_OS_CRYPT_NAME = "chrome"
    OSX_KEY_SERVICE = "Vivaldi Safe Storage"
    OSX_KEY_USER = "Vivaldi"


class FirefoxBased(_Browser):
    """Superclass for Firefox based browsers"""

    LINUX_DATA_DIRS: ClassVar[_StrTuple] = ()
    WINDOWS_DATA_DIRS: ClassVar[tuple[_WinPath, ...]] = ()
    OSX_DATA_DIRS: ClassVar[_StrTuple] = ()

    def _post_init(self):
        self._set_actual_cookie_file_to_use()
        assert self.cookie_file is not None
        # current sessions are saved in sessionstore.js
        cookies_dir = os.path.dirname(self.cookie_file)
        self.session_file: _ExpandedPath = _ExpandedPath(os.path.join(cookies_dir, "sessionstore.js"))
        self.session_file_lz4: _ExpandedPath = _ExpandedPath(
            os.path.join(cookies_dir, "sessionstore-backups", "recovery.jsonlz4")
        )

    @staticmethod
    def get_default_profile(user_data_path: str) -> str:
        config = configparser.ConfigParser()
        profiles_ini_path_list: list[str] = glob.glob(os.path.join(user_data_path + "**", "profiles.ini"))
        fallback_path = user_data_path + "**"

        if not profiles_ini_path_list:
            return fallback_path

        profiles_ini_path = profiles_ini_path_list[0]
        _ = config.read(profiles_ini_path, encoding="utf8")

        profile_path = None
        for section in config.sections():
            if section.startswith("Install"):
                profile_path = config[section].get("Default")
                break
            # in ff 72.0.1, if both an Install section and one with Default=1 are present, the former takes precedence
            elif config[section].get("Default") == "1" and not profile_path:
                profile_path = config[section].get("Path")

        for section in config.sections():
            # the Install section has no relative/absolute info, so check the profiles
            if config[section].get("Path") == profile_path:
                absolute = config[section].get("IsRelative") == "0"
                return profile_path if absolute else os.path.join(os.path.dirname(profiles_ini_path), profile_path)  # type: ignore

        return fallback_path

    @classmethod
    def __expand_and_check_path(cls, *paths: Union[_WinPath, str]) -> str:
        """Expands a path to a list of paths and returns the first one that exists"""
        for path in paths:
            if isinstance(path, tuple):
                expanded = _expand_win_path(path)
            else:
                expanded = os.path.expanduser(path)
            if os.path.isdir(expanded):
                return expanded
        raise BrowserCookieError(f"Could not find {cls.NAME} profile directory")

    @classmethod
    def _get_default_cookie_file_for(cls, os_name: SupportedOS) -> Optional[_ExpandedPath]:
        data_dirs = None
        if os_name == "osx":
            data_dirs = cls.OSX_DATA_DIRS
        elif os_name == "linux":
            data_dirs = cls.LINUX_DATA_DIRS
        elif os_name == "windows":
            data_dirs = cls.WINDOWS_DATA_DIRS

        if data_dirs:
            user_data_path = cls.__expand_and_check_path(*data_dirs)
            profile = cls.get_default_profile(user_data_path)
            cookie_files: list[str] = glob.glob(os.path.join(profile, "cookies.sqlite")) or []
            if cookie_files:
                return _ExpandedPath(cookie_files[0])

    @staticmethod
    def __create_session_cookie(cookie_json: _DictCookies) -> http.cookiejar.Cookie:
        return create_cookie(
            cookie_json.get("host", ""),
            cookie_json.get("path", ""),
            cookie_json.get("secure", False),
            None,
            cookie_json.get("name", ""),
            cookie_json.get("value", ""),
            cookie_json.get("httponly", False),
        )

    def __add_session_cookies(self, cj: http.cookiejar.CookieJar) -> None:
        if not os.path.exists(self.session_file):
            return
        try:
            with Path(self.session_file).open("rb") as file_obj:
                json_data: _NestedJson[_DictCookies] = json.load(file_obj)
        except ValueError as e:
            print(f"Error parsing {self.NAME} session JSON: {e}")  # noqa: T201
        else:
            for window in json_data.get("windows", []):
                for cookie in window.get("cookies", []):
                    if self.domain_name == "" or self.domain_name in cookie.get("host", ""):
                        cj.set_cookie(self.__create_session_cookie(cookie))

    def __add_session_cookies_lz4(self, cj: http.cookiejar.CookieJar) -> None:
        if not os.path.exists(self.session_file_lz4):
            return
        try:
            with Path(self.session_file_lz4).open("rb") as file_obj:
                file_obj.read(8)
                json_data: _Json[_DictCookies] = json.loads(lz4.block.decompress(file_obj.read()))
        except ValueError as e:
            print(f"Error parsing {self.NAME} session JSON LZ4: {e}")  # noqa: T201
        else:
            for cookie in json_data.get("cookies", []):
                if self.domain_name == "" or self.domain_name in cookie.get("host", ""):
                    cj.set_cookie(self.__create_session_cookie(cookie))

    def load(self) -> http.cookiejar.CookieJar:
        cj = http.cookiejar.CookieJar()
        # firefoxbased seems faster with legacy mode
        assert self.cookie_file is not None
        with _DatabaseConnetion(self.cookie_file, True) as con:
            cur = con.cursor()
            query = "select host, path, isSecure, expiry, name, value, isHttpOnly from moz_cookies where host like ?"
            try:
                cur.execute(query, (f"%{self.domain_name}%",))
            except sqlite3.DatabaseError as e:
                if e.args[0].startswith(("no such table: ", "file is not a database")):
                    raise BrowserCookieError(f"File {self.cookie_file} is not a Firefox cookie file") from None
                raise

            for item in cur.fetchall():
                host, path, secure, expires, name, value, http_only = item
                cookie = create_cookie(host, path, secure, expires, name, value, http_only)
                cj.set_cookie(cookie)

        self.__add_session_cookies(cj)
        self.__add_session_cookies_lz4(cj)

        return cj


class Firefox(FirefoxBased):
    """Class for Firefox"""

    NAME = "Firefox"
    LINUX_DATA_DIRS = (
        "~/snap/firefox/common/.mozilla/firefox",
        "~/.mozilla/firefox",
    )
    WINDOWS_DATA_DIRS = (
        _WinPath("APPDATA", r"Mozilla\Firefox"),
        _WinPath("LOCALAPPDATA", r"Mozilla\Firefox"),
    )
    OSX_DATA_DIRS = ("~/Library/Application Support/Firefox",)


class LibreWolf(FirefoxBased):
    """Class for LibreWolf"""

    NAME = "LibreWolf"
    LINUX_DATA_DIRS = (
        "~/snap/librewolf/common/.librewolf",
        "~/.librewolf",
    )
    WINDOWS_DATA_DIRS = (
        _WinPath("APPDATA", "librewolf"),
        _WinPath("LOCALAPPDATA", "librewolf"),
    )
    OS_DATA_DIRS = ("~/Library/Application Support/librewolf",)


class Safari(_Browser):
    """Class for Safari"""

    NAME = "Safari"
    APPLE_TO_UNIX_TIME = 978307200
    NEW_ISSUE_MESSAGE = f"Page format changed.\nPlease create a new issue on: {_NEW_ISSUE_URL}"
    OSX_COOKIE_PATHS: ClassVar[_StrTuple] = (
        "~/Library/Containers/com.apple.Safari/Data/Library/Cookies/Cookies.binarycookies",
        "~/Library/Cookies/Cookies.binarycookies",
    )

    def _post_init(self, cookie_file: Optional[str] = None, domain_name: str = "") -> None:
        self.__offset = 0
        self._set_actual_cookie_file_to_use()
        assert self.cookie_file is not None
        self.__buffer: BufferedReader = Path(self.cookie_file).open("rb")
        self.__parse_header()

    def _get_default_cookie_file_for(self, os_name: SupportedOS) -> Optional[_ExpandedPath]:
        if os_name == "osx":
            return _expand_paths("osx", *self.OSX_COOKIE_PATHS)

    def __del__(self) -> None:
        if self.__buffer:
            self.__buffer.close()

    def __read_file(self, size: int, offset: Optional[int] = None) -> BytesIO:
        if offset is not None:
            self.__offset = offset
        self.__buffer.seek(self.__offset)
        self.__offset += size
        return BytesIO(self.__buffer.read(size))

    def __parse_header(self) -> None:
        assert self.__buffer.read(4) == b"cook", "Not a safari cookie file"
        self.__total_page: int = struct.unpack(">I", self.__buffer.read(4))[0]
        self.__page_sizes: list[int] = []
        for _ in range(self.__total_page):
            self.__page_sizes.append(struct.unpack(">I", self.__buffer.read(4))[0])

    @staticmethod
    def __read_until_null(file: BytesIO, decode: bool = True) -> Union[list[bytes], str]:
        data: list[bytes] = []
        while True:
            byte = file.read(1)
            if byte == b"\x00":
                break
            data.append(byte)
        byte_array = b"".join(data)
        if decode:
            byte_array = byte_array.decode("utf-8")
        return data

    def __parse_cookie(self, page: BytesIO, cookie_offset: int) -> http.cookiejar.Cookie:
        page.seek(cookie_offset)
        # cookie size, keep it for future use and better understanding
        _ = struct.unpack("<I", page.read(4))[0]
        page.seek(4, 1)  # skip 4-bytes unknown data
        flags = struct.unpack("<I", page.read(4))[0]
        page.seek(4, 1)  # skip 4-bytes unknown data
        is_secure = bool(flags & 0x1)
        is_httponly = bool(flags & 0x4)

        host_offset = struct.unpack("<I", page.read(4))[0]
        name_offset = struct.unpack("<I", page.read(4))[0]
        path_offset = struct.unpack("<I", page.read(4))[0]
        value_offset = struct.unpack("<I", page.read(4))[0]
        comment_offset = struct.unpack("<I", page.read(4))[0]

        assert page.read(4) == b"\x00\x00\x00\x00", self.NEW_ISSUE_MESSAGE
        expiry_date = int(struct.unpack("<d", page.read(8))[0] + self.APPLE_TO_UNIX_TIME)  # convert to unix time
        # creation time, keep it for future use and better understanding
        _ = int(struct.unpack("<d", page.read(8))[0] + self.APPLE_TO_UNIX_TIME)  # convert to unix time

        def read_until_null(offset: int) -> str:
            nonlocal page
            page.seek(cookie_offset + offset, 0)
            return self.__read_until_null(page)  # type: ignore

        host = read_until_null(host_offset)
        name = read_until_null(name_offset)
        path = read_until_null(path_offset)
        value = read_until_null(value_offset)
        if comment_offset:
            # comment, keep it for future use and better understanding
            _ = read_until_null(comment_offset)

        return create_cookie(host, path, is_secure, expiry_date, name, value, is_httponly)

    def __domain_filter(self, cookie: http.cookiejar.Cookie) -> bool:
        if not self.domain_name:
            return True
        return self.domain_name in cookie.domain

    def __parse_page(self, page_index: int) -> Generator[http.cookiejar.Cookie]:
        offset = 8 + self.__total_page * 4 + sum(self.__page_sizes[:page_index])
        page = self.__read_file(self.__page_sizes[page_index], offset)
        assert page.read(4) == b"\x00\x00\x01\x00", self.NEW_ISSUE_MESSAGE
        n_cookies = struct.unpack("<I", page.read(4))[0]
        cookie_offsets = []
        for _ in range(n_cookies):
            cookie_offsets.append(struct.unpack("<I", page.read(4))[0])
        assert page.read(4) == b"\x00\x00\x00\x00", self.NEW_ISSUE_MESSAGE

        for offset in cookie_offsets:
            yield self.__parse_cookie(page, offset)

    def load(self) -> http.cookiejar.CookieJar:
        cj = http.cookiejar.CookieJar()
        for page in range(self.__total_page):
            for cookie in self.__parse_page(page):
                if self.__domain_filter(cookie):
                    cj.set_cookie(cookie)
        return cj


class Lynx(_SimpleBrowser):
    """Class for Lynx"""

    NAME = "Lynx"
    SUPPORTED_OPERATING_SYSTEMS = ("linux",)
    LINUX_COOKIE_PATHS: ClassVar[_StrTuple] = (
        "~/.lynx_cookies",  # most systems, see lynx man page
        "~/cookies",  # MS-DOS
    )

    def load(self) -> http.cookiejar.CookieJar:
        cookie_jar = http.cookiejar.CookieJar()
        assert self.cookie_file is not None
        with Path(self.cookie_file).open() as f:
            for line in f.read().splitlines():
                # documentation in source code of lynx, file src/LYCookie.c
                domain, _, path, secure, expires, name, value = [
                    None if word == "" else word for word in line.split("\t")
                ]
                assert domain is not None
                assert path is not None
                assert name is not None
                if expires is not None:
                    expires = int(expires)
                secure = secure == "TRUE"
                if self.domain_name in domain:
                    cookie = create_cookie(domain, path, secure, expires, name, value, False)
                    cookie_jar.set_cookie(cookie)
        return cookie_jar


class W3m(_SimpleBrowser):
    """Class for W3m"""

    NAME = "W3m"
    SUPPORTED_OPERATING_SYSTEMS = ("linux",)
    # see documentation in source code of w3m, file fm.h
    COO_USE: ClassVar[int] = 1
    COO_SECURE: ClassVar[int] = 2
    COO_DOMAIN: ClassVar[int] = 4
    COO_PATH: ClassVar[int] = 8
    COO_DISCARD: ClassVar[int] = 16
    COO_OVERRIDE: ClassVar[int] = 32
    LINUX_COOKIE_PATHS: ClassVar[_StrTuple] = ("~/.w3m/cookie",)

    def load(self) -> http.cookiejar.CookieJar:
        cookie_jar = http.cookiejar.CookieJar()
        assert self.cookie_file is not None
        with Path(self.cookie_file).open() as f:
            for line in f.read().splitlines():
                # see documentation in source code of w3m, file cookie.c
                url, name, value, expires, domain, path, flag, version, comment, port, comment_url = [
                    None if word == "" else word for word in line.split("\t")
                ]
                assert domain is not None
                assert path is not None
                assert name is not None
                assert flag is not None
                assert expires is not None
                if version is not None:
                    version = int(version)
                flag = int(flag)
                expires = int(expires)
                secure = bool(flag & self.COO_SECURE)
                domain_specified = bool(flag & self.COO_DOMAIN)
                path_specified = bool(flag & self.COO_PATH)
                discard = bool(flag & self.COO_DISCARD)
                if self.domain_name in domain:
                    cookie = http.cookiejar.Cookie(
                        version,
                        name,
                        value,
                        port,
                        bool(port),
                        domain,
                        domain_specified,
                        domain.startswith("."),
                        path,
                        path_specified,
                        secure,
                        expires,
                        discard,
                        comment,
                        comment_url,
                        {},
                    )
                    cookie_jar.set_cookie(cookie)
        return cookie_jar


def create_cookie(
    host: str, path: str, secure: bool, expires: Optional[int], name: str, value: Optional[str], http_only: bool
) -> http.cookiejar.Cookie:
    """Shortcut function to create a cookie"""
    # HTTPOnly flag goes in _rest, if present (see https://github.com/python/cpython/pull/17471/files#r511187060)
    rest = {"HTTPOnly": ""} if http_only else {}
    port = comment = comment_url = None
    port_speficied = bool(port)
    version = 0
    domain_specified = domain_initial_dot = host.startswith(".")
    path_specified = bool(path)
    discard = False
    return http.cookiejar.Cookie(
        version,
        name,
        value,
        port,
        port_speficied,
        host,
        domain_specified,
        domain_initial_dot,
        path,
        path_specified,
        secure,
        expires,
        discard,
        comment,
        comment_url,
        rest,
    )


def chrome(
    cookie_file: Optional[str] = None, domain_name: str = "", key_file: Optional[str] = None
) -> http.cookiejar.CookieJar:
    """Returns a cookiejar of the cookies and sessions used by Google Chrome.

    Optionally pass in a domain name to only load cookies from the specified domain"""
    return Chrome(cookie_file, domain_name, key_file).load()


def arc(
    cookie_file: Optional[str] = None, domain_name: str = "", key_file: Optional[str] = None
) -> http.cookiejar.CookieJar:
    """Returns a cookiejar of the cookies and sessions used by Arc.

    Optionally pass in a domain name to only load cookies from the specified domain"""
    return Arc(cookie_file, domain_name, key_file).load()


def chromium(
    cookie_file: Optional[str] = None, domain_name: str = "", key_file: Optional[str] = None
) -> http.cookiejar.CookieJar:
    """Returns a cookiejar of the cookies used by Chromium. Optionally pass in a
    domain name to only load cookies from the specified domain
    """
    return Chromium(cookie_file, domain_name, key_file).load()


def opera(
    cookie_file: Optional[str] = None, domain_name: str = "", key_file: Optional[str] = None
) -> http.cookiejar.CookieJar:
    """Returns a cookiejar of the cookies and sessions used by Opera.

    Optionally pass in a domain name to only load cookies from the specified domain"""
    return Opera(cookie_file, domain_name, key_file).load()


def opera_gx(
    cookie_file: Optional[str] = None, domain_name: str = "", key_file: Optional[str] = None
) -> http.cookiejar.CookieJar:
    """Returns a cookiejar of the cookies and sessions used by Opera GX.

    Optionally pass in a domain name to only load cookies from the specified domain"""
    return OperaGX(cookie_file, domain_name, key_file).load()


def brave(
    cookie_file: Optional[str] = None, domain_name: str = "", key_file: Optional[str] = None
) -> http.cookiejar.CookieJar:
    """Returns a cookiejar of the cookies and sessions used by Brave.

    Optionally pass in a domain name to only load cookies from the specified domain"""
    return Brave(cookie_file, domain_name, key_file).load()


def edge(
    cookie_file: Optional[str] = None, domain_name: str = "", key_file: Optional[str] = None
) -> http.cookiejar.CookieJar:
    """Returns a cookiejar of the cookies and sessions used by Microsoft Edge.

    Optionally pass in a domain name to only load cookies from the specified domain"""
    return Edge(cookie_file, domain_name, key_file).load()


def vivaldi(
    cookie_file: Optional[str] = None, domain_name: str = "", key_file: Optional[str] = None
) -> http.cookiejar.CookieJar:
    """Returns a cookiejar of the cookies and sessions used by Vivaldi.

    Optionally pass in a domain name to only load cookies from the specified domain"""
    return Vivaldi(cookie_file, domain_name, key_file).load()


def firefox(
    cookie_file: Optional[str] = None, domain_name: str = "", key_file: Optional[str] = None
) -> http.cookiejar.CookieJar:
    """Returns a cookiejar of the cookies and sessions used by Firefox.

    Optionally pass in a domain name to only load cookies from the specified domain"""
    return Firefox(cookie_file, domain_name, key_file).load()


def librewolf(
    cookie_file: Optional[str] = None, domain_name: str = "", key_file: Optional[str] = None
) -> http.cookiejar.CookieJar:
    """Returns a cookiejar of the cookies and sessions used by LibreWolf.

    Optionally pass in a domain name to only load cookies from the specified domain"""
    return LibreWolf(cookie_file, domain_name, key_file).load()


def safari(cookie_file: Optional[str] = None, domain_name: str = "", key_file: Optional[str] = None):
    """Returns a cookiejar of the cookies and sessions used by Safari.

    Optionally pass in a domain name to only load cookies from the specified domain"""
    return Safari(cookie_file, domain_name).load()


def lynx(cookie_file: Optional[str] = None, domain_name: str = "") -> http.cookiejar.CookieJar:
    """Returns a cookiejar of the cookies and sessions used by Lynx.

    Optionally pass in a domain name to only load cookies from the specified domain
    """
    return Lynx(cookie_file, domain_name).load()


def w3m(cookie_file: Optional[str] = None, domain_name: str = "") -> http.cookiejar.CookieJar:
    """Returns a cookiejar of the cookies and sessions used by W3m.

    Optionally pass in a domain name to only load cookies from the specified domain"""
    return W3m(cookie_file, domain_name).load()


ALL_BROWSERS: list[type[_Browser]] = [
    Chrome,
    Chromium,
    Opera,
    OperaGX,
    Brave,
    Edge,
    Vivaldi,
    Firefox,
    LibreWolf,
    Safari,
    Lynx,
    W3m,
    Arc,
]
ALL_EXTRACTORS: list[_CookieExtractor] = [
    chrome,
    chromium,
    opera,
    opera_gx,
    brave,
    edge,
    vivaldi,
    firefox,
    librewolf,
    safari,
    lynx,
    w3m,
    arc,
]


all_browsers = ALL_EXTRACTORS  # Old name


def load(domain_name: str = "") -> http.cookiejar.CookieJar:
    """Try to load cookies from all supported browsers and return combined cookiejar
    Optionally pass in a domain name to only load cookies from the specified domain
    """
    cj = http.cookiejar.CookieJar()
    for browser in ALL_BROWSERS:
        if not browser.is_supported():
            continue
        try:
            for cookie in browser(domain_name=domain_name).load():
                cj.set_cookie(cookie)
        except BrowserCookieError:
            pass
    return cj


__all__ = [
    "ALL_BROWSERS",
    "ALL_EXTRACTORS",
    "BrowserCookieError",
    "all_browsers",
    "arc",
    "brave",
    "chrome",
    "chromium",
    "edge",
    "firefox",
    "librewolf",
    "load",
    "lynx",
    "opera",
    "opera_gx",
    "safari",
    "vivaldi",
    "w3m",
]


if __name__ == "__main__":
    print(load())  # noqa: T201
