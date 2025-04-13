import os

from browser_cookie3 import _CURRENT_OS

from . import BrowserName as B
from . import logger


def get_username() -> str:
    try:
        return os.getlogin()
    except OSError:
        return os.environ.get("USERNAME") or os.environ.get("USER") or ""


_USERNAME = get_username()


_BIN_LOCATIONS = {
    B.CHROME: {
        "linux": ["/usr/bin/google-chrome-stable"],
        "windows": [
            r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        ],
        # Not tested
        "macos": ["/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"],
    },
    B.CHROMIUM: {
        "linux": ["/usr/bin/chromium", "/usr/bin/chromium-browser"],
        "windows": [
            r"C:\Program Files (x86)\Chromium\Application\chrome.exe",
            r"C:\Program Files\Chromium\Application\chrome.exe",
        ],
        # Not tested
        "macos": ["/Applications/Chromium.app/Contents/MacOS/Chromium"],
    },
    B.BRAVE: {
        "linux": ["/usr/bin/brave", "/usr/bin/brave-browser"],
        "windows": [
            r"C:\Program Files (x86)\BraveSoftware\Brave-Browser\Application\brave.exe",
            r"C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe",
            rf"C:\Users\{_USERNAME}\AppData\Local\BraveSoftware\Brave-Browser\Application\brave.exe",
        ],
        # Not tested
        "macos": ["/Applications/Brave Browser.app/Contents/MacOS/Brave Browser"],
    },
    B.EDGE: {
        "linux": ["/usr/bin/microsoft-edge-stable"],
        "windows": [
            r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
            r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
        ],
        # Not tested
        "macos": ["/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge"],
    },
    B.FIREFOX: {
        "linux": ["/usr/bin/firefox"],
        "windows": [
            r"C:\Program Files (x86)\Mozilla Firefox\firefox.exe",
            r"C:\Program Files\Mozilla Firefox\firefox.exe",
        ],
        # Not tested
        "macos": ["/Applications/Firefox.app/Contents/MacOS/firefox"],
    },
    B.LIBREWOLF: {
        "linux": ["/usr/bin/librewolf"],
        "windows": [
            r"C:\Program Files (x86)\LibreWolf\librewolf.exe",
            r"C:\Program Files\LibreWolf\librewolf.exe",
            rf"C:\Users\{_USERNAME}\AppData\Local\LibreWolf\librewolf.exe",
        ],
        # Not tested
        "macos": ["/Applications/LibreWolf.app/Contents/MacOS/LibreWolf"],
    },
    B.OPERA: {
        "linux": ["/usr/bin/opera"],
        "windows": [
            r"C:\Program Files (x86)\Opera\opera.exe",
            r"C:\Program Files\Opera\opera.exe",
            rf"C:\Users\{_USERNAME}\AppData\Local\Programs\Opera\opera.exe",
        ],
        "macos": ["/Applications/Opera.app/Contents/MacOS/Opera"],  # Not tested
    },
    B.OPERA_GX: {
        "linux": [],
        "windows": [
            r"C:\Program Files (x86)\Opera GX\opera.exe",
            r"C:\Program Files\Opera GX\opera.exe",
            rf"C:\Users\{_USERNAME}\AppData\Local\Programs\Opera GX\opera.exe",
        ],
        # Not tested
        "macos": ["/Applications/Opera GX.app/Contents/MacOS/Opera GX"],
    },
    B.VIVALDI: {
        "linux": ["/usr/bin/vivaldi-stable"],
        "windows": [
            r"C:\Program Files (x86)\Vivaldi\Application\vivaldi.exe",
            r"C:\Program Files\Vivaldi\Application\vivaldi.exe",
            rf"C:\Users\{_USERNAME}\AppData\Local\Vivaldi\Application\vivaldi.exe",
        ],
        # Not tested
        "macos": ["/Applications/Vivaldi.app/Contents/MacOS/Vivaldi"],
    },
}


class BinaryLocation:
    def __init__(self, raise_not_found: bool = False):
        self.__raise_not_found = raise_not_found
        if _CURRENT_OS == "unknown":
            raise ValueError("unsupported os")
        self.__os = _CURRENT_OS

    def get(self, browser: str) -> str:  # type: ignore
        for path in _BIN_LOCATIONS[browser][self.__os]:
            if os.path.exists(path):
                logger.info(f"found {browser} binary at: {path}")
                return path
        if self.__raise_not_found:
            raise FileNotFoundError("browser not found")
        logger.warning(f"could not find {browser} binary")
