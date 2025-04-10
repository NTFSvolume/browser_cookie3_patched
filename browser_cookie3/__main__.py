from __future__ import annotations

import argparse
import json
from typing import TYPE_CHECKING, Optional

import browser_cookie3

if TYPE_CHECKING:
    from collections.abc import Sequence
    from http.cookiejar import Cookie, CookieJar


def parse_args(args: Optional[Sequence[str]] = None):
    parser = argparse.ArgumentParser(
        description="Extract browser cookies using browser_cookie3.",
        epilog="Exit status is 0 if cookie was found, 1 if not found, and 2 if errors occurred",
    )
    parser.add_argument(
        "-j",
        "--json",
        action="store_true",
        help="Output JSON with all cookie details, rather than just the cookie's value",
    )
    parser.add_argument("domain")
    parser.add_argument("name")
    group = parser.add_argument_group("Browser selection")
    mutually_exclusive_group = group.add_mutually_exclusive_group()
    mutually_exclusive_group.add_argument(
        "-a",
        "--all",
        dest="browser",
        action="store_const",
        const=None,
        default=None,
        help="Try to load cookies from all supported browsers",
    )
    for browser in browser_cookie3.all_browsers:
        mutually_exclusive_group.add_argument(
            "--" + browser.__name__,
            dest="browser",
            action="store_const",
            const=browser,
            help=f"Load cookies from {browser.__name__.title()} browser",
        )
    group.add_argument("-f", "--cookie-file", help="Use specific cookie file (default is to autodetect).")
    group.add_argument("-k", "--key-file", help="Use specific key file (default is to autodetect).")

    parsed_args = parser.parse_args(args)

    if not parsed_args.browser and (parsed_args.cookie_file or parsed_args.key_file):
        parser.error("Must specify a specific browser with --cookie-file or --key-file arguments")

    return parser, parsed_args


def dump_cookie(cookie: Cookie) -> str:
    return json.dumps({k: v for k, v in vars(cookie).items() if v is not None and (k, v) != ("_rest", {})})


def main(args: Optional[Sequence[str]] = None):
    parser, p_args = parse_args(args)

    try:
        if p_args.browser:
            cookie_jar: CookieJar = p_args.browser(cookie_file=p_args.cookie_file, key_file=p_args.key_file)
        else:
            cookie_jar = browser_cookie3.load()

    except browser_cookie3.BrowserCookieError as e:
        parser.error(e.args[0])

    for cookie in cookie_jar:
        if cookie.domain in (p_args.domain, "." + p_args.domain) and cookie.name == p_args.name:
            if not p_args.json:
                print(cookie.value)  # noqa T201
            else:
                print(dump_cookie(cookie))  # noqa T201
            break
    else:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
