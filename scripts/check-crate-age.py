#!/usr/bin/env python3
"""Fails when Cargo.lock locks a crates.io release younger than a minimum age.

Usage: python3 scripts/check-crate-age.py <Cargo.lock> [<base Cargo.lock>]

With a base lock file, only the packages whose name and version are not in the
base are checked; a base of "-" is read from standard input, such as the
output of `git show HEAD:panel/Cargo.lock`. The minimum age is MIN_CRATE_AGE_DAYS days, 14 by default.
For each release that is too young, the newest semver-compatible release that
is old enough is named, as the `cargo update --precise` command that locks it.

A release that fixes a security advisory may be locked at any age when it is
listed in crate-age-exceptions.toml beside the lock file, as an [[exception]]
table with the crate, its exact version, the advisory id (RUSTSEC, CVE or
GHSA) and a reason. A malformed entry stops the check.

Exit status: 0 when every checked release is old enough, 1 when one is too
young, 2 when the check could not be completed.
"""

import datetime
import json
import os
import re
import sys
import time
import tomllib
import urllib.error
import urllib.parse
import urllib.request

CRATES_IO = "registry+https://github.com/rust-lang/crates.io-index"
API = "https://crates.io/api/v1/crates/"
USER_AGENT = "crate-age-check"
# crates.io asks automated clients for at most one request per second.
REQUEST_INTERVAL_SECONDS = 1.0
ATTEMPTS = 4
EXCEPTIONS_FILE = "crate-age-exceptions.toml"
EXCEPTION_FIELDS = ("crate", "version", "advisory", "reason")
ADVISORY_ID = re.compile(
    r"RUSTSEC-\d{4}-\d{4}|CVE-\d{4}-\d{4,}|GHSA(?:-[23456789cfghjmpqrvwx]{4}){3}"
)


def security_fixes(lock_path):
    """Returns {(name, version): advisory} for the releases listed in the
    exceptions file beside the lock file, or {} when there is no such file.
    Raises RuntimeError for a malformed entry."""
    path = os.path.join(os.path.dirname(os.path.abspath(lock_path)), EXCEPTIONS_FILE)
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "rb") as exceptions_file:
            listed = tomllib.load(exceptions_file).get("exception", [])
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise RuntimeError(f"{path}: {error}") from error
    fixes = {}
    for number, entry in enumerate(listed, start=1):
        missing = [
            field
            for field in EXCEPTION_FIELDS
            if not isinstance(entry.get(field), str) or not entry[field].strip()
        ]
        if missing:
            raise RuntimeError(f"{path}: exception {number} has no {', '.join(missing)}")
        if not ADVISORY_ID.fullmatch(entry["advisory"]):
            raise RuntimeError(
                f"{path}: exception {number}: '{entry['advisory']}' is not a RUSTSEC, "
                "CVE or GHSA advisory id"
            )
        fixes[(entry["crate"], entry["version"])] = entry["advisory"]
    return fixes


def locked_releases(path):
    """Returns the set of (name, version) crates.io releases a lock file locks.
    A path of "-" reads the lock file from standard input."""
    if path == "-":
        lock = tomllib.load(sys.stdin.buffer)
    else:
        with open(path, "rb") as lock_file:
            lock = tomllib.load(lock_file)
    return {
        (package["name"], package["version"])
        for package in lock.get("package", [])
        if package.get("source") == CRATES_IO
    }


class CratesIo:
    """A crates.io API client that paces and retries its requests."""

    def __init__(self):
        self.last_request = 0.0

    def get(self, path):
        url = API + path
        for attempt in range(1, ATTEMPTS + 1):
            wait = self.last_request + REQUEST_INTERVAL_SECONDS - time.monotonic()
            if wait > 0:
                time.sleep(wait)
            self.last_request = time.monotonic()
            request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            try:
                with urllib.request.urlopen(request, timeout=30) as response:
                    return json.load(response)
            except urllib.error.HTTPError as error:
                if error.code not in (429, 500, 502, 503, 504) or attempt == ATTEMPTS:
                    raise RuntimeError(f"{url}: HTTP {error.code}") from error
                reason = f"HTTP {error.code}"
            except (urllib.error.URLError, TimeoutError) as error:
                if attempt == ATTEMPTS:
                    raise RuntimeError(f"{url}: {error}") from error
                reason = str(error)
            print(f"retrying {url} after {reason}", flush=True)
            time.sleep(2**attempt)
        raise RuntimeError(f"{url}: no response after {ATTEMPTS} attempts")


def published(created_at):
    return datetime.datetime.fromisoformat(created_at.replace("Z", "+00:00"))


def compatibility_key(version):
    """The part of a version that caret requirements hold fixed: the major
    version from 1.0 on, the minor version below it, the patch below 0.1."""
    core = version.split("+")[0].split("-")[0]
    major, minor, patch = (int(part) for part in core.split("."))
    if major > 0:
        return (major,)
    if minor > 0:
        return (0, minor)
    return (0, 0, patch)


def replacement(client, name, version, cutoff):
    """The newest non-yanked, non-prerelease release compatible with `version`
    and published before `cutoff`, or None when there is none."""
    key = compatibility_key(version)
    candidates = []
    for release in client.get(urllib.parse.quote(name))["versions"]:
        number = release["num"]
        if release["yanked"] or "-" in number.split("+")[0]:
            continue
        if compatibility_key(number) != key or published(release["created_at"]) > cutoff:
            continue
        candidates.append((published(release["created_at"]), number))
    if not candidates:
        return None
    return max(candidates)[1]


def main(argv):
    if len(argv) not in (2, 3):
        print(__doc__.strip().splitlines()[2], file=sys.stderr)
        return 2
    min_days = int(os.environ.get("MIN_CRATE_AGE_DAYS", "14"))
    releases = locked_releases(argv[1])
    if len(argv) == 3:
        releases -= locked_releases(argv[2])
    try:
        fixes = security_fixes(argv[1])
    except RuntimeError as error:
        print(f"check incomplete: {error}", file=sys.stderr, flush=True)
        return 2
    for name, version in sorted(releases & fixes.keys()):
        print(f"accepted at any age as the fix for {fixes[(name, version)]}: {name} {version}", flush=True)
    releases -= fixes.keys()
    now = datetime.datetime.now(datetime.timezone.utc)
    cutoff = now - datetime.timedelta(days=min_days)
    print(f"checking {len(releases)} crates.io releases against a minimum age of {min_days} days", flush=True)
    client = CratesIo()
    young = []
    try:
        for name, version in sorted(releases):
            path = f"{urllib.parse.quote(name)}/{urllib.parse.quote(version)}"
            created = published(client.get(path)["version"]["created_at"])
            if created > cutoff:
                age = (now - created).total_seconds() / 86400
                young.append((name, version, age))
                print(f"too young: {name} {version}, published {age:.1f} days ago", flush=True)
        if not young:
            print("every checked release is old enough", flush=True)
            return 0
        for name, version, _age in young:
            older = replacement(client, name, version, cutoff)
            if older is None:
                print(f"no compatible release of {name} is {min_days} days old; "
                      f"a dependency requirement must change", flush=True)
            else:
                print(f"cargo update -p {name}@{version} --precise {older}", flush=True)
    except RuntimeError as error:
        print(f"check incomplete: {error}", file=sys.stderr, flush=True)
        return 2
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
