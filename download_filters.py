#!/usr/bin/env python3
"""
Pi-hole / AdGuard blocklist builder - download_filters.py
Version: v0.0.1
Author: Igor Brzezek
GitHub: https://github.com/IgorBrzezek/badDomainCompilator

Download filter files from:
  https://github.com/MajkiIT/polish-ads-filter/tree/master/polish-pihole-filters
(by default) or from user-supplied addresses.

Usage:
  python3 download_filters.py --help                 # show help (also shown when no options are given)
  python3 download_filters.py --ext txt              # downloads files to ./bad_domains/
  python3 download_filters.py --outdir mydir --ext txt
  python3 download_filters.py --addr URL [--addr URL2 ...]
  python3 download_filters.py --list list.txt      # file URLs, raw URLs and
                                                   # GitHub directory (tree) URLs
  python3 download_filters.py --compact --outfile merged.txt
  python3 download_filters.py --compact --outfile merged.txt --diff
  python3 download_filters.py --outdir filters --compact --outfile merged.txt --diff
  python3 download_filters.py -q --compact --outfile merged.txt --diff   # quiet, no output
  python3 download_filters.py --compact --outfile merged.txt --diff --send user@mail:/tmp
  python3 download_filters.py --compact --outfile merged.txt --send user@mail:/tmp --pwdfile ~/.secret
  python3 download_filters.py --ext txt --compact --outfile merged.txt --log run.log

Options:
  --addr ADDRESS      - URL of a file to download; can be used multiple times,
                        e.g. --addr URL1 --addr URL2. A GitHub directory page
                        (https://github.com/OWNER/REPO/tree/BRANCH/DIR) is also
                        accepted: all files from that directory are downloaded.
                        A GitHub file page (.../blob/BRANCH/FILE) is converted
                        to its raw URL automatically. If --addr and/or --list
                        is given, the script does NOT use the hardcoded GitHub
                        source, only the given addresses.
  --list LISTFILE     - text file with a list of URLs (one per line;
                        '#' starts a comment - the rest of the line is ignored).
                        May mix file URLs and GitHub directory (tree) URLs.
  --ext EXT           - download only files with this extension, e.g. --ext txt.
                        Leading dot is optional (--ext txt == --ext .txt),
                        case-insensitive. Can be used multiple times and/or as
                        a comma-separated list (--ext txt,md). If omitted, ALL
                        files are downloaded (WARNING: may include binaries
                        and other large files).
  --compact           - merge all lines from the downloaded files into one output file
  --outfile FILENAME  - output file path for --compact mode (default: combined.txt)
  --diff              - when writing the output file, drop duplicate lines
                        (one line = one www address) and print a report of how
                        many repeating lines were removed.
                        Works together with --compact (enables it automatically).
  --outdir DIR        - directory for the individually downloaded files (default: bad_domains)
  --keep-empty        - in --compact mode also keep empty lines (skipped by default)
  --keep-comments     - in --compact mode keep all comment lines (#...) without dedup
                        (by default comments are also deduplicated by --diff)
  --send name@server:directory
                      - send the merged domains file (--compact output) via scp
                        to 'directory' on 'server' as user 'name'.
                        Requires --compact (enabled automatically).
  --pwd PASSWORD      - password for --send (visible in process list - prefer --pwdfile)
  --pwdfile FILENAME  - file containing the password for --send (first line is used).
                        Use either --pwd or --pwdfile, not both. Without both,
                        key-based SSH authentication is used.
  --log FILENAME      - log everything the program does to FILENAME
                        (in addition to console output; also works with -q).
  -q, --quiet         - quiet mode: no messages on stdout/stderr (only exit codes)
"""

import argparse
import json
import re
import shutil
import subprocess
import sys
import urllib.parse
import urllib.request
from datetime import datetime
from pathlib import Path

REPO = "MajkiIT/polish-ads-filter"
SUBDIR = "polish-pihole-filters"
BRANCH = "master"
DEFAULT_OUTDIR = "bad_domains"

__version__ = "0.0.1"
__author__ = "Igor Brzezek"
__url__ = "https://github.com/IgorBrzezek/badDomainCompilator"


def parse_exts(raw_exts):
    """Normalize --ext values: strip dots, lowercase, split commas. Returns set or empty set (= all)."""
    exts = set()
    for item in raw_exts or []:
        for part in item.split(","):
            p = part.strip().lower().lstrip(".")
            if p:
                exts.add(p)
    return exts


def file_matches_ext(name, exts):
    """True if file name matches the wanted extensions (empty exts = match all)."""
    if not exts:
        return True
    suffix = Path(name).suffix.lower().lstrip(".")
    return suffix in exts


def github_api_list_files(exts, owner=None, repo=None, path=None, branch=None):
    """Return [{name, url}] of files in a GitHub repo dir, filtered by extension."""
    owner = owner or REPO.split("/")[0]
    repo = repo or REPO.split("/")[1]
    path = SUBDIR if path is None else path
    branch = branch or BRANCH
    api_url = (f"https://api.github.com/repos/{owner}/{repo}/contents/"
               f"{urllib.parse.quote(path)}?ref={urllib.parse.quote(branch)}")
    req = urllib.request.Request(api_url, headers={"User-Agent": "pihole-filter-downloader"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = json.load(resp)
    raw_base = f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{path}"
    files = []
    for entry in data:
        if entry.get("type") != "file":
            continue
        name = entry.get("name", "")
        if not file_matches_ext(name, exts):
            continue
        # download_url from the API is the most reliable, fallback to a constructed raw URL
        url = entry.get("download_url") or f"{raw_base}/{name}"
        files.append({"name": name, "url": url})
    files.sort(key=lambda x: x["name"])
    return files


def parse_github_tree_url(url):
    """If URL is a GitHub directory page, return {owner, repo, branch, path}, else None."""
    m = re.match(r"https?://github\.com/([^/]+)/([^/]+)/tree/([^/]+)(?:/(.*))?$", url.strip())
    if not m:
        return None
    owner, repo, branch, path = m.group(1), m.group(2), m.group(3), (m.group(4) or "").strip("/")
    return {"owner": owner, "repo": repo, "branch": branch, "path": path}


def parse_github_blob_url(url):
    """If URL is a GitHub file page, return {owner, repo, branch, filepath}, else None."""
    m = re.match(r"https?://github\.com/([^/]+)/([^/]+)/blob/([^/]+)/(.+)$", url.strip())
    if not m:
        return None
    return {"owner": m.group(1), "repo": m.group(2), "branch": m.group(3),
            "filepath": m.group(4).strip("/")}


def expand_custom_urls(urls, exts, msg):
    """Resolve --addr/--list URLs to [{name, url}].

    Supports plain file URLs, GitHub file pages (blob -> raw) and GitHub
    directory pages (tree -> all files of that directory via the API,
    honoring the --ext filter). Returns (files, skipped_urls).
    """
    expanded = []  # (url, suggested_name)
    skipped = []
    counter = 0
    for url in urls:
        tree = parse_github_tree_url(url)
        if tree:
            label = f"{tree['owner']}/{tree['repo']}/{tree['path'] or '.'} (branch {tree['branch']})"
            try:
                dir_files = github_api_list_files(
                    exts, owner=tree["owner"], repo=tree["repo"],
                    path=tree["path"], branch=tree["branch"])
            except Exception as e:
                msg(f"[warning] cannot expand GitHub directory {url}: {e}", file=sys.stderr)
                continue
            if not dir_files:
                msg(f"[warning] GitHub directory {label}: no files match"
                    f"{' (*.' + ', *.'.join(sorted(exts)) + ')' if exts else ''} - skipped.",
                    file=sys.stderr)
                continue
            msg(f"  directory {label}: {len(dir_files)} files.")
            expanded.extend((f["url"], f["name"]) for f in dir_files)
            continue
        blob = parse_github_blob_url(url)
        if blob:
            raw = (f"https://raw.githubusercontent.com/{blob['owner']}/{blob['repo']}/"
                   f"{blob['branch']}/{blob['filepath']}")
            base = Path(blob["filepath"]).name
            if not file_matches_ext(base, exts):
                skipped.append(url)
                continue
            msg(f"  GitHub file page -> raw: {raw}")
            expanded.append((raw, base))
            continue
        base = Path(urllib.parse.urlparse(url).path).name.strip()
        if not base or base in ("/", "."):
            counter += 1
            base = f"file_{counter}"
        if not file_matches_ext(base, exts):
            skipped.append(url)
            continue
        expanded.append((url, base))
    # Guard against file name collisions.
    files = []
    used = set()
    for url, base in expanded:
        name = base
        n = 1
        while name in used:
            n += 1
            stem, dot, suffix = base.rpartition(".")
            name = f"{stem}_{n}.{suffix}" if dot else f"{base}_{n}"
        used.add(name)
        files.append({"name": name, "url": url})
    return files, skipped


def download_file(url, dest: Path):
    req = urllib.request.Request(url, headers={"User-Agent": "pihole-filter-downloader"})
    with urllib.request.urlopen(req, timeout=60) as resp, open(dest, "wb") as f:
        while True:
            chunk = resp.read(64 * 1024)
            if not chunk:
                break
            f.write(chunk)


def read_list_file(path):
    """Read URLs from a text file (one per line, '#' starts a comment)."""
    urls = []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for raw in f:
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            urls.append(line)
    return urls


def suspicious_url_reason(url):
    """Return a warning string if the URL looks like it will not yield a filter list."""
    # GitHub tree (directory) and blob (file) pages are supported - expanded automatically.
    if parse_github_tree_url(url) or parse_github_blob_url(url):
        return None
    if not Path(urllib.parse.urlparse(url).path).suffix:
        return "URL has no file extension - it may download an HTML page instead of a filter list"
    return None


def is_html_file(path: Path):
    """Detect HTML content by sniffing the start of the file."""
    try:
        with open(path, "rb") as f:
            head = f.read(8192).decode("utf-8", errors="ignore").lower()
    except OSError:
        return False
    return "<!doctype html" in head or "<html" in head


def parse_send_target(value):
    """Parse name@server:directory. Returns (name, server, directory) or None."""
    m = re.match(r"^([^@\s]+)@([^:\s]+):(.+)$", (value or "").strip())
    if not m:
        return None
    return m.group(1), m.group(2), m.group(3)


def send_via_scp(local_file, user, server, directory, password):
    """Send local_file via scp to user@server:directory. Returns (ok, message)."""
    if not shutil.which("scp"):
        return False, "scp command not found (install openssh-client)"
    dest = f"{user}@{server}:{directory}"
    if password:
        if not shutil.which("sshpass"):
            return False, "sshpass command not found (install sshpass or use key authentication)"
        cmd = ["sshpass", "-p", password, "scp", str(local_file), dest]
    else:
        cmd = ["scp", str(local_file), dest]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    except subprocess.TimeoutExpired:
        return False, "scp timed out"
    except OSError as e:
        return False, f"cannot run scp: {e}"
    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or "").strip().splitlines()
        return False, f"scp failed (exit {proc.returncode}): {err[-1] if err else 'unknown error'}"
    return True, f"sent {local_file} -> {dest}"


def main():
    ap = argparse.ArgumentParser(description="Download Pi-hole filters from GitHub or from given addresses.")
    ap.add_argument("--addr", dest="addrs", metavar="ADDRESS", action="append", default=[],
                    help="URL of a file to download; can be used multiple times: --addr URL1 --addr URL2. "
                         "A GitHub directory page (.../tree/BRANCH/DIR) downloads all files from that "
                         "directory, a GitHub file page (.../blob/...) is converted to raw automatically.")
    ap.add_argument("--list", dest="listfile", metavar="LISTFILE", default=None,
                    help="text file with a list of URLs to download (one URL per line; "
                         "'#' starts a comment, file URLs and GitHub directory/file pages allowed)")
    ap.add_argument("--ext", dest="exts", metavar="EXT", action="append", default=[],
                    help="download only files with this extension, e.g. --ext txt (repeatable, comma-separated). "
                         "If omitted, ALL files are downloaded (may include binaries and large files).")
    ap.add_argument("--compact", action="store_true",
                    help="merge all lines from the downloaded files into one output file")
    ap.add_argument("--outfile", metavar="FILENAME", default=None,
                    help="output file for --compact mode (e.g. --outfile merged.txt)")
    ap.add_argument("--diff", action="store_true",
                    help="drop duplicate lines in the output file and print a report (requires --compact)")
    ap.add_argument("--outdir", metavar="DIR", default=DEFAULT_OUTDIR,
                    help=f"directory for single files (default: {DEFAULT_OUTDIR})")
    ap.add_argument("--keep-empty", action="store_true",
                    help="keep empty lines in the merged file (skipped by default)")
    ap.add_argument("--keep-comments", action="store_true",
                    help="keep all comment lines without dedup (by default comments are also deduplicated by --diff)")
    ap.add_argument("--send", dest="send", metavar="name@server:directory", default=None,
                    help="send the merged file (--compact output) via scp to directory on server as user name")
    ap.add_argument("--pwd", dest="password", metavar="PASSWORD", default=None,
                    help="password for --send (prefer --pwdfile, --pwd is visible in the process list)")
    ap.add_argument("--pwdfile", dest="pwdfile", metavar="FILENAME", default=None,
                    help="file containing the password for --send (first line is used)")
    ap.add_argument("--log", dest="logfile", metavar="FILENAME", default=None,
                    help="log everything the program does to FILENAME (appended, works with -q too)")
    ap.add_argument("-q", "--quiet", action="store_true",
                    help="quiet mode: no output (useful e.g. for cron)")
    ap.add_argument("--version", action="version",
                    version=f"%(prog)s v{__version__} by {__author__} ({__url__})")
    args = ap.parse_args()

    # With no options at all, do nothing except showing help.
    if len(sys.argv) == 1:
        ap.print_help()
        return

    def msg(*a, **k):
        if not args.quiet:
            print(*a, **k)
        if log_fh is not None:
            lk = {key: val for key, val in k.items() if key != "file"}
            lk["flush"] = True
            print(*a, file=log_fh, **lk)

    log_fh = None
    if args.logfile:
        try:
            if Path(args.logfile).parent != Path(".") and str(Path(args.logfile).parent) != "":
                Path(args.logfile).parent.mkdir(parents=True, exist_ok=True)
            log_fh = open(args.logfile, "a", encoding="utf-8")
            log_fh.write(f"=== run {datetime.now().isoformat(timespec='seconds')}: "
                         f"{' '.join(sys.argv)} ===\n")
            log_fh.flush()
        except OSError as e:
            print(f"ERROR: cannot open --log {args.logfile}: {e}", file=sys.stderr)
            sys.exit(1)

    wanted = parse_exts(args.exts)
    if not wanted:
        msg("[warning] no --ext specified, downloading ALL files - "
            "this may include binaries and other large files.", file=sys.stderr)

    # --diff only makes sense when merging, so it enables --compact automatically
    if args.diff and not args.compact:
        msg("[info] --diff given without --compact: enabling --compact automatically.", file=sys.stderr)
        args.compact = True

    # --send needs the merged file, so it enables --compact automatically as well
    send_target = None
    if args.send:
        send_target = parse_send_target(args.send)
        if not send_target:
            msg(f"ERROR: invalid --send value {args.send!r}, "
                f"expected name@server:directory.", file=sys.stderr)
            sys.exit(1)
        if not args.compact:
            msg("[info] --send given without --compact: enabling --compact automatically.",
                file=sys.stderr)
            args.compact = True

    if args.password and args.pwdfile:
        msg("ERROR: use either --pwd or --pwdfile, not both.", file=sys.stderr)
        sys.exit(1)

    password = args.password
    if args.pwdfile:
        try:
            with open(args.pwdfile, "r", encoding="utf-8", errors="replace") as f:
                password = f.readline().strip()
        except OSError as e:
            msg(f"ERROR: cannot read --pwdfile {args.pwdfile}: {e}", file=sys.stderr)
            sys.exit(1)
        if not password:
            msg(f"ERROR: --pwdfile {args.pwdfile} is empty.", file=sys.stderr)
            sys.exit(1)
    if (args.password or args.pwdfile) and not args.send:
        msg("[warning] --pwd/--pwdfile given without --send: password will be ignored.",
            file=sys.stderr)

    if args.compact and not args.outfile:
        args.outfile = "combined.txt"
        msg(f"[info] no --outfile given, using default: {args.outfile}", file=sys.stderr)

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    # --- source selection: --addr / --list or the default hardcoded GitHub ---
    if args.addrs or args.listfile:
        urls = list(args.addrs or [])
        if args.listfile:
            try:
                urls.extend(read_list_file(args.listfile))
            except OSError as e:
                msg(f"ERROR: cannot read --list {args.listfile}: {e}", file=sys.stderr)
                sys.exit(1)
        if not urls:
            msg("ERROR: --list/--addr contain no addresses.", file=sys.stderr)
            sys.exit(1)
        for u in urls:
            reason = suspicious_url_reason(u)
            if reason:
                msg(f"[warning] suspicious URL {u}: {reason}", file=sys.stderr)
        files, skipped = expand_custom_urls(urls, wanted, msg)
        if wanted:
            msg(f"Extension filter: {', '.join(sorted(wanted))} "
                f"({len(files)} matching, {len(skipped)} skipped).")
        else:
            msg(f"Downloading {len(files)} files from the given addresses ...")
    else:
        if wanted:
            msg(f"Fetching file list (*.{', *.'.join(sorted(wanted))}) from {REPO}/{SUBDIR} ...")
        else:
            msg(f"Fetching file list (ALL files) from {REPO}/{SUBDIR} ...")
        try:
            files = github_api_list_files(wanted)
        except Exception as e:
            msg(f"ERROR: cannot fetch file list from the GitHub API: {e}", file=sys.stderr)
            sys.exit(1)

    if not files:
        msg("ERROR: no files to download (nothing matches the --ext filter?).", file=sys.stderr)
        sys.exit(1)

    msg(f"To download: {len(files)} files.")
    local_files = []
    empty_files = []
    for entry in files:
        dest = outdir / entry["name"]
        msg(f"  downloading {entry['name']} ...", end=" ", flush=True)
        try:
            download_file(entry["url"], dest)
            size = dest.stat().st_size
            msg(f"OK ({size} B)")
            if size == 0:
                msg(f"[warning] {entry['name']} is empty (0 bytes) - "
                    f"the server returned an empty file.", file=sys.stderr)
                empty_files.append(dest)
            local_files.append(dest)
        except Exception as e:
            msg(f"ERROR: {e}")

    if not local_files:
        msg("ERROR: nothing downloaded.", file=sys.stderr)
        sys.exit(1)

    # Detect HTML pages saved by mistake (e.g. GitHub tree/blob URLs).
    html_files = [p for p in local_files if is_html_file(p)]
    for p in html_files:
        msg(f"[warning] {p.name} looks like an HTML page, not a filter list - "
            f"it will be skipped in --compact mode.", file=sys.stderr)
    merge_files = [p for p in local_files if p not in html_files]

    if not args.compact:
        msg(f"\nDone. Saved {len(local_files)} files in directory: {outdir}/")
        return

    # --- --compact mode: merging (HTML pages and empty files are skipped) ---
    if not merge_files:
        msg("ERROR: nothing to merge (all downloaded files are HTML pages?).", file=sys.stderr)
        sys.exit(1)
    outfile = Path(args.outfile)
    total_lines = 0
    seen = set()
    duplicates = 0
    unique_lines = []  # keeps order of first occurrence

    for path in merge_files:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for raw in f:
                line = raw.rstrip("\n").strip()
                if line == "" and not args.keep_empty:
                    continue
                total_lines += 1
                if args.diff:
                    # with --keep-comments, comment lines (#...) bypass dedup
                    if args.keep_comments and line.startswith("#"):
                        unique_lines.append(line)
                        continue
                    if line in seen:
                        duplicates += 1
                    else:
                        seen.add(line)
                        unique_lines.append(line)
                else:
                    unique_lines.append(line)

    if outfile.parent != Path(".") and str(outfile.parent) != "":
        outfile.parent.mkdir(parents=True, exist_ok=True)
    with open(outfile, "w", encoding="utf-8") as out:
        for line in unique_lines:
            out.write(line + "\n")

    msg(f"\nMerged {len(merge_files)} files -> {outfile}", )
    if html_files:
        msg(f"  skipped HTML files: {len(html_files)} ({', '.join(p.name for p in html_files)})")
    if empty_files:
        msg(f"  empty files (0 lines): {len(empty_files)} ({', '.join(p.name for p in empty_files)})")
    msg(f"  total lines: {total_lines}")
    if args.diff:
        msg(f"  unique lines written: {len(unique_lines)}")
        msg(f"  repeating lines (removed duplicates): {duplicates}")
        # report: one line = one www address
        if total_lines:
            pct = duplicates / total_lines * 100
            msg(f"  duplicates were: {pct:.2f}% of all lines")
    else:
        msg(f"  lines written: {len(unique_lines)}")
        msg("  (hint: add --diff to drop repeating addresses and see a report)")

    if send_target:
        user, server, directory = send_target
        msg(f"\nSending {outfile} via scp to {user}@{server}:{directory} ...")
        ok, info = send_via_scp(outfile, user, server, directory, password)
        msg(("OK: " if ok else "ERROR: ") + info, file=sys.stderr if not ok else None)
        if not ok:
            sys.exit(1)


if __name__ == "__main__":
    main()
