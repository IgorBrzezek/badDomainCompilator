# Pi-hole / AdGuard blocklist builder

Version: v0.0.1 — Author: Igor Brzezek — GitHub:
https://github.com/IgorBrzezek/badDomainCompilator

`download_filters.py` downloads ready-made malicious-domain lists from a
list of addresses (`--list`) and merges them into a single complete
`--compact` file that you can load into Pi-hole, AdGuard Home or any
other DNS-level blocker.

Lines are merged as-is (only stripped of surrounding whitespace) — source
lists use hosts-style lines (`0.0.0.0 domain`) and/or bare domains, so check
your blocker's documentation for the exact format it accepts.

## Requirements

- Python 3, standard library only (no extra packages to install).
- For `--send` only: the `scp` command (openssh-client) on this machine,
  plus `sshpass` if you authenticate with a password instead of an SSH key.

## Included example list

The file `lists.txt` contains example source addresses of malicious-domain
lists. You can extend it freely: add one address per line, use `#` for
comments (everything from `#` to the end of the line is ignored, empty
lines are skipped too). Plain file URLs, raw URLs and GitHub pages are
all accepted — see `--addr` below.

Source idea and lists on: https://github.com/MajkiIT/polish-ads-filter

## How it works

1. **Resolve sources.** With `--addr`/`--list` the script uses exactly the
   addresses you gave. A GitHub directory page
   (`https://github.com/OWNER/REPO/tree/BRANCH/DIR`) is expanded via the
   GitHub API into all files of that directory (honoring `--ext`); a GitHub
   file page (`.../blob/...`) is automatically converted to its
   `raw.githubusercontent.com` URL. Without `--addr`/`--list` the script
   falls back to its built-in source: `MajkiIT/polish-ads-filter`,
   directory `polish-pihole-filters`, branch `master`.
2. **Download** every file into `--outdir` (default: `bad_domains/`,
   created automatically). Name collisions get a `_2`, `_3`… suffix.
   Empty (0-byte) files produce a warning. Files that turn out to be HTML
   pages (e.g. a pasted GitHub web URL) produce a warning and are skipped
   later during merging.
3. **Optionally merge** (`--compact`) all downloaded files into one output
   file, **optionally deduplicate** (`--diff`) and report the numbers.
4. **Optionally send** (`--send`) the merged file to your own server, from
   where Pi-hole / AdGuard can fetch it automatically (see below).

## Options

| Option | What it does |
|---|---|
| `--addr ADDRESS` | URL of a file to download. Repeatable (`--addr URL1 --addr URL2`). GitHub directory (`tree`) pages download the whole directory, GitHub file (`blob`) pages are converted to raw URLs. If `--addr`/`--list` is given, the built-in GitHub source is NOT used. |
| `--list LISTFILE` | Text file with source URLs, one per line (`#` starts a comment). May mix file URLs and GitHub directory/file pages. |
| `--ext EXT` | Download only files with this extension, e.g. `--ext txt` (leading dot optional, case-insensitive, repeatable and comma-separated: `--ext txt,md`). If omitted, ALL files are downloaded — the script warns that this may include binaries and other large files. |
| `--outdir DIR` | Directory for the downloaded single files (default: `bad_domains/`). |
| `--compact` | Merge all lines from the downloaded files into one output file. |
| `--outfile FILENAME` | Output file for `--compact` (default: `combined.txt`). |
| `--diff` | Drop repeating lines in the merged file (one line = one address, first occurrence wins) and print a report: total lines, unique lines written, removed duplicates and their percentage. Enables `--compact` automatically. |
| `--keep-empty` | Keep empty lines in the merged file (skipped by default). |
| `--keep-comments` | Keep every `#...` comment line even if repeated (by default comments are deduplicated by `--diff` like any other line). |
| `--send name@server:directory` | Send the merged file via `scp` to `directory` on `server` as user `name`. Enables `--compact` automatically. |
| `--pwd PASSWORD` | Password for `--send`. Visible in the process list AND stored in `--log` — prefer `--pwdfile`. |
| `--pwdfile FILENAME` | File containing the password for `--send` (first line is used). Use either `--pwd` or `--pwdfile`. With neither, key-based SSH authentication is used. |
| `--log FILENAME` | Append everything the program does to `FILENAME` (each run starts with a timestamped header holding the full command line — so never combine `--pwd` with `--log`). Works together with `-q`. |
| `-q`, `--quiet` | No console output at all, only exit codes (0 = success, 1 = error). |

With no options at all the script prints help and does nothing.

## Examples

```bash
# show help (also shown when run without any options)
python3 download_filters.py --help

# download only *.txt sources from the example list
python3 download_filters.py --list lists.txt --ext txt

# download to a custom directory
python3 download_filters.py --list lists.txt --ext txt --outdir my_lists

# single addresses instead of a list file
python3 download_filters.py --addr https://hole.cert.pl/domains/v2/domains.txt --ext txt

# build one merged file with deduplication report
python3 download_filters.py --list lists.txt --ext txt --compact --outfile baddnslist.txt --diff

# silent nightly run with a log file
python3 download_filters.py --list lists.txt --ext txt --compact --outfile baddnslist.txt --diff -q --log run.log

# upload the finished list to your server (key authentication)
python3 download_filters.py --list lists.txt --ext txt --compact --outfile baddnslist.txt --diff \
  --send admin@myserver:/var/www/blocklists/

# same, but with a password read from a file
python3 download_filters.py --list lists.txt --ext txt --compact --outfile baddnslist.txt --diff \
  --send admin@myserver:/var/www/blocklists/ --pwdfile ~/.blocklist_pwd
```

Example `--diff` report:

```
Merged 3 files -> baddnslist.txt
  total lines: 311300
  unique lines written: 275506
  repeating lines (removed duplicates): 35794
  duplicates were: 11.50% of all lines
```

## Publishing the list for Pi-hole / AdGuard (`--send`)

`--send` uploads the finished merged file to **your own server** via `scp`.
Serve the target directory over HTTP(S) from that server, then add the
file's URL as a blocklist in Pi-hole / AdGuard Home — they will
re-download it automatically on their update schedule, so every rebuild +
`--send` refreshes protection on all your blockers without touching them.

Note: `--send` only copies the file. Exposing it over HTTP(S) (a web
server serving that directory) is configured on your side, outside this
script.

## Exit codes and warnings worth knowing

- Exit `0` = success (including "help shown"), exit `1` = error
  (unreadable `--list`/`--pwdfile`, invalid `--send` format, `scp`
  failure, nothing to download/merge, …).
- `--diff`/`--send` without `--compact` enable `--compact` automatically
  (with an `[info]` note and a default `--outfile` of `combined.txt`).
- `--pwd`/`--pwdfile` without `--send` only produce a warning and are
  otherwise ignored.
- A `--pwd` password is visible in the process list while `scp`/`sshpass`
  runs, and it is also stored in `--log` (the log header records the full
  command line). Prefer `--pwdfile` with restrictive file permissions
  (e.g. `chmod 600`) and keep log files private.
