# ReconScope

ReconScope is a local, AI-free reconnaissance and web-security assessment CLI for bug hunting on approved, authorized sites. It discovers assets, checks which hosts are live, performs low-impact web checks, and stores results separately for each program and target.

Only use it on sites you are explicitly authorized to test. Always follow the relevant bug-bounty program’s scope, exclusions, rate limits, and disclosure rules.

## Install

Linux/Kali/Ubuntu:

```bash
chmod +x reconscope install.sh
./install.sh
```

If the installer prints a PATH command, run it in the current terminal. Then verify:

```bash
reconscope doctor
```

Or run directly from the project folder:

```bash
./reconscope doctor
```

Windows CMD:

```cmd
reconscope.bat doctor
```

Python 3.10+ is required.

## Basic workflow

Create a new program policy:

```bash
reconscope run --new --dry-run
```

Enter the program name, then paste in-scope hostnames one per line. Press Enter on an empty line when finished. Do the same for out-of-scope hostnames. If there are none, press Enter immediately.

Review the scope:

```bash
reconscope scope check --policy scopes/<program>/scope.json
```

Preview without network requests:

```bash
reconscope run scopes/<program>/scope.json --dry-run
```

Run the approved workflow:

```bash
reconscope run scopes/<program>/scope.json
```

The workflow runs discovery, scope filtering, DNS resolution, low-rate HTTP/HTTPS checks, header/cookie/TLS/CORS checks, JavaScript reference discovery, and reporting.

To edit the saved scope later:

```bash
reconscope run --edit
```

## Useful commands

```bash
reconscope doctor --tools
reconscope discover --policy scopes/<program>/scope.json
reconscope report --program <program> --target <target>
reconscope diff --program <program> --target <target>
```

## Results

Results are stored under:

```text
data/<program>/<target>/
├── discovery/<timestamp>/
├── scans/<timestamp>/
└── latest_report.json
```

Live hosts, suspicious hosts, DNS data, HTTP results, findings, and scan summaries are kept inside each target’s folder.

## Tests

```bash
python3 -m unittest discover -s tests -v
```
