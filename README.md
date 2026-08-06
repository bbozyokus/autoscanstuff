# autoscanv3

> Not a groundbreaking tool, just a script I built around my pentesting methodology.

Automated Active Directory pentest reconnaissance script — Metasploit workspace setup, mass port
scanning, per-port web URL lists, active host list, SMB signing (relay candidate) detection, Domain
Controller verification, LDAP dumping, user/high-privilege lists, BloodHound collection,
Kerberoasting/AS-REP roasting, AD CS enumeration with Certipy, Kerberos configuration and Nuclei web
scanning — with **step-by-step resume** and a Ctrl+C that never kills the run.

## ⚡ Quick Start

```bash
sudo ./autoscanv3.sh -i ips.txt -c start -u user -p pass -d corp.local -ki
```

## 📋 Requirements

| Tool | Purpose |
|---|---|
| `masscan` | Port scanning |
| `ldap-utils` (`ldapsearch`, `ldapwhoami`) | DC verification, credential validation, adminCount query |
| `ldapdomaindump` | LDAP domain enumeration |
| `bloodhound-ce-python` or `nxc` | BloodHound data collection |
| `nxc` (netexec) | SMB signing check, Kerberoasting, AS-REP roasting, BloodHound fallback |
| `nmap` | SMB signing check fallback |
| `impacket-GetUserSPNs` / `impacket-GetNPUsers` | Kerberoasting / AS-REP roasting fallback |
| `python3` or `jq` | Parsing ldapdomaindump JSON into user lists |
| `certipy-ad` (optional) | AD CS enumeration |
| `msfconsole` / `msfdb` (optional) | Metasploit database check and workspace |
| `nuclei` (optional) | Web vulnerability scanning |
| `sudo` | Required for masscan and Kerberos config |

Every optional tool is probed with `command -v` first — if it is missing the step says so and the run
continues.

## 🚀 Usage

```
Usage: ./autoscanv3.sh -i <ip_file> -c <command> [-r <rate>]

Parameters:
  -i, --input                    IP list file (required unless --mass-result is used)
  -c, --command                  Command: check (access test) or start (full scan)
  -r, --rate                     Scan rate (default: 1000)
  -u, --username                 LDAP username (optional)
  -p, --password                 LDAP password (optional)
  -d, --domain                   LDAP domain name (optional)
  -ki, --kerberos-implementation Automate Kerberos config (hosts/resolv/krb5) after scan
  --skip-host-check              Skip host discovery, go straight to the full port scan
  -m, --mass-result <file>       Reuse an existing masscan output instead of scanning
  --project <name>               Metasploit workspace/project name (asked interactively if omitted)
  --no-msf                       Skip the Metasploit database check and workspace creation
  --resume                       Continue the previous run without asking
  --fresh                        Ignore saved progress and start over
  -h, --help                     Show this help message
```

## 📖 Examples

```bash
# Access test only (host discovery)
sudo ./autoscanv3.sh -i ips.txt -c check

# Full scan with credentials and Kerberos auto-config
sudo ./autoscanv3.sh -i ips.txt -c start -u admin -p 'Password123' -d corp.local -ki

# Full scan with custom rate
sudo ./autoscanv3.sh -i ips.txt -c start -r 5000

# Skip the discovery phase (targets are known to be up / discovery ports filtered)
sudo ./autoscanv3.sh -i ips.txt -c start --skip-host-check

# No scanning at all — process an existing masscan output and run everything after it
sudo ./autoscanv3.sh --mass-result old-mass-result.txt -u admin -p 'Password123' -d corp.local

# Continue an interrupted run where it left off
sudo ./autoscanv3.sh -i ips.txt -c start --resume

# Name the Metasploit workspace up front instead of being asked
sudo ./autoscanv3.sh -i ips.txt -c start --project acme-internal -u admin -p 'Password123' -d corp.local

# Kerberos config from input file (p389.txt not needed)
sudo ./autoscanv3.sh -i ips.txt -c check -ki -d corp.local
```

## 🔄 Execution Flow

```
┌──────────────────────────────────────────────────────────────┐
│                     COMMAND: start                           │
├──────────────────────────────────────────────────────────────┤
│  0. Metasploit DB check + workspace (asks for project name)  │
│  1. Host Discovery (masscan on common ports)                 │
│     ├── skipped by --skip-host-check                         │
│     └── replaced entirely by --mass-result <file>            │
│  2. Full Port Scan (100+ TCP ports) → mass-result.txt        │
│  3. Port files + web URL files (p80.txt, p8080-http.txt, …)  │
│     └── all-webs.txt (combined web URLs)                     │
│  4. up-ips.txt (every host that answered on any port)        │
│  5. DC Verification (LDAP root DSE check on p389.txt)        │
│  6. SMB Signing → smb-signing-disabled-devices.txt           │
│  7. LDAP Credential Validation (gate for every LDAP step)    │
│  8. Web Ports Summary                                        │
│  9. LDAP Domain Dump → ldapdomdump/                          │
│ 10. User lists → sam-names.txt, high-priv-accounts.txt       │
│ 11. BloodHound Collection                                    │
│ 12. Kerberoasting → kerberos/kerbout.txt                     │
│     ASREP-roasting (with creds) → kerberos/asrepout.txt      │
│ 13. AS-REP roasting from sam-names.txt, no password          │
│     └── kerberos/as-rep-roast.txt                            │
│ 14. Certipy AD CS enumeration → certipy/                     │
│ 15. Kerberos Implementation (-ki)                            │
│     ├── /etc/hosts (dc.domain entries)                       │
│     ├── /etc/resolv.conf (nameservers)                       │
│     └── /etc/krb5.conf (full Kerberos config)                │
│ 16. Nuclei Scan Prompt (all-webs.txt)                        │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│                     COMMAND: check                           │
├──────────────────────────────────────────────────────────────┤
│  0. Metasploit DB check + workspace                          │
│  1. Host Discovery + Access Status Report                    │
│  2. up-ips.txt                                               │
│  3. SMB Signing check                                        │
│  4. Kerberos Implementation (-ki)                            │
│  5. Roasting / AS-REP / Certipy (skip themselves unless      │
│     credentials and a p389.txt from an earlier run exist)    │
│  6. Nuclei Scan Prompt                                       │
└──────────────────────────────────────────────────────────────┘
```

Every step is tracked in `.autoscan-state`, so an interrupted run picks up exactly where it stopped —
see [Resume & Ctrl+C](#-resume--ctrlc). Ordering is dependency-driven: each step's input file is
produced by an earlier one, and `-ki` runs late on purpose so rewriting `/etc/resolv.conf` cannot
break DNS for the tools before it.

## ⏯️ Resume & Ctrl+C

**Ctrl+C never kills the tool.** Every interrupt opens a menu instead:

```
⚠️  Interrupt (Ctrl+C) received — the tool is NOT closing.
Current step: Detailed port scan
What do you want to do?
  r) Retry this step (default) — masscan continues from its paused state
  s) Skip this step and continue with the next one
  q) Save progress and quit (continue later with --resume)
Choice [r/s/q]:
```

Mashing Ctrl+C repeatedly does not stack prompts and does not exit — signals arriving while the menu
is open (or within 3 s of a decision) are absorbed.

- **`r`** restarts the current step. For masscan this is a real resume: the interrupted scan writes
  `paused.conf`, which the script stashes as `paused-discovery.conf` / `paused-detailed.conf` and
  feeds back through `masscan --resume`, **appending** to the existing `mass-result.txt`.
- **`s`** marks the step skipped and moves on; it stays skipped on later resumes.
- **`q`** saves and exits with code 130, printing the exact command to continue with.

On the next start the script finds the saved state and asks whether to continue; `--resume` answers
yes automatically, `--fresh` throws the saved progress (and any stale pause file) away. Completed
steps are skipped with a `⏩` line, failed steps run again. The state file is deleted once a run
finishes cleanly.

```
=== PREVIOUS RUN FOUND ===
  Started: 2026-08-06 04:37:33
  Command: start    IP file: ips.txt
    ✔ msfsetup
    ✔ hostdiscovery
Continue from where you left off? [y/n]:
```

## 🔧 Features

### Metasploit Workspace
The very first step asks for a **project name** (or takes it from `--project`), checks `db_status`
and, if the database is down, tries `msfdb start` (or `systemctl start postgresql`). Once connected,
a workspace named after the project is created and selected:

```
msfconsole -q -x "workspace -a <project>; workspace <project>; workspace; exit"
```

The name is sanitised to `[A-Za-z0-9._-]` (`Acme Internal 2026` → `Acme_Internal_2026`), raw output
goes to `msf-workspace.log`, and `--no-msf` skips the whole step. If `msfconsole` is missing or the
database cannot be started, the script says so and continues with the scan.

### Masscan Port Scanning
Scans **100+ TCP ports** across HTTP/HTTPS, SMB, LDAP/LDAPS/GC, Kerberos, RDP, WinRM, databases
(MSSQL, MySQL, Oracle, PostgreSQL), Redis, MongoDB, Elasticsearch, mail protocols, and more.

### Skipping the scan (`--skip-host-check` / `--mass-result`)
`--skip-host-check` drops the discovery masscan and goes straight to the full port scan — useful when
the targets are known to be up or the discovery ports are filtered.

`--mass-result <file>` skips scanning altogether: the given masscan output is taken as if the scan had
just run (copied to `mass-result.txt`) and everything after it — port files, web URLs, up-ips, DC
verification, SMB signing, LDAP/BloodHound/roasting, Certipy, nuclei — runs normally. `-i` is not
required in this mode and `-c start` is implied. Every port present in the imported file is
processed, including ports outside the built-in list.

### Access Status Report
The access rate is measured against the **real number of addresses** in the target list, not the
number of lines: CIDR blocks (`10.0.0.0/24` → 256) and ranges (`10.0.0.1-10.0.0.50` → 50,
`10.0.0.1-50` → 50) are expanded; comments and blank lines are ignored. Anything else (single IP,
hostname, IPv6) counts as one target.

```
Target entries:      3 (IP / CIDR / range lines)
Addresses in scope:  267
Active Hosts:        3
Access Rate:         %1.12
```

### Web URL Files (port suffix)
Every browser-reachable port gets its own URL file with the **port appended**:

| File | Content |
|---|---|
| `p80-http.txt` | `http://10.0.0.5` |
| `p443-https.txt` | `https://10.0.0.7` |
| `p8080-http.txt` | `http://10.0.0.5:8080` |
| `p8443-https.txt` | `https://10.0.0.7:8443` |
| `p10000-https.txt` | `https://10.0.0.2:10000` |

Only the standard ports (80/http, 443/https) are written without a suffix. Covered ports:

- **HTTP:** 80, 81, 82, 631, 3000, 4444, 5000, 5555, 8000, 8008, 8020, 8040, 8042, 8080, 8081, 8082, 8083, 8090, 8888, 9000, 9001, 9080, 9200, 9999
- **HTTPS:** 443, 4848, 6443, 7443, 8181, 8443, 8444, 9443, 10000, 10443

`all-webs.txt` combines all of them with the same rule and feeds the nuclei step.

### Active Host List (`up-ips.txt`)
Every host that answered on any port — from the discovery scan, the full port scan, or an imported
`--mass-result` — is collected, deduplicated and version-sorted into `up-ips.txt`.

### SMB Signing Check
Hosts where SMB signing is **disabled / not required** (i.e. NTLM relay candidates) are written to
`smb-signing-disabled-devices.txt`:

1. **Primary — nxc:** `nxc smb p445.txt --gen-relay-list smb-signing-disabled-devices.txt -u '' -p ''`
   (raw output in `nxc-smb-signing.log`)
2. **Fallback — nmap:** `nmap -Pn -n -p445 --script smb2-security-mode -iL p445.txt`, parsing hosts
   reporting *"Message signing enabled but not required"* / *"Message signing disabled"*
   (raw output in `nmap-smb-signing.txt`)

Targets come from `p445.txt`, falling back to `up-ips.txt`. The check deliberately runs with a **null
session**: signing status comes from the SMB negotiate banner, so no authentication is needed — this
avoids producing failed logins (and lockout risk) with credentials that have not been validated yet.

### Domain Controller Verification
Hosts with port 389 are verified as Active Directory DCs via anonymous LDAP root DSE queries
(`domainControllerFunctionality`, AD capability OID + `NTDS Settings`). Verified DCs replace
`p389.txt`; all candidates are kept in `p389-ldap-candidates.txt`. With `-d domain` the
`_ldap._tcp.dc._msdcs` SRV record is printed for reference.

### LDAP Credential Gate
If `-u/-p/-d` are provided, credentials are validated with `ldapwhoami` against the `p389.txt` hosts
(LDAPS too when the host is in `p636.txt`) before any LDAP operation proceeds. On failure the user is
prompted to re-enter them or skip the downstream LDAP steps. This gate is intentionally **not**
resume-tracked: it runs again on every resume, because every LDAP step depends on its result.

### LDAP Domain Dump
Runs `ldapdomaindump` against verified DCs. Falls back to LDAPS (port 636) if LDAP fails. Output
saved to `ldapdomdump/`.

### User Lists (`sam-names.txt` / `high-priv-accounts.txt`)
The JSON files ldapdomaindump wrote into `ldapdomdump/` are parsed (python3, `jq` fallback, plain text
scan as last resort):

- **`sam-names.txt`** — every `sAMAccountName` from `domain_users.json`, machine accounts (`…$`) excluded
- **`high-priv-accounts.txt`** — high privileged accounts, collected from several angles so that one
  missing attribute does not hide an account:
  - `adminCount=1`
  - `primaryGroupID` ∈ {512, 516, 518, 519, 520} (catches Domain Admins set as *primary* group)
  - `memberOf` a high privileged group (Domain Admins, Enterprise Admins, Schema Admins,
    Administrators, Account/Backup/Server/Print Operators, DnsAdmins, Key Admins, Cert Publishers,
    Group Policy Creator Owners, DCs/RODCs)
  - the `member` attribute of those groups in `domain_groups.json` (catches users whose `memberOf`
    is not populated)
  - plus a live `ldapsearch (&(objectCategory=person)(objectClass=user)(adminCount=1))`, falling back
    to `nxc ldap --admin-count`, when credentials and a DC are available

### AS-REP Roasting from the user list (no password)
`sam-names.txt` is roasted **without any password** — only a user list and a DC are needed:

```bash
nxc ldap <dcip> -u sam-names.txt -p '' -d <domain> --asreproast kerberos/as-rep-roast.txt
```

Fallback: `impacket-GetNPUsers <domain>/ -dc-ip <dcip> -no-pass -usersfile sam-names.txt -format hashcat`.
Hashes land in **`kerberos/as-rep-roast.txt`** with the raw tool output next to it. If you already
have a `sam-names.txt` from somewhere else, the step uses it as is.

### Certipy (AD CS)
Runs against the first DC with the supplied credentials, `ldaps` as fallback scheme:

```bash
certipy-ad find -u 'user@corp.local' -p 'pass' -dc-ip 10.10.10.10 -vulnerable -ldap-scheme ldap
```

It is executed inside the `certipy/` directory so every generated report (`*_Certipy.txt`, `*.json`,
`*.zip`) stays there, together with `certipy-find-<scheme>.log`. Any `ESCx` classes found are printed
as a summary.

### BloodHound CE
Runs `bloodhound-ce-python` with fallback chain:
1. `bloodhound-ce-python` (LDAP) → 2. `bloodhound-ce-python` (LDAPS) → 3. `nxc ldap --bloodhound` (LDAP) → 4. `nxc ldap --port 636 --bloodhound` (LDAPS)

### Kerberoasting & ASREP-roasting
Runs automatically when credentials are provided:

**Kerberoasting:**
- `nxc ldap <dcip> -u 'user' -p 'pass' --kerberoasting kerberos/kerbout.txt`
- Fallback: `impacket-GetUserSPNs -request -dc-ip <dcip> domain/user:pass -outputfile kerberos/kerberoasting.hashes`

**ASREP-roasting (authenticated):**
- `nxc ldap <dcip> -u 'user' -p 'pass' --asreproast kerberos/asrepout.txt`

Output saved to the `kerberos/` directory, alongside the passwordless user-list roast above.

### Kerberos Implementation (`-ki`)
Automates system-level Kerberos configuration:

| File | Content |
|---|---|
| `/etc/hosts` | `127.0.0.1 localhost`, `127.0.1.1 kali`, `$ip dc.$DOMAIN` per DC |
| `/etc/resolv.conf` | `domain`, `search`, `nameserver $ip` per DC |
| `/etc/krb5.conf` | `[libdefaults]`, `[realms]`, `[domain_realm]` with proper realm (UPPERCASE)/domain (lowercase) |

Creates `.bak` backups before modifying. Uses verified DCs from `p389.txt` or falls back to the input
IP file. Requires root.

### Nuclei Scan
After all operations, prompts to run Nuclei against `all-webs.txt`. Results saved to
`nuclei-results.txt`.

## 📂 Output Files

**Scanning**

| File | Description |
|---|---|
| `host-discovery.txt` | Raw discovery masscan output |
| `mass-result.txt` | Raw full-scan masscan output |
| `up-ips.txt` | All active (up) hosts, deduplicated |
| `p<port>.txt` | IPs per port (e.g. p80.txt, p443.txt) |
| `p<port>-http.txt` / `p<port>-https.txt` | Web URLs per port, `:port` appended (except 80/443) |
| `all-webs.txt` | Combined HTTP/HTTPS URLs |
| `smb-signing-disabled-devices.txt` | Hosts with SMB signing disabled/not required |
| `nxc-smb-signing.log` / `nmap-smb-signing.txt` | Raw SMB signing check output |
| `nuclei-results.txt` | Nuclei vulnerability findings |

**Active Directory**

| File | Description |
|---|---|
| `p389-ldap-candidates.txt` | All hosts with 389/tcp open |
| `p389.txt` | Verified AD DCs |
| `ldapdomdump/` | LDAP domain dump output (JSON/HTML/grep) |
| `sam-names.txt` | All domain account names (machine accounts excluded) |
| `high-priv-accounts.txt` | Domain/Enterprise Admins and other high privileged accounts |
| `nxc-admincount.log` | Raw `nxc --admin-count` output (fallback source) |
| `kerberos/kerbout.txt` | Kerberoasting hashes |
| `kerberos/asrepout.txt` | AS-REP hashes (authenticated roast) |
| `kerberos/as-rep-roast.txt` | AS-REP hashes from the passwordless user-list roast |
| `certipy/` | Certipy AD CS reports and logs |
| `*_bloodhound.zip` | BloodHound collection archive |

**Run state / system**

| File | Description |
|---|---|
| `.autoscan-state` | Resume state (deleted when a run finishes cleanly) |
| `paused-discovery.conf` / `paused-detailed.conf` | Interrupted masscan state for `--resume` |
| `msf-workspace.log` | Metasploit workspace creation output |
| `/etc/hosts.bak`, `/etc/resolv.conf.bak`, `/etc/krb5.conf.bak` | Backups written by `-ki` |

## ⚠️ Notes

- Requires `sudo` for `masscan` and Kerberos configuration
- Kerberos config (`-ki`) overwrites `/etc/hosts`, `/etc/resolv.conf`, `/etc/krb5.conf` (backups created)
- LDAP credentials are never written to disk — not even into `.autoscan-state`, so a resumed run asks
  for them again if validation fails
- The SMB signing check never authenticates (null session), so it cannot cause account lockouts
- All output files are created in the current working directory — resume a run from that same directory
- Use only against systems you are authorised to test

## 📄 License

MIT
