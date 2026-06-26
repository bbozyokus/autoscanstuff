# autoscanv3

> Not a groundbreaking tool, just a script I built around my pentesting methodology.

Automated Active Directory pentest reconnaissance script — mass port scanning, Domain Controller verification, LDAP dumping, BloodHound collection, Kerberoasting/ASREP-roasting, Kerberos configuration, and Nuclei web scanning.

## ⚡ Quick Start

```bash
sudo ./autoscanv3.sh -i ips.txt -c start -u user -p pass -d corp.local -ki
```

## 📋 Requirements

| Tool | Purpose |
|---|---|
| `masscan` | Port scanning |
| `ldap-utils` (`ldapsearch`, `ldapwhoami`) | DC verification, credential validation |
| `ldapdomaindump` | LDAP domain enumeration |
| `bloodhound-ce-python` or `nxc` | BloodHound data collection |
| `nxc` (netexec) | Kerberoasting, ASREP-roasting, BloodHound fallback |
| `impacket-GetUserSPNs` | Kerberoasting fallback |
| `nuclei` (optional) | Web vulnerability scanning |
| `sudo` | Required for masscan and Kerberos config |

## 🚀 Usage

```
Usage: ./autoscanv3.sh -i <ip_file> -c <command> [-r <rate>]

Parameters:
  -i, --input                    IP list file (required)
  -c, --command                  Command: check (access test) or start (full scan)
  -r, --rate                     Scan rate (default: 1000)
  -u, --username                 LDAP username (optional)
  -p, --password                 LDAP password (optional)
  -d, --domain                   LDAP domain name (optional)
  -ki, --kerberos-implementation Automate Kerberos config (hosts/resolv/krb5) after scan
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

# Kerberos config from input file (p389.txt not needed)
sudo ./autoscanv3.sh -i ips.txt -c check -ki -d corp.local
```

## 🔄 Execution Flow

```
┌──────────────────────────────────────────────────────────────┐
│                     COMMAND: start                           │
├──────────────────────────────────────────────────────────────┤
│  1. Host Discovery (masscan on common ports)                 │
│  2. Full Port Scan (100+ TCP ports)                          │
│  3. Port-based file creation (p80.txt, p443.txt, etc.)      │
│  4. Web URL files (p80-http.txt, p443-https.txt)            │
│  5. all-webs.txt (combined web URLs)                         │
│  6. DC Verification (LDAP root DSE check on p389.txt)       │
│  7. LDAP Credential Validation                              │
│  8. Web Ports Summary                                       │
│  9. LDAP Domain Dump → ldapdomdump/                         │
│ 10. BloodHound Collection                                   │
│ 11. Kerberoasting → kerberos/kerbout.txt                     │
│ 12. ASREP-roasting → kerberos/asrepout.txt                   │
│ 13. Kerberos Implementation (-ki)                           │
│     ├── /etc/hosts (dc.domain entries)                      │
│     ├── /etc/resolv.conf (nameservers)                      │
│     └── /etc/krb5.conf (full Kerberos config)               │
│ 14. Nuclei Scan Prompt (all-webs.txt)                        │
└──────────────────────────────────────────────────────────────┘
```

## 🔧 Features

### Masscan Port Scanning
Scans **100+ TCP ports** across HTTP/HTTPS, SMB, LDAP/LDAPS/GC, Kerberos, RDP, WinRM, databases (MSSQL, MySQL, Oracle, PostgreSQL), Redis, MongoDB, Elasticsearch, mail protocols, and more.

### Domain Controller Verification
After scanning, hosts with port 389 are verified as Active Directory DCs via anonymous LDAP root DSE queries. Verified DCs are written to `p389.txt`; all candidates kept in `p389-ldap-candidates.txt`.

### LDAP Credential Gate
If `-u/-p/-d` are provided, credentials are validated against p389.txt hosts before any LDAP operations proceed. On failure, the user is prompted to re-enter or skip downstream LDAP steps.

### LDAP Domain Dump
Runs `ldapdomaindump` against verified DCs. Falls back to LDAPS (port 636) if LDAP fails. Output saved to `ldapdomdump/`.

### BloodHound CE
Runs `bloodhound-ce-python` with fallback chain:
1. `bloodhound-ce-python` (LDAP) → 2. `bloodhound-ce-python` (LDAPS) → 3. `nxc ldap --bloodhound` (LDAP) → 4. `nxc ldap --port 636 --bloodhound` (LDAPS)

### Kerberoasting & ASREP-roasting
Runs automatically when credentials are provided:

**Kerberoasting:**
- `nxc ldap <dcip> -u 'user' -p 'pass' --kerberoasting kerberos/kerbout.txt`
- Fallback: `impacket-GetUserSPNs -request -dc-ip <dcip> domain/user:pass -outputfile kerberos/kerberoasting.hashes`

**ASREP-roasting:**
- `nxc ldap <dcip> -u 'user' -p 'pass' --asreproast kerberos/asrepout.txt`

Output saved to `kerberos/` directory.

### Kerberos Implementation (`-ki`)
Automates system-level Kerberos configuration:

| File | Content |
|---|---|
| `/etc/hosts` | `127.0.0.1 localhost`, `127.0.1.1 kali`, `$ip dc.$DOMAIN` per DC |
| `/etc/resolv.conf` | `domain`, `search`, `nameserver $ip` per DC |
| `/etc/krb5.conf` | `[libdefaults]`, `[realms]`, `[domain_realm]` with proper realm (UPPERCASE)/domain (lowercase) |

Creates `.bak` backups before modifying. Uses verified DCs from `p389.txt` or falls back to the input IP file.

### Nuclei Scan
After all operations, prompts to run Nuclei against `all-webs.txt`. Results saved to `nuclei-results.txt`.

## 📂 Output Files

| File | Description |
|---|---|
| `mass-result.txt` | Raw masscan output |
| `p<port>.txt` | IPs per port (e.g., p80.txt, p443.txt) |
| `p<port>-http.txt` / `p<port>-https.txt` | Web URLs per port |
| `all-webs.txt` | Combined HTTP/HTTPS URLs |
| `p389-ldap-candidates.txt` | All LDAP port hosts |
| `p389.txt` | Verified AD DCs |
| `ldapdomdump/` | LDAP domain dump output |
| `kerberos/` | Kerberoasting/ASREP-roasting hashes |
| `nuclei-results.txt` | Nuclei vulnerability findings |
| `/etc/hosts.bak` | Backup of original hosts |
| `/etc/resolv.conf.bak` | Backup of original resolv.conf |
| `/etc/krb5.conf.bak` | Backup of original krb5.conf |

## ⚠️ Notes

- Requires `sudo` for `masscan` and Kerberos configuration
- Kerberos config (`-ki`) overwrites `/etc/hosts`, `/etc/resolv.conf`, `/etc/krb5.conf` (backups created)
- LDAP credentials are never stored to disk
- All output files are created in the current working directory

## 📄 License

MIT