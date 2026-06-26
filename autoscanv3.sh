#!/bin/bash

# Pentest Framework - Masscan Scanning Script
# Debug: Script started
# Usage: ./autoscan.sh -i iplist.txt -c check|start [-r 1000]

# Signal handler for Ctrl+C and other interruptions
cleanup() {
    echo ""
    echo -e "${RED}⚠️  Script interrupted by user (Ctrl+C)${NC}"
    echo -e "${YELLOW}Cleaning up temporary files...${NC}"
    
    # Clean up any temporary files if needed
    if [[ -f "host-discovery.txt" ]]; then
        rm -f "host-discovery.txt"
    fi
    
    echo -e "${CYAN}Script terminated gracefully.${NC}"
    exit 130
}

# Set up signal handlers
trap cleanup SIGINT SIGTERM

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

# Port list (transferred from scan.config file)
PORTS="20,21,22,23,25,53,67,68,69,80,81,82,88,110,111,119,123,135,137,139,143,156,161,162,179,194,389,427,443,445,464,465,554,557,587,593,623,631,636,993,995,1000,1001,1433,1434,1443,1521,1522,1529,1720,1723,2021,2022,2049,3000,3268,3269,3306,3389,4022,4444,4848,5000,5060,5061,5062,5432,5555,5900,5985,5986,6000,6001,6002,6379,6380,6443,6667,7443,8000,8008,8020,8040,8042,8080,8081,8082,8083,8090,8181,8443,8444,8888,9000,9001,9080,9200,9443,9999,10000,10443,11211,27017"
echo -e "${CYAN}Port list loaded from script:${NC} $PORTS"

# Help message
show_help() {
    echo -e "${BOLD}${WHITE}Usage:${NC} $0 -i <ip_file> -c <command> [-r <rate>]"
    echo ""
    echo -e "${BOLD}${YELLOW}Parameters:${NC}"
    echo -e "  ${GREEN}-i, --input${NC}    IP list file (required)"
    echo -e "  ${GREEN}-c, --command${NC}  Command: check (access test) or start (full scan)"
    echo -e "  ${GREEN}-r, --rate${NC}     Scan rate (default: 1000)"
    echo -e "  ${GREEN}-u, --username${NC} LDAP username (optional)"
    echo -e "  ${GREEN}-p, --password${NC} LDAP password (optional)"
    echo -e "  ${GREEN}-d, --domain${NC}   LDAP domain name (optional)"
    echo -e "  ${GREEN}-ki, --kerberos-implementation${NC}  Automate Kerberos config (hosts/resolv/krb5) after scan (optional)"
    echo -e "  ${GREEN}-h, --help${NC}     Show this help message"
    echo ""
    echo -e "${BOLD}${YELLOW}Commands:${NC}"
    echo -e "  ${CYAN}check${NC}          Only performs access test (host discovery)"
    echo -e "  ${CYAN}start${NC}          Performs full port scan and saves results"
    echo ""
    echo -e "${BOLD}${YELLOW}Config:${NC}"
    echo -e "  Port list is defined within the script (${PURPLE}expanded TCP set${NC}: 100+ ports — web, mail/SMTP-IMAP-POP3,"
    echo -e "    AD/LDAP/GC/Kerberos, DBs, SMB/RDP/VNC, SIP/RTSP, WinRM, printers, Redis/Mongo/Elastic, alt HTTP/HTTPS; ${YELLOW}TCP only${NC}, no UDP)"
    echo -e "  ${PURPLE}DC verify:${NC} After scan, hosts in p389 are checked via anonymous LDAP root DSE (AD capability OIDs);"
    echo -e "    verified DCs replace p389.txt; full LDAP port list kept in p389-ldap-candidates.txt"
    echo -e "    With ${GREEN}-d domain${NC}, DNS SRV _ldap._tcp.dc._msdcs is shown as reference"
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
    echo ""
    echo -e "${BOLD}${YELLOW}Examples:${NC}"
    echo -e "  $0 -i iplist.txt -c check"
    echo -e "  $0 -i iplist.txt -c start -r 2000"
    echo -e "  $0 -i iplist.txt -c start -ki"
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
if [[ -z "$IP_FILE" ]]; then
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
if [[ ! -f "$IP_FILE" ]]; then
    echo -e "${RED}Error: IP file not found: $IP_FILE${NC}"
    exit 1
fi

# Host Discovery function
host_discovery() {
    echo -e "${BOLD}${BLUE}=== HOST DISCOVERY PHASE ===${NC}"
    echo -e "${YELLOW}Detecting active hosts...${NC}"

    # Common ports for host discovery
    DISCOVERY_PORTS="80,443,22,21,25,53,110,143,993,995,3389,5900,8080,8443"

    # Host discovery scan
    sudo masscan -p "$DISCOVERY_PORTS" --rate="$RATE" -iL "$IP_FILE" > host-discovery.txt 2>/dev/null

    # Check if any hosts are active
    if [[ -f "host-discovery.txt" && -s "host-discovery.txt" ]]; then
        active_count=$(grep "Discovered open port" host-discovery.txt | cut -d " " -f 6 | sort -u | wc -l)
        echo -e "${GREEN}✅ $active_count active hosts found${NC}"
        
        # Access status report
        echo ""
        echo -e "${BOLD}${PURPLE}=== ACCESS STATUS REPORT ===${NC}"
        total_ips=$(wc -l < "$IP_FILE")
        echo -e "${WHITE}Total IP/Subnet:${NC} $total_ips"
        echo -e "${WHITE}Active Hosts:${NC} $active_count"
        if [[ $total_ips -gt 0 ]]; then
            access_rate=$((active_count * 100 / total_ips))
            echo -e "${WHITE}Access Rate:${NC} ${GREEN}%$access_rate${NC}"
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
        if verify_ip_is_domain_controller "$ip"; then
            echo -e "  ${WHITE}${ip}${NC} ${GREEN}-> verified Active Directory DC${NC}"
            echo "$ip" >> "$tmp"
        else
            echo -e "  ${WHITE}${ip}${NC} ${YELLOW}-> not verified as AD DC (or anonymous root DSE unavailable)${NC}"
        fi
    done < "p389-ldap-candidates.txt"

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
        ldap_try_validate_bind_once
        rc=$?
        if [[ $rc -eq 0 ]]; then
            echo -e "${GREEN}Credentials validated. Proceeding with LDAP-related steps.${NC}"
            LDAP_SKIP_DOWNSTREAM_LDAP_OPS=false
            return 0
        fi

        if [[ $rc -eq 1 ]]; then
            echo -e "${RED}The username or password you entered is incorrect.${NC}"
        else
            echo -e "${RED}Could not connect to LDAP on any address in p389.txt (or no successful bind).${NC}"
        fi

        while true; do
            read -r -p "Do you want to enter credentials again? [y/n]: " yn
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
    elif [[ -f "$IP_FILE" && -s "$IP_FILE" ]]; then
        ip_source="$IP_FILE"
        echo -e "${YELLOW}p389.txt not found, falling back to input IP file: $IP_FILE${NC}"
    else
        echo -e "${RED}Error: No IP source available (neither p389.txt nor $IP_FILE found).${NC}"
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
            if [[ $? -eq 0 ]]; then
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

# Detailed port scanning function
detailed_scan() {
    echo -e "${BOLD}${BLUE}=== DETAILED PORT SCAN ===${NC}"
    echo -e "${YELLOW}Starting detailed port scan on all IPs...${NC}"
    echo -e "${WHITE}IP File:${NC} $IP_FILE"
    echo -e "${WHITE}Rate:${NC} $RATE"
    echo -e "${WHITE}Ports:${NC} $PORTS"
    echo -e "${CYAN}Results will be saved to mass-result.txt file...${NC}"
    echo ""

    sudo masscan -p "$PORTS" --rate="$RATE" -iL "$IP_FILE" > mass-result.txt

    echo -e "${GREEN}Detailed scan completed! Results saved to mass-result.txt file.${NC}"

    # Port-based filtering and file creation
    echo -e "${PURPLE}Creating port-based files...${NC}"

    # Define web ports
    declare -A WEB_PORTS
    # HTTP ports
    WEB_PORTS[80]="http"
    WEB_PORTS[81]="http"
    WEB_PORTS[82]="http"
    WEB_PORTS[3000]="http"
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
    WEB_PORTS[9080]="http"
    # HTTPS ports
    WEB_PORTS[443]="https"
    WEB_PORTS[8181]="https"
    WEB_PORTS[8443]="https"
    WEB_PORTS[8444]="https"
    WEB_PORTS[9443]="https"
    WEB_PORTS[10443]="https"
    WEB_PORTS[10000]="https"

    # Split PORTS variable by comma and process each port
    IFS=',' read -ra PORT_ARRAY <<< "$PORTS"

    for port in "${PORT_ARRAY[@]}"; do
        # Remove spaces from port number
        port=$(echo "$port" | tr -d ' ')
        
        # Filter IP addresses for this port and save with numerical sorting
        if [[ -f "mass-result.txt" ]]; then
            # Filter, sort and save IP addresses (one IP per line)
            grep " $port/" mass-result.txt | cut -d " " -f 6 | sort -V > "p${port}.txt"
            
            # Provide information if file is not empty
            if [[ -s "p${port}.txt" ]]; then
                ip_count=$(cat "p${port}.txt" | wc -l)
                echo -e "${GREEN}Found $ip_count IP addresses for port $port -> p${port}.txt${NC}"
                
                # Create HTTP/HTTPS URL file if it's a web port
                if [[ -n "${WEB_PORTS[$port]}" ]]; then
                    protocol="${WEB_PORTS[$port]}"
                    # Convert IP addresses to URL format (one per line)
                    sed "s/^/${protocol}:\/\//" "p${port}.txt" > "p${port}-${protocol}.txt"
                    echo -e "${CYAN}  -> Web URL file created: p${port}-${protocol}.txt${NC}"
                fi
            else
                rm -f "p${port}.txt"
            fi
        fi
    done

    # Create all-webs.txt combining all web URLs (with port suffix for non-standard ports)
    > "all-webs.txt"
    for port in "${!WEB_PORTS[@]}"; do
        if [[ -f "p${port}.txt" && -s "p${port}.txt" ]]; then
            protocol="${WEB_PORTS[$port]}"
            if [[ ("$protocol" == "http" && "$port" == "80") || ("$protocol" == "https" && "$port" == "443") ]]; then
                # Standard port — no port number in URL
                sed "s/^/${protocol}:\/\//" "p${port}.txt" >> "all-webs.txt"
            else
                # Non-standard port — include port number
                sed "s/^/${protocol}:\/\//; s/$/:${port}/" "p${port}.txt" >> "all-webs.txt"
            fi
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
    
    filter_verified_domain_controllers
    
    ldap_credentials_validation_gate
    
    # Web URL lists: written during port-based file creation (p<port>-http.txt / p<port>-https.txt); no live HTTP checks
    echo ""
    echo -e "${BOLD}${PURPLE}=== WEB PORTS SUMMARY ===${NC}"
    
    echo -e "${BOLD}${CYAN}HTTP Ports:${NC}"
    for port in 80 81 82 3000 8000 8008 8020 8040 8042 8080 8081 8082 8083 8090 8888 9000 9080; do
        if [[ -f "p${port}-http.txt" && -s "p${port}-http.txt" ]]; then
            url_count=$(cat "p${port}-http.txt" | wc -l)
            echo -e "${WHITE}  Port $port:${NC} $url_count URLs -> p${port}-http.txt"
        fi
    done
    
    echo ""
    echo -e "${BOLD}${CYAN}HTTPS Ports:${NC}"
    for port in 443 8181 8443 8444 9443 10443 10000; do
        if [[ -f "p${port}-https.txt" && -s "p${port}-https.txt" ]]; then
            url_count=$(cat "p${port}-https.txt" | wc -l)
            echo -e "${WHITE}  Port $port:${NC} $url_count URLs -> p${port}-https.txt"
        fi
    done
    
    # Run LDAP domain dump if credentials are provided
    ldap_domain_dump
    
    # Run BloodHound Python if credentials are provided
    bloodhound_dump
    
    # Run Kerberoasting and ASREP-roasting if credentials are provided
    kerberoasting_asreproasting
    
    # Run Kerberos implementation if flag is set
    if [[ "$KERBEROS_IMPL" == "true" ]]; then
        kerberos_implementation
    fi
    
    # Prompt for nuclei scan
    nuclei_scan_prompt
}

# Execute commands
case "$COMMAND" in
    "check")
        host_discovery
        # Run Kerberos implementation after check if flag is set (uses IP file directly)
        if [[ "$KERBEROS_IMPL" == "true" ]]; then
            kerberos_implementation
        fi
        # Run Kerberoasting and ASREP-roasting if credentials are provided
        kerberoasting_asreproasting
        # Prompt for nuclei scan
        nuclei_scan_prompt
        ;;
    "start")
        if host_discovery; then
            detailed_scan
        else
            echo -e "${RED}Host discovery failed. Cannot perform detailed scan.${NC}"
            exit 1
        fi
        ;;
esac