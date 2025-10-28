#!/bin/bash
set -euo pipefail

# Script Name: SNMP Audit Tool (SNMPAT)
# Description: This script performs an SNMP audit on a list of subnets and IP addresses using the onesixtyone SNMP scanner. It sorts the subnets and IP addresses, creates a file with SNMP community strings, and scans each subnet/IP one by one. The script then removes duplicate entries from the log file and performs a DNS lookup on each host, prepending the hostname to each line. The script also includes a cleanup section that removes all temporary files, leaving only the final log file.
# Github: wompRS

# Function to handle fatal errors
error_exit() {
    echo "Error: $1" >&2
    exit 1
}

# Ensure required commands are available
check_dependencies() {
    command -v onesixtyone >/dev/null 2>&1 || error_exit "onesixtyone is required but not installed."
    command -v dig >/dev/null 2>&1 || error_exit "dig is required but not installed."
}

check_dependencies

# Prompt user for SNMP community strings and store them in a temporary file
get_community_strings() {
    local default_strings=("public" "community" "default" "admin" "private" "manager" "cisco" "snmp" "network" "monitor" "agent" "trap" "read" "write")
    local -a collected_strings=()
    declare -A seen_strings=()
    local choice cs_input cs_file line entry trimmed

    while true; do
        echo -e "\e[93mSelect how to build the community string list:\e[0m"
        echo "1. Add default list"
        echo "2. Add strings manually"
        echo "3. Add strings from a file"
        echo "4. Finish"
        read -rp $'\e[93;1mChoice [1-4]: \e[0m' choice

        case "$choice" in
            1)
                for entry in "${default_strings[@]}"; do
                    trimmed=${entry//$'\r'/}
                    trimmed="${trimmed#${trimmed%%[![:space:]]*}}"
                    trimmed="${trimmed%${trimmed##*[![:space:]]}}"
                    if [[ -n $trimmed && -z ${seen_strings[$trimmed]+x} ]]; then
                        collected_strings+=("$trimmed")
                        seen_strings[$trimmed]=1
                    fi
                done
                echo -e "\e[92mAdded default community strings.\e[0m"
                ;;
            2)
                read -rp $'\e[93;1mEnter community strings (comma or space separated): \e[0m' cs_input
                cs_input=${cs_input//,/ }
                local -a manual_entries=()
                if [[ -n $cs_input ]]; then
                    read -ra manual_entries <<<"$cs_input"
                fi
                for entry in "${manual_entries[@]}"; do
                    trimmed=${entry//$'\r'/}
                    trimmed="${trimmed#${trimmed%%[![:space:]]*}}"
                    trimmed="${trimmed%${trimmed##*[![:space:]]}}"
                    if [[ -n $trimmed && -z ${seen_strings[$trimmed]+x} ]]; then
                        collected_strings+=("$trimmed")
                        seen_strings[$trimmed]=1
                    fi
                done
                if [[ ${#manual_entries[@]} -gt 0 ]]; then
                    echo -e "\e[92mAdded manual entries.\e[0m"
                else
                    echo -e "\e[93mNo manual entries detected.\e[0m"
                fi
                ;;
            3)
                read -rp $'\e[93;1mEnter file path: \e[0m' cs_file
                if [[ ! -f "$cs_file" ]]; then
                    echo -e "\e[91mCommunity string file not found: $cs_file\e[0m"
                    continue
                fi
                while IFS= read -r line || [[ -n $line ]]; do
                    line=${line//$'\r'/}
                    line=${line//,/ }
                    [[ -z $line ]] && continue
                    local -a file_entries=()
                    read -ra file_entries <<<"$line"
                    for entry in "${file_entries[@]}"; do
                        trimmed=${entry//$'\r'/}
                        trimmed="${trimmed#${trimmed%%[![:space:]]*}}"
                        trimmed="${trimmed%${trimmed##*[![:space:]]}}"
                        if [[ -n $trimmed && -z ${seen_strings[$trimmed]+x} ]]; then
                            collected_strings+=("$trimmed")
                            seen_strings[$trimmed]=1
                        fi
                    done
                done <"$cs_file"
                echo -e "\e[92mLoaded community strings from file.\e[0m"
                ;;
            4)
                if [[ ${#collected_strings[@]} -eq 0 ]]; then
                    echo -e "\e[91mPlease add at least one community string before finishing.\e[0m"
                    continue
                fi
                break
                ;;
            *)
                echo -e "\e[91mInvalid choice. Please select option 1-4.\e[0m"
                ;;
        esac

        if [[ ${#collected_strings[@]} -gt 0 ]]; then
            echo -e "\e[94mCurrent community strings (${#collected_strings[@]}):\e[0m"
            for entry in "${collected_strings[@]}"; do
                echo "  - $entry"
            done
        fi
    done

    community_file=$(mktemp)
    printf "%s\n" "${collected_strings[@]}" >"$community_file"
    echo -e "\e[94mUsing ${#collected_strings[@]} community strings for all scans.\e[0m"
    trap 'rm -f "$community_file"' EXIT
}

get_community_strings

# Function to print a progress bar in light green color
print_progress() {
    local current=$1 # Arguments: current progress, total, current subnet/IP, entry type
    local total=$2
    local subnet_ip=$3
    local entry_type=$4
    local progress=$((current * 100 / total))
    local completed=$((progress / 2))
    local remaining=$((50 - completed))
    local light_green="\e[92m"
    local reset_color="\e[0m"
    local completed_bar=""
    local remaining_bar=""
    if ((completed > 0)); then
        completed_bar=$(printf "%0.s#" $(seq 1 $completed))
    fi
    if ((remaining > 0)); then
        remaining_bar=$(printf "%0.s-" $(seq 1 $remaining))
    fi
    printf "\rProgress: ${light_green}[%s%s] %d%%${reset_color} (Scanning %s, %s %d of %d)" "$completed_bar" "$remaining_bar" "$progress" "$subnet_ip" "$entry_type" "$current" "$total"
}

# Define your subnets and IP addresses
subnets=()
ip_addresses=()

# Function to validate subnets and IP addresses
validate_subnets_ip() {
    # Function to convert IP to integer
    ip2int() {
        local a b c d
        IFS=. read -r a b c d <<<"$1"
        echo $(((a << 24) + (b << 16) + (c << 8) + d))
    }

    cidr_contains_ip() {
        local cidr=$1
        local ip=$2
        local network mask
        IFS=/ read -r network mask <<<"$cidr"
        local network_int=$(ip2int "$network")
        local ip_int=$(ip2int "$ip")
        local mask_int
        if ((mask == 0)); then
            mask_int=0
        else
            mask_int=$(( (0xFFFFFFFF << (32 - mask)) & 0xFFFFFFFF ))
        fi
        [[ $((network_int & mask_int)) -eq $((ip_int & mask_int)) ]]
    }

    if ((${#subnets[@]})); then
        mapfile -t subnets < <(printf '%s\n' "${subnets[@]}" | awk 'NF' | sort -u)
    else
        subnets=()
    fi

    if ((${#ip_addresses[@]})); then
        mapfile -t ip_addresses < <(printf '%s\n' "${ip_addresses[@]}" | awk 'NF' | sort -u)
    else
        ip_addresses=()
    fi

    echo -e "\e[94mSubnets:\e[0m"
    for subnet in "${subnets[@]}"; do
        echo "$subnet"
    done

    echo -e "\e[94mIP Addresses:\e[0m"
    local -a filtered_ips=()
    for ip in "${ip_addresses[@]}"; do
        local is_duplicate=false
        for subnet in "${subnets[@]}"; do
            if cidr_contains_ip "$subnet" "$ip"; then
                echo "$ip - Duplicate entry. Scanner will skip. Subnet: $subnet"
                is_duplicate=true
                break
            fi
        done
        if [[ $is_duplicate == false ]]; then
            echo "$ip"
            filtered_ips+=("$ip")
        fi
    done

    ip_addresses=("${filtered_ips[@]}")
}

# Ask the user to enter subnets and IP addresses manually or in a file containing the subnets/IPs
echo -e "\e[93mPlease enter the addresses you want to scan:\e[0m"
echo "1. Subnet in CIDR format (e.g. 192.168.0.0/24, 10.0.0.0/8)"
echo "2. Individual IP Addresses (e.g. 192.168.0.1, 10.0.0.1)"
echo "3. .txt or .csv file (e.g. subnets.txt, subnets.csv)"
echo -e "\e[94;1mEnter each value as a comma-separated list or as individual lines:\e[0m"
while true; do
    read -p $'\e[93;1mEnter subnet/IP or file: \e[0m' input
    if [[ $input == "done" ]]; then
        echo "Current list of entries:"
        for subnet_ip in "${subnets[@]}" "${ip_addresses[@]}"; do
            echo "$subnet_ip"
        done
        if ! validate_subnets_ip; then
            echo "Please re-enter the subnets/IPs."
            subnets=()
            ip_addresses=()
            continue
        fi
        break
    elif [[ $input == *.txt || $input == *.csv ]]; then
        if [[ -f $input ]]; then
            while IFS= read -r line; do
                if [[ $line =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$ ]]; then # Validate subnet format
                    if [[ " ${subnets[@]} " =~ " $line " ]]; then
                        echo "Duplicate subnet entry: $line"
                    else
                        subnets+=("$line")
                    fi
                elif [[ $line =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then # Validate IP address format
                    if [[ " ${ip_addresses[@]} " =~ " $line " ]]; then
                        echo "Duplicate IP address entry: $line"
                    else
                        ip_addresses+=("$line")
                    fi
                else
                    echo "Invalid subnet/IP format in file: $line"
                fi
            done <"$input"
            echo "Current list of entries:"
            for subnet_ip in "${subnets[@]}" "${ip_addresses[@]}"; do
                echo "$subnet_ip"
            done
            if ! validate_subnets_ip; then
                echo "Please re-enter the subnets/IPs."
                subnets=()
                ip_addresses=()
                continue
            fi
            break
        else
            echo "File not found. Please try again."
        fi
    else
        IFS=',' read -ra subnet_ip_list <<<"$input" # Validate subnet/IP format
        for subnet_ip in "${subnet_ip_list[@]}"; do
            if [[ $subnet_ip =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$ ]]; then
                if [[ " ${subnets[@]} " =~ " $subnet_ip " ]]; then
                    echo "Duplicate subnet entry: $subnet_ip"
                else
                    subnets+=("$subnet_ip")
                fi
            elif [[ $subnet_ip =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
                if [[ " ${ip_addresses[@]} " =~ " $subnet_ip " ]]; then
                    echo "Duplicate IP address entry: $subnet_ip"
                else
                    ip_addresses+=("$subnet_ip")
                fi
            else
                # Check if the input contains a file and individual subnet/IP entry on the same line
                IFS=' ' read -ra entries <<<"$subnet_ip"
                for entry in "${entries[@]}"; do
                    if [[ $entry == *.txt || $entry == *.csv ]]; then
                        if [[ -f $entry ]]; then
                            while IFS= read -r line; do
                                if [[ $line =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$ ]]; then # Validate subnet format
                                    if [[ " ${subnets[@]} " =~ " $line " ]]; then
                                        echo "Duplicate subnet entry: $line"
                                    else
                                        subnets+=("$line")
                                    fi
                                elif [[ $line =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then # Validate IP address format
                                    if [[ " ${ip_addresses[@]} " =~ " $line " ]]; then
                                        echo "Duplicate IP address entry: $line"
                                    else
                                        ip_addresses+=("$line")
                                    fi
                                else
                                    echo "Invalid subnet/IP format in file: $line"
                                fi
                            done <"$entry"
                        else
                            echo "File not found: $entry"
                        fi
                    else
                        if [[ $entry =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$ ]]; then
                            if [[ " ${subnets[@]} " =~ " $entry " ]]; then
                                echo "Duplicate subnet entry: $entry"
                            else
                                subnets+=("$entry")
                            fi
                        elif [[ $entry =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
                            if [[ " ${ip_addresses[@]} " =~ " $entry " ]]; then
                                echo "Duplicate IP address entry: $entry"
                            else
                                ip_addresses+=("$entry")
                            fi
                        else
                            echo "Invalid subnet/IP format: $entry"
                        fi
                    fi
                done
            fi
        done
        echo "Current list of entries:"
        for subnet_ip in "${subnets[@]}" "${ip_addresses[@]}"; do
            echo "$subnet_ip"
        done
        echo "" # Newline for clean output
        read -p $'\e[93;1mDo you want to add any more subnets/IPs? (y/n): \e[0m' add_more
        case $add_more in
        [Yy]*) continue ;;
        [Nn]*)
            if ! validate_subnets_ip; then
                echo "Please re-enter the subnets/IPs."
                subnets=()
                ip_addresses=()
                continue
            fi
            break
            ;;
        *) echo "Please answer yes or no." ;;
        esac
    fi
done

# Total number of subnets and IP addresses
total_subnets=${#subnets[@]}
total_ip_addresses=${#ip_addresses[@]}
total=$((total_subnets + total_ip_addresses))

# Ensure at least one address was provided
if [[ $total -eq 0 ]]; then
    error_exit "No valid subnets or IP addresses provided."
fi

# Print the starting message
echo "" # Newline for clean output
if [[ $total_subnets -eq 0 ]]; then
    echo -e "\e[94;1mStarting the scan for insecure SNMP Community Strings on $total_ip_addresses IP addresses.\e[0m"
else
    echo -e "\e[94;1mStarting the scan for insecure SNMP Community Strings on $total_subnets subnets and $total_ip_addresses IP addresses.\e[0m"
fi

# Get the start time
start_time=$(date +%s)

# Get the current date and time
now=$(date +"%Y-%m-%d_%H-%M-%S")
current_user=$(whoami)

# Create a new log file with the current date in the name
log_file="$HOME/SNMPAT_log_$now.log"

# Ensure the log file can be created
if ! touch "$log_file"; then
    error_exit "Unable to create log file at $log_file"
fi

# Write the date, time, and user info to the top of the log file
echo "SNMPAT started at $now by user $current_user." >"$log_file"

# Scan each subnet/IP one by one
current_index=0
for subnet in "${subnets[@]}"; do
    ((++current_index))
    print_progress "$current_index" "$total" "$subnet" "Subnet"
    if ! onesixtyone -c "$community_file" -i <(echo "$subnet") >>"$log_file"; then
        echo "Error occurred while scanning subnet: $subnet"
    fi
done

for ip in "${ip_addresses[@]}"; do
    ((++current_index))
    print_progress "$current_index" "$total" "$ip" "IP"
    if ! onesixtyone -c "$community_file" -i <(echo "$ip") >>"$log_file"; then
        echo "Error occurred while scanning IP address: $ip"
    fi
done
echo ""

# Perform DNS lookup on each host and prepend hostname to each line
sed -i '/Error in sendto: Permission denied/d' $log_file # Remove the "Error in sendto: Permission denied" line from the log file
sed -i '/Scanning/d' $log_file                           # Remove the "Scanning" line from the log file
tail -n +5 "$log_file" | awk '{print $1}' | sort -u | while read -r ip; do
    if ! hostname=$(dig +short -x "$ip"); then
        echo "dig lookup failed for IP: $ip" >&2
        continue
    fi
    if [[ -n $hostname ]]; then
        sed -i "s|$ip|$hostname $ip|g" "$log_file"
    else
        echo "Failed to perform DNS lookup for IP: $ip"
    fi
done

# Get the end time of the script
end_time=$(date +%s)

# Calculate the total execution time of the script
total_time=$((end_time - start_time))

# Write the total execution time to the top of the log file on line 3
sed -i "2iSNMPAT completed in $total_time seconds." $log_file

# Count unique IP entries and community strings
unique_ips=$(grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' $log_file | sort -u | wc -l)
unique_communities=$(grep -oP '\[[^\]]+\]' $log_file | sort -u | wc -l)

# Write the counts to the top of the log file
sed -i "3iThere are $unique_ips unique IP entries and $unique_communities unique community strings." $log_file
sed -i "4i------------------------------------------------------" $log_file

echo "" # Newline for clean output
echo "SNMPAT completed. You can view the log file at $log_file"

# Check for results in the log file. If none, write a message.
if [[ $unique_ips -eq 0 ]]; then
    echo "" >>"$log_file" # Newline for clean output
    echo "No results found using the provided community strings." >>"$log_file"
fi

read -p $'\e[93mDo you want to view the log file now? (yes/no): \e[0m' view_log
case $view_log in
[Yy]* | "")                                                # Accept enter key as "yes"
    echo "Thanks for using SNMPAT! Viewing $log_file now." # Newline for clean output
    echo "------------------------------------------------------"
    cat "$log_file"
    ;;
[Nn]*)
    echo "" # Newline for clean output
    echo "Log file not viewed. Thanks for using SNMPAT!"
    ;;
*)
    echo "" # Newline for clean output
    echo "Invalid option. Log file not viewed. Thanks for using SNMPAT!"
    ;;
esac
