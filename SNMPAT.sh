#!/bin/bash

# Script Name: SNMP Audit Tool (SNMPAT)
# Description: This script performs an SNMP audit on a list of subnets and IP addresses using the onesixtyone SNMP scanner. It sorts the subnets and IP addresses, creates a file with SNMP community strings, and scans each subnet/IP one by one. The script then removes duplicate entries from the log file and performs a DNS lookup on each host, prepending the hostname to each line. The script also includes a cleanup section that removes all temporary files, leaving only the final log file.
# Github: wompRS

# Function to print a progress bar in light green color
print_progress() {
    local current=$1 # Arguments: current progress, total, current subnet/IP
    local total=$2
    local subnet_ip=$3
    local progress=$((current * 100 / total))
    local completed=$((progress / 2))
    local remaining=$((50 - completed))
    local light_green="\e[92m"
    local reset_color="\e[0m"
    printf "\rProgress: ${light_green}[%s%s] %d%%${reset_color} (Scanning %s, %s %d of %d)" "$(printf "%0.s#" $(seq 1 $completed))" "$(printf "%0.s-" $(seq 1 $remaining))" "$progress" "$subnet_ip" "$entry_type" "$current" "$total"
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

    # Function to convert integer to IP
    int2ip() {
        local ui32=$1
        shift
        local ip n
        for n in 1 2 3 4; do
            ip=$((ui32 & 0xff))${ip:+.}$ip
            ui32=$((ui32 >> 8))
        done
        echo "$ip"
    }

    # Function to expand subnet to IPs
    expand_subnet() {
        local ip mask
        IFS=/ read -r ip mask <<<"$1"
        local ip_dec=$(ip2int "$ip")
        local range_size=$((2 ** (32 - mask)))
        local i
        for ((i = 0; i < range_size; i++)); do
            echo "$(int2ip $((ip_dec + i)))"
        done
    }

    # Sort the subnets array from low to high
    sorted_subnets=($(printf '%s\n' "${subnets[@]}" | sort))

    # Sort the IPs array from low to high
    sorted_ips=($(printf '%s\n' "${ip_addresses[@]}" | sort))

    # Echo the sorted subnets that will be scanned
    echo -e "\e[94mSubnets:\e[0m"
    for subnet in "${sorted_subnets[@]}"; do
        echo "$subnet"
    done

   # Echo the sorted IPs that will be scanned
    echo -e "\e[94mIP Addresses:\e[0m"
    for ip in "${sorted_ips[@]}"; do
        # Check if the IP is in any of the subnets
        local is_duplicate=false
        for subnet in "${sorted_subnets[@]}"; do
            if [[ $(expand_subnet "$subnet") =~ (^|[[:space:]])"$ip"($|[[:space:]]) ]]; then
                echo "$ip - Duplicate entry. Scanner will skip. Subnet: $subnet"
                is_duplicate=true
                break
            fi
        done
        if [ "$is_duplicate" = false ] ; then
            echo "$ip"
        fi
    done
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

# Sort the subnets and IP addresses
IFS=$'\n' subnets=($(sort <<<"${subnets[*]}"))
IFS=$'\n' ip_addresses=($(sort <<<"${ip_addresses[*]}"))
unset IFS

# Total number of subnets and IP addresses
total_subnets=${#subnets[@]}
total_ip_addresses=${#ip_addresses[@]}
total=$((total_subnets + total_ip_addresses))

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

# Write the date, time, and user info to the top of the log file
echo "SNMPAT started at $now by user $current_user." >$log_file

# Scan each subnet/IP one by one
for i in "${!subnets[@]}" "${!ip_addresses[@]}"; do
    if [[ $i -lt ${#subnets[@]} ]]; then
        print_progress "$((i + 1))" "$total" "${subnets[$i]}" # Print progress bar for subnets
    else
        print_progress "$((i + 1))" "$total" "${ip_addresses[$i - ${#subnets[@]}]}" # Print progress bar for IP addresses
    fi

    if [[ $i -lt ${#subnets[@]} ]]; then
        if ! onesixtyone -c <(echo -e "public\ncommunity\ndefault\nadmin\nprivate\npublic\nmanager\ncisco\nsnmp\nnetwork\nmonitor\nagent\ntrap\nread\nwrite") -i <(echo "${subnets[$i]}") >>"$log_file"; then
            echo "Error occurred while scanning subnet: ${subnets[$i]}"
        fi
    else
        if ! onesixtyone -c <(echo -e "public\ncommunity\ndefault\nadmin\nprivate\npublic\nmanager\ncisco\nsnmp\nnetwork\nmonitor\nagent\ntrap\nread\nwrite") -i <(echo "${ip_addresses[$i - ${#subnets[@]}]}") >>"$log_file"; then
            echo "Error occurred while scanning IP address: ${ip_addresses[$i - ${#subnets[@]}]}"
        fi
    fi
done

# Perform DNS lookup on each host and prepend hostname to each line
sed -i '/Error in sendto: Permission denied/d' $log_file # Remove the "Error in sendto: Permission denied" line from the log file
sed -i '/Scanning/d' $log_file                           # Remove the "Scanning" line from the log file
awk 'NR>3 {print $1}' $log_file | sort -u | tail -n +4 | uniq | while read -r ip; do
    hostname=$(dig +short -x "$ip")
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
