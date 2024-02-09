#!/bin/bash
# Script Name: SNMP Audit Tool (SNMPAT)
# Description: This script performs an SNMP audit on a list of subnets using the onesixtyone SNMP scanner. It sorts the subnets, creates a file with SNMP community strings, and scans each subnet one by one. The script then removes duplicate entries from the log file and performs a DNS lookup on each host, prepending the hostname to each line. The script also includes a cleanup section that removes all temporary files, leaving only the final log file. A debugging section is included at the end that redirects all error messages to a separate file for troubleshooting.
# Date: February 9th, 2024
# Author: Reed Sutherland
# Contact: reed@womp.dev
# Github: @wompieRS

# Function to print a progress bar
print_progress() {
    # Arguments: current progress, total, current subnet
    local current=$1
    local total=$2
    local subnet=$3
    local progress=$((current * 100 / total))
    local completed=$((progress / 2))
    local remaining=$((50 - completed))
    printf "\rProgress: [%s%s] %d%% (Scanning %s, subnet %d of %d)" "$(printf "%0.s#" $(seq 1 $completed))" "$(printf "%0.s-" $(seq 1 $remaining))" "$progress" "$subnet" "$current" "$total"
}

# Define your subnets
subnets=()

# Function to validate subnets
validate_subnets() {
    echo "These are the subnets that will be scanned:"
    for subnet in "${subnets[@]}"; do
        echo "$subnet"
    done
    while true; do
        read -p "Are the displayed subnets correct? (yes/no/exit) [y]: " yn
        yn=${yn,,}  # Convert input to lowercase
        yn=${yn:-y} # Default value is "y"
        case $yn in
        [Yy] | [Yy][Ee][Ss]) break ;;
        [Nn] | [Nn][Oo]) return 1 ;;
        [Ee] | [Ee][Xx][Ii][Tt]) exit ;;
        *) echo "Please type Y for Yes, N for No, or E for Exit." ;;
        esac
    done
    return 0
}

# Ask the user to enter subnets manually or in a file containing the subnets
echo "Please enter subnets as a comma-separated list (e.g., 192.168.0.0/24,10.0.0.0/16), or provide a .txt or .csv file containing the subnets you wish to scan:"
while true; do
    read -p "Enter subnet or file: " input
    if [[ $input == "done" ]]; then
        if ! validate_subnets; then
            echo "Please re-enter the subnets."
            subnets=()
            continue
        fi
        break
    elif [[ $input == *.txt || $input == *.csv ]]; then
        if [[ -f $input ]]; then
            while IFS= read -r line; do
                # Validate subnet format
                if [[ $line =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$ ]]; then
                    subnets+=("$line")
                else
                    echo "Invalid subnet format in file: $line"
                fi
            done <"$input"
            if ! validate_subnets; then
                echo "Please re-enter the subnets."
                subnets=()
                continue
            fi
            break
        else
            echo "File not found. Please try again."
        fi
    else
        # Validate subnet format
        IFS=',' read -ra subnet_list <<<"$input"
        for subnet in "${subnet_list[@]}"; do
            if [[ $subnet =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$ ]]; then
                subnets+=("$subnet")
            else
                echo "Invalid subnet format: $subnet"
            fi
        done
        read -p "Do you want to add any more subnets? (y/n): " add_more
        case $add_more in
        [Yy]*) continue ;;
        [Nn]*)
            if ! validate_subnets; then
                echo "Please re-enter the subnets."
                subnets=()
                continue
            fi
            break
            ;;
        *) echo "Please answer yes or no." ;;
        esac
    fi
done

# Sort the subnets
IFS=$'\n' subnets=($(sort <<<"${subnets[*]}"))
unset IFS

# Total number of subnets
total=${#subnets[@]}

# Print the starting message
echo "" # Newline for clean output
echo "" # Newline for clean output

echo "Starting the scan for insecure SNMP Community Strings on $total subnets."

# Get the start time
start_time=$(date +%s)

# Get the current date and time
now=$(date +"%Y-%m-%d_%H-%M-%S")
current_user=$(whoami)

# Create a new log file with the current date in the name
log_file="$HOME/SNMPAT_log_$now.log"

# Write the date, time, and user info to the top of the log file
echo "SNMPAT started at $now by user $current_user." >$log_file

# Scan each subnet one by one
for i in "${!subnets[@]}"; do
    # Print progress bar
    print_progress "$((i + 1))" "$total" "${subnets[$i]}"

    # Run onesixtyone and append output to the log file
    if ! onesixtyone -c <(echo -e "public\ncommunity\ndefault\nadmin") -i <(echo "${subnets[$i]}") >>"$log_file"; then
        echo "Error occurred while scanning subnet: ${subnets[$i]}"
    fi
done

# Perform DNS lookup on each host and prepend hostname to each line
awk 'NR>3 {print $1}' $log_file | sort -u | while read -r ip; do
    hostname=$(dig +short -x "$ip")
    if [[ -n $hostname ]]; then
        sed -i "s/^$ip/$hostname &/" $log_file
    else
        echo "Failed to perform DNS lookup for IP: $ip"
    fi
done

# Remove the "Scanning" and "error in sendto:" lines from the log file
sed -i '/Scanning/d' $log_file
sed -i '/Error  in sendto:/d' $log_file


# Count unique IP entries and community strings
unique_ips=$(awk '{print $2}' $log_file | sort -u | wc -l)
unique_communities=$(grep -oP '\[\K[^]]+' $log_file | sort -u | wc -l)

# Write the counts to the top of the log file
sed -i "1iThere are $unique_ips unique IP entries and $unique_communities unique community strings." $log_file

# Get the end time
end_time=$(date +%s)

# Calculate the total execution time
total_time=$((end_time - start_time))

# Write the total execution time to the top of the log file
sed -i "1iSNMPAT completed in $total_time seconds." $log_file

echo "" # Newline for clean output
echo "SNMPAT completed. You can view the log file at $log_file"

# Debugging section
exec 2>"$HOME/SNMPAT_debug.log"
set -x
