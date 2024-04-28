#!/bin/bash

banner="
  _   _      _   _____           _   _____       _            _   _           
 | \ | |    | | |  __ \         | | |  __ \     | |          | | (_)          
 |  \| | ___| |_| |__) |__  _ __| |_| |  | | ___| |_ ___  ___| |_ ___   _____ 
 | . \` |/ _ \ __|  ___/ _ \| '__| __| |  | |/ _ \ __/ _ \/ __| __| \ \ / / _ \\
 | |\  |  __/ |_| |  | (_) | |  | |_| |__| |  __/     __/ (__| |_| |\ V /  __/
 |_| \_|\___|\__|_|   \___/|_|   \__|_____/ \___|\__\___|\___|\__|_| \_/ \___|
                                               
                                    by \e[1;31mIsmail Barrous\e[0m
                                       Version: \e[1;31m1.0\e[0m
"

echo -e "$banner"

# Function to check if a command exists
command_exists() {
    command -v "$1" 2>/dev/null
}

# Function to check and install missing dependencies
check_and_install_dependencies() {
    echo -e "\e[1;93m[...] Checking And Installing Missing Dependencies...\e[0m"
    local dependencies=("wpscan" "cmseek" "droopescan" "nikto" "joomscan")
    if [ -z $(command_exists "droopescan") ]; then
        apt-get install python-pip
        pip install droopescan
    fi
    if [ -z $(command_exists "joomscan") ]; then
        apt install -y joomscan 
    fi
    echo -e "\n\e[1;90m[ ✓ ] Done !\e[0m\n"
}

check_and_install_dependencies

declare -a web_ports=()
declare -a db_ports=()
declare -a mail_ports=()
declare -a ad_ports=()
declare -a other_ports=()
declare -a web_technologies=()

# Function to prompt user for input
prompt_user() {
    while true; do
        read -p "$1 [y/n]: " yn
        case $yn in
            [Yy]* ) return 0;;
            [Nn]* ) return 1;;
            * ) echo "Please answer yes or no.";;
        esac
    done
}

print_table() {
    local header="\e[1;34m$1\e[0m"
    shift
    local array=("$@")  # Get the array as argument
    local error="\e[1;31m[✗] No results were found !\e[0m"
    # Check if the length is greater than 0
    if [ "${#array[@]}" -gt 0 ]; then
        array=("$header" "${array[@]}")
    else
        array=("$error" "${array[@]}")    
    fi
    printf '%b\n' "${array[@]}" | column -t -s '|'
}

#Function to classify services based on their ports and descriptions
classify_ports() {
    local host="$1"
    local port="$2"
    local svc_name="$3"
    local description="$4"
    local full_str="$host | $port | $svc_name"
    if [ ! -z "$description" ]; then
        full_str+=" | $description"
    fi
    case "$port" in
        80|443|8080|8443)
            web_ports+=("$full_str")
            ;;
        3306|5432|1521|27017|6379)
            db_ports+=("$full_str")
            ;;
        25|587|110|143|993|995)
            mail_ports+=("$full_str")
            ;;
        135|88|139|445|389|3268|3269)
            ad_ports+=("$full_str")
            ;;
        *)
            case "$description $svc_name" in
                *"http"*)
                    web_ports+=("$full_str")
                    ;;
                *"mysql"*|*"postgresql"*|*"oracle"*|*"mongodb"*|*"redis"*)
                    db_ports+=("$full_str")
                    ;;
                *"smtp"*|*"pop3"*|*"imap"*|*"submission"*|*"smtps"*)
                    mail_ports+=("$full_str")
                    ;;
                *"ldap"*|*"smb"*|*"rpc"*|*"kerberos"*|*"netbios"*)
                    ad_ports+=("$full_str")
                    ;;
                *)
                    other_ports+=("$full_str")
                    ;;
            esac
            ;;
    esac
}

echo -e "\e[1;93m[...] Identifying Hosts:\e[0m"

network_range=$(ip route | grep "/" | awk '{print $1}')

router_ip=$(ip route | grep default | awk '{print $3}')

ip_list=($(nmap -sn "$network_range" | grep "report" | awk '{print $5}'))

if [ ${#ip_list[@]} -lt 1 ]; then
    echo -e "\e[1;31m[✗] No results were found !\e[0m"
    exit
fi

#remove router
for ((i = 0; i < ${#ip_list[@]}; i++)); do
    if [ "${ip_list[i]}" = "$router_ip" ]; then
        unset 'ip_list[i]'
    fi
done

for ip in "${ip_list[@]}";do
    echo "$ip"
done

echo -e "\n\e[1;93m[...] Identifying Open Ports And Classifying The Services:\e[0m"

port=""

svc_name=""

desc=""

#For loop to perform an nmap scan on all Discovered Hosts
for ip in "${ip_list[@]}";do
    readarray -t results < <(nmap -sC -sV -T5 "$ip" 2>/dev/null | grep -E "^[0-9]+\/")
    for res in "${results[@]}";do
        port=$(echo "$res" | awk '{print $1}' | awk -F '/' '{print $1}')
        svc_name=$(echo "$res" | awk '{print $3}')
        desc=$(echo "$res" | awk '{for (i=4; i<=NF; i++) printf "%s ", $i; printf "\n"}')
        classify_ports "$ip" "$port" "$svc_name" "$desc"
    done
done

# Print classified ports in a table-like format
echo -e "\n\e[1mWeb Ports:\e[0m"
print_table "Host | Port | Service Name | Description" "${web_ports[@]}"
echo -e "\n\e[1mDatabase Ports:\e[0m"
print_table "Host | Port | Service Name | Description" "${db_ports[@]}"
echo -e "\n\e[1mMail Ports:\e[0m"
print_table "Host | Port | Service Name | Description" "${mail_ports[@]}"
echo -e "\n\e[1mActive Directory Ports:\e[0m"
print_table "Host | Port | Service Name | Description" "${ad_ports[@]}"
echo -e "\n\e[1mOther Ports:\e[0m"
print_table "Host | Port | Service Name | Description" "${other_ports[@]}"

if [ ${#web_ports[@]} -lt 1 ]; then
    exit
fi

echo -e "\e[1;90m"
if ! prompt_user "Would you like to run a thorough scan of Discovered Web Apps ?"; then
    echo -e "\e[0m"
    exit
fi

echo -e "\e[0m\n\e[1;93m[...] Gathering Information About Discovered Web Applications:\e[0m\n"

#Function to identify the used technologie in discovered web apps (CMS, Framework, Solution)
identify_technologies() {
    local ip="$1"
    local port="$2"
    local cms=""
    local framework=""
    local solution=""

    whatweb_output=$(whatweb --color=never "$ip:$port")

    # Identify CMS
    if grep -q "WordPress" <<< "$whatweb_output"; then
        cms="WordPress"
    elif grep -q "Joomla" <<< "$whatweb_output"; then
        cms="Joomla"
    elif grep -q "Drupal" <<< "$whatweb_output"; then
        cms="Drupal"
    elif grep -q "Magento" <<< "$whatweb_output"; then
        cms="Magento"
    elif grep -q "PrestaShop" <<< "$whatweb_output"; then
        cms="PrestaShop"
    elif grep -q "TYPO3" <<< "$whatweb_output"; then
        cms="TYPO3"
    elif grep -q "Shopify" <<< "$whatweb_output"; then
        cms="Shopify"
    fi

    # Identify frameworks
    if grep -q "Laravel" <<< "$whatweb_output"; then
        framework="Laravel"
    elif grep -q "Symfony" <<< "$whatweb_output"; then
        framework="Symfony"
    elif grep -q "Django" <<< "$whatweb_output"; then
        framework="Django"
    elif grep -q "Ruby on Rails" <<< "$whatweb_output"; then
        framework="Ruby on Rails"
    elif grep -q "Express" <<< "$whatweb_output"; then
        framework="Express.js"
    elif grep -q "Angular" <<< "$whatweb_output"; then
        framework="Angular"
    elif grep -q "React" <<< "$whatweb_output"; then
        framework="React.js"
    elif grep -q "Vue.js" <<< "$whatweb_output"; then
        framework="Vue.js"
    elif grep -q "Ember.js" <<< "$whatweb_output"; then
        framework="Ember.js"
    elif grep -q "Meteor" <<< "$whatweb_output"; then
        framework="Meteor"
    elif grep -q "Flask" <<< "$whatweb_output"; then
        framework="Flask"
    elif grep -q "Spring" <<< "$whatweb_output"; then
        framework="Spring Framework"
    elif grep -q "ASP.NET" <<< "$whatweb_output"; then
        framework="ASP.NET"
    elif grep -q "Express" <<< "$whatweb_output"; then
        framework="Express.js"
    fi

    # Identify solutions
    if grep -q "Jenkins" <<< "$whatweb_output"; then
        solution="Jenkins"
    elif grep -q "Apache Tomcat" <<< "$whatweb_output"; then
        solution="Apache Tomcat"
    elif grep -q "GitLab" <<< "$whatweb_output"; then
        solution="GitLab"
    elif grep -q "Redmine" <<< "$whatweb_output"; then
        solution="Redmine"
    elif grep -q "Confluence" <<< "$whatweb_output"; then
        solution="Confluence"
    elif grep -q "SonarQube" <<< "$whatweb_output"; then
        solution="SonarQube"
    elif grep -q "Gitea" <<< "$whatweb_output"; then
        solution="Gitea"
    elif grep -q "Trac" <<< "$whatweb_output"; then
        solution="Trac"
    elif grep -q "Phabricator" <<< "$whatweb_output"; then
        solution="Phabricator"
    elif grep -q "MantisBT" <<< "$whatweb_output"; then
        solution="MantisBT"
    elif grep -q "Bugzilla" <<< "$whatweb_output"; then
        solution="Bugzilla"
    elif grep -q "Redmine" <<< "$whatweb_output"; then
        solution="Redmine"
    elif grep -q "Jira" <<< "$whatweb_output"; then
        solution="Jira"
    elif grep -q "Nagios" <<< "$whatweb_output"; then
        solution="Nagios"
    elif grep -q "OpenNMS" <<< "$whatweb_output"; then
        solution="OpenNMS"
    fi

    str="$ip | $port |"

    if [ -n "$cms" ]; then
        str+=" $cms (CMS)"
    fi
    if [ -n "$framework" ]; then
        str+=" $framework (FRAMEWORK)"
    fi
    if [ -n "$solution" ]; then
        str+=" $solution (SOLUTION)"
    fi
    if [ -z "$cms" ] && [ -z "$framework" ] && [ -z "$solution" ]; then
        str+=" (\e[1;31mUNKNOWN\e[0m)"
    fi

    web_technologies+=("$str")
}

for web_app in "${web_ports[@]}"; do
    app_ip=$(echo "$web_app" | awk -F '|' '{print $1}' | tr -d ' ')
    app_port=$(echo "$web_app" | awk -F '|' '{print $2}' | tr -d ' ')
    identify_technologies "$app_ip" "$app_port"
done

print_table "Host | Port | Technology" "${web_technologies[@]}"

output_dir="scans_output"

mkdir -p "$output_dir"

for web_tech in "${web_technologies[@]}"; do
    tech_ip=$(echo "$web_tech" | awk -F '|' '{print $1}' | tr -d ' ')
    tech_port=$(echo "$web_tech" | awk -F '|' '{print $2}' | tr -d ' ')
    
    echo -e "\n\e[1;34m[ + ] Running Web Scan On $tech_ip:$tech_port\e[0m"
    if [[ $web_tech == *"(CMS)"* ]]; then
        cms_info=$(cmseek -u "$tech_ip:$tech_port" --follow-redirect --light-scan 2>/dev/null \
        | sed 's/\x1B\[[0-9;]*[JKmsu]//g')
        cms_version=$(echo "$cms_info" | awk '/Version:/{print $NF}')
        cms_name=$(echo "$cms_info" | awk '/CMS:/{print $NF}')
        echo -e "\n\e[1mCMS Name:\e[0m $cms_name"
        echo -e "\n\e[1mCMS Version:\e[0m $cms_version"

        if [ ! -z "$cms_version" ]; then
            echo -e "\n\e[1mPossible Vulnerabilities:\e[0m"
            searchsploit "$cms_name $cms_version"
        fi
        
        # Run specific CMS scans and write them to files
        output_file="$output_dir/$tech_ip:$tech_port-$cms_name-scan_output.txt"
        if [[ $cms_name == *"WordPress"* ]]; then
            echo -e "\nRunning WPScan for WordPress CMS. Output will be saved to:\e[1;36m $output_file\e[0m"
            (wpscan --url "http://$tech_ip:$tech_port" 2>/dev/null > "$output_file") &
        elif [[ $cms_name == *"Joomla"* ]]; then
            echo -e "\nRunning JoomScan for Joomla CMS. Output will be saved to:\e[1;36m $output_file\e[0m"
            (joomscan --url "$tech_ip:$tech_port" 2>/dev/null > "$output_file") &
        elif [[ $cms_name == *"Drupal"* ]]; then
            echo -e "\nRunning Droopescan for Drupal CMS. Output will be saved to:\e[1;36m $output_file\e[0m"
            (droopescan scan drupal -u "$tech_ip:$tech_port" 2>/dev/null > "$output_file") &
        else
            echo -e "\nRunning CMSeek scan for $cms_name CMS. Output will be saved to:\e[1;36m $output_file\e[0m"
            (cmseek -u "$web_ip:$web_port" --follow-redirect 2>/dev/null > "$output_file") &
        fi
    else
        # Run a general scan on Non-CMS Apps.
        nmap_output_file="$output_dir/$tech_ip:$tech_port-nmap-scan_output.txt"
        nikto_output_file="$output_dir/$tech_ip:$tech_port-nikto-scan_output.txt"
        echo -e "\nRunning Web Nmap scan for $tech_ip:$tech_port. Output will be saved to:\e[1;36m $nmap_output_file\e[0m"
        echo -e "\nRunning Nikto scan for $tech_ip:$tech_port. Output will be saved to:\e[1;36m $nikto_output_file\e[0m"
        (nmap -p$tech_port -T5 --script=vuln $tech_ip 2>/dev/null > "$nmap_output_file") &
        (timeout 5m nikto -h "$tech_ip:$tech_port" -followredirects 2>/dev/null > "$nikto_output_file") &
    fi
done

wait

echo -e "\n\e[1;32mScans completed. Results saved in: $output_dir\e[0m"