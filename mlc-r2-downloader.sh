#!/bin/bash

DEBUG_INFO_THEN_EXIT=0
CLOUDFLARE_ACCESS_SUBDOMAIN="mlcommons"
CLOUDFLARE_ACCESS_LOGOUT_URL="https://${CLOUDFLARE_ACCESS_SUBDOMAIN}.cloudflareaccess.com/cdn-cgi/access/logout"
USAGE_STRING="USAGE: bash [-d download-path] [-x] [-h] <URL>"

# Function to show help
show_help() {
    cat << EOF
MLCommons R2 Downloader - Download files from Cloudflare R2 buckets protected by Cloudflare Access

$USAGE_STRING

ARGUMENTS:
    <URL>                   URL to the dataset metadata file (*.url) on the R2 bucket
                           This file contains the base URL for the dataset files

OPTIONS:
    -d download-path       Directory where files will be downloaded
                           Defaults to the dataset name from the URL if not specified
    -x                     Debug mode - shows parsed URL components and configuration then exits
    -h                     Show this help message and exit

EXAMPLES:
    # Download to current directory using dataset name
    bash https://inference-private.mlcommons-storage.org/metadata/llama3.url

    # Download to specific directory
    bash -d ./my-dataset https://inference-private.mlcommons-storage.org/metadata/llama3.url

    # Debug mode to see how URL is parsed
    bash -x https://inference-private.mlcommons-storage.org/metadata/llama3.url

REQUIREMENTS:
    - cloudflared (will be auto-installed if missing)  
    - wget
    - mktemp
    - md5sum/gmd5sum (for hash verification)

AUTHENTICATION:
    This script uses Cloudflare Access for authentication. On first run, it will:
    1. Open a browser window for you to authenticate
    2. Cache authentication tokens for future use
    3. Automatically re-authenticate when tokens expire

EOF
}

# Parse command line options  
while getopts "d:xh" opt; do
    case $opt in
        d)
            download_dir="$OPTARG"
            ;;
        x)  # Use -x for debug mode
            DEBUG_INFO_THEN_EXIT=1
            ;;
        h)  # Show help
            show_help
            exit 0
            ;;
        \?)
            echo "Invalid option: -$OPTARG" >&2
            echo "$USAGE_STRING" >&2
            echo "Use -h for help" >&2
            exit 1
            ;;
    esac
done

# Check for mandatory non-named argument (URL)
if [ $# -lt 1 ]; then
    echo "Error: A download URL is required as a mandatory argument." >&2
    echo "$USAGE_STRING" >&2
    echo "Use -h for help and examples" >&2
    exit 1
fi

# Shift processed options so that only positional arguments remain
shift $((OPTIND - 1))

url_dataset_info=$1

# Global cleanup function
cleanup() {
    # Clean up URLs file if it exists
    [[ -n "$urls_file" && -f "$urls_file" ]] && rm -f "$urls_file"
    
    # Clean up install temp directory if it was created
    [[ -n "$tmp_dir" && -d "$tmp_dir" ]] && rm -rf "$tmp_dir"
}

# Set the cleanup as a trap to run on exit regardless of success or failure
trap cleanup EXIT

# Detect OS
case "$OSTYPE" in
    "darwin"*)
        OS="macos"
        ;;
    "linux-gnu"*)
        if uname -a | grep -qi "microsoft"; then
            OS="wsl"
        else
            OS="linux"
        fi
        ;;
    "cygwin"*)
        # Cygwin on Windows
        OS="cygwin"
        ;;
    *)
        # Unknown OS
        OS="unknown"
        ;;
esac

# Function to install cloudflared
install_cloudflared() {
    echo "Installing cloudflared..."
    
    # Create temporary directory
    tmp_dir=$(mktemp -d 2>/dev/null || mktemp -d -t 'cloudflared-install.XXXXXXXXXX')
    
    cd "$tmp_dir" || { echo "Error: Failed to create temporary directory" >&2; exit 1; }
    
    # Use existing OS detection
    case "$OS" in
        "macos")
            case "$(uname -m)" in
                x86_64)
                    ARCH="amd64"
                    ;;
                arm64)
                    ARCH="arm64"
                    ;;
                *)
                    echo "Error: Unsupported architecture" >&2
                    exit 1
                    ;;
            esac
            OS_NAME="darwin"
            BINARY_NAME="cloudflared"
            INSTALL_DIR="/usr/local/bin"
            FILE_EXT=".tgz"  # macOS uses .tgz
            ARCHIVE_NAME="cloudflared.tgz"  # Separate name for the archive
            ;;
        "linux"|"wsl")
            case "$(uname -m)" in
                x86_64)
                    ARCH="amd64"
                    ;;
                aarch64)
                    ARCH="arm64"
                    ;;
                armv7l)
                    ARCH="arm"
                    ;;
                *)
                    echo "Error: Unsupported architecture" >&2
                    exit 1
                    ;;
            esac
            OS_NAME="linux"
            BINARY_NAME="cloudflared"
            INSTALL_DIR="/usr/local/bin"
            FILE_EXT=""  # Linux uses no extension
            ARCHIVE_NAME="$BINARY_NAME"  # Same as binary name for Linux
            ;;
        "cygwin")
            case "$(uname -m)" in
                x86_64)
                    ARCH="amd64"
                    ;;
                i686)
                    ARCH="386"
                    ;;
                *)
                    echo "Error: Unsupported architecture" >&2
                    exit 1
                    ;;
            esac
            OS_NAME="windows"
            BINARY_NAME="cloudflared.exe"
            INSTALL_DIR="$HOME/.local/bin"
            FILE_EXT=".exe"  # Windows uses .exe
            ARCHIVE_NAME="$BINARY_NAME"  # Same as binary name for Windows
            ;;
        *)
            echo "Error: Unsupported operating system" >&2
            exit 1
            ;;
    esac
    
    # Download cloudflared
    echo "Downloading cloudflared..."
    curl -L "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-${OS_NAME}-${ARCH}${FILE_EXT}" -o "$ARCHIVE_NAME" || { 
        echo "Error: Failed to download cloudflared. You may need to install it manually." >&2
        exit 1
    }
    
    # For macOS, we need to extract the .tgz file
    if [[ "$OS" == "macos" ]]; then
        tar xzf "$ARCHIVE_NAME" || {
            echo "Error: Failed to extract cloudflared archive" >&2
            exit 1
        }
        # The binary is inside the .tgz, so we need to move it
        mv cloudflared "$BINARY_NAME" || {
            echo "Error: Failed to move extracted cloudflared binary" >&2
            exit 1
        }
    fi
    
    # Verify the binary exists and has content
    if [ ! -s "$BINARY_NAME" ]; then
        echo "Error: Downloaded cloudflared binary is empty or missing. You may need to install it manually." >&2
        exit 1
    fi
    
    # Make it executable (only on Unix-like systems)
    if [[ "$OS" != "cygwin" ]]; then
        chmod +x "$BINARY_NAME"
    fi
    
    # Create install directory if it doesn't exist (only for Cygwin)
    if [[ "$OS" == "cygwin" ]]; then
        mkdir -p "$INSTALL_DIR" || { echo "Error: Failed to create install directory" >&2; exit 1; }
    elif [ ! -d "$INSTALL_DIR" ]; then
        echo "Error: Install directory $INSTALL_DIR does not exist" >&2
        echo "This may indicate a system configuration issue" >&2
        exit 1
    fi
    
    # Move the binary (with or without sudo based on OS)
    if [[ "$OS" == "cygwin" ]]; then
        mv "$BINARY_NAME" "${INSTALL_DIR}/$BINARY_NAME" || {
            echo "Error: Failed to install cloudflared" >&2
            exit 1
        }
    else
        sudo mv "$BINARY_NAME" "${INSTALL_DIR}/$BINARY_NAME" || {
            echo "Error: Failed to install cloudflared. Try running with sudo." >&2
            exit 1
        }
    fi
    
    # Return to original directory
    cd - > /dev/null || { echo "Error: Failed to return to original directory during cloudflared installation" >&2; exit 1; }
    
    echo "cloudflared installed successfully to ${INSTALL_DIR}/$BINARY_NAME"
    
    # After successful installation on Cygwin
    if [[ "$OS" == "cygwin" ]]; then
        # Check if the install directory is in PATH
        if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
            echo "Adding $INSTALL_DIR to PATH..."
            # Add to PATH for current session
            export PATH="$INSTALL_DIR:$PATH"
            
            # Add to PATH permanently
            local shell_rc
            # Check for .bash_profile first (Cygwin default)
            if [ -f "$HOME/.bash_profile" ]; then
                shell_rc="$HOME/.bash_profile"
            # Fall back to .bashrc if .bash_profile doesn't exist
            elif [ -f "$HOME/.bashrc" ]; then
                shell_rc="$HOME/.bashrc"
            else
                # If neither exists, create .bash_profile (Cygwin default)
                shell_rc="$HOME/.bash_profile"
            fi
            
            # Add PATH export if it's not already there
            if ! grep -q "^export PATH=\"$INSTALL_DIR:\$PATH\"" "$shell_rc" 2>/dev/null; then
                echo "export PATH=\"$INSTALL_DIR:\$PATH\"" >> "$shell_rc"
            fi
            
            # Source the file to update PATH in current session
            if [ -f "$shell_rc" ] && [ -r "$shell_rc" ]; then
                # shellcheck disable=SC1090
                source "$shell_rc" 2>/dev/null || true
            fi
        fi
        
        # Verify cloudflared is accessible
        if ! command -v cloudflared &> /dev/null; then
            echo "Warning: cloudflared was installed but is not accessible in PATH" >&2
            echo "You may need to restart your terminal then re-run this script" >&2
        fi
    fi
}

# Function to check if a command exists
check_dependency() {
    if ! command -v "$1" &> /dev/null; then
        echo "Error: Required command '$1' not found." >&2
        echo "Please install $1 before running this script." >&2
        echo "Use -h for help and installation requirements" >&2
        exit 1
    fi
}

# Check for required dependencies
check_dependency "mktemp"
check_dependency "wget"

# Check for cloudflared & install if not found or if version is too old
echo "Checking dependencies..."
if ! command -v cloudflared &> /dev/null; then
    echo "cloudflared not found. Attempting to install..."
    install_cloudflared
else
    # Check cloudflared version
    version_info=$(cloudflared --version 2>&1)
    if [[ $version_info =~ ([0-9]+\.[0-9]+\.[0-9]+) ]]; then
        version="${BASH_REMATCH[1]}"
        # Get current date and version date
        current_date=$(date +%s)
        date_string=$(echo "$version_info" | grep -o '[0-9]\{4\}-[0-9]\{2\}-[0-9]\{2\}')

        if [ -n "$date_string" ]; then
            case "$OS" in
                "macos")
                    # macOS date requires -j and -f flags
                    version_date=$(date -j -f "%Y-%m-%d" "$date_string" +%s 2>/dev/null)
                    ;;
                *)
                    # Linux/WSL/Windows use -d flag
                    version_date=$(date -d "$date_string" +%s 2>/dev/null)
                    ;;
            esac
        fi
        
        if [ -n "$version_date" ]; then
            # Calculate difference in days
            days_diff=$(( (current_date - version_date) / 86400 ))
            
            if [ $days_diff -gt 365 ]; then
                echo "Your cloudflared version ($version) is more than one year old"
                echo "Cloudflare supports versions within one year of the most recent release"
                echo "Updating cloudflared..."
                install_cloudflared
            fi
        fi
    fi
fi

# Set hash checker command based on OS
case "$OS" in
    "macos")
        # On macOS, use md5sum or gmd5sum
        if command -v md5sum &> /dev/null; then
            HASH_CHECKER="md5sum"
        elif command -v gmd5sum &> /dev/null; then
            HASH_CHECKER="gmd5sum"
        else
            echo "Error: Neither md5sum nor gmd5sum found on macOS." >&2
            echo "Please install one of the following:" >&2
            echo "  - md5sum (from md5sha1sum): brew install md5sha1sum / sudo port install md5sha1sum" >&2
            echo "  - gmd5sum (from coreutils): brew install coreutils / sudo port install coreutils" >&2
            echo "Then re-run this script." >&2
            exit 1
        fi
        ;;
    "linux"|"wsl"|"cygwin")
        HASH_CHECKER="md5sum"
        ;;
    *)
        HASH_CHECKER="md5sum"  # Default to md5sum
        ;;
esac

# Check if hash checker is available
check_dependency "$HASH_CHECKER"

# Set browser opener command based on OS
case "$OS" in
    "macos")
        BROWSER_OPENER="open"
        ;;
    "wsl")
        BROWSER_OPENER="explorer.exe"
        ;;
    "linux")
        BROWSER_OPENER="xdg-open"
        ;;
    "cygwin")
        BROWSER_OPENER="cygstart"
        ;;
    *)
        BROWSER_OPENER=""
        ;;
esac

# Check if browser opener is available
if [ -n "$BROWSER_OPENER" ]; then
    if ! command -v "$BROWSER_OPENER" &> /dev/null; then
        BROWSER_OPENER=""
    fi
fi

echo "Logging in to Cloudflare Access at ${url_dataset_info}..."

# Log in to Cloudflare Access, showing full output except removing the token block.
# NOTE: the "sed" command omits the token from the console output
cloudflared access login "${url_dataset_info}" 2>&1 | sed '/Successfully fetched your token:/ { N; N; d; }' || { 
    echo "Error: Failed to authenticate with Cloudflare Access." >&2
    echo "Please check your network connection and try again." >&2
    exit 1
}

echo "Authentication successful!"

# Function to pluralize a word based on count
pluralize() {
    local count=$1
    local word=$2
    if [ "$count" -eq 1 ]; then
        echo "$count $word"
    else
        echo "$count ${word}s"
    fi
}

# Function to format time units
format_time_units() {
    local days=$1
    local hours=$2
    local minutes=$3
    
    if [ "$days" -gt 0 ]; then
        echo "$(pluralize "$days" "day"), $(pluralize "$hours" "hour")"
    elif [ "$hours" -gt 0 ]; then
        echo "$(pluralize "$hours" "hour"), $(pluralize "$minutes" "minute")"
    else
        echo "$(pluralize "$minutes" "minute")"
    fi
}

# Function to get JWT expiration with maximum compatibility
get_jwt_expiration() {
    local token="$1"
    local base64_flag
    
    # Detect base64 implementation
    if echo "dGVzdA==" | base64 -d >/dev/null 2>&1; then
        base64_flag="-d"  # Linux/GNU base64
    else
        base64_flag="-D"  # macOS base64
    fi
    
    # Extract payload (second part)
    local payload_b64
    payload_b64=$(echo "$token" | cut -d'.' -f2 | tr '_-' '/+')
    
    # Add padding using awk (more universal than printf modulo)
    payload_b64=$(echo "$payload_b64" | awk '{while(length%4)$0=$0"="; print}')
    
    # Decode and extract expiration
    local exp
    exp=$(echo "$payload_b64" | base64 $base64_flag 2>/dev/null | \
                sed -n 's/.*"exp":\([0-9]*\).*/\1/p')
    
    echo "$exp"
}

# Function to check token expiration
check_token_expiration() {
    local token=$1
    local exp_time
    
    # Get expiration time using get_jwt_expiration function
    exp_time=$(get_jwt_expiration "$token")
    
    if [ -z "$exp_time" ]; then
        echo "Could not decode token expiration time" >&2
        return
    fi
    
    # Get current time in seconds since epoch
    current_time=$(date +%s)
    
    # Calculate time until expiration
    time_until_expiry=$((exp_time - current_time))
    
    # Convert to human-readable format
    days=$((time_until_expiry / 86400))
    hours=$(((time_until_expiry % 86400) / 3600))
    minutes=$(((time_until_expiry % 3600) / 60))
    
    echo "Cloudflare Access token will expire in $(format_time_units $days $hours $minutes)"
    
    # If fewer than 3 days until expiry, re-authenticate
    if [ $time_until_expiry -lt 259200 ]; then
        echo "Warning: Cloudflare Access token will expire in less than 3 days, which could cause the download to fail" >&2
        echo -e "Re-authenticating...\n"
        echo "A browser window should have opened at the following URL to logout:" >&2
        echo "${CLOUDFLARE_ACCESS_LOGOUT_URL}" >&2
        echo "If the browser failed to open, please visit the URL above directly in your browser." >&2        
        # Try to open browser if we have a browser opener command
        if [ -n "$BROWSER_OPENER" ]; then
            $BROWSER_OPENER "${CLOUDFLARE_ACCESS_LOGOUT_URL}" 2>/dev/null || true
        fi
        
        echo -e "\nMake sure to visit the logout URL in the same browser in which you previously logged in."
        echo -e "When you visit the logout URL, the page should say 'Success! You successfully logged out.'\n"
        read -rp "After logging out, press Enter to continue with re-authentication..."
        
        # Token needs to be invalidated before re-authentication can be performed
        echo "Confirming token is invalidated..."
        local poll_count=0
        local max_polls=20
        local poll_interval=15
        local max_minutes=$((max_polls * poll_interval / 60))  # Calculate maximum minutes of polling
        
        while [ $poll_count -lt $max_polls ]; do
            poll_count=$((poll_count + 1))
            echo "Checking token status (attempt $poll_count of $max_polls)..."
            
            # Test if token is still valid by trying to access the protected resource
            local http_code
            http_code=$(curl -H "cf-access-token: $TOKEN" --max-time 60 --retry 3 --retry-connrefused --silent --write-out "%{http_code}" --output /dev/null "$url_dataset_info" 2>/dev/null)
            
            if [ "$http_code" = "200" ]; then
                if [ $poll_count -lt $max_polls ]; then
                    echo "Token still valid, waiting $poll_interval seconds before next check..."
                    sleep $poll_interval
                else
                    echo "Token still valid after final attempt."
                fi
            elif [ "$http_code" = "302" ]; then
                echo "Token invalidated! (HTTP $http_code - redirected to login) Starting authentication..."
                break
            else
                echo "Unexpected HTTP response: $http_code - this may indicate a service issue" >&2
                if [ $poll_count -lt $max_polls ]; then
                    echo "Waiting $poll_interval seconds before retrying..."
                    sleep $poll_interval
                else
                    echo "Proceeding with authentication attempt anyway..."
                    break
                fi
            fi
        done
        
        if [ $poll_count -ge $max_polls ]; then
            echo "Warning: Token may still be valid after $max_minutes minutes of waiting" >&2
            echo "Try logging out again, checking for network issues, and re-running the script." >&2
            exit 1
        fi
        
        # Run authentication since token should now be invalid
        echo "Logging in to Cloudflare Access at ${url_dataset_info}..."
        cloudflared access login "${url_dataset_info}" 2>&1 | sed '/Successfully fetched your token:/ { N; N; d; }' || { 
            echo "Error: Failed to authenticate with Cloudflare Access" >&2 
            exit 1 
        }
        
        # Get new token
        TOKEN=`cloudflared access token --app="$url_dataset_info"` || { echo "Error: Failed to get access token" >&2; exit 1; }
        
        # Check the new token
        check_token_expiration "$TOKEN"
    fi
}

# Download the access token after authentication
TOKEN=`cloudflared access token --app="$url_dataset_info"` || { 
    echo "Error: Failed to get access token." >&2
    echo "Please re-run the script to re-authenticate." >&2
    exit 1
}

echo "Checking token expiration time..."
check_token_expiration "$TOKEN"

# Retrieve the base path of the URL
# Regexp taken from Perplexity.ai, referencing StackOverflow
if [[ ! $url_dataset_info =~ ^(([^:/?#]+):)?(//([^/?#]*))?([^?#]*)(\?([^#]*))?(#(.*))? ]]; then
    echo "Error: Could not parse the download URL. Please check that it was entered correctly." >&2
    echo "Expected format: https://domain.com/path/to/dataset.url" >&2
    echo "Received: $url_dataset_info" >&2
    exit 1
fi

protocol=${BASH_REMATCH[2]}
host=${BASH_REMATCH[4]}
path=${BASH_REMATCH[5]}
query=${BASH_REMATCH[7]}
fragment=${BASH_REMATCH[9]}

# Validate URL components
if [[ -z "$protocol" ]]; then
    echo "Error: URL missing protocol (e.g., https://)" >&2
    echo "Received: $url_dataset_info" >&2
    exit 1
fi

if [[ -z "$host" ]]; then
    echo "Error: URL missing hostname" >&2
    echo "Received: $url_dataset_info" >&2
    exit 1
fi

if [[ -z "$path" ]]; then
    echo "Error: URL missing file path" >&2
    echo "Expected format: https://domain.com/path/to/dataset.url" >&2
    echo "Received: $url_dataset_info" >&2
    exit 1
fi

# Check if the URL ends with .url
if [[ ! "$path" =~ \.url$ ]]; then
    echo "Error: URL path does not end with .url extension" >&2
    echo "This script is designed to work with dataset metadata files (.url)" >&2
    echo "Expected format: https://domain.com/path/to/dataset.url" >&2
    echo "Received: $url_dataset_info" >&2
    echo "Path component: $path" >&2
    exit 1
fi

# Determine dataset name from the URL filename, ex: llama3.url -> llama3
dataset_name=`basename -s .url "$path"`

# Validate dataset name
if [[ -z "$dataset_name" || "$dataset_name" == "." ]]; then
    echo "Error: Could not determine dataset name from URL path" >&2
    echo "URL path: $path" >&2
    echo "Expected format: https://domain.com/path/to/dataset.url" >&2
    exit 1
fi

# Define the hashes file name using the dataset name
HASHES_FILE_NAME="$dataset_name.md5"

# Same as the directory where the .url is
hashes_path=`dirname "$path" | cut -c 2-`

# Avoid creating a download URL with "//" after the hostname
if [[ ! $hashes_path == "" ]]; then
  hashes_url="$protocol://$host/$hashes_path/$HASHES_FILE_NAME"
else
  hashes_url="$protocol://$host/$HASHES_FILE_NAME"
fi

echo "Downloading dataset information..."

# Download the actual location of the dataset
dataset_base_url=`wget --header="cf-access-token: $TOKEN" --max-redirect=0 --retry-on-http-error=500,502,503 --retry-connrefused --timeout=60 -qO- "$url_dataset_info"` || { echo "Error: Failed to download dataset info from $url_dataset_info. Check URL and network connection." >&2; exit 1; }

# Calculate the dataset_base_path by substracting the length of protocol+host from the dataset URL
dataset_base_path="$protocol://$host/"
dataset_base_path=$( echo "$dataset_base_url" | cut -c ${#dataset_base_path}- | cut -c 2- )

# Determine the number of cut_dirs by counting individual elements in dataset_base_path and adding 1 to cut off the 'dataset' directory (ex: abc/def -> 1)
cut_dirs=$(( $( echo "${dataset_base_path//\//$'\n'}" | grep -v '^$' | wc -l ) ))

# Determine download directory
if [[ -z "$download_dir" ]]; then
    # If no download directory specified, use the dataset name from the URL
    if [[ ! $dataset_base_url =~ (.*)/(.*)$ ]]; then
        echo "Error: couldn't parse dataset download URL, obtained from $url_dataset_info"
        exit 1
    fi
    download_dir=${BASH_REMATCH[2]}
fi

echo "Preparing download..."
echo "Dataset: $dataset_name"
echo "Download directory: $download_dir"

if [[ $DEBUG_INFO_THEN_EXIT == 1 ]]; then

  echo "DEBUG INFO START"

  echo -e "\nSystem info\n"

  echo "OS: $OS"
  echo "HASH_CHECKER: $HASH_CHECKER"
  echo "BROWSER_OPENER: $BROWSER_OPENER"

  echo -e "\nInitial request\n"

  echo "url_dataset_info: $url_dataset_info"
  echo "protocol: $protocol"
  echo "host: $host"
  echo "path: $path"
  echo "query: $query"
  echo "fragment: $fragment"

  echo -e "\nDataset info URL and hashes file\n"

  echo "dataset_name: $dataset_name"
  echo "hashes_path: $hashes_path"
  echo "hashes_url: $hashes_url"

  echo -e "\nDataset and download info\n"

  echo "dataset_base_url: $dataset_base_url"
  echo "dataset_base_path: $dataset_base_path"
  echo "cut_dirs: $cut_dirs"
  echo "download_dir: $download_dir"

  echo -e "\nDEBUG INFO END\n"

  exit 100
fi

# ========= ACTUAL START OF DOWNLOAD

echo "Creating download directory: $download_dir"

# Create the download directory if it doesn't exist
mkdir -p "$download_dir" || { echo "Error: Failed to create download directory '$download_dir'" >&2; exit 1; }

# Create a temporary file for keeping the file list.
# We use a file instead of a shell variable as the list can be large.
urls_file=`mktemp`	# Generated URL list for wget

echo "Downloading checksums file..."

# Download the hashes file  
wget --header="cf-access-token: $TOKEN" --max-redirect=0 --retry-on-http-error=500,502,503 --retry-connrefused --timeout=60 -nc -q -P "$download_dir" "$hashes_url" || { echo "Error: Failed to download checksums file from $hashes_url." >&2; exit 1; }

echo "Preparing file list for download..."

# Take the hashes+files list and convert it into a URL list for wget.
# The first sed command strips the hash, the second one strips an optional leading './'.
sed 's/^[a-f0-9]\{32\}[[:space:]]*//' "$download_dir/$HASHES_FILE_NAME" | sed 's,^\./,,' > "$urls_file" || { echo "Error: Failed to create URL list from checksums file" >&2; exit 1; }

echo "Starting download of dataset files..."

# Main download command. Use -P to specify the download directory. Mind the trailing "/" after "dataset_base_url; without this wget would "eat" 1 hashes_path
wget --header="cf-access-token: $TOKEN" --input-file="$urls_file" --continue -nH -x --cut-dirs="$cut_dirs" -B "$dataset_base_url/" -P "$download_dir" --progress=bar:force --max-redirect=0 --retry-on-http-error=500,502,503 --retry-connrefused --timeout=60 || { echo "Error: Download failed. Re-run the script to resume the download." >&2; exit 1; }

echo "Download completed successfully!"

# Hash-check all files
echo "Verifying file integrity with MD5 checksums..."

# Go into the download directory and run md5sum
old_wd=`pwd`

cd "$download_dir" || { echo "Error: Failed to change to download directory" >&2; exit 1; }

$HASH_CHECKER -c "$HASHES_FILE_NAME" || { echo "Error: Hash verification failed" >&2; exit 1; }

cd "$old_wd" || { echo "Error: Failed to return to original directory" >&2; exit 1; }

echo "Checksum verification completed successfully!"
echo "All files have been downloaded and verified in: $download_dir"
