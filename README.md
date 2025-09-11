# Repo Contents:

* [MLCommons R2 Downloader](#mlcommons-r2-downloader)
* [Cygwin + Wget Installer](#cygwin--wget-installer)

## MLCommons R2 Downloader

### How It Works

The MLCommons R2 Downloader is a bash script that downloads datasets from R2 buckets and verifies their integrity. In the case of buckets protected by Cloudflare Access, it automatically handles authentication. Depending on the need for authentication, it will:

- Open a browser window to a Cloudflare Access page for authentication on first run
- Cache authentication tokens for future use
- Automatically re-authenticate when tokens approach or reach expiration
- Download files with wget and verify files with MD5 hashsums pulled from the R2 bucket

### Platform Support

- **Linux & macOS:** Works natively with built-in bash
- **Windows with WSL:** Use Windows Subsystem for Linux (recommended)
- **Windows with Cygwin:** For users who don't have WSL and want a lightweight bash environment, you can use our cygwin+wget installer utility.

### Requirements

If authentication in required, the script automatically installs `cloudflared` but you may need to install other dependencies (the script will tell you if dependencies are missing).

- `cloudflared` - Will be auto-installed if missing and needed
- `wget` - For downloading files
- `mktemp` - For temporary file handling
- `md5sum/gmd5sum` - For hash verification

### Usage

The basic command syntax is:

```
bash <(curl -s https://raw.githubusercontent.com/mlcommons/r2-downloader/refs/heads/main/mlc-r2-downloader.sh) [options] <URL>
```

Where `<URL>` is the path to a dataset metadata file (*.uri) in a R2 bucket. This metadata file will point the downloader to the appropriate dataset files.

_The metadata files are maintained in the [R2 Infra repo](https://github.com/mlcommons/r2-infra)_

### Command Options

The downloader supports several options:

- `-d <download-path>` - Specify download directory (defaults to dataset name)
- `-h` - Show help message
- `-s` - Use service account credentials for authentication (requires CF_ACCESS_CLIENT_ID and CF_ACCESS_CLIENT_SECRET environment variables)
- `-t` - Testing mode for running automated tests of the script with service account credentials
- `-x` - Debug mode to see parsed URL components and detected system info

**Note:** All options must be specified *before* the `<URL>` argument.

## Cygwin + Wget Installer

If you're on Windows and don't have WSL, you can use our cygwin+wget installer:

1. **Download:** Get the installer from GitHub [here](https://github.com/mlcommons/r2-downloader/blob/main/cygwin-wget-installer.bat).
2. **Install:** Double-click the downloaded file to run it. The installer is PowerShell wrapped in batch, which allows it to run natively on Windows. It will automatically install Cygwin and `wget`
3. **Navigate:** When the installer finishes, it should launch the Cygwin terminal. To navigate to your Windows folders, use:
   - `cd /cygdrive/c/Users/YourUsername/Downloads` (for Downloads folder)
   - `cd /cygdrive/<drive-letter>/path/to/your/desired/folder` (for any other location)
4. **Run the downloader:** Once you're in your desired directory, run a downloader command.
