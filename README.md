# Phishi_Detector
This Python-based Phishing Detector scans emails and URLs for threats. It checks sender reputation, analyzes content for suspicious keywords and HTML tricks, inspects attachments, and leverages threat intelligence services to identify potential phishing.
# Phishi Detector

## Features

* Analyzes email headers for authentication status (SPF, DKIM, DMARC) and alignment.
* Checks sender domain and IP reputation using WHOIS, VirusTotal, and AbuseIPDB.
* Scans URLs found within email bodies against threat intelligence services like VirusTotal, Google Safe Browsing, and IPQS.
* Performs lexical analysis of URLs for suspicious patterns (e.g., length, special characters, keywords, typosquatting).
* Analyzes email body content (text and HTML) for phishing keywords, suspicious HTML forms, and obfuscation techniques.
* Inspects email attachments for potentially risky file types and extensions.
* Provides an overall phishing score and a qualitative verdict.

## Prerequisites

* Python 3.7+
* Required Python libraries (see `requirements.txt` or install manually):
    * `requests`
    * `beautifulsoup4`
    * `dnspython`
    * `python-whois`
    * `tabulate`
    * `html5lib`

## Setup

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/YOUR_USERNAME/YOUR_REPOSITORY_NAME.git](https://github.com/YOUR_USERNAME/YOUR_REPOSITORY_NAME.git)
    cd YOUR_REPOSITORY_NAME
    ```

2.  **Create a virtual environment (recommended):**
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows: venv\Scripts\activate
    ```

3.  **Install dependencies:**
    You can create a `requirements.txt` file by running `pip freeze > requirements.txt` in your activated virtual environment after installing the packages manually for the first time. Then, others (or you in a new environment) can install using:
    ```bash
    pip install -r requirements.txt
    ```
    Or install manually:
    ```bash
    pip install requests beautifulsoup4 dnspython python-whois tabulate html5lib
    ```

4.  **API Key Configuration (CRITICAL):**
    This script requires API keys for full functionality with external services. **DO NOT hardcode API keys directly in the `Phishi_Detector_Project.py` script.**
    You MUST configure them as environment variables:

    * `VIRUSTOTAL_API_KEY`: Your API key for VirusTotal.
    * `ABUSEIPDB_API_KEY`: Your API key for AbuseIPDB.
    * `GOOGLE_SAFE_BROWSING_API_KEY`: Your API key for Google Safe Browsing.
    * `IPQS_API_KEY`: Your API key for IPQualityScore.

    **Setting Environment Variables:**
    * **Linux/macOS (bash/zsh):**
        ```bash
        export VIRUSTOTAL_API_KEY="your_actual_virustotal_key"
        # Add to your shell profile (e.g., .bashrc, .zshrc) for persistence
        ```
    * **Windows (Command Prompt):**
        ```cmd
        set VIRUSTOTAL_API_KEY="your_actual_virustotal_key"
        # For persistence, set them through System Properties -> Environment Variables
        ```
    * **Windows (PowerShell):**
        ```powershell
        $Env:VIRUSTOTAL_API_KEY="your_actual_virustotal_key"
        # For persistence, set them through System Properties or PowerShell profile
        ```
    The script will attempt to load these keys. If any are missing, corresponding checks may be skipped or fail.

## Usage

Navigate to the project directory in your terminal and run the script:

```bash
python Phishi_Detector_Project.py
