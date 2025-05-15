# Phishi_Detector 🎣
![Gemini_Generated_Image_canou4canou4cano](https://github.com/user-attachments/assets/51e99fad-1961-4e6c-b5eb-d4b3523363e2)


**A Python-based tool for scanning emails and URLs to detect potential phishing threats.**

Phishi_Detector analyzes various components of emails and URLs, including sender reputation, content, attachments, and leverages multiple threat intelligence services to provide a comprehensive phishing assessment.


## 🌟 Key Features

* **Email Header Analysis:**
    * Verifies SPF, DKIM, and DMARC authentication statuses.
    * Checks for header alignment to detect spoofing.
* **Sender Reputation:**
    * Utilizes WHOIS lookups for domain registration details.
    * Integrates with VirusTotal and AbuseIPDB for domain and IP reputation.
* **URL Scanning & Analysis:**
    * Scans URLs found in email bodies using VirusTotal, Google Safe Browse, and IPQualityScore (IPQS).
    * Performs lexical analysis for suspicious patterns (e.g., excessive length, special characters, phishing-related keywords, typosquatting).
* **Content Inspection:**
    * Analyzes email body (text and HTML) for common phishing keywords and phrases.
    * Detects suspicious HTML forms and obfuscation techniques (e.g., hidden elements, JavaScript tricks).
* **Attachment Checking:**
    * Inspects email attachments for potentially risky file types and common malicious extensions.
* **Scoring & Verdict:**
    * Provides an overall phishing probability score.
    * Delivers a qualitative verdict (e.g., Safe, Suspicious, Phishing).

## ⚙️ How It Works (High-Level)

1.  **Input:** Takes an email file (e.g., `.eml` format) or a direct URL as input.
2.  **Extraction & Parsing:** Extracts relevant information: headers, body, attachments from emails; components from URLs.
3.  **Analysis Modules:** Each feature (header check, URL scan, content analysis, etc.) processes the extracted data.
4.  **API Integration:** Queries external threat intelligence services (VirusTotal, AbuseIPDB, etc.) for up-to-date threat data.
5.  **Scoring Algorithm:** Aggregates findings from all modules using a weighted scoring system.
6.  **Output:** Presents a summary report including the individual checks, overall score, and final verdict.

## 🔧 Prerequisites

* Python 3.7 or higher
* Required Python libraries (see `requirements.txt`):
    * `requests`
    * `beautifulsoup4`
    * `dnspython`
    * `python-whois`
    * `tabulate` (for potentially formatted output, consider if you'll use it for CLI reports)
    * `html5lib` (parser for BeautifulSoup)

## 🚀 Setup Instructions

1.  **Clone the Repository:**
    ```bash
    git clone https://github.com/DDYBDAHL/Phishi_Detector.git
    cd Phishi_Detector
    ```

2.  **Create and Activate a Virtual Environment (Recommended):**
    * **Linux/macOS:**
        ```bash
        python3 -m venv venv
        source venv/bin/activate
        ```
    * **Windows:**
        ```bash
        python -m venv venv
        venv\Scripts\activate
        ```

3.  **Install Dependencies:**
    Ensure you have a `requirements.txt` file in your repository. If not, you can create one after manual installation (for development):
    ```bash
    # First time setup or if requirements.txt is missing
    pip install requests beautifulsoup4 dnspython python-whois tabulate html5lib
    pip freeze > requirements.txt # To generate the file for others

    # If requirements.txt is already present
    pip install -r requirements.txt
    ```

4.  **🔑 API Key Configuration (CRITICAL):**
    This script requires API keys for full functionality with external services. **DO NOT hardcode API keys directly in the script.**
    You **MUST** configure them as environment variables. The script will attempt to load these keys using `os.environ.get('API_KEY_NAME')`.

    * `VIRUSTOTAL_API_KEY`: Your API key for VirusTotal.
    * `ABUSEIPDB_API_KEY`: Your API key for AbuseIPDB.
    * `GOOGLE_SAFE_Browse_API_KEY`: Your API key for Google Safe Browse API (ensure you are using the correct API, e.g., Web Risk API).
    * `IPQS_API_KEY`: Your API key for IPQualityScore.

    **Setting Environment Variables:**

    * **Linux/macOS (bash/zsh):**
        Open your shell configuration file (e.g., `~/.bashrc`, `~/.zshrc`) and add:
        ```bash
        export VIRUSTOTAL_API_KEY="your_actual_virustotal_key"
        export ABUSEIPDB_API_KEY="your_actual_abuseipdb_key"
        export GOOGLE_SAFE_Browse_API_KEY="your_actual_google_key"
        export IPQS_API_KEY="your_actual_ipqs_key"
        ```
        Then, source the file (e.g., `source ~/.bashrc`) or open a new terminal.

    * **Windows (Command Prompt - Temporary):**
        ```cmd
        set VIRUSTOTAL_API_KEY="your_actual_virustotal_key"
        set ABUSEIPDB_API_KEY="your_actual_abuseipdb_key"
        # ... and so on for other keys
        ```
        *(Note: These are set for the current session only.)*

    * **Windows (PowerShell - Temporary):**
        ```powershell
        $Env:VIRUSTOTAL_API_KEY="your_actual_virustotal_key"
        $Env:ABUSEIPDB_API_KEY="your_actual_abuseipdb_key"
        # ... and so on for other keys
        ```
        *(Note: These are set for the current session only.)*

    * **Windows (Persistent):**
        Search for "environment variables" in the Start Menu, click "Edit the system environment variables," then click the "Environment Variables..." button. Add new User variables with the names and your keys.

    If any API keys are missing, the corresponding checks may be skipped or functionality will be limited. The script should ideally handle these missing keys gracefully (e.g., by printing a warning).

## 🎮 Usage

**(Please update this section based on how your script actually takes input!)**

Navigate to the project directory in your terminal. Here are some *examples* of how it might be run. You'll need to define how users pass emails or URLs.

**Option 1: Using Gui**
![{4763B483-6CE6-420E-89E3-87E6D512CCA2}](https://github.com/user-attachments/assets/684451a2-b071-474d-bfdc-553eb8fc5075)
![{A52DBC29-717D-494F-8233-3E32FE3BF203}](https://github.com/user-attachments/assets/e4630903-d2a6-4639-8e09-6b27bacd1b85)


**Option 2: Using Command-Line Arguments (Recommended for Scripting)**

```bash
# Example: Analyze an email file
python Phishi_Detector_Project.py --email path/to/your/email.eml

# Example: Analyze a single URL
python Phishi_Detector_Project.py --url "[https://suspicious-example.com/login](https://suspicious-example.com/login)"

# Example: Analyze a URL and output to a file
python Phishi_Detector_Project.py --url "[https://example.com](https://example.com)" --output report.txt

# Display help message (if you implement argparse)
python Phishi_Detector_Project.py --help****


