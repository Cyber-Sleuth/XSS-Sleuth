XSS-Sleuth is a powerful and advanced cross-site scripting (XSS) vulnerability scanner designed for penetration testers and bug bounty hunters. This tool is capable of detecting a variety of XSS vulnerabilities by utilizing custom payloads, bypassing security filters such as Web Application Firewalls (WAFs), and avoiding false positives. It supports GET and POST methods, can handle multipart forms, JSON payloads, and offers advanced features such as threading and URL shuffling to maximize the efficiency of scans.
Features:

    1. XSS Payload Injection: Tests multiple XSS payloads across a variety of input vectors.
    2. Method Support: Supports both GET and POST requests, including JSON and multipart/form-data.
    3. Security Bypass: Capable of bypassing WAFs and Content Delivery Networks (CDNs) to test for real-world vulnerabilities.
    4. Multi-threading: Uses concurrent threads for faster scanning of large lists of URLs.
    5. Path-based Injection: Injects payloads in the URL path as well as query parameters.
    6. Custom Prefix/Suffix: Allows adding custom prefixes and suffixes around payloads to adapt to different contexts.
    7. URL Shuffling: Randomizes URL processing order to prevent detection by rate-limiting mechanisms.
    8. Timeout and Sleep Settings: Configurable timeout and sleep intervals between requests to avoid detection by Intrusion Detection Systems (IDS).
    9. Skip Option: Skip URLs to continue interrupted scans from a specific point.
Usage:
python3 xss-sleuth.py --urls urls.txt --payloads payloads.txt --get --threads 10 --shuffle
Requirements:
    1. Python 3.6+
    2. Dependencies can be installed using the provided requirements.txt file.
Installation:

    Clone the repository:

          git clone https://github.com/yourusername/cyber-sleuth-pro.git

    Install the dependencies:
    
           pip install -r requirements.txt
                
    Run the scanner:
    
          python3 cyber_sleuth_pro.py --help
