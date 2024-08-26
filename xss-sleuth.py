import argparse
import requests
from concurrent.futures import ThreadPoolExecutor
import random
import time
import json
import sys

class AdvancedXSSScanner:
    def __init__(self, urls_file=None, payloads_file=None, request_file=None, 
                 method='GET', path=False, prefix='', suffix='', use_http=False, 
                 use_https=True, json_payload=False, threads=15, shuffle=False, 
                 skip=0, sleep=0, timeout=5000, multipart=False):
        self.urls = self.load_file(urls_file) if urls_file else []
        self.payloads = self.load_file(payloads_file) if payloads_file else []
        self.request_file = request_file
        self.method = method.upper()
        self.path = path
        self.prefix = prefix
        self.suffix = suffix
        self.protocol = 'http' if use_http else 'https'
        self.json_payload = json_payload
        self.threads = threads
        self.shuffle = shuffle
        self.skip = skip
        self.sleep = sleep / 1000  # Convert to seconds
        self.timeout = timeout
        self.multipart = multipart
        self.headers = self.load_file(request_file) if request_file else []

    def load_file(self, file_path):
        with open(file_path, 'r', encoding='utf-8') as file:
            return [line.strip() for line in file.readlines()]

    def request(self, url, payload):
        full_url = url + (self.prefix + payload + self.suffix if self.path else '?' + payload)
        try:
            if self.method == 'GET':
                response = requests.get(full_url, headers=self.headers, timeout=self.timeout, verify=False if self.protocol == 'http' else True)
            elif self.method == 'POST':
                if self.multipart:
                    response = requests.post(url, files=payload, headers=self.headers, timeout=self.timeout, verify=False if self.protocol == 'http' else True)
                elif self.json_payload:
                    response = requests.post(url, json=payload, headers=self.headers, timeout=self.timeout, verify=False if self.protocol == 'http' else True)
                else:
                    response = requests.post(url, data=payload, headers=self.headers, timeout=self.timeout, verify=False if self.protocol == 'http' else True)
            else:
                raise ValueError("Method not supported.")
            return response
        except requests.RequestException as e:
            print(f"Request failed: {e}")
            return None

    def check_for_xss(self, response):
        # Add your XSS detection logic here (based on response, DOM analysis, etc.)
        if response and ("<script>alert(" in response.text or "javascript:alert(" in response.text):
            return True
        return False

    def scan_url(self, url):
        for payload in self.payloads:
            time.sleep(self.sleep)  # Sleep in seconds
            response = self.request(url, payload)
            
            if response and self.check_for_xss(response):
                print(f"Vulnerable URL: {url}")
                print(f"Working Payload: {payload}")
                return

    def run_scanner(self):
        if self.shuffle:
            random.shuffle(self.urls)
        
        if self.skip > 0:
            self.urls = self.urls[self.skip:]
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(self.scan_url, self.urls)

def print_banner():
    banner = r"""
  _____ _             _           _____ _           _           
 / ____| |           | |         / ____| |         | |          
| (___ | |_   _  __ _| | ___    | (___ | | ___  ___| |_ ___  ___ 
 \___ \| | | | |/ _` | |/ _ \    \___ \| |/ _ \/ __| __/ _ \/ __|
 ____) | | |_| | (_| | |  __/    ____) | |  __/ (__| ||  __/\__ \
|_____/|_|\__,_|\__, |_|\___|   |_____/|_|\___|\___|\__\___||___/
                 __/ |                                    
                |___/                                     
    """
    print(banner)

def main():
    print_banner()
    parser = argparse.ArgumentParser(description="Advanced XSS Scanner")
    parser.add_argument('--urls', required='--get' in sys.argv, help="Path for URLs file (required for --get)")
    parser.add_argument('--payloads', required=True, help="Path for payloads file (required)")
    parser.add_argument('--request', help="Path for request headers for POST method")
    parser.add_argument('--get', action='store_true', help="Use GET method to test for XSS (default)")
    parser.add_argument('--post', action='store_true', help="Use POST method to test for XSS")
    parser.add_argument('--path', action='store_true', help="Inject payload at the end of URL instead of into query")
    parser.add_argument('--prefix', default='', help="Prefix to inject at the start of the payload for --path type")
    parser.add_argument('--suffix', default='', help="Suffix to inject at the end of the payload for --path type")
    parser.add_argument('--http', action='store_true', help="Use HTTP protocol for URL (default is HTTPS)")
    parser.add_argument('--https', action='store_true', help="Use HTTPS protocol for URL (default)")
    parser.add_argument('--json', action='store_true', help="Use JSON structure for handling JSON POST requests")
    parser.add_argument('--threads', type=int, default=15, help="Number of threads to use for sending requests concurrently")
    parser.add_argument('--shuffle', action='store_true', help="Shuffle generated GET URLs to avoid sending all requests to the first URL")
    parser.add_argument('--skip', type=int, default=0, help="Skip N URLs to continue interrupted scan")
    parser.add_argument('--sleep', type=int, default=0, help="Wait time in milliseconds after each request to avoid detection")
    parser.add_argument('--timeout', type=int, default=5000, help="Maximum timeout in milliseconds for requests")
    parser.add_argument('--multipart', action='store_true', help="Uses multipart encoding for POST requests")

    args = parser.parse_args()

    method = 'GET' if args.get else 'POST' if args.post else 'GET'
    scanner = AdvancedXSSScanner(
        urls_file=args.urls,
        payloads_file=args.payloads,
        request_file=args.request,
        method=method,
        path=args.path,
        prefix=args.prefix,
        suffix=args.suffix,
        use_http=args.http,
        use_https=args.https,
        json_payload=args.json,
        threads=args.threads,
        shuffle=args.shuffle,
        skip=args.skip,
        sleep=args.sleep,
        timeout=args.timeout,
        multipart=args.multipart
    )
    scanner.run_scanner()

if __name__ == "__main__":
    main()
