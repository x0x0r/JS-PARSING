import re
import requests
import jsbeautifier
import random
import logging
from time import time

# Pola informasi sensitif
PATTERNS = {
    'API Key': r'(api[_-]?key\s*[:=]\s*[\'"][A-Za-z0-9_\-]{16,}[\'"])',
    'Secret Key': r'(secret[_-]?key\s*[:=]\s*[\'"][A-Za-z0-9_\-]{16,}[\'"])',
    'Access Token': r'(access[_-]?token\s*[:=]\s*[\'"][A-Za-z0-9\-_.]{16,}[\'"])',
    'Password': r'(password\s*[:=]\s*[\'"].{6,}[\'"])',
    'Username': r'(username\s*[:=]\s*[\'"][^\'"]{3,}[\'"])',
    'Authorization': r'(authorization\s*[:=]\s*[\'"][A-Za-z0-9\-_\.=]+[\'"])',
}

# Konfigurasi logging
logging.basicConfig(level=logging.DEBUG, format='[%(asctime)s] [%(levelname)s] - %(message)s')

# Deteksi obfuscation
def is_obfuscated(js_content):
    lines = js_content.splitlines()
    if len(lines) < 5 and ';' in js_content and len(js_content) > 1000:
        return True
    if any('eval(' in line or 'Function(' in line for line in lines):
        return True
    return False

# Menambah headers untuk bypass WAF
def get_headers():
    user_agents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/64.0.3282.140 Safari/537.36',
        'Mozilla/5.0 (Linux; Android 10; Pixel 4 XL) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.127 Mobile Safari/537.36',
    ]
    headers = {
        'User-Agent': random.choice(user_agents),
        'Accept': 'application/json, text/plain, */*',
        'Accept-Encoding': 'gzip, deflate, br',
        'Connection': 'keep-alive',
    }
    return headers

# Scan URL
def scan_js(url, log_file):
    start_time = time()
    logging.info(f'Scanning: {url}')
    log_file.write(f'\n[ðŸ”] Scanning: {url}\n')

    try:
        # Coba request dengan headers untuk bypass WAF
        headers = get_headers()
        response = requests.get(url, timeout=20, headers=headers)
        
        # Status & waktu respon
        elapsed_time = time() - start_time
        logging.debug(f'URL: {url} - Status Code: {response.status_code} - Response Time: {elapsed_time:.2f} sec')

        if response.status_code != 200:
            logging.warning(f'Failed to retrieve {url}, Status Code: {response.status_code}')
            log_file.write(f'[âœ—] Gagal mengambil {url}, Status Code: {response.status_code}\n')
            return

        js_content = response.text

        # Deobfuscate jika terdeteksi
        if is_obfuscated(js_content):
            logging.info('[!] Obfuscation detected, trying to beautify...')
            log_file.write('[!] Terdeteksi obfuscation â€“ mencoba beautify...\n')
            js_content = jsbeautifier.beautify(js_content)

        found = False
        for label, pattern in PATTERNS.items():
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            for match in matches:
                line = f'[â€¼ï¸] {label} ditemukan: {match.strip()}'
                logging.info(line)
                log_file.write(line + '\n')
                found = True

        if not found:
            logging.info('[âœ“] Tidak ditemukan informasi sensitif.')
            log_file.write('[âœ“] Tidak ditemukan informasi sensitif.\n')

    except requests.exceptions.RequestException as e:
        logging.error(f'[âœ—] Gagal mengambil {url}: {e}')
        log_file.write(f'[âœ—] Gagal mengambil {url}: {e}\n')

# Main
def main():
    path = input("Masukkan path ke file subdomain.txt: ").strip()
    try:
        with open(path, 'r') as f:
            links = [line.strip() for line in f if line.strip().startswith('http')]
    except FileNotFoundError:
        logging.error(f'[!] File "{path}" tidak ditemukan.')
        return

    if not links:
        logging.error('[!] Tidak ada link valid.')
        return

    logging.info(f'[ðŸš€] Mulai scan {len(links)} link...\n')
    with open('hasil_scan.txt', 'w', encoding='utf-8') as log_file:
        log_file.write('=== Hasil Scan Informasi Sensitif ===\n')
        for link in links:
            scan_js(link, log_file)

    logging.info('[âœ”ï¸] Scan selesai. Hasil disimpan di: hasil_scan_update.txt')

if __name__ == '__main__':
    main()
