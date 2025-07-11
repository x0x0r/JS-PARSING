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

# Logging
logging.basicConfig(level=logging.INFO, format='[%(asctime)s] [%(levelname)s] - %(message)s')

def is_obfuscated(js_content):
    lines = js_content.splitlines()
    return (
        (len(lines) < 5 and ';' in js_content and len(js_content) > 1000) or
        any('eval(' in line or 'Function(' in line for line in lines)
    )

def get_headers():
    user_agents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
        'Mozilla/5.0 (X11; Linux x86_64)',
        'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)',
    ]
    return {
        'User-Agent': random.choice(user_agents),
        'Accept': '*/*',
        'Connection': 'keep-alive',
    }

def scan_js(url, ditemukan_log, tidak_ditemukan_log, gagal_log):
    start_time = time()
    logging.info(f'Scanning: {url}')

    try:
        headers = get_headers()
        response = requests.get(url, timeout=20, headers=headers)
        elapsed = time() - start_time
        logging.info(f'Status: {response.status_code} | Time: {elapsed:.2f}s')

        if response.status_code != 200:
            gagal_log.write(f'{url} - Status Code: {response.status_code}\n')
            return

        js_content = response.text

        if is_obfuscated(js_content):
            logging.info('Obfuscation detected, beautifying...')
            js_content = jsbeautifier.beautify(js_content)

        found = False
        temp_result = [f'[ðŸ”] {url}']

        for label, pattern in PATTERNS.items():
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            for match in matches:
                found = True
                line = f'[â€¼ï¸] {label} ditemukan: {match.strip()}'
                temp_result.append(line)

        if found:
            temp_result.append('\n')
            ditemukan_log.write('\n'.join(temp_result) + '\n')
        else:
            tidak_ditemukan_log.write(f'{url}\n')

    except requests.exceptions.RequestException as e:
        err = f'{url} - Error: {e}'
        logging.error(err)
        gagal_log.write(err + '\n')

def main():
    path = input("Masukkan path ke file subdomain.txt: ").strip()
    try:
        with open(path, 'r') as f:
            links = [line.strip() for line in f if line.strip().startswith('http')]
    except FileNotFoundError:
        logging.error(f'File "{path}" tidak ditemukan.')
        return

    if not links:
        logging.warning('Tidak ada link valid.')
        return

    logging.info(f'Memulai scan {len(links)} link...\n')
    with open('hasil_ditemukan.txt', 'w', encoding='utf-8') as ditemukan_log, \
         open('hasil_tidak_ditemukan.txt', 'w', encoding='utf-8') as tidak_ditemukan_log, \
         open('hasil_gagal_fetch.txt', 'w', encoding='utf-8') as gagal_log:

        ditemukan_log.write('=== Link dengan Informasi Sensitif ===\n')
        tidak_ditemukan_log.write('=== Link Tanpa Informasi Sensitif ===\n')
        gagal_log.write('=== Link Gagal Diakses ===\n')

        for link in links:
            scan_js(link, ditemukan_log, tidak_ditemukan_log, gagal_log)

    logging.info('âœ… Scan selesai. Hasil disimpan di:\n- hasil_ditemukan.txt\n- hasil_tidak_ditemukan.txt\n- hasil_gagal_fetch.txt')

if __name__ == '__main__':
    main()
