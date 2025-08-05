#!/usr/bin/env python3
import re, os, base64, random, subprocess, requests, jsbeautifier, logging
from time import time

# === CONFIG ===
OUTPUT_DIR = 'js_output'
FETCH_PATTERNS = [
    r'fetch\((["\'])(https?://[^"\']+)\1',
    r'new XMLHttpRequest\(\)',
    r'\.open\(["\'](GET|POST|PUT|DELETE)["\'],\s*["\'](https?://[^"\']+)["\']',
    r'axios\.\w+\(["\'](https?://[^"\']+)["\']',
]

SENSITIVE_PATTERNS = {
    'API Key': r'(api[_-]?key\s*[:=]\s*[\'"][A-Za-z0-9_\-]{16,}[\'"])',
    'Secret Key': r'(secret[_-]?key\s*[:=]\s*[\'"][A-Za-z0-9_\-]{16,}[\'"])',
    'Access Token': r'(access[_-]?token\s*[:=]\s*[\'"][A-Za-z0-9\-_.]{16,}[\'"])',
    'Authorization': r'(authorization\s*[:=]\s*[\'"][A-Za-z0-9\-_\.=]+[\'"])',
    'Password': r'(password\s*[:=]\s*[\'"].{6,}[\'"])',
}

FINGERPRINTING = [
    r'canvas\.getContext', r'getImageData', r'toDataURL', r'AudioContext',
    r'userAgent', r'webdriver', r'deviceMemory', r'hardwareConcurrency'
]

OBFUSCATION = [
    r'eval\s*\(', r'new Function\s*\(', r'setTimeout\s*\(\s*[\'"]', r'setInterval\s*\(\s*[\'"]'
]

USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
    'Mozilla/5.0 (X11; Linux x86_64)',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)',
]

logging.basicConfig(level=logging.INFO, format='[%(asctime)s] [%(levelname)s] - %(message)s')

# === FUNCTIONS ===
def get_headers():
    return {
        'User-Agent': random.choice(USER_AGENTS),
        'Accept': '*/*',
        'Connection': 'keep-alive',
    }

def make_output_dirs():
    for sub in ['ditemukan', 'tidak_ditemukan', 'gagal', 'endpoints', 'beautified']:
        os.makedirs(os.path.join(OUTPUT_DIR, sub), exist_ok=True)

def decode_base64_strings(js_code):
    candidates = re.findall(r'["\']([A-Za-z0-9+/=]{20,})["\']', js_code)
    decoded = []
    for b64 in set(candidates):
        try:
            result = base64.b64decode(b64 + "===")
            if b"{" in result or b"http" in result or b"token" in result.lower():
                decoded.append((b64, result.decode(errors='ignore')))
        except:
            continue
    return decoded

def extract_endpoints(js_code):
    endpoints = []
    for pattern in FETCH_PATTERNS:
        found = re.findall(pattern, js_code)
        if found:
            if isinstance(found[0], tuple):
                found = [f[1] for f in found]
            endpoints.extend(found)
    return list(set(endpoints))

def extract_patterns(js_code, patterns):
    hits = {}
    for label, pattern in patterns.items():
        matches = re.findall(pattern, js_code, re.IGNORECASE)
        if matches:
            hits[label] = sorted(set(matches))
    return hits

def match_list(js_code, patterns):
    return [p for p in patterns if re.search(p, js_code)]

def write_to_file(folder, filename, content):
    path = os.path.join(OUTPUT_DIR, folder, filename)
    with open(path, 'w', encoding='utf-8') as f:
        f.write(content)

def scan_js(url):
    filename = url.replace('https://', '').replace('http://', '').replace('/', '_')
    log = f"[URL] {url}\n"
    try:
        resp = requests.get(url, headers=get_headers(), timeout=20)
        status = resp.status_code
        if status != 200:
            write_to_file('gagal', filename + '.txt', f"❌ Failed ({status}): {url}")
            return

        js = resp.text
        if len(js.splitlines()) < 5 and len(js) > 1000:
            js = jsbeautifier.beautify(js)

        write_to_file('beautified', filename + '.js', js)

        found = False

        # === Sensitive Info
        sensitive = extract_patterns(js, SENSITIVE_PATTERNS)
        if sensitive:
            log += "\n[🔐 Sensitive Info]"
            for k, v in sensitive.items():
                for val in v:
                    log += f"\n  {k}: {val}"
            found = True

        # === Base64
        b64 = decode_base64_strings(js)
        if b64:
            log += "\n\n[🔓 Base64 Decoded]"
            for raw, decoded in b64:
                preview = decoded[:100].replace('\n', ' ')
                log += f"\n  → {preview} (from: {raw[:20]}...)"
            found = True

        # === Obfuscation
        obfs = match_list(js, OBFUSCATION)
        if obfs:
            log += f"\n\n[⚠️ Obfuscation]: {', '.join(obfs)}"
            found = True

        # === Fingerprinting
        fp = match_list(js, FINGERPRINTING)
        if fp:
            log += f"\n\n[🕵️‍♂️ Fingerprinting Detected]: {', '.join(fp)}"
            found = True

        # === Endpoints
        endpoints = extract_endpoints(js)
        if endpoints:
            log += "\n\n[📡 API Endpoints]"
            for ep in endpoints:
                log += f"\n  - {ep}"
            write_to_file('endpoints', filename + '.txt', '\n'.join(endpoints))

        if found:
            write_to_file('ditemukan', filename + '.txt', log)
        else:
            write_to_file('tidak_ditemukan', filename + '.txt', f"[OK] {url} - Tidak ditemukan indikasi sensitif.")

    except Exception as e:
        write_to_file('gagal', filename + '.txt', f"❌ Error: {url}\n{str(e)}")

# === MAIN ===
def main():
    make_output_dirs()
    path = input("📥 Masukkan file URL JS (satu per baris): ").strip()
    if not os.path.exists(path):
        logging.error(f"File tidak ditemukan: {path}")
        return

    with open(path, 'r') as f:
        urls = [line.strip() for line in f if line.strip().startswith('http')]

    for url in urls:
        scan_js(url)

    logging.info(f"✅ Selesai scan {len(urls)} link.")
    logging.info(f"📁 Output disimpan di folder: {OUTPUT_DIR}")

if __name__ == '__main__':
    main()
