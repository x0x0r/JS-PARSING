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

# === HELPERS ===
def get_headers():
    return {
        'User-Agent': random.choice(USER_AGENTS),
        'Accept': '*/*',
        'Connection': 'keep-alive',
    }

def make_output_dirs():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    for sub in ['ditemukan', 'tidak_ditemukan', 'gagal', 'endpoints', 'gf', 'nuclei', 'jsleak']:
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

def run_command(tool, input_file, out_file):
    try:
        if tool == 'gf':
            for pattern in ['xss', 'sqli', 'idor', 'redirect', 'lfi']:
                subprocess.call(f"cat {input_file} | gf {pattern} >> {out_file}", shell=True)
        elif tool == 'nuclei':
            subprocess.call(f"cat {input_file} | nuclei -silent -t exposed-tokens/ -o {out_file}", shell=True)
        elif tool == 'jsleak':
            subprocess.call(f"jsleak -f {input_file} -o {out_file}", shell=True)
    except Exception as e:
        logging.warning(f"{tool} error: {e}")

# === MAIN LOGIC ===
def scan_js(url):
    filename = url.replace('https://', '').replace('http://', '').replace('/', '_')
    log = f"[URL] {url}\n"
    try:
        resp = requests.get(url, headers=get_headers(), timeout=25)
        js = resp.text

        if len(js.splitlines()) < 5 and len(js) > 1000:
            js = jsbeautifier.beautify(js)
        write_to_file('beautified', filename + '.js', js)

        found = False

        # Sensitive
        sensitive = extract_patterns(js, SENSITIVE_PATTERNS)
        if sensitive:
            log += "\n[🔐 Sensitive Info]"
            for k, v in sensitive.items():
                for val in v:
                    log += f"\n  {k}: {val}"
            found = True

        # Base64
        b64 = decode_base64_strings(js)
        if b64:
            log += "\n\n[🔓 Base64 Decoded]"
            for raw, decoded in b64:
                preview = decoded[:100].replace('\n', ' ')
                log += f"\n  → {preview} (from: {raw[:20]}...)"
            found = True

        # Obfuscation / Eval
        obfs = match_list(js, OBFUSCATION)
        if obfs:
            log += f"\n\n[⚠️ Obfuscated Function]: {', '.join(obfs)}"
            found = True

        # Fingerprinting
        fp = match_list(js, FINGERPRINTING)
        if fp:
            log += f"\n\n[🕵️‍♂️ Fingerprinting Detected]: {', '.join(fp)}"
            found = True

        # Fetch Endpoints
        endpoints = extract_endpoints(js)
        if endpoints:
            log += "\n\n[📡 API Endpoints]"
            for ep in endpoints:
                log += f"\n  - {ep}"
            write_to_file('endpoints', filename + '.txt', '\n'.join(endpoints))

        if found:
            write_to_file('ditemukan', filename + '.txt', log)
        else:
            write_to_file('tidak_ditemukan', filename + '.txt', "[OK] Tidak ditemukan indikasi sensitif.")

    except Exception as e:
        write_to_file('gagal', filename + '.txt', f"❌ Error fetching: {url}\n{str(e)}")

# === ENTRY ===
def main():
    make_output_dirs()
    path = input("📥 Masukkan file berisi URL JS: ").strip()
    try:
        with open(path, 'r') as f:
            urls = [line.strip() for line in f if line.strip().startswith('http')]
    except FileNotFoundError:
        logging.error("File tidak ditemukan.")
        return

    for url in urls:
        scan_js(url)

    logging.info("✅ Scan JS selesai.")
    
    # Chaining tools (optional)
    endpoints_file = os.path.join(OUTPUT_DIR, 'endpoints', 'all_endpoints.txt')
    with open(endpoints_file, 'w') as ep_out:
        for root, _, files in os.walk(os.path.join(OUTPUT_DIR, 'endpoints')):
            for f in files:
                if f.endswith('.txt'):
                    with open(os.path.join(root, f)) as ep_in:
                        ep_out.write(ep_in.read() + '\n')

    # Run tools
    logging.info("🔗 Running nuclei, gf, jsleak...")
    run_command('nuclei', endpoints_file, os.path.join(OUTPUT_DIR, 'nuclei', 'result.txt'))
    run_command('gf', endpoints_file, os.path.join(OUTPUT_DIR, 'gf', 'result.txt'))
    run_command('jsleak', endpoints_file, os.path.join(OUTPUT_DIR, 'jsleak', 'result.txt'))

    logging.info(f"📁 Semua output disimpan di folder: {OUTPUT_DIR}")

if __name__ == '__main__':
    main()
