#!/usr/bin/env python3
"""
Strinova Localization Extractor
Extracts .locres language files from encrypted Strinova pak files.

Usage:
    python extract.py

Requirements:
    pip install cryptography
"""

import struct
import os
import sys
import zlib

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
AES_KEY = bytes.fromhex('7456667CCC6BF87AAD3DAA2DDAC3B02564C5B9D74565BB36645C46AC210CDE40')


def decrypt_aes_ecb(data, key):
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    aligned = ((len(data) + 15) // 16) * 16
    padded = data[:aligned] if aligned <= len(data) else data + b'\x00' * (aligned - len(data))
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    d = cipher.decryptor()
    return d.update(padded) + d.finalize()


def try_decompress(data):
    for wbits in [15, -15, 31, 47]:
        try:
            return zlib.decompress(data, wbits)
        except:
            pass
    return None


def parse_pak(pak_path, aes_key=None):
    entries = []
    with open(pak_path, 'rb') as f:
        f.seek(0, 2)
        file_size = f.tell()
        f.seek(max(0, file_size - 256))
        data = f.read()
        magic_pos = data.rfind(b'\xE1\x12\x6F\x5A')
        if magic_pos == -1:
            return None, []
        struct_start = file_size - 256 + magic_pos - 17
        f.seek(struct_start)
        sd = f.read(190)
        pos = 17 + 4 + 4
        index_offset = struct.unpack_from('<q', sd, pos)[0]
        pos += 8
        index_size = struct.unpack_from('<q', sd, pos)[0]

        f.seek(index_offset)
        index_data = f.read(index_size)
        if aes_key:
            padded = ((index_size + 15) // 16) * 16
            remaining = padded - index_size
            if remaining > 0:
                index_data += f.read(remaining)
            decrypted = decrypt_aes_ecb(index_data, aes_key)[:index_size]
        else:
            decrypted = index_data

        ipos = 0
        slen = struct.unpack_from('<I', decrypted, ipos)[0]
        ipos += 4
        # mount point (not used, but we must advance)
        ipos += slen  # skip mount string
        entry_count = struct.unpack_from('<I', decrypted, ipos)[0]
        ipos += 4

        for _ in range(entry_count):
            slen = struct.unpack_from('<I', decrypted, ipos)[0]
            ipos += 4
            name = decrypted[ipos:ipos + slen - 1].decode('utf-8', errors='replace')
            ipos += slen
            ie_offset = struct.unpack_from('<Q', decrypted, ipos)[0]
            ipos += 8
            ie_comp = struct.unpack_from('<Q', decrypted, ipos)[0]
            ipos += 8
            ie_uncomp = struct.unpack_from('<Q', decrypted, ipos)[0]
            ipos += 8
            ie_method = struct.unpack_from('<I', decrypted, ipos)[0]
            ipos += 4
            ipos += 20  # skip unknown
            ie_blocks = []
            if ie_method != 0:
                ie_block_count = struct.unpack_from('<I', decrypted, ipos)[0]
                ipos += 4
                for _ in range(ie_block_count):
                    s = struct.unpack_from('<q', decrypted, ipos)[0]
                    ipos += 8
                    e = struct.unpack_from('<q', decrypted, ipos)[0]
                    ipos += 8
                    ie_blocks.append((s, e))
            ie_flags = decrypted[ipos]
            ipos += 1
            ie_cbs = struct.unpack_from('<I', decrypted, ipos)[0]
            ipos += 4
            entries.append({
                'name': name,
                'offset': ie_offset,
                'comp': ie_comp,
                'uncomp': ie_uncomp,
                'method': ie_method,
                'blocks': ie_blocks,
                'cbs': ie_cbs,
                'flags': ie_flags
            })
    return entries  # no mount point needed


def extract_entry(f, entry, aes_key=None):
    if entry['method'] == 0:
        struct_size = 53
        f.seek(entry['offset'] + struct_size)
        raw_data = f.read(entry['comp'])
        if entry['flags'] & 1 and aes_key:
            return decrypt_aes_ecb(raw_data, aes_key)[:entry['comp']]
        return raw_data

    all_data = b''
    for bs, be in entry['blocks']:
        block_size = be - bs
        aligned_size = ((block_size + 15) // 16) * 16
        abs_start = entry['offset'] + bs
        f.seek(abs_start)
        raw_block = f.read(aligned_size)

        dec = raw_block[:block_size]
        result = try_decompress(dec)
        if result is None and (entry['flags'] & 1) and aes_key:
            dec = decrypt_aes_ecb(raw_block, aes_key)[:block_size]
            result = try_decompress(dec)
        if result is None and aes_key:
            dec = decrypt_aes_ecb(raw_block, aes_key)[:block_size]
            result = try_decompress(dec)
        if result is None:
            raise Exception("Cannot decompress block")
        all_data += result
    return all_data


def extract_entry_from_pak(pak_path, entry, aes_key=None):
    with open(pak_path, 'rb') as f:
        return extract_entry(f, entry, aes_key)


LANGUAGES = {
    'de': 'German', 'en': 'English', 'es-419': 'Spanish (LATAM)',
    'fr': 'French', 'ja': 'Japanese', 'ko': 'Korean',
    'pt-BR': 'Portuguese (Brazil)', 'ru': 'Russian', 'vi': 'Vietnamese',
    'yo': 'Yoruba', 'zh-Hans': 'Chinese (Simplified)', 'zh-Hant-TW': 'Chinese (Traditional TW)',
    'zu': 'Zulu', 'zh-Hans': 'Simplified Chinese', 'zh-Hant': 'Traditional Chinese',
}


def get_lang_name(code):
    return LANGUAGES.get(code, code)


def main():
    pak_path = input("Enter path to .pak file: ").strip().strip("'\"")
    pak_path = os.path.normpath(pak_path)
    if not os.path.exists(pak_path):
        print(f"Error: File not found: {pak_path}")
        sys.exit(1)

    aes_key = AES_KEY

    print(f"\nParsing {os.path.basename(pak_path)} ({os.path.getsize(pak_path) / 1024 / 1024:.1f} MB)...")
    try:
        entries = parse_pak(pak_path, aes_key)
    except Exception as ex:
        print(f"Error parsing pak: {ex}")
        sys.exit(1)

    print(f"Total entries: {len(entries)}")

    # Collect non‑zero .locres entries by language
    locres_entries = {}
    for e in entries:
        if e['name'].endswith('.locres') and e['uncomp'] > 0:
            parts = e['name'].replace('\\', '/').split('/')
            lang = parts[-2] if len(parts) >= 2 else 'unknown'
            locres_entries[lang] = e

    all_langs = sorted(locres_entries.keys())

    if not all_langs:
        print("No non‑empty localization files found in this pak.")
        sys.exit(0)

    print(f"\nFound {len(all_langs)} languages with content:")
    print("-" * 40)
    for i, lang in enumerate(all_langs):
        size = locres_entries[lang]['uncomp']
        name = get_lang_name(lang)
        print(f"  [{i+1:2d}] {lang:20s} {name:30s}  {size:>10,d} bytes")
    print("-" * 40)

    choice = input(f"\nSelect language (1-{len(all_langs)}, or comma-separated list, or 'all'): ").strip()

    if choice.lower() == 'all':
        selected = all_langs
    else:
        selected = []
        for part in choice.split(','):
            part = part.strip()
            if '-' in part and part.replace('-', '').isdigit():
                start, end = part.split('-', 1)
                for i in range(int(start) - 1, min(int(end), len(all_langs))):
                    selected.append(all_langs[i])
            elif part.isdigit():
                idx = int(part) - 1
                if 0 <= idx < len(all_langs):
                    selected.append(all_langs[idx])
            elif part in all_langs:
                selected.append(part)

    if not selected:
        print("No valid selection.")
        sys.exit(1)

    # Output directly to the .pak's folder (no extra subfolder)
    out_dir = os.path.dirname(pak_path)
    os.makedirs(out_dir, exist_ok=True)

    print(f"\nExtracting {len(selected)} language(s) to {out_dir}/")
    print("=" * 40)

    for lang in selected:
        print(f"\n  [{lang}] {get_lang_name(lang)}:")
        entry = locres_entries[lang]
        try:
            data = extract_entry_from_pak(pak_path, entry, aes_key)
            if len(data) == 0:
                print(f"    {entry['name']}  (extracted 0 bytes, skipping)")
                continue
            out_path = os.path.join(out_dir, entry['name'])
            os.makedirs(os.path.dirname(out_path), exist_ok=True)
            with open(out_path, 'wb') as f:
                f.write(data)
            print(f"    {entry['name']}  ({len(data):,} bytes)")
        except Exception as ex:
            print(f"    FAILED {entry['name']}: {ex}")

    print(f"\nDone! Files extracted to: {out_dir}/")


if __name__ == '__main__':
    main()
