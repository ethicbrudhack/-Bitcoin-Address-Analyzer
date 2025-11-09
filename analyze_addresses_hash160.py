# analyze_addresses_hash160.py
# Reads btc_active_addressesbrain0.txt, decodes addresses, applies heuristics,
# writes suspicious entries to suspicious_addresses.txt

import hashlib, sys, os, statistics

INPUT = "btc_active_addressesbrain0.txt"
OUTPUT = "suspicious_addresses.txt"

ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
b58map = {c:i for i,c in enumerate(ALPHABET)}

def b58decode(s):
    num = 0
    for ch in s:
        if ch not in b58map:
            raise ValueError(f"Invalid Base58 char: {ch}")
        num = num * 58 + b58map[ch]
    full = num.to_bytes((num.bit_length() + 7) // 8, 'big') if num != 0 else b'\x00'
    n_pad = 0
    for ch in s:
        if ch == '1':
            n_pad += 1
        else:
            break
    return b'\x00' * n_pad + full

def decode_base58check(addr):
    raw = b58decode(addr)
    if len(raw) < 5:
        return None, None, False, "too_short"
    payload, checksum = raw[:-4], raw[-4:]
    calc_checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    valid = (calc_checksum == checksum)
    version = payload[0]
    hash160 = payload[1:]
    return version, hash160, valid, None

def analyze_hash160(hash160):
    reasons = []
    if hash160 is None or len(hash160) != 20:
        reasons.append("bad_length")
        return reasons
    bytes_list = list(hash160)
    distinct = len(set(bytes_list))
    if distinct < 6:
        reasons.append(f"low_distinct_bytes({distinct})")
    repeated_threshold = 4
    for b in set(bytes_list):
        if bytes_list.count(b) > repeated_threshold:
            reasons.append(f"byte_{b:02x}_repeated_{bytes_list.count(b)}")
            break
    if (max(bytes_list) - min(bytes_list)) < 24:
        reasons.append("small_byte_range")
    leading_zero_bytes = len(hash160) - len(hash160.lstrip(b'\x00'))
    if leading_zero_bytes >= 3:
        reasons.append(f"leading_zero_bytes={leading_zero_bytes}")
    bit_count = sum(bin(b).count("1") for b in bytes_list)
    if bit_count < 50:
        reasons.append(f"low_bitcount({bit_count})")
    if bit_count > 130:
        reasons.append(f"high_bitcount({bit_count})")
    return reasons

if not os.path.exists(INPUT):
    print(f"Input file '{INPUT}' not found in current directory: {os.getcwd()}")
    sys.exit(1)

suspicious = []
total = 0
valid_addr_count = 0
invalid_checksum_count = 0

with open(INPUT, "r", encoding="utf-8", errors="ignore") as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        total += 1
        addr_part = line.split('|',1)[0].strip()
        if not addr_part:
            continue
        addr = addr_part.split()[0].strip()
        try:
            version, hash160, valid, err = decode_base58check(addr)
        except Exception as e:
            suspicious.append((addr, None, ["decode_error", str(e)], line))
            continue
        if not valid:
            invalid_checksum_count += 1
            reasons = ["invalid_base58check"]
            suspicious.append((addr, None, reasons, line))
            continue
        valid_addr_count += 1
        reasons = analyze_hash160(hash160)
        if reasons:
            suspicious.append((addr, hash160.hex(), reasons, line))

with open(OUTPUT, "w", encoding="utf-8") as out:
    out.write("# Suspicious addresses detected by analyze_addresses_hash160.py\n")
    out.write("# Columns: address | hash160 | reasons (comma-separated) | original_line\n\n")
    for addr, h, reasons, orig in suspicious:
        out.write(f"{addr} | {h or ''} | {','.join(reasons)} | {orig}\n")

print("Input file:", INPUT)
print("Total lines processed:", total)
print("Valid addresses decoded:", valid_addr_count)
print("Invalid checksum addresses:", invalid_checksum_count)
print("Suspicious addresses found:", len(suspicious))
print("Output written to:", OUTPUT)
if len(suspicious) > 0:
    print("\nFirst 10 suspicious entries:")
    for addr, h, reasons, orig in suspicious[:10]:
        print(f"{addr} | {h or ''} | {', '.join(reasons)}")
