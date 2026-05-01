WHITELISTED_IPS = [
    "127.0.0.1",
    "::1",
    "8.8.8.8",
    "8.8.4.4",
    "1.1.1.1",
    "192.168.0.0",
    "192.168.1.1",
    "10.0.0.1",
]


def is_whitelisted(ip: str) -> bool:
    if ip in WHITELISTED_IPS:
        return True
    if ip.startswith("127."):
        return True
    if ip.startswith("192.168."):
        return True
    if ip.startswith("10."):
        return True
    if ip.startswith("172.16."):
        return True
    return False


def add_to_whitelist(ip: str):
    if ip not in WHITELISTED_IPS:
        WHITELISTED_IPS.append(ip)
        print(f"[Whitelist] Added {ip} to whitelist")
    else:
        print(f"[Whitelist] {ip} already in whitelist")


if __name__ == "__main__":
    test_ips = ["8.8.8.8", "185.220.101.1", "127.0.0.1", "192.168.1.5"]
    for ip in test_ips:
        result = is_whitelisted(ip)
        print(f"  {ip} — {'WHITELISTED' if result else 'NOT whitelisted'}")
