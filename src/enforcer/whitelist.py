"""
Whitelist of IPs that should NEVER be blocked.
"""


WHITELISTED_IPS = [
    "127.0.0.1",        # localhost
    "::1",              # localhost IPv6
    "8.8.8.8",          # Google DNS
    "8.8.4.4",          # Google DNS secondary
    "1.1.1.1",          # Cloudflare DNS
    "192.168.0.0",      # local network
    "192.168.1.1",      # common router IP
    "10.0.0.1",         # common gateway
]


def is_whitelisted(ip: str) -> bool:
    
    # Check exact match
    if ip in WHITELISTED_IPS:
        return True

    # Check if it is a private/local range
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
    # Test the whitelist
    test_ips = ["8.8.8.8", "185.220.101.1", "127.0.0.1", "192.168.1.5"]
    for ip in test_ips:
        result = is_whitelisted(ip)
        print(f"  {ip} — {'WHITELISTED (safe)' if result else 'NOT whitelisted (can block)'}")
