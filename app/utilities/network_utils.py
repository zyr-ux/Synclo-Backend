import ipaddress

from app.core.constants import LOOPBACK_HOSTS


def is_trusted_proxy(client_ip: str) -> bool:
    if not client_ip:
        return False
    if client_ip in LOOPBACK_HOSTS:
        return True
    try:
        ip = ipaddress.ip_address(client_ip)
        return ip.is_loopback or ip.is_private
    except ValueError:
        return False
