# artifact_collector.py
from typing import List, Dict, Set
import ipaddress

# Списки ключевых слов для фильтрации нежелательных сигнатур
IGNORE_SIGNATURE_KEYWORDS = ['SURICATA', 'POLICY', 'ET POLICY', 'Info', 'GPL']

def is_public_ip(ip: str) -> bool:
    """Проверяет, что IP не из LAN  диапазона"""
    try:
        return not ipaddress.ip_address(ip).is_private
    except ValueError:
        # Если это некорректный IP, считаем его непубличным
        return False

def collect_artifacts(events: List[Dict]) -> Dict[str, Set]:
    src_ips: Set[str] = set()
    dest_ips: Set[str] = set()
    domains: Set[str] = set()
    urls: Set[str] = set()
    signatures: Set[str] = set()

    for event in events:
        # IP-адреса
        if 'src_ip' in event and is_public_ip(event['src_ip']):
            src_ips.add(event['src_ip'])
        if 'dest_ip' in event and is_public_ip(event['dest_ip']):
            dest_ips.add(event['dest_ip'])

        # Домены и URL
        if event.get('event_type') == 'http':
            http = event.get('http', {})
            hostname = http.get('hostname')
            if hostname:
                domains.add(hostname.lower())
                path = http.get('url', '').strip('/')
                full_url = f"{hostname}/{path}" if path else hostname
                urls.add(full_url.lower())

        if 'tls' in event:
            sni = event['tls'].get('sni')
            if sni:
                domains.add(sni.lower())

        if event.get('event_type') == 'dns':
            rrname = event.get('dns', {}).get('rrname')
            if rrname:
                domains.add(rrname.rstrip('.').lower())

        # Сигнатуры из алертов
        if event.get('event_type') == 'alert':
            alert = event.get('alert', {})
            signature = alert.get('signature')
            if signature:
                # Фильтруем нежелательные сигнатуры по ключевым словам
                if not any(keyword.upper() in signature.upper() for keyword in IGNORE_SIGNATURE_KEYWORDS):
                    signatures.add(signature)

    all_ips = src_ips | dest_ips

    return {
        'src_ips': src_ips,
        'dest_ips': dest_ips,
        'all_ips': all_ips,
        'domains': domains,
        'urls': urls,
        'signatures': signatures,
    }