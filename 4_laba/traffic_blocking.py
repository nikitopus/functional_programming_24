from scapy.all import sniff, send
from scapy.layers.inet import IP, TCP, ICMP
import logging
import subprocess
from collections import defaultdict
from datetime import datetime, timedelta

# Настройка логирования
logging.basicConfig(filename="traffic_logs.log", level=logging.INFO)

# === ПАРАМЕТРЫ ДЛЯ НАСТРОЙКИ ===
PORT_SCAN_THRESHOLD = 3  # Порог для обнаружения сканирования портов
DOS_THRESHOLD = 100  # Максимальное количество пакетов в секунду от одного IP
BLOCK_TIME_MINUTES = 10  # Время блокировки IP-адреса (в минутах)

# === ХРАНЕНИЕ ДАННЫХ ===
scan_attempts = defaultdict(set)  # Для отслеживания сканирования портов
packet_counts = defaultdict(list)  # Для отслеживания активности (DoS)
blocked_ips = {}  # Заблокированные IP-адреса с отметкой времени

# === ФУНКЦИИ ===

# Запись в лог подозрительной активности
def log_suspicious_activity(ip, activity):
    logging.info(f"{datetime.now()} - Suspicious activity from {ip}: {activity}")

# Блокировка IP через iptables
def block_ip(ip_address):
    if ip_address not in blocked_ips:
        subprocess.run(["iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"], check=True)
        blocked_ips[ip_address] = datetime.now()
        logging.info(f"Blocking traffic from {ip_address}")

# Разблокировка устаревших IP
def unblock_ips():
    now = datetime.now()
    for ip, block_time in list(blocked_ips.items()):
        if now - block_time > timedelta(minutes=BLOCK_TIME_MINUTES):
            subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=True)
            del blocked_ips[ip]
            logging.info(f"Unblocking traffic from {ip}")

# Анализ сетевого трафика
def packet_handler(packet):
    # Проверка IP-слоя
    if packet.haslayer(IP):
        ip_src = packet[IP].src  # Исходный IP-адрес

        # === Защита от DoS-атак ===
        now = datetime.now()
        packet_counts[ip_src].append(now)
        # Удаление старых записей
        packet_counts[ip_src] = [time for time in packet_counts[ip_src] if now - time < timedelta(seconds=1)]
        if len(packet_counts[ip_src]) > DOS_THRESHOLD:
            log_suspicious_activity(ip_src, "DoS attack detected")
            block_ip(ip_src)

        # === Обнаружение сканирования портов ===
        if packet.haslayer(TCP):
            dst_port = packet[TCP].dport
            scan_attempts[ip_src].add(dst_port)
            if len(scan_attempts[ip_src]) > PORT_SCAN_THRESHOLD:
                log_suspicious_activity(ip_src, "Port scan detected")
                block_ip(ip_src)

# === ЗАПУСК ===
print("Starting network traffic monitoring...")
try:
    sniff(prn=packet_handler, store=0)
except KeyboardInterrupt:
    print("Stopping monitoring...")
finally:
    # Очистка iptables при завершении
    for ip in list(blocked_ips.keys()):
        subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=True)
    print("Unblocked all IPs.")
