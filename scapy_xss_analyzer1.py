import argparse
import socket
import random
import time
import html
from urllib.parse import urlparse, parse_qs
from scapy.layers.inet import IP, TCP
from scapy.layers.http import HTTP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.sendrecv import sr1, send
from scapy.all import sniff, wrpcap, rdpcap

def resolve_hostname(hostname):
    """Разрешает доменное имя в IP-адрес."""
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror as e:
        print(f"Ошибка разрешения доменного имени '{hostname}': {e}")
        return None


def parse_url(url_arg):
    """Парсит URL и извлекает hostname, path и scheme."""
    if not url_arg.startswith('http://') and not url_arg.startswith('https://'):
        url_arg = 'http://' + url_arg
    
    try:
        parsed = urlparse(url_arg)
        hostname = parsed.hostname
        path = parsed.path if parsed.path else '/'
        scheme = parsed.scheme or 'http'
        return hostname, path, scheme
    except Exception as e:
        print(f"Ошибка парсинга URL: {e}")
        return None, None, None


def send_http_request(hostname, path, custom_request=None):
    """Отправляет HTTP-запрос через Scapy."""
    dest_ip = resolve_hostname(hostname)
    if not dest_ip:
        return None
    
    port = 80
    client_sport = random.randint(1025, 65500)
    
    # Формируем HTTP-запрос
    if custom_request:
        http_request_str = custom_request
    else:
        http_request_str = f'GET {path} HTTP/1.1\r\nHost: {hostname}\r\nConnection: close\r\n\r\n'
    
    # Устанавливаем TCP-соединение
    syn = IP(dst=dest_ip) / TCP(sport=client_sport, dport=port, flags='S')
    syn_ack = sr1(syn, timeout=5, verbose=False)
    
    if not syn_ack or not syn_ack.haslayer(TCP) or syn_ack[TCP].flags != 0x12:
        print(f"Не удалось установить соединение с {hostname}")
        return None
    
    # Отправляем ACK
    client_seq = syn_ack[TCP].ack
    client_ack = syn_ack[TCP].seq + 1
    ack_packet = IP(dst=dest_ip) / TCP(
        sport=client_sport,
        dport=port,
        seq=client_seq,
        ack=client_ack,
        flags='A'
    )
    send(ack_packet, verbose=False)
    
    time.sleep(0.1)
    
    # Отправляем HTTP-запрос
    http_request = IP(dst=dest_ip) / TCP(
        sport=client_sport,
        dport=port,
        seq=client_seq,
        ack=client_ack,
        flags='PA'
    ) / http_request_str
    
    send(http_request, verbose=False)
    
    return dest_ip, port, client_sport


def extract_http_data(packets):
    """Извлекает HTTP-данные из пакетов."""
    http_messages = []
    
    for pkt in packets:
        if pkt.haslayer(Raw):
            try:
                data = pkt[Raw].load.decode('utf-8', errors='ignore')
                # Проверяем, это HTTP или нет
                if any(method in data for method in ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'HTTP/']):
                    http_messages.append(data)
            except:
                continue
    
    return http_messages


def detect_xss_payloads(text):
    """Обнаруживает потенциальные XSS-полезные нагрузки в тексте."""
    xss_patterns = [
        r'<script[^>]*>.*?</script>',
        r'javascript:',
        r'on\w+\s*=',
        r'<iframe[^>]*>',
        r'<img[^>]*onerror\s*=',
        r'<svg[^>]*onload\s*=',
        r'alert\(',
        r'document\.',
        r'window\.',
        r'<object[^>]*>',
        r'<embed[^>]*>',
        r'<body[^>]*onload\s*='
    ]
    
    import re
    detected = []
    
    for pattern in xss_patterns:
        matches = re.findall(pattern, text, re.IGNORECASE)
        detected.extend(matches)
    
    return detected


def extract_params_from_request(request):
    """Извлекает параметры из HTTP-запроса."""
    params = {}
    
    if '?' in request:
        query_string = request.split('?')[1].split(' ')[0]
        params = parse_qs(query_string)
    
    # Также ищем параметры в теле POST-запроса
    if '\r\n\r\n' in request:
        headers, body = request.split('\r\n\r\n', 1)
        if body and '=' in body and 'Content-Type: application/x-www-form-urlencoded' in headers:
            body_params = parse_qs(body)
            params.update(body_params)
    
    return params


def check_reflected_xss(request, response):
    """Проверяет отраженные XSS в запросе и ответе."""
    reflected = []
    
    # Извлекаем параметры из запроса
    params = extract_params_from_request(request)
    
    for param_name, param_values in params.items():
        for value in param_values:
            # Проверяем, отражается ли значение параметра в ответе
            if value and value in response:
                status = "Отражается"
                
                # Проверяем, содержит ли значение XSS-паттерны
                xss_payloads = detect_xss_payloads(value)
                if xss_payloads:
                    status = "Отражается с XSS-паттернами"
                
                reflected.append({
                    'param': param_name,
                    'value': value,
                    'status': status,
                    'xss_payloads': xss_payloads if xss_payloads else None
                })
    
    return reflected


def capture_traffic(hostname, timeout=30, output_file=None):
    """Перехватывает HTTP-трафик для указанного хоста."""
    dest_ip = resolve_hostname(hostname)
    if not dest_ip:
        print(f"Ошибка: не удалось разрешить имя хоста '{hostname}'")
        return None
    
    print(f"Начало перехвата трафика для {hostname} ({dest_ip})...")
    print(f"Таймаут: {timeout} секунд\n")
    
    try:
        # Простой фильтр для HTTP/HTTPS трафика
        bpf_filter = f"host {dest_ip} and tcp port 80"
        
        print(f"Используется фильтр: {bpf_filter}")
        print("Ожидание трафика...")
        
        # Захватываем пакеты
        packets = sniff(
            filter=bpf_filter,
            timeout=timeout,
            store=1
        )
        
        print(f"\nПерехвачено пакетов: {len(packets)}")
    
    except Exception as e:
        print(f"Ошибка при перехвате трафика: {e}")
        return None
    
    if output_file and packets:
        wrpcap(output_file, packets)
        print(f"Трафик сохранен в {output_file}")
    
    # Извлекаем HTTP-данные из пакетов
    http_data = extract_http_data(packets)
    
    # Выводим первые несколько HTTP-сообщений
    for i, data in enumerate(http_data[:3], 1):
        print(f"\nHTTP-сообщение {i} (первые 300 символов):")
        print("-" * 40)
        print(data[:300])
        if len(data) > 300:
            print("...")
    
    return packets


def analyze_packets(packets):
    """Базовый анализ перехваченных пакетов."""
    if not packets:
        print("Нет пакетов для анализа")
        return
    
    # Извлекаем HTTP-данные
    http_data = extract_http_data(packets)
    
    http_requests = []
    http_responses = []
    
    for data in http_data:
        # Определяем, это запрос или ответ
        if data.startswith(('GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS')):
            http_requests.append(data)
        elif data.startswith('HTTP/'):
            http_responses.append(data)
    
    print(f"\nНайдено HTTP-запросов: {len(http_requests)}")
    print(f"Найдено HTTP-ответов: {len(http_responses)}")
    
    # Анализ на наличие XSS
    xss_findings = []
    
    # Анализ запросов
    print("\n" + "="*60)
    print("Анализ XSS-уязвимостей")
    print("="*60)
    
    for i, req in enumerate(http_requests[:5], 1):
        print(f"\nЗапрос {i}:")
        print("-"*40)
        
        # Обнаружение XSS в запросах
        detected_xss = detect_xss_payloads(req)
        if detected_xss:
            print(f" Обнаружены потенциальные XSS-полезные нагрузки:")
            for payload in detected_xss:
                print(f"     - {html.escape(payload[:80])}...")
            xss_findings.append({
                'type': 'REQUEST',
                'payloads': detected_xss,
                'request_num': i
            })
        else:
            print(" В запросе XSS-паттернов не обнаружено")
    
    # Анализ ответов и поиск отраженных XSS
    min_length = min(len(http_requests), len(http_responses))
    if min_length > 0:
        for i in range(min(min_length, 3)):
            req = http_requests[i]
            resp = http_responses[i] if i < len(http_responses) else ""
            print(f"\nАнализ отраженных XSS {i+1}:")
            print("-"*40)
            
            reflected = check_reflected_xss(req, resp)
            if reflected:
                print(f"Обнаружены отраженные параметры:")
                for reflection in reflected:
                    print(f"     Параметр: {reflection['param']}")
                    print(f"     Значение: {html.escape(reflection['value'][:50])}...")
                    if reflection['xss_payloads']:
                        print(f"     Статус: {reflection['status']}")
                        for payload in reflection['xss_payloads']:
                            print(f"       - XSS: {html.escape(payload[:60])}...")
                    else:
                        print(f"     Статус: {reflection['status']}")
                    print()
            else:
                print("Отраженных параметров не обнаружено")
    else:
        print("\nНедостаточно данных для анализа отраженных XSS")


def analyze_saved_traffic(pcap_file):
    """Анализирует сохраненный трафик из .pcap файла."""
    print(f"Анализ трафика из файла: {pcap_file}")
    packets = rdpcap(pcap_file)
    analyze_packets(packets)


def main():
    parser = argparse.ArgumentParser(
        description='Анализ XSS-уязвимостей с использованием Scapy',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
            Примеры использования:
            # Отправка HTTP-запроса
            sudo python3 scapy_xss_analyzer1.py --send google-gruyere.appspot.com/399356804224192777396200670406347847059
            
            # Перехват трафика
            sudo python3 scapy_xss_analyzer1.py --capture google-gruyere.appspot.com --timeout 60 --output traffic.pcap
            
            # Анализ сохраненного трафика
            sudo python3 scapy_xss_analyzer1.py --analyze traffic.pcap
        """
    )
    
    parser.add_argument(
        '--send',
        metavar='URL',
        help='Отправить HTTP-запрос на указанный URL'
    )
    
    parser.add_argument(
        '--capture',
        metavar='HOSTNAME',
        help='Перехватить трафик для указанного хоста'
    )
    
    parser.add_argument(
        '--analyze',
        metavar='PCAP_FILE',
        help='Проанализировать сохраненный трафик из .pcap файла'
    )
    
    parser.add_argument(
        '--timeout',
        type=int,
        default=30,
        help='Таймаут для перехвата трафика в секундах (по умолчанию: 30)'
    )
    
    parser.add_argument(
        '--output',
        metavar='FILE',
        help='Имя файла для сохранения перехваченного трафика'
    )
    
    parser.add_argument(
        '--request',
        metavar='HTTP_REQUEST',
        help='Кастомный HTTP-запрос (для этапа 3)'
    )
    
    args = parser.parse_args()
    
    # Проверка аргументов
    if not any([args.send, args.capture, args.analyze]):
        parser.print_help()
        return
    
    # Отправка HTTP-запроса
    if args.send:
        hostname, path, scheme = parse_url(args.send)
        if not hostname:
            print("Ошибка: не удалось распарсить URL")
            return
        
        print(f"Отправка HTTP-запроса на {hostname}{path}")
        result = send_http_request(hostname, path, args.request)
        if result:
            print("HTTP-запрос отправлен")
        else:
            print("Ошибка при отправке HTTP-запроса")
    
    # Перехват трафика
    if args.capture:
        packets = capture_traffic(args.capture, args.timeout, args.output)
        if packets:
            analyze_packets(packets)
    
    # Анализ сохраненного трафика
    if args.analyze:
        analyze_saved_traffic(args.analyze)


if __name__ == '__main__':
    main()