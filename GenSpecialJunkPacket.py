import socket
import struct
import random
import secrets
import time
import threading
import json
import os
import sys
import logging
import shutil
from concurrent.futures import ThreadPoolExecutor, as_completed

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

class WireGuardPacketTester:
    def __init__(self, cycles=1):
        self.working_packets = {}
        self.lock = threading.Lock()
        self.total_packets = 0
        self.tested_packets = 0
        self.success_count = 0
        self.failed_count = 0
        self.target_host = os.getenv("AWG_TARGET_HOST", "engage.cloudflareclient.com")
        self.target_port = int(os.getenv("AWG_TARGET_PORT", "4500"))
        self.cycles = cycles
        self.google_domains = [
            "google.com", "www.google.com", "drive.google.com", 
            "docs.google.com", "mail.google.com", "accounts.google.com",
            "photos.google.com", "youtube.com", "gmail.com"
        ]
        self.sip_user_agents = [
            "Linphone/5.0.0", "Zoiper 5.0.0", "MicroSIP/3.0.0",
            "Bria 5.0.0", "Zephyr 2.0.0"
        ]

    def print_progress(self, current, total, status=''):
        bar_length = 50
        progress = float(current) / float(total)
        filled_length = int(round(bar_length * progress))
        bar = '█' * filled_length + '░' * (bar_length - filled_length)
        stats = f"Успешно: {self.success_count} | Ошибки: {self.failed_count}"
        text = f"\r[{bar}] {progress * 100:.2f}% | {stats} | {status}"
        sys.stdout.write(text)
        sys.stdout.flush()

    def test_packet(self, packet_data, protocol_name):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(5)
            
            try:
                sock.sendto(packet_data, (self.target_host, self.target_port))
                response, addr = sock.recvfrom(2048)
                return True, [f"{self.target_host}:{self.target_port}"]
            except socket.timeout:
                return True, [f"{self.target_host}:{self.target_port}"]
            finally:
                sock.close()
                    
        except Exception as e:
            log.exception("test_packet failed: %s", e)
            return False, []

    def generate_sip_register(self):
        call_id = secrets.token_hex(16)
        branch = f"z9hG4bK{secrets.token_hex(12)}"
        tag = secrets.token_hex(8)
        user_agent = random.choice(self.sip_user_agents)
        expires = random.randint(1800, 7200)
        
        sip_packet = f"""REGISTER sip:google.com SIP/2.0
Via: SIP/2.0/UDP 192.168.{random.randint(1,255)}.{random.randint(1,255)}:5060;branch={branch}
Max-Forwards: 70
To: <sip:user@google.com>
From: <sip:user@google.com>;tag={tag}
Call-ID: {call_id}
CSeq: 1 REGISTER
Contact: <sip:user@192.168.{random.randint(1,255)}.{random.randint(1,255)}:5060>
User-Agent: {user_agent}
Expires: {expires}
Content-Length: 0

""".replace('\n', '\r\n').encode()
        
        return sip_packet

    def generate_tls_client_hello(self, hostname):
        version = b'\x03\x03'
        random_bytes = secrets.token_bytes(32)
        session_id_len = random.randint(0, 32)
        session_id = secrets.token_bytes(session_id_len)
        
        cipher_suites = [
            b'\x13\x02', b'\x13\x03', b'\xc0\x2c', b'\xc0\x30', 
            b'\xcc\xa9', b'\xcc\xa8', b'\xc0\x2b', b'\xc0\x2f'
        ]
        cipher_suite = random.choice(cipher_suites)
        cipher_suites_data = b'\x00\x02' + cipher_suite
        
        compression = b'\x01\x00'
        
        server_name = hostname.encode()
        sni_ext = b'\x00\x00' + struct.pack('>H', len(server_name) + 5) + b'\x00' + struct.pack('>H', len(server_name) + 3) + b'\x00' + struct.pack('>H', len(server_name)) + server_name
        
        extensions = sni_ext + b'\x00\x0b\x00\x04\x03\x00\x01\x02\x00\x0a\x00\x0a\x00\x08' + secrets.token_bytes(8)
        
        handshake_content = version + random_bytes + bytes([session_id_len]) + session_id + cipher_suites_data + compression + struct.pack('>H', len(extensions)) + extensions
        handshake = b'\x01' + struct.pack('>I', len(handshake_content))[1:] + handshake_content
        
        record = b'\x16' + version + struct.pack('>H', len(handshake)) + handshake
        return record

    def generate_tls_server_combined(self):
        """Упрощенный и корректный TLS Server Hello"""
        try:
            version = b'\x03\x03'  
            
           
            server_random = secrets.token_bytes(32)
            
            
            session_id_len = random.randint(0, 16)
            session_id = bytes([session_id_len]) + secrets.token_bytes(session_id_len) if session_id_len > 0 else b'\x00'
            
            
            cipher_suites = [
                b'\x13\x01',  
                b'\x13\x02',  
                b'\x13\x03',  
                b'\xc0\x2c',  
            ]
            cipher_suite = random.choice(cipher_suites)
            
            
            compression = b'\x00'
            
            
            extensions = b''
            
            
            server_hello_content = version + server_random + session_id + cipher_suite + compression
            extensions_len = struct.pack('>H', len(extensions))
            server_hello_content += extensions_len + extensions
            
            
            handshake_type = b'\x02'  
            handshake_len = struct.pack('>I', len(server_hello_content))[1:]  
            handshake = handshake_type + handshake_len + server_hello_content
            
            
            record_type = b'\x16'  
            record_version = b'\x03\x03'  
            record_len = struct.pack('>H', len(handshake))
            
            record = record_type + record_version + record_len + handshake
            
            return record
            
        except Exception as e:
            
            return b'\x16\x03\x03\x00\x31\x02\x00\x00\x2d\x03\x03' + secrets.token_bytes(32) + b'\x00\x13\x02\x00\x00'

    def generate_tls_client_combined(self):
       
        key_data = secrets.token_bytes(128)
        client_key_exchange = b'\x10' + struct.pack('>I', len(key_data))[1:] + key_data
        
       
        change_cipher_spec = b'\x14\x03\x03\x00\x01\x01'
        
       
        finished_data = secrets.token_bytes(52)
        finished = b'\x16\x03\x03' + struct.pack('>H', len(finished_data)) + finished_data
        
        return client_key_exchange + change_cipher_spec + finished

    HTTP_USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Safari/605.1.15",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.81 Safari/537.36 Edg/94.0.992.47",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.164 Safari/537.36",
    ]

    def generate_http_over_tls(self):
        """Корректные HTTP запросы поверх TLS"""
        try:
            http_methods = ['GET', 'POST', 'HEAD']
            http_paths = ['/', '/search', '/mail', '/drive', '/photos', '/images', '/favicon.ico']
            rng = secrets.SystemRandom()
            method = rng.choice(http_methods)
            path = rng.choice(http_paths)
            host = rng.choice(self.google_domains)
            user_agent = rng.choice(self.HTTP_USER_AGENTS)
            http_request = f"{method} {path} HTTP/1.1\r\n".encode()
            http_request += f"Host: {host}\r\n".encode()
            http_request += f"User-Agent: {user_agent}\r\n".encode()
            http_request += b"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n"
            http_request += b"Accept-Language: en-US,en;q=0.5\r\n"
            http_request += b"Accept-Encoding: gzip, deflate, br\r\n"
            http_request += b"Connection: keep-alive\r\n"
            
            
            if method == 'POST':
                http_request += b"Content-Type: application/x-www-form-urlencoded\r\n"
                http_request += b"Content-Length: 0\r\n"
            
            http_request += b"\r\n"
            
           
            tls_header = b'\x17\x03\x03' 
            tls_payload_len = struct.pack('>H', len(http_request))
            
            return tls_header + tls_payload_len + http_request
            
        except Exception as e:
            
            fallback_request = b"GET / HTTP/1.1\r\nHost: google.com\r\n\r\n"
            return b'\x17\x03\x03' + struct.pack('>H', len(fallback_request)) + fallback_request

    def generate_cycle_packets(self, cycle_num):
        packets = {}
        rng = secrets.SystemRandom()
        domain = rng.choice(self.google_domains)
        def delay():
            time.sleep(0.005 + rng.uniform(0, 0.02))
        packets[f"I1_c{cycle_num}"] = self.generate_sip_register()
        delay()
        packets[f"I2_c{cycle_num}"] = self.generate_tls_client_hello(domain)
        delay()
        packets[f"I3_c{cycle_num}"] = self.generate_tls_server_combined()
        delay()
        packets[f"I4_c{cycle_num}"] = self.generate_tls_client_combined()
        delay()
        packets[f"I5_c{cycle_num}"] = self.generate_http_over_tls()
        return packets

    def run_test(self):
        print("🔧 WireGuard Packet Tester - Запуск тестирования")
        print(f"🎯 Целевой сервер: {self.target_host}:{self.target_port}")
        print(f"🔄 Количество циклов: {self.cycles}")
        
        all_packets_dict = {}
        for cycle in range(1, self.cycles + 1):
            cycle_packets = self.generate_cycle_packets(cycle)
            all_packets_dict.update(cycle_packets)
        
        packets_list = []
        for key, value in all_packets_dict.items():
            packets_list.append((value, key))
        
        self.total_packets = len(packets_list)
        self.tested_packets = 0
        self.success_count = 0
        self.failed_count = 0
        
        print(f"📦 Сгенерировано {self.total_packets} пакетов ({self.cycles} циклов)")
        print("🔄 Начало тестирования...")
        
        with ThreadPoolExecutor(max_workers=100) as executor:
            future_to_packet = {
                executor.submit(self._test_with_timeout, packet_data, protocol_name, 10): (packet_data, protocol_name) 
                for packet_data, protocol_name in packets_list
            }
            
            for future in as_completed(future_to_packet):
                packet_data, protocol_name = future_to_packet[future]
                try:
                    result, successful_services = future.result()
                    
                    if result and successful_services:
                        with self.lock:
                            packet_hex = f"<b 0x{packet_data.hex()}>"
                            self.working_packets[protocol_name] = packet_hex
                            self.success_count += 1
                    else:
                        self.failed_count += 1
                
                except Exception:
                    self.failed_count += 1
                
                self.tested_packets += 1
                status = f"Текущий: {protocol_name}"
                self.print_progress(self.tested_packets, self.total_packets, status)
        
        print(f"\n\n📊 Результаты тестирования:")
        print(f"   ✅ Успешных пакетов: {self.success_count}")
        print(f"   ❌ Неудачных пакетов: {self.failed_count}")
        print(f"   📨 Всего протестировано: {self.tested_packets}")
        
        return self.working_packets

    def _test_with_timeout(self, packet_data, protocol_name, timeout=10):
        result = [None]
        def test_func():
            result[0] = self.test_packet(packet_data, protocol_name)
        t = threading.Thread(target=test_func, daemon=True)
        t.start()
        t.join(timeout=timeout)
        return result[0] if result[0] is not None else (False, [])

    def save_working_packets(self, filename="packets.json"):
        try:
            current_dir = os.path.dirname(os.path.abspath(__file__))
            filepath = os.path.join(current_dir, filename)
            
            sorted_packets = {}
            for cycle in range(1, self.cycles + 1):
                for i in range(1, 6):
                    key = f"I{i}_c{cycle}"
                    if key in self.working_packets:
                        sorted_packets[key] = self.working_packets[key]
            
            output_data = {
                "dataset_id": secrets.token_hex(8),
                "generated_at": time.time(),
                "cycles": self.cycles,
                "packets": sorted_packets,
            }
            
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(output_data, f, indent=2, ensure_ascii=False)
            
            print(f"💾 Файл с {len(sorted_packets)} пакетами сохранен: {filepath}")

            web_dir = os.path.join(current_dir, "web")
            default_target = os.path.join(web_dir, "I-list1.json")
            try:
                answer = input(
                    f"Скопировать результат в {default_target}? [y/N]: "
                ).strip().lower()
            except EOFError:
                answer = ""

            if answer == "y":
                try:
                    os.makedirs(web_dir, exist_ok=True)
                    shutil.copy2(filepath, default_target)
                    print(f"📁 Результат скопирован в {default_target}")
                except Exception as copy_err:
                    print(f"❌ Не удалось скопировать файл в {default_target}: {copy_err}")

            return True
            
        except Exception as e:
            print(f"❌ Ошибка сохранения: {e}")
            return False

def main():
    print("🚀 WireGuard Packet Tester")
    print("=" * 60)
    
    try:
        cycles = int(input("Введите количество циклов: "))
        if cycles <= 0:
            cycles = 1
    except ValueError:
        cycles = 1
    
    tester = WireGuardPacketTester(cycles=cycles)
    
    start_time = time.time()
    working_packets = tester.run_test()
    end_time = time.time()
    
    print(f"\n⏱️  Время тестирования: {(end_time - start_time):.2f} секунд")
    
    if working_packets:
        tester.save_working_packets()
        print(f"\n✅ Найдено {len(working_packets)} рабочих пакетов")
    else:
        print("\n❌ Рабочие пакеты не обнаружены")

if __name__ == "__main__":
    main()
