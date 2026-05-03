#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import subprocess
import sys
import re
import socket
import os
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

# Renklandırma için kütüphane kontrolü
try:
    from colorama import init, Fore, Style
    init(autoreset=True)
except ImportError:
    print("Lütfen colorama kütüphanesini yükleyin: pip install colorama")
    sys.exit(1)

try:
    from scapy.all import IP, TCP, sr1, conf
    conf.verb = 0  # Scapy sessiz mod
except ImportError:
    print("Lütfen scapy kütüphanesini yükleyin: pip install scapy")
    sys.exit(1)

class AdvancedScanner:
    def __init__(self, target, verbose=False):
        self.target = target
        self.verbose = verbose
        self.results = {
            "os_guess": [],
            "open_ports": [],
            "services": [],
            "vulnerabilities": [],
            "traffic_hints": []
        }

    def log(self, message, level="INFO"):
        """Renkli log mesajları"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        if level == "INFO":
            color = Fore.CYAN
        elif level == "SUCCESS":
            color = Fore.GREEN
        elif level == "WARNING":
            color = Fore.YELLOW
        elif level == "ERROR":
            color = Fore.RED
        else:
            color = Fore.WHITE
        
        print(f"{color}[{timestamp}] [{level}] {Style.RESET_ALL}{message}")

    def resolve_host(self):
        """IP veya Hostname çözümleme"""
        try:
            ip = socket.gethostbyname(self.target)
            self.log(f"Hedef çözümlendi: {self.target} -> {ip}", "SUCCESS")
            return ip
        except socket.gaierror:
            self.log(f"Hedef çözümlenemedi: {self.target}", "ERROR")
            return None

    def scan_with_nmap(self):
        """Nmap ile derinlemesine tarama (OS, Servis, Versiyon)"""
        self.log("Nmap ile tarama başlatılıyor (OS Dedektörü, Servis Versiyonu)...", "INFO")
        try:
            # -O: OS tespiti, -sV: Servis versiyonu, -Pn: Ping yok say (bazen firewall engeller)
            cmd = f"nmap -O -sV -Pn --version-intensity 5 {self.target}"
            process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, stderr = process.communicate()
            
            if stdout:
                return self.parse_nmap_output(stdout)
            else:
                self.log(f"Nmap hatası: {stderr}", "ERROR")
                return None
        except Exception as e:
            self.log(f"Nmap çalıştırılamadı: {e}", "ERROR")
            return None

    def parse_nmap_output(self, output):
        """Nmap çıktısını parse ederek yapılandırılmış veri elde etme"""
        data = {"raw": output, "os": [], "ports": []}
        
        # OS Tespiti Parse
        os_matches = re.findall(r"OS details: (.+)", output)
        if not os_matches:
            os_matches = re.findall(r"Running: (.+)", output)
        
        if os_matches:
            data["os"] = [match.strip() for match in os_matches]
            self.results["os_guess"].extend(data["os"])
            self.log(f"Nmap OS Tahmini: {', '.join(data['os'])}", "SUCCESS")

        # Port ve Servis Parse
        port_pattern = re.compile(r"(\d+)/tcp\s+open\s+(\w+)\s+(.*)")
        for match in port_pattern.finditer(output):
            port = match.group(1)
            service = match.group(2)
            version = match.group(3).strip()
            data["ports"].append({"port": port, "service": service, "version": version})
            self.results["open_ports"].append(port)
            self.results["services"].append(f"{service} v{version}")
            
            # Basit zafiyet kontrolü (Versiyon bazlı uyarı)
            self.check_basic_vulns(service, version, port)

        return data

    def custom_tcp_probe(self, ip, ports=[21, 22, 80, 443]):
        """Scapy ile özel TCP prob göndererek banner yakalama"""
        self.log("Özel TCP Probları gönderiliyor (Scapy)...", "INFO")
        found_banners = []
        
        for port in ports:
            try:
                packet = IP(dst=ip)/TCP(dport=port, flags="S")
                response = sr1(packet, timeout=2)
                
                if response and response.haslayer(TCP):
                    if response[TCP].flags == 0x12: # SYN-ACK
                        # Port açık, şimdi Banner almak için ACK gönderelim (basit simülasyon)
                        # Gerçek banner grab için bağlantı kurulması gerekir, burada sadece port durumunu teyit ediyoruz.
                        found_banners.append(port)
                        self.log(f"Port {port} açık (Scapy Teyidi)", "SUCCESS")
                        
                        # Özel FTP/SSH Banner Grab denemesi (Socket ile)
                        banner = self.grab_banner(ip, port)
                        if banner:
                            self.log(f"Banner Yakalandı ({port}): {banner}", "WARNING")
                            self.results["traffic_hints"].append(banner)
                            
            except Exception as e:
                continue
        return found_banners

    def grab_banner(self, ip, port):
        """Basit Banner Grabbing"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect((ip, port))
            s.send(b"GET /\r\n\r\n" if port == 80 else b"\r\n") # HTTP veya genel prob
            banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
            s.close()
            return banner[:100] # İlk 100 karakter
        except:
            return None

    def check_basic_vulns(self, service, version, port):
        """Bilinen eski sürümler için basit potansiyel zafiyet kontrolü"""
        vulns = []
        version_lower = version.lower()
        
        if "ftp" in service and ("vsftpd 2.3.4" in version_lower or "proftpd" in version_lower):
            vulns.append("Potansiyel Backdoor (VSFTPD 2.3.4 / ProFTPD)")
        
        if "smb" in service and ("windows 2000" in version_lower or "windows xp" in version_lower):
            vulns.append("EternalBlue (MS17-010) Olasılığı Yüksek")
            
        if "apache" in service and ("2.4.49" in version or "2.4.50" in version):
            vulns.append("Path Traversal (CVE-2021-41773)")

        if "ssh" in service and ("OpenSSH 4.3" in version or "OpenSSH 5.3" in version):
            vulns.append("Eski SSH Sürümü (Kaba Kuvvet Saldırısına Açık)")

        if vulns:
            for v in vulns:
                self.results["vulnerabilities"].append(f"Port {port} ({service}): {v}")
                self.log(f"UYARI: {v}", "WARNING")

    def compare_results(self, nmap_data, scapy_ports):
        """Nmap ve Özel Tarama sonuçlarını karşılaştırıp en doğruyu sunma"""
        self.log("\n--- SONUÇ KARŞILAŞTIRMASI VE DOĞRULAMA ---", "INFO")
        
        nmap_ports = set([p['port'] for p in nmap_data.get('ports', [])]) if nmap_data else set()
        scapy_ports = set([str(p) for p in scapy_ports])
        
        common = nmap_ports.intersection(scapy_ports)
        only_nmap = nmap_ports - scapy_ports
        only_scapy = scapy_ports - nmap_ports

        print(f"\n{Fore.GREEN}Ortak Doğrulanan Açık Portlar:{Style.RESET_ALL} {common}")
        if only_nmap:
            print(f"{Fore.YELLOW}Sadece Nmap Buldu (Firewall Scapy'yi engellemiş olabilir):{Style.RESET_ALL} {only_nmap}")
        if only_scapy:
            print(f"{Fore.YELLOW}Sadece Özel Prob Buldu (Nmap Filtrelemiş olabilir):{Style.RESET_ALL} {only_scapy}")

    def generate_report(self):
        """Nihai Raporu Oluştur"""
        print("\n" + "="*60)
        print(f"{Fore.MAGENTA}>>> NİHAİ TARAMA RAPORU: {self.target} <<<{Style.RESET_ALL}")
        print("="*60)

        # İşletim Sistemi
        print(f"\n{Fore.CYAN}[+] İşletim Sistemi Tahminleri:{Style.RESET_ALL}")
        if self.results["os_guess"]:
            # Tekilleştir ve yaz
            unique_os = list(set(self.results["os_guess"]))
            for os in unique_os:
                print(f"    - {os}")
        else:
            print("    - Belirlenemedi.")

        # Servisler ve Portlar
        print(f"\n{Fore.CYAN}[+] Açık Servisler ve Portlar:{Style.RESET_ALL}")
        if self.results["services"]:
            for svc in self.results["services"]:
                print(f"    {Fore.GREEN}✓{Style.RESET_ALL} {svc}")
        else:
            print("    - Açık servis bulunamadı.")

        # Potansiyel Zafiyetler
        print(f"\n{Fore.RED}[+] Potansiyel Güvenlik Riskleri / Zafiyetler:{Style.RESET_ALL}")
        if self.results["vulnerabilities"]:
            for vuln in self.results["vulnerabilities"]:
                print(f"    {Fore.RED}!{Style.RESET_ALL} {vuln}")
        else:
            print("    - Bilinen basit imzalı risk bulunamadı.")

        # Ek Bilgiler (Traffic/Banner)
        if self.results["traffic_hints"]:
            print(f"\n{Fore.CYAN}[+] Yakalanan Banner/Trafik İpuçları:{Style.RESET_ALL}")
            for hint in self.results["traffic_hints"]:
                print(f"    > {hint}")

        print("\n" + "="*60)
        print(f"{Fore.YELLOW}Not: Bu rapor otomatize edilmiştir. Manuel doğrulama önerilir.{Style.RESET_ALL}")
        print("="*60 + "\n")

def main():
    parser = argparse.ArgumentParser(
        description="Gelişmiş İşletim Sistemi ve Servis Keşif Aracı (Nmap + Özel Prob)",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Örnek Kullanımlar:
  python advanced_os_scanner.py -t 192.168.1.1
  python advanced_os_scanner.py -t google.com -v
  python advanced_os_scanner.py --target 10.0.0.5 --full

Özellikler:
  - Nmap entegrasyonu (OS, Servis Versiyonu)
  - Scapy ile özel TCP prob gönderimi
  - Banner Grabbing
  - Sonuçların Çapraz Doğrulaması
  - Potansiyel Zafiyet Tespiti (CVE Bazlı Basit Kontrol)
  - Renkli CLI Çıktısı
        """
    )
    
    parser.add_argument('-t', '--target', required=True, help='Hedef IP adresi veya Domain (Örn: 192.168.1.1)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Detaylı çıktı modu')
    parser.add_argument('--skip-nmap', action='store_true', help='Nmap taramasını atla (Sadece özel prob)')
    parser.add_argument('--ports', type=str, default='21,22,80,443,445,3389', help='Özel prob için port listesi (virgülle ayrılmış)')

    args = parser.parse_args()

    print(f"{Fore.BLUE}Gelişmiş OS & Servis Tarayıcı Başlatılıyor...{Style.RESET_ALL}")
    
    scanner = AdvancedScanner(args.target, args.verbose)
    target_ip = scanner.resolve_host()
    
    if not target_ip:
        sys.exit(1)

    nmap_data = None
    if not args.skip_nmap:
        # Nmap genellikle root yetkisi ister (-O flagi nedeniyle)
        try:
            nmap_data = scanner.scan_with_nmap()
        except PermissionError:
            scanner.log("Nmap OS tespiti için Root/Admin yetkisi gerekebilir. Alternatif yöntemlere geçiliyor.", "WARNING")
    
    # Özel Port Taraması
    custom_ports = [int(p) for p in args.ports.split(',')]
    scanner.custom_tcp_probe(target_ip, custom_ports)

    # Karşılaştırma
    if nmap_data:
        scanner.compare_results(nmap_data, scanner.results["open_ports"])
    else:
        scanner.log("Nmap verisi olmadığı için karşılaştırma yapılamadı.", "WARNING")

    # Rapor
    scanner.generate_report()

if __name__ == "__main__":
    # Root kontrolü (Scapy ve Nmap -O için gereklidir)
    if sys.platform != "win32" and os.geteuid() != 0:
        print(f"{Fore.YELLOW}UYARI: Tam özellikli tarama (OS tespiti, RAW paketler) için Root yetkisi önerilir.{Style.RESET_ALL}")
        print("Lütfen 'sudo python3 advanced_os_scanner.py ...' ile çalıştırın.\n")

    import os
    main()
