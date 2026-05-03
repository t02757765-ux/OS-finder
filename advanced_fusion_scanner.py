#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ADVANCED FUSION OS & SERVICE SCANNER (AFOSS)
Entegre Araçlar: Masscan, Nmap, Netcat, Özel Python Modülleri
Özellikler: Çok katmanlı tarama, çapraz doğrulama, OS tahmini, zafiyet analizi.
"""

import argparse
import subprocess
import sys
import os
import re
import socket
import struct
import time
from datetime import datetime
from collections import Counter
import threading

# Renk Tanımları
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    YELLOW = '\033[93m'
    RED = '\033[91m'

def print_banner():
    banner = f"""
{Colors.CYAN}╔══════════════════════════════════════════════════════════╗
║  {Colors.BOLD}ADVANCED FUSION OS & SERVICE SCANNER (AFOSS){Colors.ENDC}{Colors.CYAN}          ║
║  Entegre: Masscan, Nmap, Netcat, Special Probes      ║
╚══════════════════════════════════════════════════════════╝{Colors.ENDC}
    """
    print(banner)

def check_tool(tool_name):
    """Aracın sistemde yüklü olup olmadığını kontrol eder."""
    try:
        subprocess.run(["which", tool_name], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        return True
    except subprocess.CalledProcessError:
        return False

def run_masscan(target, ports="1-65535", rate=1000):
    """Masscan ile hızlı port taraması yapar."""
    print(f"{Colors.BLUE}[+] Masscan ile hızlı port taraması başlatılıyor...{Colors.ENDC}")
    if not check_tool("masscan"):
        print(f"{Colors.WARNING}[!] Masscan bulunamadı. Bu adım atlanıyor.{Colors.ENDC}")
        return []

    cmd = [
        "sudo", "masscan", target,
        "-p", ports,
        "--rate", str(rate),
        "--open",
        "-oG", "-"  # Grepable output
    ]
    
    open_ports = []
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        lines = result.stdout.split('\n')
        for line in lines:
            if "open" in line:
                parts = line.split()
                if len(parts) >= 4:
                    port = int(parts[2].split('/')[0])
                    proto = parts[3]
                    open_ports.append({"port": port, "proto": proto, "source": "Masscan"})
        print(f"{Colors.GREEN}[✓] Masscan {len(open_ports)} açık port buldu.{Colors.ENDC}")
    except subprocess.TimeoutExpired:
        print(f"{Colors.FAIL}[!] Masscan taraması zaman aşımına uğradı.{Colors.ENDC}")
    except Exception as e:
        print(f"{Colors.FAIL}[!] Masscan hatası: {e}{Colors.ENDC}")
    
    return open_ports

def run_nmap(target, ports_list, version_detect=True, os_detect=True):
    """Nmap ile detaylı servis ve OS taraması yapar."""
    print(f"{Colors.BLUE}[+] Nmap ile detaylı analiz başlatılıyor...{Colors.ENDC}")
    if not check_tool("nmap"):
        print(f"{Colors.WARNING}[!] Nmap bulunamadı.{Colors.ENDC}")
        return [], {}, []

    port_str = ",".join([str(p['port']) for p in ports_list])
    if not port_str:
        return [], {}, []

    cmd = ["sudo", "nmap", "-sV", "-sC", "-T4"]
    if os_detect:
        cmd.append("-O")
    if version_detect:
        cmd.extend(["--version-intensity", "5"])
    
    # Script güvenlik kontrolü için bazı scriptleri dahil et
    cmd.extend(["--script", "banner,http-title,ssh-hostkey,ssl-cert"])
    cmd.extend(["-p", port_str, target])

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        output = result.stdout + result.stderr
        
        # Parse Ports and Services
        services = []
        port_pattern = re.compile(r"(\d+)/(\w+)\s+open\s+(\w*)\s*(.*)")
        for line in output.split('\n'):
            match = port_pattern.search(line)
            if match:
                port = int(match.group(1))
                proto = match.group(2)
                state = match.group(3)
                service_info = match.group(4).strip()
                services.append({
                    "port": port,
                    "proto": proto,
                    "service": service_info,
                    "source": "Nmap"
                })

        # Parse OS Matches
        os_matches = []
        os_section = False
        for line in output.split('\n'):
            if "OS details:" in line or "Aggressive OS guesses:" in line:
                os_section = True
                continue
            if os_section:
                if "Network Distance" in line or line.strip() == "":
                    os_section = False
                    continue
                # OS satırlarını temizle
                clean_line = line.replace("Aggressive OS guesses:", "").replace("OS details:", "").strip()
                if clean_line and not clean_line.startswith("No exact"):
                    # Yüzde bilgisini ayıkla (varsa)
                    percent_match = re.search(r"\((\d+)%\)", clean_line)
                    percent = percent_match.group(1) if percent_match else "N/A"
                    os_name = re.sub(r"\s*\(\d+%\)", "", clean_line).strip()
                    if os_name:
                        os_matches.append({"name": os_name, "confidence": percent, "source": "Nmap"})
        
        # Parse Service Info OS
        service_info_os = []
        for line in output.split('\n'):
            if "Service Info:" in line and "OS:" in line:
                parts = line.split("OS:")
                if len(parts) > 1:
                    os_candidate = parts[1].split(';')[0].strip()
                    if os_candidate and os_candidate != "Unknown":
                        service_info_os.append({"name": os_candidate, "confidence": "High (Service Info)", "source": "Nmap-ServiceInfo"})

        all_os = os_matches + service_info_os
        
        print(f"{Colors.GREEN}[✓] Nmap analizi tamamlandı. {len(services)} servis, {len(all_os)} OS tahmini.{Colors.ENDC}")
        return services, all_os, output

    except subprocess.TimeoutExpired:
        print(f"{Colors.FAIL}[!] Nmap taraması zaman aşımına uğradı.{Colors.ENDC}")
        return [], [], ""
    except Exception as e:
        print(f"{Colors.FAIL}[!] Nmap hatası: {e}{Colors.ENDC}")
        return [], [], ""

def run_netcat_banner(target, ports_list, timeout=2):
    """Netcat kullanarak manuel banner grabbing yapar."""
    print(f"{Colors.BLUE}[+] Netcat ile banner grabbing yapılıyor...{Colors.ENDC}")
    if not check_tool("nc"):
        # nc yoksa python socket kullan
        print(f"{Colors.WARNING}[!] 'nc' bulunamadı, Python socket fallback kullanılıyor.{Colors.ENDC}")
        return python_socket_grab(target, ports_list, timeout)

    banners = []
    for item in ports_list:
        port = item['port']
        try:
            # Echo gönderip cevap alma denemesi
            cmd = ["echo", ""] 
            # nc -v -w timeout target port
            # Basit bağlantı ve ilk veriyi oku
            process = subprocess.Popen(
                ["nc", "-v", "-w", str(timeout), target, str(port)],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            # Biraz bekleyip kapat
            time.sleep(0.5)
            stdout, stderr = process.communicate(input="", timeout=timeout+1)
            
            banner_data = stdout.strip()
            if not banner_data:
                banner_data = stderr.strip() # Bazen hata çıktısında bilgi olur
            
            if banner_data and "open" not in banner_data.split('\n')[0]: # "Connection open" gibi mesajları filtrele
                 # Sadece ilk satırı al ki çok uzun olmasın
                first_line = banner_data.split('\n')[0][:100]
                if first_line:
                    banners.append({"port": port, "banner": first_line, "source": "Netcat"})
        except Exception:
            pass # Hataları sessizce geç, diğer portlara devam et

    if not banners:
        # NC başarısız olduysa python fallback dene
        return python_socket_grab(target, ports_list, timeout)
        
    print(f"{Colors.GREEN}[✓] Netcat ile {len(banners)} banner yakalandı.{Colors.ENDC}")
    return banners

def python_socket_grab(target, ports_list, timeout=2):
    """Python socket kütüphanesi ile banner grabbing (Netcat alternatifi)."""
    banners = []
    for item in ports_list:
        port = item['port']
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((target, port))
            
            # Bazı servisler veri göndermeden bekler, bazıları hemen gönderir.
            # HTTP gibi protokoller için basit bir istek gönderelim.
            if port in [80, 8080, 443, 8443]:
                sock.send(f"GET / HTTP/1.0\r\nHost: {target}\r\n\r\n".encode())
            elif port == 21:
                sock.send(b"QUIT\r\n")
            
            time.sleep(0.5)
            try:
                data = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                if data:
                    first_line = data.split('\n')[0][:100]
                    banners.append({"port": port, "banner": first_line, "source": "Python-Socket"})
            except socket.timeout:
                pass
            finally:
                sock.close()
        except Exception:
            pass
    return banners

def special_probes(target, ports_list):
    """Özel Python tabanlı prob yöntemleri (TCP Stack Fingerprinting benzeri)."""
    print(f"{Colors.BLUE}[+] Özel prob yöntemleri çalıştırılıyor...{Colors.ENDC}")
    findings = []
    
    for item in ports_list:
        port = item['port']
        if port == 80 or port == 443 or port == 8080:
            # HTTP Header Analizi
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                sock.connect((target, port))
                req = f"HEAD / HTTP/1.1\r\nHost: {target}\r\nUser-Agent: AFOSS-Scanner\r\nConnection: close\r\n\r\n"
                sock.send(req.encode())
                resp = sock.recv(4096).decode('utf-8', errors='ignore')
                sock.close()
                
                headers = resp.split('\r\n')
                server_header = ""
                powered_by = ""
                os_hints = []
                
                for h in headers:
                    if h.lower().startswith("server:"):
                        server_header = h.split(":", 1)[1].strip()
                    if h.lower().startswith("x-powered-by:"):
                        powered_by = h.split(":", 1)[1].strip()
                    if h.lower().startswith("x-aspnet-version:"):
                        os_hints.append("Windows (ASP.NET)")
                    if h.lower().startswith("x-drupal-cache"):
                        os_hints.append("Linux/Unix (Drupal)")
                
                if server_header:
                    findings.append({
                        "port": port,
                        "type": "HTTP-Header",
                        "data": f"Server: {server_header}",
                        "source": "Special-Probe"
                    })
                    if "Apache" in server_header and "Unix" in server_header:
                        os_hints.append("Unix/Linux")
                    elif "IIS" in server_header or "Microsoft" in server_header:
                        os_hints.append("Windows")
                        
                if powered_by:
                     findings.append({
                        "port": port,
                        "type": "X-Powered-By",
                        "data": powered_by,
                        "source": "Special-Probe"
                    })
                
                for hint in os_hints:
                    findings.append({
                        "port": port,
                        "type": "OS-Hint",
                        "data": hint,
                        "source": "Special-Probe"
                    })

            except Exception:
                pass
    
    return findings

def analyze_vulnerabilities(services, banners):
    """Basit zafiyet analizi (Versiyon bazlı)."""
    vulns = []
    known_bad_versions = {
        "vsftpd 2.3.4": "Backdoor (CVE-2011-2523)",
        "Samba 3.5.0": "Usermap Command Execution (CVE-2012-1182)",
        "OpenSSH 4.3": "Eski sürüm, şifreleme zayıf olabilir",
        "Apache 2.2": "Eski sürüm, DoS açıkları mevcut olabilir",
        "Windows 2000": "Destek sonu, kritik açıklar var",
        "Windows XP": "Destek sonu, kritik açıklar var"
    }
    
    all_strings = []
    for s in services:
        all_strings.append(s.get('service', ''))
    for b in banners:
        all_strings.append(b.get('banner', ''))
        
    for text in all_strings:
        for bad_ver, vuln_desc in known_bad_versions.items():
            if bad_ver.lower() in text.lower():
                vulns.append({"match": bad_ver, "vulnerability": vuln_desc})
    
    return vulns

def fusion_engine(nmap_os, special_os, nmap_services, banners):
    """Tüm sonuçları birleştirir, tekrarları siler ve en iyisini seçer."""
    print(f"\n{Colors.HEADER}{'='*60}")
    print(f"  FUSION ENGINE: SONUÇLAR BİRLEŞTİRİLİYOR VE ANALİZ EDİLİYOR")
    print(f"{'='*60}{Colors.ENDC}\n")

    # 1. OS Birleştirme ve Puanlama
    os_counter = Counter()
    os_sources = {}
    
    # Nmap sonuçları (Zaten puanlı olabilir ama burada basit sayıyoruz)
    for os in nmap_os:
        name = os['name']
        conf = os['confidence']
        os_counter[name] += 1
        if name not in os_sources: os_sources[name] = []
        os_sources[name].append(f"Nmap ({conf})")
        
    # Özel Proplar
    for item in special_os:
        if item['type'] == 'OS-Hint':
            name = item['data']
            os_counter[name] += 2 # Özel prob bulgularına daha fazla ağırlık
            if name not in os_sources: os_sources[name] = []
            os_sources[name].append("Special-Probe")

    final_os_list = []
    if os_counter:
        # En çok geçen ilk 5 OS
        for os_name, count in os_counter.most_common(5):
            sources = ", ".join(os_sources[os_name])
            score = min(100, count * 20) # Basit skorlama
            final_os_list.append({"name": os_name, "score": score, "sources": sources})
    else:
        final_os_list.append({"name": "Tespit Edilemedi", "score": 0, "sources": "Hiçbir araç veri sağlayamadı"})

    # 2. Servis ve Banner Birleştirme
    merged_services = {}
    for s in nmap_services:
        key = s['port']
        merged_services[key] = {
            "port": s['port'],
            "proto": s['proto'],
            "service": s['service'],
            "banner": None,
            "sources": ["Nmap"]
        }
    
    for b in banners:
        key = b['port']
        if key in merged_services:
            merged_services[key]['banner'] = b['banner']
            merged_services[key]['sources'].append(b['source'])
        else:
            merged_services[key] = {
                "port": b['port'],
                "proto": "tcp",
                "service": "Unknown",
                "banner": b['banner'],
                "sources": [b['source']]
            }

    return final_os_list, list(merged_services.values())

def main():
    parser = argparse.ArgumentParser(description="Advanced Fusion OS & Service Scanner")
    parser.add_argument("-t", "--target", required=True, help="Hedef IP veya Domain")
    parser.add_argument("-p", "--ports", default="1-1000", help="Masscan için port aralığı (örn: 1-65535 veya 22,80,443)")
    parser.add_argument("-r", "--rate", type=int, default=500, help="Masscan hızı (paket/sn)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Detaylı çıktı")
    args = parser.parse_args()

    print_banner()
    target = args.target
    print(f"{Colors.BOLD}Hedef:{Colors.ENDC} {target}")
    print(f"{Colors.BOLD}Başlangıç Zamanı:{Colors.ENDC} {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    # 1. Katman: Masscan (Hızlı Port Bulma)
    masscan_ports = run_masscan(target, ports=args.ports, rate=args.rate)
    
    # Eğer Masscan hiçbir şey bulamazsa veya yoksa, yaygın portları dene
    if not masscan_ports:
        print(f"{Colors.WARNING}[!] Masscan sonuç boş veya yok. Yaygın portlarda Nmap ile devam ediliyor...{Colors.ENDC}")
        common_ports = [{"port": p, "proto": "tcp", "source": "Default"} for p in [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 8080]]
        # Nmap'in kendi port taramasını kullanmak için boş liste bırakabiliriz ama biz manuel verdik
        # Nmap fonksiyonu bu listeyi kullanacak
        scan_targets = common_ports
    else:
        scan_targets = masscan_ports

    # 2. Katman: Nmap (Derinlemesine Analiz)
    nmap_services, nmap_os, nmap_raw = run_nmap(target, scan_targets)

    # 3. Katman: Netcat / Socket (Banner Grabbing)
    banners = run_netcat_banner(target, scan_targets)

    # 4. Katman: Özel Proplar
    special_findings = special_probes(target, scan_targets)
    special_os = [x for x in special_findings if x['type'] == 'OS-Hint']

    # 5. Katman: Zafiyet Analizi
    vulns = analyze_vulnerabilities(nmap_services, banners)

    # 6. Katman: Fusion Engine (Birleştirme)
    final_os, final_services = fusion_engine(nmap_os, special_os, nmap_services, banners)

    # --- SONUÇLARI YAZDIR ---
    
    print(f"\n{Colors.BOLD}{Colors.GREEN}╔══════════════════════════════════════════════════════════╗")
    print(f"║  SONUÇ RAPORU: {target}{Colors.ENDC}")
    print(f"{Colors.GREEN}╚══════════════════════════════════════════════════════════╝{Colors.ENDC}")

    # OS Sonuçları
    print(f"\n{Colors.CYAN}[🖥️]  İŞLETİM SİSTEMİ TAHMİNLERİ (Fusion Score):{Colors.ENDC}")
    print("-" * 60)
    for os in final_os:
        bar_len = int(os['score'] / 5)
        bar = "█" * bar_len
        print(f"  {Colors.BOLD}{os['name']}{Colors.ENDC}")
        print(f"      Güven Skoru: {os['score']}% [{bar}]")
        print(f"      Kaynaklar: {os['sources']}")
        print()

    # Servis Sonuçları
    print(f"\n{Colors.CYAN}[🔌]  AÇIK SERVİSLER VE PORTLAR:{Colors.ENDC}")
    print("-" * 60)
    # Portlara göre sırala
    final_services.sort(key=lambda x: x['port'])
    for svc in final_services:
        print(f"  Port {svc['port']}/{svc['proto']}: {svc['service']}")
        if svc['banner']:
            print(f"      {Colors.YELLOW}Banner:{Colors.ENDC} {svc['banner']}")
        print(f"      {Colors.BLUE}Kaynaklar:{Colors.ENDC} {', '.join(svc['sources'])}")
        print()

    # Zafiyetler
    if vulns:
        print(f"\n{Colors.FAIL}[⚠️]  POTANSİYEL GÜVENLİK AÇIKLARI:{Colors.ENDC}")
        print("-" * 60)
        for v in vulns:
            print(f"  {Colors.RED}✗{Colors.ENDC} Eşleşen: {v['match']}")
            print(f"    Risk: {v['vulnerability']}")
            print()
    else:
        print(f"\n{Colors.GREEN}[✓] Bilinen basit imzalara sahip kritik zafiyet bulunamadı.{Colors.ENDC}")

    print(f"\n{Colors.BOLD}Tarama Tamamlandı.{Colors.ENDC}")

if __name__ == "__main__":
    # Root yetkisi kontrolü (Masscan ve Nmap OS detection için gerekli)
    if sys.platform != "win32" and os.geteuid() != 0:
        print(f"{Colors.WARNING}[!] Uyarı: Masscan ve Nmap OS tespiti için root yetkisi önerilir.")
        print("Bazı özellikler çalışmayabilir. Lütfen 'sudo' ile çalıştırın.\n")
    
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.FAIL}[!] Kullanıcı tarafından iptal edildi.{Colors.ENDC}")
        sys.exit(1)
    except Exception as e:
        print(f"\n{Colors.FAIL}[!] Beklenmeyen hata: {e}{Colors.ENDC}")
        sys.exit(1)
