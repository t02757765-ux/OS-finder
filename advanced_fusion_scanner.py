#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Advanced Fusion OS & Service Scanner (AFOSS)
Combines Nmap, Masscan, Netcat, Scapy and custom probes for deep analysis.
"""
import argparse
import subprocess
import sys
import re
import socket
import json
from datetime import datetime
from collections import defaultdict
import threading
import queue
# Renk Kodları
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
def log(message, level="INFO", verbose=False):
    if level == "ERROR":
        print(f"{Colors.FAIL}[ERROR]{Colors.ENDC} {message}")
    elif level == "WARNING":
        print(f"{Colors.WARNING}[WARN]{Colors.ENDC} {message}")
    elif level == "SUCCESS":
        print(f"{Colors.OKGREEN}[OK]{Colors.ENDC} {message}")
    elif level == "INFO" and verbose:
        print(f"{Colors.OKCYAN}[INFO]{Colors.ENDC} {message}")
    elif level == "DEBUG" and verbose:
        print(f"{Colors.HEADER}[DEBUG]{Colors.ENDC} {message}")
def check_tool_installed(tool_name):
    try:
        subprocess.run(["which", tool_name], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        return True
    except subprocess.CalledProcessError:
        return False
def run_masscan(target, ports="1-65535", rate=1000, verbose=False):
    """Runs Masscan and parses output."""
    print(f"\n{Colors.BOLD}>>> Masscan Hızlı Tarama Başlatılıyor...{Colors.ENDC}")
    if not check_tool_installed("masscan"):
        log("Masscan bulunamadı! Lütfen 'sudo apt install masscan' ile yükleyin.", "WARNING", verbose)
        return []
    cmd = ["sudo", "masscan", "-p", ports, target, "--rate", str(rate)]
    if verbose:
        log(f"Masscan Komutu: {' '.join(cmd)}", "DEBUG", True)
    found_ports = []
    try:
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = process.communicate(timeout=300)
        if verbose:
            log(f"Masscan Ham Çıktı:\n{stdout}", "DEBUG", True)
        # Masscan output format: "Discovered open port 80/tcp on host 192.168.1.1"
        for line in stdout.splitlines():
            match = re.search(r"Discovered open port (\d+)/(\w+) on host ([\d\.]+)", line)
            if match:
                port = int(match.group(1))
                proto = match.group(2)
                ip = match.group(3)
                if ip == target:
                    found_ports.append({'port': port, 'protocol': proto, 'state': 'open', 'source': 'Masscan'})
    except Exception as e:
        log(f"Masscan hatası: {str(e)}", "ERROR")
    
    return found_ports
def run_nmap(target, ports=None, version_detect=True, os_detect=True, verbose=False):
    """Runs Nmap with detailed service and OS detection."""
    print(f"\n{Colors.BOLD}>>> Nmap Detaylı Tarama Başlatılıyor...{Colors.ENDC}")
    if not check_tool_installed("nmap"):
        log("Nmap bulunamadı! Lütfen 'sudo apt install nmap' ile yükleyin.", "WARNING", verbose)
        return [], {}, []
    cmd = ["sudo", "nmap", "-Pn"]
    if ports:
        port_str = ",".join([str(p['port']) for p in ports]) if isinstance(ports, list) else ports
        cmd.extend(["-p", port_str])
    else:
        cmd.extend(["-p-", "--top-ports", "1000"])
    if version_detect:
        cmd.append("-sV")
    if os_detect:
        cmd.append("-O")
    if verbose:
        cmd.append("-vv")
        log(f"Nmap Komutu: {' '.join(cmd)}", "DEBUG", True)
    cmd.append(target)
    services = {}
    os_info = []
    try:
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        stdout, _ = process.communicate(timeout=600)
        if verbose:
            log(f"Nmap Ham Çıktı:\n{stdout}", "DEBUG", True)
        # Parse Services
        port_pattern = re.compile(r"^(\d+)/(\w+)\s+(open|filtered|closed)\s+(\S+)\s*(.*)?$")
        for line in stdout.splitlines():
            match = port_pattern.match(line.strip())
            if match:
                port_num = int(match.group(1))
                proto = match.group(2)
                state = match.group(3)
                service_name = match.group(4)
                version_info = match.group(5).strip() if match.group(5) else ""
                if state == 'open':
                    services[port_num] = {
                        'protocol': proto,
                        'service': service_name,
                        'version': version_info,
                        'source': 'Nmap'
                    }
        
        # Parse OS
        in_os_section = False
        for line in stdout.splitlines():
            if "OS details:" in line:
                in_os_section = True
                continue
            if in_os_section:
                if line.strip().startswith("Network Distance"):
                    break
                if "%" in line:
                    parts = line.split(":", 1)
                    if len(parts) == 2:
                        accuracy = parts[0].strip()
                        os_name = parts[1].strip()
                        os_info.append({'os': os_name, 'accuracy': accuracy, 'source': 'Nmap'})
        
        # Also check "Running:" section for alternative OS matches
        for line in stdout.splitlines():
            if "Running:" in line:
                running_part = line.split("Running:", 1)[1].strip()
                # Split by '|' for alternatives
                alternatives = running_part.split('|')
                for alt in alternatives:
                    os_info.append({'os': alt.strip(), 'accuracy': 'Yüksek', 'source': 'Nmap (Running)'})
                break
                
        # Check Service Info for OS hints
        for line in stdout.splitlines():
            if "Service Info:" in line and "OS:" in line:
                info_part = line.split("Service Info:", 1)[1].strip()
                os_match = re.search(r"OS:\s*([^;]+)", info_part)
                if os_match:
                    os_name = os_match.group(1).strip()
                    if os_name != "Unknown":
                        os_info.append({'os': os_name, 'accuracy': 'Servis Bazlı', 'source': 'Nmap (Service Info)'})
        return list(services.values()), os_info, []
    except Exception as e:
        log(f"Nmap hatası: {str(e)}", "ERROR")
        return [], [], []
def run_netcat_banner(target, ports, verbose=False):
    """Uses Netcat to grab banners from open ports."""
    print(f"\n{Colors.BOLD}>>> Netcat Banner Grabbing Başlatılıyor...{Colors.ENDC}")
    if not check_tool_installed("nc"):
        log("Netcat (nc) bulunamadı. Banner grabbing atlanıyor.", "WARNING", verbose)
        return {}
    banners = {}
    for port_info in ports:
        port = port_info['port']
        proto = port_info.get('protocol', 'tcp')
        if proto != 'tcp':
            continue
            
        try:
            cmd = ["nc", "-v", "-w", "2", target, str(port)]
            process = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                stdout, stderr = process.communicate(input="\n", timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                stdout, stderr = process.communicate()
            
            banner_data = (stdout + stderr).strip()
            if banner_
                banners[port] = banner_data
                if verbose:
                    log(f"Port {port} Banner:\n{banner_data}", "DEBUG", True)
        except Exception as e:
            if verbose:
                log(f"Port {port} Netcat hatası: {str(e)}", "WARNING", True)
    
    return banners
def custom_probe_scan(target, ports, verbose=False):
    """Custom simple socket probes for service detection."""
    print(f"\n{Colors.BOLD}>>> Özel Prob Taraması Başlatılıyor...{Colors.ENDC}")
    results = {}
    
    probes = {
        "HTTP": b"GET / HTTP/1.0\r\n\r\n",
        "SMTP": b"EHLO test.local\r\n",
        "FTP": b"USER anonymous\r\n",
    }
    for port_info in ports:
        port = port_info['port']
        proto = port_info.get('protocol', 'tcp')
        if proto != 'tcp':
            continue
        
        detected_service = None
        detected_banner = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((target, port))
            
            # Try to read initial banner
            try:
                initial_banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                if initial_banner:
                    detected_banner = initial_banner
            except socket.timeout:
                pass
            # If no banner, send probes
            if not detected_banner:
                for service_name, probe_data in probes.items():
                    sock.sendall(probe_data)
                    try:
                        response = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                        if response:
                            detected_service = service_name
                            detected_banner = response
                            break
                    except socket.timeout:
                        continue
            
            sock.close()
            
            if detected_service or detected_banner:
                results[port] = {
                    'service': detected_service,
                    'banner': detected_banner,
                    'source': 'CustomProbe'
                }
                if verbose:
                    log(f"Port {port} Özel Prob Sonucu: {detected_service}", "DEBUG", True)
        except Exception as e:
            if verbose:
                log(f"Port {port} Özel Prob Hatası: {str(e)}", "WARNING", True)
    
    return results
def analyze_vulnerabilities(service_name, version, banner):
    """Basit zafiyet analizi (örnek amaçlı)."""
    vulnerabilities = []
    search_text = f"{service_name} {version} {banner}".lower()
    
    if "vsftpd 2.3.4" in search_text:
        vulnerabilities.append({"id": "CVE-2011-2523", "severity": "CRITICAL", "description": "VSFTPD 2.3.4 Backdoor"})
    if "apache" in search_text and ("2.2." in search_text or "2.0." in search_text):
        vulnerabilities.append({"id": "GENERIC", "severity": "MEDIUM", "description": "Eski Apache sürümü potansiyel açıklara sahip olabilir."})
    if "openssh" in search_text and ("3." in search_text or "4." in search_text or "5." in search_text):
        vulnerabilities.append({"id": "GENERIC", "severity": "HIGH", "description": "Eski OpenSSH sürümü potansiyel açıklara sahip olabilir."})
        
    return vulnerabilities
def fusion_engine(masscan_results, nmap_services, nmap_os, netcat_banners, custom_probes, verbose=False):
    """Birleştirir, çakışmaları çözer ve en iyi sonucu üretir."""
    print(f"\n{Colors.BOLD}>>> Fusion Motoru Sonuçları Birleştiriyor...{Colors.ENDC}")
    
    final_ports = {}
    final_os = []
    all_vulnerabilities = []
    # 1. Port ve Servis Birleştirme
    for res in masscan_results:
        port = res['port']
        final_ports[port] = {
            'port': port,
            'protocol': res['protocol'],
            'state': res['state'],
            'service': 'unknown',
            'version': '',
            'banner': '',
            'sources': ['Masscan']
        }
    for svc in nmap_services:
        port = svc['port']
        if port in final_ports:
            final_ports[port]['service'] = svc.get('service', final_ports[port]['service'])
            final_ports[port]['version'] = svc.get('version', final_ports[port]['version'])
            final_ports[port]['sources'].append('Nmap')
        else:
            final_ports[port] = {
                'port': port,
                'protocol': svc.get('protocol', 'tcp'),
                'state': 'open',
                'service': svc.get('service', 'unknown'),
                'version': svc.get('version', ''),
                'banner': '',
                'sources': ['Nmap']
            }
    for port, banner in netcat_banners.items():
        if port in final_ports:
            final_ports[port]['banner'] = banner
            if 'Netcat' not in final_ports[port]['sources']:
                final_ports[port]['sources'].append('Netcat')
        else:
            final_ports[port] = {
                'port': port,
                'protocol': 'tcp',
                'state': 'open',
                'service': 'unknown',
                'version': '',
                'banner': banner,
                'sources': ['Netcat']
            }
    for port, probe_res in custom_probes.items():
        if port in final_ports:
            if probe_res.get('service') and final_ports[port]['service'] == 'unknown':
                final_ports[port]['service'] = probe_res['service']
            if probe_res.get('banner') and not final_ports[port]['banner']:
                final_ports[port]['banner'] = probe_res['banner']
            if 'CustomProbe' not in final_ports[port]['sources']:
                final_ports[port]['sources'].append('CustomProbe')
        else:
             final_ports[port] = {
                'port': port,
                'protocol': 'tcp',
                'state': 'open',
                'service': probe_res.get('service', 'unknown'),
                'version': '',
                'banner': probe_res.get('banner', ''),
                'sources': ['CustomProbe']
            }
    # 2. OS Bilgilerini Birleştirme
    final_os = nmap_os
    # 3. Zafiyet Analizi
    for port, info in final_ports.items():
        vulns = analyze_vulnerabilities(info['service'], info['version'], info['banner'])
        if vulns:
            info['vulnerabilities'] = vulns
            all_vulnerabilities.extend(vulns)
    return list(final_ports.values()), final_os, all_vulnerabilities
def print_report(target, ports, os_info, vulnerabilities, start_time, verbose=False):
    """Renkli ve detaylı rapor çıktısı."""
    end_time = datetime.now()
    duration = end_time - start_time
    print("\n" + "="*80)
    print(f"{Colors.BOLD}{Colors.OKBLUE}>>> AFOSS TARAMA RAPORU{Colors.ENDC}")
    print(f"{Colors.OKCYAN}Hedef:{Colors.ENDC} {target}")
    print(f"{Colors.OKCYAN}Tarih:{Colors.ENDC} {end_time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{Colors.OKCYAN}Süre:{Colors.ENDC} {duration}")
    print("="*80)
    print(f"\n{Colors.BOLD}{Colors.OKGREEN}>>> AÇIK PORTLAR VE SERVİSLER{Colors.ENDC}")
    if not ports:
        print(f"{Colors.WARNING}Hiçbir açık port veya servis bulunamadı.{Colors.ENDC}")
    else:
        ports.sort(key=lambda x: x['port'])
        for p in ports:
            port = p['port']
            proto = p['protocol']
            state = p['state']
            service = p.get('service', 'unknown')
            version = p.get('version', '')
            banner = p.get('banner', '')
            sources = ", ".join(p.get('sources', []))
            vulns = p.get('vulnerabilities', [])
            service_str = f"{service}"
            if version:
                service_str += f" ({version})"
            
            print(f"\n{Colors.BOLD}Port {port}/{proto}:{Colors.ENDC} {Colors.OKGREEN}{state}{Colors.ENDC}")
            print(f"  {Colors.OKCYAN}Servis:{Colors.ENDC} {service_str}")
            if banner:
                banner_display = banner[:100].replace('\n', ' ')
                if len(banner) > 100: banner_display += "..."
                print(f"  {Colors.OKCYAN}Banner:{Colors.ENDC} {banner_display}")
            print(f"  {Colors.OKCYAN}Kaynaklar:{Colors.ENDC} {sources}")
            
            if vulns:
                print(f"  {Colors.FAIL}⚠ POTANSİYEL AÇIKLIKLAR:{Colors.ENDC}")
                for v in vulns:
                    severity_color = Colors.FAIL if v['severity'] == 'CRITICAL' else (Colors.WARNING if v['severity'] == 'HIGH' else Colors.OKCYAN)
                    print(f"    {severity_color}[{v['severity']}]{Colors.ENDC} {v['id']}: {v['description']}")
    print(f"\n{Colors.BOLD}{Colors.OKGREEN}>>> İŞLETİM SİSTEMİ TAHMİNLERİ{Colors.ENDC}")
    if not os_info:
        print(f"{Colors.WARNING}İşletim sistemi hakkında kesin bir bilgi elde edilemedi.{Colors.ENDC}")
    else:
        for item in os_info:
            acc = item['accuracy']
            os_name = item['os']
            source = item.get('source', 'Bilinmiyor')
            acc_str = f"({acc})" if acc != 'N/A' else ""
            print(f"  • {os_name} {acc_str} {Colors.OKCYAN}[Kaynak: {source}]{Colors.ENDC}")
    if vulnerabilities:
        print(f"\n{Colors.BOLD}{Colors.FAIL}>>> GENEL ZAFİYET ÖZETİ{Colors.ENDC}")
        unique_vulns = {v['id']: v for v in vulnerabilities}.values()
        for v in unique_vulns:
            severity_color = Colors.FAIL if v['severity'] == 'CRITICAL' else (Colors.WARNING if v['severity'] == 'HIGH' else Colors.OKCYAN)
            print(f"  {severity_color}[{v['severity']}]{Colors.ENDC} {v['id']}: {v['description']}")
    
    print("\n" + "="*80)
    print(f"{Colors.OKGREEN}Tarama Tamamlandı.{Colors.ENDC}")
    print("="*80 + "\n")
def main():
    parser = argparse.ArgumentParser(description="Advanced Fusion OS & Service Scanner (AFOSS)")
    parser.add_argument("-t", "--target", required=True, help="Hedef IP adresi veya alan adı")
    parser.add_argument("-p", "--ports", default="1-65535", help="Taranacak portlar")
    parser.add_argument("-v", "--verbose", action="store_true", help="Detaylı çıktı modu")
    parser.add_argument("--no-masscan", action="store_true", help="Masscan taramasını atla")
    parser.add_argument("--no-nmap", action="store_true", help="Nmap taramasını atla")
    parser.add_argument("--no-nc", action="store_true", help="Netcat banner grabbing'i atla")
    parser.add_argument("--no-custom", action="store_true", help="Özel prob taramasını atla")
    parser.add_argument("--rate", type=int, default=1000, help="Masscan tarama hızı")
    args = parser.parse_args()
    print(f"{Colors.HEADER}")
    print(r"""
  ___  ____  _  ________      _________  ____  __
 / _ )/ __ \/ |/ /_  __/ | /|/ / ___/  |/  / |/ /
/ _  / /_/ /    / / /  | |/ / /__/ / /|_/ /    / 
/____/\____/_/|_/ /_/   |___/\___/_/  /__/_/|_|  
                                                 
Advanced Fusion OS & Service Scanner (AFOSS)
    """)
    print(f"{Colors.ENDC}")
    
    target = args.target
    verbose = args.verbose
    
    start_time = datetime.now()
    masscan_results = []
    nmap_services = []
    nmap_os = []
    netcat_banners = {}
    custom_probes = {}
    if not args.no_masscan:
        masscan_results = run_masscan(target, ports=args.ports, rate=args.rate, verbose=verbose)
    
    nmap_target_ports = masscan_results if masscan_results else args.ports
    if not args.no_nmap:
        nmap_services, nmap_os, _ = run_nmap(target, ports=nmap_target_ports, version_detect=True, os_detect=True, verbose=verbose)
    ports_for_probing = []
    seen_ports = set()
    for p in masscan_results:
        if p['port'] not in seen_ports:
            ports_for_probing.append(p)
            seen_ports.add(p['port'])
    for s in nmap_services:
        if s['port'] not in seen_ports:
            ports_for_probing.append({'port': s['port'], 'protocol': s.get('protocol', 'tcp'), 'state': 'open', 'source': 'Nmap'})
            seen_ports.add(s['port'])
    if ports_for_probing:
        if not args.no_nc:
            netcat_banners = run_netcat_banner(target, ports_for_probing, verbose=verbose)
        if not args.no_custom:
            custom_probes = custom_probe_scan(target, ports_for_probing, verbose=verbose)
    else:
        log("Taranacak port bulunamadı, ileriye dönük taramalar atlanıyor.", "WARNING", verbose)
    final_ports, final_os, final_vulns = fusion_engine(
        masscan_results, 
        nmap_services, 
        nmap_os, 
        netcat_banners, 
        custom_probes, 
        verbose=verbose
    )
    print_report(target, final_ports, final_os, final_vulns, start_time, verbose=verbose)
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}Kullanıcı tarafından iptal edildi.{Colors.ENDC}")
        sys.exit(130)
