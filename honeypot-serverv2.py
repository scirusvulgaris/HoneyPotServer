#!/usr/bin/env python3
import socket
import select
import os
import argparse
import sys
import resource
import time
from datetime import datetime
import struct

# Augmenter les limites au maximum détecté
try:
    resource.setrlimit(resource.RLIMIT_NOFILE, (65536, 65536))
except:
    pass

class ConnectionAnalyzer:
    """Analyse les connexions en détail"""
    
    @staticmethod
    def analyze_data(data, port, protocol='TCP'):
        """Analyse les données reçues"""
        if not data:
            return "Aucune donnée"
        
        decoded = data.decode('utf-8', errors='ignore')
        
        # Détection du protocole
        detected_protocol = ConnectionAnalyzer.detect_protocol(decoded, port, data)
        
        # Analyse du contenu
        analysis = {
            'protocol': detected_protocol,
            'transport': protocol,
            'size': len(data),
            'printable': len([c for c in decoded if c.isprintable()]),
            'lines': decoded.count('\n') + 1,
            'contains_credentials': ConnectionAnalyzer.check_credentials(decoded),
            'suspicious_patterns': ConnectionAnalyzer.check_suspicious(decoded),
            'first_line': decoded.split('\n')[0][:100] if decoded else "",
            'is_dns': ConnectionAnalyzer.is_dns_query(data) if port == 53 else False
        }
        
        return analysis
    
    @staticmethod
    def is_dns_query(data):
        """Vérifie si c'est une requête DNS"""
        if len(data) < 12:
            return False
        
        try:
            # Header DNS : ID(2) + Flags(2) + QDCOUNT(2) + ANCOUNT(2) + NSCOUNT(2) + ARCOUNT(2)
            header = struct.unpack('!HHHHHH', data[:12])
            transaction_id, flags, questions, answers, authority, additional = header
            
            # Vérifier que c'est une requête (QR bit = 0)
            qr_bit = (flags >> 15) & 1
            return qr_bit == 0 and questions > 0
        except:
            return False
    
    @staticmethod
    def parse_dns_query(data):
        """Parse une requête DNS pour extraire le nom de domaine"""
        if len(data) < 12:
            return "Invalid DNS query"
        
        try:
            # Skip header (12 bytes)
            offset = 12
            domain_parts = []
            
            while offset < len(data):
                length = data[offset]
                if length == 0:
                    break
                if length > 63:  # Compression pointer
                    break
                
                offset += 1
                if offset + length > len(data):
                    break
                
                part = data[offset:offset + length].decode('utf-8', errors='ignore')
                domain_parts.append(part)
                offset += length
            
            domain = '.'.join(domain_parts) if domain_parts else "unknown"
            return domain
        except:
            return "parse_error"
    
    @staticmethod
    def detect_protocol(data, port, raw_data):
        """Détecte le protocole basé sur le port et les données"""
        data_lower = data.lower()
        
        # Protocoles basés sur le port
        port_protocols = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
            53: 'DNS', 80: 'HTTP', 110: 'POP3', 143: 'IMAP',
            443: 'HTTPS', 993: 'IMAPS', 995: 'POP3S',
            3306: 'MySQL', 5432: 'PostgreSQL', 1433: 'MSSQL'
        }
        
        # Détection spéciale pour DNS
        if port == 53 and ConnectionAnalyzer.is_dns_query(raw_data):
            return 'DNS'
        
        # Détection basée sur le contenu
        if data.startswith('GET ') or data.startswith('POST '):
            return 'HTTP'
        elif data.startswith('SSH-'):
            return 'SSH'
        elif 'user ' in data_lower or 'pass ' in data_lower:
            return 'FTP/Telnet'
        elif data.startswith('\x16\x03'):  # TLS handshake
            return 'TLS/SSL'
        elif port in port_protocols:
            return port_protocols[port]
        else:
            return 'Unknown'
    
    @staticmethod
    def check_credentials(data):
        """Vérifie la présence de credentials"""
        cred_patterns = ['user', 'pass', 'login', 'admin', 'root', 'password']
        return [pattern for pattern in cred_patterns if pattern in data.lower()]
    
    @staticmethod
    def check_suspicious(data):
        """Vérifie les patterns suspects"""
        suspicious = ['../../../', 'union select', 'drop table', '<script>', 'eval(', 'system(']
        return [pattern for pattern in suspicious if pattern in data.lower()]

class HoneyPot:
    def __init__(self, start_port=1, end_port=65535, exclude_ports=None):
        self.start_port = start_port
        self.end_port = end_port
        self.exclude_ports = exclude_ports or []
        self.tcp_sockets = []
        self.udp_sockets = []
        self.tcp_port_map = {}
        self.udp_port_map = {}
        self.active_ports = set()
        self.max_sockets = 30000  # Réduire car on a TCP + UDP
        self.use_kqueue = hasattr(select, 'kqueue')
        self.connection_count = 0
        self.start_time = time.time()
        self.connections_log = []
        self.ip_stats = {}
        
    def setup_sockets(self):
        """Configure tous les sockets TCP et UDP"""
        print(f"[+] Configuration des ports {self.start_port}-{self.end_port}...")
        print(f"[*] Limite système: {self.max_sockets} sockets TCP + UDP")
        
        socket_count = 0
        
        for port in range(self.start_port, self.end_port + 1):
            if port in self.exclude_ports:
                continue
            
            if socket_count >= self.max_sockets:
                print(f"[!] Limite de sécurité atteinte ({self.max_sockets} sockets)")
                break
            
            # TCP Socket
            try:
                tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                tcp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                tcp_sock.bind(('0.0.0.0', port))
                tcp_sock.listen(5)
                tcp_sock.setblocking(False)
                
                self.tcp_sockets.append(tcp_sock)
                self.tcp_port_map[tcp_sock] = port
                self.active_ports.add(port)
                socket_count += 1
                
            except Exception as e:
                if "Address already in use" in str(e):
                    self.exclude_ports.append(port)
                elif "Too many open files" in str(e):
                    print(f"[!] Limite TCP atteinte au port {port}")
                    break
            
            # UDP Socket (seulement pour certains ports importants)
            if port in [53, 67, 68, 69, 123, 161, 162, 514] and socket_count < self.max_sockets:
                try:
                    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    udp_sock.bind(('0.0.0.0', port))
                    udp_sock.setblocking(False)
                    
                    self.udp_sockets.append(udp_sock)
                    self.udp_port_map[udp_sock] = port
                    socket_count += 1
                    
                except Exception as e:
                    if "Too many open files" in str(e):
                        print(f"[!] Limite UDP atteinte au port {port}")
                        break
        
        print(f"[*] Écoute TCP active sur {len(self.tcp_sockets)} ports")
        print(f"[*] Écoute UDP active sur {len(self.udp_sockets)} ports")
        if len(self.exclude_ports) > 0:
            excluded_count = len([p for p in self.exclude_ports if self.start_port <= p <= self.end_port])
            print(f"[*] {excluded_count} ports exclus (déjà utilisés)")

    def get_ip_info(self, ip):
        """Obtient des infos sur l'IP"""
        if ip not in self.ip_stats:
            self.ip_stats[ip] = {
                'first_seen': time.time(),
                'connections': 0,
                'ports': set(),
                'protocols': set()
            }
        return self.ip_stats[ip]

    def print_status(self):
        """Affiche le statut périodique"""
        uptime = int(time.time() - self.start_time)
        hours = uptime // 3600
        minutes = (uptime % 3600) // 60
        seconds = uptime % 60
        
        print(f"\n[📊] === STATUT HONEYPOT ===")
        print(f"    Uptime: {hours:02d}:{minutes:02d}:{seconds:02d}")
        print(f"    Connexions totales: {self.connection_count}")
        print(f"    Ports TCP: {len(self.tcp_sockets)} | UDP: {len(self.udp_sockets)}")
        print(f"    IPs uniques: {len(self.ip_stats)}")
        
        # Top 5 des IPs les plus actives
        if self.ip_stats:
            top_ips = sorted(self.ip_stats.items(), key=lambda x: x[1]['connections'], reverse=True)[:5]
            print(f"    Top IPs:")
            for ip, stats in top_ips:
                print(f"      {ip}: {stats['connections']} connexions, {len(stats['ports'])} ports")

    def handle_tcp_connection(self, sock):
        """Gère une connexion TCP"""
        client = None
        connection_successful = False
        
        try:
            client, address = sock.accept()
            connection_successful = True
            port = self.tcp_port_map[sock]
            
            ip = address[0]
            client_port = address[1]
            
            self.connection_count += 1
            ip_info = self.get_ip_info(ip)
            ip_info['connections'] += 1
            ip_info['ports'].add(port)
            
            print(f"\n[🔍] === CONNEXION TCP #{self.connection_count} ===")
            print(f"    Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"    Source: {ip}:{client_port} → TCP/{port}")
            print(f"    IP Stats: {ip_info['connections']} connexions, {len(ip_info['ports'])} ports")
            
            # Lire les données
            data_received = False
            analysis = None
            raw_data = b''
            
            try:
                client.settimeout(3)
                for attempt in range(2):
                    try:
                        chunk = client.recv(2048)
                        if chunk:
                            raw_data += chunk
                            data_received = True
                        else:
                            break
                    except socket.timeout:
                        break
                    except:
                        break
                
                if data_received and raw_data:
                    analysis = ConnectionAnalyzer.analyze_data(raw_data, port, 'TCP')
                    ip_info['protocols'].add(analysis['protocol'])
                    
                    print(f"    ✅ Données TCP: {len(raw_data)} bytes")
                    print(f"    Protocole: {analysis['protocol']}")
                    
                    if analysis['first_line']:
                        print(f"    Première ligne: {analysis['first_line']}")
                    
                    if analysis['contains_credentials']:
                        print(f"    🚨 CREDENTIALS: {analysis['contains_credentials']}")
                    
                    # Réponse
                    response = self.generate_tcp_response(port, analysis)
                    if response:
                        try:
                            client.send(response.encode())
                            print(f"    📤 Réponse TCP envoyée: {len(response)} bytes")
                        except:
                            print(f"    ❌ Erreur envoi réponse TCP")
                else:
                    print(f"    ⚡ Scan TCP rapide")
                    try:
                        response = f"220 Service ready on port {port}\r\n"
                        client.send(response.encode())
                        print(f"    📤 Réponse TCP basique envoyée")
                    except:
                        pass
                
            except Exception as e:
                print(f"    ❌ Erreur TCP: {str(e)}")
            
            print(f"    🔚 Connexion TCP fermée")
            
        except Exception as e:
            if connection_successful:
                print(f"    ❌ Erreur traitement TCP: {str(e)}")
        finally:
            if client:
                try:
                    client.close()
                except:
                    pass

    def handle_udp_data(self, sock):
        """Gère les données UDP"""
        try:
            data, address = sock.recvfrom(4096)
            port = self.udp_port_map[sock]
            
            ip = address[0]
            client_port = address[1]
            
            self.connection_count += 1
            ip_info = self.get_ip_info(ip)
            ip_info['connections'] += 1
            ip_info['ports'].add(port)
            
            print(f"\n[📡] === PAQUET UDP #{self.connection_count} ===")
            print(f"    Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"    Source: {ip}:{client_port} → UDP/{port}")
            print(f"    Taille: {len(data)} bytes")
            
            if data:
                analysis = ConnectionAnalyzer.analyze_data(data, port, 'UDP')
                ip_info['protocols'].add(analysis['protocol'])
                
                print(f"    Protocole: {analysis['protocol']}")
                
                # Traitement spécial DNS
                if port == 53 and analysis['is_dns']:
                    domain = ConnectionAnalyzer.parse_dns_query(data)
                    print(f"    🌐 Requête DNS pour: {domain}")
                    
                    # Générer réponse DNS
                    dns_response = self.generate_dns_response(data, domain)
                    if dns_response:
                        try:
                            sock.sendto(dns_response, address)
                            print(f"    📤 Réponse DNS envoyée: {len(dns_response)} bytes")
                        except Exception as e:
                            print(f"    ❌ Erreur envoi DNS: {e}")
                
                # Afficher données si intéressantes
                if len(data) > 10 or analysis['protocol'] != 'Unknown':
                    hex_data = ' '.join([f'{b:02x}' for b in data[:32]])
                    print(f"    Hex: {hex_data}{'...' if len(data) > 32 else ''}")
            
            print(f"    🔚 Paquet UDP traité")
            
        except Exception as e:
            print(f"    ❌ Erreur UDP: {str(e)}")

    def generate_dns_response(self, query_data, domain):
        """Génère une réponse DNS basique"""
        if len(query_data) < 12:
            return None
        
        try:
            # Copier l'ID de transaction
            response = bytearray(query_data[:2])
            
            # Flags: Response (QR=1), Authoritative (AA=1), No error (RCODE=0)
            response.extend([0x84, 0x00])  # 10000100 00000000
            
            # Questions count (same as query)
            response.extend(query_data[4:6])
            
            # Answer count (1 answer)
            response.extend([0x00, 0x01])
            
            # Authority and Additional (0)
            response.extend([0x00, 0x00, 0x00, 0x00])
            
            # Copy question section
            question_start = 12
            question_end = question_start
            while question_end < len(query_data) and query_data[question_end] != 0:
                length = query_data[question_end]
                question_end += length + 1
            question_end += 5  # null byte + QTYPE + QCLASS
            
            response.extend(query_data[question_start:question_end])
            
            # Answer section
            # Name (pointer to question)
            response.extend([0xc0, 0x0c])
            
            # Type A (0x0001)
            response.extend([0x00, 0x01])
            
            # Class IN (0x0001)
            response.extend([0x00, 0x01])
            
            # TTL (300 seconds)
            response.extend([0x00, 0x00, 0x01, 0x2c])
            
            # Data length (4 bytes for IPv4)
            response.extend([0x00, 0x04])
            
            # IP Address (fake: 127.0.0.1)
            response.extend([127, 0, 0, 1])
            
            return bytes(response)
            
        except Exception as e:
            print(f"    ❌ Erreur génération DNS: {e}")
            return None

    def generate_tcp_response(self, port, analysis):
        """Génère une réponse TCP réaliste"""
        if not analysis:
            return f"220 Service ready on port {port}\r\n"
        
        protocol = analysis['protocol']
        
        responses = {
            'HTTP': "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)\r\nContent-Type: text/html\r\n\r\n<html><body>Welcome</body></html>",
            'SSH': "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n",
            'FTP': "220 Welcome to FTP Server\r\n",
            'SMTP': "220 mail.example.com ESMTP Postfix\r\n",
            'DNS': "DNS over TCP not commonly used\r\n",
            'Telnet': "Ubuntu 20.04.3 LTS\r\nlogin: "
        }
        
        return responses.get(protocol, f"220 {protocol} Service ready\r\n")

    def run_with_kqueue(self):
        """Utilise kqueue pour TCP et UDP"""
        print(f"[*] Mode kqueue - TCP: {len(self.tcp_sockets)}, UDP: {len(self.udp_sockets)}")
        
        kq = select.kqueue()
        fd_to_sock = {}
        
        # Enregistrer tous les sockets TCP
        for sock in self.tcp_sockets:
            fd = sock.fileno()
            kevent = select.kevent(fd, select.KQ_FILTER_READ, select.KQ_EV_ADD)
            kq.control([kevent], 0)
            fd_to_sock[fd] = ('tcp', sock)
        
        # Enregistrer tous les sockets UDP
        for sock in self.udp_sockets:
            fd = sock.fileno()
            kevent = select.kevent(fd, select.KQ_FILTER_READ, select.KQ_EV_ADD)
            kq.control([kevent], 0)
            fd_to_sock[fd] = ('udp', sock)
        
        print("[🍯] Honeypot TCP/UDP actif")
        print("[💡] Testez avec: dig 1.1.1.1 @VOTRE_IP")
        
        last_status = time.time()
        
        try:
            while True:
                events = kq.control(None, 100, 1)
                
                for event in events:
                    if event.filter == select.KQ_FILTER_READ:
                        sock_info = fd_to_sock.get(event.ident)
                        if sock_info:
                            sock_type, sock = sock_info
                            if sock_type == 'tcp':
                                self.handle_tcp_connection(sock)
                            elif sock_type == 'udp':
                                self.handle_udp_data(sock)
                
                if time.time() - last_status >= 60:
                    self.print_status()
                    last_status = time.time()
                        
        except KeyboardInterrupt:
            print("\n[-] Arrêt du honeypot...")
        finally:
            kq.close()

    def run(self):
        """Démarre le honeypot"""
        print("[+] 🍯 Honeypot TCP/UDP Server")
        print("=" * 60)
        
        self.setup_sockets()
        
        if not self.tcp_sockets and not self.udp_sockets:
            print("[-] Aucun port disponible")
            return
        
        print(f"[*] Méthode: {'kqueue' if self.use_kqueue else 'select()'}")
        print("[*] Appuyez sur Ctrl+C pour arrêter")
        print("=" * 60)
        
        try:
            if self.use_kqueue:
                self.run_with_kqueue()
            else:
                print("[-] Mode select() non implémenté pour UDP")
        except Exception as e:
            print(f"[-] Erreur: {str(e)}")
        finally:
            self.cleanup()

    def cleanup(self):
        """Nettoie les ressources"""
        print(f"\n[📊] === STATISTIQUES FINALES ===")
        print(f"    Durée: {int(time.time() - self.start_time)} secondes")
        print(f"    Connexions: {self.connection_count}")
        print(f"    Sockets TCP: {len(self.tcp_sockets)}")
        print(f"    Sockets UDP: {len(self.udp_sockets)}")
        
        print(f"[*] Fermeture des sockets...")
        for sock in self.tcp_sockets + self.udp_sockets:
            try:
                sock.close()
            except:
                pass
        print("[✅] Honeypot arrêté")

def get_common_ports():
    return [22, 25, 80, 110, 143, 443, 993, 995, 3306, 5432, 1433, 3689]

def main():
    parser = argparse.ArgumentParser(description='🍯 Honeypot TCP/UDP')
    parser.add_argument('-s', '--start', type=int, default=1024, help='Port de début')
    parser.add_argument('-e', '--end', type=int, default=65535, help='Port de fin')
    parser.add_argument('--all-ports', action='store_true', help='Inclure ports 1-1023')
    
    args = parser.parse_args()
    
    if args.all_ports or args.start < 1024:
        if os.geteuid() != 0:
            print("[-] Root requis pour ports < 1024")
            sys.exit(1)
        args.start = 1
    
    exclude_ports = get_common_ports()
    honeypot = HoneyPot(args.start, args.end, exclude_ports)
    honeypot.run()

if __name__ == "__main__":
    main()