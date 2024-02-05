# Scapy based Network Scanner
#!/usr/bin/python3

from scapy.all import *
from prettytable import PrettyTable
from mac_vendor_lookup import MacLookup
from argparse import ArgumentParser
import sys
import progressbar
from termcolor import colored
from pyfiglet import Figlet
import os
from style import *




class Sca_N_S:
    
    def logo():
        print( """
  ______                              __    __         ______  
 /      \                            /  \  /  |       /      \ 
/$$$$$$  |  _______   ______         $$  \ $$ |      /$$$$$$  |
$$ \__$$/  /       | /      \        $$$  \$$ |      $$ \__$$/ 
$$      \ /$$$$$$$/  $$$$$$  |       $$$$  $$ |      $$      \ 
 $$$$$$  |$$ |       /    $$ |       $$ $$ $$ |       $$$$$$  |
/  \__$$ |$$ \_____ /$$$$$$$ |       $$ |$$$$ |      /  \__$$ |
$$    $$/ $$       |$$    $$ |______ $$ | $$$ |______$$    $$/ 
 $$$$$$/   $$$$$$$/  $$$$$$$//      |$$/   $$//      |$$$$$$/  
                             $$$$$$/          $$$$$$/          
                                                               
                                                                                                                                          
                                            """  + """ THE TRI-ASTRA TOOL
""" )

    
    def __init__(self, hosts, ether_dst=None, arp_pdst=None, timeout=1, arp_scan=False, icmp_scan=False, tcp_scan=False, tcp_ports=None, detailed=False, output_file=None):
        
        self.hosts = hosts
        self.alive = {}
        self.timeout = timeout
        self.arp_scan = arp_scan
        self.icmp_scan = icmp_scan
        self.tcp_scan = tcp_scan
        self.tcp_ports = tcp_ports
        self.detailed = detailed
        self.output_file = output_file
        self.create_custom_packet(ether_dst, arp_pdst)
        self.send_packet()
        self.get_alive()
        self.print_banner()
        self.print_alive()
        if self.output_file:
            self.save_to_file()
        self.print_summary()

    def create_custom_packet(self, ether_dst=None, arp_pdst=None):
        layer1 = Ether(dst=ether_dst) if ether_dst is not None else Ether(dst="ff:ff:ff:ff:ff:ff")

        if self.arp_scan:
            layer2 = ARP(pdst=arp_pdst if arp_pdst else self.hosts)
        elif self.icmp_scan:
            layer2 = IP(dst=self.hosts) / ICMP()
        elif self.tcp_scan:
            if self.tcp_ports:
                layer2 = IP(dst=self.hosts) / TCP(dport=self.tcp_ports, flags="S")  # SYN scan
            else:
                layer2 = IP(dst=self.hosts) / TCP(dport=80, flags="S")  # Default to port 80 if no ports specified
        else:
            # Default to ARP scan if neither ARP, ICMP, nor TCP scan is specified
            layer2 = ARP(pdst=arp_pdst if arp_pdst else self.hosts)

        packet = layer1 / layer2
        self.packet = packet

    def send_packet(self):
        print(colored("Scanning...", "yellow"))
        if self.tcp_scan and self.tcp_ports:
            total_packets = len(self.tcp_ports)
        else:
            total_packets = 1

        with progressbar.ProgressBar(max_value=total_packets) as bar:
            answered, unanswered = srp(self.packet, timeout=self.timeout, verbose=False)
            if answered:
                self.answered = answered
            else:
                print(colored("No Host is Up.", "red"))
                sys.exit(1)

            bar.update(1)

    def get_alive(self):
        self.alive = {received.psrc: {"mac": received.hwsrc, "os_info": self.get_os_info(received.psrc)} for sent, received in self.answered}

    def get_os_info(self, ip):
        if self.detailed:
            # Use nmap to get OS information
            try:
                os_info = os.popen(f"nmap -O {ip} | grep 'Running'").read().strip()
                return os_info if os_info else "N/A"
            except:
                return "N/A"
        else:
            return "Hidden"

    def print_banner(self):
        fig = Figlet(font="slant")
        banner = fig.renderText("Sca_N_S")
        colored_banner = colored(banner, "green")
        print(colored_banner)
        print("Welcome to the Sca_N_S tool.")
        print("Scanning your network to find alive hosts...\n")

    def print_alive(self):
        table = PrettyTable(["IP", "MAC", "VENDOR", "OS INFO", "OPEN PORTS"])
        for ip, info in self.alive.items():
            mac = info["mac"]
            os_info = info["os_info"]
            open_ports = self.get_open_ports(ip) if self.tcp_scan else "N/A"
            try:
                vendor = MacLookup().lookup(mac) if self.detailed else "Hidden"
                table.add_row([ip, mac, vendor, os_info, open_ports])
            except:
                table.add_row([ip, mac, "Unknown", os_info, open_ports])
        print(colored(table, "cyan"))

    def get_open_ports(self, ip):
        try:
            open_ports = os.popen(f"nmap {ip} | grep ^[0-9] | cut -d '/' -f 1").read().strip().split("\n")
            return ", ".join(open_ports) if open_ports else "N/A"
        except:
            return "N/A"

    def save_to_file(self):
        with open(self.output_file, 'w') as file:
            for ip, info in self.alive.items():
                mac = info["mac"]
                os_info = info["os_info"]
                open_ports = self.get_open_ports(ip) if self.tcp_scan else "N/A"
                try:
                    vendor = MacLookup().lookup(mac) if self.detailed else "Hidden"
                    file.write(f"{ip}\t{mac}\t{vendor}\t{os_info}\t{open_ports}\n")
                except:
                    file.write(f"{ip}\t{mac}\tUnknown\t{os_info}\t{open_ports}\n")
        print(colored(f"\nScan results saved to {self.output_file}", "green"))

    def print_summary(self):
        print(colored("\n=== Summary ===", "green"))
        print(f"Total hosts scanned: {len(self.hosts)}")
        print(f"Hosts alive: {len(self.alive)}")

def print_help_list():
    print("\n=== Sca_N_S Help ===")
    print("1. Perform ARP Scan:")
    print("\t./sca_n_s.py --hosts 192.168.1.1")
    print("\t./sca_n_s.py --hosts 192.168.1.1 --arp-scan")
    print("\n2. Perform ICMP Ping Scan:")
    print("\t./sca_n_s.py --hosts 192.168.1.1 --icmp-scan")
    print("\n3. Perform TCP Scan (Port 80):")
    print("\t./sca_n_s.py --hosts 192.168.1.1 --tcp-scan")
    print("\t./sca_n_s.py --hosts 192.168.1.1 --tcp-scan --tcp-ports 80")
    print("\n4. Save Scan Results to File:")
    print("\t./sca_n_s.py --hosts 192.168.1.1 --output-file scan_results.txt")
    print("\n5. Display Detailed Information:")
    print("\t./sca_n_s.py --hosts 192.168.1.1 --detailed")
    print("\n6. Combine Options:")
    print("\t./sca_n_s.py --hosts 192.168.1.1 --arp-scan --detailed --output-file scan_results.txt")
    print("\n7. Customizable Timeout:")
    print("\t./sca_n_s.py --hosts 192.168.1.1 --timeout 2")
    print("\n8. Display Progress Bar during Scan:")
    print("\t./sca_n_s.py --hosts 192.168.1.1 --tcp-scan --tcp-ports 80")
    print("\n9. Display Operating System Information (requires nmap):")
    print("\t./sca_n_s.py --hosts 192.168.1.1 --detailed")
    print("\n10. Specify Destination MAC address for Ether layer:")
    print("\t./sca_n_s.py --hosts 192.168.1.1 --ether-dst 00:11:22:33:44:55")
    print("\n11. Specify Target IP address for ARP layer:")
    print("\t./sca_n_s.py --hosts 192.168.1.1 --arp-pdst 192.168.1.2")
    print("\n12. Show Help List:")
    print("\t./sca_n_s.py --help-list")

def get_args():
    parser = ArgumentParser(description="Sca_N_S - Network Scanner")
    parser.add_argument("--hosts", dest="hosts", nargs="+", help="Hosts to scan")
    parser.add_argument("--ether-dst", dest="ether_dst", default=None, help="Destination MAC address for Ether layer")
    parser.add_argument("--arp-pdst", dest="arp_pdst", help="Target IP address for ARP layer")
    parser.add_argument("--timeout", dest="timeout", type=int, default=1, help="Timeout for packet sending")
    parser.add_argument("--arp-scan", dest="arp_scan", action="store_true", help="Perform ARP scan (default if neither ARP, ICMP, nor TCP scan specified)")
    parser.add_argument("--icmp-scan", dest="icmp_scan", action="store_true", help="Perform ICMP ping scan")
    parser.add_argument("--tcp-scan", dest="tcp_scan", action="store_true", help="Perform TCP scan")
    parser.add_argument("--tcp-ports", dest="tcp_ports", nargs="+", type=int, help="Specify multiple ports for TCP scan")
    parser.add_argument("--detailed", dest="detailed", action="store_true", help="Display detailed information about scanned hosts")
    parser.add_argument("--output-file", dest="output_file", help="Save scan results to a file")
    parser.add_argument("--help-list", dest="help_list", action="store_true", help="Show help list for using the tool")

    args = parser.parse_args()

    if args.help_list:
        print_help_list()
        sys.exit(0)

    if not args.hosts:
        parser.print_help(sys.stderr)
        sys.exit(1)

    return args.hosts, args.ether_dst, args.arp_pdst, args.timeout, args.arp_scan, args.icmp_scan, args.tcp_scan, args.tcp_ports, args.detailed, args.output_file

hosts, ether_dst, arp_pdst, timeout, arp_scan, icmp_scan, tcp_scan, tcp_ports, detailed, output_file = get_args()
Sca_N_S(hosts, ether_dst, arp_pdst, timeout, arp_scan, icmp_scan, tcp_scan, tcp_ports, detailed, output_file)
