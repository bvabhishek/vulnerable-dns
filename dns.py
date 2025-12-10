import subprocess
import os
import re
import sys
import logging
import ipaddress
import argparse
import shlex
from datetime import datetime

# Configure timestamp logging
timestamp_logger = logging.getLogger('timestamp')
timestamp_logger.setLevel(logging.INFO)
timestamp_logger.propagate = False

# Compile regex pattern once
DOMAIN_PATTERN = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$')

class DNSPentestingAutomation:
    def __init__(self, target_ip, port, output_path):
        self.target_ip = target_ip
        self.target_port = port
        self.output_path = output_path
        
        # Determine if target is IP or domain
        try:
            ipaddress.ip_address(target_ip)
            self.target_domain = None  # It's an IP
        except ValueError:
            self.target_domain = target_ip  # It's a domain
        
        # Set up file paths
        os.makedirs(self.output_path, exist_ok=True)
        self.result_filename = os.path.join(self.output_path, f"PORT_{port}_DNS_Testcases.txt")
        self.output_log_path = os.path.join(self.output_path, 'output.log')
        
        # Initialize result file
        try:
            open(self.result_filename, 'w').close()
        except Exception:
            pass
        
        # Initialize output.log
        with open(self.output_log_path, 'w') as f:
            f.write(f"DNS Pentesting Automation - Output Log\n")
            f.write(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Target: {self.target_ip}\n")
            f.write(f"Port: {self.target_port}\n")
            if self.target_domain:
                f.write(f"Domain: {self.target_domain}\n")
            f.write("=" * 60 + "\n\n")
        
        # Check for sudo and log if missing
        if not self.check_sudo_availability():
            with open(self.output_log_path, 'a') as f:
                f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] WARNING: sudo is not available on this system.\n")
                f.write("Some commands may require elevated privileges. Please ensure you have appropriate permissions.\n\n")
        
        # Setup logging
        self.setup_logging()
    
    def check_sudo_availability(self):
        """
        Check if sudo is available on the system
        """
        try:
            result = subprocess.run(['which', 'sudo'], 
                                  capture_output=True, text=True, timeout=5)
            return result.returncode == 0
        except (FileNotFoundError, Exception):
            return False
    
    def check_nmap_availability(self):
        """
        Check if nmap is available on the system
        """
        try:
            result = subprocess.run(['nmap', '--version'], 
                                  capture_output=True, text=True, timeout=10)
            return result.returncode == 0
        except (FileNotFoundError, Exception):
            return False
    
    def validate_ip_or_domain(self, target):
        """
        Validate if the provided target is a valid IP address or domain
        """
        try:
            # Try to parse as IP address
            ipaddress.ip_address(target)
            return True
        except ValueError:
            # Check if it's a valid domain (basic validation)
            return bool(DOMAIN_PATTERN.match(target))
    
    def setup_logging(self):
        """
        Set up logging handlers with the output path
        """
        # Clear existing handlers
        for handler in timestamp_logger.handlers[:]:
            timestamp_logger.removeHandler(handler)
        # Set up timestamp logging
        timestamp_handler = logging.FileHandler(os.path.join(self.output_path, 'dns_pentesting_timestamps.log'))
        timestamp_handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
        timestamp_logger.addHandler(timestamp_handler)
    
    def _run(self, command, timeout=120):
        """
        Helper method to run commands (similar to smtp.py structure)
        """
        try:
            safe_cmd = (command or "").replace("\r", r"\\r").replace("\n", r"\\n")
            print(f"[RUN] {safe_cmd}")
            proc = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                shell=True,
                timeout=timeout,
                text=True,
            )
            print("[DONE]\n")
            return proc.stdout
        except subprocess.TimeoutExpired as e:
            print("[TIMEOUT]\n")
            return f"[TIMEOUT] {command}\n{e.output or ''}"
        except Exception as e:
            print("[ERROR]\n")
            return f"[ERROR] {command}\n{str(e)}"
    
    def _append_section(self, title, command, output):
        """
        Helper method to append sections to result file (similar to smtp.py structure)
        """
        try:
            print(f"[SECTION] {title}")
            with open(self.result_filename, "a") as f:
                f.write("\n" + ("-" * 80) + "\n")
                f.write(f"{title}\n")
                f.write("=" * len(title) + "\n")
                if command:
                    safe_cmd = command.replace("\r", r"\\r").replace("\n", r"\\n")
                    f.write(f"Command: {safe_cmd}\n")
                f.write("Output:\n")
                if output:
                    f.write(output.rstrip("\n") + "\n")
                else:
                    f.write("<no output>\n")
                f.write(("-" * 80) + "\n")
                f.flush()
        except Exception:
            pass
    
    def run_dns_nsid_fingerprinting(self):
        """
        Run DNS NSID/version fingerprinting using nmap dns-nsid script
        """
        if not self.check_nmap_availability():
            print("Nmap is not available. Please install nmap first.")
            return False
        
        print("Starting: DNS NSID/Version Fingerprinting...")
        timestamp_logger.info("DNS NSID/Version Fingerprinting - Started")
        
        title = "DNS NSID/Version Fingerprinting"
        cmd = f"nmap -sU -p {self.target_port} --script=dns-nsid {shlex.quote(self.target_ip)} | cat"
        
        try:
            out = self._run(cmd, timeout=120)
            self._append_section(title, cmd, out)
            
            # Check for failures and log to output.log
            if "[ERROR]" in out or "[TIMEOUT]" in out:
                failure_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                timestamp_logger.info("DNS NSID/Version Fingerprinting - Failed")
                with open(self.output_log_path, 'a') as f:
                    f.write(f"[{failure_time}] DNS NSID/Version Fingerprinting - FAILED\n")
                    f.write(f"Command: {cmd}\n")
                    f.write("Explanation: The DNS NSID/Version fingerprinting scan failed.\n")
                    f.write("This could indicate network connectivity issues, DNS server not responding, or permission problems.\n")
                    f.write("Check the result file for detailed command output.\n\n")
            else:
                timestamp_logger.info("DNS NSID/Version Fingerprinting - Completed")
            
            print("Completed: DNS NSID/Version Fingerprinting.\n")
            return True
        except Exception as e:
            failure_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            print(f"Error running scan: {e}")
            timestamp_logger.info(f"DNS NSID/Version Fingerprinting - Error: {e}")
            with open(self.output_log_path, 'a') as f:
                f.write(f"[{failure_time}] DNS NSID/Version Fingerprinting - ERROR\n")
                f.write(f"Command: {cmd}\n")
                f.write(f"Error: {str(e)}\n")
                f.write("Explanation: An unexpected error occurred during the DNS NSID/Version fingerprinting scan.\n")
                f.write("This could be due to missing dependencies, permission issues, or system configuration problems.\n\n")
            return False
    
    def run_dns_brute_force(self):
        """
        Run DNS brute-force subdomain enumeration using nmap dns-brute script
        """
        if not self.check_nmap_availability():
            print("Nmap is not available. Please install nmap first.")
            return False
        
        print("Starting: DNS Brute-force Subdomain Enumeration...")
        timestamp_logger.info("DNS Brute-force Subdomain Enumeration - Started")
        
        title = "DNS Brute-force Subdomain Enumeration"
        script_args = f"dns-brute.domain='{self.target_domain or self.target_ip}',dns-brute.threads=50"
        cmd = f"nmap -p {self.target_port} --script=dns-brute --script-args={script_args} {shlex.quote(self.target_ip)} | cat"
        
        try:
            out = self._run(cmd, timeout=300)
            self._append_section(title, cmd, out)
            
            if "[ERROR]" in out or "[TIMEOUT]" in out:
                failure_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                timestamp_logger.info("DNS Brute-force Subdomain Enumeration - Failed")
                with open(self.output_log_path, 'a') as f:
                    f.write(f"[{failure_time}] DNS Brute-force Subdomain Enumeration - FAILED\n")
                    f.write(f"Command: {cmd}\n")
                    f.write("Explanation: The DNS brute-force subdomain enumeration failed.\n")
                    f.write("This could indicate network connectivity issues, DNS server not responding, or permission problems.\n")
                    f.write("Check the result file for detailed command output.\n\n")
            else:
                timestamp_logger.info("DNS Brute-force Subdomain Enumeration - Completed")
            
            print("Completed: DNS Brute-force Subdomain Enumeration.\n")
            return True
        except Exception as e:
            failure_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            print(f"Error running scan: {e}")
            timestamp_logger.info(f"DNS Brute-force Subdomain Enumeration - Error: {e}")
            with open(self.output_log_path, 'a') as f:
                f.write(f"[{failure_time}] DNS Brute-force Subdomain Enumeration - ERROR\n")
                f.write(f"Command: {cmd}\n")
                f.write(f"Error: {str(e)}\n")
                f.write("Explanation: An unexpected error occurred during the DNS brute-force subdomain enumeration.\n")
                f.write("This could be due to missing dependencies, permission issues, or system configuration problems.\n\n")
            return False
    
    def run_dns_srv_enumeration(self):
        """
        Run DNS SRV record enumeration using nmap dns-srv-enum script
        """
        if not self.check_nmap_availability():
            print("Nmap is not available. Please install nmap first.")
            return False
        
        if not self.target_domain:
            print("SRV enumeration requires a domain name. Skipping this test.")
            timestamp_logger.info("DNS SRV Record Enumeration - Skipped (no domain provided)")
            return False
        
        print("Starting: DNS SRV Record Enumeration...")
        timestamp_logger.info("DNS SRV Record Enumeration - Started")
        
        title = "DNS SRV Record Enumeration"
        cmd = f"nmap --script dns-srv-enum --script-args \"dns-srv-enum.domain='{self.target_domain}'\" | cat"
        
        try:
            out = self._run(cmd, timeout=120)
            self._append_section(title, cmd, out)
            
            if "[ERROR]" in out or "[TIMEOUT]" in out:
                failure_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                timestamp_logger.info("DNS SRV Record Enumeration - Failed")
                with open(self.output_log_path, 'a') as f:
                    f.write(f"[{failure_time}] DNS SRV Record Enumeration - FAILED\n")
                    f.write(f"Command: {cmd}\n")
                    f.write("Explanation: The DNS SRV record enumeration failed.\n")
                    f.write("This could indicate network connectivity issues, DNS server not responding, or permission problems.\n")
                    f.write("Check the result file for detailed command output.\n\n")
            else:
                timestamp_logger.info("DNS SRV Record Enumeration - Completed")
            
            print("Completed: DNS SRV Record Enumeration.\n")
            return True
        except Exception as e:
            failure_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            print(f"Error running scan: {e}")
            timestamp_logger.info(f"DNS SRV Record Enumeration - Error: {e}")
            with open(self.output_log_path, 'a') as f:
                f.write(f"[{failure_time}] DNS SRV Record Enumeration - ERROR\n")
                f.write(f"Command: {cmd}\n")
                f.write(f"Error: {str(e)}\n")
                f.write("Explanation: An unexpected error occurred during the DNS SRV record enumeration.\n")
                f.write("This could be due to missing dependencies, permission issues, or system configuration problems.\n\n")
            return False
    
    def run_dns_zone_transfer(self):
        """
        Run DNS zone transfer (AXFR) attempts using nmap dns-zone-transfer script
        """
        if not self.check_nmap_availability():
            print("Nmap is not available. Please install nmap first.")
            return False
        
        if not self.target_domain:
            print("Zone transfer requires a domain name. Skipping this test.")
            timestamp_logger.info("DNS Zone Transfer (AXFR) - Skipped (no domain provided)")
            return False
        
        print("Starting: DNS Zone Transfer (AXFR)...")
        timestamp_logger.info("DNS Zone Transfer (AXFR) - Started")
        
        title = "DNS Zone Transfer (AXFR)"
        cmd = f"nmap -p {self.target_port} --script=dns-zone-transfer --script-args dns-zone-transfer.domain='{self.target_domain}' {shlex.quote(self.target_ip)} | cat"
        
        try:
            out = self._run(cmd, timeout=120)
            self._append_section(title, cmd, out)
            
            if "[ERROR]" in out or "[TIMEOUT]" in out:
                failure_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                timestamp_logger.info("DNS Zone Transfer (AXFR) - Failed")
                with open(self.output_log_path, 'a') as f:
                    f.write(f"[{failure_time}] DNS Zone Transfer (AXFR) - FAILED\n")
                    f.write(f"Command: {cmd}\n")
                    f.write("Explanation: The DNS zone transfer (AXFR) attempt failed.\n")
                    f.write("This could indicate network connectivity issues, DNS server not responding, or permission problems.\n")
                    f.write("Check the result file for detailed command output.\n\n")
            else:
                timestamp_logger.info("DNS Zone Transfer (AXFR) - Completed")
            
            print("Completed: DNS Zone Transfer (AXFR).\n")
            return True
        except Exception as e:
            failure_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            print(f"Error running scan: {e}")
            timestamp_logger.info(f"DNS Zone Transfer (AXFR) - Error: {e}")
            with open(self.output_log_path, 'a') as f:
                f.write(f"[{failure_time}] DNS Zone Transfer (AXFR) - ERROR\n")
                f.write(f"Command: {cmd}\n")
                f.write(f"Error: {str(e)}\n")
                f.write("Explanation: An unexpected error occurred during the DNS zone transfer (AXFR) attempt.\n")
                f.write("This could be due to missing dependencies, permission issues, or system configuration problems.\n\n")
            return False
    
    def run_dns_nsec_enumeration(self):
        """
        Run DNSSEC NSEC enumeration using nmap dns-nsec-enum script
        """
        if not self.check_nmap_availability():
            print("Nmap is not available. Please install nmap first.")
            return False
        
        if not self.target_domain:
            print("NSEC enumeration requires a domain name. Skipping this test.")
            timestamp_logger.info("DNSSEC NSEC Enumeration - Skipped (no domain provided)")
            return False
        
        print("Starting: DNSSEC NSEC Enumeration...")
        timestamp_logger.info("DNSSEC NSEC Enumeration - Started")
        
        title = "DNSSEC NSEC Enumeration"
        cmd = f"nmap -p {self.target_port} --script=dns-nsec-enum --script-args dns-nsec-enum.domains='{self.target_domain}' {shlex.quote(self.target_ip)} | cat"
        
        try:
            out = self._run(cmd, timeout=120)
            self._append_section(title, cmd, out)
            
            if "[ERROR]" in out or "[TIMEOUT]" in out:
                failure_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                timestamp_logger.info("DNSSEC NSEC Enumeration - Failed")
                with open(self.output_log_path, 'a') as f:
                    f.write(f"[{failure_time}] DNSSEC NSEC Enumeration - FAILED\n")
                    f.write(f"Command: {cmd}\n")
                    f.write("Explanation: The DNSSEC NSEC enumeration failed.\n")
                    f.write("This could indicate network connectivity issues, DNS server not responding, or permission problems.\n")
                    f.write("Check the result file for detailed command output.\n\n")
            else:
                timestamp_logger.info("DNSSEC NSEC Enumeration - Completed")
            
            print("Completed: DNSSEC NSEC Enumeration.\n")
            return True
        except Exception as e:
            failure_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            print(f"Error running scan: {e}")
            timestamp_logger.info(f"DNSSEC NSEC Enumeration - Error: {e}")
            with open(self.output_log_path, 'a') as f:
                f.write(f"[{failure_time}] DNSSEC NSEC Enumeration - ERROR\n")
                f.write(f"Command: {cmd}\n")
                f.write(f"Error: {str(e)}\n")
                f.write("Explanation: An unexpected error occurred during the DNSSEC NSEC enumeration.\n")
                f.write("This could be due to missing dependencies, permission issues, or system configuration problems.\n\n")
            return False
    
    def run_dns_nsec3_enumeration(self):
        """
        Run DNSSEC NSEC3 enumeration using nmap dns-nsec3-enum script
        """
        if not self.check_nmap_availability():
            print("Nmap is not available. Please install nmap first.")
            return False
        
        if not self.target_domain:
            print("NSEC3 enumeration requires a domain name. Skipping this test.")
            timestamp_logger.info("DNSSEC NSEC3 Enumeration - Skipped (no domain provided)")
            return False
        
        print("Starting: DNSSEC NSEC3 Enumeration...")
        timestamp_logger.info("DNSSEC NSEC3 Enumeration - Started")
        
        title = "DNSSEC NSEC3 Enumeration"
        # Run both TCP and UDP scans
        cmd_tcp = f"nmap -sT -p {self.target_port} --script=dns-nsec3-enum --script-args dns-nsec3-enum.domain='{self.target_domain}' {shlex.quote(self.target_ip)} | cat"
        cmd_udp = f"nmap -sU -p {self.target_port} --script=dns-nsec3-enum --script-args dns-nsec3-enum.domain='{self.target_domain}' {shlex.quote(self.target_ip)} | cat"
        
        try:
            out_tcp = self._run(cmd_tcp, timeout=120)
            out_udp = self._run(cmd_udp, timeout=120)
            combined_out = f"TCP Scan Output:\n{out_tcp}\n\nUDP Scan Output:\n{out_udp}"
            combined_cmd = f"TCP: {cmd_tcp}\nUDP: {cmd_udp}"
            self._append_section(title, combined_cmd, combined_out)
            
            if "[ERROR]" in combined_out or "[TIMEOUT]" in combined_out:
                failure_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                timestamp_logger.info("DNSSEC NSEC3 Enumeration - Failed")
                with open(self.output_log_path, 'a') as f:
                    f.write(f"[{failure_time}] DNSSEC NSEC3 Enumeration - FAILED\n")
                    f.write(f"Commands: {combined_cmd}\n")
                    f.write("Explanation: The DNSSEC NSEC3 enumeration failed.\n")
                    f.write("This could indicate network connectivity issues, DNS server not responding, or permission problems.\n")
                    f.write("Check the result file for detailed command output.\n\n")
            else:
                timestamp_logger.info("DNSSEC NSEC3 Enumeration - Completed")
            
            print("Completed: DNSSEC NSEC3 Enumeration.\n")
            return True
        except Exception as e:
            failure_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            print(f"Error running scan: {e}")
            timestamp_logger.info(f"DNSSEC NSEC3 Enumeration - Error: {e}")
            with open(self.output_log_path, 'a') as f:
                f.write(f"[{failure_time}] DNSSEC NSEC3 Enumeration - ERROR\n")
                f.write(f"Commands: {combined_cmd}\n")
                f.write(f"Error: {str(e)}\n")
                f.write("Explanation: An unexpected error occurred during the DNSSEC NSEC3 enumeration.\n")
                f.write("This could be due to missing dependencies, permission issues, or system configuration problems.\n\n")
            return False
    
    def run_dns_recursion_check(self):
        """
        Run DNS recursion/open resolver checks using nmap dns-recursion script
        """
        if not self.check_nmap_availability():
            print("Nmap is not available. Please install nmap first.")
            return False
        
        print("Starting: DNS Recursion/Open Resolver Check...")
        timestamp_logger.info("DNS Recursion/Open Resolver Check - Started")
        
        title = "DNS Recursion/Open Resolver Check"
        # Run both TCP and UDP scans
        cmd_tcp = f"nmap -sT -p {self.target_port} --script=dns-recursion {shlex.quote(self.target_ip)} | cat"
        cmd_udp = f"nmap -sU -p {self.target_port} --script=dns-recursion {shlex.quote(self.target_ip)} | cat"
        
        try:
            out_tcp = self._run(cmd_tcp, timeout=120)
            out_udp = self._run(cmd_udp, timeout=120)
            combined_out = f"TCP Scan Output:\n{out_tcp}\n\nUDP Scan Output:\n{out_udp}"
            combined_cmd = f"TCP: {cmd_tcp}\nUDP: {cmd_udp}"
            self._append_section(title, combined_cmd, combined_out)
            
            if "[ERROR]" in combined_out or "[TIMEOUT]" in combined_out:
                failure_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                timestamp_logger.info("DNS Recursion/Open Resolver Check - Failed")
                with open(self.output_log_path, 'a') as f:
                    f.write(f"[{failure_time}] DNS Recursion/Open Resolver Check - FAILED\n")
                    f.write(f"Commands: {combined_cmd}\n")
                    f.write("Explanation: The DNS recursion/open resolver check failed.\n")
                    f.write("This could indicate network connectivity issues, DNS server not responding, or permission problems.\n")
                    f.write("Check the result file for detailed command output.\n\n")
            else:
                timestamp_logger.info("DNS Recursion/Open Resolver Check - Completed")
            
            print("Completed: DNS Recursion/Open Resolver Check.\n")
            return True
        except Exception as e:
            failure_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            print(f"Error running scan: {e}")
            timestamp_logger.info(f"DNS Recursion/Open Resolver Check - Error: {e}")
            with open(self.output_log_path, 'a') as f:
                f.write(f"[{failure_time}] DNS Recursion/Open Resolver Check - ERROR\n")
                f.write(f"Commands: {combined_cmd}\n")
                f.write(f"Error: {str(e)}\n")
                f.write("Explanation: An unexpected error occurred during the DNS recursion/open resolver check.\n")
                f.write("This could be due to missing dependencies, permission issues, or system configuration problems.\n\n")
            return False
    
    def run_dns_cache_snooping(self):
        """
        Run DNS cache snooping using nmap dns-cache-snoop script
        """
        if not self.check_nmap_availability():
            print("Nmap is not available. Please install nmap first.")
            return False
        
        print("Starting: DNS Cache Snooping...")
        timestamp_logger.info("DNS Cache Snooping - Started")
        
        title = "DNS Cache Snooping"
        cmd = f"nmap -p {self.target_port} --script=dns-cache-snoop {shlex.quote(self.target_ip)} | cat"
        
        try:
            out = self._run(cmd, timeout=120)
            self._append_section(title, cmd, out)
            
            if "[ERROR]" in out or "[TIMEOUT]" in out:
                failure_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                timestamp_logger.info("DNS Cache Snooping - Failed")
                with open(self.output_log_path, 'a') as f:
                    f.write(f"[{failure_time}] DNS Cache Snooping - FAILED\n")
                    f.write(f"Command: {cmd}\n")
                    f.write("Explanation: The DNS cache snooping scan failed.\n")
                    f.write("This could indicate network connectivity issues, DNS server not responding, or permission problems.\n")
                    f.write("Check the result file for detailed command output.\n\n")
            else:
                timestamp_logger.info("DNS Cache Snooping - Completed")
            
            print("Completed: DNS Cache Snooping.\n")
            return True
        except Exception as e:
            failure_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            print(f"Error running scan: {e}")
            timestamp_logger.info(f"DNS Cache Snooping - Error: {e}")
            with open(self.output_log_path, 'a') as f:
                f.write(f"[{failure_time}] DNS Cache Snooping - ERROR\n")
                f.write(f"Command: {cmd}\n")
                f.write(f"Error: {str(e)}\n")
                f.write("Explanation: An unexpected error occurred during the DNS cache snooping scan.\n")
                f.write("This could be due to missing dependencies, permission issues, or system configuration problems.\n\n")
            return False
    
    def run_dns_cache_snooping_timed(self):
        """
        Run DNS cache snooping in timed mode using nmap dns-cache-snoop script
        """
        if not self.check_nmap_availability():
            print("Nmap is not available. Please install nmap first.")
            return False
        
        print("Starting: DNS Cache Snooping (Timed Mode)...")
        timestamp_logger.info("DNS Cache Snooping (Timed Mode) - Started")
        
        title = "DNS Cache Snooping (Timed Mode)"
        cmd = f"nmap -p {self.target_port} --script=dns-cache-snoop --script-args=\"dns-cache-snoop.mode=timed\" {shlex.quote(self.target_ip)} | cat"
        
        try:
            out = self._run(cmd, timeout=120)
            self._append_section(title, cmd, out)
            
            if "[ERROR]" in out or "[TIMEOUT]" in out:
                failure_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                timestamp_logger.info("DNS Cache Snooping (Timed Mode) - Failed")
                with open(self.output_log_path, 'a') as f:
                    f.write(f"[{failure_time}] DNS Cache Snooping (Timed Mode) - FAILED\n")
                    f.write(f"Command: {cmd}\n")
                    f.write("Explanation: The DNS cache snooping (timed mode) scan failed.\n")
                    f.write("This could indicate network connectivity issues, DNS server not responding, or permission problems.\n")
                    f.write("Check the result file for detailed command output.\n\n")
            else:
                timestamp_logger.info("DNS Cache Snooping (Timed Mode) - Completed")
            
            print("Completed: DNS Cache Snooping (Timed Mode).\n")
            return True
        except Exception as e:
            failure_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            print(f"Error running scan: {e}")
            timestamp_logger.info(f"DNS Cache Snooping (Timed Mode) - Error: {e}")
            with open(self.output_log_path, 'a') as f:
                f.write(f"[{failure_time}] DNS Cache Snooping (Timed Mode) - ERROR\n")
                f.write(f"Command: {cmd}\n")
                f.write(f"Error: {str(e)}\n")
                f.write("Explanation: An unexpected error occurred during the DNS cache snooping (timed mode) scan.\n")
                f.write("This could be due to missing dependencies, permission issues, or system configuration problems.\n\n")
            return False
    
    def run_dns_service_discovery(self):
        """
        Run DNS service discovery (DNS-SD/mDNS) using nmap dns-service-discovery script
        """
        if not self.check_nmap_availability():
            print("Nmap is not available. Please install nmap first.")
            return False
        
        print("Starting: DNS Service Discovery (DNS-SD/mDNS)...")
        timestamp_logger.info("DNS Service Discovery (DNS-SD/mDNS) - Started")
        
        title = "DNS Service Discovery (DNS-SD/mDNS)"
        cmd = f"nmap -p {self.target_port} --script=dns-service-discovery {shlex.quote(self.target_ip)} | cat"
        
        try:
            out = self._run(cmd, timeout=120)
            self._append_section(title, cmd, out)
            
            if "[ERROR]" in out or "[TIMEOUT]" in out:
                failure_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                timestamp_logger.info("DNS Service Discovery (DNS-SD/mDNS) - Failed")
                with open(self.output_log_path, 'a') as f:
                    f.write(f"[{failure_time}] DNS Service Discovery (DNS-SD/mDNS) - FAILED\n")
                    f.write(f"Command: {cmd}\n")
                    f.write("Explanation: The DNS service discovery (DNS-SD/mDNS) scan failed.\n")
                    f.write("This could indicate network connectivity issues, DNS server not responding, or permission problems.\n")
                    f.write("Check the result file for detailed command output.\n\n")
            else:
                timestamp_logger.info("DNS Service Discovery (DNS-SD/mDNS) - Completed")
            
            print("Completed: DNS Service Discovery (DNS-SD/mDNS).\n")
            return True
        except Exception as e:
            failure_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            print(f"Error running scan: {e}")
            timestamp_logger.info(f"DNS Service Discovery (DNS-SD/mDNS) - Error: {e}")
            with open(self.output_log_path, 'a') as f:
                f.write(f"[{failure_time}] DNS Service Discovery (DNS-SD/mDNS) - ERROR\n")
                f.write(f"Command: {cmd}\n")
                f.write(f"Error: {str(e)}\n")
                f.write("Explanation: An unexpected error occurred during the DNS service discovery (DNS-SD/mDNS) scan.\n")
                f.write("This could be due to missing dependencies, permission issues, or system configuration problems.\n\n")
            return False
    
    def save_results(self):
        """
        Save scan results to a file with timestamp
        """
        try:
            print(f"\nResults saved to: {self.result_filename}")
        except Exception as e:
            print(f"Error saving results: {e}")
    
    def analyze_results(self):
        """
        Analyze the generated results file and store findings in output_analysis.txt
        """
        try:
            if not self.result_filename or not os.path.exists(self.result_filename):
                print("Result file not found. Skipping analysis.")
                return
            
            # Read the entire results file
            with open(self.result_filename, 'r') as rf:
                lines = [line.rstrip('\n') for line in rf]
            
            # Known test case names as section headers
            section_names = [
                "DNS NSID/Version Fingerprinting",
                "DNS Brute-force Subdomain Enumeration",
                "DNS SRV Record Enumeration",
                "DNS Zone Transfer (AXFR)",
                "DNSSEC NSEC Enumeration",
                "DNSSEC NSEC3 Enumeration",
                "DNS Recursion/Open Resolver Check",
                "DNS Cache Snooping",
                "DNS Cache Snooping (Timed Mode)",
                "DNS Service Discovery (DNS-SD/mDNS)",
            ]
            
            # Parse sections based on headers and capture command lines
            sections = {}
            commands = {name: "" for name in section_names}
            current = None
            buffer = []
            
            for line in lines:
                if line in section_names:
                    if current is not None:
                        sections[current] = "\n".join(buffer).strip()
                    current = line
                    buffer = []
                    continue
                
                # Capture the command line for the current section
                if current is not None and line.strip().startswith("Command:"):
                    try:
                        commands[current] = line.split("Command:", 1)[1].strip()
                    except Exception:
                        commands[current] = line.strip()
                    continue
                
                # Skip the underlines
                if line.strip().startswith("====") or line.strip().startswith("----"):
                    continue
                
                if current is not None:
                    buffer.append(line)
            
            if current is not None:
                sections[current] = "\n".join(buffer).strip()
            
            def contains_any(text: str, tokens):
                lowered = text.lower()
                return any(tok.lower() in lowered for tok in tokens)
            
            def select_evidence(text: str, tokens, max_lines: int = 5):
                if not text:
                    return []
                evid = []
                for ln in text.splitlines():
                    low = ln.lower()
                    if any(tok.lower() in low for tok in tokens):
                        evid.append(ln)
                    if len(evid) >= max_lines:
                        break
                return evid
            
            def analyze_section(name: str, content: str) -> (str, str, list):
                text = content or ""
                
                if name == "DNS NSID/Version Fingerprinting":
                    if contains_any(text, ["nsid", "version", "bind", "server"]):
                        return (
                            "vulnerable",
                            "DNS server version information revealed through NSID query.",
                            select_evidence(text, ["nsid", "version", "bind", "server", "id.server", "version.bind"]),
                        )
                    if text:
                        return (
                            "not vulnerable",
                            "NSID query completed but no version information revealed.",
                            select_evidence(text, ["dns", "nsid", "query", "response"]),
                        )
                    return (
                        "No output captured.",
                        "NSID fingerprinting produced no output.",
                        [],
                    )
                
                elif name == "DNS Brute-force Subdomain Enumeration":
                    if contains_any(text, ["valid", "found", "subdomain", "hostname", "a record", "aaaa record"]):
                        return (
                            "vulnerable",
                            "DNS brute-force enumeration discovered valid subdomains/hostnames.",
                            select_evidence(text, ["valid", "found", "subdomain", "hostname", "a record", "aaaa record"]),
                        )
                    if text:
                        return (
                            "not vulnerable",
                            "DNS brute-force enumeration completed but no valid subdomains found.",
                            select_evidence(text, ["dns-brute", "enumeration", "completed"]),
                        )
                    return (
                        "No output captured.",
                        "DNS brute-force enumeration produced no output.",
                        [],
                    )
                
                elif name == "DNS SRV Record Enumeration":
                    if contains_any(text, ["srv", "service", "port", "priority", "weight"]):
                        return (
                            "vulnerable",
                            "SRV records discovered revealing service information.",
                            select_evidence(text, ["srv", "service", "port", "priority", "weight", "target"]),
                        )
                    if text:
                        return (
                            "not vulnerable",
                            "SRV enumeration completed but no service records found.",
                            select_evidence(text, ["srv", "enumeration", "completed"]),
                        )
                    return (
                        "No output captured.",
                        "SRV enumeration produced no output.",
                        [],
                    )
                
                elif name == "DNS Zone Transfer (AXFR)":
                    if contains_any(text, ["axfr", "zone transfer", "successful", "records", "dns zone"]):
                        return (
                            "vulnerable",
                            "Zone transfer (AXFR) successful - serious misconfiguration detected.",
                            select_evidence(text, ["axfr", "zone transfer", "successful", "records", "dns zone"]),
                        )
                    if text:
                        return (
                            "not vulnerable",
                            "Zone transfer attempt completed but was denied.",
                            select_evidence(text, ["axfr", "zone transfer", "denied", "refused"]),
                        )
                    return (
                        "No output captured.",
                        "Zone transfer attempt produced no output.",
                        [],
                    )
                
                elif name == "DNSSEC NSEC Enumeration":
                    if contains_any(text, ["nsec", "enumeration", "names", "zone", "dnssec"]):
                        return (
                            "vulnerable",
                            "NSEC enumeration revealed zone information through DNSSEC.",
                            select_evidence(text, ["nsec", "enumeration", "names", "zone", "dnssec"]),
                        )
                    if text:
                        return (
                            "not vulnerable",
                            "NSEC enumeration completed but no zone information revealed.",
                            select_evidence(text, ["nsec", "enumeration", "completed"]),
                        )
                    return (
                        "No output captured.",
                        "NSEC enumeration produced no output.",
                        [],
                    )
                
                elif name == "DNSSEC NSEC3 Enumeration":
                    if contains_any(text, ["nsec3", "enumeration", "names", "zone", "dnssec"]):
                        return (
                            "vulnerable",
                            "NSEC3 enumeration revealed zone information through DNSSEC.",
                            select_evidence(text, ["nsec3", "enumeration", "names", "zone", "dnssec"]),
                        )
                    if text:
                        return (
                            "not vulnerable",
                            "NSEC3 enumeration completed but no zone information revealed.",
                            select_evidence(text, ["nsec3", "enumeration", "completed"]),
                        )
                    return (
                        "No output captured.",
                        "NSEC3 enumeration produced no output.",
                        [],
                    )
                
                elif name == "DNS Recursion/Open Resolver Check":
                    if contains_any(text, ["recursion", "open resolver", "allows", "recursive"]):
                        return (
                            "vulnerable",
                            "DNS server allows recursion for arbitrary queries - open resolver risk.",
                            select_evidence(text, ["recursion", "open resolver", "allows", "recursive"]),
                        )
                    if text:
                        return (
                            "not vulnerable",
                            "DNS server does not allow recursion for arbitrary queries.",
                            select_evidence(text, ["recursion", "denied", "refused"]),
                        )
                    return (
                        "No output captured.",
                        "Recursion check produced no output.",
                        [],
                    )
                
                elif name == "DNS Cache Snooping":
                    if contains_any(text, ["cached", "cache", "snooping", "timing"]):
                        return (
                            "vulnerable",
                            "DNS cache snooping revealed cached entries.",
                            select_evidence(text, ["cached", "cache", "snooping", "timing"]),
                        )
                    if text:
                        return (
                            "not vulnerable",
                            "DNS cache snooping completed but no cached entries detected.",
                            select_evidence(text, ["cache", "snooping", "completed"]),
                        )
                    return (
                        "No output captured.",
                        "Cache snooping produced no output.",
                        [],
                    )
                
                elif name == "DNS Cache Snooping (Timed Mode)":
                    if contains_any(text, ["cached", "cache", "timing", "statistical"]):
                        return (
                            "vulnerable",
                            "Timed cache snooping revealed cached entries through timing analysis.",
                            select_evidence(text, ["cached", "cache", "timing", "statistical"]),
                        )
                    if text:
                        return (
                            "not vulnerable",
                            "Timed cache snooping completed but no cached entries detected.",
                            select_evidence(text, ["cache", "timing", "completed"]),
                        )
                    return (
                        "No output captured.",
                        "Timed cache snooping produced no output.",
                        [],
                    )
                
                elif name == "DNS Service Discovery (DNS-SD/mDNS)":
                    if contains_any(text, ["mdns", "dns-sd", "service", "discovery", "advertised"]):
                        return (
                            "vulnerable",
                            "DNS service discovery revealed advertised services.",
                            select_evidence(text, ["mdns", "dns-sd", "service", "discovery", "advertised"]),
                        )
                    if text:
                        return (
                            "not vulnerable",
                            "DNS service discovery completed but no services found.",
                            select_evidence(text, ["mdns", "dns-sd", "discovery", "completed"]),
                        )
                    return (
                        "No output captured.",
                        "DNS service discovery produced no output.",
                        [],
                    )
                
                return (
                    "No analysis rule for this test case.",
                    "No analyzer implemented for this section.",
                    [],
                )
            
            analysis_path = os.path.join(self.output_path, f'PORT_{self.target_port}_DNS_OutputAnalysis.txt')
            with open(analysis_path, 'w') as af:
                af.write(f"DNS Security Analysis Report\n")
                af.write(f"Target: {self.target_ip}:{self.target_port}\n")
                af.write(f"Generated: {datetime.now().isoformat()}\n\n")
                af.write(f"results from the file {os.path.basename(self.result_filename)}\n\n")
                for name in section_names:
                    af.write(f"{name}\n")
                    af.write("-" * 18 + "\n")
                    content = sections.get(name, "")
                    conclusion, why, evidence = analyze_section(name, content)
                    cmd = commands.get(name, "")
                    af.write(f"Conclusion: {conclusion}\n")
                    af.write(f"Analysis: {why}\n")
                    if cmd:
                        af.write(f"Command: {cmd}\n")
                    if evidence:
                        af.write("Evidence:\n")
                        for ev in evidence:
                            af.write(f"- {ev}\n")
                    af.write("\n")
            
            print(f"Analysis saved to: {analysis_path}")
            
            # Create analysis.txt with only vulnerable findings
            analysis_txt_path = os.path.join(self.output_path, 'analysis.txt')
            vulnerable_findings = []
            
            for name in section_names:
                content = sections.get(name, "")
                conclusion, why, evidence = analyze_section(name, content)
                if conclusion == "vulnerable":
                    vulnerable_findings.append({
                        'name': name,
                        'why': why,
                        'evidence': evidence
                    })
            
            with open(analysis_txt_path, 'w') as atf:
                atf.write(f"DNS Security Analysis - Vulnerable Findings\n")
                atf.write(f"Target: {self.target_ip}:{self.target_port}\n")
                atf.write(f"Generated: {datetime.now().isoformat()}\n")
                atf.write("=" * 60 + "\n\n")
                
                if vulnerable_findings:
                    atf.write(f"Found {len(vulnerable_findings)} vulnerable configuration(s):\n\n")
                    for idx, finding in enumerate(vulnerable_findings, 1):
                        atf.write(f"{idx}. {finding['name']}\n")
                        atf.write(f"   Issue: {finding['why']}\n")
                        if finding['evidence']:
                            atf.write("   Evidence:\n")
                            for ev in finding['evidence']:
                                atf.write(f"   - {ev}\n")
                        atf.write("\n")
                else:
                    atf.write("No vulnerabilities detected.\n")
                    atf.write("All tested DNS security configurations appear to be secure.\n")
            
            print(f"Vulnerability summary saved to: {analysis_txt_path}")
        except Exception as e:
            print(f"Error during analysis: {e}")
    
    def run_automation(self):
        """
        Main method to run the DNS pentesting automation
        """
        print("\n===== DNS Automation Started =====\n")
        
        # Run DNS NSID/Version Fingerprinting
        self.run_dns_nsid_fingerprinting()
        
        # Run DNS Brute-force Subdomain Enumeration
        self.run_dns_brute_force()
        
        # Run DNS SRV Record Enumeration
        self.run_dns_srv_enumeration()
        
        # Run DNS Zone Transfer (AXFR)
        self.run_dns_zone_transfer()
        
        # Run DNSSEC NSEC Enumeration
        self.run_dns_nsec_enumeration()
        
        # Run DNSSEC NSEC3 Enumeration
        self.run_dns_nsec3_enumeration()
        
        # Run DNS Recursion/Open Resolver Check
        self.run_dns_recursion_check()
        
        # Run DNS Cache Snooping
        self.run_dns_cache_snooping()
        
        # Run DNS Cache Snooping (Timed Mode)
        self.run_dns_cache_snooping_timed()
        
        # Run DNS Service Discovery (DNS-SD/mDNS)
        self.run_dns_service_discovery()
        
        # Save results
        self.save_results()
        
        # Analyze results and write output_analysis.txt
        self.analyze_results()
        
        print("\n===== DNS Automation Completed =====\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DNS Security Automation Script")
    parser.add_argument("--ip", required=True, help="Target IP address or hostname")
    parser.add_argument("--port", type=int, default=53, help="DNS port (default: 53)")
    parser.add_argument("--output", type=str, default="outputs", help="Path to save output files")
    args = parser.parse_args()
    
    automation = DNSPentestingAutomation(args.ip, args.port, args.output)
    automation.run_automation()

