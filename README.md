# DNS Pentesting Automation Script

A comprehensive Python script for automated DNS security testing and enumeration. This tool performs various DNS-related security tests including fingerprinting, enumeration, zone transfers, and more.

## Features

The script performs the following DNS security tests:

1. **DNS NSID/Version Fingerprinting** - Identifies DNS server version information
2. **DNS Brute-force Subdomain Enumeration** - Discovers subdomains through brute-force
3. **DNS SRV Record Enumeration** - Enumerates SRV records for service discovery
4. **DNS Zone Transfer (AXFR)** - Attempts zone transfers to identify misconfigurations
5. **DNSSEC NSEC Enumeration** - Tests for NSEC-based zone walking vulnerabilities
6. **DNSSEC NSEC3 Enumeration** - Tests for NSEC3-based zone walking vulnerabilities
7. **DNS Recursion/Open Resolver Check** - Identifies open DNS resolvers
8. **DNS Cache Snooping** - Tests for DNS cache snooping vulnerabilities
9. **DNS Cache Snooping (Timed Mode)** - Advanced cache snooping using timing analysis
10. **DNS Service Discovery (DNS-SD/mDNS)** - Discovers services via mDNS

## Prerequisites

### Required Software

- **Python 3.x** - The script requires Python 3.6 or higher
- **Nmap** - Network scanning tool with DNS scripts
  - Install on Linux: `sudo apt-get install nmap` (Debian/Ubuntu) or `sudo yum install nmap` (RHEL/CentOS)
  - Install on macOS: `brew install nmap`
  - Install on Windows: Download from [nmap.org](https://nmap.org/download.html)

### Optional

- **sudo** - Some commands may require elevated privileges (the script will warn if sudo is not available)

## Installation

1. Clone or download the script to your local machine
2. Ensure Python 3.x is installed:
   ```bash
   python3 --version
   ```
3. Verify Nmap is installed:
   ```bash
   nmap --version
   ```
4. Make the script executable (optional):
   ```bash
   chmod +x dns.py
   ```

## Usage

### Basic Usage

Run the script using Python with command-line arguments:

```bash
python3 dns.py --ip <target_ip_or_domain> --port <port> --output <output_folder_path>
```

### Command-Line Arguments

- `--ip` (required): Target IP address or hostname/domain name
- `--port` (optional): DNS port number (default: 53)
- `--output` (optional): Path to save output files (default: `outputs`)

### Examples

**Basic usage with IP address:**
```bash
python3 dns.py --ip 192.168.1.1 --port 53 --output ./results
```

**Using a domain name:**
```bash
python3 dns.py --ip example.com --port 53 --output /root/AUTOMATION/OUTPUT
```

**Using default port and output directory:**
```bash
python3 dns.py --ip 8.8.8.8
```

**Full example:**
```bash
python3 dns.py --ip google.com --port 53 --output ./dns_results
```

### Running the Script

1. **Execute the script** with required arguments
2. **Output directory** - Will be created automatically if it doesn't exist
3. **Target** - Can be either:
   - An IP address (e.g., `192.168.1.1`)
   - A domain name (e.g., `example.com`)

### Example Session

```
$ python3 dns.py --ip example.com --port 53 --output ./results

===== DNS Automation Started =====

Starting: DNS NSID/Version Fingerprinting...
[RUN] nmap -sU -p 53 --script=dns-nsid 'example.com' | cat
[DONE]

Starting: DNS Brute-force Subdomain Enumeration...
[RUN] nmap -p 53 --script=dns-brute --script-args=dns-brute.domain='example.com',dns-brute.threads=50 'example.com' | cat
[DONE]

...
===== DNS Automation Completed =====
```

## Output Files

The script generates several output files in the specified output directory:

### 1. `PORT_{port}_DNS_Testcases.txt`
Contains the raw output from all DNS tests, including:
- Command executed for each test
- Full command output
- Scan results and findings

### 2. `dns_pentesting_timestamps.log`
Contains timestamped logs of when each test:
- Started
- Completed
- Failed (with return codes)
- Timed out
- Encountered errors

### 3. `output.log`
Contains detailed explanations of failures:
- Timestamp when each command failed
- Command that was executed
- Return code (if applicable)
- Detailed explanation of the failure
- Troubleshooting suggestions

**Note:** If `sudo` is not available on the system, a warning will be logged in `output.log`.

### 4. `PORT_{port}_DNS_OutputAnalysis.txt`
Contains automated analysis of the results:
- Vulnerability conclusions for each test
- Analysis explanations
- Evidence from scan results
- Commands used

## Understanding the Results

### Success Indicators
- Tests that complete successfully will show "Completed" in the timestamp log
- Check `PORT_{port}_DNS_Testcases.txt` for detailed findings

### Failure Indicators
- Check `dns_pentesting_timestamps.log` for failure timestamps
- Check `output.log` for detailed failure explanations with timestamps
- Common failure reasons:
  - Network connectivity issues
  - DNS server not responding
  - Permission problems
  - Timeout issues

### Analysis
- Review `output_analysis.txt` for automated vulnerability assessment
- Each test case includes:
  - Conclusion (vulnerable/not vulnerable/No output)
  - Analysis explanation
  - Evidence from scan results

## Troubleshooting

### Common Issues

1. **"Nmap is not available"**
   - Solution: Install Nmap using your system's package manager
   - Verify installation: `nmap --version`

2. **Permission Denied Errors**
   - Some scans may require elevated privileges
   - Check `output.log` for sudo availability warning
   - Run with appropriate permissions if needed

3. **Network Timeout Errors**
   - Check network connectivity to the target
   - Verify the target IP/domain is correct
   - Check firewall rules

4. **"No domain provided" for certain tests**
   - Some tests (SRV enumeration, Zone Transfer, NSEC) require a domain name
   - These tests will be skipped if only an IP address is provided

### Getting Help

If you encounter issues:
1. Check `output.log` for detailed error messages
2. Verify Nmap is installed and accessible
3. Check network connectivity to the target
4. Review the timestamp log for execution details

## Security and Legal Considerations

⚠️ **IMPORTANT:** Only use this script on systems you own or have explicit written permission to test. Unauthorized scanning of networks or systems may be illegal and could result in criminal charges.

- Always obtain proper authorization before running security tests
- Be aware of local laws and regulations regarding network scanning
- Use responsibly and ethically
- This tool is for security testing and educational purposes only

## Script Structure

The script is organized into the following main components:

- **DNSPentestingAutomation Class**: Main class containing all test methods
- **Validation Methods**: IP/domain validation, port validation
- **Test Methods**: Individual DNS security test implementations
- **Logging Setup**: Configures timestamp and output logging
- **Result Analysis**: Automated analysis of scan results

## Notes

- The script runs tests sequentially (one after another)
- Each test writes its output to the result file in real-time
- Failed tests are logged with timestamps and detailed explanations
- The script creates the output directory automatically if it doesn't exist
- All timestamps are in local system time

## License

This script is provided as-is for security testing and educational purposes.

