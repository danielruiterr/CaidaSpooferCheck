# CAIDA Spoofer Data Collection Tool

A fast, efficient Python utility for identifying networks capable of IP spoofing using the CAIDA Spoofer API.

## Features

- **Dual Reports**: Separate files for routed and private address spoofing
- **Real-time Progress**: Dynamic ETA calculation and cumulative statistics
- **Clean Output Format**: Human-readable reports with direct links to detailed information
- **Performance Optimized**: Efficient processing with minimal resource usage
- **Customizable**: Adjustable time range and output locations

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/danielruiterr/CaidaSpooferCheck.git
   cd caida-spoofer-tool
   ```

2. Install the required dependencies:
   ```bash
   pip install requests
   ```

## Usage

### Basic Usage:
```bash
python spoofer_collector.py
```

### Advanced Options:
```bash
python spoofer_collector.py --days 90 --routed-output ./reports/routed.txt --private-output ./reports/private.txt
```

### Output Example
```
Session: https://spoofer.caida.org/report.php?sessionid=887477, ASN4 number: 12222, Client4: 88.221.209.0/24, Country: pol, Privatespoof: rewritten, Routedspoof: rewritten, Timestamp: 2020-05-01T00:00:12+00:00
```

## Use Cases

- **Network security research and monitoring**
- **Evaluating BCP38/BCP84 compliance across networks**
- **Understanding potential DDoS attack vectors**

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

> **Note:** For network security research purposes only. Use responsibly.
