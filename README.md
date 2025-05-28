# Projet PPHOOK
Made by Intern No. 38

## Description

PPHOOK is an open-source middleware solution designed to ensure data integrity and consistency between phpIPAM (IP Address Management) and PowerDNS. This solution acts as an intelligent bridge that validates, synchronizes, and corrects DNS records automatically, preventing configuration errors that could affect network services.

## Key Features

- **Real-time DNS Validation**: Validates hostnames and IP addresses according to DNS standards (RFC 1035)
- **A/PTR Record Consistency**: Ensures forward and reverse DNS records are always synchronized
- **Automatic Error Correction**: Detects and removes orphaned or inconsistent DNS records
- **Email Notifications**: Sends detailed alerts to administrators when issues are detected
- **Complete Audit Trail**: Comprehensive logging of all operations for compliance and troubleshooting
- **Zone Compliance**: Validates hostnames against existing DNS zones
- **Periodic Synchronization**: Regular checks to maintain consistency between systems

## Architecture
IMG INFRA

## RTFM
- **Documentation**: Check the `/doc` directory for detailed technical documentation

## Quick Start

### Prerequisites

- Debian linux server
- Python 3.8 or higher
- phpIPAM 1.5+ with API access
- PowerDNS 4.4+ with API enabled
- SMTP server for email notifications
- Root/sudo access for installation

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/lecoqal/projet.git
   cd projet
   ```

2. **Configure global variables**
   ```bash
   cp global_vars.sh global_vars.sh.bkp
   nano global_vars.sh
   cd bash/
   source create_env.sh
   ```

3. **Run installation scripts** (must be executed from `main_scripts/` directory)
   ```bash
   cd main_scripts/
   
   # Install PPHOOK service
   source hook.sh
   ```

4. **Verify installation**
   ```bash
   systemctl status pphook
   tail -f /var/log/pphook.log
   ```

## Configuration

### Global Variables (`global_vars.sh`)
Unless otherwise required, you only need to edit this file.

## How It Works

### Validation Process

1. **Data Retrieval**: PPHOOK periodically queries phpIPAM API and PowerDNS API for new or modified entries
2. **Validation**: Each entry is validated against configured rules:
   - Hostname format compliance
   - IP address validity
   - Zone existence in PowerDNS
   - Character length limits
3. **DNS Consistency Check**: Verifies A and PTR record correspondence
4. **Correction Actions**: Automatically removes invalid or orphaned records
5. **Notification**: Sends email alerts for any issues detected

### Validation Rules

- **Hostname Format**: Must match the configured regex pattern
- **Domain Validation**: Hostname must belong to an existing DNS zone
- **IP Address**: Must be a valid IPv4/IPv6 address
- **Record Consistency**: A and PTR records must correspond
- **MAC Uniqueness**: No duplicate MAC Adress

### Error Handling

The system handles various error scenarios:

- **Invalid hostnames**: Removes associated DNS records and sends alerts
- **Orphaned records**: Automatically cleans up A records without PTR (or vice versa)
- **API failures**: Implements retry logic with exponential backoff
- **Inconsistent data**: Removes and recreates correct records

---

## Branches

```
MAIN : Latest version of PPHOOK
DEV : Developpement branch version of PPHOOK
```

## SECURITY

Please refer to our [Security Policy](misc/SECURITY.md) for information on:
- Supported versions
- How to report security vulnerabilities
- Security best practices for deployment

## CONTACT
- **Issues**: Use GitHub Issues for bug reports and feature requests
- **Email**: Contact the development team at [hook@bretagne.bzh]

## LICENCE
This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.
