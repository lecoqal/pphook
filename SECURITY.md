# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | Yes |

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue, please report it responsibly.

**Please do not report security vulnerabilities through public GitHub issues.**

### How to Report

- **GitHub Issues**: Report security problems through GitHub issues with [SECURITY] tag
- **Response Time**: We aim to acknowledge reports within 48 hours
- **Disclosure**: We follow responsible disclosure practices

### What to Include

- Description of the vulnerability
- Steps to reproduce the issue
- Potential impact assessment
- Suggested fix (if available)

## Security Measures

### Authentication & Authorization

- **API Authentication**: Token-based authentication for phpIPAM and PowerDNS APIs
- **Database Access**: Dedicated service accounts with minimal privileges
- **SSH Access**: Key-based authentication for configuration deployment

### Data Protection

- **Configuration Encryption**: GPG encryption for sensitive configuration files
- **Credential Storage**: No hardcoded credentials in source code
- **Audit Trail**: Complete logging of all operations and modifications

### Network Security

- **API Communications**: HTTPS/HTTP with API key validation
- **Database Connections**: Encrypted MySQL connections where supported
- **Service Isolation**: Dedicated service accounts and file permissions

### System Security

- **File Permissions**: Restricted access to `/opt/pphook/` directory
- **Log Security**: Secure log rotation and retention policies
- **Service Hardening**: Minimal system privileges for PPHOOK service

## Security Best Practices

### Deployment

- Keep all components updated to latest stable versions
- Use strong, unique passwords for all service accounts
- Regularly rotate API keys and database credentials
- Monitor system logs for suspicious activities

### Configuration

- Secure GPG key management and passphrase protection
- Implement proper firewall rules for service access
- Configure fail2ban for API endpoint protection
- Regular security audits of system configurations

### Monitoring

- Enable comprehensive logging for all services
- Set up alerts for authentication failures
- Monitor unusual API access patterns
- Regular review of user permissions and access logs

## Known Security Considerations

- **API Dependencies**: Security relies on phpIPAM and PowerDNS API security
- **Database Security**: Shared database access requires proper MySQL security configuration
- **Email Notifications**: SMTP communications may not be encrypted depending on configuration

## Updates and Patches

Security updates will be released as patch versions. Users are encouraged to:

- Subscribe to release notifications
- Apply security patches promptly
- Review changelog for security-related changes
- Test updates in non-production environments first

## Compliance

This project implements security measures suitable for enterprise network management environments. For specific compliance requirements, additional security controls may be necessary.

---

**Last Updated**: July 2025 
