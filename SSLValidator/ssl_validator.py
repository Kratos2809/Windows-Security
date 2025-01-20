#!/usr/bin/env python3
"""
SSL/TLS Certificate Validator
Validates SSL/TLS certificates and configuration of websites
"""

import ssl
import socket
import datetime
import argparse
import json
import sys
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from urllib.parse import urlparse
import OpenSSL
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID

@dataclass
class CertificateInfo:
    """Store certificate information"""
    subject: Dict[str, str]
    issuer: Dict[str, str]
    version: int
    serial_number: int
    not_before: datetime.datetime
    not_after: datetime.datetime
    san: List[str]
    signature_algorithm: str
    key_size: int
    protocols: List[str]
    ciphers: List[str]
    is_valid: bool
    validation_errors: List[str]

class SSLValidator:
    """Validate SSL/TLS certificates and configurations"""
    
    def __init__(self, hostname: str, port: int = 443):
        """Initialize the validator with target hostname and port"""
        self.hostname = hostname
        self.port = port
        self.validation_errors = []
    
    def get_certificate(self) -> Tuple[ssl.SSLSocket, bytes]:
        """Get the certificate from the server"""
        try:
            # Create SSL context with highest available protocol
            context = ssl.create_default_context()
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED
            
            # Create connection
            sock = socket.create_connection((self.hostname, self.port))
            ssl_sock = context.wrap_socket(sock, server_hostname=self.hostname)
            
            # Get the certificate
            cert_der = ssl_sock.getpeercert(binary_form=True)
            cert = x509.load_der_x509_certificate(cert_der, default_backend())
            cert_bytes = cert.public_bytes(serialization.Encoding.PEM)
            
            return ssl_sock, cert_bytes
            
        except ssl.SSLError as e:
            self.validation_errors.append(f"SSL error: {str(e)}")
            raise
        except socket.gaierror:
            self.validation_errors.append(f"Could not resolve hostname: {self.hostname}")
            raise
        except socket.timeout:
            self.validation_errors.append("Connection timed out")
            raise
        except Exception as e:
            self.validation_errors.append(f"Connection failed: {str(e)}")
            raise
    
    def get_supported_protocols(self, ssl_sock: ssl.SSLSocket) -> List[str]:
        """Get supported SSL/TLS protocols"""
        try:
            version = ssl_sock.version()
            return [version]
        except Exception as e:
            self.validation_errors.append(f"Failed to get protocol version: {str(e)}")
            return []
    
    def get_supported_ciphers(self, ssl_sock: ssl.SSLSocket) -> List[str]:
        """Get supported cipher suites"""
        try:
            return [ssl_sock.cipher()[0]]
        except Exception as e:
            self.validation_errors.append(f"Failed to get cipher suite: {str(e)}")
            return []
    
    def validate_certificate(self) -> CertificateInfo:
        """Validate the SSL/TLS certificate"""
        try:
            ssl_sock, cert_bytes = self.get_certificate()
            cert = x509.load_pem_x509_certificate(cert_bytes, default_backend())
            
            # Get basic certificate information
            subject = {}
            for attr in cert.subject:
                oid = attr.oid
                if hasattr(NameOID, oid._name):
                    subject[oid._name] = attr.value
            
            issuer = {}
            for attr in cert.issuer:
                oid = attr.oid
                if hasattr(NameOID, oid._name):
                    issuer[oid._name] = attr.value
            
            # Get Subject Alternative Names
            try:
                san = [name.value for name in cert.extensions.get_extension_for_oid(
                    x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
                ).value]
            except x509.extensions.ExtensionNotFound:
                san = []
            
            # Get public key information
            public_key = cert.public_key()
            key_size = public_key.key_size
            
            # Validate certificate dates
            now = datetime.datetime.now(datetime.timezone.utc)
            is_valid = cert.not_valid_before_utc <= now <= cert.not_valid_after_utc
            
            if now < cert.not_valid_before_utc:
                self.validation_errors.append("Certificate is not yet valid")
            elif now > cert.not_valid_after_utc:
                self.validation_errors.append("Certificate has expired")
            
            # Check hostname match
            if self.hostname not in san and self.hostname not in subject.values():
                self.validation_errors.append(
                    f"Hostname {self.hostname} doesn't match certificate names"
                )
            
            # Get protocols and ciphers
            protocols = self.get_supported_protocols(ssl_sock)
            ciphers = self.get_supported_ciphers(ssl_sock)
            
            # Check for weak protocols
            weak_protocols = {'SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1'}
            used_weak_protocols = weak_protocols.intersection(protocols)
            if used_weak_protocols:
                self.validation_errors.append(
                    f"Server supports weak protocols: {', '.join(used_weak_protocols)}"
                )
            
            # Create certificate info
            cert_info = CertificateInfo(
                subject=subject,
                issuer=issuer,
                version=cert.version.value,
                serial_number=cert.serial_number,
                not_before=cert.not_valid_before_utc,
                not_after=cert.not_valid_after_utc,
                san=san,
                signature_algorithm=cert.signature_algorithm_oid._name,
                key_size=key_size,
                protocols=protocols,
                ciphers=ciphers,
                is_valid=is_valid,
                validation_errors=self.validation_errors
            )
            
            # Clean up
            ssl_sock.close()
            
            return cert_info
            
        except Exception as e:
            self.validation_errors.append(f"Validation failed: {str(e)}")
            raise

def format_certificate_info(cert_info: CertificateInfo) -> str:
    """Format certificate information for display"""
    return f"""
Certificate Information:
----------------------
Subject: {cert_info.subject}
Issuer: {cert_info.issuer}
Version: {cert_info.version}
Serial Number: {cert_info.serial_number}
Valid From: {cert_info.not_before}
Valid Until: {cert_info.not_after}
Subject Alternative Names: {', '.join(cert_info.san)}
Signature Algorithm: {cert_info.signature_algorithm}
Public Key Size: {cert_info.key_size} bits
SSL/TLS Protocol: {', '.join(cert_info.protocols)}
Cipher Suite: {', '.join(cert_info.ciphers)}
Valid: {'Yes' if cert_info.is_valid else 'No'}

Validation Errors:
----------------
{chr(10).join(cert_info.validation_errors) if cert_info.validation_errors else 'None'}
"""

def main():
    """Main function to handle command line arguments"""
    parser = argparse.ArgumentParser(
        description='SSL/TLS Certificate Validator'
    )
    parser.add_argument('hostname', help='Hostname to validate')
    parser.add_argument('--port', type=int, default=443,
                       help='Port number (default: 443)')
    parser.add_argument('--json', action='store_true',
                       help='Output in JSON format')
    
    args = parser.parse_args()
    
    try:
        # Parse hostname from URL if needed
        parsed = urlparse(args.hostname)
        hostname = parsed.netloc or parsed.path
        
        validator = SSLValidator(hostname, args.port)
        cert_info = validator.validate_certificate()
        
        if args.json:
            # Convert to dict for JSON output
            cert_dict = {
                'subject': cert_info.subject,
                'issuer': cert_info.issuer,
                'version': cert_info.version,
                'serial_number': str(cert_info.serial_number),
                'not_before': cert_info.not_before.isoformat(),
                'not_after': cert_info.not_after.isoformat(),
                'san': cert_info.san,
                'signature_algorithm': cert_info.signature_algorithm,
                'key_size': cert_info.key_size,
                'protocols': cert_info.protocols,
                'ciphers': cert_info.ciphers,
                'is_valid': cert_info.is_valid,
                'validation_errors': cert_info.validation_errors
            }
            print(json.dumps(cert_dict, indent=2))
        else:
            print(format_certificate_info(cert_info))
        
        return 0 if cert_info.is_valid else 1
        
    except Exception as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        return 1

if __name__ == '__main__':
    sys.exit(main())
