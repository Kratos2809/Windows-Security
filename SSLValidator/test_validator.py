#!/usr/bin/env python3
"""
Test suite for the SSL/TLS Certificate Validator
"""

import unittest
from unittest.mock import Mock, patch
import datetime
from ssl_validator import SSLValidator, CertificateInfo
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import OpenSSL

class TestSSLValidator(unittest.TestCase):
    """Test cases for SSLValidator"""
    
    def setUp(self):
        """Set up test environment"""
        self.validator = SSLValidator("example.com")
    
    @patch('socket.create_connection')
    @patch('OpenSSL.SSL.Connection')
    def test_get_certificate(self, mock_connection, mock_socket):
        """Test getting certificate from server"""
        # Mock SSL connection and certificate
        mock_cert = Mock()
        mock_cert.to_cryptography.return_value.public_bytes.return_value = b"mock_cert"
        mock_connection.return_value.get_peer_certificate.return_value = mock_cert
        
        # Get certificate
        connection, cert_bytes = self.validator.get_certificate()
        
        # Verify connection was established
        self.assertTrue(mock_socket.called)
        self.assertTrue(mock_connection.called)
        self.assertEqual(cert_bytes, b"mock_cert")
    
    @patch('ssl_validator.SSLValidator.get_certificate')
    def test_validate_certificate(self, mock_get_cert):
        """Test certificate validation"""
        # Create a mock certificate
        cert_pem = b"""
        -----BEGIN CERTIFICATE-----
        MIIDazCCAlOgAwIBAgIUBY3+WTApP6Ih6rjyOPxX7LHCT8YwDQYJKoZIhvcNAQEL
        BQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
        GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yMzAxMTcxNTI1MzNaFw0yNDAx
        MTcxNTI1MzNaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEw
        HwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggEiMA0GCSqGSIb3DQEB
        AQUAA4IBDwAwggEKAoIBAQCqZjhpNj8MkcCCYivX7JzKpGkJGbGvFRz4WZsKmwZc
        qFR3hB/7n7Dw5p8MjnU/4Kz3O0R7HjqVzQVA0hqrKwE+DHWFcWyJ7xvJmHJ+Dx8h
        cK9lqWzk7xT8zciI9r/HzP5KHIaVJxkEYBHsYIsVxKjQRF/NWjNQB5D8WjGGGM4V
        KGDh1K+7QHyeVuExCxEDfHQKBNf8jj8Pl4IYSh7YJRYvBd7iQ5hUNl5p8kCMSYAA
        RBrZGGg1ZB+T6OdqVMB3QgEXy3xvBDZKHyaKVRmZ4YCK9Z2/5HvGtCc6LzjKXjHF
        9e4JZ9+zOWVxRZkFyO9XIxYZ1GfxA2V8yqM2IRpLAgMBAAGjUzBRMB0GA1UdDgQW
        BBQKqxCO4ZOBpxkUBTKJmsQ1S0TRXjAfBgNVHSMEGDAWgBQKqxCO4ZOBpxkUBTKJ
        msQ1S0TRXjAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQB4cOdf
        zYrHqKE7R0Xm9cSYZqKZj9wkuL5oVJHJ8QpzAzVQWQpAf/JxF6C9RtC5IVFBZbGW
        5p0WR5qgNzJHHZV3hIgGjY5LP6zv6IR2U3GnYTqmHQQw5XZXy5ZNmAW6B6wL2Nn8
        DxWzWJUV7zkqqYPGd6myN5ZH/6jIQ/s4XR0QKq9jkZpL5fJQX5ikO8LlhkYxX1p8
        W4Ye5vF7P8aW7K2JpxOyiT5jW5pVBR3RfBZZDwN8uGQJ8H/bvnGJYoMTF0k5FlXl
        KfqvLGCwNWZn5dB7ZUxA5mLNzV6RPtD5mbwUH5+/cK9X9RnkFE8TFyYI4Bx5hFVE
        PR8TLQa4/nF5GwOF
        -----END CERTIFICATE-----
        """
        
        # Mock the get_certificate method
        mock_connection = Mock()
        mock_get_cert.return_value = (mock_connection, cert_pem)
        
        # Validate certificate
        cert_info = self.validator.validate_certificate()
        
        # Verify certificate information
        self.assertIsInstance(cert_info, CertificateInfo)
        self.assertTrue(hasattr(cert_info, 'subject'))
        self.assertTrue(hasattr(cert_info, 'issuer'))
        self.assertTrue(hasattr(cert_info, 'version'))
        self.assertTrue(hasattr(cert_info, 'serial_number'))
        self.assertTrue(hasattr(cert_info, 'not_before'))
        self.assertTrue(hasattr(cert_info, 'not_after'))
        self.assertTrue(hasattr(cert_info, 'san'))
        self.assertTrue(hasattr(cert_info, 'signature_algorithm'))
        self.assertTrue(hasattr(cert_info, 'key_size'))
        self.assertTrue(hasattr(cert_info, 'is_valid'))
        self.assertTrue(hasattr(cert_info, 'validation_errors'))
    
    def test_hostname_validation(self):
        """Test hostname validation"""
        validator = SSLValidator("invalid.example.com")
        with self.assertRaises(Exception):
            validator.validate_certificate()
    
    def test_port_validation(self):
        """Test port validation"""
        validator = SSLValidator("example.com", 12345)
        with self.assertRaises(Exception):
            validator.validate_certificate()

def main():
    """Run the test suite"""
    unittest.main()

if __name__ == '__main__':
    main()
