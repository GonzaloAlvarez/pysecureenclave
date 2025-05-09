#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import pytest
import datetime
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID

from secureenclave.certs import CertManager
from secureenclave.datamodel import CertInfo, ServerInfo


@pytest.fixture
def cert_manager():
    """Returns a CertManager instance."""
    return CertManager()


@pytest.fixture
def sample_cert_info():
    """Returns a sample CertInfo object."""
    return CertInfo(
        country="US",
        state="California",
        city="San Francisco",
        owner="Test Org",
        organizational_unit="Test Unit",
        common_name="test.example.com"
    )


@pytest.fixture
def sample_server_info():
    """Returns a sample ServerInfo object."""
    return ServerInfo(
        country="US",
        state="California",
        city="San Francisco",
        owner="Test Server Org",
        organizational_unit="Test Server Unit",
        common_name="server.example.com",
        dns_name="server.example.com",
        alt_dns_name="www.server.example.com"
    )


def test_new_private_key(cert_manager):
    """Test private key generation."""
    key_size = 2048
    private_key = cert_manager.new_private_key(size=key_size)
    assert isinstance(private_key, rsa.RSAPrivateKey)
    assert private_key.key_size == key_size

    key_size_4096 = 4096
    private_key_4096 = cert_manager.new_private_key(size=key_size_4096)
    assert isinstance(private_key_4096, rsa.RSAPrivateKey)
    assert private_key_4096.key_size == key_size_4096


def test_create_subject(cert_manager, sample_cert_info):
    """Test _create_subject method."""
    attributes = cert_manager._create_subject(sample_cert_info)
    name = x509.Name(attributes)
    assert name.get_attributes_for_oid(NameOID.COUNTRY_NAME)[0].value == sample_cert_info.country
    assert name.get_attributes_for_oid(NameOID.STATE_OR_PROVINCE_NAME)[0].value == sample_cert_info.state
    assert name.get_attributes_for_oid(NameOID.LOCALITY_NAME)[0].value == sample_cert_info.city
    assert name.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value == sample_cert_info.owner
    assert name.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)[0].value == sample_cert_info.organizational_unit
    assert name.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == sample_cert_info.common_name


def test_new_ca_cert(cert_manager, sample_cert_info):
    """Test CA certificate generation."""
    private_key = cert_manager.new_private_key(size=2048)
    valid_days = 365
    ca_cert = cert_manager.new_ca_cert(sample_cert_info, private_key, valid_days=valid_days)

    assert isinstance(ca_cert, x509.Certificate)
    assert ca_cert.subject == ca_cert.issuer
    assert ca_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == sample_cert_info.common_name

    basic_constraints = ca_cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert basic_constraints.ca is True
    assert basic_constraints.path_length == 1

    assert ca_cert.not_valid_before_utc.date() == datetime.datetime.now(datetime.UTC).date()
    assert ca_cert.not_valid_after_utc.date() == (datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=valid_days)).date()


def test_new_server_cert(cert_manager, sample_server_info, sample_cert_info):
    """Test server certificate generation."""
    ca_private_key = cert_manager.new_private_key(size=2048)
    ca_cert = cert_manager.new_ca_cert(sample_cert_info, ca_private_key, valid_days=365)

    server_private_key = cert_manager.new_private_key(size=2048)
    valid_days = 180

    server_cert = cert_manager.new_server_cert(
        sample_server_info, server_private_key, ca_cert, ca_private_key, valid_days=valid_days
    )

    assert isinstance(server_cert, x509.Certificate)
    assert server_cert.issuer == ca_cert.subject
    assert server_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == sample_server_info.common_name

    basic_constraints = server_cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert basic_constraints.ca is False
    assert basic_constraints.path_length is None

    san_extension = server_cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    dns_names = san_extension.get_values_for_type(x509.DNSName)
    assert sample_server_info.dns_name in dns_names
    assert sample_server_info.alt_dns_name in dns_names

    eku_extension = server_cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert x509.oid.ExtendedKeyUsageOID.SERVER_AUTH in eku_extension
    assert x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH in eku_extension

    assert server_cert.not_valid_before_utc.date() == datetime.datetime.now(datetime.UTC).date()
    assert server_cert.not_valid_after_utc.date() == (datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=valid_days)).date()


def test_pk_to_file_and_pk_from_file(cert_manager, tmp_path):
    """Test saving a private key to a file and loading it back."""
    private_key = cert_manager.new_private_key(size=2048)
    file_path = tmp_path / "test_key.pem"

    cert_manager.pk_to_file(private_key, str(file_path))
    assert file_path.exists()

    loaded_key = cert_manager.pk_from_file(str(file_path))
    assert isinstance(loaded_key, rsa.RSAPrivateKey)
    assert loaded_key.key_size == private_key.key_size
    # Comparing private keys directly can be tricky; comparing public numbers is a good proxy
    assert loaded_key.public_key().public_numbers() == private_key.public_key().public_numbers()


def test_cert_to_file_and_cert_from_file(cert_manager, sample_cert_info, tmp_path):
    """Test saving a certificate to a file and loading it back."""
    private_key = cert_manager.new_private_key(size=2048)
    ca_cert = cert_manager.new_ca_cert(sample_cert_info, private_key, valid_days=365)
    file_path = tmp_path / "test_cert.pem"

    cert_manager.cert_to_file(ca_cert, str(file_path))
    assert file_path.exists()

    loaded_cert = cert_manager.cert_from_file(str(file_path))
    assert isinstance(loaded_cert, x509.Certificate)
    assert loaded_cert.serial_number == ca_cert.serial_number
    assert loaded_cert.subject == ca_cert.subject
    assert loaded_cert.issuer == ca_cert.issuer
    assert loaded_cert.fingerprint(hashes.SHA256()) == ca_cert.fingerprint(hashes.SHA256())
