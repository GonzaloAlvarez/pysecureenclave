#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright: (c) 2024, Gonzalo Alvarez

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import datetime
from loguru import logger
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa


class CertManager(object):
    def new_private_key(self, size: int):
        logger.info("Generating private key")
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=size,
            backend=default_backend()
        )

    def _create_subject(self, cert_info):
        attributes = []
        if cert_info.country:
            attributes.append(x509.NameAttribute(x509.oid.NameOID.COUNTRY_NAME, str(cert_info.country)))
        if cert_info.state:
            attributes.append(x509.NameAttribute(x509.oid.NameOID.STATE_OR_PROVINCE_NAME, str(cert_info.state)))
        if cert_info.city:
            attributes.append(x509.NameAttribute(x509.oid.NameOID.LOCALITY_NAME, str(cert_info.city)))
        if cert_info.owner:
            attributes.append(x509.NameAttribute(x509.oid.NameOID.ORGANIZATION_NAME, str(cert_info.owner)))
        if cert_info.organizational_unit:
            attributes.append(x509.NameAttribute(x509.oid.NameOID.ORGANIZATIONAL_UNIT_NAME, str(cert_info.organizational_unit)))
        if cert_info.common_name:
            attributes.append(x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, str(cert_info.common_name)))
        return attributes

    def cert_from_file(self, file_name):
        """
        Open a file and read the content. Create an X509 certificate object from it.
        """
        with open(file_name, "rb") as cert_file:
            content = cert_file.read()
            cert = x509.load_pem_x509_certificate(content, default_backend())
        return cert

    def pk_from_file(self, file_name):
        """
        Open a file and read the content. Create an RSA private key object from it.
        """
        with open(file_name, 'rb') as f:
            key = serialization.load_pem_private_key(
                f.read(), None
            )
            return key

    def new_ca_cert(self, cert_info, key, valid_days=729):
        """
        Create a new CA certificate object.
        """
        subject = issuer = x509.Name(self._create_subject(cert_info))
        logger.info("Generating CA Certificate")
        cert_builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=valid_days))
            .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
            .serial_number(x509.random_serial_number())
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True, key_encipherment=False,
                    content_commitment=False, data_encipherment=False,
                    key_agreement=False, key_cert_sign=True, crl_sign=True,
                    encipher_only=False, decipher_only=False
                ),
                critical=True
            )
        )
        cert = cert_builder.sign(key, hashes.SHA256(), default_backend())

        return cert

    def new_server_cert(self, server_info, server_key, ca_cert, ca_pk, valid_days=729):
        """
        Create a new server certificate.
          :param server_info: The server certificate information.
          :param server_key: The server key.
          :param ca_cert: The CA certificate.
          :param ca_pk: The CA private key.
          :param valid_days: The number of days the certificate is valid for.
        """
        subject = x509.Name(self._create_subject(server_info))
        cert_builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_cert.subject)
            .public_key(server_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=valid_days))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName(str(server_info.dns_name)),
                    x509.DNSName(str(server_info.alt_dns_name))
                ]),
                critical=False
            )
            .add_extension(
                x509.ExtendedKeyUsage([
                    x509.ExtendedKeyUsageOID.CLIENT_AUTH,
                    x509.ExtendedKeyUsageOID.SERVER_AUTH
                ]),
                critical=False
            )
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(server_key.public_key()), critical=False)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True, key_encipherment=True,
                    content_commitment=False, data_encipherment=False,
                    key_agreement=False, key_cert_sign=False, crl_sign=True,
                    encipher_only=False, decipher_only=False
                ),
                critical=True
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                    ca_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
                ),
                critical=False
            )
        )
        cert = cert_builder.sign(ca_pk, hashes.SHA256(), default_backend())

        return cert

    def cert_to_file(self, cert, filename):
        with open(filename, "wb") as cfile:
            cfile.write(cert.public_bytes(encoding=serialization.Encoding.PEM))

    def pk_to_file(self, pk, filename):
        with open(filename, "wb") as pkfile:
            pkfile.write(pk.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()))
