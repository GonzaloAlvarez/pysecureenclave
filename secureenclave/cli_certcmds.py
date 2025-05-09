"""Commands and operations to manage certificates from CLI"""
import click
from click_loguru import ClickLoguru
from .consoleui import ConsoleUI
from .datamodel import CertInfo, ServerInfo
from .certs import CertManager


__all__ = []

__program__ = 'secureenclave'
__version__ = '0.0.1'

log_format = "<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>\n"
click_loguru = ClickLoguru(__program__, __version__, stderr_format_func=lambda x: log_format)


@click.command(name='newca', help='Create a new Master SSL Certificate Authority')
@click_loguru.logging_options
@click_loguru.init_logger(logfile=False)
@click.pass_context
def cert_newca(ctx, **kwargs):
    cert_info = ConsoleUI().populate_object(CertInfo())
    cert_manager = CertManager()
    pk = cert_manager.new_private_key(4096)
    cert = cert_manager.new_ca_cert(cert_info, pk)
    cert_manager.cert_to_file(cert, "ca.crt")
    cert_manager.pk_to_file(pk, "private_key.pem")


@click.command(name='newserver', help='Create a new Master SSL Certificate Authority')
@click_loguru.logging_options
@click_loguru.init_logger(logfile=False)
@click.option("--ca-cert", "ca_cert_file", type=click.Path(exists=True, readable=True), required=True)
@click.option("--server-key", "server_private_key", type=click.Path(exists=True, readable=True), required=True)
@click.pass_context
def cert_newserver(ctx, ca_cert_file, server_private_key, **kwargs):
    cert_manager = CertManager()
    ca_cert = cert_manager.cert_from_file(ca_cert_file)
    server_pk = cert_manager.pk_from_file(server_private_key)
    server_info = ConsoleUI().populate_object(ServerInfo())
    server_pk = cert_manager.new_private_key(4096)
    server_cert = cert_manager.new_server_cert(server_info, server_pk, ca_cert, server_pk)
    cert_manager.cert_to_file(server_cert, "server_cert.crt")
    cert_manager.pk_to_file(server_pk, "server_private_key.pem")
