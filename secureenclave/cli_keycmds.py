"""Console scripts for key handling"""
import click
from click_loguru import ClickLoguru
from .secureenclave import SecureEnclave

__all__ = ['key_list', 'key_del', 'key_new', 'key_trust']

__program__ = 'secureenclave'
__version__ = '0.0.1'

log_format = "<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>\n"
click_loguru = ClickLoguru(__program__, __version__, stderr_format_func=lambda x: log_format)

@click.command(name='list', help='List keys')
@click_loguru.logging_options
@click_loguru.init_logger(logfile=False)
@click.pass_context
def key_list(ctx, **kwargs):
    with SecureEnclave() as secure_enclave:
        secure_enclave.list_keys()


@click.command(name='new', help='New key generation')
@click_loguru.logging_options
@click_loguru.init_logger(logfile=False)
@click.pass_context
def key_new(ctx, **kwargs):
    with SecureEnclave() as secure_enclave:
        secure_enclave.new_key()


@click.command(name='del', help='Delete Key')
@click_loguru.logging_options
@click_loguru.init_logger(logfile=False)
@click.pass_context
def key_del(ctx, **kwargs):
    with SecureEnclave() as secure_enclave:
        secure_enclave.del_key()


@click.command(name='trust', help='Trust a specific key from the list')
@click_loguru.logging_options
@click_loguru.init_logger(logfile=False)
@click.pass_context
def key_trust(ctx, **kwargs):
    with SecureEnclave() as secure_enclave:
        secure_enclave.trust_keys()
