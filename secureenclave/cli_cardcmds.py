"""Console scripts for card handling"""
import click
from loguru import logger
from click_loguru import ClickLoguru
from .secureenclave import SecureEnclave
from .consoleui import ConsoleUI
from .datamodel import CardInfo

__all__ = ['card_list', 'card_status']

__program__ = 'secureenclave'
__version__ = '0.0.1'

log_format = "<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>\n"
click_loguru = ClickLoguru(__program__, __version__, stderr_format_func=lambda x: log_format)


@click.command(name='status', help='Show Status of Key Card')
@click_loguru.logging_options
@click_loguru.init_logger(logfile=False)
@click.pass_context
def card_status(ctx, **kwargs):
    with SecureEnclave() as secure_enclave:
        logger.info('Waiting for smart card to be inserted')
        secure_enclave.smartcard.wait_for_it()
        secure_enclave.smartcard.card_status()


@click.command(name='list', help='List cards')
@click_loguru.logging_options
@click_loguru.init_logger(logfile=False)
@click.pass_context
def card_list(ctx, **kwargs):
    with SecureEnclave() as secure_enclave:
        logger.info('Waiting for smart card to be inserted')
        secure_enclave.smartcard.wait_for_it()
        secure_enclave.smartcard.card_list()


@click.command(name='config', help='Configure a card attributes')
@click_loguru.logging_options
@click_loguru.init_logger(logfile=False)
@click.pass_context
def card_config(ctx, **kwargs):
    with SecureEnclave() as secure_enclave:
        logger.info('Waiting for smart card to be inserted')
        secure_enclave.smartcard.wait_for_it()
        if len(secure_enclave.smartcard.list_cards()) > 1:
            logger.info('You have more than one card installed. Unfortunately, GPG does not support it. Please, insert only one and try again')
        card_info = ConsoleUI().populate_object(CardInfo())
        secure_enclave.smartcard.card_config(card_info)


@click.command(name='importkey', help='Import a key into the smart card')
@click_loguru.logging_options
@click_loguru.init_logger(logfile=False)
@click.pass_context
def card_import_key(ctx, **kwargs):
    with SecureEnclave() as secure_enclave:
        logger.info('Waiting for smart card to be inserted')
        secure_enclave.smartcard.wait_for_it()
        if len(secure_enclave.smartcard.list_cards()) > 1:
            logger.info('You have more than one card installed. Unfortunately, GPG does not support it. Please, insert only one and try again')
        secure_enclave.smartcard.card_import_key()
