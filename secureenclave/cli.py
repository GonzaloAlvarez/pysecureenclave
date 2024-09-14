"""Console script for pysecureenclave."""
import sys
import click
from loguru import logger
from click_loguru import ClickLoguru
from .secureenclave import SecureEnclave

__program__ = 'secureenclave'
__version__ = '0.0.1'

log_format = "<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>\n"
click_loguru = ClickLoguru(__program__, __version__, stderr_format_func=lambda x: log_format)


@click.group(invoke_without_command=False)
@click_loguru.logging_options
@click_loguru.stash_subcommand()
@click_loguru.init_logger(logfile=False)
@click.version_option(prog_name=__program__, version=__version__)
@click.pass_context
def cli(ctx, **kwargs):
    pass


@cli.command(name='enc', help='Encrypt file')
@click_loguru.logging_options
@click_loguru.init_logger(logfile=False)
@click.argument('inputfile', type=click.Path(exists=True))
@click.argument('outputfile')
@click.pass_context
def enc(ctx, inputfile, outputfile, **kwargs):
    with SecureEnclave() as secureenclave:
        secureenclave.encrypt(inputfile, outputfile)


@cli.command(name='dec', help='Decrypt file')
@click_loguru.logging_options
@click_loguru.init_logger(logfile=False)
@click.argument('inputfile', type=click.Path(exists=True))
@click.argument('outputfile')
@click.pass_context
def dec(ctx, inputfile, outputfile, **kwargs):
    with SecureEnclave() as secureenclave:
        secureenclave.decrypt(inputfile, outputfile)


@cli.group(help='Key related operations')
@click_loguru.logging_options
@click_loguru.init_logger(logfile=False)
@click.pass_context
def key(ctx, **kwargs):
    pass


@key.command(name='list', help='List keys')
@click_loguru.logging_options
@click_loguru.init_logger(logfile=False)
@click.pass_context
def keylist(ctx, **kwargs):
    with SecureEnclave() as secureenclave:
        secureenclave.list_keys()


@key.command(name='new', help='New key generation')
@click_loguru.logging_options
@click_loguru.init_logger(logfile=False)
@click.pass_context
def keynew(ctx, **kwargs):
    with SecureEnclave() as secureenclave:
        secureenclave.new_key()


@key.command(name='del', help='Delete Key')
@click_loguru.logging_options
@click_loguru.init_logger(logfile=False)
@click.pass_context
def keydel(ctx, **kwargs):
    with SecureEnclave() as secureenclave:
        secureenclave.del_key()


@cli.group(help='Smart Card related operations')
@click_loguru.logging_options
@click_loguru.init_logger(logfile=False)
@click.pass_context
def card(ctx, **kwargs):
    pass

@card.command(name='status', help='Show Status of Key Card')
@click_loguru.logging_options
@click_loguru.init_logger(logfile=False)
@click.pass_context
def cardstatus(ctx, **kwargs):
    with SecureEnclave() as secureenclave:
        logger.info('Waiting for smart card to be inserted')
        secureenclave.smartcard.wait_for_it()
        secureenclave.card_status()


@card.command(name='list', help='List cards')
@click_loguru.logging_options
@click_loguru.init_logger(logfile=False)
@click.pass_context
def cardslist(ctx, **kwargs):
    with SecureEnclave() as secureenclave:
        logger.info('Waiting for smart card to be inserted')
        secureenclave.smartcard.wait_for_it()
        secureenclave.card_list()

@key.command(name='trust', help='Trust a specific key from the list')
@click_loguru.logging_options
@click_loguru.init_logger(logfile=False)
@click.pass_context
def keytrust(ctx, **kwargs):
    with SecureEnclave() as secureenclave:
        secureenclave.trust_keys()


@cli.command(name='purge', help='Removes configuration from this machine, including all trusted keys')
@click_loguru.logging_options
@click_loguru.init_logger(logfile=False)
@click.pass_context
def purge(ctx, **kwargs):
    SecureEnclave.purge()


if __name__ == "__main__":
    sys.exit(cli(obj={})) # pragma: no cover
