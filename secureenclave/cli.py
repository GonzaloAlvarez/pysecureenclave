"""Console script for pysecureenclave."""
import sys
import click
from click_loguru import ClickLoguru
from .secureenclave import SecureEnclave
from .cli_keycmds import key_list, key_del, key_new, key_trust, key_import
from .cli_cardcmds import card_status, card_list

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
@click.argument('input_file', type=click.Path(exists=True))
@click.argument('output_file')
@click.pass_context
def enc(ctx, input_file, output_file, **kwargs):
    with SecureEnclave() as secure_enclave:
        secure_enclave.encrypt(input_file, output_file)


@cli.command(name='dec', help='Decrypt file')
@click_loguru.logging_options
@click_loguru.init_logger(logfile=False)
@click.argument('input_file', type=click.Path(exists=True))
@click.argument('output_file')
@click.pass_context
def dec(ctx, input_file, output_file, **kwargs):
    with SecureEnclave() as secure_enclave:
        secure_enclave.decrypt(input_file, output_file)


@cli.group(help='Key related operations')
@click_loguru.logging_options
@click_loguru.init_logger(logfile=False)
@click.pass_context
def key(ctx, **kwargs):
    pass


key.add_command(key_trust)
key.add_command(key_del)
key.add_command(key_new)
key.add_command(key_list)
key.add_command(key_import)


@cli.group(help='Smart Card related operations')
@click_loguru.logging_options
@click_loguru.init_logger(logfile=False)
@click.pass_context
def card(ctx, **kwargs):
    pass

card.add_command(card_status)
card.add_command(card_list)


@cli.command(name='purge', help='Removes configuration from this machine, including all trusted keys')
@click_loguru.logging_options
@click_loguru.init_logger(logfile=False)
@click.pass_context
def purge(ctx, **kwargs):
    SecureEnclave.purge()


if __name__ == "__main__":
    sys.exit(cli(obj={})) # pragma: no cover
