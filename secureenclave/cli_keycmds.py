"""Console scripts for key handling"""
import click
from click_loguru import ClickLoguru
from loguru import logger
from .secureenclave import SecureEnclave
from .cui_keys import ConsoleUI_Keys

__all__ = ['key_list', 'key_del', 'key_new', 'key_trust', 'key_import']

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
        keys = secure_enclave.gpg.get_keys()
        if not keys:
            logger.info("No GPG keys found in the keyring.")
            return

        logger.info("Available GPG Keys:")
        for key in keys:
            key_type = "Secret" if key.is_secret else "Public"
            logger.info("───────────────────────────────────────────────────────────────────────────")
            logger.info(f"👤 UID: {key.uid}")
            logger.info(f"   Key ID: {key.key_id} ({key_type})")
            logger.info(f"   Fingerprint: {key.fingerprint if key.fingerprint else 'N/A'}")
            logger.info(f"   Algorithm: {key.algorithm_name} ({key.key_length} bits)")
            logger.info(f"   Created: {key.creation_date}")  # Consider formatting date
            if key.expiration_date:
                logger.info(f"   Expires: {key.expiration_date}")  # Consider formatting date
            else:
                logger.info("   Expires: Never")
            logger.info(f"   Capabilities: {', '.join(key.capabilities) if key.capabilities else 'N/A'}")
            logger.info(f"   Trust: {key.owner_trust} (UID: {key.uid_validity})")

            if key.subkeys:
                logger.info("   Subkeys:")
                for subkey in key.subkeys:
                    subkey_type = "Secret" if subkey.is_secret else "Public"
                    logger.info(f"     └─ Subkey ID: {subkey.key_id} ({subkey_type})")
                    logger.info(f"        Fingerprint: {subkey.fingerprint if subkey.fingerprint else 'N/A'}")
                    logger.info(f"        Algorithm: {subkey.algorithm_name} ({subkey.key_length} bits)")
                    logger.info(f"        Created: {subkey.creation_date}")  # Consider formatting date
                    if subkey.expiration_date:
                        logger.info(f"        Expires: {subkey.expiration_date}")  # Consider formatting date
                    else:
                        logger.info("        Expires: Never")
                    logger.info(f"        Capabilities: {', '.join(subkey.capabilities) if subkey.capabilities else 'N/A'}")
            else:
                logger.info("   No Subkeys")
        logger.info("───────────────────────────────────────────────────────────────────────────")


@click.command(name='import', help='Import key into keyring')
@click_loguru.logging_options
@click_loguru.init_logger(logfile=False)
@click.argument('input_file', type=click.Path(exists=True))
@click.pass_context
def key_import(ctx, input_file, **kwargs):
    with SecureEnclave() as secure_enclave:
        secure_enclave.import_key(input_file)


@click.command(name='new', help='New key generation')
@click_loguru.logging_options
@click_loguru.init_logger(logfile=False)
@click.pass_context
def key_new(ctx, **kwargs):
    with SecureEnclave() as secure_enclave:
        console_ui_keys = ConsoleUI_Keys()
        new_key_uid, passphrase = console_ui_keys.prompt_for_new_key_details(secure_enclave)

        if new_key_uid is not None:
            if not secure_enclave.new_key(new_key_uid, passphrase):
                logger.error("Key creation process failed in the backend.")
        else:
            logger.info("Key creation process was cancelled or input was invalid.")


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
