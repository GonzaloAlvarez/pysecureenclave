"""Commands and operations to manage identities from CLI"""
import click
from click_loguru import ClickLoguru
from loguru import logger
from bullet import YesNo
from .consoleui import ConsoleUI
from .datamodel import IdentityInfo
from .secureenclave import SecureEnclave


__all__ = ['id_new', 'id_list', 'id_del']

__program__ = 'secureenclave'
__version__ = '0.0.1'

log_format = "<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>\n"
click_loguru = ClickLoguru(__program__, __version__, stderr_format_func=lambda x: log_format)


@click.command(name='new', help='Create a new identity')
@click.pass_context
def id_new(ctx, **kwargs):
    """Creates a new identity and stores it."""
    identity_info = ConsoleUI().populate_object(IdentityInfo())
    identity_info.active = False
    with SecureEnclave(base_path=ctx.obj.base_path) as secure_enclave:
        secure_enclave.identity_manager.save_identity(identity_info)
    logger.info(f"Identity for {identity_info.first_name} {identity_info.last_name} created.")


@click.command(name='list', help='List all stored identities')
@click.pass_context
def id_list(ctx, **kwargs):
    """Lists all identities stored in the database."""
    with SecureEnclave(base_path=ctx.obj.base_path) as secure_enclave:
        identities = secure_enclave.identity_manager.list_identities()
        if not identities:
            logger.info("No identities found.")
            return

        logger.info(f"  {'ID':<38} {'First Name':<15} {'Last Name':<15} {'Email':<30} {'Salutation':<15}")
        logger.info("-" * 125)
        for identity in identities:
            logger.info(f"{'* ' if identity['active'] else '  '}{identity['id']:<38} {identity['first_name']:<15} {identity['last_name']:<15} {identity['email']:<30} {identity['salutation']:<15}")


@click.command(name='active', help='Toggle the active status of an existing identity')
@click.pass_context
def id_active(ctx, **kwargs):
    """Toggles the active status of an existing identity."""
    with SecureEnclave(base_path=ctx.obj.base_path) as secure_enclave:
        identities = secure_enclave.identity_manager.list_identities()
        if not identities:
            logger.info("No identities found")
            return

        console_ui = ConsoleUI()
        selected_identity = console_ui.select_identity(identities, prompt_message="Select an identity to make active:")

        if not selected_identity:
            logger.info("Identity activation cancelled or no identity selected.")
            return

        secure_enclave.identity_manager.set_active(selected_identity['id'])


@click.command(name='del', help='Delete an existing identity')
@click.pass_context
def id_del(ctx, **kwargs):
    """Deletes an existing identity after user selection and confirmation."""
    with SecureEnclave(base_path=ctx.obj.base_path) as secure_enclave:
        identities = secure_enclave.identity_manager.list_identities()
        if not identities:
            logger.info("No identities found to delete.")
            return

        console_ui = ConsoleUI()
        selected_identity = console_ui.select_identity(identities, prompt_message="Select an identity to delete: ")

        if not selected_identity:
            logger.info("Identity deletion cancelled or no identity selected.")
            return

        identity_to_delete_display = f"{selected_identity['first_name']} {selected_identity['last_name']} ({selected_identity['email']})"
        confirm_prompt = YesNo(f"Are you sure you want to delete the identity for {identity_to_delete_display}? ", default='n')
        if confirm_prompt.launch():
            secure_enclave.identity_manager.delete_identity(selected_identity['id'])
        else:
            logger.info("Identity deletion cancelled.")
