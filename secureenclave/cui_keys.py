#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright: (c) 2018, Gonzalo Alvarez

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from bullet import YesNo, Input, VerticalPrompt, Bullet, Password
from loguru import logger

from .datamodel import IdentityInfo, GpgKey
from .consoleui import ConsoleUI


class ConsoleUI_Keys(object):
    def __init__(self):
        self.console_ui = ConsoleUI()

    def prompt_for_new_key_details(self, secure_enclave):
        """
        Prompts the user for all details required to create a new GPG key.
        This includes selecting/creating an identity, key name, and passphrase.

        Args:
            secure_enclave: An instance of the SecureEnclave class.

        Returns:
            A tuple (new_key_uid, passphrase) if successful, or (None, None) if cancelled or an error occurs.
        """
        identity_info = None
        should_create_new_identity = False

        identities = secure_enclave.identity_manager.list_identities()

        if not identities:
            logger.info("No existing identities found.")
            create_new_q = YesNo("Would you like to create a new identity? ", default='y')
            if create_new_q.launch():
                should_create_new_identity = True
            else:
                logger.info("Key creation cancelled as no identity was available or created.")
                return None, None
        else:
            identity_display_strings = [
                f"{identity['first_name']} {identity['last_name']} <{identity['email']}>"
                for identity in identities
            ]

            CREATE_NEW_ACTION_LABEL = "Create a new identity..."
            bullet_choices = identity_display_strings + [CREATE_NEW_ACTION_LABEL]

            selection_prompt = Bullet(
                prompt="\nSelect an identity for the new key, or create a new one:",
                choices=bullet_choices,
                bullet=">",
                indent=0,
                align=2,
                margin=2,
                pad_right=5
            )
            selected_choice_str = selection_prompt.launch()

            if selected_choice_str is None:
                logger.info("Identity selection cancelled. Key creation aborted.")
                return None, None

            if selected_choice_str == CREATE_NEW_ACTION_LABEL:
                should_create_new_identity = True
            else:
                try:
                    selected_index = bullet_choices.index(selected_choice_str)
                    if selected_index < len(identities):
                        selected_identity_dict = identities[selected_index]
                        identity_info = IdentityInfo(
                            first_name=selected_identity_dict['first_name'],
                            last_name=selected_identity_dict['last_name'],
                            email=selected_identity_dict['email'],
                            salutation=selected_identity_dict.get('salutation', '')
                        )
                    else:
                        logger.error("Internal error: Selected choice index out of bounds. Key creation cancelled.")
                        return None, None
                except ValueError:
                    logger.error(f"Internal error: Selected choice '{selected_choice_str}' not in provided choices. Key creation cancelled.")
                    return None, None

        if should_create_new_identity:
            logger.info("Creating a new identity for the key.")
            new_identity_obj = IdentityInfo()
            created_identity = self.console_ui.populate_object(new_identity_obj)
            if created_identity:
                identity_info = created_identity
                secure_enclave.identity_manager.save_identity(identity_info)
            else:
                logger.info("Identity creation cancelled by user. Key creation aborted.")
                return None, None

        if not identity_info:
            logger.info("Key creation aborted as no identity was specified or created.")
            return None, None

        owner_full_name = f"{identity_info.first_name} {identity_info.last_name}"
        owner_email = identity_info.email

        key_prompts = VerticalPrompt([
            Input("Key Name (e.g., Work Laptop Key): "),
            Password("Key Password: "),
            Password("Confirm Key Password: ")
        ], spacing=0).launch()

        key_name_desc = key_prompts[0][1]
        passphrase = key_prompts[1][1]
        confirm_passphrase = key_prompts[2][1]

        if passphrase != confirm_passphrase:
            logger.error("Passwords do not match. Try again.")
            return None, None

        new_key_uid = f'{owner_full_name} ({key_name_desc}) <{owner_email}>'
        return new_key_uid, passphrase


def display_key(key: GpgKey):
    """
    Displays the details of a single GPG key to the console.
    """
    key_type = "Secret" if key.secret_available else "Public"
    logger.info("───────────────────────────────────────────────────────────────────────────")
    logger.info(f"👤 UID: {key.uid}")
    logger.info(f"   Key ID: {key.key_id} ({key_type})")
    if key.secret_in_card and key.card_serial:
        logger.info(f"   Secret in Card with Serial Number: {key.card_serial}")
    logger.info(f"   Fingerprint: {key.fingerprint if key.fingerprint else 'N/A'}")
    logger.info(f"   Algorithm: {key.algorithm_name} ({key.key_length} bits)")
    # TODO: Consider formatting date for creation_date and expiration_date
    logger.info(f"   Created: {key.creation_date}")
    if key.expiration_date:
        logger.info(f"   Expires: {key.expiration_date}")
    else:
        logger.info("   Expires: Never")
    logger.info(f"   Capabilities: {', '.join(key.capabilities) if key.capabilities else 'N/A'}")
    logger.info(f"   Trust: {key.owner_trust} (UID: {key.uid_validity})")

    if key.subkeys:
        logger.info("   Subkeys:")
        for subkey in key.subkeys:
            subkey_type = "Secret" if subkey.secret_available else "Public"
            logger.info(f"     └─ Subkey ID: {subkey.key_id} ({subkey_type})")
            logger.info(f"        Fingerprint: {subkey.fingerprint if subkey.fingerprint else 'N/A'}")
            logger.info(f"        Algorithm: {subkey.algorithm_name} ({subkey.key_length} bits)")
            logger.info(f"        Created: {subkey.creation_date}")
            if subkey.expiration_date:
                logger.info(f"        Expires: {subkey.expiration_date}")
            else:
                logger.info("        Expires: Never")
            logger.info(f"        Capabilities: {', '.join(subkey.capabilities) if subkey.capabilities else 'N/A'}")
    else:
        logger.info("   No Subkeys")
