#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright: (c) 2018, Gonzalo Alvarez

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from bullet import YesNo, Input, VerticalPrompt, Bullet, Password
from loguru import logger

from .datamodel import IdentityInfo
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

        choice_prompt = Bullet(
            prompt="\nHow do you want to associate this key with an identity?",
            choices=["Use an existing identity", "Create a new identity"],
            bullet=">",
            indent=0,
            align=2,
            margin=2,
            pad_right=5
        )
        identity_choice_str = choice_prompt.launch()

        if identity_choice_str == "Use an existing identity":
            identities = secure_enclave.list_identities()
            if not identities:
                logger.info("No existing identities found.")
                create_new_q = YesNo("Would you like to create a new identity instead? ", default='y')
                if create_new_q.launch():
                    identity_choice_str = "Create a new identity"  # Fall through to creation
                else:
                    logger.info("Key creation cancelled as no identity was selected or created.")
                    return None, None
            else:
                selected_identity_dict = self.console_ui.select_identity(identities, "Select an identity for the new key:")
                if selected_identity_dict:
                    identity_info = IdentityInfo(
                        first_name=selected_identity_dict['first_name'],
                        last_name=selected_identity_dict['last_name'],
                        email=selected_identity_dict['email'],
                        salutation=selected_identity_dict.get('salutation', '')
                    )
                else:
                    logger.info("No identity selected. Key creation cancelled.")
                    return None, None
        
        if identity_choice_str == "Create a new identity":  # Handles fall-through and direct choice
            logger.info("Creating a new identity for the key.")
            new_identity_obj = IdentityInfo()
            identity_info = self.console_ui.populate_object(new_identity_obj)
            secure_enclave.save_identity(identity_info)

        if not identity_info:
            logger.info("Key creation aborted as no identity was specified.")
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
