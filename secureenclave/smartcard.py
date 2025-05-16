#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright: (c) 2018, Gonzalo Alvarez

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import time
import re

from loguru import logger
from ykman.device import list_all_devices, scan_devices
from bullet import Bullet

from .datamodel import Card, CardKeyDetails
from typing import Optional


class SmartCard:
    def __init__(self, gpg):
        self.gpg = gpg

    def wait_for_it(self):
        state = None
        while True:
            _pids, new_state = scan_devices()  # Use _pids as pids is not used
            if new_state != state:
                devices = list_all_devices()
                if devices:
                    logger.debug(devices)
                    # Always wait a bit for GPG to recognize the card after ykman detects it.
                    logger.debug('Card detected by ykman. Waiting 1 second for GPG to pick up the card.')
                    time.sleep(1.0)
                    return devices
            # Update state for the next iteration to detect changes
            state = new_state
            time.sleep(0.2)

    def list_cards(self):
        return list_all_devices()

    def is_card_installed(self):
        """Check if a smartcard is installed"""
        try:
            gpg_cmd = '{} --quiet --batch --card-status --no-tty'.format(self.gpg.getbin())
            result = self.gpg.run_cmd(gpg_cmd, silent=True)
            if match := re.search(r'sec\s+([a-zA-Z0-9/]+)', result.stdout):  # type: ignore
                self.card_pub = match.group(1)
                logger.debug(f'Found key in card [{self.card_pub}]')
            else:
                logger.debug('Failed to match. No secure key in card')
                logger.debug(result.stdout)  # type: ignore
            return True
        except Exception:
            logger.debug('Card failed to be recognized')
            return False

    def _parse_field_value(self, line_part: str) -> Optional[str]:
        val = line_part.strip()
        if val.startswith('[') and val.endswith(']') and \
           ("not set" in val or "none" in val or "disabled" in val or "no private data" in val):
            return None
        return val

    def _parse_card_status(self, raw_output: str) -> Optional[Card]:
        card = Card()
        current_key_context: Optional[CardKeyDetails] = None
        lines = raw_output.splitlines()

        for line in lines:
            parts = line.split(':', 1)
            if len(parts) < 2:
                if "General key info" in line and current_key_context:  # Handle general key info under a key block
                    # This is a bit of a guess, GPG output can be tricky here.
                    # Often "General key info" is its own section or part of a subkey block.
                    # For card status, it might be simpler or not present for the main keys.
                    pass  # Or parse if there's a clear pattern
                elif line.strip().startswith("created") and ":" in line and current_key_context:  # For key creation dates
                    created_val = self._parse_field_value(parts[0].split("created", 1)[-1].strip(". :"))
                    if created_val and current_key_context:
                        current_key_context.created = created_val
                    current_key_context = None  # Reset after processing 'created'
                continue

            key = parts[0].strip()
            value = self._parse_field_value(parts[1])

            if key == "Reader":
                card.reader = value
            elif key == "Application ID":
                card.application_id = value
            elif key == "Application type":
                card.application_type = value
            elif key == "Version":
                card.version = value
            elif key == "Manufacturer":
                card.manufacturer = value
            elif key == "Serial number":
                card.serial_number = value
            elif key == "Name of cardholder":
                card.cardholder_name = value
            elif key == "Language prefs":
                card.language_prefs = value
            elif key == "Sex":
                card.sex = value
            elif key == "Login data":
                card.login_data = value
            elif key == "URL of public key":
                card.url_of_public_key = value
            elif key == "Private data avail":
                card.private_data_available = value
            elif key == "Signature PIN":
                card.signature_pin_state = value
            elif key == "Signature counter":
                card.signature_counter = int(value) if value and value.isdigit() else None
            elif key == "General key info":
                card.general_key_info = value
            elif key.startswith("CA fingerprint"):
                if key.endswith("1"):
                    card.ca_fingerprint_1 = value
                elif key.endswith("2"):
                    card.ca_fingerprint_2 = value
                elif key.endswith("3"):
                    card.ca_fingerprint_3 = value
            elif key == "Key attributes":
                if value:
                    attrs = value.split()
                    if len(attrs) > 0:
                        card.key_attributes_sig = attrs[0]
                    if len(attrs) > 1:
                        card.key_attributes_enc = attrs[1]
                    if len(attrs) > 2:
                        card.key_attributes_auth = attrs[2]
            elif key == "Max. PIN lengths":
                if value:
                    lengths = value.split()
                    if len(lengths) > 0 and lengths[0].isdigit():
                        card.max_pin_lengths_sig = int(lengths[0])
                    if len(lengths) > 1 and lengths[1].isdigit():
                        card.max_pin_lengths_enc = int(lengths[1])
                    if len(lengths) > 2 and lengths[2].isdigit():
                        card.max_pin_lengths_auth = int(lengths[2])
            elif key == "PIN retry counter":
                if value:
                    retries = value.split()
                    # Format can be "S E A" or "S E A K" (Sig, Enc, Admin, KDF)
                    # We are interested in S, E, A
                    if len(retries) > 0 and retries[0].isdigit():
                        card.pin_retry_sig = int(retries[0])
                    if len(retries) > 1 and retries[1].isdigit():
                        card.pin_retry_enc = int(retries[1])
                    if len(retries) > 2 and retries[2].isdigit():
                        card.pin_retry_admin = int(retries[2])
            elif key == "Signature key":
                card.sig_key = CardKeyDetails(key_type="Signature", fingerprint=value)
                current_key_context = card.sig_key
            elif key == "Encryption key":
                card.enc_key = CardKeyDetails(key_type="Encryption", fingerprint=value)
                current_key_context = card.enc_key
            elif key == "Authentication key":
                card.auth_key = CardKeyDetails(key_type="Authentication", fingerprint=value)
                current_key_context = card.auth_key
            elif key == "created" and current_key_context:  # Handles 'created' on its own line or as part of key line
                current_key_context.created = value
                current_key_context = None  # Reset after processing 'created'
            else:  # Reset context if an unrelated line or a new key line appears
                if not (key.endswith("key") and "key" in key.lower()):  # avoid resetting if it's a key line itself
                    current_key_context = None
        return card

    def card_status(self):
        """Retrieve status of smartcard, parse it, and display details."""
        gpg_cmd = '{} --quiet --batch --card-status --no-tty'.format(self.gpg.getbin())
        result = self.gpg.run_cmd(gpg_cmd, silent=True)

        if result is None:
            logger.error("Failed to execute GPG command for card status. `run_cmd` returned None.")
            return

        if result.returncode != 0:
            logger.error(f"Failed to get card status. GPG error: {result.stderr}")
            if result.stdout:
                logger.error(f"GPG stdout: {result.stdout}")
            return

        if not result.stdout:
            logger.info("No card status information returned by GPG.")
            return

        card_data = self._parse_card_status(result.stdout)

        if not card_data:
            logger.error("Failed to parse card status information.")
            logger.debug(f"Raw GPG output:\n{result.stdout}")
            return

        logger.info("💳 Smart Card Status ─────────────────────────────────────────────────────────")
        if card_data.reader:
            logger.info(f"   Reader: {card_data.reader}")
        if card_data.application_id:
            logger.info(f"   Application ID: {card_data.application_id}")
        if card_data.application_type:
            logger.info(f"   Application Type: {card_data.application_type}")
        if card_data.version:
            logger.info(f"   Version: {card_data.version}")
        if card_data.manufacturer:
            logger.info(f"   Manufacturer: {card_data.manufacturer}")
        if card_data.serial_number:
            logger.info(f"   Serial Number: {card_data.serial_number}")
        if card_data.cardholder_name:
            logger.info(f"   Cardholder Name: {card_data.cardholder_name}")
        else:
            logger.info("   Cardholder Name: [not set]")
        if card_data.language_prefs:
            logger.info(f"   Language Prefs: {card_data.language_prefs}")
        else:
            logger.info("   Language Prefs: [not set]")
        if card_data.sex:
            logger.info(f"   Sex: {card_data.sex}")
        else:
            logger.info("   Sex: [not set]")
        if card_data.login_data:
            logger.info(f"   Login Data: {card_data.login_data}")
        else:
            logger.info("   Login Data: [not set]")
        if card_data.url_of_public_key:
            logger.info(f"   URL of Public Key: {card_data.url_of_public_key}")
        else:
            logger.info("   URL of Public Key: [not set]")
        if card_data.private_data_available:
            logger.info(f"   Private Data Available: {card_data.private_data_available}")
        if card_data.signature_pin_state:
            logger.info(f"   Signature PIN State: {card_data.signature_pin_state}")

        logger.info("   Key Attributes:")
        if card_data.key_attributes_sig:
            logger.info(f"     ├─ Signature: {card_data.key_attributes_sig}")
        else:
            logger.info("     ├─ Signature: N/A")
        if card_data.key_attributes_enc:
            logger.info(f"     ├─ Encryption: {card_data.key_attributes_enc}")
        else:
            logger.info("     ├─ Encryption: N/A")
        if card_data.key_attributes_auth:
            logger.info(f"     └─ Authentication: {card_data.key_attributes_auth}")
        else:
            logger.info("     └─ Authentication: N/A")

        logger.info("   Max PIN Lengths:")
        if card_data.max_pin_lengths_sig is not None:
            logger.info(f"     ├─ Signature: {card_data.max_pin_lengths_sig}")
        else:
            logger.info("     ├─ Signature: N/A")
        if card_data.max_pin_lengths_enc is not None:
            logger.info(f"     ├─ Encryption: {card_data.max_pin_lengths_enc}")
        else:
            logger.info("     ├─ Encryption: N/A")
        if card_data.max_pin_lengths_auth is not None:
            logger.info(f"     └─ Authentication: {card_data.max_pin_lengths_auth}")
        else:
            logger.info("     └─ Authentication: N/A")

        logger.info("   PIN Retry Counters:")
        if card_data.pin_retry_sig is not None:
            logger.info(f"     ├─ Signature: {card_data.pin_retry_sig}")
        else:
            logger.info("     ├─ Signature: N/A")
        if card_data.pin_retry_enc is not None:
            logger.info(f"     ├─ Encryption: {card_data.pin_retry_enc}")
        else:
            logger.info("     ├─ Encryption: N/A")
        if card_data.pin_retry_admin is not None:
            logger.info(f"     └─ Admin: {card_data.pin_retry_admin}")
        else:
            logger.info("     └─ Admin: N/A")

        if card_data.signature_counter is not None:
            logger.info(f"   Signature Counter: {card_data.signature_counter}")

        key_details = [
            ("Signature Key", card_data.sig_key, card_data.key_attributes_sig),
            ("Encryption Key", card_data.enc_key, card_data.key_attributes_enc),
            ("Authentication Key", card_data.auth_key, card_data.key_attributes_auth)
        ]

        for title, key_info, attrs in key_details:
            if key_info:
                logger.info(f"   {title}:")
                if key_info.fingerprint:
                    logger.info(f"     ├─ Fingerprint: {key_info.fingerprint}")
                else:
                    logger.info("     ├─ Fingerprint: [not set]")
                if key_info.created:
                    logger.info(f"     ├─ Created: {key_info.created}")
                else:
                    logger.info("     ├─ Created: [not set]")
                if attrs:
                    logger.info(f"     └─ Attributes: {attrs}")  # Redundant if already shown above, but good for context
            else:
                logger.info(f"   {title}: [not set or not available]")

        if card_data.general_key_info:
            logger.info(f"   General Key Info: {card_data.general_key_info}")
        if card_data.ca_fingerprint_1:
            logger.info(f"   CA Fingerprint 1: {card_data.ca_fingerprint_1}")
        if card_data.ca_fingerprint_2:
            logger.info(f"   CA Fingerprint 2: {card_data.ca_fingerprint_2}")
        if card_data.ca_fingerprint_3:
            logger.info(f"   CA Fingerprint 3: {card_data.ca_fingerprint_3}")
        logger.info("───────────────────────────────────────────────────────────────────────────")

    def card_list(self):
        """List all available cards """
        cards = self.list_cards()
        logger.info(f'Number of cards: {len(cards)}')
        for idx, card in enumerate(cards):
            dev, info = card
            logger.info(f'Card {idx + 1}: {dev.fingerprint}')

    def card_config(self, card_info):
        """Configure smartcard with given information """
        if card_info.first_name:
            self.gpg.card_edit('name', f"{card_info.last_name}\n{card_info.first_name}")
        if card_info.email:
            self.gpg.card_edit('email', card_info.email)
        if card_info.public_key_url:
            self.gpg.card_edit('url', card_info.public_key_url)
        if card_info.sex:
            self.gpg.card_edit('sex', card_info.sex)
        self.gpg.card_edit('lang', 'en')
        self.gpg.card_edit('pinretrylimit', '3')

    def card_import_key(self):
        """Import key into smartcard"""
        keys = self.gpg.get_keys()
        selected = Bullet('Select which key to import: ', keys).launch()  # type:ignore
        key_index = 1
        for subkey in selected.subkeys:
            if 'sign' in subkey.capabilities:
                self.gpg.card_key_edit(selected.fingerprint, key_index, 1)
            elif 'encrypt' in subkey.capabilities:
                self.gpg.card_key_edit(selected.fingerprint, key_index, 2)
            elif 'auth' in subkey.capabilities:
                self.gpg.card_key_edit(selected.fingerprint, key_index, 3)
            key_index = key_index + 1
