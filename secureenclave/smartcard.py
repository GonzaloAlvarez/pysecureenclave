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


class SmartCard:
    def __init__(self, gpg):
        self.gpg = gpg

    def wait_for_it(self):
        state = None
        card_not_found = False
        while True:
            pids, new_state = scan_devices()
            if new_state != state:
                devices = list_all_devices()
                if devices:
                    logger.debug(devices)
                    if card_not_found:
                        logger.debug('waiting 500 milliseconds for GPG to pick up the card')
                        time.sleep(0.5)
                    return devices
            card_not_found = True
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

    def card_status(self):
        """Retrieve status of smartcard """
        gpg_cmd = '{} --quiet --batch --card-status --no-tty'.format(self.gpg.getbin())
        self.gpg.run_cmd(gpg_cmd, silent=False)

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
