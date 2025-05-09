#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright: (c) 2018, Gonzalo Alvarez

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type
import shutil
import platformdirs
import invoke
import re
import sqlite3
import uuid

from loguru import logger
from pathlib import Path
from io import StringIO
from bullet import YesNo, Input, VerticalPrompt, Bullet, Password # Input, Password, VerticalPrompt, Bullet, YesNo are used

from .gpg import Gpg
from .gpgagent import GpgAgent
from .smartcard import SmartCard
# IdentityInfo and ConsoleUI are no longer directly used by new_key, but kept for other methods.
from .datamodel import IdentityInfo
from .consoleui import ConsoleUI


__author__ = 'Gonzalo Alvarez'
__program__ = 'SecureEnclave'

__gpg_fetch_key__ = """admin
fetch
quit
"""

__gpg_trust_key__ = """trust
5
y
quit
"""


class SecureEnclave(object):
    @staticmethod
    def purge():
        home = Path(platformdirs.user_data_dir(__program__, __author__))
        client = YesNo('Are you sure you want to remove the configuration folder for Secure Enclave and all the stored keys? ', default='n')
        if client.launch():
            shutil.rmtree(home)
            logger.debug('Configuration removed')

    def __init__(self):
        self.home = Path(platformdirs.user_data_dir(__program__, __author__))
        self.gpg = Gpg(self.home)
        self.gpg_agent = GpgAgent(self.gpg)
        self.smartcard = SmartCard(self.gpg)
        self.db_path = self.home / 'identities.db'
        self._init_db()

    def _init_db(self):
        """Initializes the SQLite database and creates the identities table if it doesn't exist."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS identities (
                    id TEXT PRIMARY KEY,
                    first_name TEXT,
                    last_name TEXT,
                    email TEXT,
                    salutation TEXT
                )
            ''')
            conn.commit()
        except sqlite3.Error as e:
            logger.error(f"Database error during initialization: {e}")
        finally:
            if conn:
                conn.close()

    def save_identity(self, identity_info):
        """Saves a new identity to the database."""
        identity_id = str(uuid.uuid4())
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO identities (id, first_name, last_name, email, salutation)
                VALUES (?, ?, ?, ?, ?)
            ''', (identity_id, identity_info.first_name, identity_info.last_name, identity_info.email, identity_info.salutation))
            conn.commit()
            logger.success(f"Identity saved with ID: {identity_id}")
        except sqlite3.Error as e:
            logger.error(f"Failed to save identity: {e}")
        finally:
            if conn:
                conn.close()

    def list_identities(self):
        """Retrieves all identities from the database."""
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT id, first_name, last_name, email, salutation FROM identities")
            rows = cursor.fetchall()
            identities = [dict(row) for row in rows]
            return identities
        except sqlite3.Error as e:
            logger.error(f"Failed to list identities: {e}")
            return []
        finally:
            if conn:
                conn.close()

    def delete_identity(self, identity_id):
        """Deletes an identity from the database by its ID."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("DELETE FROM identities WHERE id = ?", (identity_id,))
            conn.commit()
            if cursor.rowcount > 0:
                logger.success(f"Identity with ID: {identity_id} deleted successfully.")
            else:
                logger.warning(f"No identity found with ID: {identity_id}.")
        except sqlite3.Error as e:
            logger.error(f"Failed to delete identity {identity_id}: {e}")
        finally:
            if conn:
                conn.close()

    def is_card_installed(self):
        """Check if a smartcard is installed"""
        try:
            gpg_cmd = '{} --quiet --batch --card-status --no-tty'.format(self.gpg.getbin())
            result = invoke.run(gpg_cmd, env=self.gpg.getenv(), pty=True, hide=True)
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

    def _run_cmd(self, cmd, silent=True, in_stream=None):
        try:
            invoke.run(cmd, env=self.gpg.getenv(), pty=not silent, hide=silent, in_stream=in_stream)
        except Exception as e:
            logger.warning('Invocation of GPG command has failed')
            logger.warning(f'CMD: {cmd}')
            logger.warning(f'Exception: {str(e)}')

    def __enter__(self):
        """Enter context manager"""
        self.gpg_agent.start()
        if self.is_card_installed():
            key_list = self.gpg.get_keys()
            logger.debug(key_list)
            if hasattr(self, 'card_pub') and self.card_pub and len(list(filter(lambda x: x.pub == self.card_pub, key_list))) > 0:
                logger.debug(f'key [{self.card_pub}] already in key list')
            else:
                logger.info('A card is installed. Retrieving remote key id from card')
                gpg_cmd = '{} --quiet --card-edit --expert --batch --display-charset utf-8 --no-tty --command-fd 0'.format(self.gpg.getbin())
                self._run_cmd(gpg_cmd, in_stream=StringIO(__gpg_fetch_key__))
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Exit context manager"""
        self.gpg_agent.stop()

    def card_status(self):
        """Retrieve status of smartcard """
        gpg_cmd = '{} --quiet --batch --card-status --no-tty'.format(self.gpg.getbin())
        invoke.run(gpg_cmd, env=self.gpg.getenv(), pty=True)

    def card_list(self):
        """List all available cards """
        cards = self.smartcard.list_cards()
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
        selected = Bullet('Select which key to delete: ', keys).launch()  # type:ignore
        for key_number in 1, 2, 3:
            self.gpg.card_key_edit(selected.fingerprint, key_number, key_number)

    def list_keys(self):
        """List keys on smartcard"""
        logger.info('Public keys')
        gpg_cmd = '{} --list-keys --with-keygrip'.format(self.gpg.getbin())
        invoke.run(gpg_cmd, env=self.gpg.getenv(), pty=True)
        logger.info('Private keys')
        gpg_cmd = '{} --list-secret-keys'.format(self.gpg.getbin())
        invoke.run(gpg_cmd, env=self.gpg.getenv(), pty=True)

    def import_key(self, filename):
        gpg_cmd = '{} --import {}'.format(self.gpg.getbin(), filename)
        invoke.run(gpg_cmd, env=self.gpg.getenv(), pty=True)

    def new_key(self, new_key_uid, passphrase):
        """
        Creates a new GPG key with the provided UID and passphrase.
        Handles the GPG command execution for key and subkey generation.

        Args:
            new_key_uid: The user ID string for the new key.
            passphrase: The passphrase for the new key.

        Returns:
            True if key creation was successful, False otherwise.
        """
        if not new_key_uid or not passphrase:
            logger.error("New key UID or passphrase not provided.")
            return False
            
        logger.info(f"Creating new GPG key for UID: {new_key_uid}")
        gpg_cmd = '{} -q --batch --passphrase {} --quick-generate-key "{}" rsa4096 cert never'.format(self.gpg.getbin(), passphrase, new_key_uid)
        result = invoke.run(gpg_cmd, env=self.gpg.getenv(), pty=True)
        if result.exited != 0:  # type:ignore
            logger.error("Could not create the master GPG key properly.")
            logger.error(f"GPG command output: {result.stdout} {result.stderr}")
            return False
        
        created_key = None
        # Refresh keys and find the newly created one
        # GPG's --quick-generate-key output isn't easily parsable for the fingerprint directly in a batch mode without complex parsing.
        # Relying on matching the UID is a common approach.
        for key_attempt in self.gpg.get_keys(): 
            if new_key_uid in key_attempt.uid:
                created_key = key_attempt
                break
        
        if not created_key:
            logger.error(f"Failed to find the newly created GPG key with UID part: {new_key_uid}. Please check GPG manually.")
            available_keys_uids = [k.uid for k in self.gpg.get_keys()]
            logger.debug(f"Available key UIDs after creation attempt: {available_keys_uids}")
            return False

        logger.debug(f'New GPG key created with fingerprint {created_key.fingerprint}')
        logger.info('New GPG key created. Proceeding to create its subkeys.')
        for subkey_type in ['sign', 'encrypt', 'auth']:
            logger.info(f"Creating {subkey_type} subkey...")
            gpg_cmd = '{} -q --batch --pinentry-mode=loopback --passphrase {} --quick-add-key "{}" rsa4096 "{}" "2y"'.format(self.gpg.getbin(), passphrase, created_key.fingerprint, subkey_type)
            result = invoke.run(gpg_cmd, env=self.gpg.getenv(), pty=True)
            if result.exited != 0:  # type:ignore
                logger.error(f'Could not create {subkey_type} subkey properly.')
                logger.error(f"GPG command output: {result.stdout} {result.stderr}")
                # Consider if we should attempt to clean up the master key if a subkey fails. For now, it doesn't.
                return False
            logger.success(f'{subkey_type.capitalize()} subkey created successfully.')
        logger.success('GPG Key creation completed, including all subkeys. Use "key list" to explore.')
        return True

    def del_key(self):
        keys = self.gpg.get_keys()
        selected = Bullet('Select which key to delete: ', keys).launch()  # type:ignore
        gpg_cmd = '{} -q --batch --delete-secret-key {}'.format(self.gpg.getbin(), selected.fingerprint)
        invoke.run(gpg_cmd, env=self.gpg.getenv(), pty=True)
        gpg_cmd = '{} -q --batch --delete-key {}'.format(self.gpg.getbin(), selected.fingerprint)
        invoke.run(gpg_cmd, env=self.gpg.getenv(), pty=True)

    def encrypt(self, input, output):
        key_list = self.gpg.get_keys()
        if len(key_list):
            selected = Bullet('Select which key to delete: ', key_list).launch()  # type:ignore
            key_id = selected.fingerprint
            logger.debug(f'Encrypting with keyid [{key_id}]')
            gpg_cmd = '{} --quiet --armor --encrypt --recipient {} -o {} {}'.format(self.gpg.getbin(), key_id, output, input)
            invoke.run(gpg_cmd, env=self.gpg.getenv(), hide=False, pty=True)

    def trust_keys(self):
        key_list = self.gpg.get_keys()
        logger.debug(len(key_list))
        logger.debug(key_list)
        trusted_count = 0
        for key in key_list:
            if key.trust == 'ultimate':
                logger.debug('Key already trusted {key.uid}')
            else:
                trusted_count += 1
                logger.info(f'Key UID: {key.uid}')
                client = YesNo(f'Would you like to trust [{key.fingerprint}] ', default='n')
                if client.launch():
                    gpg_cmd = '{} --quiet --expert --batch --display-charset utf-8 --command-fd 0 --no-tty --edit-key {}'.format(self.gpg.getbin(), key.fingerprint)
                    invoke.run(gpg_cmd, env=self.gpg.getenv(), hide=True, in_stream=StringIO(__gpg_trust_key__))
        if trusted_count == 0:
            logger.info('No untrusted keys to trust')

    def decrypt(self, input, output):
        logger.debug('Decrypting with GPG')
        gpg_cmd = '{} --quiet --armor --decrypt -o {} {}'.format(self.gpg.getbin(), output, input)
        invoke.run(gpg_cmd, env=self.gpg.getenv(), hide=False, pty=True)
