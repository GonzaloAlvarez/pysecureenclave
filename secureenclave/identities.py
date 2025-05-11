#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright: (c) 2025, Gonzalo Alvarez

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import sqlite3
import uuid
from loguru import logger


class IdentityManager:
    def __init__(self, home):
        self.db_path = home / 'identities.db'
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
