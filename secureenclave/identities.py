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
                    salutation TEXT,
                    active BOOLEAN DEFAULT 0
                )
            ''')
            cursor.execute('''
                CREATE UNIQUE INDEX IF NOT EXISTS one_active_row ON identities(active) WHERE active=1
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
                INSERT INTO identities (id, first_name, last_name, email, salutation, active)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (identity_id, identity_info.first_name, identity_info.last_name, identity_info.email, identity_info.salutation, identity_info.active))
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
            cursor.execute("SELECT id, first_name, last_name, email, salutation, active FROM identities")
            rows = cursor.fetchall()
            identities = [dict(row) for row in rows]
            return identities
        except sqlite3.Error as e:
            logger.error(f"Failed to list identities: {e}")
            return []
        finally:
            if conn:
                conn.close()
                
                
    def get_identity(self, identity_id):
        """Retrieves an identity from the database by its ID."""
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT id, first_name, last_name, email, salutation, active FROM identities WHERE id = ?", (identity_id,))
            row = cursor.fetchone()
            return dict(row) if row else None
        except sqlite3.Error as e:
            logger.error(f"Failed to get identity: {e}")
            return None
        finally:
            if conn:
                conn.close()
                

    def set_active(self, identity_id):
        """Sets the active status of an identity in the database."""
        conn = None
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # First, deactivate any currently active identity that is not the target identity
            # This handles the case where another identity is active or if the target is already active (no change needed for it then).
            cursor.execute("UPDATE identities SET active = 0 WHERE active = 1 AND id != ?", (identity_id,))
            
            # Then, activate the target identity
            # This will also correctly set it to active if it was previously inactive.
            # If the unique constraint on 'active=1' was violated by a previous state,
            # this ensures we try to set the target one to active.
            # The unique index `one_active_row` will prevent multiple active rows.
            # If the target identity was already active, the first query would not touch it,
            # and this second query would effectively do nothing if it's already active=1.
            # However, to be explicit and ensure it becomes active if it wasn't:
            cursor.execute("UPDATE identities SET active = 1 WHERE id = ?", (identity_id,))
            
            if cursor.rowcount > 0:
                logger.success(f"Identity with ID: {identity_id} set to active.")
            else:
                # This could mean the ID doesn't exist, or it was already active and no other was active.
                # To provide more specific feedback, a SELECT could be done, but for now, this is simpler.
                logger.info(f"Attempted to set identity {identity_id} to active. Check if ID exists or was already active.")

            conn.commit()
        except sqlite3.Error as e:
            if conn:
                conn.rollback()
            logger.error(f"Failed to set active status for identity {identity_id}: {e}")
        finally:
            if conn:
                conn.close()

    def delete_identity(self, identity_id):
        """Deletes an identity from the database by its ID."""
        try:
            identity = self.get_identity(identity_id)
            if not identity:
                return None
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("DELETE FROM identities WHERE id = ?", (identity_id,))
            conn.commit()
            if cursor.rowcount > 0:
                logger.success(f"Identity with ID: {identity_id} deleted successfully.")
            else:
                logger.warning(f"No identity found with ID: {identity_id}.")
            identities = self.list_identities()
            if identities:
                active_identity = identities[0] 
                self.set_active(active_identity.id)
            else:
                logger.warning("No identities left to set as active.")
        except sqlite3.Error as e:
            logger.error(f"Failed to delete identity {identity_id}: {e}")
        finally:
            if conn:
                conn.close()
