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
        # Safely get the intended active state, defaulting to False if 'active' attribute is missing
        intended_active_state = getattr(identity_info, 'active', False)
        conn = None  # Initialize conn to None for the finally block

        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            # Always insert as inactive first (active=0).
            # This avoids unique constraint violation if another identity is already active.
            # The correct active state will be established by calling self.set_active if necessary.
            cursor.execute('''
                INSERT INTO identities (id, first_name, last_name, email, salutation, active)
                VALUES (?, ?, ?, ?, ?, 0)
            ''', (identity_id, identity_info.first_name, identity_info.last_name, identity_info.email, identity_info.salutation))
            conn.commit()
            logger.success(f"Identity saved with ID: {identity_id}")

            # Now, manage the active state
            if intended_active_state:
                # If the identity was intended to be active, make it so.
                # self.set_active will handle deactivating any other currently active identity.
                self.set_active(identity_id)
            else:
                # If the identity was intended to be inactive,
                # check if any other identity is currently active in the database.
                any_other_active = False
                conn_check = None
                try:
                    conn_check = sqlite3.connect(self.db_path)
                    cursor_check = conn_check.cursor()
                    # Check if there's any active identity. Note: the new identity (identity_id)
                    # is currently inactive in the DB at this point.
                    cursor_check.execute("SELECT 1 FROM identities WHERE active = 1 LIMIT 1")
                    if cursor_check.fetchone():
                        any_other_active = True
                except sqlite3.Error as e_check:
                    logger.error(f"Database error during active check for new identity {identity_id}: {e_check}")
                    # If check fails, we might not enforce an active identity. Consider implications.
                finally:
                    if conn_check:
                        conn_check.close()

                if not any_other_active:
                    # No other identity is active, so make this newly added one active
                    # to ensure there's always at least one active identity.
                    logger.info(f"No other active identity found. Setting newly added identity {identity_id} to active.")
                    self.set_active(identity_id)
            
        except sqlite3.Error as e:
            # Log with more context if possible
            identity_email = getattr(identity_info, 'email', 'unknown_email')
            logger.error(f"Failed to save identity ({identity_email}): {e}")
            # Do not proceed to set_active if the initial save failed.
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

            cursor.execute("UPDATE identities SET active = 0 WHERE active = 1 AND id != ?", (identity_id,))
            cursor.execute("UPDATE identities SET active = 1 WHERE id = ?", (identity_id,))

            if cursor.rowcount > 0:
                logger.success(f"Identity with ID: {identity_id} set to active.")
            else:
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
        identity_to_delete = self.get_identity(identity_id)
        if not identity_to_delete:
            logger.warning(f"No identity found with ID: {identity_id} to delete.")
            return None

        was_active = identity_to_delete['active']
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("DELETE FROM identities WHERE id = ?", (identity_id,))
            conn.commit()

            if cursor.rowcount > 0:
                logger.success(f"Identity with ID: {identity_id} deleted successfully.")
                remaining_identities = self.list_identities()
                if not remaining_identities:
                    logger.info("Last identity was deleted. No identities left to set as active.")
                else:
                    is_any_remaining_active = any(id_info['active'] for id_info in remaining_identities)
                    if was_active or not is_any_remaining_active:
                        new_active_identity_id = remaining_identities[0]['id']
                        logger.info(f"Ensuring an active identity. Attempting to set ID {new_active_identity_id} as active.")
                        self.set_active(new_active_identity_id)
            else:
                logger.warning(f"Deletion query affected 0 rows for identity ID: {identity_id}. It might have been deleted by another process.")

        except sqlite3.Error as e:
            if conn:
                conn.rollback()
            logger.error(f"Database error during identity deletion process for ID {identity_id}: {e}")
        finally:
            if conn:
                conn.close()
