#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright: (c) 2018, Gonzalo Alvarez
# -------------------------------------------------
# Secure Store management capabilities
# -------------------------------------------------

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


class StoreManager(object):
    def __init__(self, base_path):
        self.store_path = base_path.joinpath('store')
        if not self.store_path.exists():
            self.store_path.mkdir(parents=True)

    def new_store(self):
        # Folder exists, so this function should:
        # 1. Check if the store is empty
        # 2. Initialize a git repository there
        # 3. Create folder and file structure
        # To accomplish this, first:
        # 1. We need an active user
        # 2. Identities should have a 'primary' tag or field that is boolean
        # 3. HSM/SC can be associated with identities
        # 4. Keys can be associated to identities
        # 5. Store should contain the identities
        # So, the datamodel is Store -(1.1)-> IdentityStore -(1.n)-> Identity -(1.n)-> Key
        # Identity -(1.1)-> HSM/SC -(1.1)-> Key
        # Key -(1.n)-> Secret
        # --
        # Questions:
        # 1. Can you have a store without an identity? You can, but you cannot have a key without an identity associated.
        # 2. What happens if I remove an identity? Should I remove the keys associated with the identity?
        #    I can have 'orphan' keys, and then I can a function to reposses them
        pass
