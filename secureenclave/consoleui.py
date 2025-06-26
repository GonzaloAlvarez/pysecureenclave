#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright: (c) 2025, Gonzalo Alvarez

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from dataclasses import fields
from bullet import Input, VerticalPrompt, Bullet
from loguru import logger


class ConsoleUI(object):
    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def populate_object(self, object):
        inputs = []
        for attr in fields(type(object)):
            if "bullet_ignore" in attr.metadata:
                continue
            if "bullet_options" in attr.metadata:
                options = attr.metadata['bullet_options']
                inputs.append(Bullet('{}: '.format(attr.name.replace("_", " ").title()), options))
            else:
                inputs.append(Input('{}: '.format(attr.name.replace("_", " ").title())))

        values = VerticalPrompt(inputs, spacing=0).launch()

        for i, attr in enumerate([field for field in fields(type(object)) if "bullet_ignore" not in field.metadata]):
            setattr(object, attr.name, values[i][1])

        return object

    def select_identity(self, identities, prompt_message="Select an identity: "):
        if not identities:
            logger.info("No identities available to select.")
            return None

        choices = [f"{identity['first_name']} {identity['last_name']} ({identity['email']})" for identity in identities]

        selected_display_name = Bullet(
            prompt=f"\n{prompt_message}",
            choices=choices,
            indent=0,
            align=2,
            margin=2,
            bullet=">",
            pad_right=5
        ).launch()

        if selected_display_name:
            for identity in identities:
                if f"{identity['first_name']} {identity['last_name']} ({identity['email']})" == selected_display_name:
                    return identity
        return None
