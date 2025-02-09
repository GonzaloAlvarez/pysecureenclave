#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright: (c) 2018, Gonzalo Alvarez

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from dataclasses import fields
from bullet import Input, VerticalPrompt

class ConsoleUI(object):
    def __enter__(self):
        return self

    def __exit__(self):
        pass

    def populate_object(self, object):
        inputs=[]
        for attr in fields(type(object)):
            inputs.append(Input('{}: '.format(attr.name.replace("_"," ").title())))

        values = VerticalPrompt(inputs, spacing=0).launch()

        for i, attr in enumerate(fields(type(object))):
            setattr(object, attr.name, values[i][1])

        return object

