#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright: (c) 2025, Gonzalo Alvarez

import pytest
from unittest.mock import patch, MagicMock, call
from dataclasses import dataclass, fields

from secureenclave.consoleui import ConsoleUI


@dataclass
class SampleData:
    field_one: str = ""
    field_two_numeric: int = 0
    another_field: str = ""


@pytest.fixture
def console_ui_instance():
    """Provides a ConsoleUI instance for tests."""
    return ConsoleUI()


@pytest.fixture
def sample_data_object():
    """Provides a fresh instance of SampleData for each test."""
    return SampleData()


def test_console_ui_context_manager(console_ui_instance):
    """Test that ConsoleUI can be used as a context manager."""
    with console_ui_instance as ui:
        assert ui is console_ui_instance


@patch('secureenclave.consoleui.VerticalPrompt')
@patch('secureenclave.consoleui.Input')
def test_populate_object(mock_input_class, mock_vertical_prompt_class, console_ui_instance, sample_data_object):
    """Test the populate_object method of ConsoleUI."""
    mock_input_instance1 = MagicMock()
    mock_input_instance2 = MagicMock()
    mock_input_instance3 = MagicMock()
    mock_input_class.side_effect = [
        mock_input_instance1,
        mock_input_instance2,
        mock_input_instance3
    ]

    mock_prompt_instance = MagicMock()
    mock_vertical_prompt_class.return_value = mock_prompt_instance

    simulated_user_inputs = [
        ("Field One: ", "Test Value 1"),
        ("Field Two Numeric: ", "123"),
        ("Another Field: ", "Another Test Value")
    ]
    mock_prompt_instance.launch.return_value = simulated_user_inputs

    updated_object = console_ui_instance.populate_object(sample_data_object)

    expected_input_calls = [
        call("Field One: "),
        call("Field Two Numeric: "),
        call("Another Field: ")
    ]
    mock_input_class.assert_has_calls(expected_input_calls, any_order=False)
    assert mock_input_class.call_count == len(fields(SampleData))

    expected_input_instances_list = [mock_input_instance1, mock_input_instance2, mock_input_instance3]
    mock_vertical_prompt_class.assert_called_once_with(expected_input_instances_list, spacing=0)

    mock_prompt_instance.launch.assert_called_once()

    assert updated_object is sample_data_object, "populate_object should return the same object instance."
    assert sample_data_object.field_one == "Test Value 1"

    assert sample_data_object.field_two_numeric == "123"
    assert isinstance(sample_data_object.field_two_numeric, str), \
        "field_two_numeric should be a string as returned by mocked bullet.Input"

    assert sample_data_object.another_field == "Another Test Value"

    assert isinstance(sample_data_object.field_one, str)
    assert isinstance(sample_data_object.another_field, str)
