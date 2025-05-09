#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright: (c) 2018, Gonzalo Alvarez. Extended by AI.

import pytest
from unittest.mock import patch, MagicMock, call
from dataclasses import dataclass, fields

from secureenclave.consoleui import ConsoleUI


# A simple dataclass for testing
@dataclass
class SampleData:
    field_one: str = ""
    field_two_numeric: int = 0  # ConsoleUI will set this as a string from bullet's output
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
    # __enter__ returns self, __exit__ does nothing.
    # This test ensures no exceptions are raised during context management.


@patch('secureenclave.consoleui.VerticalPrompt')
@patch('secureenclave.consoleui.Input')
def test_populate_object(mock_input_class, mock_vertical_prompt_class, console_ui_instance, sample_data_object):
    """Test the populate_object method of ConsoleUI."""
    # --- Setup Mocks ---
    # Mock Input instances that will be created
    mock_input_instance1 = MagicMock()
    mock_input_instance2 = MagicMock()
    mock_input_instance3 = MagicMock()
    mock_input_class.side_effect = [
        mock_input_instance1,
        mock_input_instance2,
        mock_input_instance3
    ]

    # Mock VerticalPrompt instance and its launch method
    mock_prompt_instance = MagicMock()
    mock_vertical_prompt_class.return_value = mock_prompt_instance

    # Define the simulated user inputs.
    # VerticalPrompt.launch() returns a list of (prompt_text, value) tuples.
    # The prompt_text part of the tuple is not used by ConsoleUI's logic after launch,
    # but the value part is.
    simulated_user_inputs = [
        ("Field One: ", "Test Value 1"),
        ("Field Two Numeric: ", "123"),  # bullet.Input typically returns strings
        ("Another Field: ", "Another Test Value")
    ]
    mock_prompt_instance.launch.return_value = simulated_user_inputs

    # --- Call the method under test ---
    updated_object = console_ui_instance.populate_object(sample_data_object)

    # --- Assertions ---
    # 1. Check that Input was called correctly for each field of SampleData
    # The prompts are generated from field names: attr.name.replace("_", " ").title()
    expected_input_calls = [
        call("Field One: "),
        call("Field Two Numeric: "),
        call("Another Field: ")
    ]
    mock_input_class.assert_has_calls(expected_input_calls, any_order=False)
    assert mock_input_class.call_count == len(fields(SampleData))

    # 2. Check that VerticalPrompt was initialized with the list of mocked Input instances
    expected_input_instances_list = [mock_input_instance1, mock_input_instance2, mock_input_instance3]
    mock_vertical_prompt_class.assert_called_once_with(expected_input_instances_list, spacing=0)

    # 3. Check that launch was called on the VerticalPrompt instance
    mock_prompt_instance.launch.assert_called_once()

    # 4. Check that the object's attributes were updated with the simulated input values
    assert updated_object is sample_data_object, "populate_object should return the same object instance."
    assert sample_data_object.field_one == "Test Value 1"

    # Note: ConsoleUI currently sets attributes with string values as returned by bullet.
    # It does not perform type conversion based on dataclass field type hints.
    assert sample_data_object.field_two_numeric == "123"
    assert isinstance(sample_data_object.field_two_numeric, str), \
        "field_two_numeric should be a string as returned by mocked bullet.Input"

    assert sample_data_object.another_field == "Another Test Value"

    # 5. Verify the types of other fields (should be strings as per simulated input)
    assert isinstance(sample_data_object.field_one, str)
    assert isinstance(sample_data_object.another_field, str)
