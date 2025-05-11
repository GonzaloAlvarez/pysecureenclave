#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright: (c) 2025, Gonzalo Alvarez

"""Tests for `secureenclave` package."""

from click.testing import CliRunner

from secureenclave import cli


def test_command_line_interface():
    """Test the CLI."""
    runner = CliRunner()
    result = runner.invoke(cli.cli)
    assert result.exit_code == 0
    assert "Usage: cli [OPTIONS] COMMAND [ARGS]..." in result.output
    help_result = runner.invoke(cli.cli, ['--help'])
    assert help_result.exit_code == 0
    assert "Usage: cli [OPTIONS] COMMAND [ARGS]..." in help_result.output
