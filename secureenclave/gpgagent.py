#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright: (c) 2018, Gonzalo Alvarez

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import os, sys
import shutil
import psutil
import subprocess

__gpg_agent_conf__ = """pinentry-program {}
enable-ssh-support
default-cache-ttl 600
max-cache-ttl 7200
"""

class GpgAgent(object):
    def __init__(self, gpg):
        self.gpg = gpg
        self.gpg_agent_bin = shutil.which('gpg-agent')
        if not self.gpg_agent_bin:
            raise Exception('Failed to find gpg-agent program. Use your package manager or homebrew to install it and make sure it is in the path.')
        self.gpg_connect_agent_bin = shutil.which('gpg-connect-agent')
        if not self.gpg_connect_agent_bin:
            raise Exception('Failed to find gpg-connect-agent program. Use your package manager or homebrew to install it and make sure it is in the PATH.')
        self.pinentry_bin = shutil.which('pinentry-tty')
        if not self.pinentry_bin:
            raise Exception('Failed to find pinentry-tty program. Use your package manager or homebrew to install it and make sure it is in the PATH.')
        self.gpg_agent_conf_path = self.gpg.gethome().joinpath('gpg-agent.conf')
        if not self.gpg_agent_conf_path.exists():
            with self.gpg_agent_conf_path.open('w') as agentfile:
                agentfile.write(__gpg_agent_conf__.format(self.pinentry_bin))

    def start(self):
        gpgagent_cmd = [self.gpg_agent_bin, '--daemon', '--verbose', '--enable-ssh-support', '--log-file', self.gpg.gethome().joinpath('gpg-agent.log').as_posix()]
        subprocess.run(gpgagent_cmd, env=self.gpg.getenv(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        gpg_pid_cmd = [self.gpg_connect_agent_bin, '/subst', '/serverpid', '/echo ${get serverpid}', '/bye']
        gpg_pid_out = subprocess.run(gpg_pid_cmd, env=self.gpg.getenv(), capture_output=True)
        self.gpg_agent_pid = int(gpg_pid_out.stdout.decode("utf-8").strip())

    def stop(self):
        if psutil.pid_exists(self.gpg_agent_pid):
            agentprocess = psutil.Process(self.gpg_agent_pid)
            agentprocess.terminate()
            gone, alive = psutil.wait_procs([agentprocess], timeout=3)
            for proc in alive:
                proc.kill()

