################################################################################
#
# Copyright 2022-2025 Vincent Dary
#
# This file is part of fiit.
#
# fiit is free software: you can redistribute it and/or modify it under the
# terms of the GNU General Public License as published by the Free Software
# Foundation, either version 3 of the License, or (at your option) any later
# version.
#
# fiit is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
# fiit. If not, see <https://www.gnu.org/licenses/>.
#
################################################################################

from typing import Union
import sys
import argparse
from importlib import metadata

from fiit.core.logger import FiitLogger
from fiit.core.plugin import PluginManager
from fiit.plugins import backend
from .fiit_console import fiit_console_from_backend


SUB_PARSER_RUN = 'run'
SUB_PARSER_CONSOLE = 'console'


def fiit_session(config: str, extra_plugin_path: Union[str, None] = None) -> None:
    FiitLogger()
    plugin_loader = PluginManager()
    plugin_loader.load_plugin_by_config_file(
        config, ([extra_plugin_path] if extra_plugin_path else []))

    if plugin_loader.plugins_context.program_entry:
        plugin_loader.plugins_context.program_entry()

    sys.exit(0)


def main() -> None:
    meta = metadata.metadata('fiit-python')

    parser = argparse.ArgumentParser(
        prog=f'fiit',
        description=f'Version {meta["Version"]} - {meta["Summary"]}',
        epilog='Emulation Framework for Firmware Analysis'
    )

    subparsers = parser.add_subparsers(required=True, dest='fii_subparser')

    ###################################
    # subparser run
    ###################################
    parser_run = subparsers.add_parser(
        SUB_PARSER_RUN, help='Run a fiit session.')
    parser_run.add_argument(
        '--config', required=True, help='YAML/JSON configuration file.')
    parser_run.add_argument(
        '--extra-plugin-path', required=False, help='Extra plugin directory',
        default=None)

    ###################################
    # subparser jupiter-console
    ###################################
    parser_console = subparsers.add_parser(
        SUB_PARSER_CONSOLE,
        help=(
            'Run and connect a Jupyter Console to a remote Jupyter kernel '
            'hosted in a fiit session launched by the "plugin_shell"'
            'configured with the "remote_ipykernel" option set to true (the '
            'remote fiit session must be run with the "plugin_backend" to '
            'retrieve the Jupyter kernel connection information).'))
    parser_console.add_argument(
        '--backend-ip', required=True, help='fiit backend IP address.')
    parser_console.add_argument(
        '--backend-port', required=False, help='fiit backend port number.',
        default=backend.BACKEND_REQUEST_DEFAULT_PORT)

    ###################################
    # parsing
    ###################################
    script_args = parser.parse_args()

    if script_args.fii_subparser == SUB_PARSER_RUN:
        fiit_session(script_args.config, script_args.extra_plugin_path)
    elif script_args.fii_subparser == SUB_PARSER_CONSOLE:
        fiit_console_from_backend(script_args.backend_ip, script_args.backend_port)


if __name__ == '__main__':
    main()
