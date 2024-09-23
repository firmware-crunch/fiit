################################################################################
#
# Copyright 2022-2025 Vincent Dary
#
# This file is part of fiit.
#
# fiit is free software: you can redistribute it and/or modify it under the
# terms of the GNU Affero General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option) any
# later version.
#
# fiit is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE. See the GNU Affero General Public License for more
# details.
#
# You should have received a copy of the GNU Affero General Public License along
# with fiit. If not, see <https://www.gnu.org/licenses/>.
#
################################################################################

import logging

import pytest

from .fixtures.fixture_utils import temp_named_txt_file

from fiit.core.logger import FiitLogger


def test_fiit_logger_active_level(caplog):
    caplog.set_level(logging.INFO)
    FiitLogger.configure_loggers({'fiit.tests': 'INFO'})
    logging.getLogger('fiit.tests').info('test log msg')
    assert caplog.record_tuples[-1] == ('fiit.tests', logging.INFO,
                                        'test log msg')


def test_fiit_logger_deactivate_level(caplog):
    caplog.set_level(logging.INFO)
    FiitLogger.configure_loggers({'fiit.tests': 'ERROR'})
    logging.getLogger('fiit.tests').info('test log msg')
    for log in caplog.record_tuples:
        assert log[0] != 'fiit.tests'
