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

RULE_SET_REGISTRY = (
    ('string', {'type': 'string'}),
    ('integer', {'type': 'integer'}),

    ('DEF_INT64', {
        'type': ['string', 'integer'], 'check_with': 'hex_int64',
        'coerce': 'hex_int64'}),
    ('DEF_INT64_OPTIONAL', {
        'type': ['string', 'integer'], 'check_with': 'hex_int64',
        'coerce': 'hex_int64', 'required': False}),
    ('DEF_SIZE', {'type': ['string', 'integer'], 'coerce': 'hex_int'}),
    ('DEF_SIZE_OPTIONAL', {
        'type': ['string', 'integer'], 'coerce': 'hex_int', 'required': False}),
    ('DEF_MEM_PERM', {'type': 'string', 'check_with': 'mem_perm'}),

    ('DEF_MEMORY_REGIONS', {
        'type': 'list',
        'require_all': True,
        'schema': {
            'type': 'dict',
            'schema': {
                'name': {'type': 'string'},
                'base_address': 'DEF_INT64',
                'size': 'DEF_SIZE',
                'perm': 'DEF_MEM_PERM'
            }
        }
    }),

    ('DEF_LOAD_FILES', {
        'type': 'list',
        'schema': {
            'type': 'dict',
            'schema': {
                'filename': {'type': 'string', 'required': True},
                'file_offset': 'DEF_SIZE',
                'loading_size': 'DEF_SIZE_OPTIONAL',
                'loading_address': 'DEF_INT64'
            }
        }
    }),

    ('DEF_MEMORY_RANGES', {
        'type': 'list',
        'coerce': 'memory_ranges',
        'schema': {
            'type': 'dict',
            'schema': {
                'begin': 'DEF_INT64',
                'end': 'DEF_INT64',
                'name': {'type': 'string', 'required': False}
            }
        }
    }),

)
