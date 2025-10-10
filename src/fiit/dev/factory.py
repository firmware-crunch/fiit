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

__all__ = [
    'FiitCpuFactory'
]

import inspect
from typing import Optional, Any, Dict, Type, Union, List, Tuple

from fiit.machine import DeviceCpu, CpuFactory

from ..emunicorn import CpuFactoryUnicorn

from .arm32 import ArchArm32, DEVICES_CPU_ARM32

# ==============================================================================


class FiitCpuFactory:
    """
    The glue layer between cpu backend and top layer architecture implementation
    """

    _CPU_BACKEND_FACTORIES: Tuple[Type[CpuFactory]] = (
        CpuFactoryUnicorn,
    )

    _CPU_DEVICES: Tuple[Type[DeviceCpu]] = (
        ArchArm32,
    )

    @classmethod
    def _get_cpu_factory(cls, cpu_backend: Union[str, Any]) -> Type[CpuFactory]:

        for factory in cls._CPU_BACKEND_FACTORIES:

            if isinstance(cpu_backend, str):
                if factory.get_backend_name() == cpu_backend:
                    return factory
            else:
                if factory.get_backend_type() == type(cpu_backend):
                    return factory

        raise ValueError(f'CPU factory {cpu_backend} not found')

    @classmethod
    def _get_cpu_device_class(cls, arch_id: str) -> Type[DeviceCpu]:
        for cpu in cls._CPU_DEVICES:
            if cpu.ARCH_ID == arch_id:
                return cpu

        raise ValueError(f'CPU id "{arch_id}" not found')

    @staticmethod
    def _extract_init_args(
        klass: Type[Any],
        kwargs: Dict[str, Any],
        signature_arg_skip: Optional[List[Tuple[str, int]]] = None
    ) -> Dict[str, Any]:
        init_kwargs = {}
        klass_signature = inspect.signature(klass).parameters

        for idx, items in enumerate(klass_signature.items()):
            param_name, param_meta = items
            to_skip = False

            if signature_arg_skip is not None:
                for skip in signature_arg_skip:
                    if idx == skip[1] and param_name == skip[0]:
                        to_skip = True

            if to_skip:
                continue

            kwarg_value = kwargs.get(param_name, None)

            if kwarg_value is not None:
                init_kwargs[param_name] = kwarg_value

            elif kwarg_value is None and param_meta.default == inspect._empty:
                raise ValueError(
                    f'Parameter "{param_name}" not provided for class '
                    f'"{str(klass)}"'
                )

        return init_kwargs

    @staticmethod
    def _select_arm32_variant(
        cpu_backend: str, kwargs: Dict[str, Any]
    ) -> Type[DeviceCpu]:
        arm_spec = kwargs.get('arm_spec', None)

        if cpu_backend == 'unicorn' and arm_spec is None:
            # add spec for specific Unicorn cpu model
            unicorn_model = kwargs.get('model')

            if unicorn_model == '926':
                arm_spec = 'DDI0100'

        if arm_spec is not None:
            for cpu_dev in DEVICES_CPU_ARM32:
                cpu_dev_arm_spec = getattr(cpu_dev, 'ARM_SPEC', None)

                if cpu_dev_arm_spec == arm_spec:
                    return cpu_dev

        return ArchArm32

    @classmethod
    def get(
        cls,
        cpu_backend: Union[str, Any],
        arch_id: str,
        dev_name: Optional[str] = None,
        **kwargs: int
    ) -> DeviceCpu:
        """ """
        cpu_factory = cls._get_cpu_factory(cpu_backend)

        if isinstance(cpu_backend, str):
            cpu_class = cpu_factory.class_from_arch_id(arch_id)
        else:
            cpu_class = cpu_factory.class_from_backend_instance(
                cpu_backend, arch_id
            )

        cpu_class_kwargs = cls._extract_init_args(cpu_class, kwargs)

        if arch_id == 'arm32':
            cpu_dev_class = cls._select_arm32_variant(cpu_backend, kwargs)
        else:
            cpu_dev_class = cls._get_cpu_device_class(arch_id)

        cpu_dev_class_kwargs = cls._extract_init_args(
            cpu_dev_class, kwargs, [('cpu', 0)]
        )

        if isinstance(cpu_backend, str):
            cpu = cpu_class(**cpu_class_kwargs)
        else:
            cpu = cpu_class.from_backend(cpu_backend, **cpu_class_kwargs)

        cpu_device = cpu_dev_class(cpu, dev_name=dev_name, **cpu_dev_class_kwargs)
        return cpu_device
