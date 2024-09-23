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

CURRENT_DIR_NAME = $(shell basename $(dir $(realpath $(lastword $(MAKEFILE_LIST)))))

################################################################################
# Toolchain
################################################################################
AS = arm-none-eabi-as
CC = arm-none-eabi-gcc
LD = arm-none-eabi-ld
OBJCOPY = arm-none-eabi-objcopy
OBJDUMP = arm-none-eabi-objdump

################################################################################
# Compile Options
################################################################################
ARCH_FLAGS=$(CPU_ARCH) $(CC_ENDIAN_FLAG) $(ARCH_FLOAT) $(ABI_FLOAT)

LD_DIRS = -L $(shell $(CC) -print-search-dirs \
		       |grep 'libraries: =' |cut -d '=' -f 2 |sed -e 's/:/ -L /g')

LDFLAGS = $(LD_ENDIAN_FLAG) $(LD_DIRS) -lgcc

CCFLAGS = -g -O0 -c -mthumb-interwork $(ARCH_FLAGS) $(CC_EXTRA_FLAGS)


################################################################################
# Targets
################################################################################
all:
	$(MAKE) armel_v6_soft_float_fp16_ieee


armel_v6_soft_float_fp16_ieee: CC_ENDIAN_FLAG = -mlittle-endian
armel_v6_soft_float_fp16_ieee: LD_ENDIAN_FLAG = -EL
armel_v6_soft_float_fp16_ieee: CPU_ARCH = -mcpu=arm926ej-s
armel_v6_soft_float_fp16_ieee: ARCH_FLOAT =
armel_v6_soft_float_fp16_ieee: ABI_FLOAT = -mfloat-abi=soft -mfp16-format=ieee
armel_v6_soft_float_fp16_ieee: CC_EXTRA_FLAGS = $()
armel_v6_soft_float_fp16_ieee: blob_build


blob_build: main.o main.elf out.bin meta_blob.py clean

main.o: main.s
	$(AS) $(ARCH_FLAGS) $^ -o $@

main.elf: main.o
	$(LD) -T linking.ld $^ -o $@ $(LDFLAGS)

out.bin: main.elf
	$(OBJCOPY) --strip-unneeded --strip-debug -O binary $^ $@

meta_blob.py: main.elf
	python3 ./../meta_bin_blob.py main.elf $(CURRENT_DIR_NAME)
	echo "" > __init__.py

clean:
	rm -f *.o *.elf *.bin
