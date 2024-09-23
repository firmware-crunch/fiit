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
AS = aarch64-linux-gnu-as
CC = aarch64-linux-gnu-gcc
LD = aarch64-linux-gnu-ld
OBJCOPY = aarch64-linux-gnu-objcopy
OBJDUMP = aarch64-linux-gnu-objdump


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
	$(MAKE) aarch64


aarch64: CC_ENDIAN_FLAG = -mlittle-endian
aarch64: LD_ENDIAN_FLAG = -EL
aarch64: blob_build


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
