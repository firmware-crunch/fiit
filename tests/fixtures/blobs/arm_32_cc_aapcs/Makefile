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

BUILD_DIR = ../builds


################################################################################
# Targets
################################################################################
all:
	rm -f $(BUILD_DIR)/firmware_arm*
	$(MAKE) cc_aapcs32_armel_v6_soft_float_fp16_ieee
	$(MAKE) clean
	$(MAKE) cc_aapcs32_armel_v6_hard_float_fp16_ieee
	$(MAKE) clean
	$(MAKE) cc_aapcs32_armeb_v6_soft_float_fp16_ieee
	$(MAKE) clean
	$(MAKE) cc_aapcs32_armeb_v6_hard_float_fp16_ieee
	$(MAKE) clean


cc_aapcs32_armel_v6_soft_float_fp16_ieee: CC_ENDIAN_FLAG = -mlittle-endian
cc_aapcs32_armel_v6_soft_float_fp16_ieee: LD_ENDIAN_FLAG = -EL
cc_aapcs32_armel_v6_soft_float_fp16_ieee: CPU_ARCH = -mcpu=arm1176jzf-s
cc_aapcs32_armel_v6_soft_float_fp16_ieee: ARCH_FLOAT =
cc_aapcs32_armel_v6_soft_float_fp16_ieee: ABI_FLOAT = -mfloat-abi=soft -mfp16-format=ieee
cc_aapcs32_armel_v6_soft_float_fp16_ieee: CC_EXTRA_FLAGS = $()
cc_aapcs32_armel_v6_soft_float_fp16_ieee: META_BLOB_NAME=cc_aapcs32_armel_v6_soft_float_fp16_ieee
cc_aapcs32_armel_v6_soft_float_fp16_ieee: blob_build

cc_aapcs32_armel_v6_hard_float_fp16_ieee: CC_ENDIAN_FLAG = -mlittle-endian
cc_aapcs32_armel_v6_hard_float_fp16_ieee: LD_ENDIAN_FLAG = -EL
cc_aapcs32_armel_v6_hard_float_fp16_ieee: CPU_ARCH = -mcpu=arm1176jzf-s
cc_aapcs32_armel_v6_hard_float_fp16_ieee: ARCH_FLOAT = -mfpu=vfp
cc_aapcs32_armel_v6_hard_float_fp16_ieee: ABI_FLOAT = -mfloat-abi=hard -mfp16-format=ieee
cc_aapcs32_armel_v6_hard_float_fp16_ieee: CC_EXTRA_FLAGS = -DWITH_FP_HARD='1'
cc_aapcs32_armel_v6_hard_float_fp16_ieee: META_BLOB_NAME=cc_aapcs32_armel_v6_hard_float_fp16_ieee
cc_aapcs32_armel_v6_hard_float_fp16_ieee: blob_build

cc_aapcs32_armeb_v6_soft_float_fp16_ieee: CC_ENDIAN_FLAG = -mbig-endian
cc_aapcs32_armeb_v6_soft_float_fp16_ieee: LD_ENDIAN_FLAG = -EB
cc_aapcs32_armeb_v6_soft_float_fp16_ieee: CPU_ARCH = -mcpu=arm1176jzf-s
cc_aapcs32_armeb_v6_soft_float_fp16_ieee: ARCH_FLOAT =
cc_aapcs32_armeb_v6_soft_float_fp16_ieee: ABI_FLOAT = -mfloat-abi=soft -mfp16-format=ieee
cc_aapcs32_armeb_v6_soft_float_fp16_ieee: CC_EXTRA_FLAGS =
cc_aapcs32_armeb_v6_soft_float_fp16_ieee: META_BLOB_NAME=cc_aapcs32_armeb_v6_soft_float_fp16_ieee
cc_aapcs32_armeb_v6_soft_float_fp16_ieee: blob_build

cc_aapcs32_armeb_v6_hard_float_fp16_ieee: CC_ENDIAN_FLAG = -mbig-endian
cc_aapcs32_armeb_v6_hard_float_fp16_ieee: LD_ENDIAN_FLAG = -EB
cc_aapcs32_armeb_v6_hard_float_fp16_ieee: CPU_ARCH = -mcpu=arm1176jzf-s
cc_aapcs32_armeb_v6_hard_float_fp16_ieee: ARCH_FLOAT = -mfpu=vfp
cc_aapcs32_armeb_v6_hard_float_fp16_ieee: ABI_FLOAT = -mfloat-abi=hard -mfp16-format=ieee
cc_aapcs32_armeb_v6_hard_float_fp16_ieee: CC_EXTRA_FLAGS = -DWITH_FP_HARD='1'
cc_aapcs32_armeb_v6_hard_float_fp16_ieee: META_BLOB_NAME=cc_aapcs32_armeb_v6_hard_float_fp16_ieee
cc_aapcs32_armeb_v6_hard_float_fp16_ieee: blob_build


blob_build: firmware.o entry.o out.elf out.bin meta_blob.py clean

firmware.o: firmware.s
	$(AS) $(ARCH_FLAGS) $^ -o $@

entry.o: entry.c
	$(CC) $(CCFLAGS) -s $^ -o $@

out.elf: firmware.o entry.o
	$(LD) -T firmware.ld $^ -o $@ $(LDFLAGS)

out.bin: out.elf
	$(OBJCOPY) --strip-unneeded --strip-debug -O binary $^ $@

meta_blob.py: out.elf
	python3 ./../meta_bin_blob.py out.elf $(META_BLOB_NAME)
	python3 ./../../cc/source_code_analyzer.py out.elf entry.c "$(CC_EXTRA_FLAGS)" __entry__ $(META_BLOB_NAME)
	echo "" > __init__.py

clean:
	rm -f *.o *.elf *.bin
