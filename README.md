# Repository Coverage

[Full report](https://htmlpreview.github.io/?https://github.com/firmware-crunch/fiit/blob/fiit-py-cov/htmlcov/index.html)

| Name                                     |    Stmts |     Miss |   Cover |   Missing |
|----------------------------------------- | -------: | -------: | ------: | --------: |
| src/fiit/\_\_init\_\_.py                 |        3 |        0 |    100% |           |
| src/fiit/com/\_\_init\_\_.py             |        2 |        0 |    100% |           |
| src/fiit/com/backend.py                  |      118 |       81 |     31% |51-57, 60, 63, 68-71, 88-136, 139-146, 149, 152, 155-157, 163-164, 171-173, 176-178, 186-207, 210-222, 225 |
| src/fiit/com/data.py                     |       33 |       11 |     67% |46-51, 56-57, 62, 65-66, 74 |
| src/fiit/com/messages.py                 |       18 |        0 |    100% |           |
| src/fiit/config/\_\_init\_\_.py          |        3 |        0 |    100% |           |
| src/fiit/config/loader.py                |       78 |        0 |    100% |           |
| src/fiit/config/schema.py                |        1 |        0 |    100% |           |
| src/fiit/ctypesarch/\_\_init\_\_.py      |        3 |        0 |    100% |           |
| src/fiit/ctypesarch/arch/\_\_init\_\_.py |        0 |        0 |    100% |           |
| src/fiit/ctypesarch/arch/arm32.py        |       24 |        0 |    100% |           |
| src/fiit/ctypesarch/cdata.py             |       58 |        6 |     90% |46, 81, 84, 126-128 |
| src/fiit/ctypesarch/config.py            |       75 |        0 |    100% |           |
| src/fiit/ctypesarch/defines.py           |      314 |        2 |     99% |  224, 229 |
| src/fiit/ctypesarch/translator.py        |      238 |       17 |     93% |203, 210-216, 230, 297-299, 329-331, 334, 344, 354, 366, 382 |
| src/fiit/dbg/\_\_init\_\_.py             |        3 |        0 |    100% |           |
| src/fiit/dbg/dbg.py                      |       76 |        0 |    100% |           |
| src/fiit/dbg/defines.py                  |      354 |        0 |    100% |           |
| src/fiit/dbg/disasm.py                   |       18 |        0 |    100% |           |
| src/fiit/dbg/factory.py                  |       14 |        0 |    100% |           |
| src/fiit/dev/\_\_init\_\_.py             |        4 |        0 |    100% |           |
| src/fiit/dev/arm32/\_\_init\_\_.py       |        5 |        0 |    100% |           |
| src/fiit/dev/arm32/coproc.py             |        7 |        0 |    100% |           |
| src/fiit/dev/arm32/cpu.py                |       30 |        2 |     93% |    85, 89 |
| src/fiit/dev/arm32/ddi0100.py            |      105 |        0 |    100% |           |
| src/fiit/dev/factory.py                  |       72 |        1 |     99% |       152 |
| src/fiit/dev/pl190.py                    |      276 |       37 |     87% |186, 206-207, 351, 417-419, 423-427, 454, 457, 460, 463, 466, 473-503 |
| src/fiit/emunicorn/\_\_init\_\_.py       |        8 |        0 |    100% |           |
| src/fiit/emunicorn/arm32/\_\_init\_\_.py |        3 |        0 |    100% |           |
| src/fiit/emunicorn/arm32/const.py        |        3 |        0 |    100% |           |
| src/fiit/emunicorn/arm32/coproc.py       |       14 |        0 |    100% |           |
| src/fiit/emunicorn/arm32/cpu.py          |       79 |        0 |    100% |           |
| src/fiit/emunicorn/cpu.py                |      175 |       17 |     90% |168, 257, 276, 285, 294, 306, 315, 324, 345-346, 371-374, 379, 384, 389-390 |
| src/fiit/emunicorn/dbg.py                |      157 |        0 |    100% |           |
| src/fiit/emunicorn/factory.py            |       38 |        0 |    100% |           |
| src/fiit/emunicorn/fix.py                |       10 |        0 |    100% |           |
| src/fiit/emunicorn/memory.py             |       49 |        0 |    100% |           |
| src/fiit/emunicorn/registers.py          |       13 |        0 |    100% |           |
| src/fiit/fiit.py                         |       34 |       21 |     38% |38-46, 50-96, 100 |
| src/fiit/ftrace/\_\_init\_\_.py          |        3 |        0 |    100% |           |
| src/fiit/ftrace/ext/\_\_init\_\_.py      |        0 |        0 |    100% |           |
| src/fiit/ftrace/ext/freertos.py          |       61 |       38 |     38% |38, 42-58, 75-77, 80-86, 89-94, 102-104, 107-111, 114-117 |
| src/fiit/ftrace/filter.py                |       46 |       26 |     43% |35, 38, 69-105, 109 |
| src/fiit/ftrace/ftrace.py                |       54 |       36 |     33% |75-158, 167, 172, 177, 182, 185-186, 191-192 |
| src/fiit/ftrace/logfmt.py                |       88 |       66 |     25% |42, 45, 72-95, 101-104, 117-167, 170-187, 192-207 |
| src/fiit/hooking/\_\_init\_\_.py         |        2 |        0 |    100% |           |
| src/fiit/hooking/cc/\_\_init\_\_.py      |       15 |        8 |     47% |46-49, 53-57 |
| src/fiit/hooking/cc/aapcs32.py           |      305 |        0 |    100% |           |
| src/fiit/hooking/cc/cc.py                |       52 |       11 |     79% |51, 66, 77, 81, 85, 89, 93, 99, 103, 107, 113 |
| src/fiit/hooking/defines.py              |       56 |       20 |     64% |52-56, 60-64, 68-72, 79-87 |
| src/fiit/hooking/engine.py               |      184 |      150 |     18% |72-113, 117, 120-122, 129-147, 154-157, 160-161, 164-165, 168-200, 203-204, 207-246, 251-264, 272-290, 294, 298, 302-305, 308-311, 314-323, 326-327, 330-332, 335-389 |
| src/fiit/iotrace/\_\_init\_\_.py         |        2 |        0 |    100% |           |
| src/fiit/iotrace/mmio/\_\_init\_\_.py    |        4 |        0 |    100% |           |
| src/fiit/iotrace/mmio/dbg.py             |       55 |       39 |     29% |51-64, 77-85, 88-93, 96-101, 108-117, 122-126, 131-136 |
| src/fiit/iotrace/mmio/filter.py          |      155 |        6 |     96% |172-174, 253-254, 294 |
| src/fiit/iotrace/mmio/interceptor.py     |      121 |       86 |     29% |83-101, 106-111, 121-131, 136-140, 147-150, 157-160, 179-214, 219-226, 233-234, 239-240, 243-248, 251-256, 259-261, 266-268 |
| src/fiit/iotrace/mmio/logger.py          |       69 |       46 |     33% |41-47, 50-53, 56, 63, 68, 78, 84-103, 107-120, 126-146, 151-154, 165, 170-180, 191 |
| src/fiit/iotrace/mmio/reg.py             |        2 |        0 |    100% |           |
| src/fiit/iotrace/mmio/svd.py             |       46 |        5 |     89% | 70, 83-87 |
| src/fiit/iotrace/mmio/tracer.py          |      136 |       90 |     34% |46-47, 50, 53, 56, 59-62, 65, 68, 71, 74-77, 80, 83-90, 93, 96-103, 126-127, 130-131, 136-141, 147-148, 153-158, 162, 165-186, 189, 192-200, 215-267 |
| src/fiit/iotrace/mmio/traceviz.py        |      114 |       99 |     13% |37, 40-65, 71-86, 92-190 |
| src/fiit/logger.py                       |       21 |        7 |     67% |29-36, 46-49 |
| src/fiit/machine/\_\_init\_\_.py         |        6 |        0 |    100% |           |
| src/fiit/machine/cpu.py                  |      210 |        0 |    100% |           |
| src/fiit/machine/defines.py              |      131 |        0 |    100% |           |
| src/fiit/machine/machine.py              |       28 |        0 |    100% |           |
| src/fiit/machine/memory.py               |      151 |        1 |     99% |       338 |
| src/fiit/machine/registers.py            |       57 |        0 |    100% |           |
| src/fiit/plugin.py                       |      159 |        4 |     97% |165, 216, 235, 317 |
| src/fiit/plugins/\_\_init\_\_.py         |       26 |        0 |    100% |           |
| src/fiit/plugins/cdata.py                |       29 |       17 |     41% |     73-95 |
| src/fiit/plugins/com.py                  |       15 |        6 |     60% |     55-63 |
| src/fiit/plugins/dbg.py                  |       21 |        8 |     62% |     60-69 |
| src/fiit/plugins/ftrace.py               |       44 |       18 |     59% |59, 136-168 |
| src/fiit/plugins/hooking.py              |       27 |       15 |     44% |    76-104 |
| src/fiit/plugins/logger.py               |        9 |        0 |    100% |           |
| src/fiit/plugins/machine.py              |      120 |        6 |     95% |157, 177, 218, 268, 296, 301 |
| src/fiit/plugins/mmiotrace.py            |      144 |      105 |     27% |67-90, 93, 98-116, 119-157, 160-169, 173-199, 203-213, 332-347, 378-395 |
| src/fiit/plugins/shell.py                |       53 |       11 |     79% |94, 99-100, 105-106, 111-112, 117-122 |
| src/fiit/shell/\_\_init\_\_.py           |        3 |        0 |    100% |           |
| src/fiit/shell/front/\_\_init\_\_.py     |        6 |        0 |    100% |           |
| src/fiit/shell/front/cdata.py            |       57 |       34 |     40% |42, 45-48, 51-66, 74-83, 86-88, 98-109 |
| src/fiit/shell/front/dbg.py              |      191 |       10 |     95% |53, 108-116, 125, 135 |
| src/fiit/shell/front/machine.py          |       63 |        7 |     89% |94-95, 97-98, 105-106, 111 |
| src/fiit/shell/front/mmiodbg.py          |       31 |       15 |     52% |43-47, 50-52, 60-68 |
| src/fiit/shell/front/mmiotrace.py        |       81 |       44 |     46% |46-54, 57-59, 65-71, 80-88, 105-112, 119-146, 152-158 |
| src/fiit/shell/jupyter.py                |      184 |      142 |     23% |57-65, 69-88, 91-95, 98-103, 106-107, 111-131, 140-150, 154, 157-166, 169-192, 195-206, 209-218, 221-223, 226-241, 244-251, 254-257, 264-273, 283-299 |
| src/fiit/shell/shell.py                  |      140 |       16 |     89% |47-48, 51, 63-67, 115-116, 138-144, 162-163, 172 |
| src/fiit/utils.py                        |       51 |        6 |     88% |45-46, 84-87 |
| **TOTAL**                                | **6143** | **1393** | **77%** |           |


## Setup coverage badge

Below are examples of the badges you can use in your main branch `README` file.

### Direct image

[![Coverage badge](https://raw.githubusercontent.com/firmware-crunch/fiit/fiit-py-cov/badge.svg)](https://htmlpreview.github.io/?https://github.com/firmware-crunch/fiit/blob/fiit-py-cov/htmlcov/index.html)

This is the one to use if your repository is private or if you don't want to customize anything.

### [Shields.io](https://shields.io) Json Endpoint

[![Coverage badge](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/firmware-crunch/fiit/fiit-py-cov/endpoint.json)](https://htmlpreview.github.io/?https://github.com/firmware-crunch/fiit/blob/fiit-py-cov/htmlcov/index.html)

Using this one will allow you to [customize](https://shields.io/endpoint) the look of your badge.
It won't work with private repositories. It won't be refreshed more than once per five minutes.

### [Shields.io](https://shields.io) Dynamic Badge

[![Coverage badge](https://img.shields.io/badge/dynamic/json?color=brightgreen&label=coverage&query=%24.message&url=https%3A%2F%2Fraw.githubusercontent.com%2Ffirmware-crunch%2Ffiit%2Ffiit-py-cov%2Fendpoint.json)](https://htmlpreview.github.io/?https://github.com/firmware-crunch/fiit/blob/fiit-py-cov/htmlcov/index.html)

This one will always be the same color. It won't work for private repos. I'm not even sure why we included it.

## What is that?

This branch is part of the
[python-coverage-comment-action](https://github.com/marketplace/actions/python-coverage-comment)
GitHub Action. All the files in this branch are automatically generated and may be
overwritten at any moment.