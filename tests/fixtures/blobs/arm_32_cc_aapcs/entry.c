/*

 Copyright 2022-2025 Vincent Dary

 This file is part of fiit.

 fiit is free software: you can redistribute it and/or modify it under the
 terms of the GNU Affero General Public License as published by the Free
 Software Foundation, either version 3 of the License, or (at your option) any
 later version.

 fiit is distributed in the hope that it will be useful, but WITHOUT ANY
 WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 A PARTICULAR PURPOSE. See the GNU Affero General Public License for more
 details.

 You should have received a copy of the GNU Affero General Public License along
 with fiit. If not, see <https://www.gnu.org/licenses/>.

*/

//##############################################################################
//
//##############################################################################
unsigned int foo_01(unsigned int a, unsigned int b, unsigned int c,
                    unsigned int d)
{
  return 0x01020304;
}

//##############################################################################
//
//##############################################################################
unsigned long long foo_02(unsigned int a, unsigned long long b)
{
  return 0x0102030405060708;
}

//##############################################################################
// Mixed argument types on the registers and on the stack.
//##############################################################################
unsigned long long foo_03(unsigned long long a,
                          unsigned long long b,
                          unsigned char c,
                          unsigned long long d,
                          unsigned char e,
                          unsigned char f,
                          unsigned int g)
{
  return 0x0102030405060708;
}

//##############################################################################
// Argument split between register and the stack.
//##############################################################################
struct struct_04 { unsigned int a; unsigned int b; unsigned int c; };

unsigned int foo_04(unsigned int a, unsigned int b, struct struct_04 c)
{
  return 1;
}

//##############################################################################
// Aggregate argument with heterogeneous size members.
//##############################################################################
struct struct_05 { char a; short b; unsigned int c; char d; long long e; };

unsigned int foo_05(struct struct_05 aggregate)
{
  return 1;
}


//##############################################################################
// Aggregate argument lower than one word.
//##############################################################################
struct struct_06 { unsigned char a; };

struct struct_06 foo_06(struct struct_06 aggregate)
{
  return (struct struct_06){.a='A'};
}


//##############################################################################
//
//##############################################################################
float foo_07(int a, float x, int b, double y, float z)
{
  return 0.9375;
}


//##############################################################################
//
//##############################################################################
float foo_08(int a, float b, int c, double d, __fp16 e, float f)
{
  return 0.9375;
}


//##############################################################################
// Multiple float structure member distributed in nested aggregates.
//##############################################################################
struct struct_09_1 { double a; double b; };
struct struct_09_2 { double c; double d; };
struct struct_09_3 { struct struct_09_2 b; };
struct struct_09_4 { struct struct_09_1 a; struct struct_09_3 wrap; };

float foo_09(struct struct_09_4 a)
{
  return 0.9375;
}

//##############################################################################
// force aapcs32 c2 rule vfp registers with double.
//##############################################################################
double foo_10(double x1, double x2, double x3, double x4,
              double x5, double x6, double x7, double x8,
              double x9, double x10)
{
  return 0.25;
}

//#############################################################################
// force aapcs32 c2 rule vfp registers with fp16.
//#############################################################################
__fp16 foo_11(__fp16 x1, __fp16 x2, __fp16 x3, __fp16 x4, __fp16 x5, __fp16 x6,
              __fp16 x7, __fp16 x8, __fp16 x9, __fp16 x10, __fp16 x11,
              __fp16 x12, __fp16 x13, __fp16 x14, __fp16 x15, __fp16 x16,
              __fp16 x17, __fp16 x18)
{
  return 0.25;
}


//##############################################################################
// Return fundamental type smaller than a word.
//##############################################################################
unsigned short foo_12(void)
{
  return 0xabcd;
}

//#############################################################################
// Return fundamental type with double word size.
//#############################################################################
unsigned long long foo_13(void)
{
  return 0xffeeddccbbaa9988;;
}

//#############################################################################
// Return aggregate lower than a word.
//#############################################################################
struct struct_14 { unsigned char a; unsigned char b; unsigned char c; };

struct struct_14 foo_14(void)
{
  return (struct struct_14){.a='I', .b='J', .c='K'};
}


//##############################################################################
//
//##############################################################################
__fp16 foo_15(void)
{
  return 3.875;
}

//##############################################################################
//
//##############################################################################
float foo_16(void)
{
  return 0.75;
}

//##############################################################################
//
//##############################################################################
double foo_17(void)
{
  return 0.75;
}

//##############################################################################
// Return nested aggregate wrapping multiple float through register.
//##############################################################################
#ifdef WITH_FP_HARD

struct struct_18_a { float a; float b; };

struct struct_18_b { float c; float d; };

struct struct_18_wrap_l1 { struct struct_18_b b; };

struct struct_18_wrap_l2 { struct struct_18_a a; struct struct_18_wrap_l1 wrap; };

struct struct_18_wrap_l2 foo_18(void)
{
    return (struct struct_18_wrap_l2){
        .a = {.a=0.5, .b=0.75}, .wrap = {.b = {.c=0.875, .d=0.984375}}};
}

#endif

//##############################################################################
//
//##############################################################################
void foo_19(void)
{
}

//##############################################################################
// Argument with size lower than a word.
//##############################################################################
unsigned int foo_20(unsigned short a)
{
    return 1;
}

//##############################################################################
//
//##############################################################################
unsigned char * foo_21(unsigned char * a)
{
    return (unsigned char *) 0xBADEBABE;
}

//##############################################################################
//
//##############################################################################
unsigned char ** foo_22(unsigned char ** a)
{
    return (unsigned char **) 0xBABEBADE;
}

//##############################################################################
// Custom call site to test call method of calling convention.
//##############################################################################
extern unsigned int cc_call_test_wrapper(void);


//##############################################################################
// Entry Point
//##############################################################################
void __entry__(void)
{
  cc_call_test_wrapper();

  foo_01(0x01020304, 0x05060708, 0x090A0B0C, 0x0D0E0F10);

  foo_02(0x01020304, 0x05060708090A0B0C);

  foo_03(0x0807060504030201, 0x100F0E0D0C0B0A09,
         'A', 0x1817161514131211, 'K', 'J', 0x1c1b1a19);

  foo_04(1, 3, (struct struct_04){.a=0x0f101112, .b=0x13141516, .c=0x17181920});

  foo_05((struct struct_05)
        {.a='a', .b=0x0f10, .c=0x11121314, .d='b', .e=0x15161718191a1b1c});

  foo_06((struct struct_06){.a='a'});

  foo_07(4, 0.5, 8, 0.75, 0.875);

  foo_08(4, 0.5, 8, 0.75, 0.875, 0.984375);

  foo_09((struct struct_09_4){.a={.a=0.5, .b=0.75},
                              .wrap={.b={.c=0.875, .d=0.984375}}});

  foo_10(0.25, 0.375, 0.4375, 0.46875, 0.484375, 0.4921875, 0.49609375,
         0.498046875, 0.4990234375, 0.49951171875);

  foo_11(2, 3, 3.5, 3.75, 3.875, 8192, 12288, 14336, 15360, 15872, 16128, 512,
         768, 896, 960, 992, 1008, 1016);

  foo_12();
  foo_13();
  foo_14();
  foo_15();
  foo_16();
  foo_17();
  foo_19();
  foo_20(0x1234);
  foo_21((unsigned char *) 0xC0DEC0FE);
  foo_22((unsigned char **) 0xC0FEC0DE);

#ifdef WITH_FP_HARD
  foo_18();
#endif
}
