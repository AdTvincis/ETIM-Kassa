/* SDCC syntax probe for the emitted firmware reconstruction. */
#define ZEXT12(x) ((unsigned char)((x) & 0x0F))
#define CARRY1(a, b) ((unsigned char)(((unsigned short)((a) & 0xFF) + ((b) & 0xFF)) > 0xFF))

typedef unsigned char byte;
typedef unsigned char undefined1;
typedef unsigned short undefined2;
typedef unsigned int undefined4;

#ifdef __SDCC
#include <8051.h>
#else
volatile unsigned char P1;
volatile unsigned char TCON;
#endif

byte DAT_INTMEM_3e;
byte DAT_EXTMEM_0c7a;
byte DAT_SFR_92;
unsigned int UNK_CODE_0053;
byte BANK1_R3;

static void __baddata(void) {
  /* ROM bytes here are not valid code */
  for (;;) {
  }
}

byte *sub_810F(byte *param_1, unsigned char param_2);

void sub_810F(byte *param_1, unsigned char param_2) {
  byte bVar1;
  byte *pbVar2;
  char cVar3;
  unsigned char uVar4;
  volatile unsigned char *puVar5;
  /* address 0x810F */
  pbVar2 = (byte *)(unsigned int)param_1;
  bVar1 = (byte)(param_2 & 0x0F);
  cVar3 = (char)bVar1;
  uVar4 = (unsigned char)ZEXT12(param_2);
  uVar4 = (unsigned char)(uVar4 + 1);
  puVar5 = (volatile unsigned char *)0x8000;
  *puVar5 = uVar4;
  P1 = 0x55;
  DAT_INTMEM_3e = 1;
  DAT_EXTMEM_0c7a = DAT_INTMEM_3e;
  DAT_SFR_92 = 2;
  if (cVar3 == 0) {
    __baddata();
  }
  return;
}

unsigned short sub_1EB6_external(unsigned short param_1) {
  /* address 0x1EB6 is not covered by any dump */
  return param_1 + 1;
}
