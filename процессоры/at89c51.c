typedef unsigned char   undefined;

typedef unsigned char    undefined1;


undefined SCON;
undefined TR1;
undefined TMOD;
undefined TH1;
undefined SBUF;
undefined TI;
undefined1 BANK0_R6;
undefined1 BANK0_R4;
undefined1 BANK0_R5;
undefined1 BANK0_R2;
undefined1 BANK0_R3;
undefined1 BANK0_R1;
undefined1 BANK0_R7;
undefined1 DAT_INTMEM_61;
undefined1 DAT_EXTMEM_8000;
undefined SUB_CODE_1000;
char UNK_CODE_fffe;
char UNK_CODE_ffff;
undefined IE;
undefined1 DAT_INTMEM_44;
undefined1 DAT_INTMEM_45;
undefined UNK_CODE_668f;
undefined1 DAT_INTMEM_3e;
undefined1 DAT_INTMEM_3f;
undefined UNK_CODE_6692;
undefined1 DAT_EXTMEM_668d;
undefined1 DAT_EXTMEM_668e;
char DAT_INTMEM_3e;
undefined1 DAT_EXTMEM_62fb;
undefined1 DAT_EXTMEM_62fc;
undefined UNK_CODE_65c1;
undefined P0.0;
undefined P0.1;
undefined P0.2;

void thunk_FUN_CODE_0f26(void)

{
  TMOD = 0x21;
  TH1 = 0xfa;
  SCON = 0x50;
  TR1 = 1;
  FUN_CODE_002c();
  return;
}



void FUN_CODE_002c(void)

{
  undefined1 *puVar1;
  char cVar2;
  
  puVar1 = (undefined1 *)0x0;
  do {
    SBUF = *puVar1;
    do {
      cVar2 = TI;
    } while (cVar2 == '\0');
    TI = 0;
    cVar2 = (char)puVar1;
    puVar1 = puVar1 + 1;
  } while ((cVar2 != '\0') || ((char)((ushort)puVar1 >> 8) != '\x10'));
  FUN_CODE_02f0();
  return;
}



void FUN_CODE_006e(code *UNRECOVERED_JUMPTABLE,char param_2,char param_3)

{
  undefined1 in_stack_000000ff;
  
  if (param_2 == '\0' && param_3 == '\0') {
    BANK0_R6 = in_stack_000000ff;
                    // WARNING: Could not recover jumptable at 0x0076. Too many branches
                    // WARNING: Treating indirect jump as call
    (*UNRECOVERED_JUMPTABLE)();
    return;
  }
  return;
}



char FUN_CODE_0078(byte param_1,char param_2,byte param_3,char param_4)

{
  return param_2 + (param_4 - ((CARRY1(param_1,param_3) << 7) >> 7));
}



char FUN_CODE_007f(byte param_1,char param_2,byte param_3,char param_4)

{
  return param_4 - (param_2 - (((param_3 < param_1) << 7) >> 7));
}



void FUN_CODE_0087(undefined1 *param_1)

{
  BANK0_R4 = *param_1;
  BANK0_R5 = param_1['\x01'];
  return;
}



void FUN_CODE_008e(char param_1)

{
  *(undefined1 *)(param_1 + -1) = BANK0_R3;
  *(undefined1 *)(param_1 + -2) = BANK0_R2;
  return;
}



char FUN_CODE_0095(char param_1,byte param_2,char param_3,byte param_4)

{
  char cVar1;
  
  BANK0_R3 = BANK0_R3 ^ 0x80;
  BANK0_R5 = BANK0_R5 ^ 0x80;
  cVar1 = param_4 - param_2;
  if (cVar1 == '\0') {
    cVar1 = param_3 - (param_1 - (((param_4 < param_2) << 7) >> 7));
  }
  return cVar1;
}



void FUN_CODE_00ac(void)

{
  FUN_CODE_027f();
  FUN_CODE_0095();
  return;
}



void FUN_CODE_00af(void)

{
  FUN_CODE_0095();
  return;
}



void FUN_CODE_00bc(void)

{
  FUN_CODE_027f();
  FUN_CODE_0095();
  return;
}



void FUN_CODE_00c7(void)

{
  FUN_CODE_028b();
  FUN_CODE_010c();
  FUN_CODE_0095();
  return;
}



void FUN_CODE_0101(void)

{
  FUN_CODE_027f();
  FUN_CODE_0095();
  return;
}



void FUN_CODE_0104(void)

{
  FUN_CODE_0095();
  return;
}



undefined1 FUN_CODE_010c(undefined1 param_1,undefined1 param_2,undefined1 param_3)

{
  BANK0_R2 = param_2;
  BANK0_R3 = param_3;
  return param_1;
}



byte FUN_CODE_0123(byte param_1,byte param_2)

{
  return param_1 & param_2;
}



void FUN_CODE_012a(void)

{
  return;
}



void FUN_CODE_013d(undefined1 param_1)

{
  FUN_CODE_012a(BANK0_R2,BANK0_R4,BANK0_R5);
  FUN_CODE_012a(param_1,BANK0_R6);
  return;
}



undefined1 FUN_CODE_01cf(undefined1 param_1)

{
  return param_1;
}



undefined1 FUN_CODE_01d7(undefined1 param_1)

{
  return param_1;
}



byte FUN_CODE_01df(byte param_1,byte param_2,byte param_3,char param_4)

{
  return ~(~param_2 + (param_4 - ((CARRY1(~param_1,param_3) << 7) >> 7)));
}



char FUN_CODE_01ea(byte param_1,char param_2,byte param_3,char param_4)

{
  return param_2 + (param_4 - ((CARRY1(param_1,param_3) << 7) >> 7));
}



undefined1 FUN_CODE_01f1(undefined1 param_1)

{
  return param_1;
}



undefined1 FUN_CODE_01f8(undefined1 param_1)

{
  return param_1;
}



char FUN_CODE_023b(undefined1 param_1,undefined1 param_2,char param_3)

{
  if (param_3 != '\0') {
    *(undefined1 *)CONCAT11(param_3,param_2) = param_1;
    return param_3;
  }
  *BANK0_R4 = BANK0_R2;
  return '\0';
}



// WARNING: Removing unreachable block (CODE,0x0252)

undefined1 FUN_CODE_024b(void)

{
  undefined1 *puVar1;
  
  puVar1 = BANK0_R2;
  BANK0_R2 = (undefined1 *)*BANK0_R2;
  BANK0_R3 = puVar1['\x01'];
  return 0;
}



void FUN_CODE_0268(undefined1 param_1,char param_2)

{
  if (param_2 != '\0') {
    FUN_CODE_0277(*(undefined1 *)CONCAT11(param_2,param_1));
    return;
  }
  BANK0_R2 = (undefined1 *)*BANK0_R2;
  return;
}



void FUN_CODE_0277(void)

{
  return;
}



void FUN_CODE_027f(void)

{
  return;
}



void FUN_CODE_0287(undefined1 *param_1)

{
  FUN_CODE_0277(*param_1);
  return;
}



void FUN_CODE_028b(undefined1 *param_1)

{
  FUN_CODE_027f(*param_1);
  return;
}



// WARNING: Control flow encountered bad instruction data

void FUN_CODE_02f0(void)

{
  char cVar1;
  char cVar2;
  char *pcVar3;
  
  IE = 0;
  DAT_EXTMEM_8000 = 0x9c;
  pcVar3 = &SUB_CODE_1000;
  cVar1 = '\0';
  cVar2 = BANK0_R4;
  do {
    cVar1 = *pcVar3 + cVar1;
    if (((byte)pcVar3 & 1) != 1) {
      cVar2 = *pcVar3 + cVar2;
    }
    pcVar3 = pcVar3 + 1;
  } while (((char)((ushort)pcVar3 >> 8) != -1) || ((char)pcVar3 != -2));
  if (cCODEffff == cVar2 && cCODEfffe == cVar1) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  DAT_INTMEM_61 = 6;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



void FUN_CODE_0330(char param_1)

{
  char cVar1;
  char cVar2;
  char *pcVar3;
  
  FUN_CODE_008e(DAT_INTMEM_44,DAT_INTMEM_45);
  func_0x1000(0x13,0);
  func_0x1006(param_1 + '\x02');
  FUN_CODE_008e(DAT_INTMEM_44,DAT_INTMEM_45);
  func_0x1003(0x13,0);
  cVar2 = '\x13';
  pcVar3 = &DAT_EXTMEM_668f;
  do {
    cVar1 = *pcVar3;
    pcVar3 = pcVar3 + 1;
    if (cVar1 != BANK0_R6) {
      return;
    }
    cVar2 = cVar2 + -1;
  } while (cVar2 != '\0');
  return;
}



void FUN_CODE_038e(char param_1)

{
  undefined1 uVar1;
  undefined1 uVar2;
  
  DAT_INTMEM_3e = 1;
  DAT_INTMEM_3f = 0;
  FUN_CODE_0104(100,0,BANK0_R2,BANK0_R3);
  FUN_CODE_006e(0x401);
  FUN_CODE_013d(0x3a,2,BANK0_R2,BANK0_R3);
  FUN_CODE_0078(0,4,BANK0_R2,BANK0_R3);
  FUN_CODE_008e();
  func_0x1003(1,0);
  param_1 = param_1 + '\x02';
  FUN_CODE_0268(param_1,0x8f,0x66);
  FUN_CODE_00af(0xff,0xff,BANK0_R2,BANK0_R3);
  FUN_CODE_006e(0x3fe);
  FUN_CODE_01f8();
  FUN_CODE_01f1();
  uVar1 = 0x1e;
  uVar2 = 0;
  FUN_CODE_013d(BANK0_R2,BANK0_R3);
  DAT_INTMEM_3e = uVar1;
  DAT_INTMEM_3f = uVar2;
  FUN_CODE_0104(0xb8,0xb,BANK0_R2,BANK0_R3);
  FUN_CODE_006e(0x48f);
  FUN_CODE_013d(0x13,0,BANK0_R2,BANK0_R3);
  FUN_CODE_0078(0,4,BANK0_R2,BANK0_R3);
  FUN_CODE_008e();
  func_0x1003(1,0);
  FUN_CODE_0268(param_1 + '\x02',0x8f,0x66);
  FUN_CODE_00af(0xff,0xff,BANK0_R2,BANK0_R3);
  FUN_CODE_006e(0x48c);
  FUN_CODE_00af(0xb8,0xb,BANK0_R2,BANK0_R3);
  FUN_CODE_006e(0x4aa);
  DAT_INTMEM_61 = 0xb;
  func_0x100f();
  FUN_CODE_008e(0,4);
  FUN_CODE_013d(0x13,0,BANK0_R2,BANK0_R3);
  FUN_CODE_0087();
  FUN_CODE_0078();
  return;
}



void FUN_CODE_0519(char param_1)

{
  char cVar1;
  byte bVar2;
  byte *pbVar3;
  
  FUN_CODE_0540(0x12,BANK0_R1);
  if (param_1 != '\0') {
    pbVar3 = &DAT_EXTMEM_6692;
    cVar1 = '\x03';
    bVar2 = 0;
    do {
      bVar2 = *pbVar3 | bVar2;
      pbVar3 = pbVar3 + 1;
      cVar1 = cVar1 + -1;
    } while (cVar1 != '\0');
    if (bVar2 != 0) {
      return;
    }
  }
  func_0x1045(0x13,0x8f,0x66);
  return;
}



void FUN_CODE_0540(char param_1)

{
  do {
    param_1 = param_1 + -1;
  } while (param_1 != '\0');
  return;
}



void FUN_CODE_055d(char param_1)

{
  undefined1 uVar1;
  undefined1 uVar2;
  
  func_0x1012();
  FUN_CODE_008e(0xfe,2);
  uVar2 = DAT_EXTMEM_668e;
  FUN_CODE_0087(DAT_EXTMEM_668d);
  FUN_CODE_0078();
  FUN_CODE_008e();
  uVar1 = 0;
  BANK0_R3 = 0;
  func_0x1015();
  FUN_CODE_0287(0x663a,param_1 + '\x02');
  FUN_CODE_006e(0x597);
  FUN_CODE_038e();
  DAT_INTMEM_44 = uVar1;
  DAT_INTMEM_45 = uVar2;
  FUN_CODE_05e3();
  FUN_CODE_008e(0xff,2);
  FUN_CODE_0087(DAT_EXTMEM_668d,DAT_EXTMEM_668e);
  FUN_CODE_0078();
  FUN_CODE_008e();
  BANK0_R3 = 0;
  func_0x1015();
  return;
}



void FUN_CODE_05e3(char param_1)

{
  FUN_CODE_0330();
  if (param_1 == '\0') {
    FUN_CODE_0330();
    if (param_1 == '\0') {
      FUN_CODE_0330();
      if (param_1 == '\0') {
        DAT_INTMEM_61 = 0xc;
        func_0x100f();
      }
    }
  }
  return;
}



void FUN_CODE_05fc(char param_1)

{
  DAT_INTMEM_3e = 0;
  DAT_INTMEM_3f = 0;
  FUN_CODE_0104(0x1e,0,BANK0_R2,BANK0_R3);
  FUN_CODE_006e(0x66f);
  FUN_CODE_013d(0x13,0,BANK0_R2,BANK0_R3);
  FUN_CODE_0078(0x8e,0,BANK0_R2,BANK0_R3);
  FUN_CODE_008e();
  func_0x1003(1,0);
  FUN_CODE_0268(param_1 + '\x02',0x8f,0x66);
  FUN_CODE_00af(0xff,0xff,BANK0_R2,BANK0_R3);
  FUN_CODE_006e(0x66c);
  FUN_CODE_013d(0x13,0,BANK0_R2,BANK0_R3);
  FUN_CODE_0078(0x8e,0,BANK0_R2,BANK0_R3);
  return;
}



void FUN_CODE_068a(char param_1)

{
  FUN_CODE_008e();
  FUN_CODE_024b(0);
  FUN_CODE_013d(0x13,0,BANK0_R2,BANK0_R3);
  FUN_CODE_0078(0x8e,0,BANK0_R2,BANK0_R3);
  FUN_CODE_008e();
  func_0x1003(0x13,0);
  FUN_CODE_0268(param_1 + '\x02',0x8f,0x66);
  FUN_CODE_00af(0xff,0xff,BANK0_R2,BANK0_R3);
  FUN_CODE_006e(0x6d2);
  BANK0_R3 = 0;
  return;
}



void FUN_CODE_06f9(char param_1)

{
  char cVar1;
  undefined1 uVar2;
  undefined1 uVar3;
  char *pcVar4;
  
  FUN_CODE_008e(0x2a,0);
  func_0x1003(0x40,0);
  pcVar4 = &DAT_EXTMEM_668f;
  cVar1 = '@';
  DAT_INTMEM_3e = '\0';
  DAT_INTMEM_3f = 0;
  do {
    if (*pcVar4 != '\0') goto LAB_CODE_0722;
    DAT_INTMEM_3e = DAT_INTMEM_3e + '\x01';
    pcVar4 = pcVar4 + 1;
    cVar1 = cVar1 + -1;
  } while (cVar1 != '\0');
  DAT_INTMEM_61 = 0xb;
  func_0x100f(param_1 + '\x02');
LAB_CODE_0722:
  FUN_CODE_013d(8,0,BANK0_R2,BANK0_R3);
  FUN_CODE_008e();
  FUN_CODE_010c(DAT_INTMEM_3e,DAT_INTMEM_3f);
  uVar2 = 0x8f;
  uVar3 = 0x66;
  FUN_CODE_0078();
  FUN_CODE_0268();
  func_0x1024();
  FUN_CODE_0087();
  FUN_CODE_0078();
  DAT_INTMEM_44 = uVar2;
  DAT_INTMEM_45 = uVar3;
  return;
}



void FUN_CODE_07c6(void)

{
  undefined1 uVar1;
  undefined1 uVar2;
  
  FUN_CODE_038e();
  uVar1 = 1;
  uVar2 = 0;
  FUN_CODE_0078(BANK0_R2,BANK0_R3);
  DAT_EXTMEM_62fb = uVar1;
  DAT_EXTMEM_62fc = uVar2;
  return;
}



void FUN_CODE_07ff(char param_1,undefined1 param_2)

{
  nop();
  BANK0_R3 = param_2;
  FUN_CODE_008e();
  func_0x1027(0x15,0x66);
  FUN_CODE_006e(0x820,param_1 + '\x02');
  func_0x102a(2,0);
  BANK0_R3 = 0;
  return;
}



void FUN_CODE_098b(void)

{
  char cVar1;
  char *pcVar2;
  
  BANK0_R3 = 0;
  pcVar2 = &DAT_EXTMEM_65c1;
  cVar1 = '\x06';
  do {
    if (*pcVar2 != '\0') {
      BANK0_R3 = 0;
      return;
    }
    pcVar2 = pcVar2 + 1;
    cVar1 = cVar1 + -1;
  } while (cVar1 != '\0');
  return;
}



void FUN_CODE_0f26(void)

{
  TMOD = 0x21;
  TH1 = 0xfa;
  SCON = 0x50;
  TR1 = 1;
  FUN_CODE_002c();
  return;
}



void FUN_CODE_0f34(void)

{
  char cVar1;
  
  P0_0 = 1;
  cVar1 = P0_0;
  if (((cVar1 != '\0') && (cVar1 = P0_1, cVar1 != '\0')) && (cVar1 = P0_2, cVar1 != '\0')) {
    P0_1 = 0;
    cVar1 = P0_0;
    if (((cVar1 != '\x01') && (cVar1 = P0_1, cVar1 != '\x01')) && (cVar1 = P0_2, cVar1 != '\x01')) {
      thunk_FUN_CODE_0f26();
      return;
    }
  }
  FUN_CODE_02f0();
  return;
}


