typedef unsigned char   undefined;

typedef unsigned char    undefined1;


undefined IP;
undefined BANK0_R0;
undefined 21.1;
undefined PCON;
undefined 21.5;
undefined TCON;
undefined TMOD;
undefined TL0;
undefined BANK1_R0;
undefined TL1;
undefined BANK1_R1;
undefined TH0;
undefined BANK1_R2;
undefined TH1;
undefined1 BANK1_R7;
undefined SCON;
undefined LAB_CODE_00b9+1;
undefined LAB_CODE_007f;
undefined1 BANK2_R3;
undefined IE;
undefined1 BANK3_R4;
char DAT_INTMEM_7f;
char DAT_INTMEM_7e;
undefined LAB_CODE_0281+1;
char DAT_CODE_8001;
char DAT_CODE_8002;
char DAT_CODE_8003;
char UNK_CODE_8000;
undefined INT0;
undefined P1.6;
undefined 21.0;
undefined EA;
undefined1 DAT_INTMEM_ec;
undefined1 DAT_INTMEM_ed;
undefined1 BANK0_R1;
undefined1 DAT_INTMEM_ee;
undefined1 BANK0_R2;
undefined1 DAT_INTMEM_ef;
undefined1 BANK0_R3;
undefined1 DAT_INTMEM_f0;
undefined1 BANK0_R4;
undefined1 DAT_INTMEM_f1;
undefined1 BANK0_R5;
undefined1 DAT_INTMEM_f2;
undefined1 BANK0_R6;
undefined1 DAT_INTMEM_f3;
undefined1 BANK0_R7;

undefined1 FUN_CODE_0043(void)

{
  undefined1 uVar1;
  undefined1 *puVar2;
  char *pcVar3;
  undefined1 uVar4;
  char cVar5;
  char cVar6;
  undefined2 uVar7;
  
  TMOD = 0x21;
  TL0 = 0x40;
  TH0 = 0xfe;
  TL1 = 0xf4;
  TH1 = 0xf4;
  TCON = 0x50;
  SCON = 0x50;
  PCON = 0x80;
  BANK2_R3 = 0xfe;
  IP = 2;
  IE = 0x82;
  BANK1_R7 = 0x28;
  _1_5 = '\x01';
  FUN_CODE_022c();
  puVar2 = &DAT_INTMEM_ba;
  cVar5 = '\0';
  if (DAT_INTMEM_ba == -0x56) {
    do {
      func_0x913d();
      uVar4 = FUN_CODE_0196();
      uVar1 = BANK0_R0;
      if (cVar5 < '\0') break;
      FUN_CODE_073f(0x3f,0x17);
      BANK0_R0 = uVar1;
      FUN_CODE_073f(0x58,0x18);
      BANK0_R0 = uVar1;
      FUN_CODE_073f(0xd8,0x19);
      BANK0_R0 = uVar1;
      FUN_CODE_073f(0x52,0x1b);
      puVar2 = &BANK3_R4;
      BANK0_R0 = uVar1;
      FUN_CODE_073f(0x78);
      BANK0_R0 = uVar1;
      FUN_CODE_0196(uVar4);
    } while (-1 < cVar5);
  }
  BANK2_R3 = 0xfe;
  *puVar2 = 0xaa;
  func_0xaa46();
  func_0x8856();
  do {
  } while (_1_5 == '\x01');
  cVar5 = FUN_CODE_058c();
  if (cVar5 != '\0') {
    func_0x8004(0x1c);
    func_0x816a(0x51,1);
    func_0x9ae1();
    func_0x8004(0x30);
    func_0xc308(0xc5);
    do {
                    // WARNING: Do nothing block with infinite loop
    } while( true );
  }
  _1_1 = 0;
  BANK1_R0 = 0x7f;
  BANK1_R1 = 0x18;
  func_0x8438(0);
  cVar5 = '\x18';
  pcVar3 = &DAT_INTMEM_7f;
  do {
    if (*pcVar3 != -1) goto LAB_CODE_017e;
    pcVar3 = pcVar3 + -1;
    cVar5 = cVar5 + -1;
  } while (cVar5 != '\0');
  uVar7 = 0x18;
  BANK1_R0 = 0x7f;
  BANK1_R1 = 0x18;
  func_0x8438();
  cVar5 = '\x18';
  pcVar3 = &DAT_INTMEM_7f;
  do {
    cVar6 = (*pcVar3 != -1) << 7;
    if (*pcVar3 != -1) goto LAB_CODE_017e;
    pcVar3 = pcVar3 + -1;
    cVar5 = cVar5 + -1;
  } while (cVar5 != '\0');
  BANK1_R1 = 0x7f;
  BANK1_R2 = 0x20;
  func_0x8406(0xa681);
  func_0xad8e(uVar7,0x7f,0x20);
  BANK1_R0 = 0x7f;
  BANK1_R1 = 0x20;
  cVar5 = func_0x8458(10);
  if (cVar5 == '\0') {
    func_0x8004(0x1c);
    FUN_CODE_01d8(0x68);
    func_0x816a(100,4);
    func_0x9ae1();
    func_0x8004(0x30);
    func_0x95b9();
    if (-1 < cVar6) {
      func_0xaa46();
      func_0x9f81();
      func_0x9fa5();
      func_0x9558();
    }
  }
  else {
    _1_1 = 1;
    func_0x8004(8);
    func_0x816a(0x44,5);
    func_0x9ae1();
    func_0x8004(0x30);
    func_0xc308(0xa0);
    do {
      func_0x9878();
    } while (-1 < cVar6);
    BANK2_R3 = 0xfe;
    _1_1 = 1;
  }
LAB_CODE_017e:
  cVar5 = FUN_CODE_01e7();
  if (cVar5 != '\0') {
    FUN_CODE_0207();
  }
  func_0x8894(4);
  BANK1_R0 = 0x7f;
  func_0x818d();
  func_0xa92f();
  return 0;
}



void FUN_CODE_0196(void)

{
  char cVar1;
  char in_PSW;
  
  cVar1 = '\b';
  while( true ) {
    func_0x9878();
    if (in_PSW < '\0') {
      return;
    }
    func_0x95f4();
    func_0x9878();
    if (in_PSW < '\0') break;
    cVar1 = cVar1 + -1;
    if (cVar1 == '\0') {
      return;
    }
  }
  return;
}



void FUN_CODE_01d8(void)

{
  func_0x8165();
  func_0x9ae1();
  return;
}



undefined1 FUN_CODE_01e7(void)

{
  FUN_CODE_0680(0x7f,0x1f,0xfe,2);
  if (DAT_INTMEM_7e == 'U' && DAT_INTMEM_7f == -0x56) {
    return 0;
  }
  return 0xc3;
}



void FUN_CODE_0207(void)

{
  char in_PSW;
  
  func_0x816a(0x73,2);
  func_0x9ae1();
  FUN_CODE_01d8(0x74);
  BANK1_R0 = 0xfd;
  func_0x818d();
  func_0x9a80();
  func_0xc308(0xc3);
  do {
    func_0x9878();
  } while (-1 < in_PSW);
  BANK2_R3 = 0xfe;
  return;
}



// WARNING: Removing unreachable block (CODE,0x024c)

void FUN_CODE_022c(void)

{
  char cVar1;
  
  cVar1 = FUN_CODE_028e();
  if ((cVar1 == '\0') && (cVar1 = FUN_CODE_02a0(), cVar1 == '\0')) {
    return;
  }
  FUN_CODE_024e(&LAB_CODE_0281_1,0x14,0xc);
  do {
  } while( true );
}



void FUN_CODE_024e(undefined1 *param_1,char param_2,char param_3)

{
  do {
    FUN_CODE_073f(*param_1,param_2);
    param_2 = param_2 + '\x01';
    param_1 = param_1 + 1;
    param_3 = param_3 + -1;
  } while (param_3 != '\0');
  return;
}



undefined1 FUN_CODE_028e(char *param_1,char param_2,char param_3)

{
  FUN_CODE_02e6();
  if ((*param_1 == param_2) && (param_1[1] == param_3)) {
    return 0;
  }
  return 0xbf;
}



undefined1 FUN_CODE_02a0(char param_1,char param_2)

{
  char *pcVar1;
  
  pcVar1 = (char *)0x8000;
  if ((((cCODE8000 == -0x5b) && (DAT_CODE_8001 == 'U')) && (DAT_CODE_8002 == 'Z')) &&
     (DAT_CODE_8003 == -0x56)) {
    FUN_CODE_02c9();
    if ((*pcVar1 == param_1) && (pcVar1[1] == param_2)) {
      return 0;
    }
  }
  return 0xbf;
}



void FUN_CODE_02c9(void)

{
  short sVar1;
  
  sVar1 = -0x8000;
  do {
    do {
      sVar1 = sVar1 + 2;
    } while ((char)((ushort)sVar1 >> 8) != -1);
  } while ((char)sVar1 != -2);
  return;
}



void FUN_CODE_02e6(void)

{
  short sVar1;
  
  sVar1 = 0;
  do {
    do {
      sVar1 = sVar1 + 2;
    } while ((char)((ushort)sVar1 >> 8) != '\x0f');
  } while ((char)sVar1 != -2);
  return;
}



void FUN_CODE_049e(void)

{
  P1_6 = 1;
  INT0 = 1;
  nop();
  nop();
  P1_6 = 0;
  nop();
  nop();
  INT0 = 0;
  nop();
  return;
}



void FUN_CODE_04ac(void)

{
  INT0 = 1;
  nop();
  nop();
  P1_6 = 1;
  nop();
  nop();
  return;
}



byte FUN_CODE_04b5(byte param_1)

{
  char cVar1;
  byte bVar2;
  byte bVar3;
  
  cVar1 = '\b';
  bVar3 = 0;
  do {
    bVar2 = param_1 << 1 | bVar3 >> 7;
    bVar3 = param_1 & 0x80;
    P1_6 = param_1 >> 7;
    INT0 = 1;
    nop();
    nop();
    nop();
    INT0 = 0;
    nop();
    nop();
    cVar1 = cVar1 + -1;
    param_1 = bVar2;
  } while (cVar1 != '\0');
  P1_6 = 0;
  return bVar2;
}



byte FUN_CODE_04c9(void)

{
  byte bVar1;
  char cVar2;
  byte bVar3;
  
  bVar3 = 0;
  P1_6 = 1;
  cVar2 = '\b';
  do {
    INT0 = 1;
    nop();
    nop();
    bVar1 = P1_6;
    bVar3 = bVar3 << 1 | bVar1 & 1;
    INT0 = 0;
    nop();
    nop();
    cVar2 = cVar2 + -1;
  } while (cVar2 != '\0');
  return bVar3;
}



void FUN_CODE_04dc(void)

{
  byte in_PSW;
  
  FUN_CODE_04b5(in_PSW >> 7 | 0xd0);
  return;
}



void FUN_CODE_04e3(void)

{
  char cVar1;
  
  FUN_CODE_04b5();
  P1_6 = 1;
  INT0 = 1;
  do {
    cVar1 = P1_6;
  } while (cVar1 << 7 < '\0');
  INT0 = 0;
  P1_6 = 0;
  return;
}



void FUN_CODE_04f5(undefined1 *param_1,char param_2,char param_3)

{
  char cVar1;
  
  do {
    _1_0 = 1;
    FUN_CODE_049e(param_2);
    FUN_CODE_04dc();
    P1_6 = 1;
    INT0 = 1;
    do {
      cVar1 = P1_6;
    } while (cVar1 << 7 < '\0');
    INT0 = 0;
    P1_6 = 0;
    FUN_CODE_04e3();
    FUN_CODE_04b5(*param_1);
    P1_6 = 1;
    INT0 = 1;
    do {
      cVar1 = P1_6;
    } while (cVar1 << 7 < '\0');
    INT0 = 0;
    P1_6 = 0;
    param_1 = param_1 + -1;
    FUN_CODE_04ac();
    param_2 = param_2 + '\x01';
    param_3 = param_3 + -1;
  } while (param_3 != '\0');
  _1_0 = 0;
  return;
}



void FUN_CODE_0522(undefined1 *param_1)

{
  char cVar1;
  undefined1 uVar2;
  
  FUN_CODE_049e();
  FUN_CODE_04dc();
  P1_6 = 1;
  INT0 = 1;
  do {
    cVar1 = P1_6;
  } while (cVar1 << 7 < '\0');
  INT0 = 0;
  P1_6 = 0;
  FUN_CODE_04e3();
  FUN_CODE_049e();
  FUN_CODE_04dc();
  P1_6 = 1;
  INT0 = 1;
  do {
    cVar1 = P1_6;
  } while (cVar1 << 7 < '\0');
  INT0 = 0;
  P1_6 = 0;
  uVar2 = FUN_CODE_04c9();
  *param_1 = uVar2;
  P1_6 = 0;
  nop();
  P1_6 = 1;
  INT0 = 1;
  nop();
  nop();
  nop();
  INT0 = 0;
  P1_6 = 0;
  FUN_CODE_04ac();
  return;
}



void FUN_CODE_055b(char param_1,char param_2,char param_3)

{
  byte bVar1;
  
  bVar1 = PCON;
  PCON = bVar1 | 1;
  _1_0 = 1;
  FUN_CODE_0522();
  _1_0 = 0;
  param_3 = param_3 + -1;
  if (param_3 == '\0') {
    return;
  }
  do {
    bVar1 = PCON;
    PCON = bVar1 | 1;
    param_1 = param_1 + -1;
    param_2 = param_2 + '\x01';
    _1_0 = 1;
    FUN_CODE_0522(param_1,param_2);
    _1_0 = 0;
    param_3 = param_3 + -1;
  } while (param_3 != '\0');
  return;
}



undefined1 FUN_CODE_0577(undefined1 param_1)

{
  char cVar1;
  char cVar2;
  
  P1_6 = 1;
  INT0 = 1;
  cVar2 = '\0';
  do {
    cVar1 = P1_6;
    if (-1 < cVar1 << 7) break;
    cVar2 = cVar2 + -1;
  } while (cVar2 != '\0');
  INT0 = 0;
  P1_6 = 0;
  return param_1;
}



void FUN_CODE_058c(void)

{
  byte bVar1;
  byte bVar2;
  char cVar3;
  undefined1 uVar4;
  char cVar5;
  
  EA = 0;
  cVar3 = '\n';
  do {
    INT0 = 1;
    P1_6 = 1;
    nop();
    nop();
    bVar2 = INT0;
    bVar1 = P1_6;
    cVar5 = (bVar2 & 1 & bVar1) << 7;
    if (cVar5 < '\0') {
      FUN_CODE_049e();
      FUN_CODE_04b5(0xd0);
      FUN_CODE_0577();
      if (-1 < cVar5) {
        FUN_CODE_04b5(0);
        FUN_CODE_0577();
        if (-1 < cVar5) {
          FUN_CODE_049e();
          FUN_CODE_04b5(0xd1);
          FUN_CODE_0577();
          if (-1 < cVar5) {
            FUN_CODE_04c9();
            P1_6 = 0;
            P1_6 = 1;
            INT0 = 1;
            nop();
            nop();
            nop();
            INT0 = 0;
            P1_6 = 0;
            uVar4 = 0;
            goto LAB_CODE_05d1;
          }
        }
      }
    }
    cVar3 = cVar3 + -1;
  } while (cVar3 != '\0');
  uVar4 = 0xc5;
LAB_CODE_05d1:
  FUN_CODE_04ac(uVar4);
  EA = 1;
  return;
}



void FUN_CODE_0680(undefined1 *param_1,undefined1 param_2,undefined1 param_3,char param_4)

{
  undefined1 *puVar1;
  
  puVar1 = (undefined1 *)CONCAT11(param_2,param_3);
  do {
    P1_6 = 0;
    P1_6 = 1;
    *param_1 = *puVar1;
    param_1 = param_1 + -1;
    puVar1 = puVar1 + 1;
    param_4 = param_4 + -1;
  } while (param_4 != '\0');
  return;
}



void FUN_CODE_073f(undefined1 param_1,undefined1 *param_2)

{
  *param_2 = param_1;
  return;
}



void FUN_CODE_0951(undefined1 param_1)

{
  DAT_INTMEM_ec = param_1;
  DAT_INTMEM_ed = BANK0_R7;
  DAT_INTMEM_ee = BANK0_R6;
  DAT_INTMEM_ef = BANK0_R5;
  DAT_INTMEM_f0 = BANK0_R4;
  DAT_INTMEM_f1 = BANK0_R3;
  DAT_INTMEM_f2 = BANK0_R2;
  DAT_INTMEM_f3 = BANK0_R1;
  return;
}



void FUN_CODE_096f(void)

{
  BANK0_R7 = DAT_INTMEM_ed;
  BANK0_R6 = DAT_INTMEM_ee;
  BANK0_R5 = DAT_INTMEM_ef;
  BANK0_R4 = DAT_INTMEM_f0;
  BANK0_R3 = DAT_INTMEM_f1;
  BANK0_R2 = DAT_INTMEM_f2;
  BANK0_R1 = DAT_INTMEM_f3;
  return;
}


