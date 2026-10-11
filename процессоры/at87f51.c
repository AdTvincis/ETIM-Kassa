typedef unsigned char   undefined;

typedef unsigned char    undefined1;


byte DAT_INTMEM_30;
byte DAT_INTMEM_31;
char DAT_INTMEM_32;
char DAT_INTMEM_33;
char DAT_INTMEM_34;
char DAT_INTMEM_35;
undefined TF0;
undefined TL0;
undefined TH0;
undefined1 P1;
undefined F0;
undefined P2;
undefined 2f.5;
undefined 2f.6;
undefined 2f.7;
undefined P3;

void FUN_CODE_0126(void)

{
  char cVar1;
  byte bVar2;
  byte bVar3;
  char cVar4;
  
  TF0 = 0;
  TH0 = 0xf8;
  TL0 = 0xcd;
  DAT_INTMEM_30 = DAT_INTMEM_30 + 1;
  if (DAT_INTMEM_30 == 5) {
    DAT_INTMEM_30 = 0;
  }
  P2 = 0;
  P3 = DAT_INTMEM_30 >> 4 | DAT_INTMEM_30 << 4 | 0xf;
  bVar2 = P1;
  bVar2 = ~bVar2;
  cVar1 = DAT_INTMEM_34;
  if (bVar2 == 0) {
    if (DAT_INTMEM_33 == '\0') {
      _f_7 = '\0';
      if ((_f_6 == '\x01') && (DAT_INTMEM_32 = DAT_INTMEM_32 + -1, DAT_INTMEM_32 == '\0')) {
        _f_6 = '\0';
      }
    }
    else {
      DAT_INTMEM_33 = DAT_INTMEM_33 + -1;
    }
  }
  else {
    DAT_INTMEM_32 = ' ';
    DAT_INTMEM_31 = bVar2;
    if (DAT_INTMEM_33 == '\0') {
      DAT_INTMEM_33 = '\x04';
      DAT_INTMEM_31 = 8;
      F0 = 0;
      do {
        bVar3 = bVar2 >> 1 | bVar2 << 7;
        if ((bVar2 & 1) != 0) {
          cVar4 = F0;
          if (cVar4 == '\x01') goto LAB_CODE_0152;
          F0 = 1;
        }
        DAT_INTMEM_31 = DAT_INTMEM_31 - 1;
        bVar2 = bVar3;
      } while (DAT_INTMEM_31 != 0);
      if (_f_6 != '\x01') {
        DAT_INTMEM_31 = 0xff;
        do {
          DAT_INTMEM_31 = DAT_INTMEM_31 + 1;
          bVar2 = bVar3 & 1;
          bVar3 = bVar3 >> 1 | bVar3 << 7;
        } while (bVar2 == 0);
        cVar4 = (((DAT_INTMEM_30 << 1 | DAT_INTMEM_30 >> 7) << 1 | (DAT_INTMEM_30 & 0x7f) >> 6) << 1
                | (DAT_INTMEM_30 << 1 & 0x7f) >> 6) + DAT_INTMEM_31;
        if (_f_7 == '\x01') {
          cVar1 = cVar4;
          if ((cVar4 == DAT_INTMEM_34) && (cVar1 = DAT_INTMEM_34, _f_5 != '\x01')) {
            _f_6 = '\x01';
            _f_5 = '\x01';
            DAT_INTMEM_35 = cVar4;
          }
        }
        else {
          _f_7 = '\x01';
          DAT_INTMEM_34 = -1;
          cVar1 = DAT_INTMEM_34;
        }
      }
    }
    else {
LAB_CODE_0152:
      DAT_INTMEM_33 = '\x04';
    }
  }
  DAT_INTMEM_34 = cVar1;
  return;
}


