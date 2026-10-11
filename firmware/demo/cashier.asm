; ===========================================================================
;  cashier.asm -- ДЕМОНСТРАЦИОННАЯ (stand-in) программа кассы AO "ЭТИМ"
; ===========================================================================
;
;  !!!  ЭТО НЕ ОРИГИНАЛЬНАЯ ПРОШИВКА  !!!
;
;  Дамп firmware/nm27c512n.hex после rebasing -- это нижние 32 КиБ CPU
;  (0x0000..0x7FFF; записи hex лежат по смещениям программатора
;  0x8000..0xFFFF, вектор сброса LJMP 0x0A06 настоящий и исполняем).
;  Верхней половины 0x8000..0xFFFF в дампе нет, а сканирование клавиатуры
;  и принтер декомпиляцией покрыты не полностью (docs/hardware_evidence.md),
;  поэтому поведение настоящей прошивки в эмуляторе пока не детерминировано.
;
;  Эта программа -- ЗАМЕНА (демонстрационная), написанная вручную настоящим
;  машинным кодом MCS-51 и собранная tools/asm51.py. Она даёт работающую кассу
;  (индикатор, клавиатура, печать чека) с предсказуемым сценарием -- на ней
;  построены тесты платы и UI. Там, где программа себя называет, она говорит
;  "ДЕМО-ПРОГРАММА / НЕ ОРИГИНАЛ".
;
;  Загрузка: образ начинается с адреса 0x0000, по 0x0000 лежит LJMP START
;  (настоящий вектор сброса), поэтому ROM.load_block(0x0000, image) и
;  cpu.pc = 0 запускают программу без каких-либо правок.
;  Цикл -- опросный, без прерываний; все задержки ограничены счётчиками DJNZ.
;
;  Сборка:    python -m firmware.demo.build          (пишет cashier.hex)
;  Синтаксис: см. шапку tools/asm51.py
;
;  Аппаратура (согласовано с board/, владелец hal-ppi; см. docs/board_contract.md):
;    ППИ 8255 в XDATA 0x0000..0x0003, управляющее слово 0x89 -- как в реальном
;    дампе (в нём встречаются 0x89 и 0xA9 в одном месте: индикатор / принтер).
;      0x0000 PA (выход) -- ДАННЫЕ ИНДИКАТОРА: маска сегментов, активный
;                          высокий: бит0=a бит1=b бит2=c бит3=d бит4=e бит5=f
;                          бит6=g бит7=dp. В режиме 1 (0xA9) -- байт принтеру.
;      0x0001 PB (выход) -- ВЫБОР ЗНАКОМЕСТА, единица в одном разряде
;                          (0x01 = знакоместо 0, 0x80 = знакоместо 7).
;                          Тот же разряд выбирает строку клавиатуры.
;      0x0002 PC (вход)  -- СТОЛБЦЫ КЛАВИАТУРЫ, активный низкий
;                          (0 = нажато). PC0..PC7 -- восемь столбцов.
;      0x0003    (выход) -- регистр управления 8255.
;
;    Индикатор 8 знакомест, 1 строка. Плата защёлкивает PA и переносит маску в
;    знакоместо с номером floor(log2(PB)) по записи в PB.
;
;    Клавиатура 8 строк x 8 столбцов. Строка выбирается записью в PB (единица в
;    одном разряде), затем читается PC: 0 = нажато.
;
;    Принтер: ППИ переключается в режим 1 (управляющее слово 0xA9), после чего
;    каждый байт, записанный в PA, уходит в принтер. Индикатор при этом гаснет
;    (PB = 0), как и у настоящей кассы во время печати.
;
;  Дисплей: 8 знакомест, из них знакоместо 0 -- ИНДИКАТОР РЕЖИМА ("0".."3"),
;  знакоместа 1..7 -- сумма "99999.99" (5 целых цифр + точка + 2 копейки).
;  Ввод -- с неявной запятой: две последние введённые цифры это копейки.
;  Клавиша "." достраивает копейки двумя нулями (то же, что "00").
;  В режиме "подытог" (1) индикатор режима мигает, сама сумма видна постоянно.
; ===========================================================================

        ; чек печатается в 7-битной транслитерации -- той же, что у
        ; настоящей прошивки (docs/rom_strings.txt, board/printer.py);
        ; ascii, чтобы остаток KOI8-R в строках падал сборкой, а не
        ; молча попадал в чек.
        CHARSET ascii

; ---------------------------------------------------------------------------
;  ППИ 8255 (внешняя память данных, MOVX)
; ---------------------------------------------------------------------------
PPI_PA      EQU 0x0000      ; выход: маска сегментов индикатора / байт принтеру
PPI_PB      EQU 0x0001      ; выход: единица в разряде знакоместа (и строки)
PPI_PC      EQU 0x0002      ; вход:  столбцы клавиатуры (0 = нажато)
PPI_CTRL    EQU 0x0003      ; регистр управления 8255
PPI_MODE    EQU 0x89        ; режим 0: PA/PB выход, PC вход (индикатор)
PPI_MODE_PRN EQU 0xA9       ; группа A режим 1: PA уходит в принтер
NO_DIGIT    EQU 0x00        ; PB = 0 -- ни одно знакоместо не выбрано
NO_SEG      EQU 0x00        ; PA = 0 -- все сегменты погашены

; ---------------------------------------------------------------------------
;  Индикатор и клавиатура
; ---------------------------------------------------------------------------
DISPLAY_COLS EQU 8          ; знакомест на индикаторе
MODE_CELL    EQU 0          ; знакоместо индикатора режима
FIELD_W      EQU 7          ; ширина денежного поля: знакоместа 1..7
                            ; (знакоместо 0 занято индикатором режима, поэтому
                            ;  поле НЕ может быть шириной 8 — иначе старший
                            ;  разряд затирал бы индикатор режима)
KBD_ROWS     EQU 8          ; строк матрицы клавиатуры
KBD_COLS     EQU 8          ; столбцов матрицы клавиатуры
ALL_SEG      EQU 0x7F       ; все сегменты (самопроверка индикатора)
SEG_DP       EQU 0x80       ; десятичная точка

; ---------------------------------------------------------------------------
;  Внутренняя память данных 8051 (карта)
; ---------------------------------------------------------------------------
DISP_BUF    EQU 0x30        ; 8 байт: буфер индикатора (маски сегментов)
ENTRY       EQU 0x44        ; 4 байта BCD: вводимая сумма (младший байт первый)
TOTAL       EQU 0x48        ; 4 байта BCD: итог
LAST        EQU 0x4C        ; 4 байта BCD: последняя зарегистрированная позиция
CHANGE      EQU 0x50        ; 4 байта BCD: сдача
MODE        EQU 0x54        ; 0=ввод 1=подытог 2=итог 3=сдача
ITEM_N      EQU 0x55        ; число позиций в чеке
REC_N       EQU 0x56        ; номер чека
KEY_RAW     EQU 0x57        ; последний сырой код клавиши
KEY_CNT     EQU 0x58        ; счётчик антидребезга
KEY_STABLE  EQU 0x59        ; принятая клавиша (K_NONE = свободно)
DIGIDX      EQU 0x5A        ; текущий разряд BCD (0..6)
SIG         EQU 0x5B        ; 1 = значащие цифры уже начались
MASK        EQU 0x5C        ; маска сегментов текущей цифры
DIGIT       EQU 0x5D        ; текущая цифра 0..9
DMBASE      EQU 0x5E        ; первое знакоместо денежного поля
DMWID       EQU 0x5F        ; ширина денежного поля
DMWIDX      EQU 0x67        ; текущий разряд при отрисовке поля
DMPOS       EQU 0x68        ; знакоместо текущего разряда
PADN        EQU 0x60        ; сколько пробелов добить до левого края суммы
BLINK       EQU 0x61        ; младший байт счётчика мигания
KEYCUR      EQU 0x62        ; код клавиши в текущем сканировании
SCAN_ROW    EQU 0x63        ; текущая строка матрицы
TMP         EQU 0x64        ; рабочая ячейка
BLINK_HI    EQU 0x65        ; старший байт счётчика мигания
NEG         EQU 0x66        ; 4 байта BCD: дополнение до 10^8 (для вычитания)
DSPTR       EQU 0x6A        ; сохранённый указатель приёмника в BCD_SUB4

DEBOUNCE    EQU 3           ; сканирований подряд для подтверждения нажатия
DELAY_HI    EQU 6           ; длительность "test tpu" при включении
DELAY_LO    EQU 200

; ---------------------------------------------------------------------------
;  Внутренние коды клавиш (соответствие "матрица -> код" в таблице KEYMAP)
; ---------------------------------------------------------------------------
K_00        EQU 0x0A
K_DOT       EQU 0x0B
K_CLEAR     EQU 0x10        ; СБРОС
K_SUMM      EQU 0x11        ; СУММА
K_SUB       EQU 0x12        ; ПОДЫТОГ
K_ITOG      EQU 0x13        ; ИТОГ
K_CANCEL    EQU 0x14        ; ОТМЕНА
K_PAY       EQU 0x15        ; ОПЛ
K_ENTER     EQU 0x16        ; ВВОД (в демо = СУММА)
K_X         EQU 0x17        ; X (в демо не используется)
K_NONE      EQU 0xFF        ; клавиша не нажата

; ===========================================================================
;  КОД
; ===========================================================================
        ORG 0x0000
        LJMP START                      ; вектор сброса
        ORG 0x0003
        LJMP IRQ_NONE                   ; внешнее прерывание 0
        ORG 0x000B
        LJMP IRQ_NONE                   ; таймер 0
        ORG 0x0013
        LJMP IRQ_NONE                   ; внешнее прерывание 1
        ORG 0x001B
        LJMP IRQ_NONE                   ; таймер 1
        ORG 0x0023
        LJMP IRQ_NONE                   ; последовательный порт
        ORG 0x002B
        LJMP IRQ_NONE                   ; таймер 2 (AT89C55)
        ORG 0x0033
        LJMP IRQ_NONE                   ; PCA
        ORG 0x003B
        LJMP IRQ_NONE
        ORG 0x0043
        LJMP IRQ_NONE
        ORG 0x004B
        LJMP IRQ_NONE

        ORG 0x0080
; ---------------------------------------------------------------------------
;  Прерывания в демо не используются: любой вектор просто возвращается.
; ---------------------------------------------------------------------------
IRQ_NONE:
        RETI

; ---------------------------------------------------------------------------
;  СБРОС / ИНИЦИАЛИЗАЦИЯ
; ---------------------------------------------------------------------------
START:
        MOV  SP, #0x0F                  ; стек выше банка регистров
        MOV  P2, #0x00                  ; MOVX @Ri работает в странице 0
        ; --- очистка внутренней памяти 0x20..0x7F ---
        MOV  R0, #0x20
        MOV  R2, #0x60
        CLR  A
ST_CLR:
        MOV  @R0, A
        INC  R0
        DJNZ R2, ST_CLR
        ; --- начальные значения ---
        MOV  MODE, #0
        MOV  ITEM_N, #0
        MOV  REC_N, #0
        MOV  KEY_RAW, #K_NONE
        MOV  KEY_STABLE, #K_NONE
        MOV  KEY_CNT, #DEBOUNCE
        MOV  BLINK, #0
        MOV  BLINK_HI, #0
        ; --- настройка ППИ 8255 ---
        MOV  DPTR, #PPI_CTRL
        MOV  A, #PPI_MODE
        MOVX @DPTR, A                   ; управляющее слово (индикатор+клавиатура)
        ; Индикатор гасим в том же порядке, в каком он пишется весь остаток
        ; программы: СНАЧАЛА данные (PA), ПОТОМ выбор знакоместа (PB) -- см.
        ; REFRESH и SCAN_KEY.  Плата запоминает порядок по самому первому
        ; обращению к индикатору (board/cashboard.py, _ppi_order) и дальше до
        ; конца сеанса трактует пары PA/PB именно в нём: если первым
        ; событием станет только PB, плата решит, что код пишет «знакоместо
        ; -> данные», и весь индикатор уедет на одну позицию (индикатор
        ; режима в крайнее правое знакоместо, сумма -- левее).
        MOV  DPTR, #PPI_PA
        MOV  A, #NO_SEG
        MOVX @DPTR, A                   ; сегменты погашены
        MOV  DPTR, #PPI_PB
        MOV  A, #NO_DIGIT
        MOVX @DPTR, A                   ; ни одно знакоместо не выбрано
        ; --- "test tpu": самопроверка при включении ---
        LCALL SELFTEST
        MOV  MODE, #0
        LCALL SET_DISPLAY
        LCALL DELAY

; ---------------------------------------------------------------------------
;  ОСНОВНОЙ ЦИКЛ: индикатор -> клавиатура -> мигание индикатора режима
; ---------------------------------------------------------------------------
MAIN:
        LCALL REFRESH
        LCALL POLL_KEY
        LCALL BLINK_TICK
        SJMP MAIN

; ---------------------------------------------------------------------------
;  Самопроверка при включении: все сегменты всех знакомест ("8.8.8.8.8.8.8.8.")
; ---------------------------------------------------------------------------
SELFTEST:
        MOV  R0, #DISP_BUF
        MOV  R2, #DISPLAY_COLS
        MOV  A, #(ALL_SEG|SEG_DP)
ST_L:
        MOV  @R0, A
        INC  R0
        DJNZ R2, ST_L
        LCALL REFRESH
        LCALL REFRESH
        RET

; ---------------------------------------------------------------------------
;  Пауза (двойной цикл DJNZ, ограничена)
; ---------------------------------------------------------------------------
DELAY:
        MOV  R2, #DELAY_HI
DL_1:
        MOV  R3, #DELAY_LO
DL_2:
        DJNZ R3, DL_2
        DJNZ R2, DL_1
        RET

; ---------------------------------------------------------------------------
;  РЕФРЕШ ИНДИКАТОРА: PA = маска сегментов, затем PB = единица в разряде
;  (плата переносит маску в знакоместо по записи в PB)
; ---------------------------------------------------------------------------
REFRESH:
        MOV  R0, #DISP_BUF
        MOV  R1, #0x01                  ; единица в разряде знакоместа
        MOV  R2, #DISPLAY_COLS
RF_L:
        MOV  A, @R0
        MOV  DPTR, #PPI_PA
        MOVX @DPTR, A                   ; данные индикатора
        MOV  DPTR, #PPI_PB
        MOV  A, R1
        MOVX @DPTR, A                   ; выбор знакоместа -> защёлкивание
        INC  R0
        MOV  A, R1
        ADD  A, ACC                     ; R1 = R1 * 2 (следующий разряд)
        MOV  R1, A                      ; следующий разряд
        DJNZ R2, RF_L
        RET

; ---------------------------------------------------------------------------
;  ОПРОС КЛАВИАТУРЫ: сканирование матрицы, антидребезг, разбор
; ---------------------------------------------------------------------------
POLL_KEY:
        LCALL SCAN_KEY                  ; A = код клавиши или K_NONE
        MOV  KEYCUR, A
        CJNE A, KEY_RAW, PK_NEW         ; код изменился -> перезапуск счётчика
        INC  KEY_CNT
        MOV  A, KEY_CNT
        CJNE A, #DEBOUNCE, PK_DONE
        MOV  A, KEYCUR
        CJNE A, #K_NONE, PK_PRESS
        MOV  KEY_STABLE, #K_NONE        ; клавиша отпущена
        SJMP PK_DONE
PK_PRESS:
        MOV  A, KEY_STABLE
        CJNE A, #K_NONE, PK_DONE        ; уже обработана, ждём отпускания
        MOV  A, KEYCUR
        MOV  KEY_STABLE, A
        LCALL DISPATCH_KEY
        SJMP PK_DONE
PK_NEW:
        MOV  A, KEYCUR
        MOV  KEY_RAW, A
        MOV  KEY_CNT, #0
PK_DONE:
        RET

; ---------------------------------------------------------------------------
;  SCAN_KEY: выбирает строку записью единицы в PB (то же знакоместо), читает
;  столбцы из PC (0 = нажато). Заодно перерисовывает знакоместо, поэтому
;  индикатор во время опроса не портится.
;  Возвращает код клавиши из KEYMAP или K_NONE.
; ---------------------------------------------------------------------------
SCAN_KEY:
        MOV  SCAN_ROW, #0
SK_ROW:
        MOV  A, SCAN_ROW
        ADD  A, #DISP_BUF
        MOV  R0, A
        MOV  A, @R0                     ; правильная маска этого знакоместа
        MOV  DPTR, #PPI_PA
        MOVX @DPTR, A
        MOV  A, SCAN_ROW
        MOV  DPTR, #ROW_TAB
        MOVC A, @A+DPTR                 ; единица в разряде строки
        MOV  DPTR, #PPI_PB
        MOVX @DPTR, A                   ; строка i + знакоместо i
        MOV  DPTR, #PPI_PC
        MOVX A, @DPTR                   ; столбцы (0 = нажато)
        XRL  A, #0xFF                   ; теперь 1 = нажато
        JZ   SK_NEXT
        MOV  R2, #0
SK_COL:
        RRC  A                          ; младший бит -> C
        JC   SK_FOUND                   ; C=1 -- столбец нажат
        INC  R2
        CJNE R2, #KBD_COLS, SK_COL
        SJMP SK_NEXT
SK_FOUND:
        MOV  A, SCAN_ROW
        MOV  DPTR, #ROW_BASE
        MOVC A, @A+DPTR                 ; A = строка * 8
        ADD  A, R2                      ; + столбец
        MOV  DPTR, #KEYMAP
        MOVC A, @A+DPTR                 ; код клавиши
        RET
SK_NEXT:
        INC  SCAN_ROW
        MOV  A, SCAN_ROW
        CJNE A, #KBD_ROWS, SK_ROW
        MOV  A, #K_NONE
        RET

; ---------------------------------------------------------------------------
;  РАЗБОР КЛАВИШИ
; ---------------------------------------------------------------------------
DISPATCH_KEY:
        MOV  KEYCUR, A
        CLR  C
        SUBB A, #0x0A
        JC   DK_DIGIT                   ; 0..9 -- цифра
        MOV  A, KEYCUR
        CJNE A, #K_DOT, DK_1
        LJMP KEY_DOT
DK_1:
        CJNE A, #K_CLEAR, DK_2
        LJMP KEY_CLEAR
DK_2:
        CJNE A, #K_SUMM, DK_3
        LJMP KEY_SUMM
DK_3:
        CJNE A, #K_SUB, DK_4
        LJMP KEY_SUBTOTAL
DK_4:
        CJNE A, #K_ITOG, DK_5
        LJMP KEY_ITOG
DK_5:
        CJNE A, #K_CANCEL, DK_6
        LJMP KEY_CANCEL
DK_6:
        CJNE A, #K_PAY, DK_7
        LJMP KEY_PAY
DK_7:
        CJNE A, #K_ENTER, DK_8
        LJMP KEY_SUMM
DK_8:
        CJNE A, #K_00, DK_9
        LJMP KEY_00
DK_9:
        RET                             ; K_X и прочее игнорируются
DK_DIGIT:
        MOV  A, KEYCUR
        LJMP KEY_DIGIT

; ---------------------------------------------------------------------------
;  ЦИФРЫ: ввод суммы. Копейки -- две последние цифры (как в реальной кассе).
; ---------------------------------------------------------------------------
KEY_DIGIT:
        MOV  A, KEYCUR
        LCALL DIGIT_ENTRY
        RET
KEY_00:
        CLR  A
        LCALL DIGIT_ENTRY
        CLR  A
        LCALL DIGIT_ENTRY
        RET
KEY_DOT:                                ; "." -- зафиксировать копейки (два нуля)
        CLR  A
        LCALL DIGIT_ENTRY
        CLR  A
        LCALL DIGIT_ENTRY
        RET

; ---------------------------------------------------------------------------
;  DIGIT_ENTRY: A = цифра 0..9, ENTRY = ENTRY*10 + цифра (BCD)
; ---------------------------------------------------------------------------
DIGIT_ENTRY:
        MOV  DIGIT, A
        MOV  A, ENTRY+3                 ; старший байт BCD
        SWAP A
        ANL  A, #0x0F                   ; старший разряд (переполнение?)
        JZ   DE_OK
        RET                             ; больше 7 цифр не принимаем
DE_OK:
        MOV  R1, #ENTRY
        LCALL BCD_SHL1                  ; ENTRY *= 10
        MOV  A, DIGIT
        ORL  ENTRY, A                   ; младший разряд был 0 -> ORL == ADD
        MOV  MODE, #0
        LCALL SET_DISPLAY
        RET

; ---------------------------------------------------------------------------
;  СБРОС -- очистить вводимую сумму
; ---------------------------------------------------------------------------
KEY_CLEAR:
        MOV  ENTRY, #0
        MOV  ENTRY+1, #0
        MOV  ENTRY+2, #0
        MOV  ENTRY+3, #0
        MOV  MODE, #0
        LCALL SET_DISPLAY
        RET

; ---------------------------------------------------------------------------
;  СУММА -- зарегистрировать позицию: итог += ввод, напечатать строку чека
; ---------------------------------------------------------------------------
KEY_SUMM:
        MOV  A, ENTRY
        ORL  A, ENTRY+1
        ORL  A, ENTRY+2
        ORL  A, ENTRY+3
        JZ   KS_DONE                    ; нулевую сумму не регистрируем
        MOV  A, ITEM_N
        JNZ  KS_NOHEAD
        LCALL RECEIPT_HEAD              ; шапка чека печатается на первой позиции
KS_NOHEAD:
        MOV  R0, #ENTRY
        MOV  R1, #LAST
        LCALL BCD_COPY4                 ; LAST = ENTRY (для ОТМЕНЫ)
        MOV  R1, #TOTAL
        MOV  R0, #ENTRY
        LCALL BCD_ADD4                  ; TOTAL += ENTRY
        INC  ITEM_N
        LCALL PRINT_ITEM                ; строка позиции
        MOV  ENTRY, #0                  ; очистить ввод
        MOV  ENTRY+1, #0
        MOV  ENTRY+2, #0
        MOV  ENTRY+3, #0
        MOV  MODE, #0
        LCALL SET_DISPLAY
KS_DONE:
        RET

; ---------------------------------------------------------------------------
;  ПОДЫТОГ -- показать итог (режим 1; индикатор режима мигает)
; ---------------------------------------------------------------------------
KEY_SUBTOTAL:
        MOV  MODE, #1
        LCALL SET_DISPLAY
        RET

; ---------------------------------------------------------------------------
;  ИТОГ -- показать итог (режим 2)
; ---------------------------------------------------------------------------
KEY_ITOG:
        MOV  MODE, #2
        LCALL SET_DISPLAY
        RET

; ---------------------------------------------------------------------------
;  ОТМЕНА -- сторнировать последнюю позицию
; ---------------------------------------------------------------------------
KEY_CANCEL:
        MOV  A, ITEM_N
        JZ   KC_DONE
        MOV  R1, #TOTAL
        MOV  R0, #LAST
        LCALL BCD_SUB4                  ; TOTAL -= LAST
        DEC  ITEM_N
        LCALL PRINT_VOID
        MOV  MODE, #0
        LCALL SET_DISPLAY
KC_DONE:
        RET

; ---------------------------------------------------------------------------
;  ОПЛ -- расчёт сдачи и печать чека
; ---------------------------------------------------------------------------
KEY_PAY:
        MOV  R0, #ENTRY
        MOV  R1, #CHANGE
        LCALL BCD_COPY4                 ; CHANGE = ENTRY (внесено наличными)
        MOV  R1, #CHANGE
        MOV  R0, #TOTAL
        LCALL BCD_SUB4                  ; CHANGE -= TOTAL; C=0 -> не хватает
        JNC  KP_SHORT
        LCALL PRINT_FOOTER
        MOV  MODE, #3
        LCALL SET_DISPLAY               ; на индикаторе -- сдача
        ; --- закрыть чек ---
        MOV  TOTAL, #0
        MOV  TOTAL+1, #0
        MOV  TOTAL+2, #0
        MOV  TOTAL+3, #0
        MOV  ITEM_N, #0
        MOV  ENTRY, #0
        MOV  ENTRY+1, #0
        MOV  ENTRY+2, #0
        MOV  ENTRY+3, #0
        RET
KP_SHORT:
        LCALL PRINT_SHORT               ; "НЕДОСТАТОЧНО"
        MOV  MODE, #2
        LCALL SET_DISPLAY
        RET

; ---------------------------------------------------------------------------
;  ПЕЧАТЬ ЧЕКА
;  ППИ переводится в режим 1 (0xA9): каждый байт в PA уходит в принтер.
;  Знакоместо не выбрано, поэтому индикатор во время печати гаснет.
; ---------------------------------------------------------------------------
PR_BEGIN:
        MOV  DPTR, #PPI_PB
        MOV  A, #NO_DIGIT
        MOVX @DPTR, A
        MOV  DPTR, #PPI_CTRL
        MOV  A, #PPI_MODE_PRN
        MOVX @DPTR, A
        RET
PR_END:
        MOV  DPTR, #PPI_CTRL
        MOV  A, #PPI_MODE
        MOVX @DPTR, A
        RET

;  PR_CHAR: A = байт принтеру (DPTR сохраняется)
PR_CHAR:
        PUSH DPL
        PUSH DPH
        MOV  DPTR, #PPI_PA
        MOVX @DPTR, A
        POP  DPH
        POP  DPL
        RET

;  PR_NL: конец строки.  Шлётся ТОЛЬКО LF (0x0A): плата трактует 0x0D как
;  «стирание строки, которая печатается» (см. board/printer.py), поэтому
;  пара CRLF напечатала бы пустые строки и шапка чека не попала бы на
;  бумагу.  LF -- также то, чем печатает сама плата (её собственные тесты
;  заканчивают строки одним 0x0A).
PR_NL:
        MOV  A, #0x0A
        LCALL PR_CHAR
        RET

;  PR_STR: DPTR -> строка с завершающим нулём (DPTR сохраняется в PR_CHAR)
PR_STR:
        CLR  A
        MOVC A, @A+DPTR
        JZ   PS_DONE
        LCALL PR_CHAR
        INC  DPTR
        SJMP PR_STR
PS_DONE:
        RET

;  PR_NUM2: A -> две десятичные цифры
PR_NUM2:
        MOV  B, #10
        DIV  AB
        ADD  A, #'0'
        LCALL PR_CHAR
        MOV  A, B
        ADD  A, #'0'
        LCALL PR_CHAR
        RET

;  PR_PAD: A = число пробелов
PR_PAD:
        MOV  R2, A
        MOV  A, R2
        JZ   PP_DONE
PP_L:
        MOV  A, #' '
        LCALL PR_CHAR
        DJNZ R2, PP_L
PP_DONE:
        RET

;  PR_MONEY: R1 = 4 байта BCD; печатает 8 колонок "99999.99"
PR_MONEY:
        MOV  SIG, #0
        MOV  DIGIDX, #6
PM_L:
        MOV  A, DIGIDX
        LCALL GETDIG
        MOV  DIGIT, A
        MOV  A, DIGIDX
        CJNE A, #1, PM_NODOT            ; точка -- ПЕРЕД копейками
        MOV  A, #'.'
        LCALL PR_CHAR
PM_NODOT:
        MOV  A, DIGIT
        JNZ  PM_PR
        MOV  A, SIG
        JNZ  PM_PR
        MOV  A, DIGIDX
        CJNE A, #2, PM_MAYBE
        SJMP PM_PR
PM_MAYBE:
        CJNE A, #0, PM_SPACE
PM_PR:
        MOV  SIG, #1
        MOV  A, DIGIT
        ADD  A, #'0'
        LCALL PR_CHAR
        SJMP PM_NEXT
PM_SPACE:
        MOV  A, #' '
        LCALL PR_CHAR
PM_NEXT:
        MOV  A, DIGIDX
        JZ   PM_DONE
        DEC  DIGIDX
        SJMP PM_L
PM_DONE:
        RET

;  PR_MONEY_LINE: DPTR = подпись, R1 = BCD, PADN = пробелов до суммы
PR_MONEY_LINE:
        LCALL PR_STR
        MOV  A, PADN
        LCALL PR_PAD
        LCALL PR_MONEY
        LCALL PR_NL
        RET

; ---------------------------------------------------------------------------
;  ЧЕК
; ---------------------------------------------------------------------------
RECEIPT_HEAD:
        LCALL PR_BEGIN
        INC  REC_N
        MOV  DPTR, #S_HEAD
        LCALL PR_STR
        MOV  DPTR, #S_DEMO
        LCALL PR_STR
        MOV  DPTR, #S_NOTE
        LCALL PR_STR
        MOV  DPTR, #S_RULE
        LCALL PR_STR
        MOV  DPTR, #S_ID
        LCALL PR_STR
        MOV  A, REC_N
        LCALL PR_NUM2
        MOV  DPTR, #S_CASH
        LCALL PR_STR
        MOV  DPTR, #S_DATE
        LCALL PR_STR
        LCALL PR_END
        RET

;  строка позиции: "NN. <цена(8)> <итог(8)>"
PRINT_ITEM:
        LCALL PR_BEGIN
        LCALL PR_NL
        MOV  A, ITEM_N
        LCALL PR_NUM2
        MOV  A, #'.'
        LCALL PR_CHAR
        MOV  R1, #ENTRY
        LCALL PR_MONEY
        MOV  A, #' '
        LCALL PR_CHAR
        MOV  R1, #TOTAL
        LCALL PR_MONEY
        LCALL PR_END
        RET

;  Все три подпрограммы печати начинают строку с PR_NL (как PRINT_ITEM):
;  предыдущая строка чека не заканчивается переводом строки, и без этого
;  «ОТМЕНА»/«НЕДОСТАТОЧНО»/«ИТОГ» приклеивались бы к последней позиции.
;
;  строка отмены: "ОТМЕНА" + добивка + сумма
PRINT_VOID:
        LCALL PR_BEGIN
        LCALL PR_NL
        MOV  DPTR, #S_VOID
        MOV  R1, #LAST
        MOV  PADN, #6
        LCALL PR_MONEY_LINE
        LCALL PR_END
        RET

;  "НЕДОСТАТОЧНО"
PRINT_SHORT:
        LCALL PR_BEGIN
        LCALL PR_NL
        MOV  DPTR, #S_SHORT
        LCALL PR_STR
        LCALL PR_END
        RET

;  подвал чека: ИТОГ / НАЛИЧНЫМИ / СДАЧА / СПАСИБО
PRINT_FOOTER:
        LCALL PR_BEGIN
        LCALL PR_NL
        MOV  DPTR, #S_ITOG
        MOV  R1, #TOTAL
        MOV  PADN, #8
        LCALL PR_MONEY_LINE
        MOV  DPTR, #S_CASH_IN
        MOV  R1, #ENTRY
        MOV  PADN, #3
        LCALL PR_MONEY_LINE
        MOV  DPTR, #S_CHANGE
        MOV  R1, #CHANGE
        MOV  PADN, #7
        LCALL PR_MONEY_LINE
        MOV  DPTR, #S_THANKS
        LCALL PR_STR
        LCALL PR_END
        RET

; ---------------------------------------------------------------------------
;  BCD-АРИФМЕТИКА (4 байта, младший байт первый)
; ---------------------------------------------------------------------------
;  BCD_SHL1: R1 *= 10 (сдвиг на одну десятичную цифру влево).
;  Перенос идёт от младшего байта к старшему: цифра, вытесненная из байта i,
;  входит в младший разряд байта i+1.
;
;  Для каждого байта:  byte = ((byte << 4) & 0xF0) | carry_in
;                      carry_out = byte >> 4
;  Легко забыть перенести старшую тетраду в следующий байт — тогда теряются
;  все старшие разряды: 5,0,0 дало бы "5000" вместо "50000", а чек напечатал
;  бы "5.00" вместо "500.00".
BCD_SHL1:
        MOV  A, R1
        MOV  R0, A                      ; младший байт
        MOV  R2, #4
        MOV  R6, #0                     ; перенос
BS_L:
        MOV  A, @R0
        MOV  R3, A                      ; исходный байт
        ANL  A, #0xF0                   ; старшая тетрада -> перенос в байт i+1
        SWAP A
        MOV  R5, A
        MOV  A, R3
        SWAP A
        ANL  A, #0xF0                   ; младшая тетрада уехала в старшую
        ORL  A, R6                      ; плюс перенос из байта i-1
        MOV  @R0, A
        MOV  A, R5
        MOV  R6, A                      ; перенос для следующего байта
        INC  R0
        DJNZ R2, BS_L
        RET

;  BCD_ADD4: R1 += R0
BCD_ADD4:
        MOV  R2, #4
        CLR  C
BA_L:
        MOV  A, @R0
        ADDC A, @R1
        DA   A
        MOV  @R1, A
        INC  R0
        INC  R1
        DJNZ R2, BA_L
        RET

;  BCD_SUB4: R1 = R1 - R0 (4 байта BCD); C=1 если заёма НЕ было (R1 >= R0).
;  Способ: NEG = 10^8 - R0 (поразрядно 9-d, затем +1 с BCD-переносом),
;  после чего R1 = R1 + NEG.  Перенос из старшего байта означает R1 >= R0.
;  Инкремент сделан без DA A: DA корректен только для "хороших" входов,
;  а здесь как раз встречается 0x99 + 1.
BCD_SUB4:
        MOV  DSPTR, R1                  ; сохранить указатель приёмника
        MOV  R1, #NEG
        MOV  R2, #4
BS_NEG:
        MOV  A, #0x99                   ; 99h - байт = поразрядное 9-d
        CLR  C
        SUBB A, @R0
        MOV  @R1, A
        INC  R0
        INC  R1
        DJNZ R2, BS_NEG
        ; --- NEG += 1 (BCD, с переносом) ---
        MOV  R1, #NEG
        MOV  R2, #4
        SETB C
BS_INC:
        MOV  A, @R1
        ADDC A, #0
        MOV  R3, A
        ANL  A, #0x0F                   ; младшая тетрада > 9 -> +6
        CLR  C
        SUBB A, #0x0A
        MOV  A, R3
        JC   BS_INC_HI
        ADD  A, #6
BS_INC_HI:
        MOV  R3, A
        ANL  A, #0xF0                   ; старшая тетрада >= A0h -> +60h
        CLR  C
        SUBB A, #0xA0
        MOV  A, R3
        JC   BS_INC_ST
        ADD  A, #0x60
        SETB C                          ; байт 99h перешёл в 00h -> перенос
        SJMP BS_INC_MV
BS_INC_ST:
        CLR  C
BS_INC_MV:
        MOV  @R1, A
        INC  R1
        DJNZ R2, BS_INC
        ; --- R1 += NEG (BCD) ---
        MOV  R1, DSPTR
        MOV  R0, #NEG
        MOV  R2, #4
        CLR  C
BSB_L:
        MOV  A, @R0
        ADDC A, @R1
        DA   A
        MOV  @R1, A
        INC  R0
        INC  R1
        DJNZ R2, BSB_L
        RET

;  BCD_COPY4: R1 = R0
BCD_COPY4:
        MOV  R2, #4
BC_L:
        MOV  A, @R0
        MOV  @R1, A
        INC  R0
        INC  R1
        DJNZ R2, BC_L
        RET

;  GETDIG: A = номер разряда 0..7, R1 = база BCD -> A = цифра
GETDIG:
        MOV  R2, A
        RRC  A
        MOV  A, R2
        CLR  C
        RRC  A                          ; A = номер байта
        ADD  A, R1
        MOV  R0, A
        MOV  A, @R0
        MOV  R3, A
        MOV  A, R2
        ANL  A, #1
        JNZ  GD_HI
        MOV  A, R3
        ANL  A, #0x0F
        RET
GD_HI:
        MOV  A, R3
        SWAP A
        ANL  A, #0x0F
        RET

; ---------------------------------------------------------------------------
;  ИНДИКАТОР
; ---------------------------------------------------------------------------
;  SET_DISPLAY: нарисовать то, что соответствует режиму, и индикатор режима.
;    режим 0 -- вводимая сумма,  1 -- итог (мигает индикатор режима),
;    режим 2 -- итог,            3 -- сдача.
SET_DISPLAY:
        MOV  A, MODE
        JZ   SD_ENTRY
        CJNE A, #3, SD_TOTAL
        MOV  R1, #CHANGE
        SJMP SD_DRAW
SD_TOTAL:
        MOV  R1, #TOTAL
        SJMP SD_DRAW
SD_ENTRY:
        MOV  R1, #ENTRY
SD_DRAW:
        MOV  R0, #(DISP_BUF+MODE_CELL+1) ; денежное поле -- знакоместа MODE_CELL+1..7
        MOV  R2, #FIELD_W
        LCALL DRAW_MONEY
        ; индикатор режима -- в свободном знакоместе 0
        MOV  A, MODE
        MOV  DPTR, #DIGIT_SEG
        MOVC A, @A+DPTR
        MOV  DISP_BUF+MODE_CELL, A
        RET

;  DRAW_MONEY: R1 = BCD, R0 = первое знакоместо поля, R2 = ширина поля.
;  Разряды 6..0 (7 цифр) выравниваются по правому краю поля: разряд 0
;  (единицы копеек) лежит на ПРАВОМ крайнем знакоместе поля, разряд 6 -- на
;  его левом крае, поэтому поле читается как "0.05", а не перевёрнуто.
;  Точка -- на знакоместе разряда единиц рублей (DIGIDX = 2), т.е. ПЕРЕД
;  копейками.  Знакоместо = (начало поля + ширина - 1) - разряд, поэтому
;  DMBASE хранит ПРАВЫЙ край поля (начало + ширина - 1), а не левый.
;  Поле затирается ЦЕЛИКОМ, поэтому вызывающая программа не обязана знать
;  ширину: SET_DISPLAY просит ровно FIELD_W знакомест начиная с
;  MODE_CELL+1, и индикатор режима (знакоместо 0) в поле не попадает.
;  Нули перед числом гасятся, копейки видны всегда.
DRAW_MONEY:
        MOV  A, R0
        ADD  A, R2
        DEC  A                           ; DMBASE = правый край = начало + ширина - 1
        MOV  DMBASE, A
        MOV  A, R2
        MOV  DMWID, A
        ; --- погасить поле целиком ---
        MOV  A, DMWID
        MOV  R2, A
        MOV  A, R0
        MOV  R0, A
        CLR  A
DM_B:
        MOV  @R0, A
        INC  R0
        DJNZ R2, DM_B
        MOV  DMWIDX, #6                 ; от старшего разряда к младшему: нули
        MOV  SIG, #0                    ; перед числом гасятся, а разряды копеек
DM_L:                                   ; (1 и 0) видны всегда
        MOV  A, DMWIDX
        LCALL GETDIG
        JNZ  DM_PR
        MOV  A, SIG
        JNZ  DM_PR
        MOV  A, DMWIDX
        CJNE A, #2, DM_NEXT             ; разряд единиц рублей виден всегда
DM_PR:
        MOV  SIG, #1
        MOV  A, DMWIDX
        LCALL GETDIG
        MOV  DPTR, #DIGIT_SEG
        MOVC A, @A+DPTR
        MOV  MASK, A
        MOV  A, DMWIDX
        CJNE A, #2, DM_NODP
        MOV  A, MASK
        ORL  A, #SEG_DP                 ; десятичная точка -- перед копейками
        MOV  MASK, A
DM_NODP:
        MOV  A, DMBASE
        CLR  C
        SUBB A, DMWIDX                  ; знакоместо = правый край поля - разряд
        MOV  R0, A
        MOV  A, MASK
        MOV  @R0, A
DM_NEXT:
        MOV  A, DMWIDX
        JZ   DM_DONE
        DEC  DMWIDX
        SJMP DM_L
DM_DONE:
        RET

; ---------------------------------------------------------------------------
;  МИГАНИЕ индикатора режима (только в режиме "подытог")
; ---------------------------------------------------------------------------
BLINK_TICK:
        INC  BLINK
        MOV  A, BLINK
        JNZ  BT_TEST
        INC  BLINK_HI
BT_TEST:
        MOV  A, MODE
        CJNE A, #1, BT_LAMP             ; мигает только в режиме "подытог"
        MOV  A, BLINK_HI
        ANL  A, #0x08
        JZ   BT_OFF
BT_LAMP:
        MOV  A, MODE
        MOV  DPTR, #DIGIT_SEG
        MOVC A, @A+DPTR
        MOV  DISP_BUF+MODE_CELL, A
        RET
BT_OFF:
        MOV  DISP_BUF+MODE_CELL, #0x00
        RET

; ===========================================================================
;  ТАБЛИЦЫ (в кодовой памяти, читаются через MOVC)
; ===========================================================================
;  Единица в разряде строки клавиатуры / знакоместа индикатора
ROW_TAB:
        DB 0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80
;  Номер первой клавиши строки (строка * 8)
ROW_BASE:
        DB 0,8,16,24,32,40,48,56
;  Сегменты цифр: биты 0..6 = a..g, бит 7 = точка ("-" = 0x40)
DIGIT_SEG:
        DB 0x3F,0x06,0x5B,0x4F,0x66,0x6D,0x7D,0x07,0x7F,0x6F
;
;  Раскладка матрицы 8x8 (строка * 8 + столбец). Согласована с hal-ppi:
;    строка 0: 7  8  9  СБРОС   ВОЗВРАТ   СКИДКА   КС        Z
;    строка 1: 4  5  6  СУММА   КАССИР    СЕРВИС   X         ЧЕК
;    строка 2: 1  2  3  ОПЛ     РЕЖИМ     ВВОД     ПИТ       ТАБ
;    строка 3: 0  00  .  ИТОГ    ПОДЫТОГ   ОТМЕНА   ПРОБЕЛ    СТРЕЛКА_ВЛЕВО
;    строка 4: СТРЕЛКА_ВПРАВО  (остальное свободно)
;  Демо использует только цифры, ".", "00" и шесть действий; остальным
;  клавишам соответствует K_NONE.
;
;  Раскладка ОБЯЗАНА совпадать с эмулятором клавиатуры
;  (board/keyboard.py + board/cashboard.py: строка = счётчик сканирования,
;  столбец = разряд прочитанного байта, активный уровень — ноль).
;  Ниже — координаты, которые действительно отдаёт board.keyboard:
;    цифры 7 8 9 / 4 5 6 / 1 2 3 лежат в столбцах 0..2, строки 0..2;
;    "0" — строка 3 столбец 0; "00" — строка 0 столбец 7; "." — строка 1 столбец 7;
;    СУММА — (0,4); ОПЛ — (0,5); ITOG — (0,6); ПОДЫТОГ — (1,6);
;    ОТМЕНА — (1,4); ВВОД — (2,6); X — (0,3); СБРОС — (2,7).
KEYMAP:
        DB 7,8,9,K_X,K_SUMM,K_PAY,K_ITOG,K_00
        DB 4,5,6,K_NONE,K_CANCEL,K_NONE,K_SUB,K_DOT
        DB 1,2,3,K_NONE,K_NONE,K_NONE,K_ENTER,K_CLEAR
        DB 0,K_NONE,K_NONE,K_NONE,K_NONE,K_NONE,K_NONE,K_NONE
        DB K_NONE,K_NONE,K_NONE,K_NONE,K_NONE,K_NONE,K_NONE,K_NONE
        DB K_NONE,K_NONE,K_NONE,K_NONE,K_NONE,K_NONE,K_NONE,K_NONE
        DB K_NONE,K_NONE,K_NONE,K_NONE,K_NONE,K_NONE,K_NONE,K_NONE
        DB K_NONE,K_NONE,K_NONE,K_NONE,K_NONE,K_NONE,K_NONE,K_NONE

; ---------------------------------------------------------------------------
;  ТЕКСТ ЧЕКА -- 7-битная транслитерация, КАК В НАСТОЯЩЕЙ ПРОШИВКЕ.
;  Русский текст в ROM хранится не KOI8-R, а немецко-подобным
;  транслитом (см. docs/rom_strings.txt и «Character encoding» в
;  board/printer.py): d->д, e->е, n->н, s->с, h->х, ~->ч, }->щ, ...
;  Плата (board/printer.py ENCODE_TABLE) декодирует эти байты обратно
;  в кириллицу, поэтому printer.text() отдаёт «ИТОГ», «НАЛИЧНЫМИ»,
;  «СДАЧА», «ДЕМО-ПРОГРАММА».  Формулировки взяты по смыслу из
;  docs/rom_strings.txt: itog / nali~nymi / sda~a / spasibo.
;  Одна форма регистра на шесть букв (ч ш ъ э ю ж) -- свойство
;  однобайтовой таблицы, его же фиксирует test_board:
;  test_transliteration_round_trip сравнивает через .upper().
; ---------------------------------------------------------------------------
S_HEAD:     DB 0x0A,"   kassa 'tim",0x0A,0
S_DEMO:     DB " demo-programma",0x0A,0
S_NOTE:     DB " (ne original!)",0x0A,0
S_RULE:     DB "--------------------",0x0A,0
S_ID:       DB "id=",0
S_CASH:     DB "  kassir 01",0x0A,0
S_DATE:     DB "data --.--.--",0x0A,0
S_VOID:     DB "otmena",0
S_ITOG:     DB "itog",0
S_CASH_IN:  DB "nali~nymi",0
S_CHANGE:   DB "sda~a",0
S_THANKS:   DB "  spasibo za pokupku",0x0A,0x0A,0
S_SHORT:    DB "nedostato~no",0x0A,0

        END
