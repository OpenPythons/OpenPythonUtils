#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(non_snake_case)]
#![allow(unused_must_use)]
#![allow(unused_variables)]

use consts::*;
use builder::Instruction;
use memory::Content;
use memory::Memory;
use std::io::prelude::*;

pub fn insnx2(op: u8, rd: usize, imm32: i32) -> (i32, i32) {
    (op as i32 | ((rd as i32) << 8), imm32)
}

pub fn insnx1(op: u8, imm32: i32) -> (i32, i32) {
    (op as i32, imm32)
}

pub fn insni3(op: u8, rd: usize, rs: usize, imm16: i16) -> (i32, i32) {
    (op as i32 | ((rd as i32) << 8) | ((rs as i32) << 12) | ((imm16 as i32) << 16), 0)
}

pub fn insni2(op: u8, rd: usize, imm16: i16) -> (i32, i32) {
    (op as i32 | ((rd as i32) << 8) | ((imm16 as i32) << 16), 0)
}

pub fn insni1(op: u8, imm16: i16) -> (i32, i32) {
    (op as i32 | ((imm16 as i32) << 16), 0)
}

pub fn insn3(op: u8, rd: usize, rs: usize, rn: usize) -> (i32, i32) {
    (op as i32 | ((rd as i32) << 8) | ((rs as i32) << 12) | ((rn as i32) << 16), 0)
}

pub fn insn2(op: u8, rd: usize, rs: usize) -> (i32, i32) {
    (op as i32 | ((rd as i32) << 8) | ((rs as i32) << 12), 0)
}

pub fn insn1(op: u8, rd: usize) -> (i32, i32) {
    (op as i32 | ((rd as i32) << 8), 0)
}

pub fn insn0(op: u8) -> (i32, i32) {
    (op as i32, 0)
}

fn name(op: i32) -> &'static str {
    return match op as u8 {
        LSLSI => { "LSLSI" }
        LSRSI => { "LSRSI" }
        ASRSI => { "ASRSI" }
        ADD3S => { "ADD3S" }
        ADD3SI => { "ADD3SI" }
        SUB3S => { "SUB3S" }
        SUB3SI => { "SUB3SI" }
        MOVSI => { "MOVSI" }
        CMPI => { "CMPI" }
        ADDSI => { "ADDSI" }
        SUBSI => { "SUBSI" }
        ANDS => { "ANDS" }
        EORS => { "EORS" }
        LSLS => { "LSLS" }
        LSRS => { "LSRS" }
        ASRS => { "ASRS" }
        ADCS => { "ADCS" }
        SBCS => { "SBCS" }
        RORS => { "RORS" }
        TSTS => { "TSTS" }
        RSBS => { "RSBS" }
        CMP => { "CMP" }
        CMN => { "CMN" }
        ORRS => { "ORRS" }
        MULS => { "MULS" }
        BICS => { "BICS" }
        MVNS => { "MVNS" }
        ADD => { "ADD" }
        ADDX => { "ADDX" }
        CMPX => { "CMPX" }
        MOV => { "MOV" }
        MOVX => { "MOVX" }
        BX => { "BX" }
        BLX => { "BLX" }
        MOVI => { "MOVI" }
        STR => { "STR" }
        STRB => { "STRB" }
        LDR => { "LDR" }
        LDRB => { "LDRB" }
        STRH => { "STRH" }
        LDRH => { "LDRH" }
        LDSB => { "LDSB" }
        LDSH => { "LDSH" }
        STRI => { "STRI" }
        STRBI => { "STRBI" }
        LDRI => { "LDRI" }
        LDRBI => { "LDRBI" }
        STRHI => { "STRHI" }
        LDRHI => { "LDRHI" }
        STRSPI => { "STRSPI" }
        LDRSPI => { "LDRSPI" }
        ADDXI => { "ADDXI" }
        ADDSPI => { "ADDSPI" }
        PUSH => { "PUSH" }
        PUSHR => { "PUSHR" }
        POP => { "POP" }
        POPR => { "POPR" }
        STMIA => { "STMIA" }
        LDMIA => { "LDMIA" }
        BEQ => { "BEQ" }
        BNE => { "BNE" }
        BCS => { "BCS" }
        BCC => { "BCC" }
        BMI => { "BMI" }
        BPL => { "BPL" }
        BVS => { "BVS" }
        BVC => { "BVC" }
        BHI => { "BHI" }
        BLS => { "BLS" }
        BGE => { "BGE" }
        BLT => { "BLT" }
        BGT => { "BGT" }
        BLE => { "BLE" }
        SVC => { "SVC" }
        B => { "B" }
        BL => { "BL" }
        SXTH => { "SXTH" }
        SXTB => { "SXTB" }
        UXTH => { "UXTH" }
        UXTB => { "UXTB" }
        REV => { "REV" }
        ERROR => { "ERROR" }
        _ => { "UNKNOWN" }
    }
}

pub fn show(code: i32, imm32: i32) {
    let op = code & 0xFF;
    let rd = (code >> 8) & 0b1111;
    let rs = (code >> 12) & 0b1111;
    let rn = (code >> 16) & 0b1111;
    let imm16 = code >> 16;
    println!("{}\tRd={}\tRs={}\tRn={}\timm16={}\timm32={}", name(op), rd, rs, rn, imm16, imm32);
}

pub fn show_insn(insn: &Instruction) {
    println!("{}\tRd={}\tRs={}\tRn={}\timm16={}\timm32={}", name(insn.op as i32), insn.Rd, insn.Rs, insn.Rn, insn.imm16, insn.imm32);
}


pub fn decode(memory: &mut Memory, pc: i32) -> (i32, i32) {
    let code = memory.read_u16(pc as u32);

    return match code >> 12 & L4 {
        0 | 1 => { // :000x
            let Rs = (code >> 3 & L3) as usize;
            let Rd = (code & L3) as usize;

            match code >> 11 & L2 { // move shifted register
                0 => { // :00000 ; LSL Rd, Rs, #Offset5
                    let offset = code >> 6 & L5; // 0 ~ 31
                    insni3(LSLSI, Rd, Rs, offset as i16)
                }
                1 => { // :00001 ; LSR Rd, Rs, #Offset5
                    let offset = code >> 6 & L5; // 1 ~ 32
                    insni3(LSRSI, Rd, Rs, if offset != 0 { offset as i16 } else { 32 })
                }
                2 => { // :00010 ; ASR Rd, Rs, #Offset5
                    let offset = code >> 6 & L5; // 1 ~ 32
                    insni3(ASRSI, Rd, Rs, if offset != 0 { offset as i16 } else { 32 })
                }
                3 => { // :00011 ; add/subtract
                    let I = code >> 10 & 1 != 0;
                    let Rn = (code >> 6 & L3) as usize;

                    match code >> 9 & L1 {
                        0 => {
                            if I {
                                insni3(ADD3SI, Rd, Rs, Rn as i16) // :0001110 ; ADD Rd, Rs, #Offset3
                            } else {
                                insn3(ADD3S, Rd, Rs, Rn) // :0001100 ; ADD Rd, Rs, Rn
                            }
                        }
                        1 => {
                            if I {
                                insni3(SUB3SI, Rd, Rs, Rn as i16) // :0001111 ; SUB Rd, Rs, #Offset3
                            } else {
                                insn3(SUB3S, Rd, Rs, Rn) // :0001101 ; SUB Rd, Rs, Rn
                            }
                        }
                        _ => { panic!(); }
                    }
                }
                _ => { panic!(); }
            }
        }
        2 | 3 => { // :001 ; move/compare/add/subtract immediate
            let Rd = (code >> 8 & L3) as usize;
            let offset8 = (code & L8) as i16;

            let op = match code >> 11 & L2 {
                0 => { MOVSI } // :001100 ; MOV Rd, #Offset8
                1 => { CMPI } // :001101 ; CMP Rd, #Offset8
                2 => { ADDSI } // :001110 ; ADD Rd, #Offset8
                3 => { SUBSI } // :001111 ; SUB Rd, #Offset8
                _ => { panic!(); }
            };

            insni2(op, Rd, offset8)
        }
        4 => // :0100
            match code >> 10 & L2 {
                0 => { // :010000 ; ALU operations
                    let Rs = (code >> 3 & L3) as usize;
                    let Rd = (code & L3) as usize;
                    let op = match code >> 6 & L4 {
                        0 => { ANDS }  // :0100000000 ; & Rd, Rs ; Rd:= Rd & Rs
                        1 => { EORS }  // :0100000001 ; EOR Rd, Rs ; Rd:= Rd EOR Rs
                        2 => { LSLS }  // :0100000010 ; LSL Rd, Rs ; Rd := Rd << Rs
                        3 => { LSRS }  // :0100000011 ; LSR Rd, Rs ; Rd := Rd >>> Rs
                        4 => { ASRS }  // :0100000100 ; ASR Rd, Rs ; Rd := Rd ASR Rs
                        5 => { ADCS }  // :0100000101 ; ADC Rd, Rs ; Rd := Rd + Rs + C-bit
                        6 => { SBCS }  // :0100000110 ; SBC Rd, Rs ; Rd := Rd - Rs - NOT C-bit
                        7 => { RORS }  // :0100000111 ; ROR Rd, Rs ; Rd := Rd ROR Rs
                        8 => { TSTS }  // :0100001000 ; TST Rd, Rs ; set condition codes on Rd & Rs
                        9 => { RSBS }  // :0100001001 ; NEG Rd, Rs ; Rd = -Rs
                        10 => { CMP }  // :0100001010 ; CMP Rd, Rs ; set condition codes on Rd - Rs
                        11 => { CMN }  // :0100001011 ; CMN Rd, Rs ; set condition codes on Rd + Rs
                        12 => { ORRS }  // :0100001100 ; ORR Rd, Rs ; Rd := Rd OR Rs
                        13 => { MULS }  // :0100001101 ; MUL Rd, Rs ; Rd := Rs * Rd
                        14 => { BICS }  // :0100001110 ; BIC Rd, Rs ; Rd := Rd & NOT Rs
                        15 => { MVNS }  // :0100001111 ; MVN Rd, Rs ; Rd := NOT Rs
                        _ => { panic!(); }
                    };

                    insn2(op, Rd, Rs)
                }
                1 => { // :010001 ; Hi register operations/branch exchange
                    let H1 = code >> 7 & L1 != 0;
                    let H2 = code >> 6 & L1 != 0;
                    let Rd = ((code & L3) + if H1 { 8 } else { 0 }) as usize;
                    let Rs = ((code >> 3 & L3) + if H2 { 8 } else { 0 }) as usize;
                    let mut op = match code >> 8 & L2 {
                        0 => { ADD } // :01000100 ; ADD Rd, Hs ; ADD Hd, Rs ; ADD Hd, Hs
                        1 => { CMP } // :01000101 ; CMP Rd, Hs ; CMP Hd, Rs ; CMP Hd, Hs
                        2 => { MOV } // :01000110 ; MOV Rd, Hs ; MOV Hd, Rs ; MOV Hd, Hs
                        3 => if H1 { BLX } else { BX } // :01000111 ; BX Rs ; BX Hs
                        _ => { panic!(); }
                    };

                    let is_special_regs =
                        match Rd as usize {
                            PC | SP | LR => { true }
                            _ => { false }
                        } || match Rs as usize {
                            PC | SP | LR => { true }
                            _ => { false }
                        };

                    if is_special_regs {
                        op = match op {
                            ADD => { ADDX }
                            CMP => { CMPX }
                            MOV => { MOVX }
                            _ => { op }
                        }
                    }

                    match op {
                        ADD | CMP | MOV => { insn2(op, Rd, Rs) }
                        ADDX | CMPX | MOVX => { insn2(op, Rd, Rs) }
                        BX => { insn2(op, 0, Rs) }
                        BLX => { insn2(op, 0, Rs) }
                        _ => { panic!(); }
                    }
                }
                2 | 3 => { // :01001 ; PC-relative load ; LDR Rd, [PC, #Imm]
                    let Rd = (code >> 8 & L3) as usize;
                    let mut addr = ((code & L8) << 2) as i32;
                    addr += pc + 4 & !(I1 as i32);
                    let value = memory.read_i32(addr as u32);

                    insnx2(MOVI, Rd, value)
                }
                _ => { panic!(); }
            }
        5 => { // :0101
            if code & I9 == 0 { // :0101xx0 ; load/store with register offset
                let L = code & I11 != 0;
                let fB = code & I10 != 0;
                let Ro = (code >> 6 & L3) as usize;
                let Rb = (code >> 3 & L3) as usize;
                let Rd = (code & L3) as usize;
                let op = match (L, fB) {
                    (true, false) => { LDR } // :0101100 ; LDR Rd, [Rb, Ro]
                    (true, true) => { LDRB } // :0101100 ; LDRB Rd, [Rb, Ro]
                    (false, false) => { STR } // :0101000 ; STR Rd, [Rb, Ro]
                    (false, true) => { STRB } // :0101010 ; STRB Rd, [Rb, Ro]
                };

                insn3(op, Rd, Rb, Ro)
            } else { // :0101xx1 ; load/store sign-extended byte/halfword
                let H = code & I11 != 0;
                let S = code & I10 != 0;
                let Ro = (code >> 6 & L3) as usize;
                let Rb = (code >> 3 & L3) as usize;
                let Rd = (code & L3) as usize;
                let op = match (S, H) {
                    (true, true) => { LDSH } // :0101111 ; LDSH Rd, [Rb, Ro]
                    (true, false) => { LDRB } // :0101011 ; LDSB Rd, [Rb, Ro]
                    (false, true) => { LDRH } // :0101101 ; LDRH Rd, [Rb, Ro]
                    (false, false) => { STRH } // :0101001 ; STRH Rd, [Rb, Ro]
                };

                insn3(op, Rd, Rb, Ro)
            }
        }
        6 | 7 => { // :011 ; load/store with immediate offset
            let fB = code & I12 != 0;
            let L = code & I11 != 0;
            let Rb = (code >> 3 & L3) as usize;
            let Rd = (code & L3) as usize;
            let mut offset = (code >> 6 & L5) as i16;

            if !fB {
                offset = offset << 2;
            }

            let op = match (L, fB) {
                (true, false) => { LDRI } // :01111 ; LDR Rd, [Rb, #Imm]
                (true, true) => { LDRBI } // :01101 ; LDRB Rd, [Rb, #Imm]
                (false, false) => { STRI } // :01100 ; STR Rd, [Rb, #Imm]
                (false, true) => { STRBI } // :01110 ; STRB Rd, [Rb, #Imm]
            };

            insni3(op, Rd, Rb, offset)
        }
        8 => { // :1000x ; load/store halfword
            let L = code & I11 != 0;
            let Rb = (code >> 3 & L3) as usize;
            let Rd = (code & L3) as usize;
            let offset = (((code >> 6) & L5) << 1) as i16;
            let op = if L {
                LDRHI  // :10001 ; LDRH Rd, [Rb, #Imm]
            } else {
                STRHI  // :10000 ; STRH Rd, [Rb, #Imm]
            };

            insni3(op, Rd, Rb, offset)
        }
        9 => { // :1001x ; SP-relative load/store
            let L = code & I11 != 0;
            let Rd = (code >> 8 & L3) as usize;
            let offset = ((code & L8) << 2) as i16;
            let op = if L {
                LDRSPI // :10011 ; LDR Rd, [SP, #Imm]
            } else {
                STRSPI // :10010 ; STR Rd, [SP, #Imm]
            };

            insni3(op, Rd, SP, offset)
        }
        10 => { // :1010x ; load address
            let fSP = code & I11 != 0;
            let Rd = (code >> 8 & L3) as usize;
            let value = ((code & L8) << 2) as i16;

            if fSP {
                insni3(ADDXI, Rd, SP, value)
            } else {
                insni3(ADDXI, Rd, PC, value) // from PC
            }
        }
        11 => { // :1011
            match code >> 8 & L4 {
                0 => { // :10110000x ; add offset to Stack Pointer
                    let S = code & I7 != 0;
                    let mut value = ((code & L7) << 2) as i16;

                    if S { // :101100000 ; ADD SP, #-Imm
                        value = -value;
                    }

                    // :101100001 ; ADD SP, #Imm
                    insni1(ADDSPI, value)
                }
                1 => { insnx1(ERROR, code as i32) } // :10110001 ; CBZ Rd, #Imm
                2 => { // :10110010 ; SXTH, SXTB, UXTH, UXTB
                    let Rs = (code >> 3 & L3) as usize;
                    let Rd = (code & L3) as usize;

                    let op = match code >> 6 & L2 {
                        0 => { SXTH } // :1011001000 ; SXTH Rd, Rs
                        1 => { SXTB } // :1011001001 ; SXTB Rd, Rs
                        2 => { UXTH } // :1011001010 ; UXTH Rd, Rs
                        3 => { UXTB } // :1011001011 ; UXTB Rd, Rs
                        _ => { panic!(); }
                    };

                    insn2(op, Rd, Rs)
                }
                3 => { insnx1(ERROR, code as i32) } // :10110011 ; CBZ Rd, #Imm
                4 | 5 => { // :1011010x ; push/pop registers
                    let R = code & I8 != 0;
                    let list = (code & L8) as i16;

                    if R {
                        insni1(PUSHR, list) // :10110101 ; PUSH { ..., LR }
                    } else {
                        insni1(PUSH, list) // :10110100 ; PUSH { ... }
                    }
                }
                6 | 7 | 8 => { insnx1(ERROR, code as i32) } // :10110110 :10110111 :10111000
                9 => { insnx1(ERROR, code as i32) } // :10111001 ; CBNZ Rd, #Imm
                10 => { // :10111010xx
                    let Rs = (code >> 3 & L3) as usize;
                    let Rd = (code & L3) as usize;

                    let op = match code >> 6 & L2 {
                        0 => { REV } // :1011101000 ; REV Rd, Rs
                        1 => { ERROR } // :1011101001 ; REV16 Rd, Rs
                        2 => { ERROR } // :1011101010 ; INVALID
                        3 => { ERROR } // :1011101011 ; REVSH Rd, Rs
                        _ => { panic!(); }
                    };

                    if op == ERROR {
                        insnx1(ERROR, code as i32)
                    } else {
                        insn2(op, Rd, Rs)
                    }
                }
                11 => { insnx1(ERROR, code as i32) } // :10111011 ; CBNZ Rd, #Imm
                12 | 13 => { // :1011110x ; push/pop registers
                    let fR = code & I8 != 0;
                    let list = (code & L8) as i16;

                    if fR {
                        insni1(POPR, list) // :10110101 ; PUSH { ..., LR }
                    } else {
                        insni1(POP, list) // :10110100 ; PUSH { ... }
                    }
                }
                14 | 15 => { insnx1(ERROR, code as i32) } // :10111110 :10111111
                _ => { panic!(); }
            }
        }
        12 => { // :1100 ; multiple load/store
            let L = code & I11 != 0;
            let list = (code & L8) as i16;
            let Rb = (code >> 8 & L3) as usize;

            if !L {
                insni2(STMIA, Rb, list) // :11001 ; STMIA Rb!, { Rlist }
            } else {
                insni2(LDMIA, Rb, list) // :11000 ; LDMIA Rb!, { Rlist }
            }
        }
        13 => { // :1101 ; conditional branch (or software interrupt);
            let soffset = (code & L8) as i8;
            let op = match code >> 8 & L4 {
                0 => { BEQ } // :11010000 ; BEQ label
                1 => { BNE } // :11010001 ; BNE label
                2 => { BCS } // :11010010 ; BCS label
                3 => { BCC } // :11010011; BCC label
                4 => { BMI } // :11010100 ; BMI label
                5 => { BPL } // :11010101 ; BPL label
                6 => { BVS } // :11010110 ; BVS label
                7 => { BVC } // :11010111 ; BVC label
                8 => { BHI } // :11011000 ; BHI label
                9 => { BLS } // :11011001 ; BLS label
                10 => { BGE } // :11011010 ; BGE label ; (n && v) || (!n && !v);
                11 => { BLT } // :11011011 ; BLT label ; (n && !v) || (!n && v);
                12 => { BGT } // :11011100 ; BGT label ; !z && (n && v || !n && !v);
                13 => { BLE } // :11011101 ; BLE label ; z || (n && !v) || (!n && v);
                14 => { ERROR } // :11011110
                15 => { SVC } // :11011111 ; software interrupt
                _ => { panic!(); }
            };

            match op {
                ERROR => {
                    insnx1(ERROR, code as i32)
                }
                SVC => {
                    insni1(op, soffset as usize as i16)
                }
                _ => {
                    let mut value = (soffset as i16) << 1;
                    if value & (I8 as i16) != 0 {
                        value = value | !(L8 as i16);
                    }

                    let offset = 4 + value;
                    insni1(op, offset)
                }
            }
        }
        14 => { // :11100 ; unconditional branch
            if code & I11 != 0 {
                insnx1(ERROR, code as i32)
            } else {
                let mut value = ((code & L10) as i16) << 1;
                if code & I10 != 0 {
                    value = value | !(L11 as i16);
                }

                let offset = 4 + value;
                insni1(B, offset)
            }
        }
        15 => { // :1111 ; long branch with link
            let H1 = code >> 11 & L1 != 0;
            let value1 = (code & L11) as i32;

            if !H1 {
                let otherCode = memory.read_u16(pc as u32 + 2);
                let H2 = otherCode >> 11 & L1 != 0;
                let value2 = (otherCode & L11) as i32;

                if !H1 && H2 {
                    let mut addr = (value1 << 12) | (value2 << 1);
                    if addr & (1 << 22) != 0 {
                        addr = addr | !8388607;
                    }

                    addr += 2;
                    insnx1(BL, addr)
                } else {
                    insnx1(ERROR, code as i32)
                }
            } else {
                insnx1(ERROR, code as i32)
            }
        }
        _ => { panic!(); }
    };
}
