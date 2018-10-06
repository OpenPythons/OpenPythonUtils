#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(non_snake_case)]
#![allow(unused_must_use)]
#![allow(unused_variables)]
#![allow(unreachable_code)]

use builder::CPU;
use builder::FIRMWARE_ADDRESS;
use builder::Instruction;
use consts::*;
use memory::Content;
use memory::Memory;

//noinspection RsVariableNaming
pub fn execute(cpu: &mut CPU) {
    let regs: &mut Vec<i32> = &mut cpu.regs;
    let memory: &mut Memory = &mut cpu.memory;
    let cache: &Vec<Instruction> = &mut cpu.cache2;

    let mut lr = regs[LR];
    let mut sp = regs[SP];
    let mut pc = regs[PC];
    let cpsr = regs[CPSR];
    let mut v = (regs[CPSR] & FV) != 0;
    let mut c = (regs[CPSR] & FC) != 0;
    let mut z = (regs[CPSR] & FZ) != 0;
    let mut n = (regs[CPSR] & FN) != 0;
    let base = FIRMWARE_ADDRESS as usize;

    loop {
        let code = &cache[(pc as usize - base) >> 1];

        match code.op {
            NULL => {
                panic!("NULL");
                /*
                let (newCode, newImm32) = decode(memory, pc)
                when (newCode & 0xFF) {
                    NULL => throw UnexceptedLogicError()
                }

                buffer[pc - base] = newCode
                buffer[pc - base + 1] = newImm32
                continue
                */
            }
            NOP => { pc += 2; }
            ERROR => { panic!("throw UnknownInstructionException()"); }
            // Format 1: move shifted register
            LSLSI => { // LSL Rd, Rs, #Offset5
                let left = regs[code.Rs];
                let right = code.imm16; // 0 ~ 31
                let value = left << right;

                n = value < 0;
                z = value == 0;
                if right > 0 {
                    c = (left << right - 1) & FN != 0;
                }

                regs[code.Rd] = value;
                pc += 2;
            }
            LSRSI => { // LSR Rd, Rs, #Offset5
                let left = regs[code.Rs];
                let right = code.imm16; // 1 ~ 32
                let value = if right == 32 {
                    c = left & FN != 0;
                    0
                } else {
                    c = left & (1 << right - 1) != 0;
                    ((left as u32) >> right) as i32
                };

                regs[code.Rd] = value;
                n = value < 0;
                z = value == 0;
                pc += 2;
            }
            ASRSI => { // ASR Rd, Rs, #Offset5
                let left = regs[code.Rs];
                let right = code.imm16; // 1 ~ 32
                let value = if right == 32 {
                    c = left & FN != 0;
                    if left > 0 { 0 } else { -1 }
                } else {
                    c = left & (1 << right - 1) != 0;
                    left >> right
                };

                regs[code.Rd] = value;
                n = value < 0;
                z = value == 0;
                pc += 2;
            }

            // Format 2: add/subtract
            ADD3S => { // ADD Rd, Rs, Rn
                let left = regs[code.Rs];
                let right = regs[code.Rn];
                let Lleft = left as u32 as u64;
                let Lright = right as u32 as u64;
                let Lvalue = Lleft + Lright;
                let value = Lvalue as i32;
                n = value < 0;
                z = value == 0;
                c = Lvalue > UINT_MAX;
                v = (left ^ value) & (right ^ value) < 0;
                regs[code.Rd] = value;
                pc += 2;
            }
            ADD3SI => { // ADD Rd, Rs, #Offset3
                let left = regs[code.Rs];
                let right = code.imm16;
                let Lleft = left as u32 as u64;
                let Lright = right as u32 as u64;
                let Lvalue = Lleft + Lright;
                let value = Lvalue as i32;
                n = value < 0;
                z = value == 0;
                c = Lvalue > UINT_MAX;
                v = (left ^ value) & (right ^ value) < 0;
                regs[code.Rd] = value;
                pc += 2;
            }
            SUB3S => { // SUB Rd, Rs, Rn
                let left = regs[code.Rs];
                let right = regs[code.Rn];
                let Lleft = left as u32 as u64;
                let LIright = (!right) as u32 as u64;
                let Lvalue = Lleft + LIright + 1;
                let value = Lvalue as i32;
                n = value < 0;
                z = value == 0;
                c = Lvalue > UINT_MAX;
                v = (left ^ right) & (left ^ value) < 0;
                regs[code.Rd] = value;
                pc += 2;
            }
            SUB3SI => { // SUB Rd, Rs, #Offset3
                let left = regs[code.Rs];
                let right = code.imm16;
                let Lleft = left as u32 as u64;
                let LIright = (!right) as u32 as u64;
                let Lvalue = Lleft + LIright + 1;
                let value = Lvalue as i32;
                n = value < 0;
                z = value == 0;
                c = Lvalue > UINT_MAX;
                v = (left ^ right) & (left ^ value) < 0;
                regs[code.Rd] = value;
                pc += 2;
            }

            // Format 3: move/compare/add/subtract immediate
            MOVSI => { // MOV Rd, #Offset8
                let value = code.imm16;
                regs[code.Rd] = value;
                n = value < 0;
                z = value == 0;
                pc += 2;
            }
            CMPI => { // CMP Rd, #Offset8
                let left = regs[code.Rd];
                let right = code.imm16;
                let Lvalue = (left as u32 as u64).wrapping_add(!right as u32 as u64).wrapping_add(1);
                let value = Lvalue as i32;

                n = value < 0;
                z = value == 0;
                c = Lvalue > UINT_MAX;
                v = (left ^ right) & (left ^ value) < 0;
                pc += 2;
            }
            ADDSI => { // ADD Rd, #Offset8
                let left = regs[code.Rd];
                let right = code.imm16;
                let Lvalue = (left as u32 as u64).wrapping_add(right as u32 as u64);
                let value = Lvalue as i32;
                regs[code.Rd] = value;
                n = value < 0;
                z = value == 0;
                c = Lvalue > UINT_MAX;
                v = (left ^ value) & (right ^ value) < 0;
                pc += 2;
            }
            SUBSI => { // SUB Rd, #Offset8
                let left = regs[code.Rd];
                let right = code.imm16;
                let Lvalue = (left as u32 as u64).wrapping_add((!right) as u32 as u64).wrapping_add(1);
                let value = Lvalue as i32;
                regs[code.Rd] = value;
                n = value < 0;
                z = value == 0;
                c = Lvalue > UINT_MAX;
                v = (left ^ right) & (left ^ value) < 0;
                pc += 2;
            }

            // Format 4: ALU operations
            ANDS => { // AND Rd, Rs
                let left = regs[code.Rd];
                let right = regs[code.Rs];
                let value = left & right;

                regs[code.Rd] = value;

                n = value < 0;
                z = value == 0;
                pc += 2;
            }
            EORS => { // EOR Rd, Rs
                let left = regs[code.Rd];
                let right = regs[code.Rs];
                let value = left ^ right;

                regs[code.Rd] = value;

                n = value < 0;
                z = value == 0;
                pc += 2;
            }
            LSLS => { // LSL Rd, Rs
                let left = regs[code.Rd];
                let right = regs[code.Rs];
                let value = if right >= 32 {
                    c = right == 32 && left & 1 != 0;
                    0
                } else if right < 0 {
                    c = false;
                    0
                } else if right == 0 {
                    left
                } else {
                    c = left << right - 1 & FN != 0;
                    left << right
                };

                regs[code.Rd] = value;

                n = value < 0;
                z = value == 0;
                pc += 2;
            }
            LSRS => { // LSR Rd, Rs
                let left = regs[code.Rd];
                let right = regs[code.Rs];
                let mut value: i32;

                if right >= 32 {
                    value = 0;
                    c = right == 32 && left & FN != 0;
                } else if right < 0 {
                    value = 0;
                    c = false;
                } else if right == 0 {
                    value = left
                } else {
                    value = ((left as u32) >> right) as i32;
                    c = ((left as u32) >> (right - 1)) & 1 != 0;
                }

                regs[code.Rd] = value;

                n = value < 0;
                z = value == 0;
                pc += 2;
            }
            ASRS => { // ASR Rd, Rs
                let left = regs[code.Rd];
                let right = regs[code.Rs];
                let mut value: i32;

                if right < 0 || right >= 32 {
                    value = if left > 0 { 0 } else { -1 };
                    c = value < 0;
                } else if right == 0 {
                    value = left;
                } else {
                    value = left >> right;
                    regs[code.Rd] = value;
                    c = left & (1 << right - 1) != 0;
                }

                regs[code.Rd] = value;

                n = value < 0;
                z = value == 0;
                pc += 2;
            }
            ADCS => { // ADC Rd, Rs
                let left = regs[code.Rd];
                let right = regs[code.Rs];
                let Lvalue = (left as u32 as u64) + (right as u32 as u64) + if c { 1 } else { 0 };
                let value = Lvalue as i32;

                regs[code.Rd] = value;

                n = value < 0;
                z = value == 0;
                c = Lvalue != (value as u32 as u64);
                v = left > 0 && right > 0 && value < 0 || left < 0 && right < 0 && value > 0;
                pc += 2;
            }
            SBCS => { // SBC Rd, Rs
                let left = regs[code.Rd];
                let right = regs[code.Rs];
                let Lvalue = (left as i64).wrapping_sub(right as i64).wrapping_sub(if c { 0 } else { 1 });
                let value = left.wrapping_sub(right).wrapping_sub(if c {0} else {1});

                regs[code.Rd] = value;

                n = value < 0;
                z = value == 0;
                c = c || value < 0;
                v = Lvalue != (value as i64);
                pc += 2;
            }
            RORS => { // ROR Rd, Rs
                let left = regs[code.Rd];
                let mut right = regs[code.Rs];

                right = right & 31;
                let value = (((left as u32) >> right) as i32) | (left << 32 - right);

                regs[code.Rd] = value;

                n = value < 0;
                z = value == 0;
                c = ((left as u32) >> (right - 1)) & (I0 as u32) != 0;
                pc += 2;
            }
            TSTS => { // TST Rd, Rs
                let left = regs[code.Rd];
                let right = regs[code.Rs];

                let value = left & right;

                n = value < 0;
                z = value == 0;
                pc += 2;
            }
            RSBS => { // NEG Rd, Rs
                let right = regs[code.Rs];
                let Lvalue = (!right as u32 as u64) + 1;
                let value = Lvalue as i32;

                regs[code.Rd] = value;

                n = value < 0;
                z = value == 0;
                c = Lvalue > UINT_MAX;
                v = right & value < 0;
                pc += 2;
            }
            CMP => { // CMP Rd, Rs
                let left = regs[code.Rd];
                let right = regs[code.Rs];
                let Lvalue = (left as u32 as u64).wrapping_add(!right as u32 as u64).wrapping_add(1);
                let value = Lvalue as i32;

                n = value < 0;
                z = value == 0;
                c = Lvalue > UINT_MAX;
                v = (left ^ right) & (left ^ value) < 0;
                pc += 2;
            }
            CMN => { // CMN Rd, Rs
                let left = regs[code.Rd];
                let right = regs[code.Rs];
                let Lvalue = (left as u32 as u64) + (right as u32 as u64);
                let value = Lvalue as i32;

                n = value < 0;
                z = value == 0;
                c = Lvalue > UINT_MAX;
                v = left ^ value & (right ^ value) < 0;
                pc += 2;
            }
            ORRS => { // ORR Rd, Rs
                let left = regs[code.Rd];
                let right = regs[code.Rs];
                let value = left | right;

                regs[code.Rd] = value;

                n = value < 0;
                z = value == 0;
                pc += 2;
            }
            MULS => { // MUL Rd, Rs
                let left = regs[code.Rd];
                let right = regs[code.Rs];
                let svalue = (left as i64) * right as i64;
                let value = left * right;

                regs[code.Rd] = value;

                n = value < 0;
                z = value == 0;
                c = c | ((value as i64) != svalue);// ???
                v = false;// svalue != value?
                pc += 2;
            }
            BICS => { // BIC Rd, Rs
                let left = regs[code.Rd];
                let right = regs[code.Rs];
                let value = left & !right;

                regs[code.Rd] = value;

                n = value < 0;
                z = value == 0;
                pc += 2;
            }
            MVNS => { // MVN Rd, Rs
                let right = regs[code.Rs];
                let value = !right;

                regs[code.Rd] = value;

                n = value < 0;
                z = value == 0;
                pc += 2;
            }

            // Format 5: Hi register operations/branch exchange
            ADD => { // ADD Rd, Rs
                let left = regs[code.Rd];
                let right = regs[code.Rs];

                let value = left + right;

                regs[code.Rd] = value;

                pc += 2;
            }
            ADDX => { // ADD Rd, Rs (SP, LR, PC)
                let left = match code.Rd {
                    SP => { sp }
                    LR => { lr }
                    PC => { pc }
                    _ => { regs[code.Rd] }
                };

                let right = match code.Rs {
                    SP => { sp }
                    LR => { lr }
                    PC => { pc + 4 }
                    _ => { regs[code.Rs] }
                };

                let value = left + right;

                match code.Rd {
                    SP => {
                        sp = value;
                        pc += 2;
                    }
                    LR => {
                        lr = value;
                        pc += 2;
                    }
                    PC => {
                        pc = value;
                        pc += 2;// ?
                    }
                    _ => {
                        regs[code.Rd] = value;
                        pc += 2;
                    }
                }
            }
            CMPX => { // CMP Rd, Rs (SP, LR, PC)
                let left = regs[code.Rd];
                let right = regs[code.Rs];
                let Lvalue = (left as u32 as u64) + (!(right as u32 as u64)) + 1;
                let value = Lvalue as i32;

                n = value < 0;
                z = value == 0;
                c = Lvalue > UINT_MAX;
                v = left ^ right & (left ^ value) < 0;
                pc += 2;
            }
            MOV => { // MOV Rd, Rs
                regs[code.Rd] = regs[code.Rs];
                pc += 2;
            }
            MOVX => { // MOV Rd, Rs (SP, LR, PC)
                let value = match code.Rs {
                    SP => { sp }
                    LR => { lr }
                    PC => { pc }
                    _ => { regs[code.Rs] }
                };

                match code.Rd {
                    SP => {
                        sp = value;
                        pc += 2;
                    }
                    LR => {
                        lr = value;
                        pc += 2;
                    }
                    PC => {
                        pc = value;
                    }
                    _ => {
                        regs[code.Rd] = value;
                        pc += 2;
                    }
                }
            }

            BX => { // BX Rs
                let value = match code.Rs {
                    SP => { sp }
                    LR => { lr }
                    PC => { pc }
                    _ => { regs[code.Rs] }
                };

                if value & (I0 as i32) != 1 {
                    panic!("throw UnknownInstructionException();");
                }

                if code.Rd != 0 {
                    panic!("throw UnknownInstructionException();")
                }

                pc = value & !(I0 as i32);
            }
            BLX => { // BLX Rs
                let value = match code.Rs {
                    SP => { sp }
                    LR => { lr }
                    PC => { pc }
                    _ => { regs[code.Rs] }
                };

                if value & (I0 as i32) != 1 {
                    panic!("throw UnknownInstructionException();");
                }

                if code.Rd != 0 {
                    panic!("throw UnknownInstructionException();")
                }

                lr = pc + 2 | (I0 as i32);
                pc = value & !(I0 as i32);
            }

            // Format 6: PC-relative load
            MOVI => { // LDR Rd, [PC, #Imm]
                regs[code.Rd] = code.imm32;
                pc += 2;
            }

            // Format 7: load/store with register offset
            STR => { // STR Rd, [Rb, Ro]
                let addr = regs[code.Rs] + regs[code.Rn];
                let value = regs[code.Rd];
                memory.write_i32(addr as u32, value);
                pc += 2;
            }
            STRB => { // STRB Rd, [Rb, Ro]
                let addr = regs[code.Rs] + regs[code.Rn];
                let value = regs[code.Rd];
                memory.write_u8(addr as u32, value as u8);
                pc += 2;
            }
            LDR => { // LDR Rd, [Rb, Ro]
                let addr = regs[code.Rs] + regs[code.Rn];
                regs[code.Rd] = memory.read_i32(addr as u32);
                pc += 2;
            }
            LDRB => { // LDRB Rd, [Rb, Ro]
                let addr = regs[code.Rs] + regs[code.Rn];
                regs[code.Rd] = memory.read_u8(addr as u32) as i32;
                pc += 2;
            }

            // Format 8
            STRH => { // STRH Rd, [Rb, Ro]
                let addr = regs[code.Rs] + regs[code.Rn];
                memory.write_u16(addr as u32, regs[code.Rd] as u16);
                pc += 2;
            }
            LDRH => { // LDRH Rd, [Rb, Ro]
                let addr = regs[code.Rs] + regs[code.Rn];
                regs[code.Rd] = memory.read_u16(addr as u32) as i32;
                pc += 2;
            }
            LDSB => { // LDSB Rd, [Rb, Ro]
                let addr = regs[code.Rs] + regs[code.Rn];
                regs[code.Rd] = memory.read_u8(addr as u32) as i32;
                pc += 2;
            }
            LDSH => { // LDSH Rd, [Rb, Ro]
                let addr = regs[code.Rs] + regs[code.Rn];
                regs[code.Rd] = memory.read_u16(addr as u32) as i32;
                pc += 2;
            }

            // Format 9: load/store with immediate offset
            STRI => { // STR Rd, [Rb, #Imm]
                let addr = regs[code.Rs] + code.imm16;
                let value = regs[code.Rd];
                memory.write_i32(addr as u32, value);
                pc += 2;
            }
            STRBI => { // STRB Rd, [Rb, #Imm]
                let addr = regs[code.Rs] + code.imm16;
                let value = regs[code.Rd];
                memory.write_u8(addr as u32, value as u8);
                pc += 2;
            }
            LDRI => { // LDR Rd, [Rb, #Imm]
                let addr = regs[code.Rs] + code.imm16;
                regs[code.Rd] = memory.read_i32(addr as u32);
                pc += 2;
            }
            LDRBI => { // LDRB Rd, [Rb, #Imm]
                let addr = regs[code.Rs] + code.imm16;
                regs[code.Rd] = memory.read_u8(addr as u32) as i32;
                pc += 2;
            }

            // Format 10: load/store halfword
            STRHI => { // STRH Rd, [Rb, #Imm]
                let addr = regs[code.Rs] + code.imm16;
                memory.write_u16(addr as u32, regs[code.Rd] as u16);
                pc += 2;
            }
            LDRHI => { // LDRH Rd, [Rb, #Imm]
                let addr = regs[code.Rs] + code.imm16;
                regs[code.Rd] = memory.read_u16(addr as u32) as i32;
                pc += 2;
            }

            // Format 11: SP-relative load/store
            STRSPI => { // STR Rd, [SP, #Imm]
                let addr = sp + code.imm16;
                let value = regs[code.Rd];
                memory.write_i32(addr as u32, value);
                pc += 2;
            }
            LDRSPI => { // LDR Rd, [SP, #Imm]
                let addr = sp + code.imm16;
                regs[code.Rd] = memory.read_i32(addr as u32);
                pc += 2;
            }

            // Format 12: load address
            ADDXI => { // ADD Rd, SP, #Imm | ADD Rd, PC, #Imm
                let value = match code.Rs {
                    SP => { sp }
                    PC => { pc + 4 & !{ I1 as i32 } }
                    _ => { panic!("throw UnknownInstructionException();"); }
                };

                regs[code.Rd] = value + code.imm16;
                pc += 2;
            }

            // Format 13: add offset to Stack Pointer
            ADDSPI => { // ADD SP, #Imm | ADD SP, #-Imm
                sp += code.imm16;
                pc += 2;
            }

            // Format 14: push/pop registers
            PUSH => { // PUSH { Rlist }
                for i in (0..8).rev() {
                    if code.imm16 & (1 << i) != 0 {
                        sp -= 4;
                        memory.write_i32(sp as u32, regs[i]);
                    }
                }

                pc += 2;
            }
            PUSHR => { // PUSH { Rlist, LR }
                sp -= 4;
                memory.write_i32(sp as u32, lr);

                for i in (0..8).rev() {
                    if code.imm16 & (1 << i) != 0 {
                        sp -= 4;
                        memory.write_i32(sp as u32, regs[i]);
                    }
                }

                pc += 2;
            }
            POP => { // POP { Rlist }
                for i in 0..8 {
                    if code.imm16 & (1 << i) != 0 {
                        regs[i] = memory.read_i32(sp as u32);
                        sp += 4;
                    }
                }

                pc += 2;
            }
            POPR => { // POP { Rlist, PC }
                for i in 0..8 {
                    if code.imm16 & (1 << i) != 0 {
                        regs[i] = memory.read_i32(sp as u32);
                        sp += 4;
                    }
                }

                let value = memory.read_i32(sp as u32);
                if value & (I0 as i32) != 1 {
                    panic!("throw InvalidAddressArmException();");
                }

                pc = value & !(I0 as i32);
                sp += 4;
            }

            // Format 15: multiple load/store
            STMIA => { // STMIA Rb!, { Rlist }
                let mut addr = regs[code.Rd];
                for i in 0..8 {
                    if code.imm16 & (1 << i) != 0 {
                        memory.write_i32(addr as u32, regs[i]);
                        addr += 4;
                    }
                }

                regs[code.Rd] = addr;
                pc += 2;
            }
            LDMIA => { // LDMIA Rb!, { Rlist }
                let mut addr = regs[code.Rd];
                for i in 0..8 {
                    if code.imm16 & (1 << i) != 0 {
                        regs[i] = memory.read_i32(addr as u32);
                        addr += 4;
                    }
                }

                regs[code.Rd] = addr;
                pc += 2;
            }

            // Format 16: conditional branch
            BEQ => { pc += if z { code.imm16 } else { 2 }; } // BEQ label
            BNE => { pc += if !z { code.imm16 } else { 2 }; } // BNE label
            BCS => { pc += if c { code.imm16 } else { 2 }; } // BCS label
            BCC => { pc += if !c { code.imm16 } else { 2 }; } // BCC label
            BMI => { pc += if n { code.imm16 } else { 2 }; } // BMI label
            BPL => { pc += if !n { code.imm16 } else { 2 }; } // BPL label
            BVS => { pc += if v { code.imm16 } else { 2 }; } // BVS label
            BVC => { pc += if !v { code.imm16 } else { 2 }; } // BVC label
            BHI => { pc += if c && !z { code.imm16 } else { 2 }; } // BHI label
            BLS => { pc += if !c || z { code.imm16 } else { 2 }; } // BLS label
            BGE => { pc += if n == v { code.imm16 } else { 2 }; } // BGE label
            BLT => { pc += if n != v { code.imm16 } else { 2 }; } // BLT label
            BGT => { pc += if !z && n == v { code.imm16 } else { 2 }; } // BGT label
            BLE => { pc += if z || n != v { code.imm16 } else { 2 }; } // BLE label

            // Format 17: software interrupt
            SVC => { // SWI Value8
                // println("SVC $imm16:${regs[7]} r0=${regs[0]} r1=${regs[1]} r2=${regs[2]} r3=${regs[3]}")

                regs[SP] = sp;
                regs[LR] = lr;
                regs[PC] = pc;

                /*
                regs.setCPSR(v, c, z, n);
                regs.fastStore(regs, sp, lr, pc);

                try {
                    handler(code.imm16);
                } catch (e: ControlPauseSignal) {
                    throw e;
                } catch (e: ControlStopSignal) {
                    regs[PC] += 2;
                    throw e;
                } finally {
                    sp = regs.sp;
                    lr = regs.lr;
                    pc = regs.pc;
                    regs = regs.fastLoad();
                    v = regs.v;
                    c = regs.c;
                    z = regs.z;
                    n = regs.n;
                }
                */

                pc += 2;
                match (regs[7], regs[0]) {
                    (5, _) => {
                        for i in regs[0]..(regs[0] + regs[1]) {
                            print!("{}", memory.read_u8(i as u32) as char);
                        }
                    }
                    (10, 10) => {
                        // println!("INTERRUPT");
                    }
                    (10, 11) => {
                        return;
                    }
                    _ => {
                        println!("INTERRUPT");
                        println!("INTERRUPT POSITION={:x} code.imm16={} r7={} r0={} r1={} r2={} r3={}", pc, code.imm16, regs[7], regs[0], regs[1], regs[2], regs[3]);
                        return;
                    }
                }
            }

            // Format 18: unconditional branch
            B => { // B label
                pc += code.imm16;
            }

            // Format 19: long branch with link
            BL => { // BL label
                lr = pc + 3 + 2;
                pc += code.imm32 + 2;
            }

            // Format X
            SXTH => { // SXTH Rd, Rs
                regs[code.Rd] = regs[code.Rs] as i16 as i32;
                pc += 2;
            }
            SXTB => { // SXTB Rd, Rs
                regs[code.Rd] = regs[code.Rs] as i8 as i32;
                pc += 2;
            }
            UXTH => { // UXTH Rd, Rs
                regs[code.Rd] = regs[code.Rs] & 0xFFFF;
                pc += 2;
            }
            UXTB => { // UXTB Rd, Rs
                regs[code.Rd] = regs[code.Rs] & 0xFF;
                pc += 2;
            }
            REV => { // REV Rd, Rs
                let value = regs[code.Rs];
                regs[code.Rd] = (value >> 24 & 0xFF) |
                    ((value >> 16 & 0xFF) << 8) |
                    ((value >> 8 & 0xFF) << 16) |
                    ((value & 0xFF) << 24);
                pc += 2;
            }

            _ => { unimplemented!(); }
        }
    }

    regs[SP] = sp;
    regs[LR] = lr;
    regs[PC] = pc;
    regs[CPSR] =
        if v { FV } else { 0 } |
        if c { FC } else { 0 } |
        if z { FZ } else { 0 } |
        if n { FN } else { 0 };
}