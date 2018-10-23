#![allow(non_snake_case)]

use consts::*;
use decoder;
use memory::Content;
use memory::Memory;
use std::fs::File;
use std::io::prelude::*;

pub const FIRMWARE_ADDRESS: u32 = 0x08000000;
pub const FIRMWARE_PATH: &str = r##"C:\Users\EcmaXp\Dropbox\Projects\OpenPie\oprom\build\firmware.bin"##;

fn load_firmware(path: &str) -> Vec<u8> {
    let mut file = File::open(path).unwrap();
    let mut contents: Vec<u8> = vec![];
    file.read_to_end(&mut contents).unwrap();
    contents
}

//noinspection RsFieldNaming
pub struct Instruction {
    pub op: u8,
    pub Rd: usize,
    pub Rs: usize,
    pub Rn: usize,
    pub imm16: i32,
    pub imm32: i32,
}

pub struct CPU {
    pub regs: Vec<i32>,
    pub memory: Memory,
    pub cache: Vec<i32>,
    pub cache2: Vec<Instruction>,
}

pub fn build() -> CPU {
    let firmware = load_firmware(FIRMWARE_PATH);

    let mut regs: Vec<i32> = vec![0i32; CPSR + 1];
    let mut memory = Memory::new();

    // flush firmware
    memory.map(FIRMWARE_ADDRESS, 256 * 1024);
    for (pos, value) in firmware.iter().enumerate() {
        memory.write_u8(FIRMWARE_ADDRESS + pos as u32, *value);
    }

    // mapping memory
    memory.map(0x20000000, 64 * 1024);
    memory.map(0x60000000, 256 * 1024);
    memory.map(0xE0000000, 16 * 1024);

    let mut cache = vec![0i32; 256 * 1024];
    let mut cache2: Vec<Instruction> = Vec::with_capacity(256 * 1024);

    // build cache
    for pos in (0..firmware.len()).step_by(2) {
        let addr = (FIRMWARE_ADDRESS as usize + pos) as usize;
        let (code, imm32) = decoder::decode(&mut memory, addr as i32);
        cache[pos] = code;
        cache[pos + 1] = imm32;
        cache2.push(Instruction {
            op: (code & 0xFF) as u8,
            Rd: (code >> RDEST & RMASK) as usize,
            Rs: (code >> RSRC & RMASK) as usize,
            Rn: (code >> RNUM & RMASK) as usize,
            imm16: (code >> RIMM) as i16 as i32,
            imm32,
        });
    }

    // build registers
    regs[PC as usize] = memory.read_i32(FIRMWARE_ADDRESS + 4) & !1;
    regs[CPSR as usize] = FZ as i32;

    CPU {
        regs,
        memory,
        cache,
        cache2,
    }
}