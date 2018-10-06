#![allow(dead_code)]

pub enum Flag {
    RW,
    RX,
    HOOK,
}

struct BufferRegion {
    flag: Flag,
    start: u32,
    size: u32,
    end: u32,
    buffer: Vec<u8>,
}

pub trait Region {
    fn new(start: u32, size: u32, flag: Flag) -> Self;
    fn valid(&self, address: u32, _size: u32) -> bool;
}

pub trait Content {
    fn read_i32(&mut self, address: u32) -> i32;
    fn read_u16(&mut self, address: u32) -> u16;
    fn read_u8(&mut self, address: u32) -> u8;
    fn write_i32(&mut self, address: u32, value: i32);
    fn write_u16(&mut self, address: u32, value: u16);
    fn write_u8(&mut self, address: u32, value: u8);
}

impl BufferRegion {
    fn load_key(&self, address: u32) -> usize {
        return (address - self.start) as usize;
    }
}

impl Region for BufferRegion {
    fn new(start: u32, size: u32, flag: Flag) -> Self {
        Self {
            flag,
            start,
            size,
            end: start + size,
            buffer: vec![0u8; size as usize],
        }
    }

    fn valid(&self, address: u32, size: u32) -> bool {
        return self.start <= address && address + size <= self.end;
    }
}

impl Content for BufferRegion {
    fn read_i32(&mut self, address: u32) -> i32 {
        let key = self.load_key(address);
        return (self.buffer[key] as i32) |
            ((self.buffer[key + 1] as i32) << 8) |
            ((self.buffer[key + 2] as i32) << 16) |
            ((self.buffer[key + 3] as i32) << 24);
    }

    fn read_u16(&mut self, address: u32) -> u16 {
        let key = self.load_key(address);
        return (self.buffer[key] as u16) |
            ((self.buffer[key + 1] as u16) << 8);
    }

    fn read_u8(&mut self, address: u32) -> u8 {
        let key = self.load_key(address);
        return self.buffer[key];
    }

    fn write_i32(&mut self, address: u32, value: i32) {
        let key = self.load_key(address);
        self.buffer[key] = value as u8;
        self.buffer[key + 1] = (value >> 8) as u8;
        self.buffer[key + 2] = (value >> 16) as u8;
        self.buffer[key + 3] = (value >> 24) as u8;
    }

    fn write_u16(&mut self, address: u32, value: u16) {
        let key = self.load_key(address);
        self.buffer[key] = value as u8;
        self.buffer[key + 1] = (value >> 8) as u8;
    }

    fn write_u8(&mut self, address: u32, value: u8) {
        let key = self.load_key(address);
        self.buffer[key] = value;
    }
}

pub struct Memory {
    buffers: Vec<BufferRegion>,
}

impl Memory {
    pub fn new() -> Memory {
        let mut buffers: Vec<BufferRegion> = Vec::new();
        for i in 0..256 {
            buffers.push(BufferRegion::new(0, 0, Flag::RW));
        }

        Memory {
            buffers,
        }
    }

    pub fn map(&mut self, address: u32, size: u32) {
        let region = Region::new(address, size, Flag::RW);
        self.buffers[(address >> 24) as usize] = region;
    }
}

impl Content for Memory {
    fn read_i32(&mut self, address: u32) -> i32 {
        return self.buffers[(address >> 24) as usize].read_i32(address);
    }

    fn read_u16(&mut self, address: u32) -> u16 {
        return self.buffers[(address >> 24) as usize].read_u16(address);
    }

    fn read_u8(&mut self, address: u32) -> u8 {
        return self.buffers[(address >> 24) as usize].read_u8(address);
    }

    fn write_i32(&mut self, address: u32, value: i32) {
        self.buffers[(address >> 24) as usize].write_i32(address, value);
    }

    fn write_u16(&mut self, address: u32, value: u16) {
        self.buffers[(address >> 24) as usize].write_u16(address, value);
    }

    fn write_u8(&mut self, address: u32, value: u8) {
        self.buffers[(address >> 24) as usize].write_u8(address, value);
    }
}
