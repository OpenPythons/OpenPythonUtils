#![warn(unused_variables)]
extern crate jni;
#[macro_use]
extern crate lazy_static;

use builder::CPU;
use builder::FIRMWARE_ADDRESS;
use jni::JNIEnv;
use jni::objects::{JClass};
use jni::sys::jarray;
use std::sync::Mutex;

mod executor;
mod decoder;
mod memory;
mod consts;
pub mod builder;

lazy_static! {
    // Since it's mutable and shared, use mutext.
    static ref STATES: Mutex<CPU> = Mutex::new(builder::build());
}


#[no_mangle]
#[allow(non_snake_case)]
pub extern "system" fn Java_kr_pe_ecmaxp_thumbsf_ECPU_init(_env: JNIEnv,
                                                           _class: JClass) {}

#[no_mangle]
#[allow(non_snake_case)]
pub extern "system" fn Java_kr_pe_ecmaxp_thumbsf_ECPU_step(env: JNIEnv,
                                                           _class: JClass)
                                                           -> jarray {
    let mut cpu = STATES.lock().unwrap();
    let array = env.new_int_array(17).expect("?");

    executor::execute(&mut cpu);
    env.set_int_array_region(array, 0, &cpu.regs).unwrap();

    array
}

#[no_mangle]
#[allow(non_snake_case)]
pub extern "system" fn Java_kr_pe_ecmaxp_thumbsf_ECPU_debug(_env: JNIEnv,
                                                           _class: JClass,
                                                           address: i32) {
    let cpu = STATES.lock().unwrap();
    let insn = cpu.cache2.get((((address as u32) - FIRMWARE_ADDRESS) >> 1) as usize).unwrap();
    decoder::show_insn(&insn);
}
