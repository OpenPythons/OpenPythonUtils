// package kr.pe.ecmaxp.thumbsf / class CPU

// [ECPU] val ecpu: ECPU = ECPU()
// [ECPU] val prev_pc = pc;
// [ECPU] debugging
/*
if (ecpu != null) {
    regs.setCPSR(v, c, z, n)
    regs.fastStore(REGS, sp, lr, pc)
    val eregs = ecpu!!.step()
    var error = false
    for (reg in 0..CPSR) {
        if (regs[reg] != eregs[reg])
            error = true
    }

    if (error) {
        val imm32 = buffer[prev_pc - base + 1]
        println()
        println("$prev_pc")
        show(code, imm32)
        ecpu!!.debug(prev_pc);

        for (reg in 0..CPSR) {
            when (reg) {
                16 -> {
                    fun writeCPSR(cpsr: Int) {
                        print(if ((cpsr and FV) != 0) "V" else "-")
                        print(if ((cpsr and FC) != 0) "C" else "-")
                        print(if ((cpsr and FZ) != 0) "Z" else "-")
                        print(if ((cpsr and FN) != 0) "N" else "-")
                    }

                    print("r$reg => CPU:")
                    writeCPSR(regs[reg])
                    print("\tECPU:")
                    writeCPSR(eregs[reg])
                    println()
                    // println("r$reg => CPU:${regs[reg]}\tECPU:${eregs[reg]}")
                }
                else -> if (regs[reg] != eregs[reg]) {
                    println("r$reg => CPU:${regs[reg]}\tECPU:${eregs[reg]}")
                } else {
                    println("r$reg => CPU:${regs[reg]}")
                }
            }
        }

        throw ControlStopSignal()
    } else {
        if (false) {
            val imm32 = buffer[prev_pc - base + 1]
            show(code, imm32)
        }
    }
}
*/

// package kr.pe.ecmaxp.optvm / class ECPU
class ECPU {
    init {
        System.loadLibrary("optvm")
        init()
    };

    external fun init()
    external fun step(): IntArray
    external fun debug(address: Int)
}
