/*
 * QEMU utilities
 */

#ifndef QEMU_H
#define QEMU_H

// hack to exit QEMU
// TODO can we integrate into Zephyr somehow?
__attribute__((noreturn))
static inline void qemu_exit(void) {
    __asm__ volatile (
        "mov r0, #0x18 \n\t"
        "ldr r1, =#0x20026 \n\t"
        "bkpt #0xab \n\t"
    );

    __builtin_unreachable();
}

#endif
