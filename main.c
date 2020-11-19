/*
 * mini-durango - A Veracruz client targetting microcontroller devices
 *
 */
#include <zephyr.h>
#include <sys/printk.h>

void main(void) {
	printk("Hello World! %s\n", CONFIG_BOARD);

    // exit QEMU
    __asm__ volatile (
        "mov r0, #0x18 \n\t"
        "ldr r1, =#0x20026 \n\t"
        "bkpt #0xab \n\t"
    );
}
