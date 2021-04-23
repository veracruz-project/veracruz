/*
 * Veracruz client aimed at microcontrollers, built in Zephyr OS
 *
 * Note that there are very few arguments to these functions, the Veracruz
 * client is based on a static policy file that is expected preprocessed into
 * a policy.h file (see policy_to_header.py).
 *
 * TODO config struct?
 *
 */

#ifndef VC_H
#define VC_H

#include <stdio.h>
#include <stdlib.h>

int vc_attest(void);

#endif
