/*
 ============================================================================
 Name        : hev-task-execute.S
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2017 everyone.
 Description :
 ============================================================================
 */

#if defined(__i386__)

# include "arch/x86/hev-task-execute-x86.s"

#elif defined(__x86_64__)

# include "arch/x86/hev-task-execute-x86_64.s"

#elif defined(__mips__)

# if (_MIPS_SIM == _ABI64)
#  include "arch/mips/hev-task-execute-mips64.s"
# else
#  include "arch/mips/hev-task-execute-mips32.s"
# endif

#elif defined(__arm__)

# include "arch/arm/hev-task-execute-arm.s"

#elif defined(__aarch64__)

# include "arch/arm/hev-task-execute-aarch64.s"

#elif defined(__sw_64__)

# include "arch/sw64/hev-task-execute-sw64.s"

#elif defined(__riscv)

# if defined(_LP64)
#  include "arch/riscv/hev-task-execute-riscv64.s"
# else
#  include "arch/riscv/hev-task-execute-riscv32.s"
# endif

#elif defined(__loongarch__)

# if defined(_LP64)
#  include "arch/loong/hev-task-execute-la64.s"
# else
#  include "arch/loong/hev-task-execute-la32.s"
# endif

#elif defined(__powerpc64__)

# include "arch/ppc/hev-task-execute-ppc64.s"

#elif defined(__powerpc__)

# include "arch/ppc/hev-task-execute-ppc32.s"

#elif defined(__arc__)

# include "arch/arc/hev-task-execute-arc32.s"

#elif defined(__m68k__)

# include "arch/m68k/hev-task-execute-m68k.s"

#elif defined(__microblaze__)

# include "arch/microblaze/hev-task-execute-microblaze.s"

#elif defined(__s390x__)

# include "arch/s390/hev-task-execute-s390x.s"

#elif defined(__sh__)

# include "arch/sh/hev-task-execute-sh.s"

#elif defined(__or1k__)

# include "arch/openrisc/hev-task-execute-or1k.s"

#else

# error "Unsupported platform!"

#endif

#if defined(__ELF__) && defined(__linux__)
/* An executable stack is *not* required for these functions. */
    .section .note.GNU-stack,"",%progbits
    .previous
#endif
