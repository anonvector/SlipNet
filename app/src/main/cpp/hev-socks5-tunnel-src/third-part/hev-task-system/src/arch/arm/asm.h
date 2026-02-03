/*
 ============================================================================
 Name        : asm.h
 Author      : hev <r@hev.cc>
 Copyright   : Copyright (c) 2021 everyone.
 Description :
 ============================================================================
 */

#if defined(__APPLE__) || defined(__MACH__)

#ifdef __arm__
# define NESTED(symbol) \
    .globl _##symbol; \
    .p2align 2; \
_##symbol:
#else
# define NESTED(symbol) \
    .globl _##symbol%% \
    .p2align 2%% \
_##symbol:
#endif

# define END(symbol)

#else

# define NESTED(symbol) \
    .globl symbol; \
    .type symbol, %function; \
symbol:

# define END(symbol) \
    .size symbol, . - symbol;

#endif
