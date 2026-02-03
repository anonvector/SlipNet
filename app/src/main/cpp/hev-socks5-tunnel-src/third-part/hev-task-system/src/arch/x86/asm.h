/*
 ============================================================================
 Name        : asm.h
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2018 - 2025 everyone.
 Description :
 ============================================================================
 */

#if defined(__APPLE__) || defined(__MACH__)

# define NESTED(symbol) \
    .globl _##symbol; \
_##symbol:

# define END(symbol)

#elif defined(__MSYS__)

# define NESTED(symbol) \
    .globl symbol; \
symbol:

# define END(symbol)

#else

# define NESTED(symbol) \
    .globl symbol; \
    .type symbol, @function; \
symbol:

# define END(symbol) \
    .size symbol, . - symbol;

#endif
