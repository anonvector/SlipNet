# Makefile for lwip

PROJECT=lwip

CROSS_PREFIX :=
PP=$(CROSS_PREFIX)cpp
CC=$(CROSS_PREFIX)gcc
LD=$(CROSS_PREFIX)ld
AR=$(CROSS_PREFIX)ar
CCFLAGS=-O3 -pipe $(CFLAGS)
LDFLAGS=$(LFLAGS)

SRCDIR=src
BINDIR=bin
BUILDDIR=build

STATIC_TARGET=$(BINDIR)/lib$(PROJECT).a
SHARED_TARGET=$(BINDIR)/lib$(PROJECT).so

$(SHARED_TARGET) : CCFLAGS+=-fPIC
$(SHARED_TARGET) : LDFLAGS+=-shared -pthread

-include build.mk
CCFLAGS+=-Isrc/include -Isrc/ports/include

CCSRCS=$(filter %.c,$(SRCFILES))
ASSRCS=$(filter %.S,$(SRCFILES))
LDOBJS=$(patsubst $(SRCDIR)/%.c,$(BUILDDIR)/%.o,$(CCSRCS)) \
       $(patsubst $(SRCDIR)/%.S,$(BUILDDIR)/%.o,$(ASSRCS))
DEPEND=$(LDOBJS:.o=.dep)

BUILDMSG="\e[1;31mBUILD\e[0m %s\n"
LINKMSG="\e[1;34mLINK\e[0m  \e[1;32m%s\e[0m\n"
CLEANMSG="\e[1;34mCLEAN\e[0m %s\n"
TESTMSG="\e[1;34mTEST\e[0m  \e[1;32m%s\e[0m\n"

ENABLE_DEBUG :=
ifeq ($(ENABLE_DEBUG),1)
	CCFLAGS+=-g -O0 -DENABLE_DEBUG
endif

V:=
ECHO_PREFIX:=@
ifeq ($(V),1)
    undefine ECHO_PREFIX
endif

.PHONY: static shared clean

static : $(STATIC_TARGET)

shared : $(SHARED_TARGET)

clean :
	$(ECHO_PREFIX) $(RM) -rf $(BINDIR) $(BUILDDIR)
	@printf $(CLEANMSG) $(PROJECT)

$(STATIC_TARGET) : $(LDOBJS)
	$(ECHO_PREFIX) mkdir -p $(dir $@)
	$(ECHO_PREFIX) $(AR) csq $@ $^
	@printf $(LINKMSG) $@

$(SHARED_TARGET) : $(LDOBJS)
	$(ECHO_PREFIX) mkdir -p $(dir $@)
	$(ECHO_PREFIX) $(CC) -o $@ $^ $(LDFLAGS)
	@printf $(LINKMSG) $@

$(BUILDDIR)/%.dep : $(SRCDIR)/%.c
	$(ECHO_PREFIX) mkdir -p $(dir $@)
	$(ECHO_PREFIX) $(PP) $(CCFLAGS) -MM -MT$(@:.dep=.o) -MF$@ $< 2>/dev/null

$(BUILDDIR)/%.dep : $(SRCDIR)/%.S
	$(ECHO_PREFIX) mkdir -p $(dir $@)
	$(ECHO_PREFIX) $(PP) $(CCFLAGS) -MM -MT$(@:.dep=.o) -MF$@ $< 2>/dev/null

$(BUILDDIR)/%.o : $(SRCDIR)/%.c
	$(ECHO_PREFIX) mkdir -p $(dir $@)
	$(ECHO_PREFIX) $(CC) $(CCFLAGS) -c -o $@ $<
	@printf $(BUILDMSG) $<

$(BUILDDIR)/%.o : $(SRCDIR)/%.S
	$(ECHO_PREFIX) mkdir -p $(dir $@)
	$(ECHO_PREFIX) $(CC) $(CCFLAGS) -c -o $@ $<
	@printf $(BUILDMSG) $<

ifneq ($(MAKECMDGOALS),clean)
-include $(DEPEND)
endif
