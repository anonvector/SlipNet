# Makefile for hev-task-system

PROJECT=hev-task-system

CROSS_PREFIX :=
PP=$(CROSS_PREFIX)cpp
CC=$(CROSS_PREFIX)gcc
LD=$(CROSS_PREFIX)ld
AR=$(CROSS_PREFIX)ar
CCFLAGS=-O3 -pipe -Werror -Wall -I include $(CFLAGS)
LDFLAGS=$(LFLAGS)

APP_CCFLAGS=$(CCFLAGS)
APP_LDFLAGS=$(LDFLAGS) -L $(BINDIR) -l $(PROJECT) -pthread

SRCDIR=src
BINDIR=bin
APPDIR=apps
TESTDIR=tests
BUILDDIR=build

STATIC_TARGET=$(BINDIR)/lib$(PROJECT).a
SHARED_TARGET=$(BINDIR)/lib$(PROJECT).so

$(SHARED_TARGET) : CCFLAGS+=-fPIC -fvisibility=hidden
$(SHARED_TARGET) : LDFLAGS+=-shared -pthread

-include build.mk
-include configs.mk
CCFLAGS+=-I$(SRCDIR) $(CONFIG_CFLAGS)

CCSRCS=$(filter %.c,$(SRCFILES))
ASSRCS=$(filter %.S,$(SRCFILES))
LDOBJS=$(patsubst $(SRCDIR)/%.c,$(BUILDDIR)/%.o,$(CCSRCS)) \
       $(patsubst $(SRCDIR)/%.S,$(BUILDDIR)/%.o,$(ASSRCS))
DEPEND=$(LDOBJS:.o=.dep)

BUILDMSG="\e[1;31mBUILD\e[0m %s\n"
LINKMSG="\e[1;34mLINK\e[0m  \e[1;32m%s\e[0m\n"
CLEANMSG="\e[1;34mCLEAN\e[0m %s\n"
TESTMSG="\e[1;34mTEST\e[0m  \e[1;32m%s\e[0m\n"

ifeq ($(MSYSTEM),MSYS)
	LDFLAGS+=-lmsys-2.0 -lws2_32
endif

V:=
ECHO_PREFIX:=@
ifeq ($(V),1)
    undefine ECHO_PREFIX
endif

.PHONY: static shared clean tests apps

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


tests : $(patsubst $(TESTDIR)/%.c,$(BINDIR)/test-%,$(wildcard $(TESTDIR)/*.c))
	$(ECHO_PREFIX) for test in $^; do printf $(TESTMSG) $$test; $$test; done

$(BINDIR)/test-% : $(TESTDIR)/%.c $(STATIC_TARGET)
	$(ECHO_PREFIX) $(CC) -o $@ $^ $(APP_CCFLAGS) $(APP_LDFLAGS)
	@printf $(LINKMSG) $@

apps : \
	$(BINDIR)/simple \
	$(BINDIR)/wakeup \
	$(BINDIR)/channel \
	$(BINDIR)/timeout \
	$(BINDIR)/echo-server \
	$(BINDIR)/curl \
	$(BINDIR)/gtk

$(BINDIR)/simple : $(APPDIR)/simple.c $(STATIC_TARGET)
	$(ECHO_PREFIX) $(CC) -o $@ $^ $(APP_CCFLAGS) $(APP_LDFLAGS)
	@printf $(LINKMSG) $@

$(BINDIR)/wakeup : $(APPDIR)/wakeup.c $(STATIC_TARGET)
	$(ECHO_PREFIX) $(CC) -o $@ $^ $(APP_CCFLAGS) $(APP_LDFLAGS)
	@printf $(LINKMSG) $@

$(BINDIR)/channel : $(APPDIR)/channel.c $(STATIC_TARGET)
	$(ECHO_PREFIX) $(CC) -o $@ $^ $(APP_CCFLAGS) $(APP_LDFLAGS)
	@printf $(LINKMSG) $@

$(BINDIR)/timeout : $(APPDIR)/timeout.c $(STATIC_TARGET)
	$(ECHO_PREFIX) $(CC) -o $@ $^ $(APP_CCFLAGS) $(APP_LDFLAGS)
	@printf $(LINKMSG) $@

$(BINDIR)/echo-server : $(APPDIR)/echo-server.c $(STATIC_TARGET)
	$(ECHO_PREFIX) $(CC) -o $@ $^ $(APP_CCFLAGS) $(APP_LDFLAGS)
	@printf $(LINKMSG) $@

$(BINDIR)/curl : $(APPDIR)/curl.c $(STATIC_TARGET)
	$(ECHO_PREFIX) $(CC) -o $@ $^ $(APP_CCFLAGS) $(APP_LDFLAGS) \
		`pkg-config --cflags --libs libcurl` -ldl
	@printf $(LINKMSG) $@

$(BINDIR)/gtk : $(APPDIR)/gtk.c $(STATIC_TARGET)
	$(ECHO_PREFIX) $(CC) -o $@ $^ $(APP_CCFLAGS) $(APP_LDFLAGS) \
		`pkg-config --cflags --libs gtk+-3.0`
	@printf $(LINKMSG) $@
