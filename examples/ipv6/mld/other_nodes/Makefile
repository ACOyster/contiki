DEFINES+=PROJECT_CONF_H=\"project-conf.h\"

CONTIKI_PROJECT = mldrouter sink sink2
all: $(CONTIKI_PROJECT)

CONTIKI = ../../../..

CFLAGS += -DPROJECT_CONF_H=\"project-conf.h\"

MODULES += core/net/ipv6/multicast

ifeq ($(PREFIX),)
 PREFIX = fd80::1/64
endif

CONTIKI_WITH_IPV6 = 1
include $(CONTIKI)/Makefile.include

$(CONTIKI)/tools/tunslip6:	$(CONTIKI)/tools/tunslip6.c
	(cd $(CONTIKI)/tools && $(MAKE) tunslip6)

connect-router:	$(CONTIKI)/tools/tunslip6
	sudo $(CONTIKI)/tools/tunslip6 $(PREFIX)

connect-router-cooja:	$(CONTIKI)/tools/tunslip6
	sudo $(CONTIKI)/tools/tunslip6 -a 127.0.0.1 $(PREFIX)
