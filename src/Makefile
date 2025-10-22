# Makefile for kc_validator (server module via PGXS)
MODULE_big = kc_validator
OBJS = kc_validator.o
PG_CONFIG = pg_config

SHLIB_LINK += -lcurl

PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
