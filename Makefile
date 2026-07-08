CC      = gcc
CFLAGS  = -O2 -Wall -Wno-format-truncation -Wno-maybe-uninitialized
LDFLAGS = -static

AUDIT_HOOK_WARN = -Wno-unused-result -Wno-unused-function

.PHONY: all clean

all: vsapstar sap_audit_hook

vsapstar: vsapstar.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

sap_audit_hook: sap_audit_hook.c
	$(CC) $(CFLAGS) $(AUDIT_HOOK_WARN) $(LDFLAGS) -o $@ $<

clean:
	rm -f vsapstar sap_audit_hook
