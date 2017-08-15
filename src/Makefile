CC = apxs
CFLAGS = -Wc,-std=gnu99 -c
LDFLAGS = `pkg-config --cflags --libs jansson openssl libcurl`
DBG_CFLAGS = -g -DDEBUG

SOURCES = mod_perimeterx.c curl_pool.c px_payload.c px_json.c px_utils.c px_enforcer.c px_template.c mustach.c
HEADERS =  px_types.h curl_pool.h px_payload.h px_json.h px_utils.h px_enforcer.h px_template.h mustach.h

all: clean mod

mod: $(HEADERS) $(SOURCES)
	$(CC) $(CFLAGS) $(LDFLAGS) $(SOURCES)

debug: $(HEADERS) $(SOURCES)
	$(CC) $(CFLAGS) -DDEBUG -DPX_AUT_HEADER_KEY=\\\"$(PX_AUT_HEADER_KEY)\\\" -DPX_AUT_HEADER_VALUE=\\\"$(PX_AUT_HEADER_VALUE)\\\" $(LDFLAGS) $(SOURCES)

.PHONY: install
install:
	$(CC) -i -a mod_perimeterx.la

.PHONY: clean
clean:
	@rm -f *.lo *.slo *.la *.o
	@rm -rf .libs
