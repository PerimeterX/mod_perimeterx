CC = apxs
CFLAGS = -i -a -Wc,-std=gnu99 -c
LDFLAGS = `pkg-config --cflags --libs jansson openssl libcurl json-c`
DBG_CFLAGS = -g -DDEBUG

SOURCES = mod_perimeterx.c curl_pool.c px_cookie.c px_json.c px_utils.c px_enforcer.c px_template.c mustach-json-c.c mustach.c
HEADERS =  px_types.h curl_pool.h px_cookie.h px_json.h px_utils.h px_enforcer.h px_template.h mustach-json-c.h mustach.h

all: clean mod

mod: $(HEADERS) $(SOURCES)
	$(CC) $(CFLAGS) $(LDFLAGS) $(SOURCES)

debug: $(HEADERS) $(SOURCES)
	$(CC) $(CFLAGS) -DDEBUG $(LDFLAGS) $(SOURCES)

#docker:

#test:

clean:
	rm -f *.{lo,slo,la,o}
