CC = apxs
CFLAGS = -g

all: clean mod

mod: mod_perimeterx.c curl_pool.h curl_pool.c
	$(CC) -i -a -Wc,-std=gnu99 -c `pkg-config --cflags --libs jansson openssl libcurl` mod_perimeterx.c curl_pool.c

b: b.c
	gcc b.c -std=gnu99 -ljansson -ob

clean:
	rm -f *.{lo,slo,la,o} b
