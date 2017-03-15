/*
 Author: José Bollo <jobol@nonadev.net>
 Author: José Bollo <jose.bollo@iot.bzh>

 https://gitlab.com/jobol/mustach

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
*/

#include <stdio.h>
#include <string.h>

#include <json-c/json.h>

#include "mustach.h"

#define MAX_DEPTH 256

#if defined(NO_EXTENSION_FOR_MUSTACH)
# if !defined(NO_COLON_EXTENSION_FOR_MUSTACH)
#  define NO_COLON_EXTENSION_FOR_MUSTACH
# endif
# if !defined(NO_EQUAL_VALUE_EXTENSION_FOR_MUSTACH)
#  define NO_EQUAL_VALUE_EXTENSION_FOR_MUSTACH
# endif
# if !defined(NO_JSON_POINTER_EXTENSION_FOR_MUSTACH)
#  define NO_JSON_POINTER_EXTENSION_FOR_MUSTACH
# endif
#endif

#if defined(NO_COLON_EXTENSION_FOR_MUSTACH)
# if !defined(NO_JSON_POINTER_EXTENSION_FOR_MUSTACH)
#  define NO_JSON_POINTER_EXTENSION_FOR_MUSTACH
# endif
#endif

struct expl {
	struct json_object *root;
	int depth;
	struct {
		struct json_object *cont;
		struct json_object *obj;
		int index, count;
	} stack[MAX_DEPTH];
};

#if !defined(NO_EQUAL_VALUE_EXTENSION_FOR_MUSTACH)
static char *keyval(char *head, int isptr)
{
	char *w, c;

	c = *(w = head);
	while (c && c != '=') {
#if !defined(NO_JSON_POINTER_EXTENSION_FOR_MUSTACH)
		if (isptr) {
			if (isptr && c == '~' && head[1] == '=')
				c = *++head;
		} else
#endif
		if (!isptr && c == '\\' && head[1] == '=')
			c = *++head;
		*w++ = c;
		c = *++head;
	}
	*w = 0;
	return c == '=' ? ++head : NULL;
}
#endif

static char *key(char **head, int isptr)
{
	char *r, *i, *w, c;

	c = *(i = *head);
	if (!c)
		r = NULL;
	else {
		r = w = i;
#if !defined(NO_JSON_POINTER_EXTENSION_FOR_MUSTACH)
		if (isptr)
			while (c && c != '/') {
				if (c == '~')
					switch (i[1]) {
					case '1': c = '/';
					case '0': i++;
					}
				*w++ = c;
				c = *++i;
			}
		else
#endif
		while (c && c != '.') {
			if (c == '\\' && (i[1] == '.' || i[1] == '\\'))
				c = *++i;
			*w++ = c;
			c = *++i;
		}
		*w = 0;
		*head = i + !!c;
	}
	return r;
}

static struct json_object *find(struct expl *e, const char *name)
{
	int i, isptr;
	struct json_object *o;
	char *n, *c, *v;

	n = strdupa(name);
	isptr = 0;
#if !defined(NO_JSON_POINTER_EXTENSION_FOR_MUSTACH)
	isptr = n[0] == '/';
	n += isptr;
#endif

	v = NULL;
#if !defined(NO_EQUAL_VALUE_EXTENSION_FOR_MUSTACH)
	v = keyval(n, isptr);
#endif
	if (n[0] == '.' && !n[1]) {
		/* case of . alone */
		o = e->stack[e->depth].obj;
	} else {
		c = key(&n, isptr);
		if (c == NULL)
			return NULL;
		o = NULL;
		i = e->depth;
		while (i >= 0 && !json_object_object_get_ex(e->stack[i].obj, c, &o))
			i--;
		if (i < 0)
			return NULL;
		c = key(&n, isptr);
		while(c) {
			if (!json_object_object_get_ex(o, c, &o))
				return NULL;
			c = key(&n, isptr);
		}
	}
	if (v) {
		i = v[0] == '!';
		if (i == !strcmp(&v[i], json_object_get_string(o)))
			o = NULL;
	}
	return o;
}

static int start(void *closure)
{
	struct expl *e = closure;
	e->depth = 0;
	e->stack[0].cont = NULL;
	e->stack[0].obj = e->root;
	e->stack[0].index = 0;
	e->stack[0].count = 1;
	return 0;
}

static void print(FILE *file, const char *string, int escape)
{
	if (!escape)
		fprintf(file, "%s", string);
	else if (*string)
		do {
			switch(*string) {
			case '<': fputs("&lt;", file); break;
			case '>': fputs("&gt;", file); break;
			case '&': fputs("&amp;", file); break;
			default: putc(*string, file); break;
			}
		} while(*++string);
}

static int put(void *closure, const char *name, int escape, FILE *file)
{
	struct expl *e = closure;
	struct json_object *o = find(e, name);
	if (o)
		print(file, json_object_get_string(o), escape);
	return 0;
}

static int enter(void *closure, const char *name)
{
	struct expl *e = closure;
	struct json_object *o = find(e, name);
	if (++e->depth >= MAX_DEPTH)
		return MUSTACH_ERROR_TOO_DEPTH;
	if (json_object_is_type(o, json_type_array)) {
		e->stack[e->depth].count = json_object_array_length(o);
		if (e->stack[e->depth].count == 0) {
			e->depth--;
			return 0;
		}
		e->stack[e->depth].cont = o;
		e->stack[e->depth].obj = json_object_array_get_idx(o, 0);
		e->stack[e->depth].index = 0;
	} else if (json_object_is_type(o, json_type_object) || json_object_get_boolean(o)) {
		e->stack[e->depth].count = 1;
		e->stack[e->depth].cont = NULL;
		e->stack[e->depth].obj = o;
		e->stack[e->depth].index = 0;
	} else {
		e->depth--;
		return 0;
	}
	return 1;
}

static int next(void *closure)
{
	struct expl *e = closure;
	if (e->depth <= 0)
		return MUSTACH_ERROR_CLOSING;
	e->stack[e->depth].index++;
	if (e->stack[e->depth].index >= e->stack[e->depth].count)
		return 0;
	e->stack[e->depth].obj = json_object_array_get_idx(e->stack[e->depth].cont, e->stack[e->depth].index);
	return 1;
}

static int leave(void *closure)
{
	struct expl *e = closure;
	if (e->depth <= 0)
		return MUSTACH_ERROR_CLOSING;
	e->depth--;
	return 0;
}

static struct mustach_itf itf = {
	.start = start,
	.put = put,
	.enter = enter,
	.next = next,
	.leave = leave
};

int fmustach_json_c(const char *template, struct json_object *root, FILE *file)
{
	struct expl e;
	e.root = root;
	return fmustach(template, &itf, &e, file);
}

int fdmustach_json_c(const char *template, struct json_object *root, int fd)
{
	struct expl e;
	e.root = root;
	return fdmustach(template, &itf, &e, fd);
}

int mustach_json_c(const char *template, struct json_object *root, char **result, size_t *size)
{
	struct expl e;
	e.root = root;
	return mustach(template, &itf, &e, result, size);
}

