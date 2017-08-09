#include "px_template.h"

#include "mustach.h"

static const char *visible = "visible";
static const char *hidden = "hidden";

typedef struct px_props_t {
    int depth;
    const char *appId;
    const char *refId;
    const char *vid;
    const char *uuid;
    const char *customLogo;
    const char *cssRef;
    const char *jsRef;
    const char *logoVisibility;
} px_props;

static const char *get_px_props_value(const px_props *props, const char *key) {
    if (!strcmp(key, "appId")) {
        return props->appId;
    }
    if (!strcmp(key, "refId")) {
        return props->refId;
    }
    if (!strcmp(key, "vid")) {
        return props->vid;
    }
    if (!strcmp(key, "uuid")) {
        return props->uuid;
    }
    if (!strcmp(key, "customLogo")) {
        return props->customLogo;
    }
    if (!strcmp(key, "cssRef")) {
        return props->cssRef;
    }
    if (!strcmp(key, "jsRef")) {
        return props->jsRef;
    }
    if (!strcmp(key, "logoVisibility")) {
        return props->logoVisibility;
    }
    return NULL;
}

static int start(void *closure) {
    px_props *props = (px_props *)closure;
    props->depth = 0;
    return 0;
}

static void print(FILE *file, const char *string, int escape) {
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

static int put(void *closure, const char *name, int escape, FILE *file) {
    const px_props *props = (const px_props *)closure;
    const char *v = get_px_props_value(props, name);
    if (v) {
        print(file, v, escape);
    }
    return 0;
}

static int enter(void *closure, const char *name) {
    px_props *props = (px_props *)closure;
    if (++props->depth >= 255) {
        return MUSTACH_ERROR_TOO_DEPTH;
    }
    if (props->depth == 1 && get_px_props_value(props, name)) {
        return 1;
    }
    props->depth--;
    return 0;
}

static int next(void *closure) {
    px_props *props = (px_props *)closure;
    return (props->depth > 0) ? 0 : 1;
}

static int leave(void *closure) {
    px_props *props = (px_props *)closure;
    if (props->depth <= 0) {
        return MUSTACH_ERROR_CLOSING;
    }
    props->depth--;
    return 0;
}

static struct mustach_itf itf = {
    .start = start,
    .put = put,
    .enter = enter,
    .next = next,
    .leave = leave
};

int render_template(const char *tpl, char **html, const request_context *ctx, const px_config *conf, size_t *size) {
    px_props props = {
        .appId = conf->app_id,
        .uuid = ctx->uuid,
        .vid = ctx->vid,
        .refId = ctx->uuid,
        .customLogo = conf->custom_logo,
        .cssRef = conf->css_ref,
        .jsRef = conf->js_ref,
        .logoVisibility = conf->custom_logo ? visible : hidden,
    };
    int res = mustach(tpl, &itf, &props, html, size);
    return res;
}

