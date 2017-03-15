#include "px_template.h"

#include "mustach-json-c.h"
#include <json-c/json.h>

const char *visible = "visible";
const char *hidden = "hidden";

void put_props(json_object *root, const char* prop_name, const char* prop_value){
  if (prop_value){
     json_object *str = json_object_new_string(prop_value);
     json_object_object_add(root, prop_name, str);
  }
}

void get_props(json_object *root, const px_config *conf, const request_context *ctx){
  put_props(root, "appId", conf->app_id);
  put_props(root, "refId", ctx->uuid);
  put_props(root, "vid", ctx->vid);
  put_props(root, "uuid", ctx->uuid);
  put_props(root, "customLogo", conf->custom_logo);
  put_props(root, "cssRef", conf->css_ref);
  put_props(root, "jsRef", conf->js_ref);
  put_props(root, "logoVisibility", conf->custom_logo ? visible : hidden);
}

int render_template(const char *tpl, char **html, const request_context *ctx, const px_config *conf, size_t *size) {
  json_object *props = json_object_new_object();
  get_props(props, conf, ctx);
  int res = mustach_json_c(tpl, props, html, size);
  json_object_put(props);
  return res;
}

