#include "px_template.h"
#include <http_log.h>
#include <apr_strings.h>

#include "px_types.h"
#include "mustach.h"

#ifdef APLOG_USE_MODULE
APLOG_USE_MODULE(perimeterx);
#endif

static const char *page_template_block_web = "<!DOCTYPE html> <html lang=\"en\"> <head> <meta charset=\"utf-8\"> <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"> <title>Access to this page has been denied.</title> <link href=\"https://fonts.googleapis.com/css?family=Open+Sans:300\" rel=\"stylesheet\"> <style> html,body{ margin: 0; padding: 0; font-family: 'Open Sans', sans-serif; color: #000; } a{ color: #c5c5c5; text-decoration: none; } .container{ align-items: center; display: flex; flex: 1; justify-content: space-between; flex-direction: column; height: 100%; } .container > div { width: 100%; display: flex; justify-content:center; } .container > div > div { display: flex; width: 80%; } .customer-logo-wrapper{ padding-top: 2rem; flex-grow: 0; background-color: #fff; visibility: {{logoVisibility}}; } .customer-logo{ border-bottom: 1px solid #000; } .customer-logo > img{ padding-bottom: 1rem; max-height: 50px; max-width: auto; } .page-title-wrapper{ flex-grow: 2; } .page-title { flex-direction: column-reverse; } .content-wrapper{ flex-grow: 5; } .content{ flex-direction: column; } .page-footer-wrapper{ align-items: center; flex-grow: 0.2; background-color: #000; color: #c5c5c5; font-size: 70%; } @media (min-width:768px){ html,body{ height: 100%; } } </style> <!-- Custom CSS --> {{# cssRef }} <link rel=\"stylesheet\" type=\"text/css\" href=\"{{cssRef}}\" /> {{/ cssRef }} </head> <body> <section class=\"container\"> <div class=\"customer-logo-wrapper\"> <div class=\"customer-logo\"> <img src=\"{{customLogo}}\" alt=\"Logo\"/> </div> </div> <div class=\"page-title-wrapper\"> <div class=\"page-title\"> <h1>Access to this page has been denied.</h1> </div> </div> <div class=\"content-wrapper\"> <div class=\"content\"> <p> You have been blocked because we believe you are using automation tools to browse the website. </p> <p> Please note that Javascript and Cookies must be enabled on your browser to access the website. </p> <p> If you think you have been blocked by mistake, please contact the website administrator with the reference ID below. </p> <p> Reference ID: #{{refId}} </p> </div> </div> <div class=\"page-footer-wrapper\"> <div class=\"page-footer\"> <p> Powered by <a href=\"https://www.perimeterx.com/whywasiblocked\">PerimeterX</a> , Inc. </p> </div> </div> </section> <!-- Px --> <script> ( function (){ window._pxAppId = '{{appId}}'; var p = document.getElementsByTagName(\"script\")[0], s = document.createElement(\"script\"); s.async = 1; s.src = '{{{jsClientSrc}}}'; p.parentNode.insertBefore(s, p); {{#firstPartyEnabled}} s.onerror = function() { s = document.createElement('script'); s.src = '//client.perimeterx.net/{{appId}}/main.min.js'; p.parentNode.insertBefore(s,p); }; {{/firstPartyEnabled}} } () ); </script> <!-- Custom Script --> {{# jsRef }} <script src=\"{{jsRef}}\"></script> {{/ jsRef }} </body> </html>";
static const char *page_template_recaptcha_web = "<!DOCTYPE html> <html lang=\"en\"> <head> <meta charset=\"utf-8\"> <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"> <title>Access to this page has been denied.</title> <link href=\"https://fonts.googleapis.com/css?family=Open+Sans:300\" rel=\"stylesheet\"> <style> html,body{ margin: 0; padding: 0; font-family: 'Open Sans', sans-serif; color: #000; } a{ color: #c5c5c5; text-decoration: none; } .container{ align-items: center; display: flex; flex: 1; justify-content: space-between; flex-direction: column; height: 100%; } .container > div { width: 100%; display: flex; justify-content:center; } .container > div > div { display: flex; width: 80%; } .customer-logo-wrapper{ padding-top: 2rem; flex-grow: 0; background-color: #fff; visibility: {{logoVisibility}}; } .customer-logo{ border-bottom: 1px solid #000; } .customer-logo > img{ padding-bottom: 1rem; max-height: 50px; max-width: auto; } .page-title-wrapper{ flex-grow: 2; } .page-title { flex-direction: column-reverse; } .content-wrapper{ flex-grow: 5; } .content{ flex-direction: column; } .page-footer-wrapper{ align-items: center; flex-grow: 0.2; background-color: #000; color: #c5c5c5; font-size: 70%; } @media (min-width:768px){ html,body{ height: 100%; } } </style> <!-- Custom CSS --> {{#cssRef}} <link rel=\"stylesheet\" type=\"text/css\" href=\"{{cssRef}}\" /> {{/cssRef}} <script src=\"https://www.google.com/recaptcha/api.js\" async defer></script> </head> <body> <section class=\"container\"> <div class=\"customer-logo-wrapper\"> <div class=\"customer-logo\"> <img src=\"{{customLogo}}\" alt=\"Logo\"/> </div> </div> <div class=\"page-title-wrapper\"> <div class=\"page-title\"> <h1>Please verify you are a human</h1> </div> </div> <div class=\"content-wrapper\"> <div class=\"content\"> <p> Please click \"I am not a robot\" to continue </p> <div class=\"g-recaptcha\" data-sitekey=\"6Lcj-R8TAAAAABs3FrRPuQhLMbp5QrHsHufzLf7b\" data-callback=\"handleCaptcha\" data-theme=\"dark\"> </div> <p> Access to this page has been denied because we believe you are using automation tools to browse the website. </p> <p> This may happen as a result of the following: </p> <ul> <li> Javascript is disabled or blocked by an extension (ad blockers for example) </li> <li> Your browser does not support cookies </li> </ul> <p> Please make sure that Javascript and cookies are enabled on your browser and that you are not blocking them from loading. </p> <p> Reference ID: #{{refId}} </p> </div> </div> <div class=\"page-footer-wrapper\"> <div class=\"page-footer\"> <p> Powered by <a href=\"https://www.perimeterx.com/whywasiblocked\">PerimeterX</a> , Inc. </p> </div> </div> </section> <!-- Px --> <script> ( function (){ window._pxAppId = '{{appId}}'; var p = document.getElementsByTagName(\"script\")[0], s = document.createElement(\"script\"); s.async = 1; s.src = '{{{jsClientSrc}}}'; p.parentNode.insertBefore(s, p); {{#firstPartyEnabled}} s.onerror = function() { s = document.createElement('script'); s.src = '//client.perimeterx.net/{{appId}}/main.min.js'; p.parentNode.insertBefore(s,p); }; {{/firstPartyEnabled}} } () ); </script> <!-- Captcha --> <script> window.px_vid = '{{vid}}' || ''; function handleCaptcha(response){ var vid = '{{vid}}' || ''; var uuid = '{{uuid}}' || ''; var name = \"_pxCaptcha\"; var expiryUtc = new Date(Date.now()+1000).toUTCString(); var cookieParts = [ name, \"=\", btoa(JSON.stringify({r:response, v:vid, u:uuid})), \"; expires=\", expiryUtc, \"; path=/\" ]; document.cookie = cookieParts.join(\"\"); location.reload(); } </script> <!-- Custom Script --> {{#jsRef}} <script src=\"{{jsRef}}\"></script> {{/jsRef}} </body> </html>";
static const char *page_template_funcaptcha_web = "<!DOCTYPE html> <html lang=\"en\"> <head> <meta charset=\"utf-8\"> <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"> <title>Access to this page has been denied.</title> <link href=\"https://fonts.googleapis.com/css?family=Open+Sans:300\" rel=\"stylesheet\"> <style> html, body { margin: 0; padding: 0; font-family: 'Open Sans', sans-serif; color: #000; } a { color: #c5c5c5; text-decoration: none; } .container { align-items: center; display: flex; flex: 1; justify-content: space-between; flex-direction: column; height: 100%; } .container > div { width: 100%; display: flex; justify-content: center; } .container > div > div { display: flex; width: 80%; } .customer-logo-wrapper { padding-top: 2rem; flex-grow: 0; background-color: #fff; visibility: {{logoVisibility}}; } .customer-logo { border-bottom: 1px solid #000; } .customer-logo > img { padding-bottom: 1rem; max-height: 50px; max-width: 100%; } .page-title-wrapper { flex-grow: 2; } .page-title { flex-direction: column-reverse; } .content-wrapper { flex-grow: 5; } .content { flex-direction: column; } .page-footer-wrapper { align-items: center; flex-grow: 0.2; background-color: #000; color: #c5c5c5; font-size: 70%; } @media (min-width: 768px) { html, body { height: 100%; } } </style> <!-- Custom CSS --> {{# cssRef }} <link rel=\"stylesheet\" type=\"text/css\" href=\"{{ . }}\"/> {{/ cssRef }} <script src=\"https://funcaptcha.com/fc/api/?onload=loadFunCaptcha\" async defer></script> </head> <body> <section class=\"container\"> <div class=\"customer-logo-wrapper\"> <div class=\"customer-logo\"> <img src=\"{{customLogo}}\" alt=\"Logo\"/> </div> </div> <div class=\"page-title-wrapper\"> <div class=\"page-title\"> <h1>Please verify you are a human</h1> </div> </div> <div class=\"content-wrapper\"> <div class=\"content\"> <p> Please click \"Verify\" to continue </p> <div id=\"CAPTCHA\"></div> <p> Access to this page has been denied because we believe you are using automation tools to browse the website. </p> <p> This may happen as a result of the following: </p> <ul> <li> Javascript is disabled or blocked by an extension (ad blockers for example) </li> <li> Your browser does not support cookies </li> </ul> <p> Please make sure that Javascript and cookies are enabled on your browser and that you are not blocking them from loading. </p> <p> Reference ID: #{{refId}} </p> </div> </div> <div class=\"page-footer-wrapper\"> <div class=\"page-footer\"> <p> Powered by <a href=\"https://www.perimeterx.com/whywasiblocked\">PerimeterX</a> , Inc. </p> </div> </div> </section> <!-- Px --> <script> ( function () { window._pxAppId = '{{appId}}'; var p = document.getElementsByTagName(\"script\")[0], s = document.createElement(\"script\"); s.async = 1; s.src = '{{{jsClientSrc}}}'; p.parentNode.insertBefore(s, p); {{#firstPartyEnabled}} s.onerror = function() { s = document.createElement('script'); s.src = '//client.perimeterx.net/{{appId}}/main.min.js'; p.parentNode.insertBefore(s,p); }; {{/firstPartyEnabled}} }() ); </script> <!-- Captcha --> <script> function loadFunCaptcha() { var vid = '{{vid}}'; var uuid = '{{uuid}}'; new FunCaptcha({ public_key: \"19E4B3B8-6CBE-35CC-4205-FC79ECDDA765\", target_html: \"CAPTCHA\", callback: function () { var expiryUtc = new Date(Date.now() + 1000 * 10).toUTCString(); var pxCaptcha = \"_pxCaptcha=\" + btoa(JSON.stringify({r: document.getElementById(\"FunCaptcha-Token\").value, u: uuid, v: vid})); var cookieParts = [ pxCaptcha, \"; expires=\", expiryUtc, \"; path=/\" ]; document.cookie = cookieParts.join(\"\"); location.reload(); } }); } </script> <!-- Custom Script --> {{# jsRef }} <script src=\"{{ . }}\"></script> {{/ jsRef }} </body> </html>";
static const char *page_template_block_mobile ="<!DOCTYPE html> <html lang=\"en\"> <head> <meta charset=\"utf-8\"> <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"> <title>Access to this page has been denied.</title> <link href=\"https://fonts.googleapis.com/css?family=Open+Sans:300\" rel=\"stylesheet\"> <style> html,body{ margin: 0; padding: 0; font-family: 'Open Sans', sans-serif; color: #000; } a{ color: #c5c5c5; text-decoration: none; } .container{ align-items: center; display: flex; flex: 1; justify-content: space-between; flex-direction: column; height: 100%; } .container > div { width: 100%; display: flex; justify-content:center; } .container > div > div { display: flex; width: 80%; } .customer-logo-wrapper{ padding-top: 2rem; flex-grow: 0; background-color: #fff; visibility: {{logoVisibility}}; } .customer-logo{ border-bottom: 1px solid #000; } .customer-logo > img{ padding-bottom: 1rem; max-height: 50px; max-width: auto; } .page-title-wrapper{ flex-grow: 2; } .page-title { flex-direction: column-reverse; } .content-wrapper{ flex-grow: 5; } .content{ flex-direction: column; } .page-footer-wrapper{ align-items: center; flex-grow: 0.2; background-color: #000; color: #c5c5c5; font-size: 70%; } @media (min-width:768px){ html,body{ height: 100%; } } </style> <!-- Custom CSS --> {{# cssRef }} <link rel=\"stylesheet\" type=\"text/css\" href=\"{{ . }}\" /> {{/ cssRef }} </head> <body> <section class=\"container\"> <div class=\"customer-logo-wrapper\"> <div class=\"customer-logo\"> <img src=\"{{customLogo}}\" alt=\"Logo\"/> </div> </div> <div class=\"page-title-wrapper\"> <div class=\"page-title\"> <h1>Access to this page has been denied.</h1> </div> </div> <div class=\"content-wrapper\"> <div class=\"content\"> <p> You have been blocked because we believe you are using automation tools to browse the website. </p> <p> Please note that Javascript and Cookies must be enabled on your browser to access the website. </p> <p> If you think you have been blocked by mistake, please contact the website administrator with the reference ID below. </p> <p> Reference ID: #{{refId}} </p> </div> </div> <div class=\"page-footer-wrapper\"> <div class=\"page-footer\"> <p> Powered by <a href=\"https://www.perimeterx.com/whywasiblocked\">PerimeterX</a> , Inc. </p> </div> </div> </section> <!-- Custom Script --> {{# jsRef }} <script src=\"{{ . }}\"></script> {{/ jsRef }} </body> </html>";
static const char *page_template_recaptcha_mobile = "<!DOCTYPE html> <html lang=\"en\"> <head> <meta charset=\"utf-8\"> <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"> <title>Access to this page has been denied.</title> <link href=\"https://fonts.googleapis.com/css?family=Open+Sans:300\" rel=\"stylesheet\"> <style> html,body{ margin: 0; padding: 0; font-family: 'Open Sans', sans-serif; color: #000; } a{ color: #c5c5c5; text-decoration: none; } .container{ align-items: center; display: flex; flex: 1; justify-content: space-between; flex-direction: column; height: 100%; } .container > div { width: 100%; display: flex; justify-content:center; } .container > div > div { display: flex; width: 80%; } .customer-logo-wrapper{ padding-top: 2rem; flex-grow: 0; background-color: #fff; visibility: {{logoVisibility}}; } .customer-logo{ border-bottom: 1px solid #000; } .customer-logo > img{ padding-bottom: 1rem; max-height: 50px; max-width: auto; } .page-title-wrapper{ flex-grow: 2; } .page-title { flex-direction: column-reverse; } .content-wrapper{ flex-grow: 5; } .content{ flex-direction: column; } .page-footer-wrapper{ align-items: center; flex-grow: 0.2; background-color: #000; color: #c5c5c5; font-size: 70%; } @media (min-width:768px){ html,body{ height: 100%; } } </style> <!-- Custom CSS --> {{#cssRef}} <link rel=\"stylesheet\" type=\"text/css\" href=\"{{cssRef}}\" /> {{/cssRef}} <script src=\"https://www.google.com/recaptcha/api.js\" async defer></script> </head> <body> <section class=\"container\"> <div class=\"customer-logo-wrapper\"> <div class=\"customer-logo\"> <img src=\"{{customLogo}}\" alt=\"Logo\"/> </div> </div> <div class=\"page-title-wrapper\"> <div class=\"page-title\"> <h1>Please verify you are a human</h1> </div> </div> <div class=\"content-wrapper\"> <div class=\"content\"> <p> Please click \"I am not a robot\" to continue </p> <div class=\"g-recaptcha\" data-sitekey=\"6Lcj-R8TAAAAABs3FrRPuQhLMbp5QrHsHufzLf7b\" data-callback=\"handleCaptcha\" data-theme=\"dark\"> </div> <p> Access to this page has been denied because we believe you are using automation tools to browse the website. </p> <p> This may happen as a result of the following: </p> <ul> <li> Javascript is disabled or blocked by an extension (ad blockers for example) </li> <li> Your browser does not support cookies </li> </ul> <p> Please make sure that Javascript and cookies are enabled on your browser and that you are not blocking them from loading. </p> <p> Reference ID: #{{refId}} </p> </div> </div> <div class=\"page-footer-wrapper\"> <div class=\"page-footer\"> <p> Powered by <a href=\"https://www.perimeterx.com/whywasiblocked\">PerimeterX</a> , Inc. </p> </div> </div> </section> <!-- Captcha --> <script> function captchaSolved(res) { window.location.href = '/px/captcha_callback?status=' + res.status; } function handleCaptcha(response) { var appId = '{{appId}}'; var vid = '{{vid}}'; var uuid = '{{uuid}}'; var collectorUrl = '{{{hostUrl}}}'; var req = new XMLHttpRequest(); req.open('POST', collectorUrl + '/api/v1/collector/captcha'); req.setRequestHeader('Content-Type', 'application/json'); req.addEventListener('error', function() { captchaSolved({ status: 1 }); }); req.addEventListener('cancel', function() { captchaSolved({ status: 2 }); }); req.addEventListener('load', function() { if (req.status == 200) { try { var responseJSON = JSON.parse(req.responseText); return captchaSolved(responseJSON); } catch (ex) {} } captchaSolved({ status: 3 }); }); req.send(JSON.stringify({ appId: appId, uuid: uuid, vid: vid, captchaType: '{{captchaType}}', pxCaptcha: response, hostname: window.location.hostname, request: { url: window.location.href } })); } </script> <!-- Custom Script --> {{#jsRef}} <script src=\"{{jsRef}}\"></script> {{/jsRef}} </body> </html>";
static const char *page_template_funcaptcha_mobile = "<!DOCTYPE html> <html lang=\"en\"> <head> <meta charset=\"utf-8\"> <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"> <title>Access to this page has been denied.</title> <link href=\"https://fonts.googleapis.com/css?family=Open+Sans:300\" rel=\"stylesheet\"> <style> html, body { margin: 0; padding: 0; font-family: 'Open Sans', sans-serif; color: #000; } a { color: #c5c5c5; text-decoration: none; } .container { align-items: center; display: flex; flex: 1; justify-content: space-between; flex-direction: column; height: 100%; } .container > div { width: 100%; display: flex; justify-content: center; } .container > div > div { display: flex; width: 80%; } .customer-logo-wrapper { padding-top: 2rem; flex-grow: 0; background-color: #fff; visibility: {{logoVisibility}}; } .customer-logo { border-bottom: 1px solid #000; } .customer-logo > img { padding-bottom: 1rem; max-height: 50px; max-width: 100%; } .page-title-wrapper { flex-grow: 2; } .page-title { flex-direction: column-reverse; } .content-wrapper { flex-grow: 5; } .content { flex-direction: column; } .page-footer-wrapper { align-items: center; flex-grow: 0.2; background-color: #000; color: #c5c5c5; font-size: 70%; } @media (min-width: 768px) { html, body { height: 100%; } } </style> <!-- Custom CSS --> {{# cssRef }} <link rel=\"stylesheet\" type=\"text/css\" href=\"{{ . }}\"/> {{/ cssRef }} <script src=\"https://funcaptcha.com/fc/api/?onload=loadFunCaptcha\" async defer></script> </head> <body> <section class=\"container\"> <div class=\"customer-logo-wrapper\"> <div class=\"customer-logo\"> <img src=\"{{customLogo}}\" alt=\"Logo\"/> </div> </div> <div class=\"page-title-wrapper\"> <div class=\"page-title\"> <h1>Please verify you are a human</h1> </div> </div> <div class=\"content-wrapper\"> <div class=\"content\"> <p> Please click \"Verify\" to continue </p> <div id=\"CAPTCHA\"></div> <p> Access to this page has been denied because we believe you are using automation tools to browse the website. </p> <p> This may happen as a result of the following: </p> <ul> <li> Javascript is disabled or blocked by an extension (ad blockers for example) </li> <li> Your browser does not support cookies </li> </ul> <p> Please make sure that Javascript and cookies are enabled on your browser and that you are not blocking them from loading. </p> <p> Reference ID: #{{refId}} </p> </div> </div> <div class=\"page-footer-wrapper\"> <div class=\"page-footer\"> <p> Powered by <a href=\"https://www.perimeterx.com/whywasiblocked\">PerimeterX</a> , Inc. </p> </div> </div> </section> <!-- Captcha --> <script> function captchaSolved(res) { window.location.href = '/px/captcha_callback?status=' + res.status; } function loadFunCaptcha() { var appId = '{{appId}}'; var vid = '{{vid}}'; var uuid = '{{uuid}}'; var collectorUrl = '{{{hostUrl}}}'; new FunCaptcha({ public_key: \"19E4B3B8-6CBE-35CC-4205-FC79ECDDA765\", target_html: \"CAPTCHA\", callback: function () { var req = new XMLHttpRequest(); req.open('POST', collectorUrl + '/api/v1/collector/captcha'); req.setRequestHeader('Content-Type', 'application/json'); req.addEventListener('error', function () { captchaSolved({ status: 1 }); }); req.addEventListener('cancel', function () { captchaSolved({ status: 2 }); }); req.addEventListener('load', function () { if (req.status == 200) { try { var responseJSON = JSON.parse(req.responseText); return captchaSolved(responseJSON); } catch (ex) { } } captchaSolved({ status: 3 }); }); req.send(JSON.stringify({ appId: appId, uuid: uuid, vid: vid, captchaType: '{{captchaType}}', pxCaptcha: btoa(JSON.stringify({\"u\": uuid, \"v\": vid, \"r\": document.getElementById(\"FunCaptcha-Token\").value})), hostname: window.location.hostname, request: { url: window.location.href } })); } }); } </script> <!-- Custom Script --> {{# jsRef }} <script src=\"{{jsRef}}\"></script> {{/ jsRef }} </body> </html>";

static const char *visible = "visible";
static const char *hidden = "hidden";
static const char *collector_url = "https://collector-%s.perimeterx.net";
static const char *LOGGER_DEBUG_FORMAT = "[PerimeterX - DEBUG][%s] - %s"; 

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
    const char *hostUrl;
    const char *jsClientSrc;
    const char *firstPartyEnabled;
    const char *captchaType;
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
    if (!strcmp(key, "hostUrl")) {
        return props->hostUrl;
    }
    if (!strcmp(key, "jsClientSrc")) {
        return props->jsClientSrc;
    }
    if (!strcmp(key, "firstPartyEnabled")) {
        return props->firstPartyEnabled;
    }
    if (!strcmp(key, "captchaType")) {
        return props->captchaType;
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
        .jsClientSrc = conf->first_party_enabled ? conf->client_path_prefix : conf->client_exteral_path,
        .firstPartyEnabled = conf->first_party_enabled ? "1" : NULL,
        .logoVisibility = conf->custom_logo ? visible : hidden,
        .captchaType = conf->captcha_type == CAPTCHA_TYPE_FUNCAPTCHA ? "funCaptcha" : "reCaptcha",
        .hostUrl =  apr_psprintf(ctx->r->pool, collector_url, conf->app_id, NULL)
    };

    int res = mustach(tpl, &itf, &props, html, size);
    return res;
}

const char* select_template(const px_config *conf, const request_context *ctx) {
    if (ctx->action == ACTION_CHALLENGE) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, ctx->r->server, LOGGER_DEBUG_FORMAT, ctx->app_id, "Enforcing action: challenge page is served");
        return ctx->action_data_body;
    }

    int pt_flag = 0;

    pt_flag |= ctx->token_origin == TOKEN_ORIGIN_COOKIE ? PT_FLAG_WEB : PT_FLAG_MOBILE;

    // select captcha type
    if (ctx->action == ACTION_CAPTCHA) {
        pt_flag = conf->captcha_type == CAPTCHA_TYPE_RECAPTCHA ? (pt_flag | PT_FLAG_RECAPTCHA) : pt_flag;
        pt_flag = conf->captcha_type == CAPTCHA_TYPE_FUNCAPTCHA ? (pt_flag | PT_FLAG_FUNCAPTCHA) : pt_flag;
    }

    //ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, ctx->r->server, "[%s]: select_template: value of template %d", ctx->app_id, pt_flag);

    switch (pt_flag) {
        case PAGE_TEMPLATE_BLOCK_WEB:
            ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, ctx->r->server, LOGGER_DEBUG_FORMAT, ctx->app_id, "Enforcing action: block page is served");
            return page_template_block_web;
        case PAGE_TEMPLATE_RECAPTCHA_WEB:
            ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, ctx->r->server, LOGGER_DEBUG_FORMAT, ctx->app_id, "Enforcing action: captcha page is served");
            return page_template_recaptcha_web;
        case PAGE_TEMPLATE_FUNCAPTCHA_WEB:
            ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, ctx->r->server, LOGGER_DEBUG_FORMAT, ctx->app_id, "Enforcing action: captcha page is served");
            return page_template_funcaptcha_web;
        case PAGE_TEMPLATE_BLOCK_MOBILE:
            ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, ctx->r->server, LOGGER_DEBUG_FORMAT, ctx->app_id, "Enforcing action: block page is served");
            return page_template_block_mobile;
        case PAGE_TEMPLATE_RECAPTCHA_MOBILE:
            ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, ctx->r->server, LOGGER_DEBUG_FORMAT, ctx->app_id, "Enforcing action: captcha page is served");
            return page_template_recaptcha_mobile;
        case PAGE_TEMPLATE_FUNCAPTCHA_MOBILE:
            ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, ctx->r->server, LOGGER_DEBUG_FORMAT, ctx->app_id, "Enforcing action: captcha page is served");
            return page_template_funcaptcha_mobile;
        default:
            ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, ctx->r->server, LOGGER_DEBUG_FORMAT, ctx->app_id, apr_pstrcat(ctx->r->pool, "select_template: wrong value for template ", apr_itoa(ctx->r->pool, pt_flag), ", rendering default web block", NULL));
            return page_template_block_web;
    }
}
