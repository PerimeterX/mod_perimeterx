![image](http://media.marketwire.com/attachments/201604/34215_PerimeterX_logo.jpg)

[PerimeterX](http://www.perimeterx.com) Apache Module
===========================================

Dependencies
----------------------------------------
- [openssl 1.0.1] (https://www.openssl.org/source/) 
- [libcurl >= 7.19.0] (https://curl.haxx.se/docs/install.html) 
- [jansson 2.6](http://www.digip.org/jansson/)
- [Apache Portable Runtime (APR) >=1.4.6](https://apr.apache.org/)

You can install dependencies using linux package manager (```yum``` / ```debian``` packages) or install them manually.

#### Ubuntu users:
```shell
$ sudo apt-get install libjansson-dev
$ sudo apt-get install libcurl4-openssl-dev
$ sudo apt-get install apache2-dev 
```

Installation
----------------------------------------
```shell
$ git clone https://github.com/PerimeterX/mod_perimeterx.git
$ cd mod_perimeterx
$ sudo make
$ apache2ctl restart
```

Make sure that this line is added to your configuration file: 

`LoadModule perimeterx_module $MODULES_PATH/mod_perimeterx.so`

##### Verify installation by listing all installed modules:

```shell
$ httpd -M
Loaded Modules:
 core_module (static)
 so_module (static)
 watchdog_module (static)
 http_module (static)
 ...
 perimeterx_module (shared)
```

## Directives ##

The directives should be under the server configuration.

### `PXEnabled` ###
**description** : Enables the PerimeterX module

**required** : yes

**default** : Off

**values** : On|Off

When set to ```On``` the module will be applied on webpage requests.

### `AppId` ###

**description** : Unique application ID

**required** : yes

**default** : NULL

**values** : string

### `CookieKey` ###
**description** : Cookie signing key

**required** : yes

**default** : NULL

**values** : string

### `AuthToken` ###
**description** : Api authentication token

**required** : yes

**default** : NULL

**values** : string

### `BlockingScore` ###
**description** : Blocking score. When requests with a score of equal or higher value they will be blocked.

**required** : No

**default** : 70

**values** : Integer between 0 and 100

### `Captcha` ###

**description** : Enable reCaptcha on the blocking page. 

***Note***: When using custom block page with captcha abilities implementation - this option must be `On`.

**required** : No

**default** : Off

**values** : On | Off

### `ReportPageRequest` ###

**description** : Enables the ablity to report page requests and blocking activities to PerimeterX

**required** : No

**default** : Off

**values** : On | Off

### `APITimeout` ###
**description** : Timeout, in seconds, for API calles

**required** : No

**default** : 0 (no timeout)

**values** : Integer between 0 and 3

### `IPHeader` ###

**description** : List of HTTP header names that contains the real client IP address. Use this feature when your server is behind a CDN.

**required** : No

**default** : NULL

**values** : List of strings

***Note***: 

* The order of headers in the configuration matters, the first header found with value will be taken as the IP
* If no valid IP address is found in the IP header list the - module will use [`useragent_ip`](https://httpd.apache.org/docs/2.4/developer/new_api_2_4.html) as the requet IP.


### `BlockPageURL`

Apache module allows you to customize your blocking page.

Under this configuration you need to specify the uri to an blocking page html file (relative to servers `DocumentRoot`).

This module will send a redirect response with the `Location` header in this format: 

```
$host/$blockpageURL?url=${original_request_url}&uuid=${uuid}&vid=${vid}
```

Visitor ID (vid) must be extracted from this URL for the captcha JS snippet use (see below for explanation and example).

**required**: No, if not specified the default block page will be used.

**default**: NULL

**value**: String

***Note***: When using custom block page with captcha abilities implementation - `Captcha` configuration  option must be `On`.

#### Blocked user example: 

If I'm blocked when browsing to `http://www.mysite.com/coolpage`, and the server configuration is: 

```xml
BlockPageURL /block.html
```

Redirect URL will be: 

```
http://www.mysite.com/block.html&url=coolpage&uuid=uuid=e8e6efb0-8a59-11e6-815c-3bdad80c1d39&vid=08320300-6516-11e6-9308-b9c827550d47
```


When captcha is enabled, the block page **must** include:

###### Custom blockpage requirements:

* Inside `<head>` section:

```html
<script src="https://www.google.com/recaptcha/api.js"></script>
<script>
function handleCaptcha(response) {
    var vid = getQueryString("vid"); // getQueryString should be implemented 
    var name = '_pxCaptcha';
    var expiryUtc = new Date(Date.now() + 1000 * 10).toUTCString();
    var cookieParts = [name, '=', response + ':' + vid + '; expires=', expiryUtc, '; path=/'];
    document.cookie = cookieParts.join('');
    var originalURL = getQueryString("url");
    var originalHost = window.location.host;
    window.location.href = window.location.protocol + "//" +  originalHost + originalURL;
}
</script>
```
* Inside `<body>` section:

```
<div class="g-recaptcha" data-sitekey="6Lcj-R8TAAAAABs3FrRPuQhLMbp5QrHsHufzLf7b" data-callback="handleCaptcha" data-theme="dark"></div>
```

* [PerimeterX Javascript snippet](https://console.perimeterx.com/#/app/applicationsmgmt).

#### configuration example:
 
```xml
<IfModule mod_perimeterx.c>
	...
	BlockPageURL /blockpage.html
	...
</IfModule>
```

#### Block page implementation example: 

```html
<html>
    <head>
        <script src="https://www.google.com/recaptcha/api.js"></script>
        <script>
        function handleCaptcha(response) {
            var vid = getQueryString("vid");
            var name = '_pxCaptcha';
            var expiryUtc = new Date(Date.now() + 1000 * 10).toUTCString();
            var cookieParts = [name, '=', response + ':' + vid, '; expires=', expiryUtc, '; path=/'];
            document.cookie = cookieParts.join('');
            // after getting resopnse we want to reaload the original page requested
            var originalURL = getQueryString("url");
            var originalHost = window.location.host;
            window.location.href = window.location.protocol + "//" +  originalHost + originalURL;
        }
       
       // http://stackoverflow.com/questions/901115/how-can-i-get-query-string-values-in-javascript
		function getQueryString(name, url) {
		    if (!url) url = window.location.href;
		    name = name.replace(/[\[\]]/g, "\\$&");
		    var regex = new RegExp("[?&]" + name + "(=([^&#]*)|&|#|$)"),
		        results = regex.exec(url);
		    if (!results) return null;
		    if (!results[2]) return '';
		    return decodeURIComponent(results[2].replace(/\+/g, " "));
		}

        </script>
    </head>
    <body>
        <h1>You are Blocked</h1>
        <p>Try and solve the captcha</p> 
        <div class="g-recaptcha" data-sitekey="6Lcj-R8TAAAAABs3FrRPuQhLMbp5QrHsHufzLf7b" data-callback="handleCaptcha" data-theme="dark"></div>
    </body>
<html>
```


### `CurlPoolSize` ###
**description** : The number of active curl handles for each server

**required** : No

**default** : 40

**values** : Integer

### `BaseURL` ###
**description** : PerimeterX API server URL

**required** : No

**default** : https://collector.perimeterx.net

**values** : string

Determines PerimeterX server base URL.

###`SensitiveRoutes`

**descripotion** : List of routes the perimeterx module will always do a server-to-server call for, even if the cookie score is low and valid. 

**required** : No

**default** : Empty list

**values** : whitespace seperated list of string

**example** : `/api/checkout /users/login`


###`PXWhitelistRoutes`

**descripotion** : Whitespace seperated list of paths that will not be examined by PX module. 

**required** : No

**default** : Empty list

**values** : whitespace seperated list of string

**example** : `/server-status /staging`

### `PXWhitelistUserAgents`

**description** : Whitespace seperated list of User-Agents that will not be examined by PX module.

**required**: No

**default** : Empty list

**values** : backspace delimetered list of string

### `ExtensionWhitelist`

**description** : Whitespace seperated list of file extensions that will not be examined by PX module.

**required**: No

**default** : .css, .bmp, .tif, .ttf, .docx, .woff2, .js, .pict, .tiff, .eot, .xlsx, .jpg, .csv,
    .eps, .woff, .xls, .jpeg, .doc, .ejs, .otf, .pptx, .gif, .pdf, .swf, .svg, .ps,
    .ico, .pls, .midi, .svgz, .class, .png, .ppt, .mid, webp, .jar.
    
**Note**: when using this option the default values are cleared and the supplied list will be used instead.

**values** : whitespace delimetered list of strings

**example**: `.txt .css .jpeg`

### `IPRangeWhitelist`

**description** : Whitespace seperated list of `hostaddress/netmask` strings.

**required**: No

**default** : Empty list
    
**Note**: when using this option the default values are cleared and the supplied list will be used instead.

**values** : whitespace delimetered list of strings

**example**: `192.168.0.0/24`


### Example ###

* Configuration for apache server

```xml
<IfModule mod_perimeterx.c>
    PXEnabled On
    CookieKey my_key
    AppID my_app_id
    AuthToken my_auth_token
    BlockingScore 90
    ReportPageRequest On
    IPHeader X-True-IP
    CurlPoolSize 40
    PXWhitelistRoutes /server-status /staging
    PXWhitelistUserAgents "Mozilla/5.0 (Macintosh; Intel Mac OS X) AppleWebKit/534.34 (KHTML,  like Gecko) PhantomJS/1.9.0 (development) Safari/534.34"
    IPRangeWhitelist 192.168.0.0/16
</IfModule>
```

* Configuration for specific VirtuaHost

```xml
<VirtualHost *:80>
        ServerAdmin webmaster@localhost
        DocumentRoot /var/www/html
        <IfModule mod_perimeterx.c>
                PXEnabled On
                CookieKey my_key
                AppID my_app_id
                AuthToken my_auth_token
                BlockingScore 30
                ReportPageRequest On
                Captcha On
        </IfModule>
</VirtualHost>
```
