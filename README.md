[![Build Status](https://travis-ci.org/PerimeterX/mod_perimeterx.svg?branch=travisBuild)](https://travis-ci.org/PerimeterX/mod_perimeterx)

![image](https://s.perimeterx.net/logo.png)

[PerimeterX](http://www.perimeterx.com) Apache Module
===========================================

Table of Contents
-----------------

-   [Usage](#usage)
  *   [Dependencies](#dependencies)
  *   [Installation](#installation)
  *   [Basic Usage Example](#basic-usage)
-   [Directives](#directives)
-   [Contributing](#contributing)
  *   [Tests](#tests)


<a name="Usage"></a>

<a name="dependencies"></a> Dependencies
----------------------------------------
- [openssl 1.0.1](https://www.openssl.org/source/) 
- [libcurl >= 7.19.0](https://curl.haxx.se/docs/install.html) 
- [jansson 2.6](http://www.digip.org/jansson/)
- [Apache Portable Runtime (APR) >=1.4.6](https://apr.apache.org/)
- [pkg-config](https://en.wikipedia.org/wiki/Pkg-config)
- [json-c](https://github.com/json-c/json-c/wiki)

You can install dependencies using the Linux package manager (```yum``` / ```debian``` packages) or install them manually.

#### Ubuntu users:
```shell
$ sudo apt-get install libjansson-dev libjson0 libjson0-dev libssl-dev libcurl4-openssl-dev apache2-dev pkg-config
```

<a name="installation"></a>Installation
----------------------------------------
```shell
$ git clone https://github.com/PerimeterX/mod_perimeterx.git
$ cd mod_perimeterx/src
$ make
$ sudo make install
```

Make sure that the following line is added to your configuration file: 

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

<a name="directives"></a>
## Directives ##

The directives should be under the server configuration.

### <a name="enabled"></a> `PXEnabled` ###
**description** : Enables the PerimeterX module

**required** : yes

**default** : Off

**values** : On|Off

When set to ```On``` the module will be applied on webpage requests.

### <a name="appid"></a> `AppId` ###

**description** : Unique application ID

**required** : yes

**default** : NULL

**values** : string

### <a name="cookiekey"></a> `CookieKey` ###
**description** : Cookie signing key

**required** : yes

**default** : NULL

**values** : string

### <a name="authtoken"></a> `AuthToken` ###
**description** : API authentication token

**required** : yes

**default** : NULL

**values** : string

### <a name="blockingscore"></a>`BlockingScore` ###
**description** : Blocking score. When requests with a score equal to or higher value they will be blocked.

**required** : No

**default** : 70

**values** : Integer between 0 and 100

### <a name="captcha"></a> `Captcha` ###

**description** : Enable reCaptcha on the blocking page. 

***Note***: When using a custom block page with captcha abilities implementation, this option must be `On`.

**required** : No

**default** : On

**values** : On | Off

### <a name="reportpagerequested"></a> `ReportPageRequest` ###

**description** : Enables the ablity to report page requests and blocking activities to PerimeterX.

**required** : No

**default** : On

**values** : On | Off

### <a name="apitimeout"></a> `APITimeout` ###
**description** : Timeout, in seconds, for API calls.

**required** : No

**default** : 1

**values** : Integer between 1 and 3

### <a name="ipheader"></a> `IPHeader` ###

**description** : List of HTTP header names that contain the real client IP address. Use this feature when your server is behind a CDN.

**required** : No

**default** : NULL

**values** : List of strings

***Note***: 

* The order of headers in the configuration matters. The first header found with a value will be taken as the IP address.
* If no valid IP address is found in the IP header list, the module will use [`useragent_ip`](https://httpd.apache.org/docs/2.4/developer/new_api_2_4.html) as the request IP.


### <a name="blockpageurl"></a> `BlockPageURL`

The Apache module allows you to customize your blocking page.

Under this configuration, you need to specify the URL to a blocking page HTML file (relative to servers `DocumentRoot`).

This module will send a redirect response with the `Location` header in the following format: 

```
$host/$blockpageURL?url=${original_request_url}&uuid=${uuid}&vid=${vid}
```

The Visitor ID (vid) must be extracted from this URL for captcha JS snippet use (see below for explanation and example).

**required**: No. If not specified, the default block page will be used.

**default**: NULL

**value**: String

***Note***: When using a custom block page with captcha abilities implemented, the `Captcha` configuration option must be `On`.

#### Blocked user example: 

If I'm blocked when browsing to `http://www.mysite.com/coolpage`, and the server configuration is: 

```xml
BlockPageURL /block.html
```

Redirect URL will be: 

```
http://www.mysite.com/block.html&url=coolpage&uuid=uuid=e8e6efb0-8a59-11e6-815c-3bdad80c1d39&vid=08320300-6516-11e6-9308-b9c827550d47
```


When captcha is enabled, the block page **must** include the following:

###### Custom blockpage requirements:

* Inside `<head>` section:

```html
<script src="https://www.google.com/recaptcha/api.js"></script>
<script>
function handleCaptcha(response) {
    var vid = getQueryString("vid"); // getQueryString is implemented below
    var uuid = getQueryString("uuid");
    var name = '_pxCaptcha';
    var expiryUtc = new Date(Date.now() + 1000 * 10).toUTCString();
    var cookieParts = [name, '=', response + ':' + uuid + ':' + vid, '; expires=', expiryUtc, '; path=/'];
    document.cookie = cookieParts.join('');
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

#### Block page implementation full example: 

```html
<html>
    <head>
        <script src="https://www.google.com/recaptcha/api.js"></script>
        <script>
        function handleCaptcha(response) {
            var vid = getQueryString("vid");
            var uuid = getQueryString("uuid");
            var name = '_pxCaptcha';
            var expiryUtc = new Date(Date.now() + 1000 * 10).toUTCString();
            var cookieParts = [name, '=', response + ':' + uuid + ':' + vid, '; expires=', expiryUtc, '; path=/'];
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

### <a name="curlpoolsize"></a> `CurlPoolSize` ###
**description** : The number of active curl handles for each server

**required** : No

**default** : 40

**max**: 10000

**values** : Integer

> Note: For optimized performance, it is best to use the number of running worker threads in your Apache server as the CurlPoolSize.



### <a name="baseurl"></a> `BaseURL` ###
**description** : PerimeterX API server URL

**required** : No

**default** : https://collector.perimeterx.net

**values** : string

Determines PerimeterX server base URL.

### <a name="baseurl"></a> `SkipModByEnvvar` ###
**description** : Allow to skip PerimeterX module if environment variable `PX_SKIP_MODULE` is set on the request.

**required** : No

**default** : Off

**values** : On|Off

##### Example Use-cases

If you are using `mod_setenvif`, or something similiar, you can configure set of rules for flagging a request with `PX_SKIP_MODULE`. 

Consider the following examples:

* You can consider skipping module for resources of your choice. This configuration will skip module on either `gif` or `jpg`:
 
```
SetEnvIf Request_URI "\.gif$" PX_SKIP_MODULE true
SetEnvIf Request_URI "\.jpg$" PX_SKIP_MODULE true
```

* This will skip module according to the referer:

```
SetEnvIf Referer www\.mydomain\.example\.com PX_SKIP_MODULE true
```

* This will skip all `HEAD` requests:

```
SetEnvIf Request_Method HEAD PX_SKIP_MODULE true
```

* If you are using an internal test client of some sort you can skip px module by it's user agnet:

```
SetEnvIf User-Agent good-bot PX_SKIP_MODULE true
```

> **Read more on `mod_setenvif` [here](https://httpd.apache.org/docs/current/mod/mod_setenvif.html).**


### <a name="sensitiveroutes"></a> `SensitiveRoutes`

**descripotion** : List of routes the Perimeterx module will always do a server-to-server call for, even if the cookie score is low and valid. 

**required** : No

**default** : Empty list

**values** : A whitespace seperated list of strings.

**example** : `/api/checkout /users/login`

###`SensitiveRoutesPrefix`

**descripotion** : List of routes prefix. The Perimeterx module will always match request uri by this prefix list and if match was found will create a server-to-server call for, even if the cookie score is low and valid. 

**required** : No

**default** : Empty list

**values** : A whitespace seperated list of strings.

**example** : `/api /users`


###<a name="whitelistroutes"></a> `PXWhitelistRoutes`

**descripotion** : A whitespace seperated list of paths that will not be examined by PX module. 

**required** : No

**default** : Empty list

**values** : A whitespace seperated list of strings.

**example** : `/server-status /staging`

### <a name="whitelistuseragent"></a> `PXWhitelistUserAgents`

**description** : A whitespace seperated list of User-Agents that will not be examined by PX module.

**required**: No

**default** : Empty list

**values** : A backspace delimited list of strings.

### <a name="extensionwhitelist"></a> `ExtensionWhitelist`

**description** : A whitespace seperated list of file extensions that will not be examined by PX module.

**required**: No

**default** : .css, .bmp, .tif, .ttf, .docx, .woff2, .js, .pict, .tiff, .eot, .xlsx, .jpg, .csv,
    .eps, .woff, .xls, .jpeg, .doc, .ejs, .otf, .pptx, .gif, .pdf, .swf, .svg, .ps,
    .ico, .pls, .midi, .svgz, .class, .png, .ppt, .mid, webp, .jar.
    
**Note**: When using this option, the default values are cleared and the supplied list will be used instead.

**values** : A whitespace delimited list of strings.

**example**: `.txt .css .jpeg`

### `EnableBlockingByHostname`

**description** : A whitespace seperated list of hostnames that PX module will enable block for.

**required**: No

**default** : Empty list
    
> **Note**: If this option is persent - only hostnames appear in this list will pass through mod_perimeterx.

**values** : A whitespace delimited list of strings.

**example**: `www.mysite.com www.mynewsite.com `

## <a name="custom-block-page"></a> Customizing Default Block Pages

**Custom logo insertion**

### `CustomLogo`

**description**: The logo will be displayed at the top div of the the block page.
The logo's ```max-heigh``` property would be 150px and width would be set to ```auto```. 

`CustomLogo` directive will except valid URL.

**required**: No

**default**: NULL

**example**: ```https://s.perimeterx.net/logo.png```

**Custom JS/CSS**

### `CSSRef`

**description**: The block page can be modified with a custom CSS by adding the ```CSSRef``` directive and providing a valid URL to the css.

**required**: No

**default**: NULL

**example**: ```https://s.perimeterx.net/style.css```

### `JSRef` 

**description**: The block page can be added with custom JS file by adding ```JSRef``` directive and providing the JS file that will be loaded with the block page.

**required**: No

**default**: NULL

**example**: ```https://s.perimeterx.net/myscript.js```

### <a name="example"></a> Example ###

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

<a name="contributing"></a> Contributing
----------------------------------------

The following steps are welcome when contributing to our project.
### Fork/Clone
First and foremost, [Create a fork](https://guides.github.com/activities/forking/) of the repository, and clone it locally.
Create a branch on your fork, preferably using a self descriptive branch name.

### Code/Run
Code your way out of your mess, and help improve our project by implementing missing features, adding capabilites or fixing bugs.

To run the code, simply follow the steps in the [installation guide](#installation). Grab the keys from the PerimeterX Portal, and try refreshing your page several times continously. If no default behaviours have been overriden, you should see the PerimeterX block page. Solve the CAPTCHA to clean yourself and start fresh again.

### Pull Request
After you have completed the process, create a pull request to the Upstream repository. Please provide a complete and thorough description explaining the changes. Remember this code has to be read by our maintainers, so keep it simple, smart and accurate.

### Thanks
After all, you are helping us by contributing to this project, and we want to thank you for it.
We highly appreciate your time invested in contributing to our project, and are glad to have people like you - kind helpers.
