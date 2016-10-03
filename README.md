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
**description** : HTTP header name that contains the real client IP address. Use this feature when your server is behind a CDN.

**required** : No

**default** : NULL

**values** : string

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

        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined

</VirtualHost>
```
