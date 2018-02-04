Directives
===========================================

- [Basic](#basic)
- [Filters](#filters)
- [Customizing block page](#blockpage)
- [PerimeterX Service monitor](#servicemonitor)


## <a name="#basic"></a>Basic 

|Directive Name| Description   | Default value   | Values  | Note
|---|---|---|---|---|
| PXEnabled   | Flag for enabling \ disabling Perimeterx protection, Off - disabled, On - enabled	 | Off  | On / Off |
| AppId  | PX custom application id in the format of PX______	  | NULL | String  |
| CookieKey  | Key used for cookie signing - Can be found \ generated in PX portal - Policy page. | NULL  |   |   |
| AuthToken | JWT token used for REST API - Can be found \ generated in PX portal - Application page.  | NULL  | String |
| BlockingScore | When requests with a score equal to or higher value they will be blocked.  | 101  | 0 - 100  |
| Captcha | Enable reCaptcha on the blocking page  | On  | On / Off  | When using a custom block page with captcha abilities implementation, this option must be `On`.
| ReportPageRequest | Boolean flag to enable or disable sending activities and metrics to PerimeterX on each page request. Enabling this feature will provide data that populates the PerimeterX portal with valuable information	  |  On | On / Off  |
| APITimeoutMS |  REST API timeout in milliseconds | 1000  | Integer  | In case APITimeoutMS and APITimeout (deprecated but supported for backward compatibility) are both set in the module configuration - the one that is set later in the file will be the one that will be used. Any other value set prior of it will be discarded.
| CaptchaTimeout |  Captcha timeout in milliseconds | APITimeoutMS  | Integer  |  If not set - CaptchaTimeout is the same as APITimeoutMS
| IPHeader | List of HTTP header names that contain the real client IP address. Use this feature when your server is behind a CDN. | NULL | List |  [IPHeader Additional Information](#ipheader)
| CurlPoolSize | The number of active curl handles for each server  | 100  | Integer 1-1000  | For optimized performance, it is best to use the number of running worker threads in your Apache server as the CurlPoolSize.
| BaseURL |  Determines PerimeterX server base URL. | https://sapi-\<app_id\>.perimeterx.net  | String |
| ProxyURL |  Proxy URL for outgoing PerimeterX service API | NULL  | String |
| ScoreHeader |  Enable request score to be placed on the response headers | Off  | On / Off |
| ScoreHeaderName |  Sets the header key on the response object that holds the risk score  | X-PX-SCORE  | String | Works only when `ScoreHeader` is set to On
| VidHeader |  Enables VID to be placed on the response headers | Off  | On / Off |
| VidHeaderName | Sets the key for the VID header on the response | X-PX-VID  | String | Works only when `VidHeader` is set to On |
| UuidHeader | Enables UUID to be placed on the response headers | Off  | On / Off |
| UuidHeaderName | Sets the key for the UUID header on the response | X-PX-UUID  | String | Works only when `UuidHeader` is set to On |
| EnableJsonResponse | Turn on response json when accept headers are `application/json` | Off | bool | On / Off |
| PXApplyAccessControlAllowOriginByEnvVar | Take the value of a defined environmental variable and apply it as the value of the response header Access-Control-Allow-Origin on a blocked response. If the value of the environmental variable is not a compliant URI (scheme "://" host [ ":" port ]; <scheme>, <host>, <port> from RFC 3986) then it will not be applied| NULL  | String | Only enabled when a value is provided|
| EnableAccessControlAllowOriginWildcard | Apply **\*** as the value of the response header Access-Control-Allow-Origin. When set this directive will override **PXApplyAccessControlAllowOriginByEnvVar** if it is also defined. | Off | Bool | On / Off|
| CaptchaType | Sets the type of which captcha provider to use | reCaptcha  | String | reCaptcha/funCaptcha |
| EnableTokenViaHeader | Toggles on/off using mobile sdk| On | bool | On / Off |
| BackgroundActivitySend | Toggles on/off asyncrounus activity reporting | On | bool | On / Off |
| BackgroundActivityWorkers | Number of background workers to send activities | 10 | Number | Integer |
| BackgroundActivityQueueSize | Queue size for background activity send | 1000 | Number | Integer |
| MonitorMode | Toggles the module monitor | False | bool | On / Off |
| CaptchaSubdomain | Toggles captcha on subdomain making the module remove pxCaptcha cookie from all domains under main domain (will use .<domain>.<ext> instead of www.<domain>.<ext>)| False | bool | On / Off |
#### <a name="ipheader">IPHeader Additional Information</a>: 

* The order of headers in the configuration matters. The first header found with a value will be taken as the IP address.
* If no valid IP address is found in the IP header list, the module will use [`useragent_ip`](https://httpd.apache.org/docs/2.4/developer/new_api_2_4.html) as the request IP.

## <a name="blockpage"></a>Customizing block page:
| Directive Name |                                                                  Description                                                                  | Default value | Values |                                 Note                                 |
|:--------------:|:---------------------------------------------------------------------------------------------------------------------------------------------:|:-------------:|:------:|:--------------------------------------------------------------------:|
|  BlockPageURL  |                                                     [Explanation & Examples](BLOCKPAGE.md)                                                    |      NULL     | String | The block page URL should be specified as relative to `DocumentRoot` |
|   CustomLogo   | The logo will be displayed at the top div of the the block page. The logo's max-height property would be 150px and width would be set to auto. |      NULL     | String |                                                                      |
|     CSSRef     |              The block page can be modified with a custom CSS by adding the CSSRef directive and providing a valid URL to the css             |      NULL     | String |                                                                      |
|      JSRef     |  The block page can be added with custom JS file by adding JSRef directive and providing the JS file that will be loaded with the block page. |      NULL     | String |                                                                      |



## <a name="#filters"></a>Filters 

|     Directive Name    |                                                                                                Description                                                                                               | Default value |  Values  |          Note           |
|:---------------------:|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------:|:-------------:|:--------:|:-----------------------:|
|    SensitiveRoutes    | List of routes the Perimeterx module will always do a server-to-server call for, even if the cookie score is low and valid                                                                               | Empty list    | List     |  /login                       |
| SensitiveRoutesPrefix | List of routes prefix. The PerimeterX module will always match request URI by this prefix list and if match was found will create a server-to-server call for, even if the cookie score is low and valid | Empty list    | List     |                         |
|   DisableModByEnvvar  | Disables the PerimeterX module if environment variable `PX_SKIP_MODULE` is set on the request.                                                                                                           | Off           | On / Off | [Examples and Use cases](#disablemodenvvar)  |
|   PXWhitelistRoutes   | A whitespace separated list of paths prefixes that will not be examined by PX module.                                                                                                                             | Empy list     | List     | /server-status /staging |
| PXWhitelistUserAgents | A whitespace separated list of User-Agents that will not be examined by PX module.                                                                                                                       | Empty list    | List     |                         |
| ExtensionWhitelist    | A whitespace separated list of file extensions that will not be examined by PX module. | .css, .bmp, .tif, .ttf, .docx, .woff2, .js, .pict, .tiff, .eot, .xlsx, .jpg, .csv,,.eps, .woff, .xls, .jpeg, .doc, .ejs, .otf, .pptx, .gif, .pdf, .swf, .svg, .ps,,.ico, .pls, .midi, .svgz, .class, .png, .ppt, .mid, webp, .jar. | List | When using this option, the default values are cleared and the supplied list will be used |
| EnableBlockingByHostname |     A whitespace separated list of hostnames that PX module will enable block for.     |                                                                                                              Empy list                                                                                                             | List | If this option is present - only hostnames appear in this list will pass through mod_perimeterx. |


#### <a name="disablemodenvvar"></a>DisableModByEnvvar Examples and Use cases:

By using `mod_setenvif` you can configure a set of rules to set the `PX_SKIP_MODULE` variable on a request.

* Disable the PerimeterX module on either `gif` or `jpg` file extensions:
 
```
SetEnvIf Request_URI "\.gif$" PX_SKIP_MODULE true
SetEnvIf Request_URI "\.jpg$" PX_SKIP_MODULE true
```

* Disable the PerimeterX module according to the referer:

```
SetEnvIf Referer www\.mydomain\.example\.com PX_SKIP_MODULE true
```

* Disable the PerimeterX module on all `HEAD` requests:

```
SetEnvIf Request_Method HEAD PX_SKIP_MODULE true
```

* Disable the PerimeterX module based on the user-agent string:

```
SetEnvIf User-Agent good-bot PX_SKIP_MODULE true
```

#### <a name="corsheader"></a> PXApplyAccessControlAllowOriginByEnvVar Examples

By using `mod_setenvif` you can configure a set of rules to set an environmental variable on a request that takes the value of the **Origin** header.  If a value is present, its value will be set for the header `Access-Control-Allow-Origin`
Note that the directive `PXApplyAccessControlAllowOriginByEnvVar` must be configured with the environmental variable name.

Examples below:
```
SetEnvIfNoCase Origin ^(.*) PX_APPLY_CORS_VALUE=$1 
```

```
SetEnvIf Origin "http(s)?://(www\.)?(google.com|staging.google.com|development.google.com)$" PX_APPLY_CORS_VALUE=$0
```

Read more on `mod_setenvif` [here](https://httpd.apache.org/docs/current/mod/mod_setenvif.html).
 
**`mod_env` is not supported with any directives that use the environmental variables set on a request. Though the syntax is similar to mod_setenvif, mod_env will only run after the PerimeterX module in the Apache fixups phase. You should NOT use the `SetEnv` directive to set the `PX_SKIP_MODULE` or `PX_APPLY_CORS_VALUE` environmental variables.

## <a name="#filters"></a>PerimeterX Service Monitor

When `PXServiceMonitor` is set to `On` - the module will count errors from PerimeterX service and if the number of errors on the specific apache instance will reach `MaxPXErrorsThreshold` in `PXErrorsCountInterval` seconds - fail open strategy will be activated and the requests will pass PerimeterX module without causing any delays.

In the background there will be periodic health check with PerimeterX service and once service is healthy - the module will start handling requests again.

|     Directive Name    |                                                                                                        Description                                                                                                       | Default value |  Values  | Note |
|:---------------------:|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------:|:-------------:|:--------:|:----:|
|    PXServiceMonitor   |                                     Boolean flag to allow self disable PerimeterX module when PerimeterX service is unhealthy and periodic examine the service until it is healthy.                                      |      Off      | On / Off |      |
|  MaxPXErrorsThreshold |                                                        Number  of allowed PerimeterX service errors (during an interval) until we will block the PerimeterX module                                                       |       10      |  Integer |      |
| PXErrorsCountInterval | Time interval - In milliseconds -  in which we will count any kind of non successful call for PerimeterX service - when time is reached, without reaching the MaxPXErrorsThreshold, the counter will be set back to zero |    60000 |  Integer |      |




