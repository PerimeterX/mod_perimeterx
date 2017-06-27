Custom Block Page
===========================================
This section will discuss about implementing block page by the user. 

This is relevant only when `BlockPageURL` is set.

When BlockPageURL is set to some `$blockpageURL` - mod_perimeter will send a redirect response with the `Location` header in the following format: 

```
$host/$blockpageURL?url=${original_request_url}&uuid=${uuid}&vid=${vid}
```

The Visitor ID (vid) must be extracted from this URL for captcha JS snippet use (see below for explanation and example).

> Note: When using a custom block page with captcha abilities implemented, the `Captcha` configuration option must be `On`.

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

#### Configuration example:
 
```xml
<IfModule mod_perimeterx.c>
	...
	BlockPageURL /blockpage.html
	...
</IfModule>
```

#### Block page implementation full example: 

```html
<!DOCTYPE html>
<html>

<head>
    <title>Access to this page is denied.</title>
    <!-- REQUIRED Google Recaptha JS file -->
    <script src="https://www.google.com/recaptcha/api.js"></script>
    <!-- REQUIRED PerimeterX JS snippet -->
    <!-- Replace this section with your PerimeterX tag. -->
    <script type="text/javascript">
    (function() {
        window._pxAppId = 'PX01234567';
        // Custom parameters
        // window._pxParam1 = "<param1>";
        var p = document.getElementsByTagName('script')[0],
            s = document.createElement('script');
        s.async = 1;
        s.src = '//client.perimeterx.net/PX01234567/main.min.js';
        p.parentNode.insertBefore(s, p);
    }());
    </script>
    <noscript>
        <div style="position:fixed; top:0; left:0;" width="1" height="1">
            <img src="//collector-PX01234567.perimeterx.net/api/v1/collector/noScript.gif?appId=PX01234567">
        </div>
    </noscript>
    <!-- REQUIRED Call back handler for reCaptcha and query string function -->
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
        window.location.href = window.location.protocol + "//" + originalHost + originalURL;
    }

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
    <div class="page-title-wrapper">
        <div class="page-title">
            <h1>Please verify you are a human</h1>
        </div>
    </div>
    <div class="content-wrapper">
        <div class="content">
            <p>
                Please click "I am not a robot" to continue
            </p>
            <!-- REQUIRED Google Recaptha div w/ PX site key -->
            <div class="g-recaptcha" data-sitekey="6Lcj-R8TAAAAABs3FrRPuQhLMbp5QrHsHufzLf7b" data-callback="handleCaptcha" data-theme="dark">
            </div>
            <p>
                Access to this page has been denied because we believe you are using automation tools to browse the website.
            </p>
            <p>
                This may happen as a result of the following:
            </p>
            <ul>
                <li>
                    Javascript is disabled or blocked by an extension. For example ad blockers and other tools can prevent neccessary parts of the website from loading.
                </li>
                <li>
                    Your browser does not support cookies or you have disabled them.
                </li>
            </ul>
            <p>
                Please make sure that Javascript and cookies are enabled on your browser and that you are not blocking them from loading.
            </p>
            <p id="referenceID">
            </p>
        </div>
    </div>
    <!-- REQUIRED Sets the reference ID to be displayed on the page -->
    <script type="text/javascript">
    var uuid = getQueryString("uuid");
    var referenceID = document.getElementById("referenceID");
    referenceID.innerHTML = "Reference ID: " + uuid;
    </script>
</body>
<html>
```
