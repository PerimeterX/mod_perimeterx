reCAPTCHA Example
-----------------
> This folder contains an example of a reCAPTCHA implementation. The original PerimeterX reCAPTCHA page has been customized, with a different color background, some icons and some colored texts.

In order to use the example:

1. Create a block.html file in your application (or copy the one in this folder).
 The `<body>` section **must** include (replacing <APP_ID> with your PX App ID):

```html
<script>
    window._pxAppId = '<APP_ID>';
    window._pxJsClientSrc = 'https://client.perimeterx.net/<APP_ID>/main.min.js';
    window._pxHostUrl = 'https://collector-<APP_ID>.perimeterx.net';
</script>
<script src="https://captcha.px-cdn.net/<APP_ID>/captcha.js?a=c&m=0"></script>
```
* In the HTML structure, the `<body>` section must include the following line where the Captcha element is to be located:

```
<div id="px-captcha"></div>
```

2. Set the `BlockPageURL` to the location you have just defined (e.g. /block.html)
3. Change the `<APP_ID>` placeholder on the block.html page to the Application ID provided on the PerimeterX Portal.

You are now Blocking requests providing a CAPTCHA to the user for cleanup.
