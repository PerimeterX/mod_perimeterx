Custom Block Page
===========================================
This section will discuss about implementing block page by the user. 

This is relevant only when `BlockPageURL` is set.

When BlockPageURL is set to some `$blockpageURL` - mod_perimeter will send a redirect response with the `Location` header in the following format: 

```
$host/$blockpageURL?url=${original_request_url}&uuid=${uuid}&vid=${vid}
```

The Visitor ID (vid) and request reference must be extracted from this URL for captcha JS snippet use 

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

###### Custom blockpage requirements:
For custom block implementaitons please refer to the links below:

* [Block page with reCaptcha](examples/Custom Block Page reCAPTCHA Redirect/README.md)
* [Block page with funCaptcha](examples/Custom Block Page funCAPTCHA Redirect/README.md)
* [Block page without Captcha](examples/Custom Block Page/README.md)

* [PerimeterX Javascript snippet](https://console.perimeterx.com/botDefender/admin?page=applicationsmgmt).
#### Configuration example:
 
```xml
<IfModule mod_perimeterx.c>
	...
	BlockPageURL /blockpage.html
	...
</IfModule>
```
