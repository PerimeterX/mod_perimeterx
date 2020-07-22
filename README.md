[![Build Status](https://travis-ci.org/PerimeterX/mod_perimeterx.svg?branch=travisBuild)](https://travis-ci.org/PerimeterX/mod_perimeterx)
<a href="https://scan.coverity.com/projects/mod_perimeterx">
  <img alt="Coverity Scan Build Status"
       src="https://scan.coverity.com/projects/10339/badge.svg"/>
</a>

![image](https://s.perimeterx.net/logo.png)

[PerimeterX](http://www.perimeterx.com) Apache Module
===========================================

> Latest stable version: [v3.2.0](https://github.com/PerimeterX/mod_perimeterx/releases/tag/v3.2.0)


Table of Contents
-----------------

- [Usage](#usage)
	- [Dependencies](#dependencies)
	- [Installation](#installation)
	- [Basic Usage Example](#basic-usage)
- [Upgrade](#upgrade)
	- [Upgrade to v3.x](#upgrade-v3)
- [Directives](DIRECTIVES.md)
- [Custom Block page](BLOCKPAGE.md)
- [Logging and Troubleshooting](#troubleshoot)
- [Testing](#testing)
- [Contributing](#contributing)
	- [Tests](#tests)


<a name="Usage"></a>

<a name="dependencies"></a> Dependencies
----------------------------------------
- [openssl 1.0.1](https://www.openssl.org/source/)
- [libcurl >= 7.19.0](https://curl.haxx.se/docs/install.html)
- [jansson 2.6](http://www.digip.org/jansson/)
- [Apache Portable Runtime (APR) >= 1.4.6](https://apr.apache.org/)

You can install dependencies using the Linux package manager (```yum``` / ```debian``` packages) or install them manually.

#### Ubuntu users:
```shell
$ sudo apt-get install libtool m4 autoconf automake libjansson-dev libssl-dev libcurl4-openssl-dev apache2-dev
```

### RHEL/CentOS users
```shell
$ sudo yum install -y yum-plugin-ovl
$ sudo yum install wget -y
$ sudo yum install epel-release
$ sudo yum -y groupinstall multilib_policy=all "Development tools"
$ sudo yum -y install httpd-devel jansson-devel libcurl-devel openssl-devel gcc make
```

<a name="installation"></a>Installation
----------------------------------------
```shell
1. $ git clone https://github.com/PerimeterX/mod_perimeterx.git
2. $ cd mod_perimeterx/
3. sh autogen.sh && ./configure && make clean && make && make install
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

### <a name="basic-usage"></a> Basic usage example ###

* Configuration for apache server

```xml
<IfModule mod_perimeterx.c>
    # basic directives
    PXEnabled On
    CookieKey [COOKIE KEY PLACEHOLDER]
    AppID [APPID PLACEHOLDER]
    AuthToken [AUTHTOKEN PLACEHOLDER]
    BlockingScore 100
    ReportPageRequest On
    IPHeader X-True-IP
    MonitorMode On
</IfModule>
```

* Configuration for specific VirtualHost

```xml
<VirtualHost *:80>
        ServerAdmin webmaster@localhost
        DocumentRoot /var/www/html
        <IfModule mod_perimeterx.c>
                PXEnabled On
		CookieKey [COOKIE KEY PLACEHOLDER]
		AppID [APPID PLACEHOLDER]
		AuthToken [AUTHTOKEN PLACEHOLDER]
                BlockingScore 100
		MonitorMode On
                ReportPageRequest On
        </IfModule>
</VirtualHost>
```

### <a name="upgrade"></a> Upgrade ###
#### <a name="upgrade-v3"></a> Upgrade to v3.x ####
#### Default Configurations ####
From v3.x, mod_perimeterx is shipped out in Monitor Mode turned on and BlockingScore set to 100.
For users who wish to set the module to active blocking mode, additonal changes will be required to the module configurations.

Basic example v3.x - Blocking Mode
```
        <IfModule mod_perimeterx.c>
            PXEnabled On
		    AppID [APPID PLACEHOLDER]
		    AuthToken [AUTHTOKEN PLACEHOLDER]
		    CookieKey [COOKIE KEY PLACEHOLDER]
		    MonitorMode Off
        </IfModule>
```

Basic example v3.x - Monitor Mode
```
        <IfModule mod_perimeterx.c>
            PXEnabled On
		    AppID [APPID PLACEHOLDER]
		    AuthToken [AUTHTOKEN PLACEHOLDER]
		    CookieKey [COOKIE KEY PLACEHOLDER]
        </IfModule>
```

#### Custom Block Page upgrade ####
Upgrading to version 3.x will requrie additional changes if CustomBlockPage is enabled.
From v3.x, the enforcer will not handle captcah validations, instead all captcha solving requests will be send direactly to the PerimeterX service from the Javascript handler

Please refer to [Custom Block Page](BLOCKPAGE.md) implementaion for more information

<a name="troubleshoot"></a>Logging and Troubleshooting
----------------------------------------
### Module Logging
mod_perimeterx is capable of writing "Error" and "Debug" type of messages to Apache error log.

In order to log module's messages to Apache error log you should set `LogLevel` [directive](https://httpd.apache.org/docs/2.4/mod/core.html#loglevel) to any value equal or lower than `error` level:
* If mod_perimeterx's `EnableDebugMode` directive is enabled (`On`), then mod_perimeterx will log both "Error" and "Debug" type of messages.
* If mod_perimeterx's `EnableDebugMode` directive is disabled (`Off`), then mod_perimeterx will log only "Error" messages.

Example: to see both "Error" and "Debug" mod_perimeterx messages in Apache error log:
```
# apache configuration
LogLevel error
<IfModule mod_perimeterx.c>
    ...
    EnableDebugMode On
    ...
</IfModule>
```

By the default, `EnableDebugMode` directive is disabled (`Off`), and only "Error" messages are logged.

According to your apache configurations you should find in the error log mod_perimeters log, for example:

```
[Sun Dec 17 09:44:13.799604 2017] [perimeterx:debug] [pid 9] mod_perimeterx.c(235): [PerimeterX - DEBUG][APP_ID] - Starting request verification
[Sun Dec 17 09:44:13.799788 2017] [perimeterx:debug] [pid 9] px_enforcer.c(264): [PerimeterX - DEBUG][APP_ID] - Cookie V3 found, Evaluating
[Sun Dec 17 09:44:13.799884 2017] [perimeterx:debug] [pid 9] mod_perimeterx.c(239): [PerimeterX - DEBUG][APP_ID] - Request context created successfully
[Sun Dec 17 09:44:13.799904 2017] [perimeterx:debug] [pid 9] px_enforcer.c(322): [PerimeterX - DEBUG][APP_ID] - No Captcha cookie present on the request
[Sun Dec 17 09:44:13.799922 2017] [perimeterx:debug] [pid 9] px_payload.c(237): [PerimeterX - DEBUG][APP_ID] - decode_payload: hmac for v3 is b224726ef08887b80b4a09ec3ef55a91536147d8b334fb3f0ae3c43f8dbc678a
[Sun Dec 17 09:44:13.802889 2017] [perimeterx:debug] [pid 9] px_payload.c(352): [PerimeterX - DEBUG][APP_ID] - Cookie evaluation ended successfully, risk score: 0
[Sun Dec 17 09:44:14.216108 2017] [perimeterx:debug] [pid 9] px_client.c(24): [APP_ID]: post_req_request: post request payload  {"type":"page_requested","socket_ip":"172.17.0.1","url":"localhost/","px_app_id":"APP_ID","details":{"block_score":0,"block_reason":"none","http_method":"GET","http_version":"1.1","module_version":"Apache Module v2.8.0-rc.9","px_cookie":"{\\"u\\":\\"d79b83b0-e30e-11e7-9fc6-6f721d4b631d\\",\\"v\\":\\"7f803340-9d42-11e7-83a5-8f78028be852\\",\\"t\\":1513504354651,\\"s\\":0,\\"a\\":\\"c\\"}","client_uuid":"d79b83b0-e30e-11e7-9fc6-6f721d4b631d","pass_reason":"cookie"},"headers":{"Host":"localhost:3000","Connection":"keep-alive","Pragma":"no-cache","Cache-Control":"no-cache","Upgrade-Insecure-Requests":"1","User-Agent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.84 Safari/537.36","Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8","Accept-Encoding":"gzip, deflate, br","Accept-Language":"en-US,en;q=0.9,he;q=0.8","Cookie":"PHPSESSID=h04pp2pbb7atjmrq9ovqc65hqp; _px=YNWJo4NKmRjcSl2lvohGq2KnAixUiBNbQq1AO9D6EkyS8trJ2dJye3oXk8EL53fl1BwW1zH3RJ+d/INP58k4ZQ==:1000:bS5VI9Y33XHl1hMw7X2IAdk83BNYh+VhpETz31+LxrA+xsc/bBkZGB9yAIlaaEZd3r/nujxmcADAvQgmsTrQuGwJGF7Nts85cEG/JnQ+CmoXCBNgLapIvkxYI7MowWDip6oiZ0LPR3JTkuqHdd7efHfG6Ex9Q4HEJ7g4pbIGB68/6mqbN6MkY+3coBtzBwv4iyoxpHPtyst61vA5HbTyw5d+VLEiBqKPezgBYI55F3dMpPDCcC/V+5N//HFWuUZ/oIN0LpzYlXFVK9LBympnvA==; _px3=b224726ef08887b80b4a09ec3ef55a91536147d8b334fb3f0ae3c43f8dbc678a:fhsk7nKkdV5lvBFWsIelUlpgVY44sa3e336YYrJ9T2MQvv5iJLcWYc3aZmICiIq8VqwFryK8BUWZMBDCZ+sdPQ==:1000:9bBom31EJqfEvSyqRHm44tI2OacekjgKioNcnVlBvjSDl/dbQzNXZdHSTZI5m0yIUyAT/kxMjOWdrpO/UR69gVE6ohuy+rR98ttMx/94MD2dHYKMevqN/D7pNNCFelL3s4nM41U88gyIN/ADf7ajwaNRk/XJ1zHFs9P4ipcaqKc="},"vid":"7f803340-9d42-11e7-83a5-8f78028be852"}
```

<a name="testing"></a> Testing
------------------------------

### Code coverage support
By default code coverage is disabled. In order to collect code coverage, configure and build the module with gcov support:
```
./configure --enable-code-coverage
```
Enable mod_perimeterx in Apache configuration, (re-)start Apache and run tests.
Code coverate files will be located in the project's source directory.
[Gcovr](http://gcovr.com/) is a tool to generate HTML files with the code coverage report.
You can run a simple script ```contrib/run_gcovr.sh``` from the project's root directory to generate ```code-coverage.html``` file.


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
