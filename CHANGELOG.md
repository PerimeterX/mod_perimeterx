# Change Log
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/) 
and this project adheres to [Semantic Versioning](http://semver.org/).

## [3.1.1] - 01-10-2020
### Fixed
 * Empty 304/204 responses handling.
 * Handling mobile SDK response when `BlockPageURL` is set.

## [3.1.0] - 12-11-2019
### Fixed
 * Handle no content on first party response

## [3.0.0] - 06-11-2018
### Added 
 * Remote configuration support
 * Enforcer telemetry support
 * Improved background activity handling, using curl multi instead of threads
 * Configurable debug mode via config (refer to readme)
 * Implemented connection timeout (supported by remote configurations)

### Fixed
 * First party error handling
 * Attaching XFF header to reverse proxy requests

### Changes
 * Default values were changed:
 	* Blocking score: 100
	* Monitor Mode: true

## [2.11.1] - 04-20-2018
* Fixed Debian packaging  

## [2.11.0] - 04-11-2018
* Added autoconf support, make sure to follow the installation instructions, package dependencies have changed
* Fixed bug in PXMonitorService
* Fixed apache crash when module is not configured properly
* Fixed possible memory leak in debug mode
* Memory optimizations - using apr instead of malloc

## [2.10.1] - 03-15-2018
* Fixed potential memory leak on first party while reading body
* Fixed first party XHR flag
* Fixed crash on empty configuration 

## [2.10.0] - 03-01-2018
* Added support for OpenSSL 1.1.0

## [2.9.1] - 02-26-2018
* Fixed base64 padding handling

## [2.9.0] - 02-21-2018
* Added support for removing captcha cookie on subdomain wildcard, disabled by default
* Added first party support, enabled by default - please note that additional changes may be required, refer to directives for more information
* Added support for funCaptcha on mobile

## [2.9.1] - 02-27-2018
* Fixed base64 handling for cookies 

## [2.9.0] - 02-21-2018
* Added support for removing captcha cookie on subdomain wildcard, disabled by default
* Added first party support, enabled by default - please note that additional changes may be required, refer to directives for more information
* Added support for funCaptcha on mobile

## [2.8.0] - 01-22-2018
* Added support for APR 1.4.6
* Added support for js challenge
* Added new logs format
 -- RC Changes Below
* Added CORS support
* Added Monitor Mode, default mode is Off
* Added support new captcha flow
* Added support Cookie V3
* Added support for funCaptcha
* Modified rendering block pages by action
* Fixed internal request handling
* Fixed mobile sdk and configurations
* Improved stability and memory allocations 
* Improved SSL Optimizations

## [2.8.0-rc.9] 11-20-2017
* Init and clean OpenSSL with threading support 
* Switched background activities to off by default\
* Added debug symbols to debian installation
* Fixed reCaptcha support for mobile sdk
* Memory leak optimizations
* Fixed payload v1 action value

## [2.8.0-rc.8] 10-03-2017
* Support to modify CORS header by setting the Allow header using an envvar regex set on PXApplyAccessControlAllowOriginByEnvVar configs
* Enabling wildcard CORS header with EnableAccessControlAllowOriginWildcard configuration

## [2.8.0-rc.7] 10-03-2017
* Support to modify CORS header by setting the Allow header using an envvar regex set on PXApplyAccessControlAllowOriginByEnvVar configs
* Enabling wildcard CORS header with EnableAccessControlAllowOriginWildcard configuration

## [2.8.0-rc.6] 10-03-2017
* Fixed crash when module gets empty header
* Fixed cookie v1 score
* Fixed BaseUrl set before AppId

## [2.8.0-rc.5] 9-28-2017
* Change the default configuration values, MonitorMode set to false and BlockingScore set to 101

## [2.8.0-rc.4] 9-27-2017
* Fixed internal request would not be inspected
* Added missing directives in docs

## [2.8.0-rc.3] 9-14-2017
* Added support for cookie v3 
* Rendering block page by action value
* Added monitor mode
* Added new captcah capabilities
* New configuratio key, CaptchaType
* Update default values for directives, mobile sdk, async activites, by defualt set to true

## [2.8.0-rc.1] 9-06-2017
* Added support for CORS headers
* Better handling for threads

## [2.7.0] - 8-16-2017
* Update default values for blocking score 

## [2.6.3] - 8-16-2017
* fixed missing debug messages

## [2.6.2] - 8-16-2017
* New call_reason for mobile sdk connection error

## [2.6.1] - 8-09-2017
* Sending content-type application/json when needed

## [2.6.0] - 8-09-2017
* Added support for a json response when expecting application/json response 
* Remove json-c dependency.

## [2.5.0] - 7-31-2017
* Added UuidHeader on response 
* Added VidHeader on response 

## [2.4.2] - 7-24-2017

* Remove special handling for POST requests.

## [2.4.1] - 7-13-2017

* Add ScoreHeader on request instead of response.

## [2.4.0] - 7-10-2017

* Add UUID to page_requested.
* Add score header to response.
* Add `CaptchaTimeout` for captcha requests.

## [2.3.1] - 5-30-2017

* Bug fixes.

## [2.3.0] - 5-25-2017

* Proxy support via `ProxyURL` directive.

## [2.2.0] - 5-22-2017

* Disable `mod_perimeterx` when reaching errors threshod. 
* Monitor PX service health.
* Background `block` / `page_requested` activities send.
* `APITimeoutMS` to set timeout in milliseconds and not seconds.
* Add `pass_reason` to `page_requested` - Indicating the reason PX module passed the request.
* Moved to `risk_api` V2.
* Prefixing `mod_perimeterx` logs with `app_id`.
* Changed cookie handle log level to debug from error.

## [2.1.0] - 4-07-2017
### Added 

* `SkipModByEnvvar` Directive for skipping `mod_perimeterx` on request if the environment variable `PX_SKIP_MODULE` is set on the request.


## [2.0.0] - 3-22-2017
### Changed 

* Redesign block/captcha page.
* Handle invalid `_px` and `_pxCaptcha` cookie format.
* Bug fixes.

### Added
* Support custom css/javascript/logo on block page.

## [1.0.10] - 1-1-2017
### Added

- Adding px_cookie to page_requested.
- Adding uuid to captcha api request.

### Changed
- Base server url from: `https://sapi.perimeterx.net ` to `https://sapi-${app_id}.glb1.perimeterx.net `

## [1.0.9] - 12-26-2016
### Added

- Enable module block mode per request hostname.
- Allow prefix match for seneitive page configuration.

### Changed
- Base server url from: `https://sapi.perimeterx.net ` to `https://sapi-${app_id}.glb1.perimeterx.net `
