# Change Log
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/) 
and this project adheres to [Semantic Versioning](http://semver.org/).

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
