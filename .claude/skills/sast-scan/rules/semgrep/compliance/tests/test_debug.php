<?php
// ruleid: iso27001.a8-9-production-debug-php
define("APP_DEBUG", true);
// ok: iso27001.a8-9-production-debug-php
define("APP_DEBUG", false);
function authenticate() {
    // ruleid: nist800-53.ac3-access-enforcement-php
    if (getenv("APP_ENV") === "development") { return true; }
}
