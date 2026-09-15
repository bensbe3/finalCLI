<?php
// INTENTIONALLY VULNERABLE test fixture - never deploy or copy.
// Planted: hardcoded database credentials (CWE-798). Fake values.

define('DB_HOST', 'localhost');
define('DB_NAME', 'sample_app');
define('DB_USER', 'app_admin');
define('DB_PASSWORD', 'Pa55w0rd-hardcoded-in-source');

// Planted: weak hashing for passwords (CWE-327 / CWE-328).
function hash_password($plain) {
    return md5($plain);
}
