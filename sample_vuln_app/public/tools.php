<?php
// INTENTIONALLY VULNERABLE test fixture - never deploy or copy.
// Planted: OS command injection (CWE-78) and path traversal (CWE-22).

// Flaw 1: request data reaches a shell command.
$host = $_POST['host'];
system("ping -c 1 " . $host);

// Flaw 2: request data used as a file path with no containment.
$page = $_GET['page'];
include("/var/www/pages/" . $page);

// Flaw 3: the same input handed to another shell entry point.
$archive = $_GET['archive'];
exec("tar -tf /var/uploads/" . $archive, $listing);
print_r($listing);
