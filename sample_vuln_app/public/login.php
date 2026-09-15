<?php
// INTENTIONALLY VULNERABLE test fixture - never deploy or copy.
// Planted: SQL injection (CWE-89) and reflected XSS (CWE-79).

require_once __DIR__ . '/../src/config.php';

$connection = mysqli_connect(DB_HOST, DB_USER, DB_PASSWORD, DB_NAME);

// Flaw 1: user input concatenated straight into SQL.
$username = $_GET['username'];
$query = "SELECT id, email FROM users WHERE username = '" . $username . "'";
$result = mysqli_query($connection, $query);

// Flaw 2: user input echoed back without encoding.
echo "<h1>Results for " . $_GET['username'] . "</h1>";

while ($row = mysqli_fetch_assoc($result)) {
    echo "<p>" . $row['email'] . "</p>";
}
