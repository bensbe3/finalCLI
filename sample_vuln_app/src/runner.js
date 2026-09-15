// INTENTIONALLY VULNERABLE test fixture - never deploy or copy.
// Planted: command injection via child_process (CWE-78).

const { exec } = require("child_process");
const http = require("http");

http
  .createServer((request, response) => {
    const target = new URL(request.url, "http://placeholder").searchParams.get("file");

    // Flaw: request data concatenated into a shell command.
    exec("cat /var/data/" + target, (error, stdout) => {
      response.end(stdout);
    });
  })
  .listen(3000);
