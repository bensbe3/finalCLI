// INTENTIONALLY VULNERABLE test fixture - never deploy or copy.
// Planted: eval of user input (CWE-94) and insecure randomness (CWE-330).

// Flaw 1: a value from the page is evaluated as code.
function calculate() {
  const expression = document.getElementById("formula").value;
  return eval(expression);
}

// Flaw 2: a security-relevant token built from a non-cryptographic RNG.
function newSessionToken() {
  return Math.random().toString(36).substring(2);
}

// Flaw 3: user-controlled HTML written straight into the DOM (CWE-79).
function showGreeting(name) {
  document.getElementById("greeting").innerHTML = "Hello " + name;
}

module.exports = { calculate, newSessionToken, showGreeting };
