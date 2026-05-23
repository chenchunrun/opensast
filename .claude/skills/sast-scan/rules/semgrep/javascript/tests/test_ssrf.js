// SSRF tests

// Positive: fetch with user input
// ruleid: javascript.security.ssrf-fetch
fetch(userProvidedUrl);

// Positive: axios with user input
// ruleid: javascript.security.ssrf-fetch
axios.get(userUrl);

// Positive: axios.post with user input
// ruleid: javascript.security.ssrf-fetch
axios.post(userUrl, data);

// Positive: generic client with user input
// ruleid: javascript.security.ssrf-fetch
httpClient.get(userUrl);

// Negative: fetch with literal URL
// ok: javascript.security.ssrf-fetch
fetch("https://api.example.com/data");

// Negative: axios with literal
// ok: javascript.security.ssrf-fetch
axios.get("https://api.example.com/users");

// Negative: fetch with template literal API path
// ok: javascript.security.ssrf-fetch
fetch(`/api/tasks/${taskId}`);
