// Insecure random tests

// Positive: Math.random in ID generation
// ruleid: javascript.security.insecure-random
const storageId = `file_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

// Positive: Math.random in token
// ruleid: javascript.security.insecure-random
const token = Math.random().toString(36);

// Positive: Math.random concatenated
// ruleid: javascript.security.insecure-random
const id = "user_" + Math.random().toString(36).substr(2, 9);

// Positive: Math.random in template
// ruleid: javascript.security.insecure-random
const key = `key_${Math.random()}`;

// Negative: Math.random for comparison
// ok: javascript.security.insecure-random
if (Math.random() < 0.5) { }

// Negative: Math.random for scaling
// ok: javascript.security.insecure-random
const value = Math.random() * 100;
