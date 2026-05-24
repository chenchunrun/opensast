// Test corpus for C/C++ rules
// Lines with // ruleid: should trigger
// Lines with // ok: should NOT trigger

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

void test_buffer_overflow() {
    char buf[64];

    // --- buffer-overflow ---

    // ruleid: cpp.security.buffer-overflow-gets
    gets(buf);

    // ruleid: cpp.security.buffer-overflow-scanf
    scanf("%s", buf);

    // ok: cpp.security.buffer-overflow-scanf
    scanf("%63s", buf);

    // ruleid: cpp.security.buffer-overflow-sprintf
    sprintf(buf, "%s", userInput);

    // ruleid: cpp.security.buffer-overflow-strcpy
    strcpy(buf, userInput);

    // ruleid: cpp.security.buffer-overflow-strcat
    strcat(buf, userInput);
}

void test_format_string() {
    // --- format-string ---

    // ruleid: cpp.security.format-string
    printf(user_input);

    // ok: cpp.security.format-string
    printf("%s", user_input);
}

void test_command_injection() {
    // --- command-injection ---

    // ruleid: cpp.security.command-injection-system
    system(user_input);

    // ok: cpp.security.command-injection-system
    system("ls -la");
}

void test_crypto() {
    // --- insecure-random ---

    // ruleid: cpp.security.insecure-random-rand
    rand();

    // --- hardcoded-credentials ---

    // ruleid: cpp.security.hardcoded-credentials
    char password[] = "supersecret123";
}

void test_memory() {
    // --- tempfile ---

    // ruleid: cpp.security.tempfile-mktemp
    mktemp(template_buf);
}
