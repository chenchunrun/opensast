#include <assert.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

void vulnerable(char *user_input, char *path, size_t x, size_t y, char *password) {
    char buf[64];
    char sql[256];
    char *ptr = NULL;
    char *ptr2 = NULL;

    // ruleid: cpp.security.buffer-overflow-gets
    gets(buf);

    // ruleid: cpp.security.buffer-overflow-scanf
    scanf("%s", buf);

    // ok: cpp.security.buffer-overflow-scanf
    scanf("%63s", buf);

    // ruleid: cpp.security.buffer-overflow-sprintf
    sprintf(buf, "%s", user_input);

    // ok: cpp.security.buffer-overflow-sprintf
    snprintf(buf, sizeof(buf), "%s", user_input);

    // ruleid: cpp.security.buffer-overflow-strcpy
    strcpy(buf, user_input);

    // ruleid: cpp.security.buffer-overflow-strcat
    strcat(buf, user_input);

    // ruleid: cpp.security.out-of-bounds-read
    value = arr[index];

    // ok: cpp.security.out-of-bounds-read
    if (index < size) { value = arr[index]; }

    // ruleid: cpp.security.format-string
    printf(user_input);

    // ok: cpp.security.format-string
    printf("%s", user_input);

    // ruleid: cpp.security.command-injection-system
    system(user_input);

    // ok: cpp.security.command-injection-system
    system("ls -la");

    // ruleid: cpp.security.sql-injection-sprintf
    sprintf(sql, "SELECT * FROM users WHERE name = '%s'", user_input);

    // ruleid: cpp.security.integer-overflow-malloc
    malloc(x * y);

    // ok: cpp.security.integer-overflow-malloc
    if (x > SIZE_MAX / y) {
        malloc(x * y);
    }

    // ruleid: cpp.security.use-after-free
    free(ptr);

    // ruleid: cpp.security.double-free
    free(ptr2);
    free(ptr2);

    // ruleid: cpp.security.insecure-random-rand
    rand();

    // ruleid: cpp.security.hardcoded-credentials
    password = "supersecret123";

    // ruleid: cpp.security.toctou-race
    access(path, F_OK);
    open(path, O_RDONLY);

    // ruleid: cpp.security.tempfile-mktemp
    mktemp(template_buf);

    // ruleid: cpp.security.null-pointer-dereference
    ptr = malloc(128);

    // ok: cpp.security.null-pointer-dereference
    if ((ptr = malloc(128)) == NULL) { return; }

    // ruleid: cpp.security.insecure-file-permission
    chmod(path, 0777);

    // ruleid: cpp.security.assert-in-production
    assert(user_input != NULL);

    // ruleid: cpp.security.unchecked-return
    malloc(64);
}
