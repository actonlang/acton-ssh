#include <libssh/libssh.h>

/* Internal table access used only to verify the typed catalogs in this test. */
const char *ssh_kex_get_supported_method(enum ssh_kex_types_e algo);
const char *ssh_kex_get_default_methods(enum ssh_kex_types_e algo);

void sshQ_test_ssh_catalogQ___ext_init__() {
}

B_str sshQ_test_ssh_catalogQ__libssh_supported_algorithms(int64_t method) {
    const char *value = method >= 0 && method < 10 ?
        ssh_kex_get_supported_method((enum ssh_kex_types_e)method) : NULL;
    return to$str((char *)(value != NULL ? value : ""));
}

B_str sshQ_test_ssh_catalogQ__libssh_default_algorithms(int64_t method) {
    const char *value = method >= 0 && method < 10 ?
        ssh_kex_get_default_methods((enum ssh_kex_types_e)method) : NULL;
    return to$str((char *)(value != NULL ? value : ""));
}
