#include <libssh/libssh.h>
#include <libssh/libssh_version.h>

void sshQ___ext_init__() {
    // NOP
}

B_str sshQ_version () {
    if (LIBSSH_VERSION_MINOR != 11)
        return to$str("invalid");
    return to$str("0.11.0");
}
