#include <libssh/libssh.h>

void sshQ___ext_init__() {
    ssh_init();
}

B_str sshQ_version() {
    return to$str(ssh_version(0));
}
