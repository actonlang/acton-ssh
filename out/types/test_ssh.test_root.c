#include "rts/common.h"
#include "out/types/test_ssh.h"
void $ROOTINIT () {
    test_sshQ___init__();
}
$Actor $ROOT () {
    return ($Actor)$NEWACTOR(test_sshQ_test_main);
}