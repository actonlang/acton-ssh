#include "rts/common.h"
#include "out/types/ssh.h"
void $ROOTINIT () {
    sshQ___init__();
}
$Actor $ROOT () {
    return ($Actor)$NEWACTOR(sshQ_test_main);
}