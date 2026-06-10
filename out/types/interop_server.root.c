#include "rts/common.h"
#include "out/types/interop_server.h"
void $ROOTINIT () {
    interop_serverQ___init__();
}
$Actor $ROOT () {
    return ($Actor)$NEWACTOR(interop_serverQ_main);
}