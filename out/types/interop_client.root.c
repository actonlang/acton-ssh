#include "rts/common.h"
#include "out/types/interop_client.h"
void $ROOTINIT () {
    interop_clientQ___init__();
}
$Actor $ROOT () {
    return ($Actor)$NEWACTOR(interop_clientQ_main);
}