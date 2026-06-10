#include "rts/common.h"
#include "out/types/soak.h"
void $ROOTINIT () {
    soakQ___init__();
}
$Actor $ROOT () {
    return ($Actor)$NEWACTOR(soakQ_main);
}