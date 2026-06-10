#include "rts/common.h"
#include "out/types/example_server.h"
void $ROOTINIT () {
    example_serverQ___init__();
}
$Actor $ROOT () {
    return ($Actor)$NEWACTOR(example_serverQ_main);
}