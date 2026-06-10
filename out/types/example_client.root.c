#include "rts/common.h"
#include "out/types/example_client.h"
void $ROOTINIT () {
    example_clientQ___init__();
}
$Actor $ROOT () {
    return ($Actor)$NEWACTOR(example_clientQ_main);
}