#include "rts/common.h"
#include "out/types/bench_echo.h"
void $ROOTINIT () {
    bench_echoQ___init__();
}
$Actor $ROOT () {
    return ($Actor)$NEWACTOR(bench_echoQ_main);
}