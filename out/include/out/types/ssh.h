/* Acton impl hash: ae888c40bbe572591df0676f4d8d395cda2d17a6ca42a139a66bb0676cbf8a9e */
#pragma once
#include "builtin/builtin.h"
#include "rts/rts.h"
#include "out/types/testing.h"
B_str sshQ_version ();
B_NoneType sshQ__test_version ();
struct sshQ_L_1mut;
typedef struct sshQ_L_1mut *sshQ_L_1mut;
struct sshQ_L_1mutG_class {
    char *$GCINFO;
    int $class_id;
    $SuperG_class $superclass;
    B_NoneType (*__init__) (sshQ_L_1mut);
    void (*__serialize__) (sshQ_L_1mut, $Serial$state);
    sshQ_L_1mut (*__deserialize__) (sshQ_L_1mut, $Serial$state);
    B_bool (*__bool__) (sshQ_L_1mut);
    B_str (*__str__) (sshQ_L_1mut);
    B_str (*__repr__) (sshQ_L_1mut);
    $R (*__call__) (sshQ_L_1mut, $Cont);
    $R (*__exec__) (sshQ_L_1mut, $Cont);
    B_NoneType (*__eval__) (sshQ_L_1mut);
};
struct sshQ_L_1mut {
    struct sshQ_L_1mutG_class *$class;
};
extern struct sshQ_L_1mutG_class sshQ_L_1mutG_methods;
sshQ_L_1mut sshQ_L_1mutG_new();
struct sshQ_L_3Cont;
struct sshQ_L_4proc;
struct sshQ_test_main;
typedef struct sshQ_L_3Cont *sshQ_L_3Cont;
typedef struct sshQ_L_4proc *sshQ_L_4proc;
typedef struct sshQ_test_main *sshQ_test_main;
$R sshQ_L_2C_1cont ($Cont, sshQ_test_main, B_NoneType);
struct sshQ_L_3ContG_class {
    char *$GCINFO;
    int $class_id;
    $SuperG_class $superclass;
    B_NoneType (*__init__) (sshQ_L_3Cont, $Cont, sshQ_test_main);
    void (*__serialize__) (sshQ_L_3Cont, $Serial$state);
    sshQ_L_3Cont (*__deserialize__) (sshQ_L_3Cont, $Serial$state);
    B_bool (*__bool__) (sshQ_L_3Cont);
    B_str (*__str__) (sshQ_L_3Cont);
    B_str (*__repr__) (sshQ_L_3Cont);
    $R (*__call__) (sshQ_L_3Cont, B_NoneType);
};
struct sshQ_L_3Cont {
    struct sshQ_L_3ContG_class *$class;
    $Cont C_cont;
    sshQ_test_main G_act;
};
struct sshQ_L_4procG_class {
    char *$GCINFO;
    int $class_id;
    $SuperG_class $superclass;
    B_NoneType (*__init__) (sshQ_L_4proc, sshQ_test_main, B_Env);
    void (*__serialize__) (sshQ_L_4proc, $Serial$state);
    sshQ_L_4proc (*__deserialize__) (sshQ_L_4proc, $Serial$state);
    B_bool (*__bool__) (sshQ_L_4proc);
    B_str (*__str__) (sshQ_L_4proc);
    B_str (*__repr__) (sshQ_L_4proc);
    $R (*__call__) (sshQ_L_4proc, $Cont);
    $R (*__exec__) (sshQ_L_4proc, $Cont);
};
struct sshQ_L_4proc {
    struct sshQ_L_4procG_class *$class;
    sshQ_test_main G_act;
    B_Env env;
};
struct sshQ_test_mainG_class {
    char *$GCINFO;
    int $class_id;
    $SuperG_class $superclass;
    $R (*__init__) (sshQ_test_main, $Cont, B_Env);
    void (*__serialize__) (sshQ_test_main, $Serial$state);
    sshQ_test_main (*__deserialize__) (sshQ_test_main, $Serial$state);
    B_bool (*__bool__) (sshQ_test_main);
    B_str (*__str__) (sshQ_test_main);
    B_str (*__repr__) (sshQ_test_main);
    B_NoneType (*__resume__) (sshQ_test_main);
    B_NoneType (*__cleanup__) (sshQ_test_main);
};
struct sshQ_test_main {
    struct sshQ_test_mainG_class *$class;
    $Actor $next;
    B_Msg $msg;
    B_Msg $msg_tail;
    $Lock $msg_lock;
    $int64 $affinity;
    B_Msg $outgoing;
    B_Msg $waitsfor;
    $int64 $consume_hd;
    $Catcher $catcher;
    $long $globkey;
};
$R sshQ_test_mainG_newact ($Cont, B_Env);
extern struct sshQ_L_3ContG_class sshQ_L_3ContG_methods;
sshQ_L_3Cont sshQ_L_3ContG_new($Cont, sshQ_test_main);
extern struct sshQ_L_4procG_class sshQ_L_4procG_methods;
sshQ_L_4proc sshQ_L_4procG_new(sshQ_test_main, B_Env);
extern struct sshQ_test_mainG_class sshQ_test_mainG_methods;
$R sshQ_test_mainG_new($Cont, B_Env);
extern B_dict sshQ___unit_tests;
extern B_dict sshQ___simple_sync_tests;
extern B_dict sshQ___sync_tests;
extern B_dict sshQ___async_tests;
extern B_dict sshQ___env_tests;
void sshQ___init__ ();