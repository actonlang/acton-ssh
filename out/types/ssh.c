/* Acton impl hash: ae888c40bbe572591df0676f4d8d395cda2d17a6ca42a139a66bb0676cbf8a9e */
#include "rts/common.h"
#include "out/types/ssh.h"
#include "src/ssh.ext.c"
B_str sshQ_version ();
/*
#line 5 "src/ssh.act"
B_str sshQ_version () {
    #line 7 "src/ssh.act"
    // NotImplemented
}
*/
#line 9 "src/ssh.act"
B_NoneType sshQ__test_version () {
    B_Eq W__test_version_3 = (B_Eq)B_OrdD_strG_witness;
    #line 10 "src/ssh.act"
    ((B_NoneType (*) (B_Eq, B_str, B_str, B_str, B_bool, B_bool))testingQ_assertEqual)(W__test_version_3, to$str("0.11.0/mbedtls"), sshQ_version(), B_None, B_None, B_None);
    return B_None;
}
B_NoneType sshQ_L_1mutD___init__ (sshQ_L_1mut L_self) {
    return B_None;
}
$R sshQ_L_1mutD___call__ (sshQ_L_1mut L_self, $Cont L_cont) {
    return $R_CONT(L_cont, ((B_NoneType (*) ($WORD))((sshQ_L_1mut)(L_self))->$class->__eval__)(L_self));
}
$R sshQ_L_1mutD___exec__ (sshQ_L_1mut L_self, $Cont L_cont) {
    return $R_CONT(L_cont, ((B_NoneType (*) ($WORD))((sshQ_L_1mut)(L_self))->$class->__eval__)(L_self));
}
B_NoneType sshQ_L_1mutD___eval__ (sshQ_L_1mut L_self) {
    return sshQ__test_version();
}
void sshQ_L_1mutD___serialize__ (sshQ_L_1mut self, $Serial$state state) {
}
sshQ_L_1mut sshQ_L_1mutD___deserialize__ (sshQ_L_1mut self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_1mut));
            self->$class = &sshQ_L_1mutG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_1mut, state);
    }
    return self;
}
sshQ_L_1mut sshQ_L_1mutG_new() {
    sshQ_L_1mut $tmp = acton_malloc(sizeof(struct sshQ_L_1mut));
    $tmp->$class = &sshQ_L_1mutG_methods;
    sshQ_L_1mutG_methods.__init__($tmp);
    return $tmp;
}
struct sshQ_L_1mutG_class sshQ_L_1mutG_methods;
B_dict sshQ___unit_tests;
B_dict sshQ___simple_sync_tests;
B_dict sshQ___sync_tests;
B_dict sshQ___async_tests;
B_dict sshQ___env_tests;
$R sshQ_L_2C_1cont ($Cont C_cont, sshQ_test_main G_act, B_NoneType C_2res) {
    return $R_CONT(C_cont, G_act);
}
B_NoneType sshQ_L_3ContD___init__ (sshQ_L_3Cont L_self, $Cont C_cont, sshQ_test_main G_act) {
    ((sshQ_L_3Cont)(L_self))->C_cont = C_cont;
    ((sshQ_L_3Cont)(L_self))->G_act = G_act;
    return B_None;
}
$R sshQ_L_3ContD___call__ (sshQ_L_3Cont L_self, B_NoneType G_1) {
    $Cont C_cont = ((sshQ_L_3Cont)(L_self))->C_cont;
    sshQ_test_main G_act = ((sshQ_L_3Cont)(L_self))->G_act;
    return sshQ_L_2C_1cont(C_cont, G_act, G_1);
}
void sshQ_L_3ContD___serialize__ (sshQ_L_3Cont self, $Serial$state state) {
    $step_serialize(self->C_cont, state);
    $step_serialize(self->G_act, state);
}
sshQ_L_3Cont sshQ_L_3ContD___deserialize__ (sshQ_L_3Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_3Cont));
            self->$class = &sshQ_L_3ContG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_3Cont, state);
    }
    self->C_cont = $step_deserialize(state);
    self->G_act = $step_deserialize(state);
    return self;
}
sshQ_L_3Cont sshQ_L_3ContG_new($Cont G_1, sshQ_test_main G_2) {
    sshQ_L_3Cont $tmp = acton_malloc(sizeof(struct sshQ_L_3Cont));
    $tmp->$class = &sshQ_L_3ContG_methods;
    sshQ_L_3ContG_methods.__init__($tmp, G_1, G_2);
    return $tmp;
}
struct sshQ_L_3ContG_class sshQ_L_3ContG_methods;
B_NoneType sshQ_L_4procD___init__ (sshQ_L_4proc L_self, sshQ_test_main G_act, B_Env env) {
    ((sshQ_L_4proc)(L_self))->G_act = G_act;
    ((sshQ_L_4proc)(L_self))->env = env;
    return B_None;
}
$R sshQ_L_4procD___call__ (sshQ_L_4proc L_self, $Cont C_cont) {
    sshQ_test_main G_act = ((sshQ_L_4proc)(L_self))->G_act;
    B_Env env = ((sshQ_L_4proc)(L_self))->env;
    return (($R (*) ($WORD, $Cont, B_Env))((sshQ_test_main)(G_act))->$class->__init__)(G_act, C_cont, env);
}
$R sshQ_L_4procD___exec__ (sshQ_L_4proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((sshQ_L_4proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void sshQ_L_4procD___serialize__ (sshQ_L_4proc self, $Serial$state state) {
    $step_serialize(self->G_act, state);
    $step_serialize(self->env, state);
}
sshQ_L_4proc sshQ_L_4procD___deserialize__ (sshQ_L_4proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_4proc));
            self->$class = &sshQ_L_4procG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_4proc, state);
    }
    self->G_act = $step_deserialize(state);
    self->env = $step_deserialize(state);
    return self;
}
sshQ_L_4proc sshQ_L_4procG_new(sshQ_test_main G_1, B_Env G_2) {
    sshQ_L_4proc $tmp = acton_malloc(sizeof(struct sshQ_L_4proc));
    $tmp->$class = &sshQ_L_4procG_methods;
    sshQ_L_4procG_methods.__init__($tmp, G_1, G_2);
    return $tmp;
}
struct sshQ_L_4procG_class sshQ_L_4procG_methods;
$R sshQ_test_mainD___init__ (sshQ_test_main self, $Cont C_cont, B_Env env) {
    return testingQ_test_runnerG_newact($SKIPRES(C_cont), env, sshQ___unit_tests, sshQ___simple_sync_tests, sshQ___sync_tests, sshQ___async_tests, sshQ___env_tests);
}
void sshQ_test_mainD___serialize__ (sshQ_test_main self, $Serial$state state) {
    $ActorG_methods.__serialize__(($Actor)self, state);
}
sshQ_test_main sshQ_test_mainD___deserialize__ (sshQ_test_main self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_test_main));
            self->$class = &sshQ_test_mainG_methods;
            return self;
        }
        self = $DNEW(sshQ_test_main, state);
    }
    $ActorG_methods.__deserialize__(($Actor)self, state);
    return self;
}
void sshQ_test_mainD_GCfinalizer (void *obj, void *cdata) {
    sshQ_test_main self = (sshQ_test_main)obj;
    self->$class->__cleanup__(self);
}
$R sshQ_test_mainG_new($Cont G_1, B_Env G_2) {
    sshQ_test_main $tmp = acton_malloc(sizeof(struct sshQ_test_main));
    $tmp->$class = &sshQ_test_mainG_methods;
    return sshQ_test_mainG_methods.__init__($tmp, $CONSTCONT($tmp, G_1), G_2);
}
struct sshQ_test_mainG_class sshQ_test_mainG_methods;
$R sshQ_test_mainG_newact ($Cont C_cont, B_Env env) {
    sshQ_test_main G_act = $NEWACTOR(sshQ_test_main);
    if ((void*)G_act->$class->__cleanup__ != (void*)$ActorD___cleanup__) $InstallFinalizer(G_act, sshQ_test_mainD_GCfinalizer);
    return $AWAIT((($Cont)sshQ_L_3ContG_new(C_cont, G_act)), $ASYNC((($Actor)G_act), (($Cont)sshQ_L_4procG_new(G_act, env))));
}
int sshQ_done$ = 0;
void sshQ___init__ () {
    if (sshQ_done$) return;
    sshQ_done$ = 1;
    sshQ___ext_init__ ();
    testingQ___init__();
    {
        sshQ_L_1mutG_methods.$GCINFO = "sshQ_L_1mut";
        sshQ_L_1mutG_methods.$superclass = ($SuperG_class)&$mutG_methods;
        sshQ_L_1mutG_methods.__bool__ = (B_bool (*) (sshQ_L_1mut))B_valueG_methods.__bool__;
        sshQ_L_1mutG_methods.__str__ = (B_str (*) (sshQ_L_1mut))B_valueG_methods.__str__;
        sshQ_L_1mutG_methods.__repr__ = (B_str (*) (sshQ_L_1mut))B_valueG_methods.__repr__;
        sshQ_L_1mutG_methods.__init__ = (B_NoneType (*) (sshQ_L_1mut))sshQ_L_1mutD___init__;
        sshQ_L_1mutG_methods.__call__ = ($R (*) (sshQ_L_1mut, $Cont))sshQ_L_1mutD___call__;
        sshQ_L_1mutG_methods.__exec__ = ($R (*) (sshQ_L_1mut, $Cont))sshQ_L_1mutD___exec__;
        sshQ_L_1mutG_methods.__eval__ = (B_NoneType (*) (sshQ_L_1mut))sshQ_L_1mutD___eval__;
        sshQ_L_1mutG_methods.__serialize__ = sshQ_L_1mutD___serialize__;
        sshQ_L_1mutG_methods.__deserialize__ = sshQ_L_1mutD___deserialize__;
        $register(&sshQ_L_1mutG_methods);
    }
    {
        sshQ_L_3ContG_methods.$GCINFO = "sshQ_L_3Cont";
        sshQ_L_3ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        sshQ_L_3ContG_methods.__bool__ = (B_bool (*) (sshQ_L_3Cont))B_valueG_methods.__bool__;
        sshQ_L_3ContG_methods.__str__ = (B_str (*) (sshQ_L_3Cont))B_valueG_methods.__str__;
        sshQ_L_3ContG_methods.__repr__ = (B_str (*) (sshQ_L_3Cont))B_valueG_methods.__repr__;
        sshQ_L_3ContG_methods.__init__ = (B_NoneType (*) (sshQ_L_3Cont, $Cont, sshQ_test_main))sshQ_L_3ContD___init__;
        sshQ_L_3ContG_methods.__call__ = ($R (*) (sshQ_L_3Cont, B_NoneType))sshQ_L_3ContD___call__;
        sshQ_L_3ContG_methods.__serialize__ = sshQ_L_3ContD___serialize__;
        sshQ_L_3ContG_methods.__deserialize__ = sshQ_L_3ContD___deserialize__;
        $register(&sshQ_L_3ContG_methods);
    }
    {
        sshQ_L_4procG_methods.$GCINFO = "sshQ_L_4proc";
        sshQ_L_4procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        sshQ_L_4procG_methods.__bool__ = (B_bool (*) (sshQ_L_4proc))B_valueG_methods.__bool__;
        sshQ_L_4procG_methods.__str__ = (B_str (*) (sshQ_L_4proc))B_valueG_methods.__str__;
        sshQ_L_4procG_methods.__repr__ = (B_str (*) (sshQ_L_4proc))B_valueG_methods.__repr__;
        sshQ_L_4procG_methods.__init__ = (B_NoneType (*) (sshQ_L_4proc, sshQ_test_main, B_Env))sshQ_L_4procD___init__;
        sshQ_L_4procG_methods.__call__ = ($R (*) (sshQ_L_4proc, $Cont))sshQ_L_4procD___call__;
        sshQ_L_4procG_methods.__exec__ = ($R (*) (sshQ_L_4proc, $Cont))sshQ_L_4procD___exec__;
        sshQ_L_4procG_methods.__serialize__ = sshQ_L_4procD___serialize__;
        sshQ_L_4procG_methods.__deserialize__ = sshQ_L_4procD___deserialize__;
        $register(&sshQ_L_4procG_methods);
    }
    {
        sshQ_test_mainG_methods.$GCINFO = "sshQ_test_main";
        sshQ_test_mainG_methods.$superclass = ($SuperG_class)&$ActorG_methods;
        sshQ_test_mainG_methods.__bool__ = (B_bool (*) (sshQ_test_main))$ActorG_methods.__bool__;
        sshQ_test_mainG_methods.__str__ = (B_str (*) (sshQ_test_main))$ActorG_methods.__str__;
        sshQ_test_mainG_methods.__repr__ = (B_str (*) (sshQ_test_main))$ActorG_methods.__repr__;
        sshQ_test_mainG_methods.__resume__ = (B_NoneType (*) (sshQ_test_main))$ActorG_methods.__resume__;
        sshQ_test_mainG_methods.__cleanup__ = (B_NoneType (*) (sshQ_test_main))$ActorG_methods.__cleanup__;
        sshQ_test_mainG_methods.__init__ = ($R (*) (sshQ_test_main, $Cont, B_Env))sshQ_test_mainD___init__;
        sshQ_test_mainG_methods.__serialize__ = sshQ_test_mainD___serialize__;
        sshQ_test_mainG_methods.__deserialize__ = sshQ_test_mainD___deserialize__;
        $register(&sshQ_test_mainG_methods);
    }
    B_dict __unit_tests = B_mk_dict(1, ((B_Hashable)B_HashableD_strG_new()), $NEWTUPLE(2, to$str("_test_version"), testingQ_UnitTestG_new((($mut)sshQ_L_1mutG_new()), to$str("_test_version"), to$str(""), to$str("ssh"))));
    sshQ___unit_tests = __unit_tests;
    B_dict __simple_sync_tests = B_mk_dict(0, ((B_Hashable)B_HashableD_strG_new()));
    sshQ___simple_sync_tests = __simple_sync_tests;
    B_dict __sync_tests = B_mk_dict(0, ((B_Hashable)B_HashableD_strG_new()));
    sshQ___sync_tests = __sync_tests;
    B_dict __async_tests = B_mk_dict(0, ((B_Hashable)B_HashableD_strG_new()));
    sshQ___async_tests = __async_tests;
    B_dict __env_tests = B_mk_dict(0, ((B_Hashable)B_HashableD_strG_new()));
    sshQ___env_tests = __env_tests;
}