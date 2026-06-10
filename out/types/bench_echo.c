/* Acton impl hash: 024337666fdc5b8e46a4f6477c74c02f79500c4f12b7e11087176e0b565d88a8 */
#include "rts/common.h"
#include "out/types/bench_echo.h"
B_Collection bench_echoQ_W_main_34;
B_Iterable bench_echoQ_W_main_1054;
B_Collection bench_echoQ_W_main_822;
B_Sliceable bench_echoQ_W_main_751;
B_Plus bench_echoQ_W_main_1092;
$R bench_echoQ_L_1C_2cont (bench_echoQ_main self, $Cont C_cont, sshQ_Server C_3res) {
    #line 129 "src/bench_echo.act"
    ((bench_echoQ_main)(self))->server = C_3res;
    return $R_CONT(C_cont, B_None);
}
B_NoneType bench_echoQ_L_2ContD___init__ (bench_echoQ_L_2Cont L_self, bench_echoQ_main self, $Cont C_cont) {
    ((bench_echoQ_L_2Cont)(L_self))->self = self;
    ((bench_echoQ_L_2Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R bench_echoQ_L_2ContD___call__ (bench_echoQ_L_2Cont L_self, sshQ_Server G_1) {
    bench_echoQ_main self = ((bench_echoQ_L_2Cont)(L_self))->self;
    $Cont C_cont = ((bench_echoQ_L_2Cont)(L_self))->C_cont;
    return bench_echoQ_L_1C_2cont(self, C_cont, G_1);
}
void bench_echoQ_L_2ContD___serialize__ (bench_echoQ_L_2Cont self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->C_cont, state);
}
bench_echoQ_L_2Cont bench_echoQ_L_2ContD___deserialize__ (bench_echoQ_L_2Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct bench_echoQ_L_2Cont));
            self->$class = &bench_echoQ_L_2ContG_methods;
            return self;
        }
        self = $DNEW(bench_echoQ_L_2Cont, state);
    }
    self->self = $step_deserialize(state);
    self->C_cont = $step_deserialize(state);
    return self;
}
bench_echoQ_L_2Cont bench_echoQ_L_2ContG_new(bench_echoQ_main G_1, $Cont G_2) {
    bench_echoQ_L_2Cont $tmp = acton_malloc(sizeof(struct bench_echoQ_L_2Cont));
    $tmp->$class = &bench_echoQ_L_2ContG_methods;
    bench_echoQ_L_2ContG_methods.__init__($tmp, G_1, G_2);
    return $tmp;
}
struct bench_echoQ_L_2ContG_class bench_echoQ_L_2ContG_methods;
B_NoneType bench_echoQ_L_4actionD___init__ (bench_echoQ_L_4action L_self, bench_echoQ_main L_3obj) {
    ((bench_echoQ_L_4action)(L_self))->L_3obj = L_3obj;
    return B_None;
}
$R bench_echoQ_L_4actionD___call__ (bench_echoQ_L_4action L_self, $Cont L_cont, sshQ_Server G_1, B_str G_2) {
    return $AWAIT(L_cont, ((B_Msg (*) ($WORD, sshQ_Server, B_str))((bench_echoQ_L_4action)(L_self))->$class->__asyn__)(L_self, G_1, G_2));
}
$R bench_echoQ_L_4actionD___exec__ (bench_echoQ_L_4action L_self, $Cont L_cont, sshQ_Server G_1, B_str G_2) {
    return $R_CONT(L_cont, ((B_Msg (*) ($WORD, sshQ_Server, B_str))((bench_echoQ_L_4action)(L_self))->$class->__asyn__)(L_self, G_1, G_2));
}
B_Msg bench_echoQ_L_4actionD___asyn__ (bench_echoQ_L_4action L_self, sshQ_Server G_1, B_str G_2) {
    bench_echoQ_main L_3obj = ((bench_echoQ_L_4action)(L_self))->L_3obj;
    return ((B_Msg (*) ($WORD, sshQ_Server, B_str))((bench_echoQ_main)(L_3obj))->$class->on_listen)(L_3obj, G_1, G_2);
}
void bench_echoQ_L_4actionD___serialize__ (bench_echoQ_L_4action self, $Serial$state state) {
    $step_serialize(self->L_3obj, state);
}
bench_echoQ_L_4action bench_echoQ_L_4actionD___deserialize__ (bench_echoQ_L_4action self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct bench_echoQ_L_4action));
            self->$class = &bench_echoQ_L_4actionG_methods;
            return self;
        }
        self = $DNEW(bench_echoQ_L_4action, state);
    }
    self->L_3obj = $step_deserialize(state);
    return self;
}
bench_echoQ_L_4action bench_echoQ_L_4actionG_new(bench_echoQ_main G_1) {
    bench_echoQ_L_4action $tmp = acton_malloc(sizeof(struct bench_echoQ_L_4action));
    $tmp->$class = &bench_echoQ_L_4actionG_methods;
    bench_echoQ_L_4actionG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct bench_echoQ_L_4actionG_class bench_echoQ_L_4actionG_methods;
B_NoneType bench_echoQ_L_6actionD___init__ (bench_echoQ_L_6action L_self, bench_echoQ_main L_5obj) {
    ((bench_echoQ_L_6action)(L_self))->L_5obj = L_5obj;
    return B_None;
}
$R bench_echoQ_L_6actionD___call__ (bench_echoQ_L_6action L_self, $Cont L_cont, sshQ_Server G_1, B_str G_2) {
    return $AWAIT(L_cont, ((B_Msg (*) ($WORD, sshQ_Server, B_str))((bench_echoQ_L_6action)(L_self))->$class->__asyn__)(L_self, G_1, G_2));
}
$R bench_echoQ_L_6actionD___exec__ (bench_echoQ_L_6action L_self, $Cont L_cont, sshQ_Server G_1, B_str G_2) {
    return $R_CONT(L_cont, ((B_Msg (*) ($WORD, sshQ_Server, B_str))((bench_echoQ_L_6action)(L_self))->$class->__asyn__)(L_self, G_1, G_2));
}
B_Msg bench_echoQ_L_6actionD___asyn__ (bench_echoQ_L_6action L_self, sshQ_Server G_1, B_str G_2) {
    bench_echoQ_main L_5obj = ((bench_echoQ_L_6action)(L_self))->L_5obj;
    return ((B_Msg (*) ($WORD, sshQ_Server, B_str))((bench_echoQ_main)(L_5obj))->$class->on_server_close)(L_5obj, G_1, G_2);
}
void bench_echoQ_L_6actionD___serialize__ (bench_echoQ_L_6action self, $Serial$state state) {
    $step_serialize(self->L_5obj, state);
}
bench_echoQ_L_6action bench_echoQ_L_6actionD___deserialize__ (bench_echoQ_L_6action self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct bench_echoQ_L_6action));
            self->$class = &bench_echoQ_L_6actionG_methods;
            return self;
        }
        self = $DNEW(bench_echoQ_L_6action, state);
    }
    self->L_5obj = $step_deserialize(state);
    return self;
}
bench_echoQ_L_6action bench_echoQ_L_6actionG_new(bench_echoQ_main G_1) {
    bench_echoQ_L_6action $tmp = acton_malloc(sizeof(struct bench_echoQ_L_6action));
    $tmp->$class = &bench_echoQ_L_6actionG_methods;
    bench_echoQ_L_6actionG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct bench_echoQ_L_6actionG_class bench_echoQ_L_6actionG_methods;
B_NoneType bench_echoQ_L_8actionD___init__ (bench_echoQ_L_8action L_self, bench_echoQ_main L_7obj) {
    ((bench_echoQ_L_8action)(L_self))->L_7obj = L_7obj;
    return B_None;
}
$R bench_echoQ_L_8actionD___call__ (bench_echoQ_L_8action L_self, $Cont L_cont, sshQ_ServerSession G_1) {
    return $AWAIT(L_cont, ((B_Msg (*) ($WORD, sshQ_ServerSession))((bench_echoQ_L_8action)(L_self))->$class->__asyn__)(L_self, G_1));
}
$R bench_echoQ_L_8actionD___exec__ (bench_echoQ_L_8action L_self, $Cont L_cont, sshQ_ServerSession G_1) {
    return $R_CONT(L_cont, ((B_Msg (*) ($WORD, sshQ_ServerSession))((bench_echoQ_L_8action)(L_self))->$class->__asyn__)(L_self, G_1));
}
B_Msg bench_echoQ_L_8actionD___asyn__ (bench_echoQ_L_8action L_self, sshQ_ServerSession G_1) {
    bench_echoQ_main L_7obj = ((bench_echoQ_L_8action)(L_self))->L_7obj;
    return ((B_Msg (*) ($WORD, sshQ_ServerSession))((bench_echoQ_main)(L_7obj))->$class->on_session)(L_7obj, G_1);
}
void bench_echoQ_L_8actionD___serialize__ (bench_echoQ_L_8action self, $Serial$state state) {
    $step_serialize(self->L_7obj, state);
}
bench_echoQ_L_8action bench_echoQ_L_8actionD___deserialize__ (bench_echoQ_L_8action self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct bench_echoQ_L_8action));
            self->$class = &bench_echoQ_L_8actionG_methods;
            return self;
        }
        self = $DNEW(bench_echoQ_L_8action, state);
    }
    self->L_7obj = $step_deserialize(state);
    return self;
}
bench_echoQ_L_8action bench_echoQ_L_8actionG_new(bench_echoQ_main G_1) {
    bench_echoQ_L_8action $tmp = acton_malloc(sizeof(struct bench_echoQ_L_8action));
    $tmp->$class = &bench_echoQ_L_8actionG_methods;
    bench_echoQ_L_8actionG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct bench_echoQ_L_8actionG_class bench_echoQ_L_8actionG_methods;
B_NoneType bench_echoQ_L_10actionD___init__ (bench_echoQ_L_10action L_self, bench_echoQ_main L_9obj) {
    ((bench_echoQ_L_10action)(L_self))->L_9obj = L_9obj;
    return B_None;
}
$R bench_echoQ_L_10actionD___call__ (bench_echoQ_L_10action L_self, $Cont L_cont, sshQ_ServerSession G_1, sshQ_AuthRequest G_2) {
    return $AWAIT(L_cont, ((B_Msg (*) ($WORD, sshQ_ServerSession, sshQ_AuthRequest))((bench_echoQ_L_10action)(L_self))->$class->__asyn__)(L_self, G_1, G_2));
}
$R bench_echoQ_L_10actionD___exec__ (bench_echoQ_L_10action L_self, $Cont L_cont, sshQ_ServerSession G_1, sshQ_AuthRequest G_2) {
    return $R_CONT(L_cont, ((B_Msg (*) ($WORD, sshQ_ServerSession, sshQ_AuthRequest))((bench_echoQ_L_10action)(L_self))->$class->__asyn__)(L_self, G_1, G_2));
}
B_Msg bench_echoQ_L_10actionD___asyn__ (bench_echoQ_L_10action L_self, sshQ_ServerSession G_1, sshQ_AuthRequest G_2) {
    bench_echoQ_main L_9obj = ((bench_echoQ_L_10action)(L_self))->L_9obj;
    return ((B_Msg (*) ($WORD, sshQ_ServerSession, sshQ_AuthRequest))((bench_echoQ_main)(L_9obj))->$class->on_auth)(L_9obj, G_1, G_2);
}
void bench_echoQ_L_10actionD___serialize__ (bench_echoQ_L_10action self, $Serial$state state) {
    $step_serialize(self->L_9obj, state);
}
bench_echoQ_L_10action bench_echoQ_L_10actionD___deserialize__ (bench_echoQ_L_10action self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct bench_echoQ_L_10action));
            self->$class = &bench_echoQ_L_10actionG_methods;
            return self;
        }
        self = $DNEW(bench_echoQ_L_10action, state);
    }
    self->L_9obj = $step_deserialize(state);
    return self;
}
bench_echoQ_L_10action bench_echoQ_L_10actionG_new(bench_echoQ_main G_1) {
    bench_echoQ_L_10action $tmp = acton_malloc(sizeof(struct bench_echoQ_L_10action));
    $tmp->$class = &bench_echoQ_L_10actionG_methods;
    bench_echoQ_L_10actionG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct bench_echoQ_L_10actionG_class bench_echoQ_L_10actionG_methods;
B_NoneType bench_echoQ_L_12actionD___init__ (bench_echoQ_L_12action L_self, bench_echoQ_main L_11obj) {
    ((bench_echoQ_L_12action)(L_self))->L_11obj = L_11obj;
    return B_None;
}
$R bench_echoQ_L_12actionD___call__ (bench_echoQ_L_12action L_self, $Cont L_cont, sshQ_ServerSession G_1) {
    return $AWAIT(L_cont, ((B_Msg (*) ($WORD, sshQ_ServerSession))((bench_echoQ_L_12action)(L_self))->$class->__asyn__)(L_self, G_1));
}
$R bench_echoQ_L_12actionD___exec__ (bench_echoQ_L_12action L_self, $Cont L_cont, sshQ_ServerSession G_1) {
    return $R_CONT(L_cont, ((B_Msg (*) ($WORD, sshQ_ServerSession))((bench_echoQ_L_12action)(L_self))->$class->__asyn__)(L_self, G_1));
}
B_Msg bench_echoQ_L_12actionD___asyn__ (bench_echoQ_L_12action L_self, sshQ_ServerSession G_1) {
    bench_echoQ_main L_11obj = ((bench_echoQ_L_12action)(L_self))->L_11obj;
    return ((B_Msg (*) ($WORD, sshQ_ServerSession))((bench_echoQ_main)(L_11obj))->$class->on_channel_open)(L_11obj, G_1);
}
void bench_echoQ_L_12actionD___serialize__ (bench_echoQ_L_12action self, $Serial$state state) {
    $step_serialize(self->L_11obj, state);
}
bench_echoQ_L_12action bench_echoQ_L_12actionD___deserialize__ (bench_echoQ_L_12action self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct bench_echoQ_L_12action));
            self->$class = &bench_echoQ_L_12actionG_methods;
            return self;
        }
        self = $DNEW(bench_echoQ_L_12action, state);
    }
    self->L_11obj = $step_deserialize(state);
    return self;
}
bench_echoQ_L_12action bench_echoQ_L_12actionG_new(bench_echoQ_main G_1) {
    bench_echoQ_L_12action $tmp = acton_malloc(sizeof(struct bench_echoQ_L_12action));
    $tmp->$class = &bench_echoQ_L_12actionG_methods;
    bench_echoQ_L_12actionG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct bench_echoQ_L_12actionG_class bench_echoQ_L_12actionG_methods;
B_NoneType bench_echoQ_L_14actionD___init__ (bench_echoQ_L_14action L_self, bench_echoQ_main L_13obj) {
    ((bench_echoQ_L_14action)(L_self))->L_13obj = L_13obj;
    return B_None;
}
$R bench_echoQ_L_14actionD___call__ (bench_echoQ_L_14action L_self, $Cont L_cont, sshQ_ServerSession G_1, sshQ_ServerChannel G_2, B_str G_3) {
    return $AWAIT(L_cont, ((B_Msg (*) ($WORD, sshQ_ServerSession, sshQ_ServerChannel, B_str))((bench_echoQ_L_14action)(L_self))->$class->__asyn__)(L_self, G_1, G_2, G_3));
}
$R bench_echoQ_L_14actionD___exec__ (bench_echoQ_L_14action L_self, $Cont L_cont, sshQ_ServerSession G_1, sshQ_ServerChannel G_2, B_str G_3) {
    return $R_CONT(L_cont, ((B_Msg (*) ($WORD, sshQ_ServerSession, sshQ_ServerChannel, B_str))((bench_echoQ_L_14action)(L_self))->$class->__asyn__)(L_self, G_1, G_2, G_3));
}
B_Msg bench_echoQ_L_14actionD___asyn__ (bench_echoQ_L_14action L_self, sshQ_ServerSession G_1, sshQ_ServerChannel G_2, B_str G_3) {
    bench_echoQ_main L_13obj = ((bench_echoQ_L_14action)(L_self))->L_13obj;
    return ((B_Msg (*) ($WORD, sshQ_ServerSession, sshQ_ServerChannel, B_str))((bench_echoQ_main)(L_13obj))->$class->on_exec)(L_13obj, G_1, G_2, G_3);
}
void bench_echoQ_L_14actionD___serialize__ (bench_echoQ_L_14action self, $Serial$state state) {
    $step_serialize(self->L_13obj, state);
}
bench_echoQ_L_14action bench_echoQ_L_14actionD___deserialize__ (bench_echoQ_L_14action self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct bench_echoQ_L_14action));
            self->$class = &bench_echoQ_L_14actionG_methods;
            return self;
        }
        self = $DNEW(bench_echoQ_L_14action, state);
    }
    self->L_13obj = $step_deserialize(state);
    return self;
}
bench_echoQ_L_14action bench_echoQ_L_14actionG_new(bench_echoQ_main G_1) {
    bench_echoQ_L_14action $tmp = acton_malloc(sizeof(struct bench_echoQ_L_14action));
    $tmp->$class = &bench_echoQ_L_14actionG_methods;
    bench_echoQ_L_14actionG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct bench_echoQ_L_14actionG_class bench_echoQ_L_14actionG_methods;
$R bench_echoQ_L_17C_8cont (bench_echoQ_main self, $Cont C_cont, sshQ_Client C_9res) {
    #line 30 "src/bench_echo.act"
    ((bench_echoQ_main)(self))->client = C_9res;
    return $R_CONT(C_cont, B_None);
}
B_NoneType bench_echoQ_L_18ContD___init__ (bench_echoQ_L_18Cont L_self, bench_echoQ_main self, $Cont C_cont) {
    ((bench_echoQ_L_18Cont)(L_self))->self = self;
    ((bench_echoQ_L_18Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R bench_echoQ_L_18ContD___call__ (bench_echoQ_L_18Cont L_self, sshQ_Client G_1) {
    bench_echoQ_main self = ((bench_echoQ_L_18Cont)(L_self))->self;
    $Cont C_cont = ((bench_echoQ_L_18Cont)(L_self))->C_cont;
    return bench_echoQ_L_17C_8cont(self, C_cont, G_1);
}
void bench_echoQ_L_18ContD___serialize__ (bench_echoQ_L_18Cont self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->C_cont, state);
}
bench_echoQ_L_18Cont bench_echoQ_L_18ContD___deserialize__ (bench_echoQ_L_18Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct bench_echoQ_L_18Cont));
            self->$class = &bench_echoQ_L_18ContG_methods;
            return self;
        }
        self = $DNEW(bench_echoQ_L_18Cont, state);
    }
    self->self = $step_deserialize(state);
    self->C_cont = $step_deserialize(state);
    return self;
}
bench_echoQ_L_18Cont bench_echoQ_L_18ContG_new(bench_echoQ_main G_1, $Cont G_2) {
    bench_echoQ_L_18Cont $tmp = acton_malloc(sizeof(struct bench_echoQ_L_18Cont));
    $tmp->$class = &bench_echoQ_L_18ContG_methods;
    bench_echoQ_L_18ContG_methods.__init__($tmp, G_1, G_2);
    return $tmp;
}
struct bench_echoQ_L_18ContG_class bench_echoQ_L_18ContG_methods;
B_NoneType bench_echoQ_L_20actionD___init__ (bench_echoQ_L_20action L_self, bench_echoQ_main L_19obj) {
    ((bench_echoQ_L_20action)(L_self))->L_19obj = L_19obj;
    return B_None;
}
$R bench_echoQ_L_20actionD___call__ (bench_echoQ_L_20action L_self, $Cont L_cont, sshQ_Client G_1, B_str G_2) {
    return $AWAIT(L_cont, ((B_Msg (*) ($WORD, sshQ_Client, B_str))((bench_echoQ_L_20action)(L_self))->$class->__asyn__)(L_self, G_1, G_2));
}
$R bench_echoQ_L_20actionD___exec__ (bench_echoQ_L_20action L_self, $Cont L_cont, sshQ_Client G_1, B_str G_2) {
    return $R_CONT(L_cont, ((B_Msg (*) ($WORD, sshQ_Client, B_str))((bench_echoQ_L_20action)(L_self))->$class->__asyn__)(L_self, G_1, G_2));
}
B_Msg bench_echoQ_L_20actionD___asyn__ (bench_echoQ_L_20action L_self, sshQ_Client G_1, B_str G_2) {
    bench_echoQ_main L_19obj = ((bench_echoQ_L_20action)(L_self))->L_19obj;
    return ((B_Msg (*) ($WORD, sshQ_Client, B_str))((bench_echoQ_main)(L_19obj))->$class->on_connect)(L_19obj, G_1, G_2);
}
void bench_echoQ_L_20actionD___serialize__ (bench_echoQ_L_20action self, $Serial$state state) {
    $step_serialize(self->L_19obj, state);
}
bench_echoQ_L_20action bench_echoQ_L_20actionD___deserialize__ (bench_echoQ_L_20action self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct bench_echoQ_L_20action));
            self->$class = &bench_echoQ_L_20actionG_methods;
            return self;
        }
        self = $DNEW(bench_echoQ_L_20action, state);
    }
    self->L_19obj = $step_deserialize(state);
    return self;
}
bench_echoQ_L_20action bench_echoQ_L_20actionG_new(bench_echoQ_main G_1) {
    bench_echoQ_L_20action $tmp = acton_malloc(sizeof(struct bench_echoQ_L_20action));
    $tmp->$class = &bench_echoQ_L_20actionG_methods;
    bench_echoQ_L_20actionG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct bench_echoQ_L_20actionG_class bench_echoQ_L_20actionG_methods;
B_NoneType bench_echoQ_L_22actionD___init__ (bench_echoQ_L_22action L_self, bench_echoQ_main L_21obj) {
    ((bench_echoQ_L_22action)(L_self))->L_21obj = L_21obj;
    return B_None;
}
$R bench_echoQ_L_22actionD___call__ (bench_echoQ_L_22action L_self, $Cont L_cont, sshQ_Client G_1, B_str G_2) {
    return $AWAIT(L_cont, ((B_Msg (*) ($WORD, sshQ_Client, B_str))((bench_echoQ_L_22action)(L_self))->$class->__asyn__)(L_self, G_1, G_2));
}
$R bench_echoQ_L_22actionD___exec__ (bench_echoQ_L_22action L_self, $Cont L_cont, sshQ_Client G_1, B_str G_2) {
    return $R_CONT(L_cont, ((B_Msg (*) ($WORD, sshQ_Client, B_str))((bench_echoQ_L_22action)(L_self))->$class->__asyn__)(L_self, G_1, G_2));
}
B_Msg bench_echoQ_L_22actionD___asyn__ (bench_echoQ_L_22action L_self, sshQ_Client G_1, B_str G_2) {
    bench_echoQ_main L_21obj = ((bench_echoQ_L_22action)(L_self))->L_21obj;
    return ((B_Msg (*) ($WORD, sshQ_Client, B_str))((bench_echoQ_main)(L_21obj))->$class->on_client_close)(L_21obj, G_1, G_2);
}
void bench_echoQ_L_22actionD___serialize__ (bench_echoQ_L_22action self, $Serial$state state) {
    $step_serialize(self->L_21obj, state);
}
bench_echoQ_L_22action bench_echoQ_L_22actionD___deserialize__ (bench_echoQ_L_22action self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct bench_echoQ_L_22action));
            self->$class = &bench_echoQ_L_22actionG_methods;
            return self;
        }
        self = $DNEW(bench_echoQ_L_22action, state);
    }
    self->L_21obj = $step_deserialize(state);
    return self;
}
bench_echoQ_L_22action bench_echoQ_L_22actionG_new(bench_echoQ_main G_1) {
    bench_echoQ_L_22action $tmp = acton_malloc(sizeof(struct bench_echoQ_L_22action));
    $tmp->$class = &bench_echoQ_L_22actionG_methods;
    bench_echoQ_L_22actionG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct bench_echoQ_L_22actionG_class bench_echoQ_L_22actionG_methods;
B_NoneType bench_echoQ_L_24actionD___init__ (bench_echoQ_L_24action L_self, bench_echoQ_main L_23obj) {
    ((bench_echoQ_L_24action)(L_self))->L_23obj = L_23obj;
    return B_None;
}
$R bench_echoQ_L_24actionD___call__ (bench_echoQ_L_24action L_self, $Cont L_cont, sshQ_Client G_1, B_str G_2, sshQ_HostKeyInfo G_3) {
    return $AWAIT(L_cont, ((B_Msg (*) ($WORD, sshQ_Client, B_str, sshQ_HostKeyInfo))((bench_echoQ_L_24action)(L_self))->$class->__asyn__)(L_self, G_1, G_2, G_3));
}
$R bench_echoQ_L_24actionD___exec__ (bench_echoQ_L_24action L_self, $Cont L_cont, sshQ_Client G_1, B_str G_2, sshQ_HostKeyInfo G_3) {
    return $R_CONT(L_cont, ((B_Msg (*) ($WORD, sshQ_Client, B_str, sshQ_HostKeyInfo))((bench_echoQ_L_24action)(L_self))->$class->__asyn__)(L_self, G_1, G_2, G_3));
}
B_Msg bench_echoQ_L_24actionD___asyn__ (bench_echoQ_L_24action L_self, sshQ_Client G_1, B_str G_2, sshQ_HostKeyInfo G_3) {
    bench_echoQ_main L_23obj = ((bench_echoQ_L_24action)(L_self))->L_23obj;
    return ((B_Msg (*) ($WORD, sshQ_Client, B_str, sshQ_HostKeyInfo))((bench_echoQ_main)(L_23obj))->$class->on_hostkey)(L_23obj, G_1, G_2, G_3);
}
void bench_echoQ_L_24actionD___serialize__ (bench_echoQ_L_24action self, $Serial$state state) {
    $step_serialize(self->L_23obj, state);
}
bench_echoQ_L_24action bench_echoQ_L_24actionD___deserialize__ (bench_echoQ_L_24action self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct bench_echoQ_L_24action));
            self->$class = &bench_echoQ_L_24actionG_methods;
            return self;
        }
        self = $DNEW(bench_echoQ_L_24action, state);
    }
    self->L_23obj = $step_deserialize(state);
    return self;
}
bench_echoQ_L_24action bench_echoQ_L_24actionG_new(bench_echoQ_main G_1) {
    bench_echoQ_L_24action $tmp = acton_malloc(sizeof(struct bench_echoQ_L_24action));
    $tmp->$class = &bench_echoQ_L_24actionG_methods;
    bench_echoQ_L_24actionG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct bench_echoQ_L_24actionG_class bench_echoQ_L_24actionG_methods;
$R bench_echoQ_L_16C_6cont (bench_echoQ_main self, $Cont C_cont, uint16_t C_7res) {
    #line 29 "src/bench_echo.act"
    uint16_t port = C_7res;
    return sshQ_ClientG_newact((($Cont)bench_echoQ_L_18ContG_new(self, C_cont)), netQ_TCPConnectCapG_new(netQ_TCPCapG_new(netQ_NetCapG_new(((B_Env)(((bench_echoQ_main)(self))->env))->cap))), to$str("127.0.0.1"), to$str("bench"), (($action)bench_echoQ_L_20actionG_new(self)), (($action)bench_echoQ_L_22actionG_new(self)), (($action)bench_echoQ_L_24actionG_new(self)), to$str("bench"), B_None, B_None, toB_u16(port), B_None, B_None, B_None, B_None, B_None, B_None);
}
B_NoneType bench_echoQ_L_25ContD___init__ (bench_echoQ_L_25Cont L_self, bench_echoQ_main self, $Cont C_cont) {
    ((bench_echoQ_L_25Cont)(L_self))->self = self;
    ((bench_echoQ_L_25Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R bench_echoQ_L_25ContD___call__ (bench_echoQ_L_25Cont L_self, B_u16 G_1) {
    bench_echoQ_main self = ((bench_echoQ_L_25Cont)(L_self))->self;
    $Cont C_cont = ((bench_echoQ_L_25Cont)(L_self))->C_cont;
    return bench_echoQ_L_16C_6cont(self, C_cont, ((B_u16)G_1)->val);
}
void bench_echoQ_L_25ContD___serialize__ (bench_echoQ_L_25Cont self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->C_cont, state);
}
bench_echoQ_L_25Cont bench_echoQ_L_25ContD___deserialize__ (bench_echoQ_L_25Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct bench_echoQ_L_25Cont));
            self->$class = &bench_echoQ_L_25ContG_methods;
            return self;
        }
        self = $DNEW(bench_echoQ_L_25Cont, state);
    }
    self->self = $step_deserialize(state);
    self->C_cont = $step_deserialize(state);
    return self;
}
bench_echoQ_L_25Cont bench_echoQ_L_25ContG_new(bench_echoQ_main G_1, $Cont G_2) {
    bench_echoQ_L_25Cont $tmp = acton_malloc(sizeof(struct bench_echoQ_L_25Cont));
    $tmp->$class = &bench_echoQ_L_25ContG_methods;
    bench_echoQ_L_25ContG_methods.__init__($tmp, G_1, G_2);
    return $tmp;
}
struct bench_echoQ_L_25ContG_class bench_echoQ_L_25ContG_methods;
$R bench_echoQ_L_15C_4cont (bench_echoQ_main self, $Cont C_cont, sshQ_Server s, B_NoneType C_5res) {
    return $AWAIT((($Cont)bench_echoQ_L_25ContG_new(self, C_cont)), ((B_Msg (*) ($WORD))((sshQ_Server)(s))->$class->bound_port)(s));
}
$R bench_echoQ_L_26C_10cont ($Cont C_cont, B_NoneType C_11res) {
    return $R_CONT(C_cont, B_None);
}
B_NoneType bench_echoQ_L_27ContD___init__ (bench_echoQ_L_27Cont L_self, $Cont C_cont) {
    ((bench_echoQ_L_27Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R bench_echoQ_L_27ContD___call__ (bench_echoQ_L_27Cont L_self, B_NoneType G_1) {
    $Cont C_cont = ((bench_echoQ_L_27Cont)(L_self))->C_cont;
    return bench_echoQ_L_26C_10cont(C_cont, G_1);
}
void bench_echoQ_L_27ContD___serialize__ (bench_echoQ_L_27Cont self, $Serial$state state) {
    $step_serialize(self->C_cont, state);
}
bench_echoQ_L_27Cont bench_echoQ_L_27ContD___deserialize__ (bench_echoQ_L_27Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct bench_echoQ_L_27Cont));
            self->$class = &bench_echoQ_L_27ContG_methods;
            return self;
        }
        self = $DNEW(bench_echoQ_L_27Cont, state);
    }
    self->C_cont = $step_deserialize(state);
    return self;
}
bench_echoQ_L_27Cont bench_echoQ_L_27ContG_new($Cont G_1) {
    bench_echoQ_L_27Cont $tmp = acton_malloc(sizeof(struct bench_echoQ_L_27Cont));
    $tmp->$class = &bench_echoQ_L_27ContG_methods;
    bench_echoQ_L_27ContG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct bench_echoQ_L_27ContG_class bench_echoQ_L_27ContG_methods;
B_NoneType bench_echoQ_L_28ContD___init__ (bench_echoQ_L_28Cont L_self, bench_echoQ_main self, $Cont C_cont, sshQ_Server s) {
    ((bench_echoQ_L_28Cont)(L_self))->self = self;
    ((bench_echoQ_L_28Cont)(L_self))->C_cont = C_cont;
    ((bench_echoQ_L_28Cont)(L_self))->s = s;
    return B_None;
}
$R bench_echoQ_L_28ContD___call__ (bench_echoQ_L_28Cont L_self, B_NoneType G_1) {
    bench_echoQ_main self = ((bench_echoQ_L_28Cont)(L_self))->self;
    $Cont C_cont = ((bench_echoQ_L_28Cont)(L_self))->C_cont;
    sshQ_Server s = ((bench_echoQ_L_28Cont)(L_self))->s;
    return bench_echoQ_L_15C_4cont(self, C_cont, s, G_1);
}
void bench_echoQ_L_28ContD___serialize__ (bench_echoQ_L_28Cont self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->C_cont, state);
    $step_serialize(self->s, state);
}
bench_echoQ_L_28Cont bench_echoQ_L_28ContD___deserialize__ (bench_echoQ_L_28Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct bench_echoQ_L_28Cont));
            self->$class = &bench_echoQ_L_28ContG_methods;
            return self;
        }
        self = $DNEW(bench_echoQ_L_28Cont, state);
    }
    self->self = $step_deserialize(state);
    self->C_cont = $step_deserialize(state);
    self->s = $step_deserialize(state);
    return self;
}
bench_echoQ_L_28Cont bench_echoQ_L_28ContG_new(bench_echoQ_main G_1, $Cont G_2, sshQ_Server G_3) {
    bench_echoQ_L_28Cont $tmp = acton_malloc(sizeof(struct bench_echoQ_L_28Cont));
    $tmp->$class = &bench_echoQ_L_28ContG_methods;
    bench_echoQ_L_28ContG_methods.__init__($tmp, G_1, G_2, G_3);
    return $tmp;
}
struct bench_echoQ_L_28ContG_class bench_echoQ_L_28ContG_methods;
$R bench_echoQ_L_29C_12cont (sshQ_ServerSession sess, $Cont C_cont, sshQ_ServerChannel C_13res) {
    sshQ_ServerChannel C_1pre = C_13res;
    #line 64 "src/bench_echo.act"
    ((B_Msg (*) ($WORD, sshQ_ServerChannel))((sshQ_ServerSession)(sess))->$class->accept_channel)(sess, C_1pre);
    return $R_CONT(C_cont, B_None);
}
B_NoneType bench_echoQ_L_30ContD___init__ (bench_echoQ_L_30Cont L_self, sshQ_ServerSession sess, $Cont C_cont) {
    ((bench_echoQ_L_30Cont)(L_self))->sess = sess;
    ((bench_echoQ_L_30Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R bench_echoQ_L_30ContD___call__ (bench_echoQ_L_30Cont L_self, sshQ_ServerChannel G_1) {
    sshQ_ServerSession sess = ((bench_echoQ_L_30Cont)(L_self))->sess;
    $Cont C_cont = ((bench_echoQ_L_30Cont)(L_self))->C_cont;
    return bench_echoQ_L_29C_12cont(sess, C_cont, G_1);
}
void bench_echoQ_L_30ContD___serialize__ (bench_echoQ_L_30Cont self, $Serial$state state) {
    $step_serialize(self->sess, state);
    $step_serialize(self->C_cont, state);
}
bench_echoQ_L_30Cont bench_echoQ_L_30ContD___deserialize__ (bench_echoQ_L_30Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct bench_echoQ_L_30Cont));
            self->$class = &bench_echoQ_L_30ContG_methods;
            return self;
        }
        self = $DNEW(bench_echoQ_L_30Cont, state);
    }
    self->sess = $step_deserialize(state);
    self->C_cont = $step_deserialize(state);
    return self;
}
bench_echoQ_L_30Cont bench_echoQ_L_30ContG_new(sshQ_ServerSession G_1, $Cont G_2) {
    bench_echoQ_L_30Cont $tmp = acton_malloc(sizeof(struct bench_echoQ_L_30Cont));
    $tmp->$class = &bench_echoQ_L_30ContG_methods;
    bench_echoQ_L_30ContG_methods.__init__($tmp, G_1, G_2);
    return $tmp;
}
struct bench_echoQ_L_30ContG_class bench_echoQ_L_30ContG_methods;
B_NoneType bench_echoQ_L_32actionD___init__ (bench_echoQ_L_32action L_self, bench_echoQ_main L_31obj) {
    ((bench_echoQ_L_32action)(L_self))->L_31obj = L_31obj;
    return B_None;
}
$R bench_echoQ_L_32actionD___call__ (bench_echoQ_L_32action L_self, $Cont L_cont, sshQ_ServerChannel G_1, B_bytes G_2) {
    return $AWAIT(L_cont, ((B_Msg (*) ($WORD, sshQ_ServerChannel, B_bytes))((bench_echoQ_L_32action)(L_self))->$class->__asyn__)(L_self, G_1, G_2));
}
$R bench_echoQ_L_32actionD___exec__ (bench_echoQ_L_32action L_self, $Cont L_cont, sshQ_ServerChannel G_1, B_bytes G_2) {
    return $R_CONT(L_cont, ((B_Msg (*) ($WORD, sshQ_ServerChannel, B_bytes))((bench_echoQ_L_32action)(L_self))->$class->__asyn__)(L_self, G_1, G_2));
}
B_Msg bench_echoQ_L_32actionD___asyn__ (bench_echoQ_L_32action L_self, sshQ_ServerChannel G_1, B_bytes G_2) {
    bench_echoQ_main L_31obj = ((bench_echoQ_L_32action)(L_self))->L_31obj;
    return ((B_Msg (*) ($WORD, sshQ_ServerChannel, B_bytes))((bench_echoQ_main)(L_31obj))->$class->srv_on_data)(L_31obj, G_1, G_2);
}
void bench_echoQ_L_32actionD___serialize__ (bench_echoQ_L_32action self, $Serial$state state) {
    $step_serialize(self->L_31obj, state);
}
bench_echoQ_L_32action bench_echoQ_L_32actionD___deserialize__ (bench_echoQ_L_32action self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct bench_echoQ_L_32action));
            self->$class = &bench_echoQ_L_32actionG_methods;
            return self;
        }
        self = $DNEW(bench_echoQ_L_32action, state);
    }
    self->L_31obj = $step_deserialize(state);
    return self;
}
bench_echoQ_L_32action bench_echoQ_L_32actionG_new(bench_echoQ_main G_1) {
    bench_echoQ_L_32action $tmp = acton_malloc(sizeof(struct bench_echoQ_L_32action));
    $tmp->$class = &bench_echoQ_L_32actionG_methods;
    bench_echoQ_L_32actionG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct bench_echoQ_L_32actionG_class bench_echoQ_L_32actionG_methods;
B_NoneType bench_echoQ_L_34actionD___init__ (bench_echoQ_L_34action L_self, bench_echoQ_main L_33obj) {
    ((bench_echoQ_L_34action)(L_self))->L_33obj = L_33obj;
    return B_None;
}
$R bench_echoQ_L_34actionD___call__ (bench_echoQ_L_34action L_self, $Cont L_cont, sshQ_ServerChannel G_1, B_bytes G_2) {
    return $AWAIT(L_cont, ((B_Msg (*) ($WORD, sshQ_ServerChannel, B_bytes))((bench_echoQ_L_34action)(L_self))->$class->__asyn__)(L_self, G_1, G_2));
}
$R bench_echoQ_L_34actionD___exec__ (bench_echoQ_L_34action L_self, $Cont L_cont, sshQ_ServerChannel G_1, B_bytes G_2) {
    return $R_CONT(L_cont, ((B_Msg (*) ($WORD, sshQ_ServerChannel, B_bytes))((bench_echoQ_L_34action)(L_self))->$class->__asyn__)(L_self, G_1, G_2));
}
B_Msg bench_echoQ_L_34actionD___asyn__ (bench_echoQ_L_34action L_self, sshQ_ServerChannel G_1, B_bytes G_2) {
    bench_echoQ_main L_33obj = ((bench_echoQ_L_34action)(L_self))->L_33obj;
    return ((B_Msg (*) ($WORD, sshQ_ServerChannel, B_bytes))((bench_echoQ_main)(L_33obj))->$class->srv_on_stderr)(L_33obj, G_1, G_2);
}
void bench_echoQ_L_34actionD___serialize__ (bench_echoQ_L_34action self, $Serial$state state) {
    $step_serialize(self->L_33obj, state);
}
bench_echoQ_L_34action bench_echoQ_L_34actionD___deserialize__ (bench_echoQ_L_34action self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct bench_echoQ_L_34action));
            self->$class = &bench_echoQ_L_34actionG_methods;
            return self;
        }
        self = $DNEW(bench_echoQ_L_34action, state);
    }
    self->L_33obj = $step_deserialize(state);
    return self;
}
bench_echoQ_L_34action bench_echoQ_L_34actionG_new(bench_echoQ_main G_1) {
    bench_echoQ_L_34action $tmp = acton_malloc(sizeof(struct bench_echoQ_L_34action));
    $tmp->$class = &bench_echoQ_L_34actionG_methods;
    bench_echoQ_L_34actionG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct bench_echoQ_L_34actionG_class bench_echoQ_L_34actionG_methods;
B_NoneType bench_echoQ_L_36actionD___init__ (bench_echoQ_L_36action L_self, bench_echoQ_main L_35obj) {
    ((bench_echoQ_L_36action)(L_self))->L_35obj = L_35obj;
    return B_None;
}
$R bench_echoQ_L_36actionD___call__ (bench_echoQ_L_36action L_self, $Cont L_cont, sshQ_ServerChannel G_1, B_str G_2) {
    return $AWAIT(L_cont, ((B_Msg (*) ($WORD, sshQ_ServerChannel, B_str))((bench_echoQ_L_36action)(L_self))->$class->__asyn__)(L_self, G_1, G_2));
}
$R bench_echoQ_L_36actionD___exec__ (bench_echoQ_L_36action L_self, $Cont L_cont, sshQ_ServerChannel G_1, B_str G_2) {
    return $R_CONT(L_cont, ((B_Msg (*) ($WORD, sshQ_ServerChannel, B_str))((bench_echoQ_L_36action)(L_self))->$class->__asyn__)(L_self, G_1, G_2));
}
B_Msg bench_echoQ_L_36actionD___asyn__ (bench_echoQ_L_36action L_self, sshQ_ServerChannel G_1, B_str G_2) {
    bench_echoQ_main L_35obj = ((bench_echoQ_L_36action)(L_self))->L_35obj;
    return ((B_Msg (*) ($WORD, sshQ_ServerChannel, B_str))((bench_echoQ_main)(L_35obj))->$class->srv_on_close)(L_35obj, G_1, G_2);
}
void bench_echoQ_L_36actionD___serialize__ (bench_echoQ_L_36action self, $Serial$state state) {
    $step_serialize(self->L_35obj, state);
}
bench_echoQ_L_36action bench_echoQ_L_36actionD___deserialize__ (bench_echoQ_L_36action self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct bench_echoQ_L_36action));
            self->$class = &bench_echoQ_L_36actionG_methods;
            return self;
        }
        self = $DNEW(bench_echoQ_L_36action, state);
    }
    self->L_35obj = $step_deserialize(state);
    return self;
}
bench_echoQ_L_36action bench_echoQ_L_36actionG_new(bench_echoQ_main G_1) {
    bench_echoQ_L_36action $tmp = acton_malloc(sizeof(struct bench_echoQ_L_36action));
    $tmp->$class = &bench_echoQ_L_36actionG_methods;
    bench_echoQ_L_36actionG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct bench_echoQ_L_36actionG_class bench_echoQ_L_36actionG_methods;
$R bench_echoQ_L_38C_16cont ($Cont C_cont, sshQ_Channel C_17res) {
    return $R_CONT(C_cont, B_None);
}
B_NoneType bench_echoQ_L_39ContD___init__ (bench_echoQ_L_39Cont L_self, $Cont C_cont) {
    ((bench_echoQ_L_39Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R bench_echoQ_L_39ContD___call__ (bench_echoQ_L_39Cont L_self, sshQ_Channel G_1) {
    $Cont C_cont = ((bench_echoQ_L_39Cont)(L_self))->C_cont;
    return bench_echoQ_L_38C_16cont(C_cont, G_1);
}
void bench_echoQ_L_39ContD___serialize__ (bench_echoQ_L_39Cont self, $Serial$state state) {
    $step_serialize(self->C_cont, state);
}
bench_echoQ_L_39Cont bench_echoQ_L_39ContD___deserialize__ (bench_echoQ_L_39Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct bench_echoQ_L_39Cont));
            self->$class = &bench_echoQ_L_39ContG_methods;
            return self;
        }
        self = $DNEW(bench_echoQ_L_39Cont, state);
    }
    self->C_cont = $step_deserialize(state);
    return self;
}
bench_echoQ_L_39Cont bench_echoQ_L_39ContG_new($Cont G_1) {
    bench_echoQ_L_39Cont $tmp = acton_malloc(sizeof(struct bench_echoQ_L_39Cont));
    $tmp->$class = &bench_echoQ_L_39ContG_methods;
    bench_echoQ_L_39ContG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct bench_echoQ_L_39ContG_class bench_echoQ_L_39ContG_methods;
B_NoneType bench_echoQ_L_41actionD___init__ (bench_echoQ_L_41action L_self, bench_echoQ_main L_40obj) {
    ((bench_echoQ_L_41action)(L_self))->L_40obj = L_40obj;
    return B_None;
}
$R bench_echoQ_L_41actionD___call__ (bench_echoQ_L_41action L_self, $Cont L_cont, sshQ_Channel G_1, B_str G_2) {
    return $AWAIT(L_cont, ((B_Msg (*) ($WORD, sshQ_Channel, B_str))((bench_echoQ_L_41action)(L_self))->$class->__asyn__)(L_self, G_1, G_2));
}
$R bench_echoQ_L_41actionD___exec__ (bench_echoQ_L_41action L_self, $Cont L_cont, sshQ_Channel G_1, B_str G_2) {
    return $R_CONT(L_cont, ((B_Msg (*) ($WORD, sshQ_Channel, B_str))((bench_echoQ_L_41action)(L_self))->$class->__asyn__)(L_self, G_1, G_2));
}
B_Msg bench_echoQ_L_41actionD___asyn__ (bench_echoQ_L_41action L_self, sshQ_Channel G_1, B_str G_2) {
    bench_echoQ_main L_40obj = ((bench_echoQ_L_41action)(L_self))->L_40obj;
    return ((B_Msg (*) ($WORD, sshQ_Channel, B_str))((bench_echoQ_main)(L_40obj))->$class->ch_open)(L_40obj, G_1, G_2);
}
void bench_echoQ_L_41actionD___serialize__ (bench_echoQ_L_41action self, $Serial$state state) {
    $step_serialize(self->L_40obj, state);
}
bench_echoQ_L_41action bench_echoQ_L_41actionD___deserialize__ (bench_echoQ_L_41action self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct bench_echoQ_L_41action));
            self->$class = &bench_echoQ_L_41actionG_methods;
            return self;
        }
        self = $DNEW(bench_echoQ_L_41action, state);
    }
    self->L_40obj = $step_deserialize(state);
    return self;
}
bench_echoQ_L_41action bench_echoQ_L_41actionG_new(bench_echoQ_main G_1) {
    bench_echoQ_L_41action $tmp = acton_malloc(sizeof(struct bench_echoQ_L_41action));
    $tmp->$class = &bench_echoQ_L_41actionG_methods;
    bench_echoQ_L_41actionG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct bench_echoQ_L_41actionG_class bench_echoQ_L_41actionG_methods;
B_NoneType bench_echoQ_L_43actionD___init__ (bench_echoQ_L_43action L_self, bench_echoQ_main L_42obj) {
    ((bench_echoQ_L_43action)(L_self))->L_42obj = L_42obj;
    return B_None;
}
$R bench_echoQ_L_43actionD___call__ (bench_echoQ_L_43action L_self, $Cont L_cont, sshQ_Channel G_1, B_bytes G_2) {
    return $AWAIT(L_cont, ((B_Msg (*) ($WORD, sshQ_Channel, B_bytes))((bench_echoQ_L_43action)(L_self))->$class->__asyn__)(L_self, G_1, G_2));
}
$R bench_echoQ_L_43actionD___exec__ (bench_echoQ_L_43action L_self, $Cont L_cont, sshQ_Channel G_1, B_bytes G_2) {
    return $R_CONT(L_cont, ((B_Msg (*) ($WORD, sshQ_Channel, B_bytes))((bench_echoQ_L_43action)(L_self))->$class->__asyn__)(L_self, G_1, G_2));
}
B_Msg bench_echoQ_L_43actionD___asyn__ (bench_echoQ_L_43action L_self, sshQ_Channel G_1, B_bytes G_2) {
    bench_echoQ_main L_42obj = ((bench_echoQ_L_43action)(L_self))->L_42obj;
    return ((B_Msg (*) ($WORD, sshQ_Channel, B_bytes))((bench_echoQ_main)(L_42obj))->$class->ch_out)(L_42obj, G_1, G_2);
}
void bench_echoQ_L_43actionD___serialize__ (bench_echoQ_L_43action self, $Serial$state state) {
    $step_serialize(self->L_42obj, state);
}
bench_echoQ_L_43action bench_echoQ_L_43actionD___deserialize__ (bench_echoQ_L_43action self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct bench_echoQ_L_43action));
            self->$class = &bench_echoQ_L_43actionG_methods;
            return self;
        }
        self = $DNEW(bench_echoQ_L_43action, state);
    }
    self->L_42obj = $step_deserialize(state);
    return self;
}
bench_echoQ_L_43action bench_echoQ_L_43actionG_new(bench_echoQ_main G_1) {
    bench_echoQ_L_43action $tmp = acton_malloc(sizeof(struct bench_echoQ_L_43action));
    $tmp->$class = &bench_echoQ_L_43actionG_methods;
    bench_echoQ_L_43actionG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct bench_echoQ_L_43actionG_class bench_echoQ_L_43actionG_methods;
B_NoneType bench_echoQ_L_45actionD___init__ (bench_echoQ_L_45action L_self, bench_echoQ_main L_44obj) {
    ((bench_echoQ_L_45action)(L_self))->L_44obj = L_44obj;
    return B_None;
}
$R bench_echoQ_L_45actionD___call__ (bench_echoQ_L_45action L_self, $Cont L_cont, sshQ_Channel G_1, B_bytes G_2) {
    return $AWAIT(L_cont, ((B_Msg (*) ($WORD, sshQ_Channel, B_bytes))((bench_echoQ_L_45action)(L_self))->$class->__asyn__)(L_self, G_1, G_2));
}
$R bench_echoQ_L_45actionD___exec__ (bench_echoQ_L_45action L_self, $Cont L_cont, sshQ_Channel G_1, B_bytes G_2) {
    return $R_CONT(L_cont, ((B_Msg (*) ($WORD, sshQ_Channel, B_bytes))((bench_echoQ_L_45action)(L_self))->$class->__asyn__)(L_self, G_1, G_2));
}
B_Msg bench_echoQ_L_45actionD___asyn__ (bench_echoQ_L_45action L_self, sshQ_Channel G_1, B_bytes G_2) {
    bench_echoQ_main L_44obj = ((bench_echoQ_L_45action)(L_self))->L_44obj;
    return ((B_Msg (*) ($WORD, sshQ_Channel, B_bytes))((bench_echoQ_main)(L_44obj))->$class->ch_err)(L_44obj, G_1, G_2);
}
void bench_echoQ_L_45actionD___serialize__ (bench_echoQ_L_45action self, $Serial$state state) {
    $step_serialize(self->L_44obj, state);
}
bench_echoQ_L_45action bench_echoQ_L_45actionD___deserialize__ (bench_echoQ_L_45action self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct bench_echoQ_L_45action));
            self->$class = &bench_echoQ_L_45actionG_methods;
            return self;
        }
        self = $DNEW(bench_echoQ_L_45action, state);
    }
    self->L_44obj = $step_deserialize(state);
    return self;
}
bench_echoQ_L_45action bench_echoQ_L_45actionG_new(bench_echoQ_main G_1) {
    bench_echoQ_L_45action $tmp = acton_malloc(sizeof(struct bench_echoQ_L_45action));
    $tmp->$class = &bench_echoQ_L_45actionG_methods;
    bench_echoQ_L_45actionG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct bench_echoQ_L_45actionG_class bench_echoQ_L_45actionG_methods;
B_NoneType bench_echoQ_L_47actionD___init__ (bench_echoQ_L_47action L_self, bench_echoQ_main L_46obj) {
    ((bench_echoQ_L_47action)(L_self))->L_46obj = L_46obj;
    return B_None;
}
$R bench_echoQ_L_47actionD___call__ (bench_echoQ_L_47action L_self, $Cont L_cont, sshQ_Channel G_1, B_int G_2, B_str G_3) {
    return $AWAIT(L_cont, ((B_Msg (*) ($WORD, sshQ_Channel, B_int, B_str))((bench_echoQ_L_47action)(L_self))->$class->__asyn__)(L_self, G_1, G_2, G_3));
}
$R bench_echoQ_L_47actionD___exec__ (bench_echoQ_L_47action L_self, $Cont L_cont, sshQ_Channel G_1, B_int G_2, B_str G_3) {
    return $R_CONT(L_cont, ((B_Msg (*) ($WORD, sshQ_Channel, B_int, B_str))((bench_echoQ_L_47action)(L_self))->$class->__asyn__)(L_self, G_1, G_2, G_3));
}
B_Msg bench_echoQ_L_47actionD___asyn__ (bench_echoQ_L_47action L_self, sshQ_Channel G_1, B_int G_2, B_str G_3) {
    bench_echoQ_main L_46obj = ((bench_echoQ_L_47action)(L_self))->L_46obj;
    return ((B_Msg (*) ($WORD, sshQ_Channel, int64_t, B_str))((bench_echoQ_main)(L_46obj))->$class->ch_exit)(L_46obj, G_1, ((B_int)G_2)->val, G_3);
}
void bench_echoQ_L_47actionD___serialize__ (bench_echoQ_L_47action self, $Serial$state state) {
    $step_serialize(self->L_46obj, state);
}
bench_echoQ_L_47action bench_echoQ_L_47actionD___deserialize__ (bench_echoQ_L_47action self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct bench_echoQ_L_47action));
            self->$class = &bench_echoQ_L_47actionG_methods;
            return self;
        }
        self = $DNEW(bench_echoQ_L_47action, state);
    }
    self->L_46obj = $step_deserialize(state);
    return self;
}
bench_echoQ_L_47action bench_echoQ_L_47actionG_new(bench_echoQ_main G_1) {
    bench_echoQ_L_47action $tmp = acton_malloc(sizeof(struct bench_echoQ_L_47action));
    $tmp->$class = &bench_echoQ_L_47actionG_methods;
    bench_echoQ_L_47actionG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct bench_echoQ_L_47actionG_class bench_echoQ_L_47actionG_methods;
B_NoneType bench_echoQ_L_49actionD___init__ (bench_echoQ_L_49action L_self, bench_echoQ_main L_48obj) {
    ((bench_echoQ_L_49action)(L_self))->L_48obj = L_48obj;
    return B_None;
}
$R bench_echoQ_L_49actionD___call__ (bench_echoQ_L_49action L_self, $Cont L_cont, sshQ_Channel G_1, B_str G_2) {
    return $AWAIT(L_cont, ((B_Msg (*) ($WORD, sshQ_Channel, B_str))((bench_echoQ_L_49action)(L_self))->$class->__asyn__)(L_self, G_1, G_2));
}
$R bench_echoQ_L_49actionD___exec__ (bench_echoQ_L_49action L_self, $Cont L_cont, sshQ_Channel G_1, B_str G_2) {
    return $R_CONT(L_cont, ((B_Msg (*) ($WORD, sshQ_Channel, B_str))((bench_echoQ_L_49action)(L_self))->$class->__asyn__)(L_self, G_1, G_2));
}
B_Msg bench_echoQ_L_49actionD___asyn__ (bench_echoQ_L_49action L_self, sshQ_Channel G_1, B_str G_2) {
    bench_echoQ_main L_48obj = ((bench_echoQ_L_49action)(L_self))->L_48obj;
    return ((B_Msg (*) ($WORD, sshQ_Channel, B_str))((bench_echoQ_main)(L_48obj))->$class->ch_close)(L_48obj, G_1, G_2);
}
void bench_echoQ_L_49actionD___serialize__ (bench_echoQ_L_49action self, $Serial$state state) {
    $step_serialize(self->L_48obj, state);
}
bench_echoQ_L_49action bench_echoQ_L_49actionD___deserialize__ (bench_echoQ_L_49action self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct bench_echoQ_L_49action));
            self->$class = &bench_echoQ_L_49actionG_methods;
            return self;
        }
        self = $DNEW(bench_echoQ_L_49action, state);
    }
    self->L_48obj = $step_deserialize(state);
    return self;
}
bench_echoQ_L_49action bench_echoQ_L_49actionG_new(bench_echoQ_main G_1) {
    bench_echoQ_L_49action $tmp = acton_malloc(sizeof(struct bench_echoQ_L_49action));
    $tmp->$class = &bench_echoQ_L_49actionG_methods;
    bench_echoQ_L_49actionG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct bench_echoQ_L_49actionG_class bench_echoQ_L_49actionG_methods;
$R bench_echoQ_L_37C_14cont (bench_echoQ_main self, $Cont C_cont, sshQ_Client c, B_NoneType C_15res) {
    #line 76 "src/bench_echo.act"
    ((bench_echoQ_main)(self))->t_connect = timeQ_monotonic();
    return sshQ_ChannelG_newact((($Cont)bench_echoQ_L_39ContG_new(C_cont)), c, (($action)bench_echoQ_L_41actionG_new(self)), (($action)bench_echoQ_L_43actionG_new(self)), (($action)bench_echoQ_L_45actionG_new(self)), (($action)bench_echoQ_L_47actionG_new(self)), (($action)bench_echoQ_L_49actionG_new(self)));
}
$R bench_echoQ_L_50C_18cont ($Cont C_cont, B_NoneType C_19res) {
    return $R_CONT(C_cont, B_None);
}
B_NoneType bench_echoQ_L_51ContD___init__ (bench_echoQ_L_51Cont L_self, $Cont C_cont) {
    ((bench_echoQ_L_51Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R bench_echoQ_L_51ContD___call__ (bench_echoQ_L_51Cont L_self, B_NoneType G_1) {
    $Cont C_cont = ((bench_echoQ_L_51Cont)(L_self))->C_cont;
    return bench_echoQ_L_50C_18cont(C_cont, G_1);
}
void bench_echoQ_L_51ContD___serialize__ (bench_echoQ_L_51Cont self, $Serial$state state) {
    $step_serialize(self->C_cont, state);
}
bench_echoQ_L_51Cont bench_echoQ_L_51ContD___deserialize__ (bench_echoQ_L_51Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct bench_echoQ_L_51Cont));
            self->$class = &bench_echoQ_L_51ContG_methods;
            return self;
        }
        self = $DNEW(bench_echoQ_L_51Cont, state);
    }
    self->C_cont = $step_deserialize(state);
    return self;
}
bench_echoQ_L_51Cont bench_echoQ_L_51ContG_new($Cont G_1) {
    bench_echoQ_L_51Cont $tmp = acton_malloc(sizeof(struct bench_echoQ_L_51Cont));
    $tmp->$class = &bench_echoQ_L_51ContG_methods;
    bench_echoQ_L_51ContG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct bench_echoQ_L_51ContG_class bench_echoQ_L_51ContG_methods;
B_NoneType bench_echoQ_L_52ContD___init__ (bench_echoQ_L_52Cont L_self, bench_echoQ_main self, $Cont C_cont, sshQ_Client c) {
    ((bench_echoQ_L_52Cont)(L_self))->self = self;
    ((bench_echoQ_L_52Cont)(L_self))->C_cont = C_cont;
    ((bench_echoQ_L_52Cont)(L_self))->c = c;
    return B_None;
}
$R bench_echoQ_L_52ContD___call__ (bench_echoQ_L_52Cont L_self, B_NoneType G_1) {
    bench_echoQ_main self = ((bench_echoQ_L_52Cont)(L_self))->self;
    $Cont C_cont = ((bench_echoQ_L_52Cont)(L_self))->C_cont;
    sshQ_Client c = ((bench_echoQ_L_52Cont)(L_self))->c;
    return bench_echoQ_L_37C_14cont(self, C_cont, c, G_1);
}
void bench_echoQ_L_52ContD___serialize__ (bench_echoQ_L_52Cont self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->C_cont, state);
    $step_serialize(self->c, state);
}
bench_echoQ_L_52Cont bench_echoQ_L_52ContD___deserialize__ (bench_echoQ_L_52Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct bench_echoQ_L_52Cont));
            self->$class = &bench_echoQ_L_52ContG_methods;
            return self;
        }
        self = $DNEW(bench_echoQ_L_52Cont, state);
    }
    self->self = $step_deserialize(state);
    self->C_cont = $step_deserialize(state);
    self->c = $step_deserialize(state);
    return self;
}
bench_echoQ_L_52Cont bench_echoQ_L_52ContG_new(bench_echoQ_main G_1, $Cont G_2, sshQ_Client G_3) {
    bench_echoQ_L_52Cont $tmp = acton_malloc(sizeof(struct bench_echoQ_L_52Cont));
    $tmp->$class = &bench_echoQ_L_52ContG_methods;
    bench_echoQ_L_52ContG_methods.__init__($tmp, G_1, G_2, G_3);
    return $tmp;
}
struct bench_echoQ_L_52ContG_class bench_echoQ_L_52ContG_methods;
$R bench_echoQ_L_53C_20cont (sshQ_Channel ch, bench_echoQ_main self, $Cont C_cont, B_NoneType C_21res) {
    #line 86 "src/bench_echo.act"
    ((B_Msg (*) ($WORD, B_str))((sshQ_Channel)(ch))->$class->request_exec)(ch, to$str("echo-stream"));
    #line 87 "src/bench_echo.act"
    int64_t chunk_size = 65536LL;
    #line 88 "src/bench_echo.act"
    int64_t offset = 0LL;
    #line 89 "src/bench_echo.act"
    while (true) {
        if (offset < ((int64_t (*) (B_Collection, B_bytes))B_len)(bench_echoQ_W_main_822, ((bench_echoQ_main)(self))->payload)) {
        }
        else {
            break;
        }
        #line 90 "src/bench_echo.act"
        int64_t end = (((int64_t)(offset + chunk_size)));
        #line 91 "src/bench_echo.act"
        if (end > ((int64_t (*) (B_Collection, B_bytes))B_len)(bench_echoQ_W_main_822, ((bench_echoQ_main)(self))->payload)) {
            #line 92 "src/bench_echo.act"
            end = ((int64_t (*) (B_Collection, B_bytes))B_len)(bench_echoQ_W_main_822, ((bench_echoQ_main)(self))->payload);
        }
        #line 93 "src/bench_echo.act"
        ((B_Msg (*) ($WORD, B_bytes))((sshQ_Channel)(ch))->$class->write)(ch, ((B_bytes (*) ($WORD, B_bytes, B_slice))((B_Sliceable)(bench_echoQ_W_main_751))->$class->__getslice__)(bench_echoQ_W_main_751, ((bench_echoQ_main)(self))->payload, B_sliceG_new(toB_int(offset), toB_int(end), B_None)));
        #line 94 "src/bench_echo.act"
        offset = end;
    }
    #line 95 "src/bench_echo.act"
    ((B_Msg (*) ($WORD))((sshQ_Channel)(ch))->$class->send_eof)(ch);
    return $R_CONT(C_cont, B_None);
}
$R bench_echoQ_L_54C_22cont ($Cont C_cont, B_NoneType C_23res) {
    return $R_CONT(C_cont, B_None);
}
B_NoneType bench_echoQ_L_55ContD___init__ (bench_echoQ_L_55Cont L_self, $Cont C_cont) {
    ((bench_echoQ_L_55Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R bench_echoQ_L_55ContD___call__ (bench_echoQ_L_55Cont L_self, B_NoneType G_1) {
    $Cont C_cont = ((bench_echoQ_L_55Cont)(L_self))->C_cont;
    return bench_echoQ_L_54C_22cont(C_cont, G_1);
}
void bench_echoQ_L_55ContD___serialize__ (bench_echoQ_L_55Cont self, $Serial$state state) {
    $step_serialize(self->C_cont, state);
}
bench_echoQ_L_55Cont bench_echoQ_L_55ContD___deserialize__ (bench_echoQ_L_55Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct bench_echoQ_L_55Cont));
            self->$class = &bench_echoQ_L_55ContG_methods;
            return self;
        }
        self = $DNEW(bench_echoQ_L_55Cont, state);
    }
    self->C_cont = $step_deserialize(state);
    return self;
}
bench_echoQ_L_55Cont bench_echoQ_L_55ContG_new($Cont G_1) {
    bench_echoQ_L_55Cont $tmp = acton_malloc(sizeof(struct bench_echoQ_L_55Cont));
    $tmp->$class = &bench_echoQ_L_55ContG_methods;
    bench_echoQ_L_55ContG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct bench_echoQ_L_55ContG_class bench_echoQ_L_55ContG_methods;
B_NoneType bench_echoQ_L_56ContD___init__ (bench_echoQ_L_56Cont L_self, sshQ_Channel ch, bench_echoQ_main self, $Cont C_cont) {
    ((bench_echoQ_L_56Cont)(L_self))->ch = ch;
    ((bench_echoQ_L_56Cont)(L_self))->self = self;
    ((bench_echoQ_L_56Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R bench_echoQ_L_56ContD___call__ (bench_echoQ_L_56Cont L_self, B_NoneType G_1) {
    sshQ_Channel ch = ((bench_echoQ_L_56Cont)(L_self))->ch;
    bench_echoQ_main self = ((bench_echoQ_L_56Cont)(L_self))->self;
    $Cont C_cont = ((bench_echoQ_L_56Cont)(L_self))->C_cont;
    return bench_echoQ_L_53C_20cont(ch, self, C_cont, G_1);
}
void bench_echoQ_L_56ContD___serialize__ (bench_echoQ_L_56Cont self, $Serial$state state) {
    $step_serialize(self->ch, state);
    $step_serialize(self->self, state);
    $step_serialize(self->C_cont, state);
}
bench_echoQ_L_56Cont bench_echoQ_L_56ContD___deserialize__ (bench_echoQ_L_56Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct bench_echoQ_L_56Cont));
            self->$class = &bench_echoQ_L_56ContG_methods;
            return self;
        }
        self = $DNEW(bench_echoQ_L_56Cont, state);
    }
    self->ch = $step_deserialize(state);
    self->self = $step_deserialize(state);
    self->C_cont = $step_deserialize(state);
    return self;
}
bench_echoQ_L_56Cont bench_echoQ_L_56ContG_new(sshQ_Channel G_1, bench_echoQ_main G_2, $Cont G_3) {
    bench_echoQ_L_56Cont $tmp = acton_malloc(sizeof(struct bench_echoQ_L_56Cont));
    $tmp->$class = &bench_echoQ_L_56ContG_methods;
    bench_echoQ_L_56ContG_methods.__init__($tmp, G_1, G_2, G_3);
    return $tmp;
}
struct bench_echoQ_L_56ContG_class bench_echoQ_L_56ContG_methods;
B_NoneType bench_echoQ_L_57procD___init__ (bench_echoQ_L_57proc L_self, bench_echoQ_main self, B_str msg) {
    ((bench_echoQ_L_57proc)(L_self))->self = self;
    ((bench_echoQ_L_57proc)(L_self))->msg = msg;
    return B_None;
}
$R bench_echoQ_L_57procD___call__ (bench_echoQ_L_57proc L_self, $Cont C_cont) {
    bench_echoQ_main self = ((bench_echoQ_L_57proc)(L_self))->self;
    B_str msg = ((bench_echoQ_L_57proc)(L_self))->msg;
    return (($R (*) ($WORD, $Cont, B_str))((bench_echoQ_main)(self))->$class->failG_local)(self, C_cont, msg);
}
$R bench_echoQ_L_57procD___exec__ (bench_echoQ_L_57proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((bench_echoQ_L_57proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void bench_echoQ_L_57procD___serialize__ (bench_echoQ_L_57proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->msg, state);
}
bench_echoQ_L_57proc bench_echoQ_L_57procD___deserialize__ (bench_echoQ_L_57proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct bench_echoQ_L_57proc));
            self->$class = &bench_echoQ_L_57procG_methods;
            return self;
        }
        self = $DNEW(bench_echoQ_L_57proc, state);
    }
    self->self = $step_deserialize(state);
    self->msg = $step_deserialize(state);
    return self;
}
bench_echoQ_L_57proc bench_echoQ_L_57procG_new(bench_echoQ_main G_1, B_str G_2) {
    bench_echoQ_L_57proc $tmp = acton_malloc(sizeof(struct bench_echoQ_L_57proc));
    $tmp->$class = &bench_echoQ_L_57procG_methods;
    bench_echoQ_L_57procG_methods.__init__($tmp, G_1, G_2);
    return $tmp;
}
struct bench_echoQ_L_57procG_class bench_echoQ_L_57procG_methods;
B_NoneType bench_echoQ_L_58procD___init__ (bench_echoQ_L_58proc L_self, bench_echoQ_main self, sshQ_Server s, B_str err) {
    ((bench_echoQ_L_58proc)(L_self))->self = self;
    ((bench_echoQ_L_58proc)(L_self))->s = s;
    ((bench_echoQ_L_58proc)(L_self))->err = err;
    return B_None;
}
$R bench_echoQ_L_58procD___call__ (bench_echoQ_L_58proc L_self, $Cont C_cont) {
    bench_echoQ_main self = ((bench_echoQ_L_58proc)(L_self))->self;
    sshQ_Server s = ((bench_echoQ_L_58proc)(L_self))->s;
    B_str err = ((bench_echoQ_L_58proc)(L_self))->err;
    return (($R (*) ($WORD, $Cont, sshQ_Server, B_str))((bench_echoQ_main)(self))->$class->on_listenG_local)(self, C_cont, s, err);
}
$R bench_echoQ_L_58procD___exec__ (bench_echoQ_L_58proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((bench_echoQ_L_58proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void bench_echoQ_L_58procD___serialize__ (bench_echoQ_L_58proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->s, state);
    $step_serialize(self->err, state);
}
bench_echoQ_L_58proc bench_echoQ_L_58procD___deserialize__ (bench_echoQ_L_58proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct bench_echoQ_L_58proc));
            self->$class = &bench_echoQ_L_58procG_methods;
            return self;
        }
        self = $DNEW(bench_echoQ_L_58proc, state);
    }
    self->self = $step_deserialize(state);
    self->s = $step_deserialize(state);
    self->err = $step_deserialize(state);
    return self;
}
bench_echoQ_L_58proc bench_echoQ_L_58procG_new(bench_echoQ_main G_1, sshQ_Server G_2, B_str G_3) {
    bench_echoQ_L_58proc $tmp = acton_malloc(sizeof(struct bench_echoQ_L_58proc));
    $tmp->$class = &bench_echoQ_L_58procG_methods;
    bench_echoQ_L_58procG_methods.__init__($tmp, G_1, G_2, G_3);
    return $tmp;
}
struct bench_echoQ_L_58procG_class bench_echoQ_L_58procG_methods;
B_NoneType bench_echoQ_L_59procD___init__ (bench_echoQ_L_59proc L_self, bench_echoQ_main self, sshQ_Server s, B_str reason) {
    ((bench_echoQ_L_59proc)(L_self))->self = self;
    ((bench_echoQ_L_59proc)(L_self))->s = s;
    ((bench_echoQ_L_59proc)(L_self))->reason = reason;
    return B_None;
}
$R bench_echoQ_L_59procD___call__ (bench_echoQ_L_59proc L_self, $Cont C_cont) {
    bench_echoQ_main self = ((bench_echoQ_L_59proc)(L_self))->self;
    sshQ_Server s = ((bench_echoQ_L_59proc)(L_self))->s;
    B_str reason = ((bench_echoQ_L_59proc)(L_self))->reason;
    return (($R (*) ($WORD, $Cont, sshQ_Server, B_str))((bench_echoQ_main)(self))->$class->on_server_closeG_local)(self, C_cont, s, reason);
}
$R bench_echoQ_L_59procD___exec__ (bench_echoQ_L_59proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((bench_echoQ_L_59proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void bench_echoQ_L_59procD___serialize__ (bench_echoQ_L_59proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->s, state);
    $step_serialize(self->reason, state);
}
bench_echoQ_L_59proc bench_echoQ_L_59procD___deserialize__ (bench_echoQ_L_59proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct bench_echoQ_L_59proc));
            self->$class = &bench_echoQ_L_59procG_methods;
            return self;
        }
        self = $DNEW(bench_echoQ_L_59proc, state);
    }
    self->self = $step_deserialize(state);
    self->s = $step_deserialize(state);
    self->reason = $step_deserialize(state);
    return self;
}
bench_echoQ_L_59proc bench_echoQ_L_59procG_new(bench_echoQ_main G_1, sshQ_Server G_2, B_str G_3) {
    bench_echoQ_L_59proc $tmp = acton_malloc(sizeof(struct bench_echoQ_L_59proc));
    $tmp->$class = &bench_echoQ_L_59procG_methods;
    bench_echoQ_L_59procG_methods.__init__($tmp, G_1, G_2, G_3);
    return $tmp;
}
struct bench_echoQ_L_59procG_class bench_echoQ_L_59procG_methods;
B_NoneType bench_echoQ_L_60procD___init__ (bench_echoQ_L_60proc L_self, bench_echoQ_main self, sshQ_ServerSession sess) {
    ((bench_echoQ_L_60proc)(L_self))->self = self;
    ((bench_echoQ_L_60proc)(L_self))->sess = sess;
    return B_None;
}
$R bench_echoQ_L_60procD___call__ (bench_echoQ_L_60proc L_self, $Cont C_cont) {
    bench_echoQ_main self = ((bench_echoQ_L_60proc)(L_self))->self;
    sshQ_ServerSession sess = ((bench_echoQ_L_60proc)(L_self))->sess;
    return (($R (*) ($WORD, $Cont, sshQ_ServerSession))((bench_echoQ_main)(self))->$class->on_sessionG_local)(self, C_cont, sess);
}
$R bench_echoQ_L_60procD___exec__ (bench_echoQ_L_60proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((bench_echoQ_L_60proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void bench_echoQ_L_60procD___serialize__ (bench_echoQ_L_60proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->sess, state);
}
bench_echoQ_L_60proc bench_echoQ_L_60procD___deserialize__ (bench_echoQ_L_60proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct bench_echoQ_L_60proc));
            self->$class = &bench_echoQ_L_60procG_methods;
            return self;
        }
        self = $DNEW(bench_echoQ_L_60proc, state);
    }
    self->self = $step_deserialize(state);
    self->sess = $step_deserialize(state);
    return self;
}
bench_echoQ_L_60proc bench_echoQ_L_60procG_new(bench_echoQ_main G_1, sshQ_ServerSession G_2) {
    bench_echoQ_L_60proc $tmp = acton_malloc(sizeof(struct bench_echoQ_L_60proc));
    $tmp->$class = &bench_echoQ_L_60procG_methods;
    bench_echoQ_L_60procG_methods.__init__($tmp, G_1, G_2);
    return $tmp;
}
struct bench_echoQ_L_60procG_class bench_echoQ_L_60procG_methods;
B_NoneType bench_echoQ_L_61procD___init__ (bench_echoQ_L_61proc L_self, bench_echoQ_main self, sshQ_ServerSession sess, sshQ_AuthRequest req) {
    ((bench_echoQ_L_61proc)(L_self))->self = self;
    ((bench_echoQ_L_61proc)(L_self))->sess = sess;
    ((bench_echoQ_L_61proc)(L_self))->req = req;
    return B_None;
}
$R bench_echoQ_L_61procD___call__ (bench_echoQ_L_61proc L_self, $Cont C_cont) {
    bench_echoQ_main self = ((bench_echoQ_L_61proc)(L_self))->self;
    sshQ_ServerSession sess = ((bench_echoQ_L_61proc)(L_self))->sess;
    sshQ_AuthRequest req = ((bench_echoQ_L_61proc)(L_self))->req;
    return (($R (*) ($WORD, $Cont, sshQ_ServerSession, sshQ_AuthRequest))((bench_echoQ_main)(self))->$class->on_authG_local)(self, C_cont, sess, req);
}
$R bench_echoQ_L_61procD___exec__ (bench_echoQ_L_61proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((bench_echoQ_L_61proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void bench_echoQ_L_61procD___serialize__ (bench_echoQ_L_61proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->sess, state);
    $step_serialize(self->req, state);
}
bench_echoQ_L_61proc bench_echoQ_L_61procD___deserialize__ (bench_echoQ_L_61proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct bench_echoQ_L_61proc));
            self->$class = &bench_echoQ_L_61procG_methods;
            return self;
        }
        self = $DNEW(bench_echoQ_L_61proc, state);
    }
    self->self = $step_deserialize(state);
    self->sess = $step_deserialize(state);
    self->req = $step_deserialize(state);
    return self;
}
bench_echoQ_L_61proc bench_echoQ_L_61procG_new(bench_echoQ_main G_1, sshQ_ServerSession G_2, sshQ_AuthRequest G_3) {
    bench_echoQ_L_61proc $tmp = acton_malloc(sizeof(struct bench_echoQ_L_61proc));
    $tmp->$class = &bench_echoQ_L_61procG_methods;
    bench_echoQ_L_61procG_methods.__init__($tmp, G_1, G_2, G_3);
    return $tmp;
}
struct bench_echoQ_L_61procG_class bench_echoQ_L_61procG_methods;
B_NoneType bench_echoQ_L_62procD___init__ (bench_echoQ_L_62proc L_self, bench_echoQ_main self, sshQ_ServerChannel ch, B_bytes data) {
    ((bench_echoQ_L_62proc)(L_self))->self = self;
    ((bench_echoQ_L_62proc)(L_self))->ch = ch;
    ((bench_echoQ_L_62proc)(L_self))->data = data;
    return B_None;
}
$R bench_echoQ_L_62procD___call__ (bench_echoQ_L_62proc L_self, $Cont C_cont) {
    bench_echoQ_main self = ((bench_echoQ_L_62proc)(L_self))->self;
    sshQ_ServerChannel ch = ((bench_echoQ_L_62proc)(L_self))->ch;
    B_bytes data = ((bench_echoQ_L_62proc)(L_self))->data;
    return (($R (*) ($WORD, $Cont, sshQ_ServerChannel, B_bytes))((bench_echoQ_main)(self))->$class->srv_on_dataG_local)(self, C_cont, ch, data);
}
$R bench_echoQ_L_62procD___exec__ (bench_echoQ_L_62proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((bench_echoQ_L_62proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void bench_echoQ_L_62procD___serialize__ (bench_echoQ_L_62proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->ch, state);
    $step_serialize(self->data, state);
}
bench_echoQ_L_62proc bench_echoQ_L_62procD___deserialize__ (bench_echoQ_L_62proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct bench_echoQ_L_62proc));
            self->$class = &bench_echoQ_L_62procG_methods;
            return self;
        }
        self = $DNEW(bench_echoQ_L_62proc, state);
    }
    self->self = $step_deserialize(state);
    self->ch = $step_deserialize(state);
    self->data = $step_deserialize(state);
    return self;
}
bench_echoQ_L_62proc bench_echoQ_L_62procG_new(bench_echoQ_main G_1, sshQ_ServerChannel G_2, B_bytes G_3) {
    bench_echoQ_L_62proc $tmp = acton_malloc(sizeof(struct bench_echoQ_L_62proc));
    $tmp->$class = &bench_echoQ_L_62procG_methods;
    bench_echoQ_L_62procG_methods.__init__($tmp, G_1, G_2, G_3);
    return $tmp;
}
struct bench_echoQ_L_62procG_class bench_echoQ_L_62procG_methods;
B_NoneType bench_echoQ_L_63procD___init__ (bench_echoQ_L_63proc L_self, bench_echoQ_main self, sshQ_ServerChannel ch, B_bytes data) {
    ((bench_echoQ_L_63proc)(L_self))->self = self;
    ((bench_echoQ_L_63proc)(L_self))->ch = ch;
    ((bench_echoQ_L_63proc)(L_self))->data = data;
    return B_None;
}
$R bench_echoQ_L_63procD___call__ (bench_echoQ_L_63proc L_self, $Cont C_cont) {
    bench_echoQ_main self = ((bench_echoQ_L_63proc)(L_self))->self;
    sshQ_ServerChannel ch = ((bench_echoQ_L_63proc)(L_self))->ch;
    B_bytes data = ((bench_echoQ_L_63proc)(L_self))->data;
    return (($R (*) ($WORD, $Cont, sshQ_ServerChannel, B_bytes))((bench_echoQ_main)(self))->$class->srv_on_stderrG_local)(self, C_cont, ch, data);
}
$R bench_echoQ_L_63procD___exec__ (bench_echoQ_L_63proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((bench_echoQ_L_63proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void bench_echoQ_L_63procD___serialize__ (bench_echoQ_L_63proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->ch, state);
    $step_serialize(self->data, state);
}
bench_echoQ_L_63proc bench_echoQ_L_63procD___deserialize__ (bench_echoQ_L_63proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct bench_echoQ_L_63proc));
            self->$class = &bench_echoQ_L_63procG_methods;
            return self;
        }
        self = $DNEW(bench_echoQ_L_63proc, state);
    }
    self->self = $step_deserialize(state);
    self->ch = $step_deserialize(state);
    self->data = $step_deserialize(state);
    return self;
}
bench_echoQ_L_63proc bench_echoQ_L_63procG_new(bench_echoQ_main G_1, sshQ_ServerChannel G_2, B_bytes G_3) {
    bench_echoQ_L_63proc $tmp = acton_malloc(sizeof(struct bench_echoQ_L_63proc));
    $tmp->$class = &bench_echoQ_L_63procG_methods;
    bench_echoQ_L_63procG_methods.__init__($tmp, G_1, G_2, G_3);
    return $tmp;
}
struct bench_echoQ_L_63procG_class bench_echoQ_L_63procG_methods;
B_NoneType bench_echoQ_L_64procD___init__ (bench_echoQ_L_64proc L_self, bench_echoQ_main self, sshQ_ServerChannel ch, B_str reason) {
    ((bench_echoQ_L_64proc)(L_self))->self = self;
    ((bench_echoQ_L_64proc)(L_self))->ch = ch;
    ((bench_echoQ_L_64proc)(L_self))->reason = reason;
    return B_None;
}
$R bench_echoQ_L_64procD___call__ (bench_echoQ_L_64proc L_self, $Cont C_cont) {
    bench_echoQ_main self = ((bench_echoQ_L_64proc)(L_self))->self;
    sshQ_ServerChannel ch = ((bench_echoQ_L_64proc)(L_self))->ch;
    B_str reason = ((bench_echoQ_L_64proc)(L_self))->reason;
    return (($R (*) ($WORD, $Cont, sshQ_ServerChannel, B_str))((bench_echoQ_main)(self))->$class->srv_on_closeG_local)(self, C_cont, ch, reason);
}
$R bench_echoQ_L_64procD___exec__ (bench_echoQ_L_64proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((bench_echoQ_L_64proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void bench_echoQ_L_64procD___serialize__ (bench_echoQ_L_64proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->ch, state);
    $step_serialize(self->reason, state);
}
bench_echoQ_L_64proc bench_echoQ_L_64procD___deserialize__ (bench_echoQ_L_64proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct bench_echoQ_L_64proc));
            self->$class = &bench_echoQ_L_64procG_methods;
            return self;
        }
        self = $DNEW(bench_echoQ_L_64proc, state);
    }
    self->self = $step_deserialize(state);
    self->ch = $step_deserialize(state);
    self->reason = $step_deserialize(state);
    return self;
}
bench_echoQ_L_64proc bench_echoQ_L_64procG_new(bench_echoQ_main G_1, sshQ_ServerChannel G_2, B_str G_3) {
    bench_echoQ_L_64proc $tmp = acton_malloc(sizeof(struct bench_echoQ_L_64proc));
    $tmp->$class = &bench_echoQ_L_64procG_methods;
    bench_echoQ_L_64procG_methods.__init__($tmp, G_1, G_2, G_3);
    return $tmp;
}
struct bench_echoQ_L_64procG_class bench_echoQ_L_64procG_methods;
B_NoneType bench_echoQ_L_65procD___init__ (bench_echoQ_L_65proc L_self, bench_echoQ_main self, sshQ_ServerSession sess) {
    ((bench_echoQ_L_65proc)(L_self))->self = self;
    ((bench_echoQ_L_65proc)(L_self))->sess = sess;
    return B_None;
}
$R bench_echoQ_L_65procD___call__ (bench_echoQ_L_65proc L_self, $Cont C_cont) {
    bench_echoQ_main self = ((bench_echoQ_L_65proc)(L_self))->self;
    sshQ_ServerSession sess = ((bench_echoQ_L_65proc)(L_self))->sess;
    return (($R (*) ($WORD, $Cont, sshQ_ServerSession))((bench_echoQ_main)(self))->$class->on_channel_openG_local)(self, C_cont, sess);
}
$R bench_echoQ_L_65procD___exec__ (bench_echoQ_L_65proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((bench_echoQ_L_65proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void bench_echoQ_L_65procD___serialize__ (bench_echoQ_L_65proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->sess, state);
}
bench_echoQ_L_65proc bench_echoQ_L_65procD___deserialize__ (bench_echoQ_L_65proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct bench_echoQ_L_65proc));
            self->$class = &bench_echoQ_L_65procG_methods;
            return self;
        }
        self = $DNEW(bench_echoQ_L_65proc, state);
    }
    self->self = $step_deserialize(state);
    self->sess = $step_deserialize(state);
    return self;
}
bench_echoQ_L_65proc bench_echoQ_L_65procG_new(bench_echoQ_main G_1, sshQ_ServerSession G_2) {
    bench_echoQ_L_65proc $tmp = acton_malloc(sizeof(struct bench_echoQ_L_65proc));
    $tmp->$class = &bench_echoQ_L_65procG_methods;
    bench_echoQ_L_65procG_methods.__init__($tmp, G_1, G_2);
    return $tmp;
}
struct bench_echoQ_L_65procG_class bench_echoQ_L_65procG_methods;
B_NoneType bench_echoQ_L_66procD___init__ (bench_echoQ_L_66proc L_self, bench_echoQ_main self, sshQ_ServerSession sess, sshQ_ServerChannel ch, B_str cmd) {
    ((bench_echoQ_L_66proc)(L_self))->self = self;
    ((bench_echoQ_L_66proc)(L_self))->sess = sess;
    ((bench_echoQ_L_66proc)(L_self))->ch = ch;
    ((bench_echoQ_L_66proc)(L_self))->cmd = cmd;
    return B_None;
}
$R bench_echoQ_L_66procD___call__ (bench_echoQ_L_66proc L_self, $Cont C_cont) {
    bench_echoQ_main self = ((bench_echoQ_L_66proc)(L_self))->self;
    sshQ_ServerSession sess = ((bench_echoQ_L_66proc)(L_self))->sess;
    sshQ_ServerChannel ch = ((bench_echoQ_L_66proc)(L_self))->ch;
    B_str cmd = ((bench_echoQ_L_66proc)(L_self))->cmd;
    return (($R (*) ($WORD, $Cont, sshQ_ServerSession, sshQ_ServerChannel, B_str))((bench_echoQ_main)(self))->$class->on_execG_local)(self, C_cont, sess, ch, cmd);
}
$R bench_echoQ_L_66procD___exec__ (bench_echoQ_L_66proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((bench_echoQ_L_66proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void bench_echoQ_L_66procD___serialize__ (bench_echoQ_L_66proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->sess, state);
    $step_serialize(self->ch, state);
    $step_serialize(self->cmd, state);
}
bench_echoQ_L_66proc bench_echoQ_L_66procD___deserialize__ (bench_echoQ_L_66proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct bench_echoQ_L_66proc));
            self->$class = &bench_echoQ_L_66procG_methods;
            return self;
        }
        self = $DNEW(bench_echoQ_L_66proc, state);
    }
    self->self = $step_deserialize(state);
    self->sess = $step_deserialize(state);
    self->ch = $step_deserialize(state);
    self->cmd = $step_deserialize(state);
    return self;
}
bench_echoQ_L_66proc bench_echoQ_L_66procG_new(bench_echoQ_main G_1, sshQ_ServerSession G_2, sshQ_ServerChannel G_3, B_str G_4) {
    bench_echoQ_L_66proc $tmp = acton_malloc(sizeof(struct bench_echoQ_L_66proc));
    $tmp->$class = &bench_echoQ_L_66procG_methods;
    bench_echoQ_L_66procG_methods.__init__($tmp, G_1, G_2, G_3, G_4);
    return $tmp;
}
struct bench_echoQ_L_66procG_class bench_echoQ_L_66procG_methods;
B_NoneType bench_echoQ_L_67procD___init__ (bench_echoQ_L_67proc L_self, bench_echoQ_main self, sshQ_Client c, B_str state, sshQ_HostKeyInfo info) {
    ((bench_echoQ_L_67proc)(L_self))->self = self;
    ((bench_echoQ_L_67proc)(L_self))->c = c;
    ((bench_echoQ_L_67proc)(L_self))->state = state;
    ((bench_echoQ_L_67proc)(L_self))->info = info;
    return B_None;
}
$R bench_echoQ_L_67procD___call__ (bench_echoQ_L_67proc L_self, $Cont C_cont) {
    bench_echoQ_main self = ((bench_echoQ_L_67proc)(L_self))->self;
    sshQ_Client c = ((bench_echoQ_L_67proc)(L_self))->c;
    B_str state = ((bench_echoQ_L_67proc)(L_self))->state;
    sshQ_HostKeyInfo info = ((bench_echoQ_L_67proc)(L_self))->info;
    return (($R (*) ($WORD, $Cont, sshQ_Client, B_str, sshQ_HostKeyInfo))((bench_echoQ_main)(self))->$class->on_hostkeyG_local)(self, C_cont, c, state, info);
}
$R bench_echoQ_L_67procD___exec__ (bench_echoQ_L_67proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((bench_echoQ_L_67proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void bench_echoQ_L_67procD___serialize__ (bench_echoQ_L_67proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->c, state);
    $step_serialize(self->state, state);
    $step_serialize(self->info, state);
}
bench_echoQ_L_67proc bench_echoQ_L_67procD___deserialize__ (bench_echoQ_L_67proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct bench_echoQ_L_67proc));
            self->$class = &bench_echoQ_L_67procG_methods;
            return self;
        }
        self = $DNEW(bench_echoQ_L_67proc, state);
    }
    self->self = $step_deserialize(state);
    self->c = $step_deserialize(state);
    self->state = $step_deserialize(state);
    self->info = $step_deserialize(state);
    return self;
}
bench_echoQ_L_67proc bench_echoQ_L_67procG_new(bench_echoQ_main G_1, sshQ_Client G_2, B_str G_3, sshQ_HostKeyInfo G_4) {
    bench_echoQ_L_67proc $tmp = acton_malloc(sizeof(struct bench_echoQ_L_67proc));
    $tmp->$class = &bench_echoQ_L_67procG_methods;
    bench_echoQ_L_67procG_methods.__init__($tmp, G_1, G_2, G_3, G_4);
    return $tmp;
}
struct bench_echoQ_L_67procG_class bench_echoQ_L_67procG_methods;
B_NoneType bench_echoQ_L_68procD___init__ (bench_echoQ_L_68proc L_self, bench_echoQ_main self, sshQ_Client c, B_str err) {
    ((bench_echoQ_L_68proc)(L_self))->self = self;
    ((bench_echoQ_L_68proc)(L_self))->c = c;
    ((bench_echoQ_L_68proc)(L_self))->err = err;
    return B_None;
}
$R bench_echoQ_L_68procD___call__ (bench_echoQ_L_68proc L_self, $Cont C_cont) {
    bench_echoQ_main self = ((bench_echoQ_L_68proc)(L_self))->self;
    sshQ_Client c = ((bench_echoQ_L_68proc)(L_self))->c;
    B_str err = ((bench_echoQ_L_68proc)(L_self))->err;
    return (($R (*) ($WORD, $Cont, sshQ_Client, B_str))((bench_echoQ_main)(self))->$class->on_connectG_local)(self, C_cont, c, err);
}
$R bench_echoQ_L_68procD___exec__ (bench_echoQ_L_68proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((bench_echoQ_L_68proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void bench_echoQ_L_68procD___serialize__ (bench_echoQ_L_68proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->c, state);
    $step_serialize(self->err, state);
}
bench_echoQ_L_68proc bench_echoQ_L_68procD___deserialize__ (bench_echoQ_L_68proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct bench_echoQ_L_68proc));
            self->$class = &bench_echoQ_L_68procG_methods;
            return self;
        }
        self = $DNEW(bench_echoQ_L_68proc, state);
    }
    self->self = $step_deserialize(state);
    self->c = $step_deserialize(state);
    self->err = $step_deserialize(state);
    return self;
}
bench_echoQ_L_68proc bench_echoQ_L_68procG_new(bench_echoQ_main G_1, sshQ_Client G_2, B_str G_3) {
    bench_echoQ_L_68proc $tmp = acton_malloc(sizeof(struct bench_echoQ_L_68proc));
    $tmp->$class = &bench_echoQ_L_68procG_methods;
    bench_echoQ_L_68procG_methods.__init__($tmp, G_1, G_2, G_3);
    return $tmp;
}
struct bench_echoQ_L_68procG_class bench_echoQ_L_68procG_methods;
B_NoneType bench_echoQ_L_69procD___init__ (bench_echoQ_L_69proc L_self, bench_echoQ_main self, sshQ_Client c, B_str reason) {
    ((bench_echoQ_L_69proc)(L_self))->self = self;
    ((bench_echoQ_L_69proc)(L_self))->c = c;
    ((bench_echoQ_L_69proc)(L_self))->reason = reason;
    return B_None;
}
$R bench_echoQ_L_69procD___call__ (bench_echoQ_L_69proc L_self, $Cont C_cont) {
    bench_echoQ_main self = ((bench_echoQ_L_69proc)(L_self))->self;
    sshQ_Client c = ((bench_echoQ_L_69proc)(L_self))->c;
    B_str reason = ((bench_echoQ_L_69proc)(L_self))->reason;
    return (($R (*) ($WORD, $Cont, sshQ_Client, B_str))((bench_echoQ_main)(self))->$class->on_client_closeG_local)(self, C_cont, c, reason);
}
$R bench_echoQ_L_69procD___exec__ (bench_echoQ_L_69proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((bench_echoQ_L_69proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void bench_echoQ_L_69procD___serialize__ (bench_echoQ_L_69proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->c, state);
    $step_serialize(self->reason, state);
}
bench_echoQ_L_69proc bench_echoQ_L_69procD___deserialize__ (bench_echoQ_L_69proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct bench_echoQ_L_69proc));
            self->$class = &bench_echoQ_L_69procG_methods;
            return self;
        }
        self = $DNEW(bench_echoQ_L_69proc, state);
    }
    self->self = $step_deserialize(state);
    self->c = $step_deserialize(state);
    self->reason = $step_deserialize(state);
    return self;
}
bench_echoQ_L_69proc bench_echoQ_L_69procG_new(bench_echoQ_main G_1, sshQ_Client G_2, B_str G_3) {
    bench_echoQ_L_69proc $tmp = acton_malloc(sizeof(struct bench_echoQ_L_69proc));
    $tmp->$class = &bench_echoQ_L_69procG_methods;
    bench_echoQ_L_69procG_methods.__init__($tmp, G_1, G_2, G_3);
    return $tmp;
}
struct bench_echoQ_L_69procG_class bench_echoQ_L_69procG_methods;
B_NoneType bench_echoQ_L_70procD___init__ (bench_echoQ_L_70proc L_self, bench_echoQ_main self, sshQ_Channel ch, B_str err) {
    ((bench_echoQ_L_70proc)(L_self))->self = self;
    ((bench_echoQ_L_70proc)(L_self))->ch = ch;
    ((bench_echoQ_L_70proc)(L_self))->err = err;
    return B_None;
}
$R bench_echoQ_L_70procD___call__ (bench_echoQ_L_70proc L_self, $Cont C_cont) {
    bench_echoQ_main self = ((bench_echoQ_L_70proc)(L_self))->self;
    sshQ_Channel ch = ((bench_echoQ_L_70proc)(L_self))->ch;
    B_str err = ((bench_echoQ_L_70proc)(L_self))->err;
    return (($R (*) ($WORD, $Cont, sshQ_Channel, B_str))((bench_echoQ_main)(self))->$class->ch_openG_local)(self, C_cont, ch, err);
}
$R bench_echoQ_L_70procD___exec__ (bench_echoQ_L_70proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((bench_echoQ_L_70proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void bench_echoQ_L_70procD___serialize__ (bench_echoQ_L_70proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->ch, state);
    $step_serialize(self->err, state);
}
bench_echoQ_L_70proc bench_echoQ_L_70procD___deserialize__ (bench_echoQ_L_70proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct bench_echoQ_L_70proc));
            self->$class = &bench_echoQ_L_70procG_methods;
            return self;
        }
        self = $DNEW(bench_echoQ_L_70proc, state);
    }
    self->self = $step_deserialize(state);
    self->ch = $step_deserialize(state);
    self->err = $step_deserialize(state);
    return self;
}
bench_echoQ_L_70proc bench_echoQ_L_70procG_new(bench_echoQ_main G_1, sshQ_Channel G_2, B_str G_3) {
    bench_echoQ_L_70proc $tmp = acton_malloc(sizeof(struct bench_echoQ_L_70proc));
    $tmp->$class = &bench_echoQ_L_70procG_methods;
    bench_echoQ_L_70procG_methods.__init__($tmp, G_1, G_2, G_3);
    return $tmp;
}
struct bench_echoQ_L_70procG_class bench_echoQ_L_70procG_methods;
B_NoneType bench_echoQ_L_71procD___init__ (bench_echoQ_L_71proc L_self, bench_echoQ_main self, sshQ_Channel ch, B_bytes data) {
    ((bench_echoQ_L_71proc)(L_self))->self = self;
    ((bench_echoQ_L_71proc)(L_self))->ch = ch;
    ((bench_echoQ_L_71proc)(L_self))->data = data;
    return B_None;
}
$R bench_echoQ_L_71procD___call__ (bench_echoQ_L_71proc L_self, $Cont C_cont) {
    bench_echoQ_main self = ((bench_echoQ_L_71proc)(L_self))->self;
    sshQ_Channel ch = ((bench_echoQ_L_71proc)(L_self))->ch;
    B_bytes data = ((bench_echoQ_L_71proc)(L_self))->data;
    return (($R (*) ($WORD, $Cont, sshQ_Channel, B_bytes))((bench_echoQ_main)(self))->$class->ch_outG_local)(self, C_cont, ch, data);
}
$R bench_echoQ_L_71procD___exec__ (bench_echoQ_L_71proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((bench_echoQ_L_71proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void bench_echoQ_L_71procD___serialize__ (bench_echoQ_L_71proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->ch, state);
    $step_serialize(self->data, state);
}
bench_echoQ_L_71proc bench_echoQ_L_71procD___deserialize__ (bench_echoQ_L_71proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct bench_echoQ_L_71proc));
            self->$class = &bench_echoQ_L_71procG_methods;
            return self;
        }
        self = $DNEW(bench_echoQ_L_71proc, state);
    }
    self->self = $step_deserialize(state);
    self->ch = $step_deserialize(state);
    self->data = $step_deserialize(state);
    return self;
}
bench_echoQ_L_71proc bench_echoQ_L_71procG_new(bench_echoQ_main G_1, sshQ_Channel G_2, B_bytes G_3) {
    bench_echoQ_L_71proc $tmp = acton_malloc(sizeof(struct bench_echoQ_L_71proc));
    $tmp->$class = &bench_echoQ_L_71procG_methods;
    bench_echoQ_L_71procG_methods.__init__($tmp, G_1, G_2, G_3);
    return $tmp;
}
struct bench_echoQ_L_71procG_class bench_echoQ_L_71procG_methods;
B_NoneType bench_echoQ_L_72procD___init__ (bench_echoQ_L_72proc L_self, bench_echoQ_main self, sshQ_Channel ch, B_bytes data) {
    ((bench_echoQ_L_72proc)(L_self))->self = self;
    ((bench_echoQ_L_72proc)(L_self))->ch = ch;
    ((bench_echoQ_L_72proc)(L_self))->data = data;
    return B_None;
}
$R bench_echoQ_L_72procD___call__ (bench_echoQ_L_72proc L_self, $Cont C_cont) {
    bench_echoQ_main self = ((bench_echoQ_L_72proc)(L_self))->self;
    sshQ_Channel ch = ((bench_echoQ_L_72proc)(L_self))->ch;
    B_bytes data = ((bench_echoQ_L_72proc)(L_self))->data;
    return (($R (*) ($WORD, $Cont, sshQ_Channel, B_bytes))((bench_echoQ_main)(self))->$class->ch_errG_local)(self, C_cont, ch, data);
}
$R bench_echoQ_L_72procD___exec__ (bench_echoQ_L_72proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((bench_echoQ_L_72proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void bench_echoQ_L_72procD___serialize__ (bench_echoQ_L_72proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->ch, state);
    $step_serialize(self->data, state);
}
bench_echoQ_L_72proc bench_echoQ_L_72procD___deserialize__ (bench_echoQ_L_72proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct bench_echoQ_L_72proc));
            self->$class = &bench_echoQ_L_72procG_methods;
            return self;
        }
        self = $DNEW(bench_echoQ_L_72proc, state);
    }
    self->self = $step_deserialize(state);
    self->ch = $step_deserialize(state);
    self->data = $step_deserialize(state);
    return self;
}
bench_echoQ_L_72proc bench_echoQ_L_72procG_new(bench_echoQ_main G_1, sshQ_Channel G_2, B_bytes G_3) {
    bench_echoQ_L_72proc $tmp = acton_malloc(sizeof(struct bench_echoQ_L_72proc));
    $tmp->$class = &bench_echoQ_L_72procG_methods;
    bench_echoQ_L_72procG_methods.__init__($tmp, G_1, G_2, G_3);
    return $tmp;
}
struct bench_echoQ_L_72procG_class bench_echoQ_L_72procG_methods;
B_NoneType bench_echoQ_L_73procD___init__ (bench_echoQ_L_73proc L_self, bench_echoQ_main self, sshQ_Channel ch, int64_t code, B_str sig) {
    ((bench_echoQ_L_73proc)(L_self))->self = self;
    ((bench_echoQ_L_73proc)(L_self))->ch = ch;
    ((bench_echoQ_L_73proc)(L_self))->code = code;
    ((bench_echoQ_L_73proc)(L_self))->sig = sig;
    return B_None;
}
$R bench_echoQ_L_73procD___call__ (bench_echoQ_L_73proc L_self, $Cont C_cont) {
    bench_echoQ_main self = ((bench_echoQ_L_73proc)(L_self))->self;
    sshQ_Channel ch = ((bench_echoQ_L_73proc)(L_self))->ch;
    int64_t code = ((int64_t)((bench_echoQ_L_73proc)(L_self))->code);
    B_str sig = ((bench_echoQ_L_73proc)(L_self))->sig;
    return (($R (*) ($WORD, $Cont, sshQ_Channel, int64_t, B_str))((bench_echoQ_main)(self))->$class->ch_exitG_local)(self, C_cont, ch, code, sig);
}
$R bench_echoQ_L_73procD___exec__ (bench_echoQ_L_73proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((bench_echoQ_L_73proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void bench_echoQ_L_73procD___serialize__ (bench_echoQ_L_73proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->ch, state);
    $val_serialize(I64_ID, &self->code, state);
    $step_serialize(self->sig, state);
}
bench_echoQ_L_73proc bench_echoQ_L_73procD___deserialize__ (bench_echoQ_L_73proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct bench_echoQ_L_73proc));
            self->$class = &bench_echoQ_L_73procG_methods;
            return self;
        }
        self = $DNEW(bench_echoQ_L_73proc, state);
    }
    self->self = $step_deserialize(state);
    self->ch = $step_deserialize(state);
    $tmp = $val_deserialize(state);
    memcpy(&self->code, &$tmp, sizeof(self->code));
    self->sig = $step_deserialize(state);
    return self;
}
bench_echoQ_L_73proc bench_echoQ_L_73procG_new(bench_echoQ_main G_1, sshQ_Channel G_2, int64_t G_3, B_str G_4) {
    bench_echoQ_L_73proc $tmp = acton_malloc(sizeof(struct bench_echoQ_L_73proc));
    $tmp->$class = &bench_echoQ_L_73procG_methods;
    bench_echoQ_L_73procG_methods.__init__($tmp, G_1, G_2, G_3, G_4);
    return $tmp;
}
struct bench_echoQ_L_73procG_class bench_echoQ_L_73procG_methods;
B_NoneType bench_echoQ_L_74procD___init__ (bench_echoQ_L_74proc L_self, bench_echoQ_main self, sshQ_Channel ch, B_str reason) {
    ((bench_echoQ_L_74proc)(L_self))->self = self;
    ((bench_echoQ_L_74proc)(L_self))->ch = ch;
    ((bench_echoQ_L_74proc)(L_self))->reason = reason;
    return B_None;
}
$R bench_echoQ_L_74procD___call__ (bench_echoQ_L_74proc L_self, $Cont C_cont) {
    bench_echoQ_main self = ((bench_echoQ_L_74proc)(L_self))->self;
    sshQ_Channel ch = ((bench_echoQ_L_74proc)(L_self))->ch;
    B_str reason = ((bench_echoQ_L_74proc)(L_self))->reason;
    return (($R (*) ($WORD, $Cont, sshQ_Channel, B_str))((bench_echoQ_main)(self))->$class->ch_closeG_local)(self, C_cont, ch, reason);
}
$R bench_echoQ_L_74procD___exec__ (bench_echoQ_L_74proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((bench_echoQ_L_74proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void bench_echoQ_L_74procD___serialize__ (bench_echoQ_L_74proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->ch, state);
    $step_serialize(self->reason, state);
}
bench_echoQ_L_74proc bench_echoQ_L_74procD___deserialize__ (bench_echoQ_L_74proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct bench_echoQ_L_74proc));
            self->$class = &bench_echoQ_L_74procG_methods;
            return self;
        }
        self = $DNEW(bench_echoQ_L_74proc, state);
    }
    self->self = $step_deserialize(state);
    self->ch = $step_deserialize(state);
    self->reason = $step_deserialize(state);
    return self;
}
bench_echoQ_L_74proc bench_echoQ_L_74procG_new(bench_echoQ_main G_1, sshQ_Channel G_2, B_str G_3) {
    bench_echoQ_L_74proc $tmp = acton_malloc(sizeof(struct bench_echoQ_L_74proc));
    $tmp->$class = &bench_echoQ_L_74procG_methods;
    bench_echoQ_L_74procG_methods.__init__($tmp, G_1, G_2, G_3);
    return $tmp;
}
struct bench_echoQ_L_74procG_class bench_echoQ_L_74procG_methods;
$R bench_echoQ_L_75C_24cont ($Cont C_cont, bench_echoQ_main G_act, B_NoneType C_25res) {
    return $R_CONT(C_cont, G_act);
}
B_NoneType bench_echoQ_L_76ContD___init__ (bench_echoQ_L_76Cont L_self, $Cont C_cont, bench_echoQ_main G_act) {
    ((bench_echoQ_L_76Cont)(L_self))->C_cont = C_cont;
    ((bench_echoQ_L_76Cont)(L_self))->G_act = G_act;
    return B_None;
}
$R bench_echoQ_L_76ContD___call__ (bench_echoQ_L_76Cont L_self, B_NoneType G_1) {
    $Cont C_cont = ((bench_echoQ_L_76Cont)(L_self))->C_cont;
    bench_echoQ_main G_act = ((bench_echoQ_L_76Cont)(L_self))->G_act;
    return bench_echoQ_L_75C_24cont(C_cont, G_act, G_1);
}
void bench_echoQ_L_76ContD___serialize__ (bench_echoQ_L_76Cont self, $Serial$state state) {
    $step_serialize(self->C_cont, state);
    $step_serialize(self->G_act, state);
}
bench_echoQ_L_76Cont bench_echoQ_L_76ContD___deserialize__ (bench_echoQ_L_76Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct bench_echoQ_L_76Cont));
            self->$class = &bench_echoQ_L_76ContG_methods;
            return self;
        }
        self = $DNEW(bench_echoQ_L_76Cont, state);
    }
    self->C_cont = $step_deserialize(state);
    self->G_act = $step_deserialize(state);
    return self;
}
bench_echoQ_L_76Cont bench_echoQ_L_76ContG_new($Cont G_1, bench_echoQ_main G_2) {
    bench_echoQ_L_76Cont $tmp = acton_malloc(sizeof(struct bench_echoQ_L_76Cont));
    $tmp->$class = &bench_echoQ_L_76ContG_methods;
    bench_echoQ_L_76ContG_methods.__init__($tmp, G_1, G_2);
    return $tmp;
}
struct bench_echoQ_L_76ContG_class bench_echoQ_L_76ContG_methods;
B_NoneType bench_echoQ_L_77procD___init__ (bench_echoQ_L_77proc L_self, bench_echoQ_main G_act, B_Env env) {
    ((bench_echoQ_L_77proc)(L_self))->G_act = G_act;
    ((bench_echoQ_L_77proc)(L_self))->env = env;
    return B_None;
}
$R bench_echoQ_L_77procD___call__ (bench_echoQ_L_77proc L_self, $Cont C_cont) {
    bench_echoQ_main G_act = ((bench_echoQ_L_77proc)(L_self))->G_act;
    B_Env env = ((bench_echoQ_L_77proc)(L_self))->env;
    return (($R (*) ($WORD, $Cont, B_Env))((bench_echoQ_main)(G_act))->$class->__init__)(G_act, C_cont, env);
}
$R bench_echoQ_L_77procD___exec__ (bench_echoQ_L_77proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((bench_echoQ_L_77proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void bench_echoQ_L_77procD___serialize__ (bench_echoQ_L_77proc self, $Serial$state state) {
    $step_serialize(self->G_act, state);
    $step_serialize(self->env, state);
}
bench_echoQ_L_77proc bench_echoQ_L_77procD___deserialize__ (bench_echoQ_L_77proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct bench_echoQ_L_77proc));
            self->$class = &bench_echoQ_L_77procG_methods;
            return self;
        }
        self = $DNEW(bench_echoQ_L_77proc, state);
    }
    self->G_act = $step_deserialize(state);
    self->env = $step_deserialize(state);
    return self;
}
bench_echoQ_L_77proc bench_echoQ_L_77procG_new(bench_echoQ_main G_1, B_Env G_2) {
    bench_echoQ_L_77proc $tmp = acton_malloc(sizeof(struct bench_echoQ_L_77proc));
    $tmp->$class = &bench_echoQ_L_77procG_methods;
    bench_echoQ_L_77procG_methods.__init__($tmp, G_1, G_2);
    return $tmp;
}
struct bench_echoQ_L_77procG_class bench_echoQ_L_77procG_methods;
$R bench_echoQ_mainD___init__ (bench_echoQ_main self, $Cont C_cont, B_Env env) {
    ((bench_echoQ_main)(self))->env = env;
    #line 9 "src/bench_echo.act"
    ((bench_echoQ_main)(self))->payload_mb = 1LL;
    #line 10 "src/bench_echo.act"
    if (((int64_t (*) (B_Collection, B_list))B_len)(bench_echoQ_W_main_34, ((B_Env)(((bench_echoQ_main)(self))->env))->argv) > 1LL) {
        #line 11 "src/bench_echo.act"
        int64_t pm = B_intG_new(((B_atom)$listD_U__getitem__(((B_Env)(((bench_echoQ_main)(self))->env))->argv, 1LL)), B_None);
        #line 12 "src/bench_echo.act"
        ((bench_echoQ_main)(self))->payload_mb = pm;
    }
    #line 14 "src/bench_echo.act"
    ((bench_echoQ_main)(self))->payload = to$bytesD_len("", 0);
    #line 15 "src/bench_echo.act"
    ((bench_echoQ_main)(self))->echoed_len = 0LL;
    #line 16 "src/bench_echo.act"
    ((bench_echoQ_main)(self))->server = B_None;
    #line 17 "src/bench_echo.act"
    ((bench_echoQ_main)(self))->client = B_None;
    #line 18 "src/bench_echo.act"
    ((bench_echoQ_main)(self))->t_start = timeQ_monotonic();
    #line 19 "src/bench_echo.act"
    ((bench_echoQ_main)(self))->t_connect = timeQ_monotonic();
    #line 123 "src/bench_echo.act"
    ((bench_echoQ_main)(self))->pattern = to$bytesD_len("", 0);
    B_range N_range_iter = B_rangeG_new(256LL, B_None, B_None);
    if ($PUSH()) {
        #line 124 "src/bench_echo.act"
        while (true) {
            int64_t i = $rangeD_U__next__(N_range_iter);
            ((bench_echoQ_main)(self))->pattern = ((B_bytes (*) ($WORD, B_bytes, B_bytes))((B_Plus)(bench_echoQ_W_main_1092))->$class->__iadd__)(bench_echoQ_W_main_1092, ((bench_echoQ_main)(self))->pattern, B_bytesG_new(bench_echoQ_W_main_1054, B_mk_list(1, toB_int(i))));
        }
        $DROP();
    }
    else {
        B_BaseException N_2x = $POP();
        if ($ISINSTANCE0(N_2x, B_StopIteration)) {
        }
        else {
            $RAISE(N_2x);
            __builtin_unreachable();
        }
    }
    B_range N_3range_iter = B_rangeG_new((((int64_t)(((int64_t)((bench_echoQ_main)(self))->payload_mb) * 4096LL))), B_None, B_None);
    if ($PUSH()) {
        #line 126 "src/bench_echo.act"
        while (true) {
            int64_t i = $rangeD_U__next__(N_3range_iter);
            ((bench_echoQ_main)(self))->payload = ((B_bytes (*) ($WORD, B_bytes, B_bytes))((B_Plus)(bench_echoQ_W_main_1092))->$class->__iadd__)(bench_echoQ_W_main_1092, ((bench_echoQ_main)(self))->payload, ((bench_echoQ_main)(self))->pattern);
        }
        $DROP();
    }
    else {
        B_BaseException N_5x = $POP();
        if ($ISINSTANCE0(N_5x, B_StopIteration)) {
        }
        else {
            $RAISE(N_5x);
            __builtin_unreachable();
        }
    }
    return sshQ_ServerG_newact((($Cont)bench_echoQ_L_2ContG_new(self, C_cont)), netQ_TCPListenCapG_new(netQ_TCPCapG_new(netQ_NetCapG_new(((B_Env)(((bench_echoQ_main)(self))->env))->cap))), to$str("127.0.0.1"), B_u16G_new(((B_atom)toB_int(0LL)), B_None), (($action)bench_echoQ_L_4actionG_new(self)), (($action)bench_echoQ_L_6actionG_new(self)), (($action)bench_echoQ_L_8actionG_new(self)), (($action)bench_echoQ_L_10actionG_new(self)), (($action)bench_echoQ_L_12actionG_new(self)), (($action)bench_echoQ_L_14actionG_new(self)), B_None, B_None, B_None, B_None, B_None, B_None, B_None, B_None, B_None, B_None, B_None);
}
#line 21 "src/bench_echo.act"
$R bench_echoQ_mainD_failG_local (bench_echoQ_main self, $Cont C_cont, B_str msg) {
    #line 22 "src/bench_echo.act"
    ((B_NoneType (*) (B_tuple, B_str, B_str, B_bool, B_bool))B_print)($NEWTUPLE(2, to$str("FAIL:"), msg), B_None, B_None, B_None, B_None);
    #line 23 "src/bench_echo.act"
    ((B_Msg (*) ($WORD, int64_t))((B_Env)(((bench_echoQ_main)(self))->env))->$class->exit)(((bench_echoQ_main)(self))->env, 1LL);
    return $R_CONT(C_cont, B_None);
}
#line 25 "src/bench_echo.act"
$R bench_echoQ_mainD_on_listenG_local (bench_echoQ_main self, $Cont C_cont, sshQ_Server s, B_str err) {
    B_Plus W_main_194 = (B_Plus)B_TimesD_strG_witness;
    if ($ISNOTNONE0(err)) {
        return (($R (*) ($WORD, $Cont, B_str))((bench_echoQ_main)(self))->$class->failG_local)(self, (($Cont)bench_echoQ_L_27ContG_new(C_cont)), ((B_str (*) ($WORD, B_str, B_str))((B_Plus)(W_main_194))->$class->__add__)(W_main_194, to$str("listen: "), ((B_str)err)));
    }
    else {
        return $R_CONT((($Cont)bench_echoQ_L_28ContG_new(self, C_cont, s)), B_None);
    }
}
#line 41 "src/bench_echo.act"
$R bench_echoQ_mainD_on_server_closeG_local (bench_echoQ_main self, $Cont C_cont, sshQ_Server s, B_str reason) {
    #line 42 "src/bench_echo.act"
    return $R_CONT(C_cont, B_None);
}
#line 44 "src/bench_echo.act"
$R bench_echoQ_mainD_on_sessionG_local (bench_echoQ_main self, $Cont C_cont, sshQ_ServerSession sess) {
    #line 45 "src/bench_echo.act"
    return $R_CONT(C_cont, B_None);
}
#line 47 "src/bench_echo.act"
$R bench_echoQ_mainD_on_authG_local (bench_echoQ_main self, $Cont C_cont, sshQ_ServerSession sess, sshQ_AuthRequest req) {
    #line 48 "src/bench_echo.act"
    ((B_Msg (*) ($WORD))((sshQ_ServerSession)(sess))->$class->accept_auth)(sess);
    return $R_CONT(C_cont, B_None);
}
#line 50 "src/bench_echo.act"
$R bench_echoQ_mainD_srv_on_dataG_local (bench_echoQ_main self, $Cont C_cont, sshQ_ServerChannel ch, B_bytes data) {
    #line 51 "src/bench_echo.act"
    if ($ISNOTNONE0(data)) {
        #line 52 "src/bench_echo.act"
        ((B_Msg (*) ($WORD, B_bytes))((sshQ_ServerChannel)(ch))->$class->write)(ch, ((B_bytes)data));
    }
    else {
        #line 54 "src/bench_echo.act"
        ((B_Msg (*) ($WORD, int64_t))((sshQ_ServerChannel)(ch))->$class->send_exit_status)(ch, 0LL);
        #line 55 "src/bench_echo.act"
        ((B_Msg (*) ($WORD))((sshQ_ServerChannel)(ch))->$class->close)(ch);
    }
    return $R_CONT(C_cont, B_None);
}
#line 57 "src/bench_echo.act"
$R bench_echoQ_mainD_srv_on_stderrG_local (bench_echoQ_main self, $Cont C_cont, sshQ_ServerChannel ch, B_bytes data) {
    #line 58 "src/bench_echo.act"
    return $R_CONT(C_cont, B_None);
}
#line 60 "src/bench_echo.act"
$R bench_echoQ_mainD_srv_on_closeG_local (bench_echoQ_main self, $Cont C_cont, sshQ_ServerChannel ch, B_str reason) {
    #line 61 "src/bench_echo.act"
    return $R_CONT(C_cont, B_None);
}
#line 63 "src/bench_echo.act"
$R bench_echoQ_mainD_on_channel_openG_local (bench_echoQ_main self, $Cont C_cont, sshQ_ServerSession sess) {
    return sshQ_ServerChannelG_newact((($Cont)bench_echoQ_L_30ContG_new(sess, C_cont)), sess, (($action)bench_echoQ_L_32actionG_new(self)), (($action)bench_echoQ_L_34actionG_new(self)), (($action)bench_echoQ_L_36actionG_new(self)));
}
#line 66 "src/bench_echo.act"
$R bench_echoQ_mainD_on_execG_local (bench_echoQ_main self, $Cont C_cont, sshQ_ServerSession sess, sshQ_ServerChannel ch, B_str cmd) {
    #line 67 "src/bench_echo.act"
    ((B_Msg (*) ($WORD))((sshQ_ServerChannel)(ch))->$class->accept_request)(ch);
    return $R_CONT(C_cont, B_None);
}
#line 69 "src/bench_echo.act"
$R bench_echoQ_mainD_on_hostkeyG_local (bench_echoQ_main self, $Cont C_cont, sshQ_Client c, B_str state, sshQ_HostKeyInfo info) {
    #line 70 "src/bench_echo.act"
    ((B_Msg (*) ($WORD))((sshQ_Client)(c))->$class->accept_hostkey)(c);
    return $R_CONT(C_cont, B_None);
}
#line 72 "src/bench_echo.act"
$R bench_echoQ_mainD_on_connectG_local (bench_echoQ_main self, $Cont C_cont, sshQ_Client c, B_str err) {
    B_Plus W_main_514 = (B_Plus)B_TimesD_strG_witness;
    if ($ISNOTNONE0(err)) {
        return (($R (*) ($WORD, $Cont, B_str))((bench_echoQ_main)(self))->$class->failG_local)(self, (($Cont)bench_echoQ_L_51ContG_new(C_cont)), ((B_str (*) ($WORD, B_str, B_str))((B_Plus)(W_main_514))->$class->__add__)(W_main_514, to$str("connect: "), ((B_str)err)));
    }
    else {
        return $R_CONT((($Cont)bench_echoQ_L_52ContG_new(self, C_cont, c)), B_None);
    }
}
#line 79 "src/bench_echo.act"
$R bench_echoQ_mainD_on_client_closeG_local (bench_echoQ_main self, $Cont C_cont, sshQ_Client c, B_str reason) {
    #line 80 "src/bench_echo.act"
    return $R_CONT(C_cont, B_None);
}
#line 82 "src/bench_echo.act"
$R bench_echoQ_mainD_ch_openG_local (bench_echoQ_main self, $Cont C_cont, sshQ_Channel ch, B_str err) {
    B_Plus W_main_636 = (B_Plus)B_TimesD_strG_witness;
    if ($ISNOTNONE0(err)) {
        return (($R (*) ($WORD, $Cont, B_str))((bench_echoQ_main)(self))->$class->failG_local)(self, (($Cont)bench_echoQ_L_55ContG_new(C_cont)), ((B_str (*) ($WORD, B_str, B_str))((B_Plus)(W_main_636))->$class->__add__)(W_main_636, to$str("channel open: "), ((B_str)err)));
    }
    else {
        return $R_CONT((($Cont)bench_echoQ_L_56ContG_new(ch, self, C_cont)), B_None);
    }
}
#line 97 "src/bench_echo.act"
$R bench_echoQ_mainD_ch_outG_local (bench_echoQ_main self, $Cont C_cont, sshQ_Channel ch, B_bytes data) {
    #line 98 "src/bench_echo.act"
    if ($ISNOTNONE0(data)) {
        ((bench_echoQ_main)(self))->echoed_len += ((int64_t (*) (B_Collection, B_bytes))B_len)(bench_echoQ_W_main_822, ((B_bytes)data));
        #line 100 "src/bench_echo.act"
        if (((int64_t)((bench_echoQ_main)(self))->echoed_len) >= ((int64_t (*) (B_Collection, B_bytes))B_len)(bench_echoQ_W_main_822, ((bench_echoQ_main)(self))->payload)) {
            #line 101 "src/bench_echo.act"
            timeQ_Instant t_end = timeQ_monotonic();
            #line 102 "src/bench_echo.act"
            int64_t dt_us = (((int64_t)(((int64_t (*) ($WORD))((timeQ_Instant)(t_end))->$class->unix_us)(t_end) - ((int64_t (*) ($WORD))((timeQ_Instant)(((bench_echoQ_main)(self))->t_connect))->$class->unix_us)(((bench_echoQ_main)(self))->t_connect))));
            #line 103 "src/bench_echo.act"
            if (dt_us <= 0LL) {
                #line 104 "src/bench_echo.act"
                dt_us = 1LL;
            }
            #line 105 "src/bench_echo.act"
            int64_t kbps = (int_FLOORDIV((int_FLOORDIV((((int64_t)(((int64_t)((bench_echoQ_main)(self))->echoed_len) * 1000000LL))), dt_us)), 1024LL));
            #line 106 "src/bench_echo.act"
            ((B_NoneType (*) (B_tuple, B_str, B_str, B_bool, B_bool))B_print)($NEWTUPLE(7, to$str("echoed"), toB_int(((int64_t)((bench_echoQ_main)(self))->echoed_len)), to$str("bytes in"), toB_int(dt_us), to$str("us ="), toB_int(kbps), to$str("KiB/s")), B_None, B_None, B_None, B_None);
            #line 107 "src/bench_echo.act"
            ((B_Msg (*) ($WORD))((sshQ_Channel)(ch))->$class->close)(ch);
            #line 108 "src/bench_echo.act"
            if ($ISNOTNONE0(((bench_echoQ_main)(self))->client)) {
                #line 109 "src/bench_echo.act"
                ({ sshQ_Client $tmp = ((sshQ_Client)((bench_echoQ_main)(self))->client);
                   ((B_Msg (*) ($WORD))((sshQ_Client)($tmp))->$class->close)($tmp); });
            }
            #line 110 "src/bench_echo.act"
            if ($ISNOTNONE0(((bench_echoQ_main)(self))->server)) {
                #line 111 "src/bench_echo.act"
                ({ sshQ_Server $tmp = ((sshQ_Server)((bench_echoQ_main)(self))->server);
                   ((B_Msg (*) ($WORD))((sshQ_Server)($tmp))->$class->close)($tmp); });
            }
            #line 112 "src/bench_echo.act"
            ((B_Msg (*) ($WORD, int64_t))((B_Env)(((bench_echoQ_main)(self))->env))->$class->exit)(((bench_echoQ_main)(self))->env, 0LL);
        }
    }
    return $R_CONT(C_cont, B_None);
}
#line 114 "src/bench_echo.act"
$R bench_echoQ_mainD_ch_errG_local (bench_echoQ_main self, $Cont C_cont, sshQ_Channel ch, B_bytes data) {
    #line 115 "src/bench_echo.act"
    return $R_CONT(C_cont, B_None);
}
#line 117 "src/bench_echo.act"
$R bench_echoQ_mainD_ch_exitG_local (bench_echoQ_main self, $Cont C_cont, sshQ_Channel ch, int64_t code, B_str sig) {
    #line 118 "src/bench_echo.act"
    return $R_CONT(C_cont, B_None);
}
#line 120 "src/bench_echo.act"
$R bench_echoQ_mainD_ch_closeG_local (bench_echoQ_main self, $Cont C_cont, sshQ_Channel ch, B_str reason) {
    #line 121 "src/bench_echo.act"
    return $R_CONT(C_cont, B_None);
}
B_Msg bench_echoQ_mainD_fail (bench_echoQ_main self, B_str msg) {
    return $ASYNC((($Actor)self), (($Cont)bench_echoQ_L_57procG_new(self, msg)));
}
B_Msg bench_echoQ_mainD_on_listen (bench_echoQ_main self, sshQ_Server s, B_str err) {
    return $ASYNC((($Actor)self), (($Cont)bench_echoQ_L_58procG_new(self, s, err)));
}
B_Msg bench_echoQ_mainD_on_server_close (bench_echoQ_main self, sshQ_Server s, B_str reason) {
    return $ASYNC((($Actor)self), (($Cont)bench_echoQ_L_59procG_new(self, s, reason)));
}
B_Msg bench_echoQ_mainD_on_session (bench_echoQ_main self, sshQ_ServerSession sess) {
    return $ASYNC((($Actor)self), (($Cont)bench_echoQ_L_60procG_new(self, sess)));
}
B_Msg bench_echoQ_mainD_on_auth (bench_echoQ_main self, sshQ_ServerSession sess, sshQ_AuthRequest req) {
    return $ASYNC((($Actor)self), (($Cont)bench_echoQ_L_61procG_new(self, sess, req)));
}
B_Msg bench_echoQ_mainD_srv_on_data (bench_echoQ_main self, sshQ_ServerChannel ch, B_bytes data) {
    return $ASYNC((($Actor)self), (($Cont)bench_echoQ_L_62procG_new(self, ch, data)));
}
B_Msg bench_echoQ_mainD_srv_on_stderr (bench_echoQ_main self, sshQ_ServerChannel ch, B_bytes data) {
    return $ASYNC((($Actor)self), (($Cont)bench_echoQ_L_63procG_new(self, ch, data)));
}
B_Msg bench_echoQ_mainD_srv_on_close (bench_echoQ_main self, sshQ_ServerChannel ch, B_str reason) {
    return $ASYNC((($Actor)self), (($Cont)bench_echoQ_L_64procG_new(self, ch, reason)));
}
B_Msg bench_echoQ_mainD_on_channel_open (bench_echoQ_main self, sshQ_ServerSession sess) {
    return $ASYNC((($Actor)self), (($Cont)bench_echoQ_L_65procG_new(self, sess)));
}
B_Msg bench_echoQ_mainD_on_exec (bench_echoQ_main self, sshQ_ServerSession sess, sshQ_ServerChannel ch, B_str cmd) {
    return $ASYNC((($Actor)self), (($Cont)bench_echoQ_L_66procG_new(self, sess, ch, cmd)));
}
B_Msg bench_echoQ_mainD_on_hostkey (bench_echoQ_main self, sshQ_Client c, B_str state, sshQ_HostKeyInfo info) {
    return $ASYNC((($Actor)self), (($Cont)bench_echoQ_L_67procG_new(self, c, state, info)));
}
B_Msg bench_echoQ_mainD_on_connect (bench_echoQ_main self, sshQ_Client c, B_str err) {
    return $ASYNC((($Actor)self), (($Cont)bench_echoQ_L_68procG_new(self, c, err)));
}
B_Msg bench_echoQ_mainD_on_client_close (bench_echoQ_main self, sshQ_Client c, B_str reason) {
    return $ASYNC((($Actor)self), (($Cont)bench_echoQ_L_69procG_new(self, c, reason)));
}
B_Msg bench_echoQ_mainD_ch_open (bench_echoQ_main self, sshQ_Channel ch, B_str err) {
    return $ASYNC((($Actor)self), (($Cont)bench_echoQ_L_70procG_new(self, ch, err)));
}
B_Msg bench_echoQ_mainD_ch_out (bench_echoQ_main self, sshQ_Channel ch, B_bytes data) {
    return $ASYNC((($Actor)self), (($Cont)bench_echoQ_L_71procG_new(self, ch, data)));
}
B_Msg bench_echoQ_mainD_ch_err (bench_echoQ_main self, sshQ_Channel ch, B_bytes data) {
    return $ASYNC((($Actor)self), (($Cont)bench_echoQ_L_72procG_new(self, ch, data)));
}
B_Msg bench_echoQ_mainD_ch_exit (bench_echoQ_main self, sshQ_Channel ch, int64_t code, B_str sig) {
    return $ASYNC((($Actor)self), (($Cont)bench_echoQ_L_73procG_new(self, ch, code, sig)));
}
B_Msg bench_echoQ_mainD_ch_close (bench_echoQ_main self, sshQ_Channel ch, B_str reason) {
    return $ASYNC((($Actor)self), (($Cont)bench_echoQ_L_74procG_new(self, ch, reason)));
}
void bench_echoQ_mainD___serialize__ (bench_echoQ_main self, $Serial$state state) {
    $ActorG_methods.__serialize__(($Actor)self, state);
    $step_serialize(self->env, state);
    $val_serialize(I64_ID, &self->payload_mb, state);
    $step_serialize(self->payload, state);
    $val_serialize(I64_ID, &self->echoed_len, state);
    $step_serialize(self->server, state);
    $step_serialize(self->client, state);
    $step_serialize(self->t_start, state);
    $step_serialize(self->t_connect, state);
    $step_serialize(self->pattern, state);
}
bench_echoQ_main bench_echoQ_mainD___deserialize__ (bench_echoQ_main self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct bench_echoQ_main));
            self->$class = &bench_echoQ_mainG_methods;
            return self;
        }
        self = $DNEW(bench_echoQ_main, state);
    }
    $ActorG_methods.__deserialize__(($Actor)self, state);
    self->env = $step_deserialize(state);
    $tmp = $val_deserialize(state);
    memcpy(&self->payload_mb, &$tmp, sizeof(self->payload_mb));
    self->payload = $step_deserialize(state);
    $tmp = $val_deserialize(state);
    memcpy(&self->echoed_len, &$tmp, sizeof(self->echoed_len));
    self->server = $step_deserialize(state);
    self->client = $step_deserialize(state);
    self->t_start = $step_deserialize(state);
    self->t_connect = $step_deserialize(state);
    self->pattern = $step_deserialize(state);
    return self;
}
void bench_echoQ_mainD_GCfinalizer (void *obj, void *cdata) {
    bench_echoQ_main self = (bench_echoQ_main)obj;
    self->$class->__cleanup__(self);
}
$R bench_echoQ_mainG_new($Cont G_1, B_Env G_2) {
    bench_echoQ_main $tmp = acton_malloc(sizeof(struct bench_echoQ_main));
    $tmp->$class = &bench_echoQ_mainG_methods;
    return bench_echoQ_mainG_methods.__init__($tmp, $CONSTCONT($tmp, G_1), G_2);
}
struct bench_echoQ_mainG_class bench_echoQ_mainG_methods;
$R bench_echoQ_mainG_newact ($Cont C_cont, B_Env env) {
    bench_echoQ_main G_act = $NEWACTOR(bench_echoQ_main);
    if ((void*)G_act->$class->__cleanup__ != (void*)$ActorD___cleanup__) $InstallFinalizer(G_act, bench_echoQ_mainD_GCfinalizer);
    return $AWAIT((($Cont)bench_echoQ_L_76ContG_new(C_cont, G_act)), $ASYNC((($Actor)G_act), (($Cont)bench_echoQ_L_77procG_new(G_act, env))));
}
int bench_echoQ_done$ = 0;
void bench_echoQ___init__ () {
    if (bench_echoQ_done$) return;
    bench_echoQ_done$ = 1;
    netQ___init__();
    sshQ___init__();
    timeQ___init__();
    {
        bench_echoQ_L_2ContG_methods.$GCINFO = "bench_echoQ_L_2Cont";
        bench_echoQ_L_2ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        bench_echoQ_L_2ContG_methods.__bool__ = (B_bool (*) (bench_echoQ_L_2Cont))B_valueG_methods.__bool__;
        bench_echoQ_L_2ContG_methods.__str__ = (B_str (*) (bench_echoQ_L_2Cont))B_valueG_methods.__str__;
        bench_echoQ_L_2ContG_methods.__repr__ = (B_str (*) (bench_echoQ_L_2Cont))B_valueG_methods.__repr__;
        bench_echoQ_L_2ContG_methods.__init__ = (B_NoneType (*) (bench_echoQ_L_2Cont, bench_echoQ_main, $Cont))bench_echoQ_L_2ContD___init__;
        bench_echoQ_L_2ContG_methods.__call__ = ($R (*) (bench_echoQ_L_2Cont, sshQ_Server))bench_echoQ_L_2ContD___call__;
        bench_echoQ_L_2ContG_methods.__serialize__ = bench_echoQ_L_2ContD___serialize__;
        bench_echoQ_L_2ContG_methods.__deserialize__ = bench_echoQ_L_2ContD___deserialize__;
        $register(&bench_echoQ_L_2ContG_methods);
    }
    {
        bench_echoQ_L_4actionG_methods.$GCINFO = "bench_echoQ_L_4action";
        bench_echoQ_L_4actionG_methods.$superclass = ($SuperG_class)&$actionG_methods;
        bench_echoQ_L_4actionG_methods.__bool__ = (B_bool (*) (bench_echoQ_L_4action))B_valueG_methods.__bool__;
        bench_echoQ_L_4actionG_methods.__str__ = (B_str (*) (bench_echoQ_L_4action))B_valueG_methods.__str__;
        bench_echoQ_L_4actionG_methods.__repr__ = (B_str (*) (bench_echoQ_L_4action))B_valueG_methods.__repr__;
        bench_echoQ_L_4actionG_methods.__init__ = (B_NoneType (*) (bench_echoQ_L_4action, bench_echoQ_main))bench_echoQ_L_4actionD___init__;
        bench_echoQ_L_4actionG_methods.__call__ = ($R (*) (bench_echoQ_L_4action, $Cont, sshQ_Server, B_str))bench_echoQ_L_4actionD___call__;
        bench_echoQ_L_4actionG_methods.__exec__ = ($R (*) (bench_echoQ_L_4action, $Cont, sshQ_Server, B_str))bench_echoQ_L_4actionD___exec__;
        bench_echoQ_L_4actionG_methods.__asyn__ = (B_Msg (*) (bench_echoQ_L_4action, sshQ_Server, B_str))bench_echoQ_L_4actionD___asyn__;
        bench_echoQ_L_4actionG_methods.__serialize__ = bench_echoQ_L_4actionD___serialize__;
        bench_echoQ_L_4actionG_methods.__deserialize__ = bench_echoQ_L_4actionD___deserialize__;
        $register(&bench_echoQ_L_4actionG_methods);
    }
    {
        bench_echoQ_L_6actionG_methods.$GCINFO = "bench_echoQ_L_6action";
        bench_echoQ_L_6actionG_methods.$superclass = ($SuperG_class)&$actionG_methods;
        bench_echoQ_L_6actionG_methods.__bool__ = (B_bool (*) (bench_echoQ_L_6action))B_valueG_methods.__bool__;
        bench_echoQ_L_6actionG_methods.__str__ = (B_str (*) (bench_echoQ_L_6action))B_valueG_methods.__str__;
        bench_echoQ_L_6actionG_methods.__repr__ = (B_str (*) (bench_echoQ_L_6action))B_valueG_methods.__repr__;
        bench_echoQ_L_6actionG_methods.__init__ = (B_NoneType (*) (bench_echoQ_L_6action, bench_echoQ_main))bench_echoQ_L_6actionD___init__;
        bench_echoQ_L_6actionG_methods.__call__ = ($R (*) (bench_echoQ_L_6action, $Cont, sshQ_Server, B_str))bench_echoQ_L_6actionD___call__;
        bench_echoQ_L_6actionG_methods.__exec__ = ($R (*) (bench_echoQ_L_6action, $Cont, sshQ_Server, B_str))bench_echoQ_L_6actionD___exec__;
        bench_echoQ_L_6actionG_methods.__asyn__ = (B_Msg (*) (bench_echoQ_L_6action, sshQ_Server, B_str))bench_echoQ_L_6actionD___asyn__;
        bench_echoQ_L_6actionG_methods.__serialize__ = bench_echoQ_L_6actionD___serialize__;
        bench_echoQ_L_6actionG_methods.__deserialize__ = bench_echoQ_L_6actionD___deserialize__;
        $register(&bench_echoQ_L_6actionG_methods);
    }
    {
        bench_echoQ_L_8actionG_methods.$GCINFO = "bench_echoQ_L_8action";
        bench_echoQ_L_8actionG_methods.$superclass = ($SuperG_class)&$actionG_methods;
        bench_echoQ_L_8actionG_methods.__bool__ = (B_bool (*) (bench_echoQ_L_8action))B_valueG_methods.__bool__;
        bench_echoQ_L_8actionG_methods.__str__ = (B_str (*) (bench_echoQ_L_8action))B_valueG_methods.__str__;
        bench_echoQ_L_8actionG_methods.__repr__ = (B_str (*) (bench_echoQ_L_8action))B_valueG_methods.__repr__;
        bench_echoQ_L_8actionG_methods.__init__ = (B_NoneType (*) (bench_echoQ_L_8action, bench_echoQ_main))bench_echoQ_L_8actionD___init__;
        bench_echoQ_L_8actionG_methods.__call__ = ($R (*) (bench_echoQ_L_8action, $Cont, sshQ_ServerSession))bench_echoQ_L_8actionD___call__;
        bench_echoQ_L_8actionG_methods.__exec__ = ($R (*) (bench_echoQ_L_8action, $Cont, sshQ_ServerSession))bench_echoQ_L_8actionD___exec__;
        bench_echoQ_L_8actionG_methods.__asyn__ = (B_Msg (*) (bench_echoQ_L_8action, sshQ_ServerSession))bench_echoQ_L_8actionD___asyn__;
        bench_echoQ_L_8actionG_methods.__serialize__ = bench_echoQ_L_8actionD___serialize__;
        bench_echoQ_L_8actionG_methods.__deserialize__ = bench_echoQ_L_8actionD___deserialize__;
        $register(&bench_echoQ_L_8actionG_methods);
    }
    {
        bench_echoQ_L_10actionG_methods.$GCINFO = "bench_echoQ_L_10action";
        bench_echoQ_L_10actionG_methods.$superclass = ($SuperG_class)&$actionG_methods;
        bench_echoQ_L_10actionG_methods.__bool__ = (B_bool (*) (bench_echoQ_L_10action))B_valueG_methods.__bool__;
        bench_echoQ_L_10actionG_methods.__str__ = (B_str (*) (bench_echoQ_L_10action))B_valueG_methods.__str__;
        bench_echoQ_L_10actionG_methods.__repr__ = (B_str (*) (bench_echoQ_L_10action))B_valueG_methods.__repr__;
        bench_echoQ_L_10actionG_methods.__init__ = (B_NoneType (*) (bench_echoQ_L_10action, bench_echoQ_main))bench_echoQ_L_10actionD___init__;
        bench_echoQ_L_10actionG_methods.__call__ = ($R (*) (bench_echoQ_L_10action, $Cont, sshQ_ServerSession, sshQ_AuthRequest))bench_echoQ_L_10actionD___call__;
        bench_echoQ_L_10actionG_methods.__exec__ = ($R (*) (bench_echoQ_L_10action, $Cont, sshQ_ServerSession, sshQ_AuthRequest))bench_echoQ_L_10actionD___exec__;
        bench_echoQ_L_10actionG_methods.__asyn__ = (B_Msg (*) (bench_echoQ_L_10action, sshQ_ServerSession, sshQ_AuthRequest))bench_echoQ_L_10actionD___asyn__;
        bench_echoQ_L_10actionG_methods.__serialize__ = bench_echoQ_L_10actionD___serialize__;
        bench_echoQ_L_10actionG_methods.__deserialize__ = bench_echoQ_L_10actionD___deserialize__;
        $register(&bench_echoQ_L_10actionG_methods);
    }
    {
        bench_echoQ_L_12actionG_methods.$GCINFO = "bench_echoQ_L_12action";
        bench_echoQ_L_12actionG_methods.$superclass = ($SuperG_class)&$actionG_methods;
        bench_echoQ_L_12actionG_methods.__bool__ = (B_bool (*) (bench_echoQ_L_12action))B_valueG_methods.__bool__;
        bench_echoQ_L_12actionG_methods.__str__ = (B_str (*) (bench_echoQ_L_12action))B_valueG_methods.__str__;
        bench_echoQ_L_12actionG_methods.__repr__ = (B_str (*) (bench_echoQ_L_12action))B_valueG_methods.__repr__;
        bench_echoQ_L_12actionG_methods.__init__ = (B_NoneType (*) (bench_echoQ_L_12action, bench_echoQ_main))bench_echoQ_L_12actionD___init__;
        bench_echoQ_L_12actionG_methods.__call__ = ($R (*) (bench_echoQ_L_12action, $Cont, sshQ_ServerSession))bench_echoQ_L_12actionD___call__;
        bench_echoQ_L_12actionG_methods.__exec__ = ($R (*) (bench_echoQ_L_12action, $Cont, sshQ_ServerSession))bench_echoQ_L_12actionD___exec__;
        bench_echoQ_L_12actionG_methods.__asyn__ = (B_Msg (*) (bench_echoQ_L_12action, sshQ_ServerSession))bench_echoQ_L_12actionD___asyn__;
        bench_echoQ_L_12actionG_methods.__serialize__ = bench_echoQ_L_12actionD___serialize__;
        bench_echoQ_L_12actionG_methods.__deserialize__ = bench_echoQ_L_12actionD___deserialize__;
        $register(&bench_echoQ_L_12actionG_methods);
    }
    {
        bench_echoQ_L_14actionG_methods.$GCINFO = "bench_echoQ_L_14action";
        bench_echoQ_L_14actionG_methods.$superclass = ($SuperG_class)&$actionG_methods;
        bench_echoQ_L_14actionG_methods.__bool__ = (B_bool (*) (bench_echoQ_L_14action))B_valueG_methods.__bool__;
        bench_echoQ_L_14actionG_methods.__str__ = (B_str (*) (bench_echoQ_L_14action))B_valueG_methods.__str__;
        bench_echoQ_L_14actionG_methods.__repr__ = (B_str (*) (bench_echoQ_L_14action))B_valueG_methods.__repr__;
        bench_echoQ_L_14actionG_methods.__init__ = (B_NoneType (*) (bench_echoQ_L_14action, bench_echoQ_main))bench_echoQ_L_14actionD___init__;
        bench_echoQ_L_14actionG_methods.__call__ = ($R (*) (bench_echoQ_L_14action, $Cont, sshQ_ServerSession, sshQ_ServerChannel, B_str))bench_echoQ_L_14actionD___call__;
        bench_echoQ_L_14actionG_methods.__exec__ = ($R (*) (bench_echoQ_L_14action, $Cont, sshQ_ServerSession, sshQ_ServerChannel, B_str))bench_echoQ_L_14actionD___exec__;
        bench_echoQ_L_14actionG_methods.__asyn__ = (B_Msg (*) (bench_echoQ_L_14action, sshQ_ServerSession, sshQ_ServerChannel, B_str))bench_echoQ_L_14actionD___asyn__;
        bench_echoQ_L_14actionG_methods.__serialize__ = bench_echoQ_L_14actionD___serialize__;
        bench_echoQ_L_14actionG_methods.__deserialize__ = bench_echoQ_L_14actionD___deserialize__;
        $register(&bench_echoQ_L_14actionG_methods);
    }
    {
        bench_echoQ_L_18ContG_methods.$GCINFO = "bench_echoQ_L_18Cont";
        bench_echoQ_L_18ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        bench_echoQ_L_18ContG_methods.__bool__ = (B_bool (*) (bench_echoQ_L_18Cont))B_valueG_methods.__bool__;
        bench_echoQ_L_18ContG_methods.__str__ = (B_str (*) (bench_echoQ_L_18Cont))B_valueG_methods.__str__;
        bench_echoQ_L_18ContG_methods.__repr__ = (B_str (*) (bench_echoQ_L_18Cont))B_valueG_methods.__repr__;
        bench_echoQ_L_18ContG_methods.__init__ = (B_NoneType (*) (bench_echoQ_L_18Cont, bench_echoQ_main, $Cont))bench_echoQ_L_18ContD___init__;
        bench_echoQ_L_18ContG_methods.__call__ = ($R (*) (bench_echoQ_L_18Cont, sshQ_Client))bench_echoQ_L_18ContD___call__;
        bench_echoQ_L_18ContG_methods.__serialize__ = bench_echoQ_L_18ContD___serialize__;
        bench_echoQ_L_18ContG_methods.__deserialize__ = bench_echoQ_L_18ContD___deserialize__;
        $register(&bench_echoQ_L_18ContG_methods);
    }
    {
        bench_echoQ_L_20actionG_methods.$GCINFO = "bench_echoQ_L_20action";
        bench_echoQ_L_20actionG_methods.$superclass = ($SuperG_class)&$actionG_methods;
        bench_echoQ_L_20actionG_methods.__bool__ = (B_bool (*) (bench_echoQ_L_20action))B_valueG_methods.__bool__;
        bench_echoQ_L_20actionG_methods.__str__ = (B_str (*) (bench_echoQ_L_20action))B_valueG_methods.__str__;
        bench_echoQ_L_20actionG_methods.__repr__ = (B_str (*) (bench_echoQ_L_20action))B_valueG_methods.__repr__;
        bench_echoQ_L_20actionG_methods.__init__ = (B_NoneType (*) (bench_echoQ_L_20action, bench_echoQ_main))bench_echoQ_L_20actionD___init__;
        bench_echoQ_L_20actionG_methods.__call__ = ($R (*) (bench_echoQ_L_20action, $Cont, sshQ_Client, B_str))bench_echoQ_L_20actionD___call__;
        bench_echoQ_L_20actionG_methods.__exec__ = ($R (*) (bench_echoQ_L_20action, $Cont, sshQ_Client, B_str))bench_echoQ_L_20actionD___exec__;
        bench_echoQ_L_20actionG_methods.__asyn__ = (B_Msg (*) (bench_echoQ_L_20action, sshQ_Client, B_str))bench_echoQ_L_20actionD___asyn__;
        bench_echoQ_L_20actionG_methods.__serialize__ = bench_echoQ_L_20actionD___serialize__;
        bench_echoQ_L_20actionG_methods.__deserialize__ = bench_echoQ_L_20actionD___deserialize__;
        $register(&bench_echoQ_L_20actionG_methods);
    }
    {
        bench_echoQ_L_22actionG_methods.$GCINFO = "bench_echoQ_L_22action";
        bench_echoQ_L_22actionG_methods.$superclass = ($SuperG_class)&$actionG_methods;
        bench_echoQ_L_22actionG_methods.__bool__ = (B_bool (*) (bench_echoQ_L_22action))B_valueG_methods.__bool__;
        bench_echoQ_L_22actionG_methods.__str__ = (B_str (*) (bench_echoQ_L_22action))B_valueG_methods.__str__;
        bench_echoQ_L_22actionG_methods.__repr__ = (B_str (*) (bench_echoQ_L_22action))B_valueG_methods.__repr__;
        bench_echoQ_L_22actionG_methods.__init__ = (B_NoneType (*) (bench_echoQ_L_22action, bench_echoQ_main))bench_echoQ_L_22actionD___init__;
        bench_echoQ_L_22actionG_methods.__call__ = ($R (*) (bench_echoQ_L_22action, $Cont, sshQ_Client, B_str))bench_echoQ_L_22actionD___call__;
        bench_echoQ_L_22actionG_methods.__exec__ = ($R (*) (bench_echoQ_L_22action, $Cont, sshQ_Client, B_str))bench_echoQ_L_22actionD___exec__;
        bench_echoQ_L_22actionG_methods.__asyn__ = (B_Msg (*) (bench_echoQ_L_22action, sshQ_Client, B_str))bench_echoQ_L_22actionD___asyn__;
        bench_echoQ_L_22actionG_methods.__serialize__ = bench_echoQ_L_22actionD___serialize__;
        bench_echoQ_L_22actionG_methods.__deserialize__ = bench_echoQ_L_22actionD___deserialize__;
        $register(&bench_echoQ_L_22actionG_methods);
    }
    {
        bench_echoQ_L_24actionG_methods.$GCINFO = "bench_echoQ_L_24action";
        bench_echoQ_L_24actionG_methods.$superclass = ($SuperG_class)&$actionG_methods;
        bench_echoQ_L_24actionG_methods.__bool__ = (B_bool (*) (bench_echoQ_L_24action))B_valueG_methods.__bool__;
        bench_echoQ_L_24actionG_methods.__str__ = (B_str (*) (bench_echoQ_L_24action))B_valueG_methods.__str__;
        bench_echoQ_L_24actionG_methods.__repr__ = (B_str (*) (bench_echoQ_L_24action))B_valueG_methods.__repr__;
        bench_echoQ_L_24actionG_methods.__init__ = (B_NoneType (*) (bench_echoQ_L_24action, bench_echoQ_main))bench_echoQ_L_24actionD___init__;
        bench_echoQ_L_24actionG_methods.__call__ = ($R (*) (bench_echoQ_L_24action, $Cont, sshQ_Client, B_str, sshQ_HostKeyInfo))bench_echoQ_L_24actionD___call__;
        bench_echoQ_L_24actionG_methods.__exec__ = ($R (*) (bench_echoQ_L_24action, $Cont, sshQ_Client, B_str, sshQ_HostKeyInfo))bench_echoQ_L_24actionD___exec__;
        bench_echoQ_L_24actionG_methods.__asyn__ = (B_Msg (*) (bench_echoQ_L_24action, sshQ_Client, B_str, sshQ_HostKeyInfo))bench_echoQ_L_24actionD___asyn__;
        bench_echoQ_L_24actionG_methods.__serialize__ = bench_echoQ_L_24actionD___serialize__;
        bench_echoQ_L_24actionG_methods.__deserialize__ = bench_echoQ_L_24actionD___deserialize__;
        $register(&bench_echoQ_L_24actionG_methods);
    }
    {
        bench_echoQ_L_25ContG_methods.$GCINFO = "bench_echoQ_L_25Cont";
        bench_echoQ_L_25ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        bench_echoQ_L_25ContG_methods.__bool__ = (B_bool (*) (bench_echoQ_L_25Cont))B_valueG_methods.__bool__;
        bench_echoQ_L_25ContG_methods.__str__ = (B_str (*) (bench_echoQ_L_25Cont))B_valueG_methods.__str__;
        bench_echoQ_L_25ContG_methods.__repr__ = (B_str (*) (bench_echoQ_L_25Cont))B_valueG_methods.__repr__;
        bench_echoQ_L_25ContG_methods.__init__ = (B_NoneType (*) (bench_echoQ_L_25Cont, bench_echoQ_main, $Cont))bench_echoQ_L_25ContD___init__;
        bench_echoQ_L_25ContG_methods.__call__ = ($R (*) (bench_echoQ_L_25Cont, B_u16))bench_echoQ_L_25ContD___call__;
        bench_echoQ_L_25ContG_methods.__serialize__ = bench_echoQ_L_25ContD___serialize__;
        bench_echoQ_L_25ContG_methods.__deserialize__ = bench_echoQ_L_25ContD___deserialize__;
        $register(&bench_echoQ_L_25ContG_methods);
    }
    {
        bench_echoQ_L_27ContG_methods.$GCINFO = "bench_echoQ_L_27Cont";
        bench_echoQ_L_27ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        bench_echoQ_L_27ContG_methods.__bool__ = (B_bool (*) (bench_echoQ_L_27Cont))B_valueG_methods.__bool__;
        bench_echoQ_L_27ContG_methods.__str__ = (B_str (*) (bench_echoQ_L_27Cont))B_valueG_methods.__str__;
        bench_echoQ_L_27ContG_methods.__repr__ = (B_str (*) (bench_echoQ_L_27Cont))B_valueG_methods.__repr__;
        bench_echoQ_L_27ContG_methods.__init__ = (B_NoneType (*) (bench_echoQ_L_27Cont, $Cont))bench_echoQ_L_27ContD___init__;
        bench_echoQ_L_27ContG_methods.__call__ = ($R (*) (bench_echoQ_L_27Cont, B_NoneType))bench_echoQ_L_27ContD___call__;
        bench_echoQ_L_27ContG_methods.__serialize__ = bench_echoQ_L_27ContD___serialize__;
        bench_echoQ_L_27ContG_methods.__deserialize__ = bench_echoQ_L_27ContD___deserialize__;
        $register(&bench_echoQ_L_27ContG_methods);
    }
    {
        bench_echoQ_L_28ContG_methods.$GCINFO = "bench_echoQ_L_28Cont";
        bench_echoQ_L_28ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        bench_echoQ_L_28ContG_methods.__bool__ = (B_bool (*) (bench_echoQ_L_28Cont))B_valueG_methods.__bool__;
        bench_echoQ_L_28ContG_methods.__str__ = (B_str (*) (bench_echoQ_L_28Cont))B_valueG_methods.__str__;
        bench_echoQ_L_28ContG_methods.__repr__ = (B_str (*) (bench_echoQ_L_28Cont))B_valueG_methods.__repr__;
        bench_echoQ_L_28ContG_methods.__init__ = (B_NoneType (*) (bench_echoQ_L_28Cont, bench_echoQ_main, $Cont, sshQ_Server))bench_echoQ_L_28ContD___init__;
        bench_echoQ_L_28ContG_methods.__call__ = ($R (*) (bench_echoQ_L_28Cont, B_NoneType))bench_echoQ_L_28ContD___call__;
        bench_echoQ_L_28ContG_methods.__serialize__ = bench_echoQ_L_28ContD___serialize__;
        bench_echoQ_L_28ContG_methods.__deserialize__ = bench_echoQ_L_28ContD___deserialize__;
        $register(&bench_echoQ_L_28ContG_methods);
    }
    {
        bench_echoQ_L_30ContG_methods.$GCINFO = "bench_echoQ_L_30Cont";
        bench_echoQ_L_30ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        bench_echoQ_L_30ContG_methods.__bool__ = (B_bool (*) (bench_echoQ_L_30Cont))B_valueG_methods.__bool__;
        bench_echoQ_L_30ContG_methods.__str__ = (B_str (*) (bench_echoQ_L_30Cont))B_valueG_methods.__str__;
        bench_echoQ_L_30ContG_methods.__repr__ = (B_str (*) (bench_echoQ_L_30Cont))B_valueG_methods.__repr__;
        bench_echoQ_L_30ContG_methods.__init__ = (B_NoneType (*) (bench_echoQ_L_30Cont, sshQ_ServerSession, $Cont))bench_echoQ_L_30ContD___init__;
        bench_echoQ_L_30ContG_methods.__call__ = ($R (*) (bench_echoQ_L_30Cont, sshQ_ServerChannel))bench_echoQ_L_30ContD___call__;
        bench_echoQ_L_30ContG_methods.__serialize__ = bench_echoQ_L_30ContD___serialize__;
        bench_echoQ_L_30ContG_methods.__deserialize__ = bench_echoQ_L_30ContD___deserialize__;
        $register(&bench_echoQ_L_30ContG_methods);
    }
    {
        bench_echoQ_L_32actionG_methods.$GCINFO = "bench_echoQ_L_32action";
        bench_echoQ_L_32actionG_methods.$superclass = ($SuperG_class)&$actionG_methods;
        bench_echoQ_L_32actionG_methods.__bool__ = (B_bool (*) (bench_echoQ_L_32action))B_valueG_methods.__bool__;
        bench_echoQ_L_32actionG_methods.__str__ = (B_str (*) (bench_echoQ_L_32action))B_valueG_methods.__str__;
        bench_echoQ_L_32actionG_methods.__repr__ = (B_str (*) (bench_echoQ_L_32action))B_valueG_methods.__repr__;
        bench_echoQ_L_32actionG_methods.__init__ = (B_NoneType (*) (bench_echoQ_L_32action, bench_echoQ_main))bench_echoQ_L_32actionD___init__;
        bench_echoQ_L_32actionG_methods.__call__ = ($R (*) (bench_echoQ_L_32action, $Cont, sshQ_ServerChannel, B_bytes))bench_echoQ_L_32actionD___call__;
        bench_echoQ_L_32actionG_methods.__exec__ = ($R (*) (bench_echoQ_L_32action, $Cont, sshQ_ServerChannel, B_bytes))bench_echoQ_L_32actionD___exec__;
        bench_echoQ_L_32actionG_methods.__asyn__ = (B_Msg (*) (bench_echoQ_L_32action, sshQ_ServerChannel, B_bytes))bench_echoQ_L_32actionD___asyn__;
        bench_echoQ_L_32actionG_methods.__serialize__ = bench_echoQ_L_32actionD___serialize__;
        bench_echoQ_L_32actionG_methods.__deserialize__ = bench_echoQ_L_32actionD___deserialize__;
        $register(&bench_echoQ_L_32actionG_methods);
    }
    {
        bench_echoQ_L_34actionG_methods.$GCINFO = "bench_echoQ_L_34action";
        bench_echoQ_L_34actionG_methods.$superclass = ($SuperG_class)&$actionG_methods;
        bench_echoQ_L_34actionG_methods.__bool__ = (B_bool (*) (bench_echoQ_L_34action))B_valueG_methods.__bool__;
        bench_echoQ_L_34actionG_methods.__str__ = (B_str (*) (bench_echoQ_L_34action))B_valueG_methods.__str__;
        bench_echoQ_L_34actionG_methods.__repr__ = (B_str (*) (bench_echoQ_L_34action))B_valueG_methods.__repr__;
        bench_echoQ_L_34actionG_methods.__init__ = (B_NoneType (*) (bench_echoQ_L_34action, bench_echoQ_main))bench_echoQ_L_34actionD___init__;
        bench_echoQ_L_34actionG_methods.__call__ = ($R (*) (bench_echoQ_L_34action, $Cont, sshQ_ServerChannel, B_bytes))bench_echoQ_L_34actionD___call__;
        bench_echoQ_L_34actionG_methods.__exec__ = ($R (*) (bench_echoQ_L_34action, $Cont, sshQ_ServerChannel, B_bytes))bench_echoQ_L_34actionD___exec__;
        bench_echoQ_L_34actionG_methods.__asyn__ = (B_Msg (*) (bench_echoQ_L_34action, sshQ_ServerChannel, B_bytes))bench_echoQ_L_34actionD___asyn__;
        bench_echoQ_L_34actionG_methods.__serialize__ = bench_echoQ_L_34actionD___serialize__;
        bench_echoQ_L_34actionG_methods.__deserialize__ = bench_echoQ_L_34actionD___deserialize__;
        $register(&bench_echoQ_L_34actionG_methods);
    }
    {
        bench_echoQ_L_36actionG_methods.$GCINFO = "bench_echoQ_L_36action";
        bench_echoQ_L_36actionG_methods.$superclass = ($SuperG_class)&$actionG_methods;
        bench_echoQ_L_36actionG_methods.__bool__ = (B_bool (*) (bench_echoQ_L_36action))B_valueG_methods.__bool__;
        bench_echoQ_L_36actionG_methods.__str__ = (B_str (*) (bench_echoQ_L_36action))B_valueG_methods.__str__;
        bench_echoQ_L_36actionG_methods.__repr__ = (B_str (*) (bench_echoQ_L_36action))B_valueG_methods.__repr__;
        bench_echoQ_L_36actionG_methods.__init__ = (B_NoneType (*) (bench_echoQ_L_36action, bench_echoQ_main))bench_echoQ_L_36actionD___init__;
        bench_echoQ_L_36actionG_methods.__call__ = ($R (*) (bench_echoQ_L_36action, $Cont, sshQ_ServerChannel, B_str))bench_echoQ_L_36actionD___call__;
        bench_echoQ_L_36actionG_methods.__exec__ = ($R (*) (bench_echoQ_L_36action, $Cont, sshQ_ServerChannel, B_str))bench_echoQ_L_36actionD___exec__;
        bench_echoQ_L_36actionG_methods.__asyn__ = (B_Msg (*) (bench_echoQ_L_36action, sshQ_ServerChannel, B_str))bench_echoQ_L_36actionD___asyn__;
        bench_echoQ_L_36actionG_methods.__serialize__ = bench_echoQ_L_36actionD___serialize__;
        bench_echoQ_L_36actionG_methods.__deserialize__ = bench_echoQ_L_36actionD___deserialize__;
        $register(&bench_echoQ_L_36actionG_methods);
    }
    {
        bench_echoQ_L_39ContG_methods.$GCINFO = "bench_echoQ_L_39Cont";
        bench_echoQ_L_39ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        bench_echoQ_L_39ContG_methods.__bool__ = (B_bool (*) (bench_echoQ_L_39Cont))B_valueG_methods.__bool__;
        bench_echoQ_L_39ContG_methods.__str__ = (B_str (*) (bench_echoQ_L_39Cont))B_valueG_methods.__str__;
        bench_echoQ_L_39ContG_methods.__repr__ = (B_str (*) (bench_echoQ_L_39Cont))B_valueG_methods.__repr__;
        bench_echoQ_L_39ContG_methods.__init__ = (B_NoneType (*) (bench_echoQ_L_39Cont, $Cont))bench_echoQ_L_39ContD___init__;
        bench_echoQ_L_39ContG_methods.__call__ = ($R (*) (bench_echoQ_L_39Cont, sshQ_Channel))bench_echoQ_L_39ContD___call__;
        bench_echoQ_L_39ContG_methods.__serialize__ = bench_echoQ_L_39ContD___serialize__;
        bench_echoQ_L_39ContG_methods.__deserialize__ = bench_echoQ_L_39ContD___deserialize__;
        $register(&bench_echoQ_L_39ContG_methods);
    }
    {
        bench_echoQ_L_41actionG_methods.$GCINFO = "bench_echoQ_L_41action";
        bench_echoQ_L_41actionG_methods.$superclass = ($SuperG_class)&$actionG_methods;
        bench_echoQ_L_41actionG_methods.__bool__ = (B_bool (*) (bench_echoQ_L_41action))B_valueG_methods.__bool__;
        bench_echoQ_L_41actionG_methods.__str__ = (B_str (*) (bench_echoQ_L_41action))B_valueG_methods.__str__;
        bench_echoQ_L_41actionG_methods.__repr__ = (B_str (*) (bench_echoQ_L_41action))B_valueG_methods.__repr__;
        bench_echoQ_L_41actionG_methods.__init__ = (B_NoneType (*) (bench_echoQ_L_41action, bench_echoQ_main))bench_echoQ_L_41actionD___init__;
        bench_echoQ_L_41actionG_methods.__call__ = ($R (*) (bench_echoQ_L_41action, $Cont, sshQ_Channel, B_str))bench_echoQ_L_41actionD___call__;
        bench_echoQ_L_41actionG_methods.__exec__ = ($R (*) (bench_echoQ_L_41action, $Cont, sshQ_Channel, B_str))bench_echoQ_L_41actionD___exec__;
        bench_echoQ_L_41actionG_methods.__asyn__ = (B_Msg (*) (bench_echoQ_L_41action, sshQ_Channel, B_str))bench_echoQ_L_41actionD___asyn__;
        bench_echoQ_L_41actionG_methods.__serialize__ = bench_echoQ_L_41actionD___serialize__;
        bench_echoQ_L_41actionG_methods.__deserialize__ = bench_echoQ_L_41actionD___deserialize__;
        $register(&bench_echoQ_L_41actionG_methods);
    }
    {
        bench_echoQ_L_43actionG_methods.$GCINFO = "bench_echoQ_L_43action";
        bench_echoQ_L_43actionG_methods.$superclass = ($SuperG_class)&$actionG_methods;
        bench_echoQ_L_43actionG_methods.__bool__ = (B_bool (*) (bench_echoQ_L_43action))B_valueG_methods.__bool__;
        bench_echoQ_L_43actionG_methods.__str__ = (B_str (*) (bench_echoQ_L_43action))B_valueG_methods.__str__;
        bench_echoQ_L_43actionG_methods.__repr__ = (B_str (*) (bench_echoQ_L_43action))B_valueG_methods.__repr__;
        bench_echoQ_L_43actionG_methods.__init__ = (B_NoneType (*) (bench_echoQ_L_43action, bench_echoQ_main))bench_echoQ_L_43actionD___init__;
        bench_echoQ_L_43actionG_methods.__call__ = ($R (*) (bench_echoQ_L_43action, $Cont, sshQ_Channel, B_bytes))bench_echoQ_L_43actionD___call__;
        bench_echoQ_L_43actionG_methods.__exec__ = ($R (*) (bench_echoQ_L_43action, $Cont, sshQ_Channel, B_bytes))bench_echoQ_L_43actionD___exec__;
        bench_echoQ_L_43actionG_methods.__asyn__ = (B_Msg (*) (bench_echoQ_L_43action, sshQ_Channel, B_bytes))bench_echoQ_L_43actionD___asyn__;
        bench_echoQ_L_43actionG_methods.__serialize__ = bench_echoQ_L_43actionD___serialize__;
        bench_echoQ_L_43actionG_methods.__deserialize__ = bench_echoQ_L_43actionD___deserialize__;
        $register(&bench_echoQ_L_43actionG_methods);
    }
    {
        bench_echoQ_L_45actionG_methods.$GCINFO = "bench_echoQ_L_45action";
        bench_echoQ_L_45actionG_methods.$superclass = ($SuperG_class)&$actionG_methods;
        bench_echoQ_L_45actionG_methods.__bool__ = (B_bool (*) (bench_echoQ_L_45action))B_valueG_methods.__bool__;
        bench_echoQ_L_45actionG_methods.__str__ = (B_str (*) (bench_echoQ_L_45action))B_valueG_methods.__str__;
        bench_echoQ_L_45actionG_methods.__repr__ = (B_str (*) (bench_echoQ_L_45action))B_valueG_methods.__repr__;
        bench_echoQ_L_45actionG_methods.__init__ = (B_NoneType (*) (bench_echoQ_L_45action, bench_echoQ_main))bench_echoQ_L_45actionD___init__;
        bench_echoQ_L_45actionG_methods.__call__ = ($R (*) (bench_echoQ_L_45action, $Cont, sshQ_Channel, B_bytes))bench_echoQ_L_45actionD___call__;
        bench_echoQ_L_45actionG_methods.__exec__ = ($R (*) (bench_echoQ_L_45action, $Cont, sshQ_Channel, B_bytes))bench_echoQ_L_45actionD___exec__;
        bench_echoQ_L_45actionG_methods.__asyn__ = (B_Msg (*) (bench_echoQ_L_45action, sshQ_Channel, B_bytes))bench_echoQ_L_45actionD___asyn__;
        bench_echoQ_L_45actionG_methods.__serialize__ = bench_echoQ_L_45actionD___serialize__;
        bench_echoQ_L_45actionG_methods.__deserialize__ = bench_echoQ_L_45actionD___deserialize__;
        $register(&bench_echoQ_L_45actionG_methods);
    }
    {
        bench_echoQ_L_47actionG_methods.$GCINFO = "bench_echoQ_L_47action";
        bench_echoQ_L_47actionG_methods.$superclass = ($SuperG_class)&$actionG_methods;
        bench_echoQ_L_47actionG_methods.__bool__ = (B_bool (*) (bench_echoQ_L_47action))B_valueG_methods.__bool__;
        bench_echoQ_L_47actionG_methods.__str__ = (B_str (*) (bench_echoQ_L_47action))B_valueG_methods.__str__;
        bench_echoQ_L_47actionG_methods.__repr__ = (B_str (*) (bench_echoQ_L_47action))B_valueG_methods.__repr__;
        bench_echoQ_L_47actionG_methods.__init__ = (B_NoneType (*) (bench_echoQ_L_47action, bench_echoQ_main))bench_echoQ_L_47actionD___init__;
        bench_echoQ_L_47actionG_methods.__call__ = ($R (*) (bench_echoQ_L_47action, $Cont, sshQ_Channel, B_int, B_str))bench_echoQ_L_47actionD___call__;
        bench_echoQ_L_47actionG_methods.__exec__ = ($R (*) (bench_echoQ_L_47action, $Cont, sshQ_Channel, B_int, B_str))bench_echoQ_L_47actionD___exec__;
        bench_echoQ_L_47actionG_methods.__asyn__ = (B_Msg (*) (bench_echoQ_L_47action, sshQ_Channel, B_int, B_str))bench_echoQ_L_47actionD___asyn__;
        bench_echoQ_L_47actionG_methods.__serialize__ = bench_echoQ_L_47actionD___serialize__;
        bench_echoQ_L_47actionG_methods.__deserialize__ = bench_echoQ_L_47actionD___deserialize__;
        $register(&bench_echoQ_L_47actionG_methods);
    }
    {
        bench_echoQ_L_49actionG_methods.$GCINFO = "bench_echoQ_L_49action";
        bench_echoQ_L_49actionG_methods.$superclass = ($SuperG_class)&$actionG_methods;
        bench_echoQ_L_49actionG_methods.__bool__ = (B_bool (*) (bench_echoQ_L_49action))B_valueG_methods.__bool__;
        bench_echoQ_L_49actionG_methods.__str__ = (B_str (*) (bench_echoQ_L_49action))B_valueG_methods.__str__;
        bench_echoQ_L_49actionG_methods.__repr__ = (B_str (*) (bench_echoQ_L_49action))B_valueG_methods.__repr__;
        bench_echoQ_L_49actionG_methods.__init__ = (B_NoneType (*) (bench_echoQ_L_49action, bench_echoQ_main))bench_echoQ_L_49actionD___init__;
        bench_echoQ_L_49actionG_methods.__call__ = ($R (*) (bench_echoQ_L_49action, $Cont, sshQ_Channel, B_str))bench_echoQ_L_49actionD___call__;
        bench_echoQ_L_49actionG_methods.__exec__ = ($R (*) (bench_echoQ_L_49action, $Cont, sshQ_Channel, B_str))bench_echoQ_L_49actionD___exec__;
        bench_echoQ_L_49actionG_methods.__asyn__ = (B_Msg (*) (bench_echoQ_L_49action, sshQ_Channel, B_str))bench_echoQ_L_49actionD___asyn__;
        bench_echoQ_L_49actionG_methods.__serialize__ = bench_echoQ_L_49actionD___serialize__;
        bench_echoQ_L_49actionG_methods.__deserialize__ = bench_echoQ_L_49actionD___deserialize__;
        $register(&bench_echoQ_L_49actionG_methods);
    }
    {
        bench_echoQ_L_51ContG_methods.$GCINFO = "bench_echoQ_L_51Cont";
        bench_echoQ_L_51ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        bench_echoQ_L_51ContG_methods.__bool__ = (B_bool (*) (bench_echoQ_L_51Cont))B_valueG_methods.__bool__;
        bench_echoQ_L_51ContG_methods.__str__ = (B_str (*) (bench_echoQ_L_51Cont))B_valueG_methods.__str__;
        bench_echoQ_L_51ContG_methods.__repr__ = (B_str (*) (bench_echoQ_L_51Cont))B_valueG_methods.__repr__;
        bench_echoQ_L_51ContG_methods.__init__ = (B_NoneType (*) (bench_echoQ_L_51Cont, $Cont))bench_echoQ_L_51ContD___init__;
        bench_echoQ_L_51ContG_methods.__call__ = ($R (*) (bench_echoQ_L_51Cont, B_NoneType))bench_echoQ_L_51ContD___call__;
        bench_echoQ_L_51ContG_methods.__serialize__ = bench_echoQ_L_51ContD___serialize__;
        bench_echoQ_L_51ContG_methods.__deserialize__ = bench_echoQ_L_51ContD___deserialize__;
        $register(&bench_echoQ_L_51ContG_methods);
    }
    {
        bench_echoQ_L_52ContG_methods.$GCINFO = "bench_echoQ_L_52Cont";
        bench_echoQ_L_52ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        bench_echoQ_L_52ContG_methods.__bool__ = (B_bool (*) (bench_echoQ_L_52Cont))B_valueG_methods.__bool__;
        bench_echoQ_L_52ContG_methods.__str__ = (B_str (*) (bench_echoQ_L_52Cont))B_valueG_methods.__str__;
        bench_echoQ_L_52ContG_methods.__repr__ = (B_str (*) (bench_echoQ_L_52Cont))B_valueG_methods.__repr__;
        bench_echoQ_L_52ContG_methods.__init__ = (B_NoneType (*) (bench_echoQ_L_52Cont, bench_echoQ_main, $Cont, sshQ_Client))bench_echoQ_L_52ContD___init__;
        bench_echoQ_L_52ContG_methods.__call__ = ($R (*) (bench_echoQ_L_52Cont, B_NoneType))bench_echoQ_L_52ContD___call__;
        bench_echoQ_L_52ContG_methods.__serialize__ = bench_echoQ_L_52ContD___serialize__;
        bench_echoQ_L_52ContG_methods.__deserialize__ = bench_echoQ_L_52ContD___deserialize__;
        $register(&bench_echoQ_L_52ContG_methods);
    }
    {
        bench_echoQ_L_55ContG_methods.$GCINFO = "bench_echoQ_L_55Cont";
        bench_echoQ_L_55ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        bench_echoQ_L_55ContG_methods.__bool__ = (B_bool (*) (bench_echoQ_L_55Cont))B_valueG_methods.__bool__;
        bench_echoQ_L_55ContG_methods.__str__ = (B_str (*) (bench_echoQ_L_55Cont))B_valueG_methods.__str__;
        bench_echoQ_L_55ContG_methods.__repr__ = (B_str (*) (bench_echoQ_L_55Cont))B_valueG_methods.__repr__;
        bench_echoQ_L_55ContG_methods.__init__ = (B_NoneType (*) (bench_echoQ_L_55Cont, $Cont))bench_echoQ_L_55ContD___init__;
        bench_echoQ_L_55ContG_methods.__call__ = ($R (*) (bench_echoQ_L_55Cont, B_NoneType))bench_echoQ_L_55ContD___call__;
        bench_echoQ_L_55ContG_methods.__serialize__ = bench_echoQ_L_55ContD___serialize__;
        bench_echoQ_L_55ContG_methods.__deserialize__ = bench_echoQ_L_55ContD___deserialize__;
        $register(&bench_echoQ_L_55ContG_methods);
    }
    {
        bench_echoQ_L_56ContG_methods.$GCINFO = "bench_echoQ_L_56Cont";
        bench_echoQ_L_56ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        bench_echoQ_L_56ContG_methods.__bool__ = (B_bool (*) (bench_echoQ_L_56Cont))B_valueG_methods.__bool__;
        bench_echoQ_L_56ContG_methods.__str__ = (B_str (*) (bench_echoQ_L_56Cont))B_valueG_methods.__str__;
        bench_echoQ_L_56ContG_methods.__repr__ = (B_str (*) (bench_echoQ_L_56Cont))B_valueG_methods.__repr__;
        bench_echoQ_L_56ContG_methods.__init__ = (B_NoneType (*) (bench_echoQ_L_56Cont, sshQ_Channel, bench_echoQ_main, $Cont))bench_echoQ_L_56ContD___init__;
        bench_echoQ_L_56ContG_methods.__call__ = ($R (*) (bench_echoQ_L_56Cont, B_NoneType))bench_echoQ_L_56ContD___call__;
        bench_echoQ_L_56ContG_methods.__serialize__ = bench_echoQ_L_56ContD___serialize__;
        bench_echoQ_L_56ContG_methods.__deserialize__ = bench_echoQ_L_56ContD___deserialize__;
        $register(&bench_echoQ_L_56ContG_methods);
    }
    {
        bench_echoQ_L_57procG_methods.$GCINFO = "bench_echoQ_L_57proc";
        bench_echoQ_L_57procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        bench_echoQ_L_57procG_methods.__bool__ = (B_bool (*) (bench_echoQ_L_57proc))B_valueG_methods.__bool__;
        bench_echoQ_L_57procG_methods.__str__ = (B_str (*) (bench_echoQ_L_57proc))B_valueG_methods.__str__;
        bench_echoQ_L_57procG_methods.__repr__ = (B_str (*) (bench_echoQ_L_57proc))B_valueG_methods.__repr__;
        bench_echoQ_L_57procG_methods.__init__ = (B_NoneType (*) (bench_echoQ_L_57proc, bench_echoQ_main, B_str))bench_echoQ_L_57procD___init__;
        bench_echoQ_L_57procG_methods.__call__ = ($R (*) (bench_echoQ_L_57proc, $Cont))bench_echoQ_L_57procD___call__;
        bench_echoQ_L_57procG_methods.__exec__ = ($R (*) (bench_echoQ_L_57proc, $Cont))bench_echoQ_L_57procD___exec__;
        bench_echoQ_L_57procG_methods.__serialize__ = bench_echoQ_L_57procD___serialize__;
        bench_echoQ_L_57procG_methods.__deserialize__ = bench_echoQ_L_57procD___deserialize__;
        $register(&bench_echoQ_L_57procG_methods);
    }
    {
        bench_echoQ_L_58procG_methods.$GCINFO = "bench_echoQ_L_58proc";
        bench_echoQ_L_58procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        bench_echoQ_L_58procG_methods.__bool__ = (B_bool (*) (bench_echoQ_L_58proc))B_valueG_methods.__bool__;
        bench_echoQ_L_58procG_methods.__str__ = (B_str (*) (bench_echoQ_L_58proc))B_valueG_methods.__str__;
        bench_echoQ_L_58procG_methods.__repr__ = (B_str (*) (bench_echoQ_L_58proc))B_valueG_methods.__repr__;
        bench_echoQ_L_58procG_methods.__init__ = (B_NoneType (*) (bench_echoQ_L_58proc, bench_echoQ_main, sshQ_Server, B_str))bench_echoQ_L_58procD___init__;
        bench_echoQ_L_58procG_methods.__call__ = ($R (*) (bench_echoQ_L_58proc, $Cont))bench_echoQ_L_58procD___call__;
        bench_echoQ_L_58procG_methods.__exec__ = ($R (*) (bench_echoQ_L_58proc, $Cont))bench_echoQ_L_58procD___exec__;
        bench_echoQ_L_58procG_methods.__serialize__ = bench_echoQ_L_58procD___serialize__;
        bench_echoQ_L_58procG_methods.__deserialize__ = bench_echoQ_L_58procD___deserialize__;
        $register(&bench_echoQ_L_58procG_methods);
    }
    {
        bench_echoQ_L_59procG_methods.$GCINFO = "bench_echoQ_L_59proc";
        bench_echoQ_L_59procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        bench_echoQ_L_59procG_methods.__bool__ = (B_bool (*) (bench_echoQ_L_59proc))B_valueG_methods.__bool__;
        bench_echoQ_L_59procG_methods.__str__ = (B_str (*) (bench_echoQ_L_59proc))B_valueG_methods.__str__;
        bench_echoQ_L_59procG_methods.__repr__ = (B_str (*) (bench_echoQ_L_59proc))B_valueG_methods.__repr__;
        bench_echoQ_L_59procG_methods.__init__ = (B_NoneType (*) (bench_echoQ_L_59proc, bench_echoQ_main, sshQ_Server, B_str))bench_echoQ_L_59procD___init__;
        bench_echoQ_L_59procG_methods.__call__ = ($R (*) (bench_echoQ_L_59proc, $Cont))bench_echoQ_L_59procD___call__;
        bench_echoQ_L_59procG_methods.__exec__ = ($R (*) (bench_echoQ_L_59proc, $Cont))bench_echoQ_L_59procD___exec__;
        bench_echoQ_L_59procG_methods.__serialize__ = bench_echoQ_L_59procD___serialize__;
        bench_echoQ_L_59procG_methods.__deserialize__ = bench_echoQ_L_59procD___deserialize__;
        $register(&bench_echoQ_L_59procG_methods);
    }
    {
        bench_echoQ_L_60procG_methods.$GCINFO = "bench_echoQ_L_60proc";
        bench_echoQ_L_60procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        bench_echoQ_L_60procG_methods.__bool__ = (B_bool (*) (bench_echoQ_L_60proc))B_valueG_methods.__bool__;
        bench_echoQ_L_60procG_methods.__str__ = (B_str (*) (bench_echoQ_L_60proc))B_valueG_methods.__str__;
        bench_echoQ_L_60procG_methods.__repr__ = (B_str (*) (bench_echoQ_L_60proc))B_valueG_methods.__repr__;
        bench_echoQ_L_60procG_methods.__init__ = (B_NoneType (*) (bench_echoQ_L_60proc, bench_echoQ_main, sshQ_ServerSession))bench_echoQ_L_60procD___init__;
        bench_echoQ_L_60procG_methods.__call__ = ($R (*) (bench_echoQ_L_60proc, $Cont))bench_echoQ_L_60procD___call__;
        bench_echoQ_L_60procG_methods.__exec__ = ($R (*) (bench_echoQ_L_60proc, $Cont))bench_echoQ_L_60procD___exec__;
        bench_echoQ_L_60procG_methods.__serialize__ = bench_echoQ_L_60procD___serialize__;
        bench_echoQ_L_60procG_methods.__deserialize__ = bench_echoQ_L_60procD___deserialize__;
        $register(&bench_echoQ_L_60procG_methods);
    }
    {
        bench_echoQ_L_61procG_methods.$GCINFO = "bench_echoQ_L_61proc";
        bench_echoQ_L_61procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        bench_echoQ_L_61procG_methods.__bool__ = (B_bool (*) (bench_echoQ_L_61proc))B_valueG_methods.__bool__;
        bench_echoQ_L_61procG_methods.__str__ = (B_str (*) (bench_echoQ_L_61proc))B_valueG_methods.__str__;
        bench_echoQ_L_61procG_methods.__repr__ = (B_str (*) (bench_echoQ_L_61proc))B_valueG_methods.__repr__;
        bench_echoQ_L_61procG_methods.__init__ = (B_NoneType (*) (bench_echoQ_L_61proc, bench_echoQ_main, sshQ_ServerSession, sshQ_AuthRequest))bench_echoQ_L_61procD___init__;
        bench_echoQ_L_61procG_methods.__call__ = ($R (*) (bench_echoQ_L_61proc, $Cont))bench_echoQ_L_61procD___call__;
        bench_echoQ_L_61procG_methods.__exec__ = ($R (*) (bench_echoQ_L_61proc, $Cont))bench_echoQ_L_61procD___exec__;
        bench_echoQ_L_61procG_methods.__serialize__ = bench_echoQ_L_61procD___serialize__;
        bench_echoQ_L_61procG_methods.__deserialize__ = bench_echoQ_L_61procD___deserialize__;
        $register(&bench_echoQ_L_61procG_methods);
    }
    {
        bench_echoQ_L_62procG_methods.$GCINFO = "bench_echoQ_L_62proc";
        bench_echoQ_L_62procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        bench_echoQ_L_62procG_methods.__bool__ = (B_bool (*) (bench_echoQ_L_62proc))B_valueG_methods.__bool__;
        bench_echoQ_L_62procG_methods.__str__ = (B_str (*) (bench_echoQ_L_62proc))B_valueG_methods.__str__;
        bench_echoQ_L_62procG_methods.__repr__ = (B_str (*) (bench_echoQ_L_62proc))B_valueG_methods.__repr__;
        bench_echoQ_L_62procG_methods.__init__ = (B_NoneType (*) (bench_echoQ_L_62proc, bench_echoQ_main, sshQ_ServerChannel, B_bytes))bench_echoQ_L_62procD___init__;
        bench_echoQ_L_62procG_methods.__call__ = ($R (*) (bench_echoQ_L_62proc, $Cont))bench_echoQ_L_62procD___call__;
        bench_echoQ_L_62procG_methods.__exec__ = ($R (*) (bench_echoQ_L_62proc, $Cont))bench_echoQ_L_62procD___exec__;
        bench_echoQ_L_62procG_methods.__serialize__ = bench_echoQ_L_62procD___serialize__;
        bench_echoQ_L_62procG_methods.__deserialize__ = bench_echoQ_L_62procD___deserialize__;
        $register(&bench_echoQ_L_62procG_methods);
    }
    {
        bench_echoQ_L_63procG_methods.$GCINFO = "bench_echoQ_L_63proc";
        bench_echoQ_L_63procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        bench_echoQ_L_63procG_methods.__bool__ = (B_bool (*) (bench_echoQ_L_63proc))B_valueG_methods.__bool__;
        bench_echoQ_L_63procG_methods.__str__ = (B_str (*) (bench_echoQ_L_63proc))B_valueG_methods.__str__;
        bench_echoQ_L_63procG_methods.__repr__ = (B_str (*) (bench_echoQ_L_63proc))B_valueG_methods.__repr__;
        bench_echoQ_L_63procG_methods.__init__ = (B_NoneType (*) (bench_echoQ_L_63proc, bench_echoQ_main, sshQ_ServerChannel, B_bytes))bench_echoQ_L_63procD___init__;
        bench_echoQ_L_63procG_methods.__call__ = ($R (*) (bench_echoQ_L_63proc, $Cont))bench_echoQ_L_63procD___call__;
        bench_echoQ_L_63procG_methods.__exec__ = ($R (*) (bench_echoQ_L_63proc, $Cont))bench_echoQ_L_63procD___exec__;
        bench_echoQ_L_63procG_methods.__serialize__ = bench_echoQ_L_63procD___serialize__;
        bench_echoQ_L_63procG_methods.__deserialize__ = bench_echoQ_L_63procD___deserialize__;
        $register(&bench_echoQ_L_63procG_methods);
    }
    {
        bench_echoQ_L_64procG_methods.$GCINFO = "bench_echoQ_L_64proc";
        bench_echoQ_L_64procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        bench_echoQ_L_64procG_methods.__bool__ = (B_bool (*) (bench_echoQ_L_64proc))B_valueG_methods.__bool__;
        bench_echoQ_L_64procG_methods.__str__ = (B_str (*) (bench_echoQ_L_64proc))B_valueG_methods.__str__;
        bench_echoQ_L_64procG_methods.__repr__ = (B_str (*) (bench_echoQ_L_64proc))B_valueG_methods.__repr__;
        bench_echoQ_L_64procG_methods.__init__ = (B_NoneType (*) (bench_echoQ_L_64proc, bench_echoQ_main, sshQ_ServerChannel, B_str))bench_echoQ_L_64procD___init__;
        bench_echoQ_L_64procG_methods.__call__ = ($R (*) (bench_echoQ_L_64proc, $Cont))bench_echoQ_L_64procD___call__;
        bench_echoQ_L_64procG_methods.__exec__ = ($R (*) (bench_echoQ_L_64proc, $Cont))bench_echoQ_L_64procD___exec__;
        bench_echoQ_L_64procG_methods.__serialize__ = bench_echoQ_L_64procD___serialize__;
        bench_echoQ_L_64procG_methods.__deserialize__ = bench_echoQ_L_64procD___deserialize__;
        $register(&bench_echoQ_L_64procG_methods);
    }
    {
        bench_echoQ_L_65procG_methods.$GCINFO = "bench_echoQ_L_65proc";
        bench_echoQ_L_65procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        bench_echoQ_L_65procG_methods.__bool__ = (B_bool (*) (bench_echoQ_L_65proc))B_valueG_methods.__bool__;
        bench_echoQ_L_65procG_methods.__str__ = (B_str (*) (bench_echoQ_L_65proc))B_valueG_methods.__str__;
        bench_echoQ_L_65procG_methods.__repr__ = (B_str (*) (bench_echoQ_L_65proc))B_valueG_methods.__repr__;
        bench_echoQ_L_65procG_methods.__init__ = (B_NoneType (*) (bench_echoQ_L_65proc, bench_echoQ_main, sshQ_ServerSession))bench_echoQ_L_65procD___init__;
        bench_echoQ_L_65procG_methods.__call__ = ($R (*) (bench_echoQ_L_65proc, $Cont))bench_echoQ_L_65procD___call__;
        bench_echoQ_L_65procG_methods.__exec__ = ($R (*) (bench_echoQ_L_65proc, $Cont))bench_echoQ_L_65procD___exec__;
        bench_echoQ_L_65procG_methods.__serialize__ = bench_echoQ_L_65procD___serialize__;
        bench_echoQ_L_65procG_methods.__deserialize__ = bench_echoQ_L_65procD___deserialize__;
        $register(&bench_echoQ_L_65procG_methods);
    }
    {
        bench_echoQ_L_66procG_methods.$GCINFO = "bench_echoQ_L_66proc";
        bench_echoQ_L_66procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        bench_echoQ_L_66procG_methods.__bool__ = (B_bool (*) (bench_echoQ_L_66proc))B_valueG_methods.__bool__;
        bench_echoQ_L_66procG_methods.__str__ = (B_str (*) (bench_echoQ_L_66proc))B_valueG_methods.__str__;
        bench_echoQ_L_66procG_methods.__repr__ = (B_str (*) (bench_echoQ_L_66proc))B_valueG_methods.__repr__;
        bench_echoQ_L_66procG_methods.__init__ = (B_NoneType (*) (bench_echoQ_L_66proc, bench_echoQ_main, sshQ_ServerSession, sshQ_ServerChannel, B_str))bench_echoQ_L_66procD___init__;
        bench_echoQ_L_66procG_methods.__call__ = ($R (*) (bench_echoQ_L_66proc, $Cont))bench_echoQ_L_66procD___call__;
        bench_echoQ_L_66procG_methods.__exec__ = ($R (*) (bench_echoQ_L_66proc, $Cont))bench_echoQ_L_66procD___exec__;
        bench_echoQ_L_66procG_methods.__serialize__ = bench_echoQ_L_66procD___serialize__;
        bench_echoQ_L_66procG_methods.__deserialize__ = bench_echoQ_L_66procD___deserialize__;
        $register(&bench_echoQ_L_66procG_methods);
    }
    {
        bench_echoQ_L_67procG_methods.$GCINFO = "bench_echoQ_L_67proc";
        bench_echoQ_L_67procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        bench_echoQ_L_67procG_methods.__bool__ = (B_bool (*) (bench_echoQ_L_67proc))B_valueG_methods.__bool__;
        bench_echoQ_L_67procG_methods.__str__ = (B_str (*) (bench_echoQ_L_67proc))B_valueG_methods.__str__;
        bench_echoQ_L_67procG_methods.__repr__ = (B_str (*) (bench_echoQ_L_67proc))B_valueG_methods.__repr__;
        bench_echoQ_L_67procG_methods.__init__ = (B_NoneType (*) (bench_echoQ_L_67proc, bench_echoQ_main, sshQ_Client, B_str, sshQ_HostKeyInfo))bench_echoQ_L_67procD___init__;
        bench_echoQ_L_67procG_methods.__call__ = ($R (*) (bench_echoQ_L_67proc, $Cont))bench_echoQ_L_67procD___call__;
        bench_echoQ_L_67procG_methods.__exec__ = ($R (*) (bench_echoQ_L_67proc, $Cont))bench_echoQ_L_67procD___exec__;
        bench_echoQ_L_67procG_methods.__serialize__ = bench_echoQ_L_67procD___serialize__;
        bench_echoQ_L_67procG_methods.__deserialize__ = bench_echoQ_L_67procD___deserialize__;
        $register(&bench_echoQ_L_67procG_methods);
    }
    {
        bench_echoQ_L_68procG_methods.$GCINFO = "bench_echoQ_L_68proc";
        bench_echoQ_L_68procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        bench_echoQ_L_68procG_methods.__bool__ = (B_bool (*) (bench_echoQ_L_68proc))B_valueG_methods.__bool__;
        bench_echoQ_L_68procG_methods.__str__ = (B_str (*) (bench_echoQ_L_68proc))B_valueG_methods.__str__;
        bench_echoQ_L_68procG_methods.__repr__ = (B_str (*) (bench_echoQ_L_68proc))B_valueG_methods.__repr__;
        bench_echoQ_L_68procG_methods.__init__ = (B_NoneType (*) (bench_echoQ_L_68proc, bench_echoQ_main, sshQ_Client, B_str))bench_echoQ_L_68procD___init__;
        bench_echoQ_L_68procG_methods.__call__ = ($R (*) (bench_echoQ_L_68proc, $Cont))bench_echoQ_L_68procD___call__;
        bench_echoQ_L_68procG_methods.__exec__ = ($R (*) (bench_echoQ_L_68proc, $Cont))bench_echoQ_L_68procD___exec__;
        bench_echoQ_L_68procG_methods.__serialize__ = bench_echoQ_L_68procD___serialize__;
        bench_echoQ_L_68procG_methods.__deserialize__ = bench_echoQ_L_68procD___deserialize__;
        $register(&bench_echoQ_L_68procG_methods);
    }
    {
        bench_echoQ_L_69procG_methods.$GCINFO = "bench_echoQ_L_69proc";
        bench_echoQ_L_69procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        bench_echoQ_L_69procG_methods.__bool__ = (B_bool (*) (bench_echoQ_L_69proc))B_valueG_methods.__bool__;
        bench_echoQ_L_69procG_methods.__str__ = (B_str (*) (bench_echoQ_L_69proc))B_valueG_methods.__str__;
        bench_echoQ_L_69procG_methods.__repr__ = (B_str (*) (bench_echoQ_L_69proc))B_valueG_methods.__repr__;
        bench_echoQ_L_69procG_methods.__init__ = (B_NoneType (*) (bench_echoQ_L_69proc, bench_echoQ_main, sshQ_Client, B_str))bench_echoQ_L_69procD___init__;
        bench_echoQ_L_69procG_methods.__call__ = ($R (*) (bench_echoQ_L_69proc, $Cont))bench_echoQ_L_69procD___call__;
        bench_echoQ_L_69procG_methods.__exec__ = ($R (*) (bench_echoQ_L_69proc, $Cont))bench_echoQ_L_69procD___exec__;
        bench_echoQ_L_69procG_methods.__serialize__ = bench_echoQ_L_69procD___serialize__;
        bench_echoQ_L_69procG_methods.__deserialize__ = bench_echoQ_L_69procD___deserialize__;
        $register(&bench_echoQ_L_69procG_methods);
    }
    {
        bench_echoQ_L_70procG_methods.$GCINFO = "bench_echoQ_L_70proc";
        bench_echoQ_L_70procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        bench_echoQ_L_70procG_methods.__bool__ = (B_bool (*) (bench_echoQ_L_70proc))B_valueG_methods.__bool__;
        bench_echoQ_L_70procG_methods.__str__ = (B_str (*) (bench_echoQ_L_70proc))B_valueG_methods.__str__;
        bench_echoQ_L_70procG_methods.__repr__ = (B_str (*) (bench_echoQ_L_70proc))B_valueG_methods.__repr__;
        bench_echoQ_L_70procG_methods.__init__ = (B_NoneType (*) (bench_echoQ_L_70proc, bench_echoQ_main, sshQ_Channel, B_str))bench_echoQ_L_70procD___init__;
        bench_echoQ_L_70procG_methods.__call__ = ($R (*) (bench_echoQ_L_70proc, $Cont))bench_echoQ_L_70procD___call__;
        bench_echoQ_L_70procG_methods.__exec__ = ($R (*) (bench_echoQ_L_70proc, $Cont))bench_echoQ_L_70procD___exec__;
        bench_echoQ_L_70procG_methods.__serialize__ = bench_echoQ_L_70procD___serialize__;
        bench_echoQ_L_70procG_methods.__deserialize__ = bench_echoQ_L_70procD___deserialize__;
        $register(&bench_echoQ_L_70procG_methods);
    }
    {
        bench_echoQ_L_71procG_methods.$GCINFO = "bench_echoQ_L_71proc";
        bench_echoQ_L_71procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        bench_echoQ_L_71procG_methods.__bool__ = (B_bool (*) (bench_echoQ_L_71proc))B_valueG_methods.__bool__;
        bench_echoQ_L_71procG_methods.__str__ = (B_str (*) (bench_echoQ_L_71proc))B_valueG_methods.__str__;
        bench_echoQ_L_71procG_methods.__repr__ = (B_str (*) (bench_echoQ_L_71proc))B_valueG_methods.__repr__;
        bench_echoQ_L_71procG_methods.__init__ = (B_NoneType (*) (bench_echoQ_L_71proc, bench_echoQ_main, sshQ_Channel, B_bytes))bench_echoQ_L_71procD___init__;
        bench_echoQ_L_71procG_methods.__call__ = ($R (*) (bench_echoQ_L_71proc, $Cont))bench_echoQ_L_71procD___call__;
        bench_echoQ_L_71procG_methods.__exec__ = ($R (*) (bench_echoQ_L_71proc, $Cont))bench_echoQ_L_71procD___exec__;
        bench_echoQ_L_71procG_methods.__serialize__ = bench_echoQ_L_71procD___serialize__;
        bench_echoQ_L_71procG_methods.__deserialize__ = bench_echoQ_L_71procD___deserialize__;
        $register(&bench_echoQ_L_71procG_methods);
    }
    {
        bench_echoQ_L_72procG_methods.$GCINFO = "bench_echoQ_L_72proc";
        bench_echoQ_L_72procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        bench_echoQ_L_72procG_methods.__bool__ = (B_bool (*) (bench_echoQ_L_72proc))B_valueG_methods.__bool__;
        bench_echoQ_L_72procG_methods.__str__ = (B_str (*) (bench_echoQ_L_72proc))B_valueG_methods.__str__;
        bench_echoQ_L_72procG_methods.__repr__ = (B_str (*) (bench_echoQ_L_72proc))B_valueG_methods.__repr__;
        bench_echoQ_L_72procG_methods.__init__ = (B_NoneType (*) (bench_echoQ_L_72proc, bench_echoQ_main, sshQ_Channel, B_bytes))bench_echoQ_L_72procD___init__;
        bench_echoQ_L_72procG_methods.__call__ = ($R (*) (bench_echoQ_L_72proc, $Cont))bench_echoQ_L_72procD___call__;
        bench_echoQ_L_72procG_methods.__exec__ = ($R (*) (bench_echoQ_L_72proc, $Cont))bench_echoQ_L_72procD___exec__;
        bench_echoQ_L_72procG_methods.__serialize__ = bench_echoQ_L_72procD___serialize__;
        bench_echoQ_L_72procG_methods.__deserialize__ = bench_echoQ_L_72procD___deserialize__;
        $register(&bench_echoQ_L_72procG_methods);
    }
    {
        bench_echoQ_L_73procG_methods.$GCINFO = "bench_echoQ_L_73proc";
        bench_echoQ_L_73procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        bench_echoQ_L_73procG_methods.__bool__ = (B_bool (*) (bench_echoQ_L_73proc))B_valueG_methods.__bool__;
        bench_echoQ_L_73procG_methods.__str__ = (B_str (*) (bench_echoQ_L_73proc))B_valueG_methods.__str__;
        bench_echoQ_L_73procG_methods.__repr__ = (B_str (*) (bench_echoQ_L_73proc))B_valueG_methods.__repr__;
        bench_echoQ_L_73procG_methods.__init__ = (B_NoneType (*) (bench_echoQ_L_73proc, bench_echoQ_main, sshQ_Channel, int64_t, B_str))bench_echoQ_L_73procD___init__;
        bench_echoQ_L_73procG_methods.__call__ = ($R (*) (bench_echoQ_L_73proc, $Cont))bench_echoQ_L_73procD___call__;
        bench_echoQ_L_73procG_methods.__exec__ = ($R (*) (bench_echoQ_L_73proc, $Cont))bench_echoQ_L_73procD___exec__;
        bench_echoQ_L_73procG_methods.__serialize__ = bench_echoQ_L_73procD___serialize__;
        bench_echoQ_L_73procG_methods.__deserialize__ = bench_echoQ_L_73procD___deserialize__;
        $register(&bench_echoQ_L_73procG_methods);
    }
    {
        bench_echoQ_L_74procG_methods.$GCINFO = "bench_echoQ_L_74proc";
        bench_echoQ_L_74procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        bench_echoQ_L_74procG_methods.__bool__ = (B_bool (*) (bench_echoQ_L_74proc))B_valueG_methods.__bool__;
        bench_echoQ_L_74procG_methods.__str__ = (B_str (*) (bench_echoQ_L_74proc))B_valueG_methods.__str__;
        bench_echoQ_L_74procG_methods.__repr__ = (B_str (*) (bench_echoQ_L_74proc))B_valueG_methods.__repr__;
        bench_echoQ_L_74procG_methods.__init__ = (B_NoneType (*) (bench_echoQ_L_74proc, bench_echoQ_main, sshQ_Channel, B_str))bench_echoQ_L_74procD___init__;
        bench_echoQ_L_74procG_methods.__call__ = ($R (*) (bench_echoQ_L_74proc, $Cont))bench_echoQ_L_74procD___call__;
        bench_echoQ_L_74procG_methods.__exec__ = ($R (*) (bench_echoQ_L_74proc, $Cont))bench_echoQ_L_74procD___exec__;
        bench_echoQ_L_74procG_methods.__serialize__ = bench_echoQ_L_74procD___serialize__;
        bench_echoQ_L_74procG_methods.__deserialize__ = bench_echoQ_L_74procD___deserialize__;
        $register(&bench_echoQ_L_74procG_methods);
    }
    {
        bench_echoQ_L_76ContG_methods.$GCINFO = "bench_echoQ_L_76Cont";
        bench_echoQ_L_76ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        bench_echoQ_L_76ContG_methods.__bool__ = (B_bool (*) (bench_echoQ_L_76Cont))B_valueG_methods.__bool__;
        bench_echoQ_L_76ContG_methods.__str__ = (B_str (*) (bench_echoQ_L_76Cont))B_valueG_methods.__str__;
        bench_echoQ_L_76ContG_methods.__repr__ = (B_str (*) (bench_echoQ_L_76Cont))B_valueG_methods.__repr__;
        bench_echoQ_L_76ContG_methods.__init__ = (B_NoneType (*) (bench_echoQ_L_76Cont, $Cont, bench_echoQ_main))bench_echoQ_L_76ContD___init__;
        bench_echoQ_L_76ContG_methods.__call__ = ($R (*) (bench_echoQ_L_76Cont, B_NoneType))bench_echoQ_L_76ContD___call__;
        bench_echoQ_L_76ContG_methods.__serialize__ = bench_echoQ_L_76ContD___serialize__;
        bench_echoQ_L_76ContG_methods.__deserialize__ = bench_echoQ_L_76ContD___deserialize__;
        $register(&bench_echoQ_L_76ContG_methods);
    }
    {
        bench_echoQ_L_77procG_methods.$GCINFO = "bench_echoQ_L_77proc";
        bench_echoQ_L_77procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        bench_echoQ_L_77procG_methods.__bool__ = (B_bool (*) (bench_echoQ_L_77proc))B_valueG_methods.__bool__;
        bench_echoQ_L_77procG_methods.__str__ = (B_str (*) (bench_echoQ_L_77proc))B_valueG_methods.__str__;
        bench_echoQ_L_77procG_methods.__repr__ = (B_str (*) (bench_echoQ_L_77proc))B_valueG_methods.__repr__;
        bench_echoQ_L_77procG_methods.__init__ = (B_NoneType (*) (bench_echoQ_L_77proc, bench_echoQ_main, B_Env))bench_echoQ_L_77procD___init__;
        bench_echoQ_L_77procG_methods.__call__ = ($R (*) (bench_echoQ_L_77proc, $Cont))bench_echoQ_L_77procD___call__;
        bench_echoQ_L_77procG_methods.__exec__ = ($R (*) (bench_echoQ_L_77proc, $Cont))bench_echoQ_L_77procD___exec__;
        bench_echoQ_L_77procG_methods.__serialize__ = bench_echoQ_L_77procD___serialize__;
        bench_echoQ_L_77procG_methods.__deserialize__ = bench_echoQ_L_77procD___deserialize__;
        $register(&bench_echoQ_L_77procG_methods);
    }
    {
        bench_echoQ_mainG_methods.$GCINFO = "bench_echoQ_main";
        bench_echoQ_mainG_methods.$superclass = ($SuperG_class)&$ActorG_methods;
        bench_echoQ_mainG_methods.__bool__ = (B_bool (*) (bench_echoQ_main))$ActorG_methods.__bool__;
        bench_echoQ_mainG_methods.__str__ = (B_str (*) (bench_echoQ_main))$ActorG_methods.__str__;
        bench_echoQ_mainG_methods.__repr__ = (B_str (*) (bench_echoQ_main))$ActorG_methods.__repr__;
        bench_echoQ_mainG_methods.__resume__ = (B_NoneType (*) (bench_echoQ_main))$ActorG_methods.__resume__;
        bench_echoQ_mainG_methods.__cleanup__ = (B_NoneType (*) (bench_echoQ_main))$ActorG_methods.__cleanup__;
        bench_echoQ_mainG_methods.__init__ = ($R (*) (bench_echoQ_main, $Cont, B_Env))bench_echoQ_mainD___init__;
        bench_echoQ_mainG_methods.failG_local = ($R (*) (bench_echoQ_main, $Cont, B_str))bench_echoQ_mainD_failG_local;
        bench_echoQ_mainG_methods.on_listenG_local = ($R (*) (bench_echoQ_main, $Cont, sshQ_Server, B_str))bench_echoQ_mainD_on_listenG_local;
        bench_echoQ_mainG_methods.on_server_closeG_local = ($R (*) (bench_echoQ_main, $Cont, sshQ_Server, B_str))bench_echoQ_mainD_on_server_closeG_local;
        bench_echoQ_mainG_methods.on_sessionG_local = ($R (*) (bench_echoQ_main, $Cont, sshQ_ServerSession))bench_echoQ_mainD_on_sessionG_local;
        bench_echoQ_mainG_methods.on_authG_local = ($R (*) (bench_echoQ_main, $Cont, sshQ_ServerSession, sshQ_AuthRequest))bench_echoQ_mainD_on_authG_local;
        bench_echoQ_mainG_methods.srv_on_dataG_local = ($R (*) (bench_echoQ_main, $Cont, sshQ_ServerChannel, B_bytes))bench_echoQ_mainD_srv_on_dataG_local;
        bench_echoQ_mainG_methods.srv_on_stderrG_local = ($R (*) (bench_echoQ_main, $Cont, sshQ_ServerChannel, B_bytes))bench_echoQ_mainD_srv_on_stderrG_local;
        bench_echoQ_mainG_methods.srv_on_closeG_local = ($R (*) (bench_echoQ_main, $Cont, sshQ_ServerChannel, B_str))bench_echoQ_mainD_srv_on_closeG_local;
        bench_echoQ_mainG_methods.on_channel_openG_local = ($R (*) (bench_echoQ_main, $Cont, sshQ_ServerSession))bench_echoQ_mainD_on_channel_openG_local;
        bench_echoQ_mainG_methods.on_execG_local = ($R (*) (bench_echoQ_main, $Cont, sshQ_ServerSession, sshQ_ServerChannel, B_str))bench_echoQ_mainD_on_execG_local;
        bench_echoQ_mainG_methods.on_hostkeyG_local = ($R (*) (bench_echoQ_main, $Cont, sshQ_Client, B_str, sshQ_HostKeyInfo))bench_echoQ_mainD_on_hostkeyG_local;
        bench_echoQ_mainG_methods.on_connectG_local = ($R (*) (bench_echoQ_main, $Cont, sshQ_Client, B_str))bench_echoQ_mainD_on_connectG_local;
        bench_echoQ_mainG_methods.on_client_closeG_local = ($R (*) (bench_echoQ_main, $Cont, sshQ_Client, B_str))bench_echoQ_mainD_on_client_closeG_local;
        bench_echoQ_mainG_methods.ch_openG_local = ($R (*) (bench_echoQ_main, $Cont, sshQ_Channel, B_str))bench_echoQ_mainD_ch_openG_local;
        bench_echoQ_mainG_methods.ch_outG_local = ($R (*) (bench_echoQ_main, $Cont, sshQ_Channel, B_bytes))bench_echoQ_mainD_ch_outG_local;
        bench_echoQ_mainG_methods.ch_errG_local = ($R (*) (bench_echoQ_main, $Cont, sshQ_Channel, B_bytes))bench_echoQ_mainD_ch_errG_local;
        bench_echoQ_mainG_methods.ch_exitG_local = ($R (*) (bench_echoQ_main, $Cont, sshQ_Channel, int64_t, B_str))bench_echoQ_mainD_ch_exitG_local;
        bench_echoQ_mainG_methods.ch_closeG_local = ($R (*) (bench_echoQ_main, $Cont, sshQ_Channel, B_str))bench_echoQ_mainD_ch_closeG_local;
        bench_echoQ_mainG_methods.fail = (B_Msg (*) (bench_echoQ_main, B_str))bench_echoQ_mainD_fail;
        bench_echoQ_mainG_methods.on_listen = (B_Msg (*) (bench_echoQ_main, sshQ_Server, B_str))bench_echoQ_mainD_on_listen;
        bench_echoQ_mainG_methods.on_server_close = (B_Msg (*) (bench_echoQ_main, sshQ_Server, B_str))bench_echoQ_mainD_on_server_close;
        bench_echoQ_mainG_methods.on_session = (B_Msg (*) (bench_echoQ_main, sshQ_ServerSession))bench_echoQ_mainD_on_session;
        bench_echoQ_mainG_methods.on_auth = (B_Msg (*) (bench_echoQ_main, sshQ_ServerSession, sshQ_AuthRequest))bench_echoQ_mainD_on_auth;
        bench_echoQ_mainG_methods.srv_on_data = (B_Msg (*) (bench_echoQ_main, sshQ_ServerChannel, B_bytes))bench_echoQ_mainD_srv_on_data;
        bench_echoQ_mainG_methods.srv_on_stderr = (B_Msg (*) (bench_echoQ_main, sshQ_ServerChannel, B_bytes))bench_echoQ_mainD_srv_on_stderr;
        bench_echoQ_mainG_methods.srv_on_close = (B_Msg (*) (bench_echoQ_main, sshQ_ServerChannel, B_str))bench_echoQ_mainD_srv_on_close;
        bench_echoQ_mainG_methods.on_channel_open = (B_Msg (*) (bench_echoQ_main, sshQ_ServerSession))bench_echoQ_mainD_on_channel_open;
        bench_echoQ_mainG_methods.on_exec = (B_Msg (*) (bench_echoQ_main, sshQ_ServerSession, sshQ_ServerChannel, B_str))bench_echoQ_mainD_on_exec;
        bench_echoQ_mainG_methods.on_hostkey = (B_Msg (*) (bench_echoQ_main, sshQ_Client, B_str, sshQ_HostKeyInfo))bench_echoQ_mainD_on_hostkey;
        bench_echoQ_mainG_methods.on_connect = (B_Msg (*) (bench_echoQ_main, sshQ_Client, B_str))bench_echoQ_mainD_on_connect;
        bench_echoQ_mainG_methods.on_client_close = (B_Msg (*) (bench_echoQ_main, sshQ_Client, B_str))bench_echoQ_mainD_on_client_close;
        bench_echoQ_mainG_methods.ch_open = (B_Msg (*) (bench_echoQ_main, sshQ_Channel, B_str))bench_echoQ_mainD_ch_open;
        bench_echoQ_mainG_methods.ch_out = (B_Msg (*) (bench_echoQ_main, sshQ_Channel, B_bytes))bench_echoQ_mainD_ch_out;
        bench_echoQ_mainG_methods.ch_err = (B_Msg (*) (bench_echoQ_main, sshQ_Channel, B_bytes))bench_echoQ_mainD_ch_err;
        bench_echoQ_mainG_methods.ch_exit = (B_Msg (*) (bench_echoQ_main, sshQ_Channel, int64_t, B_str))bench_echoQ_mainD_ch_exit;
        bench_echoQ_mainG_methods.ch_close = (B_Msg (*) (bench_echoQ_main, sshQ_Channel, B_str))bench_echoQ_mainD_ch_close;
        bench_echoQ_mainG_methods.__serialize__ = bench_echoQ_mainD___serialize__;
        bench_echoQ_mainG_methods.__deserialize__ = bench_echoQ_mainD___deserialize__;
        $register(&bench_echoQ_mainG_methods);
    }
    B_Collection W_main_34 = (B_Collection)B_SequenceD_listG_witness->W_Collection;
    bench_echoQ_W_main_34 = W_main_34;
    B_Iterable W_main_1054 = (B_Iterable)B_SequenceD_listG_witness->W_Collection;
    bench_echoQ_W_main_1054 = W_main_1054;
    B_Collection W_main_822 = (B_Collection)B_ContainerD_bytesG_witness;
    bench_echoQ_W_main_822 = W_main_822;
    B_Sliceable W_main_751 = (B_Sliceable)B_SliceableD_bytesG_witness;
    bench_echoQ_W_main_751 = W_main_751;
    B_Plus W_main_1092 = (B_Plus)B_TimesD_bytesG_witness;
    bench_echoQ_W_main_1092 = W_main_1092;
}