/* Acton impl hash: e482e977c0331f61d603ecdd81c5db23f859be779c65f1cf5d09fec138777e32 */
#include "rts/common.h"
#include "out/types/example_server.h"
B_Eq example_serverQ_W_main_489;
B_Collection example_serverQ_W_main_20;
B_Plus example_serverQ_W_main_268;
$R example_serverQ_L_1C_2cont (example_serverQ_main self, $Cont C_cont, sshQ_Server C_3res) {
    #line 78 "src/example_server.act"
    ((example_serverQ_main)(self))->server = C_3res;
    return $R_CONT(C_cont, B_None);
}
B_NoneType example_serverQ_L_2ContD___init__ (example_serverQ_L_2Cont L_self, example_serverQ_main self, $Cont C_cont) {
    ((example_serverQ_L_2Cont)(L_self))->self = self;
    ((example_serverQ_L_2Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R example_serverQ_L_2ContD___call__ (example_serverQ_L_2Cont L_self, sshQ_Server G_1) {
    example_serverQ_main self = ((example_serverQ_L_2Cont)(L_self))->self;
    $Cont C_cont = ((example_serverQ_L_2Cont)(L_self))->C_cont;
    return example_serverQ_L_1C_2cont(self, C_cont, G_1);
}
void example_serverQ_L_2ContD___serialize__ (example_serverQ_L_2Cont self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->C_cont, state);
}
example_serverQ_L_2Cont example_serverQ_L_2ContD___deserialize__ (example_serverQ_L_2Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct example_serverQ_L_2Cont));
            self->$class = &example_serverQ_L_2ContG_methods;
            return self;
        }
        self = $DNEW(example_serverQ_L_2Cont, state);
    }
    self->self = $step_deserialize(state);
    self->C_cont = $step_deserialize(state);
    return self;
}
example_serverQ_L_2Cont example_serverQ_L_2ContG_new(example_serverQ_main G_1, $Cont G_2) {
    example_serverQ_L_2Cont $tmp = acton_malloc(sizeof(struct example_serverQ_L_2Cont));
    $tmp->$class = &example_serverQ_L_2ContG_methods;
    example_serverQ_L_2ContG_methods.__init__($tmp, G_1, G_2);
    return $tmp;
}
struct example_serverQ_L_2ContG_class example_serverQ_L_2ContG_methods;
B_NoneType example_serverQ_L_4actionD___init__ (example_serverQ_L_4action L_self, example_serverQ_main L_3obj) {
    ((example_serverQ_L_4action)(L_self))->L_3obj = L_3obj;
    return B_None;
}
$R example_serverQ_L_4actionD___call__ (example_serverQ_L_4action L_self, $Cont L_cont, sshQ_Server G_1, B_str G_2) {
    return $AWAIT(L_cont, ((B_Msg (*) ($WORD, sshQ_Server, B_str))((example_serverQ_L_4action)(L_self))->$class->__asyn__)(L_self, G_1, G_2));
}
$R example_serverQ_L_4actionD___exec__ (example_serverQ_L_4action L_self, $Cont L_cont, sshQ_Server G_1, B_str G_2) {
    return $R_CONT(L_cont, ((B_Msg (*) ($WORD, sshQ_Server, B_str))((example_serverQ_L_4action)(L_self))->$class->__asyn__)(L_self, G_1, G_2));
}
B_Msg example_serverQ_L_4actionD___asyn__ (example_serverQ_L_4action L_self, sshQ_Server G_1, B_str G_2) {
    example_serverQ_main L_3obj = ((example_serverQ_L_4action)(L_self))->L_3obj;
    return ((B_Msg (*) ($WORD, sshQ_Server, B_str))((example_serverQ_main)(L_3obj))->$class->on_listen)(L_3obj, G_1, G_2);
}
void example_serverQ_L_4actionD___serialize__ (example_serverQ_L_4action self, $Serial$state state) {
    $step_serialize(self->L_3obj, state);
}
example_serverQ_L_4action example_serverQ_L_4actionD___deserialize__ (example_serverQ_L_4action self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct example_serverQ_L_4action));
            self->$class = &example_serverQ_L_4actionG_methods;
            return self;
        }
        self = $DNEW(example_serverQ_L_4action, state);
    }
    self->L_3obj = $step_deserialize(state);
    return self;
}
example_serverQ_L_4action example_serverQ_L_4actionG_new(example_serverQ_main G_1) {
    example_serverQ_L_4action $tmp = acton_malloc(sizeof(struct example_serverQ_L_4action));
    $tmp->$class = &example_serverQ_L_4actionG_methods;
    example_serverQ_L_4actionG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct example_serverQ_L_4actionG_class example_serverQ_L_4actionG_methods;
B_NoneType example_serverQ_L_6actionD___init__ (example_serverQ_L_6action L_self, example_serverQ_main L_5obj) {
    ((example_serverQ_L_6action)(L_self))->L_5obj = L_5obj;
    return B_None;
}
$R example_serverQ_L_6actionD___call__ (example_serverQ_L_6action L_self, $Cont L_cont, sshQ_Server G_1, B_str G_2) {
    return $AWAIT(L_cont, ((B_Msg (*) ($WORD, sshQ_Server, B_str))((example_serverQ_L_6action)(L_self))->$class->__asyn__)(L_self, G_1, G_2));
}
$R example_serverQ_L_6actionD___exec__ (example_serverQ_L_6action L_self, $Cont L_cont, sshQ_Server G_1, B_str G_2) {
    return $R_CONT(L_cont, ((B_Msg (*) ($WORD, sshQ_Server, B_str))((example_serverQ_L_6action)(L_self))->$class->__asyn__)(L_self, G_1, G_2));
}
B_Msg example_serverQ_L_6actionD___asyn__ (example_serverQ_L_6action L_self, sshQ_Server G_1, B_str G_2) {
    example_serverQ_main L_5obj = ((example_serverQ_L_6action)(L_self))->L_5obj;
    return ((B_Msg (*) ($WORD, sshQ_Server, B_str))((example_serverQ_main)(L_5obj))->$class->on_server_close)(L_5obj, G_1, G_2);
}
void example_serverQ_L_6actionD___serialize__ (example_serverQ_L_6action self, $Serial$state state) {
    $step_serialize(self->L_5obj, state);
}
example_serverQ_L_6action example_serverQ_L_6actionD___deserialize__ (example_serverQ_L_6action self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct example_serverQ_L_6action));
            self->$class = &example_serverQ_L_6actionG_methods;
            return self;
        }
        self = $DNEW(example_serverQ_L_6action, state);
    }
    self->L_5obj = $step_deserialize(state);
    return self;
}
example_serverQ_L_6action example_serverQ_L_6actionG_new(example_serverQ_main G_1) {
    example_serverQ_L_6action $tmp = acton_malloc(sizeof(struct example_serverQ_L_6action));
    $tmp->$class = &example_serverQ_L_6actionG_methods;
    example_serverQ_L_6actionG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct example_serverQ_L_6actionG_class example_serverQ_L_6actionG_methods;
B_NoneType example_serverQ_L_8actionD___init__ (example_serverQ_L_8action L_self, example_serverQ_main L_7obj) {
    ((example_serverQ_L_8action)(L_self))->L_7obj = L_7obj;
    return B_None;
}
$R example_serverQ_L_8actionD___call__ (example_serverQ_L_8action L_self, $Cont L_cont, sshQ_ServerSession G_1) {
    return $AWAIT(L_cont, ((B_Msg (*) ($WORD, sshQ_ServerSession))((example_serverQ_L_8action)(L_self))->$class->__asyn__)(L_self, G_1));
}
$R example_serverQ_L_8actionD___exec__ (example_serverQ_L_8action L_self, $Cont L_cont, sshQ_ServerSession G_1) {
    return $R_CONT(L_cont, ((B_Msg (*) ($WORD, sshQ_ServerSession))((example_serverQ_L_8action)(L_self))->$class->__asyn__)(L_self, G_1));
}
B_Msg example_serverQ_L_8actionD___asyn__ (example_serverQ_L_8action L_self, sshQ_ServerSession G_1) {
    example_serverQ_main L_7obj = ((example_serverQ_L_8action)(L_self))->L_7obj;
    return ((B_Msg (*) ($WORD, sshQ_ServerSession))((example_serverQ_main)(L_7obj))->$class->on_session)(L_7obj, G_1);
}
void example_serverQ_L_8actionD___serialize__ (example_serverQ_L_8action self, $Serial$state state) {
    $step_serialize(self->L_7obj, state);
}
example_serverQ_L_8action example_serverQ_L_8actionD___deserialize__ (example_serverQ_L_8action self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct example_serverQ_L_8action));
            self->$class = &example_serverQ_L_8actionG_methods;
            return self;
        }
        self = $DNEW(example_serverQ_L_8action, state);
    }
    self->L_7obj = $step_deserialize(state);
    return self;
}
example_serverQ_L_8action example_serverQ_L_8actionG_new(example_serverQ_main G_1) {
    example_serverQ_L_8action $tmp = acton_malloc(sizeof(struct example_serverQ_L_8action));
    $tmp->$class = &example_serverQ_L_8actionG_methods;
    example_serverQ_L_8actionG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct example_serverQ_L_8actionG_class example_serverQ_L_8actionG_methods;
B_NoneType example_serverQ_L_10actionD___init__ (example_serverQ_L_10action L_self, example_serverQ_main L_9obj) {
    ((example_serverQ_L_10action)(L_self))->L_9obj = L_9obj;
    return B_None;
}
$R example_serverQ_L_10actionD___call__ (example_serverQ_L_10action L_self, $Cont L_cont, sshQ_ServerSession G_1, sshQ_AuthRequest G_2) {
    return $AWAIT(L_cont, ((B_Msg (*) ($WORD, sshQ_ServerSession, sshQ_AuthRequest))((example_serverQ_L_10action)(L_self))->$class->__asyn__)(L_self, G_1, G_2));
}
$R example_serverQ_L_10actionD___exec__ (example_serverQ_L_10action L_self, $Cont L_cont, sshQ_ServerSession G_1, sshQ_AuthRequest G_2) {
    return $R_CONT(L_cont, ((B_Msg (*) ($WORD, sshQ_ServerSession, sshQ_AuthRequest))((example_serverQ_L_10action)(L_self))->$class->__asyn__)(L_self, G_1, G_2));
}
B_Msg example_serverQ_L_10actionD___asyn__ (example_serverQ_L_10action L_self, sshQ_ServerSession G_1, sshQ_AuthRequest G_2) {
    example_serverQ_main L_9obj = ((example_serverQ_L_10action)(L_self))->L_9obj;
    return ((B_Msg (*) ($WORD, sshQ_ServerSession, sshQ_AuthRequest))((example_serverQ_main)(L_9obj))->$class->on_auth)(L_9obj, G_1, G_2);
}
void example_serverQ_L_10actionD___serialize__ (example_serverQ_L_10action self, $Serial$state state) {
    $step_serialize(self->L_9obj, state);
}
example_serverQ_L_10action example_serverQ_L_10actionD___deserialize__ (example_serverQ_L_10action self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct example_serverQ_L_10action));
            self->$class = &example_serverQ_L_10actionG_methods;
            return self;
        }
        self = $DNEW(example_serverQ_L_10action, state);
    }
    self->L_9obj = $step_deserialize(state);
    return self;
}
example_serverQ_L_10action example_serverQ_L_10actionG_new(example_serverQ_main G_1) {
    example_serverQ_L_10action $tmp = acton_malloc(sizeof(struct example_serverQ_L_10action));
    $tmp->$class = &example_serverQ_L_10actionG_methods;
    example_serverQ_L_10actionG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct example_serverQ_L_10actionG_class example_serverQ_L_10actionG_methods;
B_NoneType example_serverQ_L_12actionD___init__ (example_serverQ_L_12action L_self, example_serverQ_main L_11obj) {
    ((example_serverQ_L_12action)(L_self))->L_11obj = L_11obj;
    return B_None;
}
$R example_serverQ_L_12actionD___call__ (example_serverQ_L_12action L_self, $Cont L_cont, sshQ_ServerSession G_1) {
    return $AWAIT(L_cont, ((B_Msg (*) ($WORD, sshQ_ServerSession))((example_serverQ_L_12action)(L_self))->$class->__asyn__)(L_self, G_1));
}
$R example_serverQ_L_12actionD___exec__ (example_serverQ_L_12action L_self, $Cont L_cont, sshQ_ServerSession G_1) {
    return $R_CONT(L_cont, ((B_Msg (*) ($WORD, sshQ_ServerSession))((example_serverQ_L_12action)(L_self))->$class->__asyn__)(L_self, G_1));
}
B_Msg example_serverQ_L_12actionD___asyn__ (example_serverQ_L_12action L_self, sshQ_ServerSession G_1) {
    example_serverQ_main L_11obj = ((example_serverQ_L_12action)(L_self))->L_11obj;
    return ((B_Msg (*) ($WORD, sshQ_ServerSession))((example_serverQ_main)(L_11obj))->$class->on_channel_open)(L_11obj, G_1);
}
void example_serverQ_L_12actionD___serialize__ (example_serverQ_L_12action self, $Serial$state state) {
    $step_serialize(self->L_11obj, state);
}
example_serverQ_L_12action example_serverQ_L_12actionD___deserialize__ (example_serverQ_L_12action self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct example_serverQ_L_12action));
            self->$class = &example_serverQ_L_12actionG_methods;
            return self;
        }
        self = $DNEW(example_serverQ_L_12action, state);
    }
    self->L_11obj = $step_deserialize(state);
    return self;
}
example_serverQ_L_12action example_serverQ_L_12actionG_new(example_serverQ_main G_1) {
    example_serverQ_L_12action $tmp = acton_malloc(sizeof(struct example_serverQ_L_12action));
    $tmp->$class = &example_serverQ_L_12actionG_methods;
    example_serverQ_L_12actionG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct example_serverQ_L_12actionG_class example_serverQ_L_12actionG_methods;
B_NoneType example_serverQ_L_14actionD___init__ (example_serverQ_L_14action L_self, example_serverQ_main L_13obj) {
    ((example_serverQ_L_14action)(L_self))->L_13obj = L_13obj;
    return B_None;
}
$R example_serverQ_L_14actionD___call__ (example_serverQ_L_14action L_self, $Cont L_cont, sshQ_ServerSession G_1, sshQ_ServerChannel G_2, B_str G_3) {
    return $AWAIT(L_cont, ((B_Msg (*) ($WORD, sshQ_ServerSession, sshQ_ServerChannel, B_str))((example_serverQ_L_14action)(L_self))->$class->__asyn__)(L_self, G_1, G_2, G_3));
}
$R example_serverQ_L_14actionD___exec__ (example_serverQ_L_14action L_self, $Cont L_cont, sshQ_ServerSession G_1, sshQ_ServerChannel G_2, B_str G_3) {
    return $R_CONT(L_cont, ((B_Msg (*) ($WORD, sshQ_ServerSession, sshQ_ServerChannel, B_str))((example_serverQ_L_14action)(L_self))->$class->__asyn__)(L_self, G_1, G_2, G_3));
}
B_Msg example_serverQ_L_14actionD___asyn__ (example_serverQ_L_14action L_self, sshQ_ServerSession G_1, sshQ_ServerChannel G_2, B_str G_3) {
    example_serverQ_main L_13obj = ((example_serverQ_L_14action)(L_self))->L_13obj;
    return ((B_Msg (*) ($WORD, sshQ_ServerSession, sshQ_ServerChannel, B_str))((example_serverQ_main)(L_13obj))->$class->on_exec)(L_13obj, G_1, G_2, G_3);
}
void example_serverQ_L_14actionD___serialize__ (example_serverQ_L_14action self, $Serial$state state) {
    $step_serialize(self->L_13obj, state);
}
example_serverQ_L_14action example_serverQ_L_14actionD___deserialize__ (example_serverQ_L_14action self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct example_serverQ_L_14action));
            self->$class = &example_serverQ_L_14actionG_methods;
            return self;
        }
        self = $DNEW(example_serverQ_L_14action, state);
    }
    self->L_13obj = $step_deserialize(state);
    return self;
}
example_serverQ_L_14action example_serverQ_L_14actionG_new(example_serverQ_main G_1) {
    example_serverQ_L_14action $tmp = acton_malloc(sizeof(struct example_serverQ_L_14action));
    $tmp->$class = &example_serverQ_L_14actionG_methods;
    example_serverQ_L_14actionG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct example_serverQ_L_14actionG_class example_serverQ_L_14actionG_methods;
B_NoneType example_serverQ_L_16actionD___init__ (example_serverQ_L_16action L_self, example_serverQ_main L_15obj) {
    ((example_serverQ_L_16action)(L_self))->L_15obj = L_15obj;
    return B_None;
}
$R example_serverQ_L_16actionD___call__ (example_serverQ_L_16action L_self, $Cont L_cont, sshQ_ServerSession G_1, B_str G_2) {
    return $AWAIT(L_cont, ((B_Msg (*) ($WORD, sshQ_ServerSession, B_str))((example_serverQ_L_16action)(L_self))->$class->__asyn__)(L_self, G_1, G_2));
}
$R example_serverQ_L_16actionD___exec__ (example_serverQ_L_16action L_self, $Cont L_cont, sshQ_ServerSession G_1, B_str G_2) {
    return $R_CONT(L_cont, ((B_Msg (*) ($WORD, sshQ_ServerSession, B_str))((example_serverQ_L_16action)(L_self))->$class->__asyn__)(L_self, G_1, G_2));
}
B_Msg example_serverQ_L_16actionD___asyn__ (example_serverQ_L_16action L_self, sshQ_ServerSession G_1, B_str G_2) {
    example_serverQ_main L_15obj = ((example_serverQ_L_16action)(L_self))->L_15obj;
    return ((B_Msg (*) ($WORD, sshQ_ServerSession, B_str))((example_serverQ_main)(L_15obj))->$class->on_session_close)(L_15obj, G_1, G_2);
}
void example_serverQ_L_16actionD___serialize__ (example_serverQ_L_16action self, $Serial$state state) {
    $step_serialize(self->L_15obj, state);
}
example_serverQ_L_16action example_serverQ_L_16actionD___deserialize__ (example_serverQ_L_16action self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct example_serverQ_L_16action));
            self->$class = &example_serverQ_L_16actionG_methods;
            return self;
        }
        self = $DNEW(example_serverQ_L_16action, state);
    }
    self->L_15obj = $step_deserialize(state);
    return self;
}
example_serverQ_L_16action example_serverQ_L_16actionG_new(example_serverQ_main G_1) {
    example_serverQ_L_16action $tmp = acton_malloc(sizeof(struct example_serverQ_L_16action));
    $tmp->$class = &example_serverQ_L_16actionG_methods;
    example_serverQ_L_16actionG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct example_serverQ_L_16actionG_class example_serverQ_L_16actionG_methods;
$R example_serverQ_L_18C_6cont (example_serverQ_main self, $Cont C_cont, uint16_t C_7res) {
    #line 35 "src/example_server.act"
    uint16_t p = C_7res;
    #line 36 "src/example_server.act"
    ((B_NoneType (*) (B_tuple, B_str, B_str, B_bool, B_bool))B_print)($NEWTUPLE(1, ((B_str (*) ($WORD, B_str, B_str))((B_Plus)(example_serverQ_W_main_268))->$class->__add__)(example_serverQ_W_main_268, ((B_str (*) ($WORD, B_str, B_str))((B_Plus)(example_serverQ_W_main_268))->$class->__add__)(example_serverQ_W_main_268, ((B_str (*) ($WORD, B_str, B_str))((B_Plus)(example_serverQ_W_main_268))->$class->__add__)(example_serverQ_W_main_268, ((B_str (*) ($WORD, B_str, B_str))((B_Plus)(example_serverQ_W_main_268))->$class->__add__)(example_serverQ_W_main_268, to$str("listening on 127.0.0.1:"), B_strG_new(((B_value)toB_u16(p)))), to$str(" (user=")), ((example_serverQ_main)(self))->user), to$str(")"))), B_None, B_None, B_None, B_None);
    return $R_CONT(C_cont, B_None);
}
B_NoneType example_serverQ_L_19ContD___init__ (example_serverQ_L_19Cont L_self, example_serverQ_main self, $Cont C_cont) {
    ((example_serverQ_L_19Cont)(L_self))->self = self;
    ((example_serverQ_L_19Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R example_serverQ_L_19ContD___call__ (example_serverQ_L_19Cont L_self, B_u16 G_1) {
    example_serverQ_main self = ((example_serverQ_L_19Cont)(L_self))->self;
    $Cont C_cont = ((example_serverQ_L_19Cont)(L_self))->C_cont;
    return example_serverQ_L_18C_6cont(self, C_cont, ((B_u16)G_1)->val);
}
void example_serverQ_L_19ContD___serialize__ (example_serverQ_L_19Cont self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->C_cont, state);
}
example_serverQ_L_19Cont example_serverQ_L_19ContD___deserialize__ (example_serverQ_L_19Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct example_serverQ_L_19Cont));
            self->$class = &example_serverQ_L_19ContG_methods;
            return self;
        }
        self = $DNEW(example_serverQ_L_19Cont, state);
    }
    self->self = $step_deserialize(state);
    self->C_cont = $step_deserialize(state);
    return self;
}
example_serverQ_L_19Cont example_serverQ_L_19ContG_new(example_serverQ_main G_1, $Cont G_2) {
    example_serverQ_L_19Cont $tmp = acton_malloc(sizeof(struct example_serverQ_L_19Cont));
    $tmp->$class = &example_serverQ_L_19ContG_methods;
    example_serverQ_L_19ContG_methods.__init__($tmp, G_1, G_2);
    return $tmp;
}
struct example_serverQ_L_19ContG_class example_serverQ_L_19ContG_methods;
$R example_serverQ_L_17C_4cont (example_serverQ_main self, $Cont C_cont, sshQ_Server s, B_NoneType C_5res) {
    return $AWAIT((($Cont)example_serverQ_L_19ContG_new(self, C_cont)), ((B_Msg (*) ($WORD))((sshQ_Server)(s))->$class->bound_port)(s));
}
B_NoneType example_serverQ_L_20ContD___init__ (example_serverQ_L_20Cont L_self, example_serverQ_main self, $Cont C_cont, sshQ_Server s) {
    ((example_serverQ_L_20Cont)(L_self))->self = self;
    ((example_serverQ_L_20Cont)(L_self))->C_cont = C_cont;
    ((example_serverQ_L_20Cont)(L_self))->s = s;
    return B_None;
}
$R example_serverQ_L_20ContD___call__ (example_serverQ_L_20Cont L_self, B_NoneType G_1) {
    example_serverQ_main self = ((example_serverQ_L_20Cont)(L_self))->self;
    $Cont C_cont = ((example_serverQ_L_20Cont)(L_self))->C_cont;
    sshQ_Server s = ((example_serverQ_L_20Cont)(L_self))->s;
    return example_serverQ_L_17C_4cont(self, C_cont, s, G_1);
}
void example_serverQ_L_20ContD___serialize__ (example_serverQ_L_20Cont self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->C_cont, state);
    $step_serialize(self->s, state);
}
example_serverQ_L_20Cont example_serverQ_L_20ContD___deserialize__ (example_serverQ_L_20Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct example_serverQ_L_20Cont));
            self->$class = &example_serverQ_L_20ContG_methods;
            return self;
        }
        self = $DNEW(example_serverQ_L_20Cont, state);
    }
    self->self = $step_deserialize(state);
    self->C_cont = $step_deserialize(state);
    self->s = $step_deserialize(state);
    return self;
}
example_serverQ_L_20Cont example_serverQ_L_20ContG_new(example_serverQ_main G_1, $Cont G_2, sshQ_Server G_3) {
    example_serverQ_L_20Cont $tmp = acton_malloc(sizeof(struct example_serverQ_L_20Cont));
    $tmp->$class = &example_serverQ_L_20ContG_methods;
    example_serverQ_L_20ContG_methods.__init__($tmp, G_1, G_2, G_3);
    return $tmp;
}
struct example_serverQ_L_20ContG_class example_serverQ_L_20ContG_methods;
$R example_serverQ_L_21C_8cont (sshQ_ServerSession sess, $Cont C_cont, sshQ_ServerChannel C_9res) {
    sshQ_ServerChannel C_1pre = C_9res;
    #line 69 "src/example_server.act"
    ((B_Msg (*) ($WORD, sshQ_ServerChannel))((sshQ_ServerSession)(sess))->$class->accept_channel)(sess, C_1pre);
    return $R_CONT(C_cont, B_None);
}
B_NoneType example_serverQ_L_22ContD___init__ (example_serverQ_L_22Cont L_self, sshQ_ServerSession sess, $Cont C_cont) {
    ((example_serverQ_L_22Cont)(L_self))->sess = sess;
    ((example_serverQ_L_22Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R example_serverQ_L_22ContD___call__ (example_serverQ_L_22Cont L_self, sshQ_ServerChannel G_1) {
    sshQ_ServerSession sess = ((example_serverQ_L_22Cont)(L_self))->sess;
    $Cont C_cont = ((example_serverQ_L_22Cont)(L_self))->C_cont;
    return example_serverQ_L_21C_8cont(sess, C_cont, G_1);
}
void example_serverQ_L_22ContD___serialize__ (example_serverQ_L_22Cont self, $Serial$state state) {
    $step_serialize(self->sess, state);
    $step_serialize(self->C_cont, state);
}
example_serverQ_L_22Cont example_serverQ_L_22ContD___deserialize__ (example_serverQ_L_22Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct example_serverQ_L_22Cont));
            self->$class = &example_serverQ_L_22ContG_methods;
            return self;
        }
        self = $DNEW(example_serverQ_L_22Cont, state);
    }
    self->sess = $step_deserialize(state);
    self->C_cont = $step_deserialize(state);
    return self;
}
example_serverQ_L_22Cont example_serverQ_L_22ContG_new(sshQ_ServerSession G_1, $Cont G_2) {
    example_serverQ_L_22Cont $tmp = acton_malloc(sizeof(struct example_serverQ_L_22Cont));
    $tmp->$class = &example_serverQ_L_22ContG_methods;
    example_serverQ_L_22ContG_methods.__init__($tmp, G_1, G_2);
    return $tmp;
}
struct example_serverQ_L_22ContG_class example_serverQ_L_22ContG_methods;
B_NoneType example_serverQ_L_24actionD___init__ (example_serverQ_L_24action L_self, example_serverQ_main L_23obj) {
    ((example_serverQ_L_24action)(L_self))->L_23obj = L_23obj;
    return B_None;
}
$R example_serverQ_L_24actionD___call__ (example_serverQ_L_24action L_self, $Cont L_cont, sshQ_ServerChannel G_1, B_bytes G_2) {
    return $AWAIT(L_cont, ((B_Msg (*) ($WORD, sshQ_ServerChannel, B_bytes))((example_serverQ_L_24action)(L_self))->$class->__asyn__)(L_self, G_1, G_2));
}
$R example_serverQ_L_24actionD___exec__ (example_serverQ_L_24action L_self, $Cont L_cont, sshQ_ServerChannel G_1, B_bytes G_2) {
    return $R_CONT(L_cont, ((B_Msg (*) ($WORD, sshQ_ServerChannel, B_bytes))((example_serverQ_L_24action)(L_self))->$class->__asyn__)(L_self, G_1, G_2));
}
B_Msg example_serverQ_L_24actionD___asyn__ (example_serverQ_L_24action L_self, sshQ_ServerChannel G_1, B_bytes G_2) {
    example_serverQ_main L_23obj = ((example_serverQ_L_24action)(L_self))->L_23obj;
    return ((B_Msg (*) ($WORD, sshQ_ServerChannel, B_bytes))((example_serverQ_main)(L_23obj))->$class->srv_on_data)(L_23obj, G_1, G_2);
}
void example_serverQ_L_24actionD___serialize__ (example_serverQ_L_24action self, $Serial$state state) {
    $step_serialize(self->L_23obj, state);
}
example_serverQ_L_24action example_serverQ_L_24actionD___deserialize__ (example_serverQ_L_24action self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct example_serverQ_L_24action));
            self->$class = &example_serverQ_L_24actionG_methods;
            return self;
        }
        self = $DNEW(example_serverQ_L_24action, state);
    }
    self->L_23obj = $step_deserialize(state);
    return self;
}
example_serverQ_L_24action example_serverQ_L_24actionG_new(example_serverQ_main G_1) {
    example_serverQ_L_24action $tmp = acton_malloc(sizeof(struct example_serverQ_L_24action));
    $tmp->$class = &example_serverQ_L_24actionG_methods;
    example_serverQ_L_24actionG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct example_serverQ_L_24actionG_class example_serverQ_L_24actionG_methods;
B_NoneType example_serverQ_L_26actionD___init__ (example_serverQ_L_26action L_self, example_serverQ_main L_25obj) {
    ((example_serverQ_L_26action)(L_self))->L_25obj = L_25obj;
    return B_None;
}
$R example_serverQ_L_26actionD___call__ (example_serverQ_L_26action L_self, $Cont L_cont, sshQ_ServerChannel G_1, B_bytes G_2) {
    return $AWAIT(L_cont, ((B_Msg (*) ($WORD, sshQ_ServerChannel, B_bytes))((example_serverQ_L_26action)(L_self))->$class->__asyn__)(L_self, G_1, G_2));
}
$R example_serverQ_L_26actionD___exec__ (example_serverQ_L_26action L_self, $Cont L_cont, sshQ_ServerChannel G_1, B_bytes G_2) {
    return $R_CONT(L_cont, ((B_Msg (*) ($WORD, sshQ_ServerChannel, B_bytes))((example_serverQ_L_26action)(L_self))->$class->__asyn__)(L_self, G_1, G_2));
}
B_Msg example_serverQ_L_26actionD___asyn__ (example_serverQ_L_26action L_self, sshQ_ServerChannel G_1, B_bytes G_2) {
    example_serverQ_main L_25obj = ((example_serverQ_L_26action)(L_self))->L_25obj;
    return ((B_Msg (*) ($WORD, sshQ_ServerChannel, B_bytes))((example_serverQ_main)(L_25obj))->$class->srv_on_stderr)(L_25obj, G_1, G_2);
}
void example_serverQ_L_26actionD___serialize__ (example_serverQ_L_26action self, $Serial$state state) {
    $step_serialize(self->L_25obj, state);
}
example_serverQ_L_26action example_serverQ_L_26actionD___deserialize__ (example_serverQ_L_26action self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct example_serverQ_L_26action));
            self->$class = &example_serverQ_L_26actionG_methods;
            return self;
        }
        self = $DNEW(example_serverQ_L_26action, state);
    }
    self->L_25obj = $step_deserialize(state);
    return self;
}
example_serverQ_L_26action example_serverQ_L_26actionG_new(example_serverQ_main G_1) {
    example_serverQ_L_26action $tmp = acton_malloc(sizeof(struct example_serverQ_L_26action));
    $tmp->$class = &example_serverQ_L_26actionG_methods;
    example_serverQ_L_26actionG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct example_serverQ_L_26actionG_class example_serverQ_L_26actionG_methods;
B_NoneType example_serverQ_L_28actionD___init__ (example_serverQ_L_28action L_self, example_serverQ_main L_27obj) {
    ((example_serverQ_L_28action)(L_self))->L_27obj = L_27obj;
    return B_None;
}
$R example_serverQ_L_28actionD___call__ (example_serverQ_L_28action L_self, $Cont L_cont, sshQ_ServerChannel G_1, B_str G_2) {
    return $AWAIT(L_cont, ((B_Msg (*) ($WORD, sshQ_ServerChannel, B_str))((example_serverQ_L_28action)(L_self))->$class->__asyn__)(L_self, G_1, G_2));
}
$R example_serverQ_L_28actionD___exec__ (example_serverQ_L_28action L_self, $Cont L_cont, sshQ_ServerChannel G_1, B_str G_2) {
    return $R_CONT(L_cont, ((B_Msg (*) ($WORD, sshQ_ServerChannel, B_str))((example_serverQ_L_28action)(L_self))->$class->__asyn__)(L_self, G_1, G_2));
}
B_Msg example_serverQ_L_28actionD___asyn__ (example_serverQ_L_28action L_self, sshQ_ServerChannel G_1, B_str G_2) {
    example_serverQ_main L_27obj = ((example_serverQ_L_28action)(L_self))->L_27obj;
    return ((B_Msg (*) ($WORD, sshQ_ServerChannel, B_str))((example_serverQ_main)(L_27obj))->$class->srv_on_close)(L_27obj, G_1, G_2);
}
void example_serverQ_L_28actionD___serialize__ (example_serverQ_L_28action self, $Serial$state state) {
    $step_serialize(self->L_27obj, state);
}
example_serverQ_L_28action example_serverQ_L_28actionD___deserialize__ (example_serverQ_L_28action self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct example_serverQ_L_28action));
            self->$class = &example_serverQ_L_28actionG_methods;
            return self;
        }
        self = $DNEW(example_serverQ_L_28action, state);
    }
    self->L_27obj = $step_deserialize(state);
    return self;
}
example_serverQ_L_28action example_serverQ_L_28actionG_new(example_serverQ_main G_1) {
    example_serverQ_L_28action $tmp = acton_malloc(sizeof(struct example_serverQ_L_28action));
    $tmp->$class = &example_serverQ_L_28actionG_methods;
    example_serverQ_L_28actionG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct example_serverQ_L_28actionG_class example_serverQ_L_28actionG_methods;
B_NoneType example_serverQ_L_29procD___init__ (example_serverQ_L_29proc L_self, example_serverQ_main self, sshQ_Server s, B_str err) {
    ((example_serverQ_L_29proc)(L_self))->self = self;
    ((example_serverQ_L_29proc)(L_self))->s = s;
    ((example_serverQ_L_29proc)(L_self))->err = err;
    return B_None;
}
$R example_serverQ_L_29procD___call__ (example_serverQ_L_29proc L_self, $Cont C_cont) {
    example_serverQ_main self = ((example_serverQ_L_29proc)(L_self))->self;
    sshQ_Server s = ((example_serverQ_L_29proc)(L_self))->s;
    B_str err = ((example_serverQ_L_29proc)(L_self))->err;
    return (($R (*) ($WORD, $Cont, sshQ_Server, B_str))((example_serverQ_main)(self))->$class->on_listenG_local)(self, C_cont, s, err);
}
$R example_serverQ_L_29procD___exec__ (example_serverQ_L_29proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((example_serverQ_L_29proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void example_serverQ_L_29procD___serialize__ (example_serverQ_L_29proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->s, state);
    $step_serialize(self->err, state);
}
example_serverQ_L_29proc example_serverQ_L_29procD___deserialize__ (example_serverQ_L_29proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct example_serverQ_L_29proc));
            self->$class = &example_serverQ_L_29procG_methods;
            return self;
        }
        self = $DNEW(example_serverQ_L_29proc, state);
    }
    self->self = $step_deserialize(state);
    self->s = $step_deserialize(state);
    self->err = $step_deserialize(state);
    return self;
}
example_serverQ_L_29proc example_serverQ_L_29procG_new(example_serverQ_main G_1, sshQ_Server G_2, B_str G_3) {
    example_serverQ_L_29proc $tmp = acton_malloc(sizeof(struct example_serverQ_L_29proc));
    $tmp->$class = &example_serverQ_L_29procG_methods;
    example_serverQ_L_29procG_methods.__init__($tmp, G_1, G_2, G_3);
    return $tmp;
}
struct example_serverQ_L_29procG_class example_serverQ_L_29procG_methods;
B_NoneType example_serverQ_L_30procD___init__ (example_serverQ_L_30proc L_self, example_serverQ_main self, sshQ_Server s, B_str reason) {
    ((example_serverQ_L_30proc)(L_self))->self = self;
    ((example_serverQ_L_30proc)(L_self))->s = s;
    ((example_serverQ_L_30proc)(L_self))->reason = reason;
    return B_None;
}
$R example_serverQ_L_30procD___call__ (example_serverQ_L_30proc L_self, $Cont C_cont) {
    example_serverQ_main self = ((example_serverQ_L_30proc)(L_self))->self;
    sshQ_Server s = ((example_serverQ_L_30proc)(L_self))->s;
    B_str reason = ((example_serverQ_L_30proc)(L_self))->reason;
    return (($R (*) ($WORD, $Cont, sshQ_Server, B_str))((example_serverQ_main)(self))->$class->on_server_closeG_local)(self, C_cont, s, reason);
}
$R example_serverQ_L_30procD___exec__ (example_serverQ_L_30proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((example_serverQ_L_30proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void example_serverQ_L_30procD___serialize__ (example_serverQ_L_30proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->s, state);
    $step_serialize(self->reason, state);
}
example_serverQ_L_30proc example_serverQ_L_30procD___deserialize__ (example_serverQ_L_30proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct example_serverQ_L_30proc));
            self->$class = &example_serverQ_L_30procG_methods;
            return self;
        }
        self = $DNEW(example_serverQ_L_30proc, state);
    }
    self->self = $step_deserialize(state);
    self->s = $step_deserialize(state);
    self->reason = $step_deserialize(state);
    return self;
}
example_serverQ_L_30proc example_serverQ_L_30procG_new(example_serverQ_main G_1, sshQ_Server G_2, B_str G_3) {
    example_serverQ_L_30proc $tmp = acton_malloc(sizeof(struct example_serverQ_L_30proc));
    $tmp->$class = &example_serverQ_L_30procG_methods;
    example_serverQ_L_30procG_methods.__init__($tmp, G_1, G_2, G_3);
    return $tmp;
}
struct example_serverQ_L_30procG_class example_serverQ_L_30procG_methods;
B_NoneType example_serverQ_L_31procD___init__ (example_serverQ_L_31proc L_self, example_serverQ_main self, sshQ_ServerSession sess) {
    ((example_serverQ_L_31proc)(L_self))->self = self;
    ((example_serverQ_L_31proc)(L_self))->sess = sess;
    return B_None;
}
$R example_serverQ_L_31procD___call__ (example_serverQ_L_31proc L_self, $Cont C_cont) {
    example_serverQ_main self = ((example_serverQ_L_31proc)(L_self))->self;
    sshQ_ServerSession sess = ((example_serverQ_L_31proc)(L_self))->sess;
    return (($R (*) ($WORD, $Cont, sshQ_ServerSession))((example_serverQ_main)(self))->$class->on_sessionG_local)(self, C_cont, sess);
}
$R example_serverQ_L_31procD___exec__ (example_serverQ_L_31proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((example_serverQ_L_31proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void example_serverQ_L_31procD___serialize__ (example_serverQ_L_31proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->sess, state);
}
example_serverQ_L_31proc example_serverQ_L_31procD___deserialize__ (example_serverQ_L_31proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct example_serverQ_L_31proc));
            self->$class = &example_serverQ_L_31procG_methods;
            return self;
        }
        self = $DNEW(example_serverQ_L_31proc, state);
    }
    self->self = $step_deserialize(state);
    self->sess = $step_deserialize(state);
    return self;
}
example_serverQ_L_31proc example_serverQ_L_31procG_new(example_serverQ_main G_1, sshQ_ServerSession G_2) {
    example_serverQ_L_31proc $tmp = acton_malloc(sizeof(struct example_serverQ_L_31proc));
    $tmp->$class = &example_serverQ_L_31procG_methods;
    example_serverQ_L_31procG_methods.__init__($tmp, G_1, G_2);
    return $tmp;
}
struct example_serverQ_L_31procG_class example_serverQ_L_31procG_methods;
B_NoneType example_serverQ_L_32procD___init__ (example_serverQ_L_32proc L_self, example_serverQ_main self, sshQ_ServerSession sess, B_str reason) {
    ((example_serverQ_L_32proc)(L_self))->self = self;
    ((example_serverQ_L_32proc)(L_self))->sess = sess;
    ((example_serverQ_L_32proc)(L_self))->reason = reason;
    return B_None;
}
$R example_serverQ_L_32procD___call__ (example_serverQ_L_32proc L_self, $Cont C_cont) {
    example_serverQ_main self = ((example_serverQ_L_32proc)(L_self))->self;
    sshQ_ServerSession sess = ((example_serverQ_L_32proc)(L_self))->sess;
    B_str reason = ((example_serverQ_L_32proc)(L_self))->reason;
    return (($R (*) ($WORD, $Cont, sshQ_ServerSession, B_str))((example_serverQ_main)(self))->$class->on_session_closeG_local)(self, C_cont, sess, reason);
}
$R example_serverQ_L_32procD___exec__ (example_serverQ_L_32proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((example_serverQ_L_32proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void example_serverQ_L_32procD___serialize__ (example_serverQ_L_32proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->sess, state);
    $step_serialize(self->reason, state);
}
example_serverQ_L_32proc example_serverQ_L_32procD___deserialize__ (example_serverQ_L_32proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct example_serverQ_L_32proc));
            self->$class = &example_serverQ_L_32procG_methods;
            return self;
        }
        self = $DNEW(example_serverQ_L_32proc, state);
    }
    self->self = $step_deserialize(state);
    self->sess = $step_deserialize(state);
    self->reason = $step_deserialize(state);
    return self;
}
example_serverQ_L_32proc example_serverQ_L_32procG_new(example_serverQ_main G_1, sshQ_ServerSession G_2, B_str G_3) {
    example_serverQ_L_32proc $tmp = acton_malloc(sizeof(struct example_serverQ_L_32proc));
    $tmp->$class = &example_serverQ_L_32procG_methods;
    example_serverQ_L_32procG_methods.__init__($tmp, G_1, G_2, G_3);
    return $tmp;
}
struct example_serverQ_L_32procG_class example_serverQ_L_32procG_methods;
B_NoneType example_serverQ_L_33procD___init__ (example_serverQ_L_33proc L_self, example_serverQ_main self, sshQ_ServerSession sess, sshQ_AuthRequest req) {
    ((example_serverQ_L_33proc)(L_self))->self = self;
    ((example_serverQ_L_33proc)(L_self))->sess = sess;
    ((example_serverQ_L_33proc)(L_self))->req = req;
    return B_None;
}
$R example_serverQ_L_33procD___call__ (example_serverQ_L_33proc L_self, $Cont C_cont) {
    example_serverQ_main self = ((example_serverQ_L_33proc)(L_self))->self;
    sshQ_ServerSession sess = ((example_serverQ_L_33proc)(L_self))->sess;
    sshQ_AuthRequest req = ((example_serverQ_L_33proc)(L_self))->req;
    return (($R (*) ($WORD, $Cont, sshQ_ServerSession, sshQ_AuthRequest))((example_serverQ_main)(self))->$class->on_authG_local)(self, C_cont, sess, req);
}
$R example_serverQ_L_33procD___exec__ (example_serverQ_L_33proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((example_serverQ_L_33proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void example_serverQ_L_33procD___serialize__ (example_serverQ_L_33proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->sess, state);
    $step_serialize(self->req, state);
}
example_serverQ_L_33proc example_serverQ_L_33procD___deserialize__ (example_serverQ_L_33proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct example_serverQ_L_33proc));
            self->$class = &example_serverQ_L_33procG_methods;
            return self;
        }
        self = $DNEW(example_serverQ_L_33proc, state);
    }
    self->self = $step_deserialize(state);
    self->sess = $step_deserialize(state);
    self->req = $step_deserialize(state);
    return self;
}
example_serverQ_L_33proc example_serverQ_L_33procG_new(example_serverQ_main G_1, sshQ_ServerSession G_2, sshQ_AuthRequest G_3) {
    example_serverQ_L_33proc $tmp = acton_malloc(sizeof(struct example_serverQ_L_33proc));
    $tmp->$class = &example_serverQ_L_33procG_methods;
    example_serverQ_L_33procG_methods.__init__($tmp, G_1, G_2, G_3);
    return $tmp;
}
struct example_serverQ_L_33procG_class example_serverQ_L_33procG_methods;
B_NoneType example_serverQ_L_34procD___init__ (example_serverQ_L_34proc L_self, example_serverQ_main self, sshQ_ServerChannel ch, B_bytes data) {
    ((example_serverQ_L_34proc)(L_self))->self = self;
    ((example_serverQ_L_34proc)(L_self))->ch = ch;
    ((example_serverQ_L_34proc)(L_self))->data = data;
    return B_None;
}
$R example_serverQ_L_34procD___call__ (example_serverQ_L_34proc L_self, $Cont C_cont) {
    example_serverQ_main self = ((example_serverQ_L_34proc)(L_self))->self;
    sshQ_ServerChannel ch = ((example_serverQ_L_34proc)(L_self))->ch;
    B_bytes data = ((example_serverQ_L_34proc)(L_self))->data;
    return (($R (*) ($WORD, $Cont, sshQ_ServerChannel, B_bytes))((example_serverQ_main)(self))->$class->srv_on_dataG_local)(self, C_cont, ch, data);
}
$R example_serverQ_L_34procD___exec__ (example_serverQ_L_34proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((example_serverQ_L_34proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void example_serverQ_L_34procD___serialize__ (example_serverQ_L_34proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->ch, state);
    $step_serialize(self->data, state);
}
example_serverQ_L_34proc example_serverQ_L_34procD___deserialize__ (example_serverQ_L_34proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct example_serverQ_L_34proc));
            self->$class = &example_serverQ_L_34procG_methods;
            return self;
        }
        self = $DNEW(example_serverQ_L_34proc, state);
    }
    self->self = $step_deserialize(state);
    self->ch = $step_deserialize(state);
    self->data = $step_deserialize(state);
    return self;
}
example_serverQ_L_34proc example_serverQ_L_34procG_new(example_serverQ_main G_1, sshQ_ServerChannel G_2, B_bytes G_3) {
    example_serverQ_L_34proc $tmp = acton_malloc(sizeof(struct example_serverQ_L_34proc));
    $tmp->$class = &example_serverQ_L_34procG_methods;
    example_serverQ_L_34procG_methods.__init__($tmp, G_1, G_2, G_3);
    return $tmp;
}
struct example_serverQ_L_34procG_class example_serverQ_L_34procG_methods;
B_NoneType example_serverQ_L_35procD___init__ (example_serverQ_L_35proc L_self, example_serverQ_main self, sshQ_ServerChannel ch, B_bytes data) {
    ((example_serverQ_L_35proc)(L_self))->self = self;
    ((example_serverQ_L_35proc)(L_self))->ch = ch;
    ((example_serverQ_L_35proc)(L_self))->data = data;
    return B_None;
}
$R example_serverQ_L_35procD___call__ (example_serverQ_L_35proc L_self, $Cont C_cont) {
    example_serverQ_main self = ((example_serverQ_L_35proc)(L_self))->self;
    sshQ_ServerChannel ch = ((example_serverQ_L_35proc)(L_self))->ch;
    B_bytes data = ((example_serverQ_L_35proc)(L_self))->data;
    return (($R (*) ($WORD, $Cont, sshQ_ServerChannel, B_bytes))((example_serverQ_main)(self))->$class->srv_on_stderrG_local)(self, C_cont, ch, data);
}
$R example_serverQ_L_35procD___exec__ (example_serverQ_L_35proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((example_serverQ_L_35proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void example_serverQ_L_35procD___serialize__ (example_serverQ_L_35proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->ch, state);
    $step_serialize(self->data, state);
}
example_serverQ_L_35proc example_serverQ_L_35procD___deserialize__ (example_serverQ_L_35proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct example_serverQ_L_35proc));
            self->$class = &example_serverQ_L_35procG_methods;
            return self;
        }
        self = $DNEW(example_serverQ_L_35proc, state);
    }
    self->self = $step_deserialize(state);
    self->ch = $step_deserialize(state);
    self->data = $step_deserialize(state);
    return self;
}
example_serverQ_L_35proc example_serverQ_L_35procG_new(example_serverQ_main G_1, sshQ_ServerChannel G_2, B_bytes G_3) {
    example_serverQ_L_35proc $tmp = acton_malloc(sizeof(struct example_serverQ_L_35proc));
    $tmp->$class = &example_serverQ_L_35procG_methods;
    example_serverQ_L_35procG_methods.__init__($tmp, G_1, G_2, G_3);
    return $tmp;
}
struct example_serverQ_L_35procG_class example_serverQ_L_35procG_methods;
B_NoneType example_serverQ_L_36procD___init__ (example_serverQ_L_36proc L_self, example_serverQ_main self, sshQ_ServerChannel ch, B_str reason) {
    ((example_serverQ_L_36proc)(L_self))->self = self;
    ((example_serverQ_L_36proc)(L_self))->ch = ch;
    ((example_serverQ_L_36proc)(L_self))->reason = reason;
    return B_None;
}
$R example_serverQ_L_36procD___call__ (example_serverQ_L_36proc L_self, $Cont C_cont) {
    example_serverQ_main self = ((example_serverQ_L_36proc)(L_self))->self;
    sshQ_ServerChannel ch = ((example_serverQ_L_36proc)(L_self))->ch;
    B_str reason = ((example_serverQ_L_36proc)(L_self))->reason;
    return (($R (*) ($WORD, $Cont, sshQ_ServerChannel, B_str))((example_serverQ_main)(self))->$class->srv_on_closeG_local)(self, C_cont, ch, reason);
}
$R example_serverQ_L_36procD___exec__ (example_serverQ_L_36proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((example_serverQ_L_36proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void example_serverQ_L_36procD___serialize__ (example_serverQ_L_36proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->ch, state);
    $step_serialize(self->reason, state);
}
example_serverQ_L_36proc example_serverQ_L_36procD___deserialize__ (example_serverQ_L_36proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct example_serverQ_L_36proc));
            self->$class = &example_serverQ_L_36procG_methods;
            return self;
        }
        self = $DNEW(example_serverQ_L_36proc, state);
    }
    self->self = $step_deserialize(state);
    self->ch = $step_deserialize(state);
    self->reason = $step_deserialize(state);
    return self;
}
example_serverQ_L_36proc example_serverQ_L_36procG_new(example_serverQ_main G_1, sshQ_ServerChannel G_2, B_str G_3) {
    example_serverQ_L_36proc $tmp = acton_malloc(sizeof(struct example_serverQ_L_36proc));
    $tmp->$class = &example_serverQ_L_36procG_methods;
    example_serverQ_L_36procG_methods.__init__($tmp, G_1, G_2, G_3);
    return $tmp;
}
struct example_serverQ_L_36procG_class example_serverQ_L_36procG_methods;
B_NoneType example_serverQ_L_37procD___init__ (example_serverQ_L_37proc L_self, example_serverQ_main self, sshQ_ServerSession sess) {
    ((example_serverQ_L_37proc)(L_self))->self = self;
    ((example_serverQ_L_37proc)(L_self))->sess = sess;
    return B_None;
}
$R example_serverQ_L_37procD___call__ (example_serverQ_L_37proc L_self, $Cont C_cont) {
    example_serverQ_main self = ((example_serverQ_L_37proc)(L_self))->self;
    sshQ_ServerSession sess = ((example_serverQ_L_37proc)(L_self))->sess;
    return (($R (*) ($WORD, $Cont, sshQ_ServerSession))((example_serverQ_main)(self))->$class->on_channel_openG_local)(self, C_cont, sess);
}
$R example_serverQ_L_37procD___exec__ (example_serverQ_L_37proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((example_serverQ_L_37proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void example_serverQ_L_37procD___serialize__ (example_serverQ_L_37proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->sess, state);
}
example_serverQ_L_37proc example_serverQ_L_37procD___deserialize__ (example_serverQ_L_37proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct example_serverQ_L_37proc));
            self->$class = &example_serverQ_L_37procG_methods;
            return self;
        }
        self = $DNEW(example_serverQ_L_37proc, state);
    }
    self->self = $step_deserialize(state);
    self->sess = $step_deserialize(state);
    return self;
}
example_serverQ_L_37proc example_serverQ_L_37procG_new(example_serverQ_main G_1, sshQ_ServerSession G_2) {
    example_serverQ_L_37proc $tmp = acton_malloc(sizeof(struct example_serverQ_L_37proc));
    $tmp->$class = &example_serverQ_L_37procG_methods;
    example_serverQ_L_37procG_methods.__init__($tmp, G_1, G_2);
    return $tmp;
}
struct example_serverQ_L_37procG_class example_serverQ_L_37procG_methods;
B_NoneType example_serverQ_L_38procD___init__ (example_serverQ_L_38proc L_self, example_serverQ_main self, sshQ_ServerSession sess, sshQ_ServerChannel ch, B_str cmd) {
    ((example_serverQ_L_38proc)(L_self))->self = self;
    ((example_serverQ_L_38proc)(L_self))->sess = sess;
    ((example_serverQ_L_38proc)(L_self))->ch = ch;
    ((example_serverQ_L_38proc)(L_self))->cmd = cmd;
    return B_None;
}
$R example_serverQ_L_38procD___call__ (example_serverQ_L_38proc L_self, $Cont C_cont) {
    example_serverQ_main self = ((example_serverQ_L_38proc)(L_self))->self;
    sshQ_ServerSession sess = ((example_serverQ_L_38proc)(L_self))->sess;
    sshQ_ServerChannel ch = ((example_serverQ_L_38proc)(L_self))->ch;
    B_str cmd = ((example_serverQ_L_38proc)(L_self))->cmd;
    return (($R (*) ($WORD, $Cont, sshQ_ServerSession, sshQ_ServerChannel, B_str))((example_serverQ_main)(self))->$class->on_execG_local)(self, C_cont, sess, ch, cmd);
}
$R example_serverQ_L_38procD___exec__ (example_serverQ_L_38proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((example_serverQ_L_38proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void example_serverQ_L_38procD___serialize__ (example_serverQ_L_38proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->sess, state);
    $step_serialize(self->ch, state);
    $step_serialize(self->cmd, state);
}
example_serverQ_L_38proc example_serverQ_L_38procD___deserialize__ (example_serverQ_L_38proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct example_serverQ_L_38proc));
            self->$class = &example_serverQ_L_38procG_methods;
            return self;
        }
        self = $DNEW(example_serverQ_L_38proc, state);
    }
    self->self = $step_deserialize(state);
    self->sess = $step_deserialize(state);
    self->ch = $step_deserialize(state);
    self->cmd = $step_deserialize(state);
    return self;
}
example_serverQ_L_38proc example_serverQ_L_38procG_new(example_serverQ_main G_1, sshQ_ServerSession G_2, sshQ_ServerChannel G_3, B_str G_4) {
    example_serverQ_L_38proc $tmp = acton_malloc(sizeof(struct example_serverQ_L_38proc));
    $tmp->$class = &example_serverQ_L_38procG_methods;
    example_serverQ_L_38procG_methods.__init__($tmp, G_1, G_2, G_3, G_4);
    return $tmp;
}
struct example_serverQ_L_38procG_class example_serverQ_L_38procG_methods;
$R example_serverQ_L_39C_10cont ($Cont C_cont, example_serverQ_main G_act, B_NoneType C_11res) {
    return $R_CONT(C_cont, G_act);
}
B_NoneType example_serverQ_L_40ContD___init__ (example_serverQ_L_40Cont L_self, $Cont C_cont, example_serverQ_main G_act) {
    ((example_serverQ_L_40Cont)(L_self))->C_cont = C_cont;
    ((example_serverQ_L_40Cont)(L_self))->G_act = G_act;
    return B_None;
}
$R example_serverQ_L_40ContD___call__ (example_serverQ_L_40Cont L_self, B_NoneType G_1) {
    $Cont C_cont = ((example_serverQ_L_40Cont)(L_self))->C_cont;
    example_serverQ_main G_act = ((example_serverQ_L_40Cont)(L_self))->G_act;
    return example_serverQ_L_39C_10cont(C_cont, G_act, G_1);
}
void example_serverQ_L_40ContD___serialize__ (example_serverQ_L_40Cont self, $Serial$state state) {
    $step_serialize(self->C_cont, state);
    $step_serialize(self->G_act, state);
}
example_serverQ_L_40Cont example_serverQ_L_40ContD___deserialize__ (example_serverQ_L_40Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct example_serverQ_L_40Cont));
            self->$class = &example_serverQ_L_40ContG_methods;
            return self;
        }
        self = $DNEW(example_serverQ_L_40Cont, state);
    }
    self->C_cont = $step_deserialize(state);
    self->G_act = $step_deserialize(state);
    return self;
}
example_serverQ_L_40Cont example_serverQ_L_40ContG_new($Cont G_1, example_serverQ_main G_2) {
    example_serverQ_L_40Cont $tmp = acton_malloc(sizeof(struct example_serverQ_L_40Cont));
    $tmp->$class = &example_serverQ_L_40ContG_methods;
    example_serverQ_L_40ContG_methods.__init__($tmp, G_1, G_2);
    return $tmp;
}
struct example_serverQ_L_40ContG_class example_serverQ_L_40ContG_methods;
B_NoneType example_serverQ_L_41procD___init__ (example_serverQ_L_41proc L_self, example_serverQ_main G_act, B_Env env) {
    ((example_serverQ_L_41proc)(L_self))->G_act = G_act;
    ((example_serverQ_L_41proc)(L_self))->env = env;
    return B_None;
}
$R example_serverQ_L_41procD___call__ (example_serverQ_L_41proc L_self, $Cont C_cont) {
    example_serverQ_main G_act = ((example_serverQ_L_41proc)(L_self))->G_act;
    B_Env env = ((example_serverQ_L_41proc)(L_self))->env;
    return (($R (*) ($WORD, $Cont, B_Env))((example_serverQ_main)(G_act))->$class->__init__)(G_act, C_cont, env);
}
$R example_serverQ_L_41procD___exec__ (example_serverQ_L_41proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((example_serverQ_L_41proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void example_serverQ_L_41procD___serialize__ (example_serverQ_L_41proc self, $Serial$state state) {
    $step_serialize(self->G_act, state);
    $step_serialize(self->env, state);
}
example_serverQ_L_41proc example_serverQ_L_41procD___deserialize__ (example_serverQ_L_41proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct example_serverQ_L_41proc));
            self->$class = &example_serverQ_L_41procG_methods;
            return self;
        }
        self = $DNEW(example_serverQ_L_41proc, state);
    }
    self->G_act = $step_deserialize(state);
    self->env = $step_deserialize(state);
    return self;
}
example_serverQ_L_41proc example_serverQ_L_41procG_new(example_serverQ_main G_1, B_Env G_2) {
    example_serverQ_L_41proc $tmp = acton_malloc(sizeof(struct example_serverQ_L_41proc));
    $tmp->$class = &example_serverQ_L_41procG_methods;
    example_serverQ_L_41procG_methods.__init__($tmp, G_1, G_2);
    return $tmp;
}
struct example_serverQ_L_41procG_class example_serverQ_L_41procG_methods;
$R example_serverQ_mainD___init__ (example_serverQ_main self, $Cont C_cont, B_Env env) {
    ((example_serverQ_main)(self))->env = env;
    #line 24 "src/example_server.act"
    ((example_serverQ_main)(self))->port = (((((int64_t (*) (B_Collection, B_list))B_len)(example_serverQ_W_main_20, ((B_Env)(((example_serverQ_main)(self))->env))->argv) > 1LL)) ? B_u16G_new(((B_atom)toB_int(B_intG_new(((B_atom)$listD_U__getitem__(((B_Env)(((example_serverQ_main)(self))->env))->argv, 1LL)), B_None))), B_None) : B_u16G_new(((B_atom)toB_int(2222LL)), B_None));
    #line 25 "src/example_server.act"
    ((example_serverQ_main)(self))->user = (((((int64_t (*) (B_Collection, B_list))B_len)(example_serverQ_W_main_20, ((B_Env)(((example_serverQ_main)(self))->env))->argv) > 2LL)) ? $listD_U__getitem__(((B_Env)(((example_serverQ_main)(self))->env))->argv, 2LL) : to$str("demo"));
    #line 26 "src/example_server.act"
    ((example_serverQ_main)(self))->password = (((((int64_t (*) (B_Collection, B_list))B_len)(example_serverQ_W_main_20, ((B_Env)(((example_serverQ_main)(self))->env))->argv) > 3LL)) ? $listD_U__getitem__(((B_Env)(((example_serverQ_main)(self))->env))->argv, 3LL) : to$str("demo"));
    #line 28 "src/example_server.act"
    ((example_serverQ_main)(self))->server = B_None;
    return sshQ_ServerG_newact((($Cont)example_serverQ_L_2ContG_new(self, C_cont)), netQ_TCPListenCapG_new(netQ_TCPCapG_new(netQ_NetCapG_new(((B_Env)(((example_serverQ_main)(self))->env))->cap))), to$str("127.0.0.1"), ((uint16_t)((example_serverQ_main)(self))->port), (($action)example_serverQ_L_4actionG_new(self)), (($action)example_serverQ_L_6actionG_new(self)), (($action)example_serverQ_L_8actionG_new(self)), (($action)example_serverQ_L_10actionG_new(self)), (($action)example_serverQ_L_12actionG_new(self)), (($action)example_serverQ_L_14actionG_new(self)), B_None, (($action)example_serverQ_L_16actionG_new(self)), B_None, B_None, B_None, B_None, B_None, B_None, B_None, B_None, B_None, B_None);
}
#line 30 "src/example_server.act"
$R example_serverQ_mainD_on_listenG_local (example_serverQ_main self, $Cont C_cont, sshQ_Server s, B_str err) {
    if ($ISNOTNONE0(err)) {
        #line 32 "src/example_server.act"
        ((B_NoneType (*) (B_tuple, B_str, B_str, B_bool, B_bool))B_print)($NEWTUPLE(2, to$str("listen error:"), ((B_str)err)), B_None, B_None, B_None, B_None);
        #line 33 "src/example_server.act"
        ((B_Msg (*) ($WORD, int64_t))((B_Env)(((example_serverQ_main)(self))->env))->$class->exit)(((example_serverQ_main)(self))->env, 1LL);
        return $R_CONT(C_cont, B_None);
    }
    else {
        return $R_CONT((($Cont)example_serverQ_L_20ContG_new(self, C_cont, s)), B_None);
    }
}
#line 38 "src/example_server.act"
$R example_serverQ_mainD_on_server_closeG_local (example_serverQ_main self, $Cont C_cont, sshQ_Server s, B_str reason) {
    #line 39 "src/example_server.act"
    ((B_NoneType (*) (B_tuple, B_str, B_str, B_bool, B_bool))B_print)($NEWTUPLE(2, to$str("server closed:"), reason), B_None, B_None, B_None, B_None);
    #line 40 "src/example_server.act"
    ((B_Msg (*) ($WORD, int64_t))((B_Env)(((example_serverQ_main)(self))->env))->$class->exit)(((example_serverQ_main)(self))->env, 0LL);
    return $R_CONT(C_cont, B_None);
}
#line 42 "src/example_server.act"
$R example_serverQ_mainD_on_sessionG_local (example_serverQ_main self, $Cont C_cont, sshQ_ServerSession sess) {
    #line 43 "src/example_server.act"
    ((B_NoneType (*) (B_tuple, B_str, B_str, B_bool, B_bool))B_print)($NEWTUPLE(1, to$str("session established")), B_None, B_None, B_None, B_None);
    return $R_CONT(C_cont, B_None);
}
#line 45 "src/example_server.act"
$R example_serverQ_mainD_on_session_closeG_local (example_serverQ_main self, $Cont C_cont, sshQ_ServerSession sess, B_str reason) {
    #line 46 "src/example_server.act"
    ((B_NoneType (*) (B_tuple, B_str, B_str, B_bool, B_bool))B_print)($NEWTUPLE(2, to$str("session closed:"), reason), B_None, B_None, B_None, B_None);
    return $R_CONT(C_cont, B_None);
}
#line 48 "src/example_server.act"
$R example_serverQ_mainD_on_authG_local (example_serverQ_main self, $Cont C_cont, sshQ_ServerSession sess, sshQ_AuthRequest req) {
    B_Eq W_main_406 = ((B_Eq)$EqOptG_new(example_serverQ_W_main_489));
    #line 52 "src/example_server.act"
    if (((B_bool)$AND(B_bool, $AND(B_bool, ((B_bool (*) ($WORD, B_str, B_str))((B_Eq)(example_serverQ_W_main_489))->$class->__eq__)(example_serverQ_W_main_489, ((sshQ_AuthRequest)(req))->method, to$str("password")), ((B_bool (*) ($WORD, B_str, B_str))((B_Eq)(example_serverQ_W_main_489))->$class->__eq__)(example_serverQ_W_main_489, ((sshQ_AuthRequest)(req))->user, ((example_serverQ_main)(self))->user)), ((B_bool (*) ($WORD, B_str, B_str))((B_Eq)(W_main_406))->$class->__eq__)(W_main_406, ((sshQ_AuthRequest)(req))->password, ((example_serverQ_main)(self))->password)))->val) {
        #line 53 "src/example_server.act"
        ((B_NoneType (*) (B_tuple, B_str, B_str, B_bool, B_bool))B_print)($NEWTUPLE(2, to$str("auth ok for"), ((sshQ_AuthRequest)(req))->user), B_None, B_None, B_None, B_None);
        #line 54 "src/example_server.act"
        ((B_Msg (*) ($WORD))((sshQ_ServerSession)(sess))->$class->accept_auth)(sess);
    }
    else {
        #line 56 "src/example_server.act"
        ((B_NoneType (*) (B_tuple, B_str, B_str, B_bool, B_bool))B_print)($NEWTUPLE(3, to$str("auth rejected for"), ((sshQ_AuthRequest)(req))->user, ((B_str (*) ($WORD, B_str, B_str))((B_Plus)(example_serverQ_W_main_268))->$class->__add__)(example_serverQ_W_main_268, ((B_str (*) ($WORD, B_str, B_str))((B_Plus)(example_serverQ_W_main_268))->$class->__add__)(example_serverQ_W_main_268, to$str("("), ((sshQ_AuthRequest)(req))->method), to$str(")"))), B_None, B_None, B_None, B_None);
        #line 57 "src/example_server.act"
        ((B_Msg (*) ($WORD, B_str))((sshQ_ServerSession)(sess))->$class->reject_auth)(sess, to$str("denied"));
    }
    return $R_CONT(C_cont, B_None);
}
#line 59 "src/example_server.act"
$R example_serverQ_mainD_srv_on_dataG_local (example_serverQ_main self, $Cont C_cont, sshQ_ServerChannel ch, B_bytes data) {
    #line 60 "src/example_server.act"
    return $R_CONT(C_cont, B_None);
}
#line 62 "src/example_server.act"
$R example_serverQ_mainD_srv_on_stderrG_local (example_serverQ_main self, $Cont C_cont, sshQ_ServerChannel ch, B_bytes data) {
    #line 63 "src/example_server.act"
    return $R_CONT(C_cont, B_None);
}
#line 65 "src/example_server.act"
$R example_serverQ_mainD_srv_on_closeG_local (example_serverQ_main self, $Cont C_cont, sshQ_ServerChannel ch, B_str reason) {
    #line 66 "src/example_server.act"
    return $R_CONT(C_cont, B_None);
}
#line 68 "src/example_server.act"
$R example_serverQ_mainD_on_channel_openG_local (example_serverQ_main self, $Cont C_cont, sshQ_ServerSession sess) {
    return sshQ_ServerChannelG_newact((($Cont)example_serverQ_L_22ContG_new(sess, C_cont)), sess, (($action)example_serverQ_L_24actionG_new(self)), (($action)example_serverQ_L_26actionG_new(self)), (($action)example_serverQ_L_28actionG_new(self)));
}
#line 71 "src/example_server.act"
$R example_serverQ_mainD_on_execG_local (example_serverQ_main self, $Cont C_cont, sshQ_ServerSession sess, sshQ_ServerChannel ch, B_str cmd) {
    #line 72 "src/example_server.act"
    ((B_NoneType (*) (B_tuple, B_str, B_str, B_bool, B_bool))B_print)($NEWTUPLE(2, to$str("exec:"), cmd), B_None, B_None, B_None, B_None);
    #line 73 "src/example_server.act"
    ((B_Msg (*) ($WORD))((sshQ_ServerChannel)(ch))->$class->accept_request)(ch);
    #line 74 "src/example_server.act"
    ((B_Msg (*) ($WORD, B_bytes))((sshQ_ServerChannel)(ch))->$class->write)(ch, ({ B_str $tmp = ((B_str (*) ($WORD, B_str, B_str))((B_Plus)(example_serverQ_W_main_268))->$class->__add__)(example_serverQ_W_main_268, ((B_str (*) ($WORD, B_str, B_str))((B_Plus)(example_serverQ_W_main_268))->$class->__add__)(example_serverQ_W_main_268, to$str("you ran: "), cmd), to$str("\n"));
                                                                                   ((B_bytes (*) ($WORD))((B_str)($tmp))->$class->encode)($tmp); }));
    #line 75 "src/example_server.act"
    ((B_Msg (*) ($WORD, int64_t))((sshQ_ServerChannel)(ch))->$class->send_exit_status)(ch, 0LL);
    #line 76 "src/example_server.act"
    ((B_Msg (*) ($WORD))((sshQ_ServerChannel)(ch))->$class->close)(ch);
    return $R_CONT(C_cont, B_None);
}
B_Msg example_serverQ_mainD_on_listen (example_serverQ_main self, sshQ_Server s, B_str err) {
    return $ASYNC((($Actor)self), (($Cont)example_serverQ_L_29procG_new(self, s, err)));
}
B_Msg example_serverQ_mainD_on_server_close (example_serverQ_main self, sshQ_Server s, B_str reason) {
    return $ASYNC((($Actor)self), (($Cont)example_serverQ_L_30procG_new(self, s, reason)));
}
B_Msg example_serverQ_mainD_on_session (example_serverQ_main self, sshQ_ServerSession sess) {
    return $ASYNC((($Actor)self), (($Cont)example_serverQ_L_31procG_new(self, sess)));
}
B_Msg example_serverQ_mainD_on_session_close (example_serverQ_main self, sshQ_ServerSession sess, B_str reason) {
    return $ASYNC((($Actor)self), (($Cont)example_serverQ_L_32procG_new(self, sess, reason)));
}
B_Msg example_serverQ_mainD_on_auth (example_serverQ_main self, sshQ_ServerSession sess, sshQ_AuthRequest req) {
    return $ASYNC((($Actor)self), (($Cont)example_serverQ_L_33procG_new(self, sess, req)));
}
B_Msg example_serverQ_mainD_srv_on_data (example_serverQ_main self, sshQ_ServerChannel ch, B_bytes data) {
    return $ASYNC((($Actor)self), (($Cont)example_serverQ_L_34procG_new(self, ch, data)));
}
B_Msg example_serverQ_mainD_srv_on_stderr (example_serverQ_main self, sshQ_ServerChannel ch, B_bytes data) {
    return $ASYNC((($Actor)self), (($Cont)example_serverQ_L_35procG_new(self, ch, data)));
}
B_Msg example_serverQ_mainD_srv_on_close (example_serverQ_main self, sshQ_ServerChannel ch, B_str reason) {
    return $ASYNC((($Actor)self), (($Cont)example_serverQ_L_36procG_new(self, ch, reason)));
}
B_Msg example_serverQ_mainD_on_channel_open (example_serverQ_main self, sshQ_ServerSession sess) {
    return $ASYNC((($Actor)self), (($Cont)example_serverQ_L_37procG_new(self, sess)));
}
B_Msg example_serverQ_mainD_on_exec (example_serverQ_main self, sshQ_ServerSession sess, sshQ_ServerChannel ch, B_str cmd) {
    return $ASYNC((($Actor)self), (($Cont)example_serverQ_L_38procG_new(self, sess, ch, cmd)));
}
void example_serverQ_mainD___serialize__ (example_serverQ_main self, $Serial$state state) {
    $ActorG_methods.__serialize__(($Actor)self, state);
    $step_serialize(self->env, state);
    $val_serialize(U16_ID, &self->port, state);
    $step_serialize(self->user, state);
    $step_serialize(self->password, state);
    $step_serialize(self->server, state);
}
example_serverQ_main example_serverQ_mainD___deserialize__ (example_serverQ_main self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct example_serverQ_main));
            self->$class = &example_serverQ_mainG_methods;
            return self;
        }
        self = $DNEW(example_serverQ_main, state);
    }
    $ActorG_methods.__deserialize__(($Actor)self, state);
    self->env = $step_deserialize(state);
    $tmp = $val_deserialize(state);
    memcpy(&self->port, &$tmp, sizeof(self->port));
    self->user = $step_deserialize(state);
    self->password = $step_deserialize(state);
    self->server = $step_deserialize(state);
    return self;
}
void example_serverQ_mainD_GCfinalizer (void *obj, void *cdata) {
    example_serverQ_main self = (example_serverQ_main)obj;
    self->$class->__cleanup__(self);
}
$R example_serverQ_mainG_new($Cont G_1, B_Env G_2) {
    example_serverQ_main $tmp = acton_malloc(sizeof(struct example_serverQ_main));
    $tmp->$class = &example_serverQ_mainG_methods;
    return example_serverQ_mainG_methods.__init__($tmp, $CONSTCONT($tmp, G_1), G_2);
}
struct example_serverQ_mainG_class example_serverQ_mainG_methods;
$R example_serverQ_mainG_newact ($Cont C_cont, B_Env env) {
    example_serverQ_main G_act = $NEWACTOR(example_serverQ_main);
    if ((void*)G_act->$class->__cleanup__ != (void*)$ActorD___cleanup__) $InstallFinalizer(G_act, example_serverQ_mainD_GCfinalizer);
    return $AWAIT((($Cont)example_serverQ_L_40ContG_new(C_cont, G_act)), $ASYNC((($Actor)G_act), (($Cont)example_serverQ_L_41procG_new(G_act, env))));
}
int example_serverQ_done$ = 0;
void example_serverQ___init__ () {
    if (example_serverQ_done$) return;
    example_serverQ_done$ = 1;
    netQ___init__();
    sshQ___init__();
    {
        example_serverQ_L_2ContG_methods.$GCINFO = "example_serverQ_L_2Cont";
        example_serverQ_L_2ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        example_serverQ_L_2ContG_methods.__bool__ = (B_bool (*) (example_serverQ_L_2Cont))B_valueG_methods.__bool__;
        example_serverQ_L_2ContG_methods.__str__ = (B_str (*) (example_serverQ_L_2Cont))B_valueG_methods.__str__;
        example_serverQ_L_2ContG_methods.__repr__ = (B_str (*) (example_serverQ_L_2Cont))B_valueG_methods.__repr__;
        example_serverQ_L_2ContG_methods.__init__ = (B_NoneType (*) (example_serverQ_L_2Cont, example_serverQ_main, $Cont))example_serverQ_L_2ContD___init__;
        example_serverQ_L_2ContG_methods.__call__ = ($R (*) (example_serverQ_L_2Cont, sshQ_Server))example_serverQ_L_2ContD___call__;
        example_serverQ_L_2ContG_methods.__serialize__ = example_serverQ_L_2ContD___serialize__;
        example_serverQ_L_2ContG_methods.__deserialize__ = example_serverQ_L_2ContD___deserialize__;
        $register(&example_serverQ_L_2ContG_methods);
    }
    {
        example_serverQ_L_4actionG_methods.$GCINFO = "example_serverQ_L_4action";
        example_serverQ_L_4actionG_methods.$superclass = ($SuperG_class)&$actionG_methods;
        example_serverQ_L_4actionG_methods.__bool__ = (B_bool (*) (example_serverQ_L_4action))B_valueG_methods.__bool__;
        example_serverQ_L_4actionG_methods.__str__ = (B_str (*) (example_serverQ_L_4action))B_valueG_methods.__str__;
        example_serverQ_L_4actionG_methods.__repr__ = (B_str (*) (example_serverQ_L_4action))B_valueG_methods.__repr__;
        example_serverQ_L_4actionG_methods.__init__ = (B_NoneType (*) (example_serverQ_L_4action, example_serverQ_main))example_serverQ_L_4actionD___init__;
        example_serverQ_L_4actionG_methods.__call__ = ($R (*) (example_serverQ_L_4action, $Cont, sshQ_Server, B_str))example_serverQ_L_4actionD___call__;
        example_serverQ_L_4actionG_methods.__exec__ = ($R (*) (example_serverQ_L_4action, $Cont, sshQ_Server, B_str))example_serverQ_L_4actionD___exec__;
        example_serverQ_L_4actionG_methods.__asyn__ = (B_Msg (*) (example_serverQ_L_4action, sshQ_Server, B_str))example_serverQ_L_4actionD___asyn__;
        example_serverQ_L_4actionG_methods.__serialize__ = example_serverQ_L_4actionD___serialize__;
        example_serverQ_L_4actionG_methods.__deserialize__ = example_serverQ_L_4actionD___deserialize__;
        $register(&example_serverQ_L_4actionG_methods);
    }
    {
        example_serverQ_L_6actionG_methods.$GCINFO = "example_serverQ_L_6action";
        example_serverQ_L_6actionG_methods.$superclass = ($SuperG_class)&$actionG_methods;
        example_serverQ_L_6actionG_methods.__bool__ = (B_bool (*) (example_serverQ_L_6action))B_valueG_methods.__bool__;
        example_serverQ_L_6actionG_methods.__str__ = (B_str (*) (example_serverQ_L_6action))B_valueG_methods.__str__;
        example_serverQ_L_6actionG_methods.__repr__ = (B_str (*) (example_serverQ_L_6action))B_valueG_methods.__repr__;
        example_serverQ_L_6actionG_methods.__init__ = (B_NoneType (*) (example_serverQ_L_6action, example_serverQ_main))example_serverQ_L_6actionD___init__;
        example_serverQ_L_6actionG_methods.__call__ = ($R (*) (example_serverQ_L_6action, $Cont, sshQ_Server, B_str))example_serverQ_L_6actionD___call__;
        example_serverQ_L_6actionG_methods.__exec__ = ($R (*) (example_serverQ_L_6action, $Cont, sshQ_Server, B_str))example_serverQ_L_6actionD___exec__;
        example_serverQ_L_6actionG_methods.__asyn__ = (B_Msg (*) (example_serverQ_L_6action, sshQ_Server, B_str))example_serverQ_L_6actionD___asyn__;
        example_serverQ_L_6actionG_methods.__serialize__ = example_serverQ_L_6actionD___serialize__;
        example_serverQ_L_6actionG_methods.__deserialize__ = example_serverQ_L_6actionD___deserialize__;
        $register(&example_serverQ_L_6actionG_methods);
    }
    {
        example_serverQ_L_8actionG_methods.$GCINFO = "example_serverQ_L_8action";
        example_serverQ_L_8actionG_methods.$superclass = ($SuperG_class)&$actionG_methods;
        example_serverQ_L_8actionG_methods.__bool__ = (B_bool (*) (example_serverQ_L_8action))B_valueG_methods.__bool__;
        example_serverQ_L_8actionG_methods.__str__ = (B_str (*) (example_serverQ_L_8action))B_valueG_methods.__str__;
        example_serverQ_L_8actionG_methods.__repr__ = (B_str (*) (example_serverQ_L_8action))B_valueG_methods.__repr__;
        example_serverQ_L_8actionG_methods.__init__ = (B_NoneType (*) (example_serverQ_L_8action, example_serverQ_main))example_serverQ_L_8actionD___init__;
        example_serverQ_L_8actionG_methods.__call__ = ($R (*) (example_serverQ_L_8action, $Cont, sshQ_ServerSession))example_serverQ_L_8actionD___call__;
        example_serverQ_L_8actionG_methods.__exec__ = ($R (*) (example_serverQ_L_8action, $Cont, sshQ_ServerSession))example_serverQ_L_8actionD___exec__;
        example_serverQ_L_8actionG_methods.__asyn__ = (B_Msg (*) (example_serverQ_L_8action, sshQ_ServerSession))example_serverQ_L_8actionD___asyn__;
        example_serverQ_L_8actionG_methods.__serialize__ = example_serverQ_L_8actionD___serialize__;
        example_serverQ_L_8actionG_methods.__deserialize__ = example_serverQ_L_8actionD___deserialize__;
        $register(&example_serverQ_L_8actionG_methods);
    }
    {
        example_serverQ_L_10actionG_methods.$GCINFO = "example_serverQ_L_10action";
        example_serverQ_L_10actionG_methods.$superclass = ($SuperG_class)&$actionG_methods;
        example_serverQ_L_10actionG_methods.__bool__ = (B_bool (*) (example_serverQ_L_10action))B_valueG_methods.__bool__;
        example_serverQ_L_10actionG_methods.__str__ = (B_str (*) (example_serverQ_L_10action))B_valueG_methods.__str__;
        example_serverQ_L_10actionG_methods.__repr__ = (B_str (*) (example_serverQ_L_10action))B_valueG_methods.__repr__;
        example_serverQ_L_10actionG_methods.__init__ = (B_NoneType (*) (example_serverQ_L_10action, example_serverQ_main))example_serverQ_L_10actionD___init__;
        example_serverQ_L_10actionG_methods.__call__ = ($R (*) (example_serverQ_L_10action, $Cont, sshQ_ServerSession, sshQ_AuthRequest))example_serverQ_L_10actionD___call__;
        example_serverQ_L_10actionG_methods.__exec__ = ($R (*) (example_serverQ_L_10action, $Cont, sshQ_ServerSession, sshQ_AuthRequest))example_serverQ_L_10actionD___exec__;
        example_serverQ_L_10actionG_methods.__asyn__ = (B_Msg (*) (example_serverQ_L_10action, sshQ_ServerSession, sshQ_AuthRequest))example_serverQ_L_10actionD___asyn__;
        example_serverQ_L_10actionG_methods.__serialize__ = example_serverQ_L_10actionD___serialize__;
        example_serverQ_L_10actionG_methods.__deserialize__ = example_serverQ_L_10actionD___deserialize__;
        $register(&example_serverQ_L_10actionG_methods);
    }
    {
        example_serverQ_L_12actionG_methods.$GCINFO = "example_serverQ_L_12action";
        example_serverQ_L_12actionG_methods.$superclass = ($SuperG_class)&$actionG_methods;
        example_serverQ_L_12actionG_methods.__bool__ = (B_bool (*) (example_serverQ_L_12action))B_valueG_methods.__bool__;
        example_serverQ_L_12actionG_methods.__str__ = (B_str (*) (example_serverQ_L_12action))B_valueG_methods.__str__;
        example_serverQ_L_12actionG_methods.__repr__ = (B_str (*) (example_serverQ_L_12action))B_valueG_methods.__repr__;
        example_serverQ_L_12actionG_methods.__init__ = (B_NoneType (*) (example_serverQ_L_12action, example_serverQ_main))example_serverQ_L_12actionD___init__;
        example_serverQ_L_12actionG_methods.__call__ = ($R (*) (example_serverQ_L_12action, $Cont, sshQ_ServerSession))example_serverQ_L_12actionD___call__;
        example_serverQ_L_12actionG_methods.__exec__ = ($R (*) (example_serverQ_L_12action, $Cont, sshQ_ServerSession))example_serverQ_L_12actionD___exec__;
        example_serverQ_L_12actionG_methods.__asyn__ = (B_Msg (*) (example_serverQ_L_12action, sshQ_ServerSession))example_serverQ_L_12actionD___asyn__;
        example_serverQ_L_12actionG_methods.__serialize__ = example_serverQ_L_12actionD___serialize__;
        example_serverQ_L_12actionG_methods.__deserialize__ = example_serverQ_L_12actionD___deserialize__;
        $register(&example_serverQ_L_12actionG_methods);
    }
    {
        example_serverQ_L_14actionG_methods.$GCINFO = "example_serverQ_L_14action";
        example_serverQ_L_14actionG_methods.$superclass = ($SuperG_class)&$actionG_methods;
        example_serverQ_L_14actionG_methods.__bool__ = (B_bool (*) (example_serverQ_L_14action))B_valueG_methods.__bool__;
        example_serverQ_L_14actionG_methods.__str__ = (B_str (*) (example_serverQ_L_14action))B_valueG_methods.__str__;
        example_serverQ_L_14actionG_methods.__repr__ = (B_str (*) (example_serverQ_L_14action))B_valueG_methods.__repr__;
        example_serverQ_L_14actionG_methods.__init__ = (B_NoneType (*) (example_serverQ_L_14action, example_serverQ_main))example_serverQ_L_14actionD___init__;
        example_serverQ_L_14actionG_methods.__call__ = ($R (*) (example_serverQ_L_14action, $Cont, sshQ_ServerSession, sshQ_ServerChannel, B_str))example_serverQ_L_14actionD___call__;
        example_serverQ_L_14actionG_methods.__exec__ = ($R (*) (example_serverQ_L_14action, $Cont, sshQ_ServerSession, sshQ_ServerChannel, B_str))example_serverQ_L_14actionD___exec__;
        example_serverQ_L_14actionG_methods.__asyn__ = (B_Msg (*) (example_serverQ_L_14action, sshQ_ServerSession, sshQ_ServerChannel, B_str))example_serverQ_L_14actionD___asyn__;
        example_serverQ_L_14actionG_methods.__serialize__ = example_serverQ_L_14actionD___serialize__;
        example_serverQ_L_14actionG_methods.__deserialize__ = example_serverQ_L_14actionD___deserialize__;
        $register(&example_serverQ_L_14actionG_methods);
    }
    {
        example_serverQ_L_16actionG_methods.$GCINFO = "example_serverQ_L_16action";
        example_serverQ_L_16actionG_methods.$superclass = ($SuperG_class)&$actionG_methods;
        example_serverQ_L_16actionG_methods.__bool__ = (B_bool (*) (example_serverQ_L_16action))B_valueG_methods.__bool__;
        example_serverQ_L_16actionG_methods.__str__ = (B_str (*) (example_serverQ_L_16action))B_valueG_methods.__str__;
        example_serverQ_L_16actionG_methods.__repr__ = (B_str (*) (example_serverQ_L_16action))B_valueG_methods.__repr__;
        example_serverQ_L_16actionG_methods.__init__ = (B_NoneType (*) (example_serverQ_L_16action, example_serverQ_main))example_serverQ_L_16actionD___init__;
        example_serverQ_L_16actionG_methods.__call__ = ($R (*) (example_serverQ_L_16action, $Cont, sshQ_ServerSession, B_str))example_serverQ_L_16actionD___call__;
        example_serverQ_L_16actionG_methods.__exec__ = ($R (*) (example_serverQ_L_16action, $Cont, sshQ_ServerSession, B_str))example_serverQ_L_16actionD___exec__;
        example_serverQ_L_16actionG_methods.__asyn__ = (B_Msg (*) (example_serverQ_L_16action, sshQ_ServerSession, B_str))example_serverQ_L_16actionD___asyn__;
        example_serverQ_L_16actionG_methods.__serialize__ = example_serverQ_L_16actionD___serialize__;
        example_serverQ_L_16actionG_methods.__deserialize__ = example_serverQ_L_16actionD___deserialize__;
        $register(&example_serverQ_L_16actionG_methods);
    }
    {
        example_serverQ_L_19ContG_methods.$GCINFO = "example_serverQ_L_19Cont";
        example_serverQ_L_19ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        example_serverQ_L_19ContG_methods.__bool__ = (B_bool (*) (example_serverQ_L_19Cont))B_valueG_methods.__bool__;
        example_serverQ_L_19ContG_methods.__str__ = (B_str (*) (example_serverQ_L_19Cont))B_valueG_methods.__str__;
        example_serverQ_L_19ContG_methods.__repr__ = (B_str (*) (example_serverQ_L_19Cont))B_valueG_methods.__repr__;
        example_serverQ_L_19ContG_methods.__init__ = (B_NoneType (*) (example_serverQ_L_19Cont, example_serverQ_main, $Cont))example_serverQ_L_19ContD___init__;
        example_serverQ_L_19ContG_methods.__call__ = ($R (*) (example_serverQ_L_19Cont, B_u16))example_serverQ_L_19ContD___call__;
        example_serverQ_L_19ContG_methods.__serialize__ = example_serverQ_L_19ContD___serialize__;
        example_serverQ_L_19ContG_methods.__deserialize__ = example_serverQ_L_19ContD___deserialize__;
        $register(&example_serverQ_L_19ContG_methods);
    }
    {
        example_serverQ_L_20ContG_methods.$GCINFO = "example_serverQ_L_20Cont";
        example_serverQ_L_20ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        example_serverQ_L_20ContG_methods.__bool__ = (B_bool (*) (example_serverQ_L_20Cont))B_valueG_methods.__bool__;
        example_serverQ_L_20ContG_methods.__str__ = (B_str (*) (example_serverQ_L_20Cont))B_valueG_methods.__str__;
        example_serverQ_L_20ContG_methods.__repr__ = (B_str (*) (example_serverQ_L_20Cont))B_valueG_methods.__repr__;
        example_serverQ_L_20ContG_methods.__init__ = (B_NoneType (*) (example_serverQ_L_20Cont, example_serverQ_main, $Cont, sshQ_Server))example_serverQ_L_20ContD___init__;
        example_serverQ_L_20ContG_methods.__call__ = ($R (*) (example_serverQ_L_20Cont, B_NoneType))example_serverQ_L_20ContD___call__;
        example_serverQ_L_20ContG_methods.__serialize__ = example_serverQ_L_20ContD___serialize__;
        example_serverQ_L_20ContG_methods.__deserialize__ = example_serverQ_L_20ContD___deserialize__;
        $register(&example_serverQ_L_20ContG_methods);
    }
    {
        example_serverQ_L_22ContG_methods.$GCINFO = "example_serverQ_L_22Cont";
        example_serverQ_L_22ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        example_serverQ_L_22ContG_methods.__bool__ = (B_bool (*) (example_serverQ_L_22Cont))B_valueG_methods.__bool__;
        example_serverQ_L_22ContG_methods.__str__ = (B_str (*) (example_serverQ_L_22Cont))B_valueG_methods.__str__;
        example_serverQ_L_22ContG_methods.__repr__ = (B_str (*) (example_serverQ_L_22Cont))B_valueG_methods.__repr__;
        example_serverQ_L_22ContG_methods.__init__ = (B_NoneType (*) (example_serverQ_L_22Cont, sshQ_ServerSession, $Cont))example_serverQ_L_22ContD___init__;
        example_serverQ_L_22ContG_methods.__call__ = ($R (*) (example_serverQ_L_22Cont, sshQ_ServerChannel))example_serverQ_L_22ContD___call__;
        example_serverQ_L_22ContG_methods.__serialize__ = example_serverQ_L_22ContD___serialize__;
        example_serverQ_L_22ContG_methods.__deserialize__ = example_serverQ_L_22ContD___deserialize__;
        $register(&example_serverQ_L_22ContG_methods);
    }
    {
        example_serverQ_L_24actionG_methods.$GCINFO = "example_serverQ_L_24action";
        example_serverQ_L_24actionG_methods.$superclass = ($SuperG_class)&$actionG_methods;
        example_serverQ_L_24actionG_methods.__bool__ = (B_bool (*) (example_serverQ_L_24action))B_valueG_methods.__bool__;
        example_serverQ_L_24actionG_methods.__str__ = (B_str (*) (example_serverQ_L_24action))B_valueG_methods.__str__;
        example_serverQ_L_24actionG_methods.__repr__ = (B_str (*) (example_serverQ_L_24action))B_valueG_methods.__repr__;
        example_serverQ_L_24actionG_methods.__init__ = (B_NoneType (*) (example_serverQ_L_24action, example_serverQ_main))example_serverQ_L_24actionD___init__;
        example_serverQ_L_24actionG_methods.__call__ = ($R (*) (example_serverQ_L_24action, $Cont, sshQ_ServerChannel, B_bytes))example_serverQ_L_24actionD___call__;
        example_serverQ_L_24actionG_methods.__exec__ = ($R (*) (example_serverQ_L_24action, $Cont, sshQ_ServerChannel, B_bytes))example_serverQ_L_24actionD___exec__;
        example_serverQ_L_24actionG_methods.__asyn__ = (B_Msg (*) (example_serverQ_L_24action, sshQ_ServerChannel, B_bytes))example_serverQ_L_24actionD___asyn__;
        example_serverQ_L_24actionG_methods.__serialize__ = example_serverQ_L_24actionD___serialize__;
        example_serverQ_L_24actionG_methods.__deserialize__ = example_serverQ_L_24actionD___deserialize__;
        $register(&example_serverQ_L_24actionG_methods);
    }
    {
        example_serverQ_L_26actionG_methods.$GCINFO = "example_serverQ_L_26action";
        example_serverQ_L_26actionG_methods.$superclass = ($SuperG_class)&$actionG_methods;
        example_serverQ_L_26actionG_methods.__bool__ = (B_bool (*) (example_serverQ_L_26action))B_valueG_methods.__bool__;
        example_serverQ_L_26actionG_methods.__str__ = (B_str (*) (example_serverQ_L_26action))B_valueG_methods.__str__;
        example_serverQ_L_26actionG_methods.__repr__ = (B_str (*) (example_serverQ_L_26action))B_valueG_methods.__repr__;
        example_serverQ_L_26actionG_methods.__init__ = (B_NoneType (*) (example_serverQ_L_26action, example_serverQ_main))example_serverQ_L_26actionD___init__;
        example_serverQ_L_26actionG_methods.__call__ = ($R (*) (example_serverQ_L_26action, $Cont, sshQ_ServerChannel, B_bytes))example_serverQ_L_26actionD___call__;
        example_serverQ_L_26actionG_methods.__exec__ = ($R (*) (example_serverQ_L_26action, $Cont, sshQ_ServerChannel, B_bytes))example_serverQ_L_26actionD___exec__;
        example_serverQ_L_26actionG_methods.__asyn__ = (B_Msg (*) (example_serverQ_L_26action, sshQ_ServerChannel, B_bytes))example_serverQ_L_26actionD___asyn__;
        example_serverQ_L_26actionG_methods.__serialize__ = example_serverQ_L_26actionD___serialize__;
        example_serverQ_L_26actionG_methods.__deserialize__ = example_serverQ_L_26actionD___deserialize__;
        $register(&example_serverQ_L_26actionG_methods);
    }
    {
        example_serverQ_L_28actionG_methods.$GCINFO = "example_serverQ_L_28action";
        example_serverQ_L_28actionG_methods.$superclass = ($SuperG_class)&$actionG_methods;
        example_serverQ_L_28actionG_methods.__bool__ = (B_bool (*) (example_serverQ_L_28action))B_valueG_methods.__bool__;
        example_serverQ_L_28actionG_methods.__str__ = (B_str (*) (example_serverQ_L_28action))B_valueG_methods.__str__;
        example_serverQ_L_28actionG_methods.__repr__ = (B_str (*) (example_serverQ_L_28action))B_valueG_methods.__repr__;
        example_serverQ_L_28actionG_methods.__init__ = (B_NoneType (*) (example_serverQ_L_28action, example_serverQ_main))example_serverQ_L_28actionD___init__;
        example_serverQ_L_28actionG_methods.__call__ = ($R (*) (example_serverQ_L_28action, $Cont, sshQ_ServerChannel, B_str))example_serverQ_L_28actionD___call__;
        example_serverQ_L_28actionG_methods.__exec__ = ($R (*) (example_serverQ_L_28action, $Cont, sshQ_ServerChannel, B_str))example_serverQ_L_28actionD___exec__;
        example_serverQ_L_28actionG_methods.__asyn__ = (B_Msg (*) (example_serverQ_L_28action, sshQ_ServerChannel, B_str))example_serverQ_L_28actionD___asyn__;
        example_serverQ_L_28actionG_methods.__serialize__ = example_serverQ_L_28actionD___serialize__;
        example_serverQ_L_28actionG_methods.__deserialize__ = example_serverQ_L_28actionD___deserialize__;
        $register(&example_serverQ_L_28actionG_methods);
    }
    {
        example_serverQ_L_29procG_methods.$GCINFO = "example_serverQ_L_29proc";
        example_serverQ_L_29procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        example_serverQ_L_29procG_methods.__bool__ = (B_bool (*) (example_serverQ_L_29proc))B_valueG_methods.__bool__;
        example_serverQ_L_29procG_methods.__str__ = (B_str (*) (example_serverQ_L_29proc))B_valueG_methods.__str__;
        example_serverQ_L_29procG_methods.__repr__ = (B_str (*) (example_serverQ_L_29proc))B_valueG_methods.__repr__;
        example_serverQ_L_29procG_methods.__init__ = (B_NoneType (*) (example_serverQ_L_29proc, example_serverQ_main, sshQ_Server, B_str))example_serverQ_L_29procD___init__;
        example_serverQ_L_29procG_methods.__call__ = ($R (*) (example_serverQ_L_29proc, $Cont))example_serverQ_L_29procD___call__;
        example_serverQ_L_29procG_methods.__exec__ = ($R (*) (example_serverQ_L_29proc, $Cont))example_serverQ_L_29procD___exec__;
        example_serverQ_L_29procG_methods.__serialize__ = example_serverQ_L_29procD___serialize__;
        example_serverQ_L_29procG_methods.__deserialize__ = example_serverQ_L_29procD___deserialize__;
        $register(&example_serverQ_L_29procG_methods);
    }
    {
        example_serverQ_L_30procG_methods.$GCINFO = "example_serverQ_L_30proc";
        example_serverQ_L_30procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        example_serverQ_L_30procG_methods.__bool__ = (B_bool (*) (example_serverQ_L_30proc))B_valueG_methods.__bool__;
        example_serverQ_L_30procG_methods.__str__ = (B_str (*) (example_serverQ_L_30proc))B_valueG_methods.__str__;
        example_serverQ_L_30procG_methods.__repr__ = (B_str (*) (example_serverQ_L_30proc))B_valueG_methods.__repr__;
        example_serverQ_L_30procG_methods.__init__ = (B_NoneType (*) (example_serverQ_L_30proc, example_serverQ_main, sshQ_Server, B_str))example_serverQ_L_30procD___init__;
        example_serverQ_L_30procG_methods.__call__ = ($R (*) (example_serverQ_L_30proc, $Cont))example_serverQ_L_30procD___call__;
        example_serverQ_L_30procG_methods.__exec__ = ($R (*) (example_serverQ_L_30proc, $Cont))example_serverQ_L_30procD___exec__;
        example_serverQ_L_30procG_methods.__serialize__ = example_serverQ_L_30procD___serialize__;
        example_serverQ_L_30procG_methods.__deserialize__ = example_serverQ_L_30procD___deserialize__;
        $register(&example_serverQ_L_30procG_methods);
    }
    {
        example_serverQ_L_31procG_methods.$GCINFO = "example_serverQ_L_31proc";
        example_serverQ_L_31procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        example_serverQ_L_31procG_methods.__bool__ = (B_bool (*) (example_serverQ_L_31proc))B_valueG_methods.__bool__;
        example_serverQ_L_31procG_methods.__str__ = (B_str (*) (example_serverQ_L_31proc))B_valueG_methods.__str__;
        example_serverQ_L_31procG_methods.__repr__ = (B_str (*) (example_serverQ_L_31proc))B_valueG_methods.__repr__;
        example_serverQ_L_31procG_methods.__init__ = (B_NoneType (*) (example_serverQ_L_31proc, example_serverQ_main, sshQ_ServerSession))example_serverQ_L_31procD___init__;
        example_serverQ_L_31procG_methods.__call__ = ($R (*) (example_serverQ_L_31proc, $Cont))example_serverQ_L_31procD___call__;
        example_serverQ_L_31procG_methods.__exec__ = ($R (*) (example_serverQ_L_31proc, $Cont))example_serverQ_L_31procD___exec__;
        example_serverQ_L_31procG_methods.__serialize__ = example_serverQ_L_31procD___serialize__;
        example_serverQ_L_31procG_methods.__deserialize__ = example_serverQ_L_31procD___deserialize__;
        $register(&example_serverQ_L_31procG_methods);
    }
    {
        example_serverQ_L_32procG_methods.$GCINFO = "example_serverQ_L_32proc";
        example_serverQ_L_32procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        example_serverQ_L_32procG_methods.__bool__ = (B_bool (*) (example_serverQ_L_32proc))B_valueG_methods.__bool__;
        example_serverQ_L_32procG_methods.__str__ = (B_str (*) (example_serverQ_L_32proc))B_valueG_methods.__str__;
        example_serverQ_L_32procG_methods.__repr__ = (B_str (*) (example_serverQ_L_32proc))B_valueG_methods.__repr__;
        example_serverQ_L_32procG_methods.__init__ = (B_NoneType (*) (example_serverQ_L_32proc, example_serverQ_main, sshQ_ServerSession, B_str))example_serverQ_L_32procD___init__;
        example_serverQ_L_32procG_methods.__call__ = ($R (*) (example_serverQ_L_32proc, $Cont))example_serverQ_L_32procD___call__;
        example_serverQ_L_32procG_methods.__exec__ = ($R (*) (example_serverQ_L_32proc, $Cont))example_serverQ_L_32procD___exec__;
        example_serverQ_L_32procG_methods.__serialize__ = example_serverQ_L_32procD___serialize__;
        example_serverQ_L_32procG_methods.__deserialize__ = example_serverQ_L_32procD___deserialize__;
        $register(&example_serverQ_L_32procG_methods);
    }
    {
        example_serverQ_L_33procG_methods.$GCINFO = "example_serverQ_L_33proc";
        example_serverQ_L_33procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        example_serverQ_L_33procG_methods.__bool__ = (B_bool (*) (example_serverQ_L_33proc))B_valueG_methods.__bool__;
        example_serverQ_L_33procG_methods.__str__ = (B_str (*) (example_serverQ_L_33proc))B_valueG_methods.__str__;
        example_serverQ_L_33procG_methods.__repr__ = (B_str (*) (example_serverQ_L_33proc))B_valueG_methods.__repr__;
        example_serverQ_L_33procG_methods.__init__ = (B_NoneType (*) (example_serverQ_L_33proc, example_serverQ_main, sshQ_ServerSession, sshQ_AuthRequest))example_serverQ_L_33procD___init__;
        example_serverQ_L_33procG_methods.__call__ = ($R (*) (example_serverQ_L_33proc, $Cont))example_serverQ_L_33procD___call__;
        example_serverQ_L_33procG_methods.__exec__ = ($R (*) (example_serverQ_L_33proc, $Cont))example_serverQ_L_33procD___exec__;
        example_serverQ_L_33procG_methods.__serialize__ = example_serverQ_L_33procD___serialize__;
        example_serverQ_L_33procG_methods.__deserialize__ = example_serverQ_L_33procD___deserialize__;
        $register(&example_serverQ_L_33procG_methods);
    }
    {
        example_serverQ_L_34procG_methods.$GCINFO = "example_serverQ_L_34proc";
        example_serverQ_L_34procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        example_serverQ_L_34procG_methods.__bool__ = (B_bool (*) (example_serverQ_L_34proc))B_valueG_methods.__bool__;
        example_serverQ_L_34procG_methods.__str__ = (B_str (*) (example_serverQ_L_34proc))B_valueG_methods.__str__;
        example_serverQ_L_34procG_methods.__repr__ = (B_str (*) (example_serverQ_L_34proc))B_valueG_methods.__repr__;
        example_serverQ_L_34procG_methods.__init__ = (B_NoneType (*) (example_serverQ_L_34proc, example_serverQ_main, sshQ_ServerChannel, B_bytes))example_serverQ_L_34procD___init__;
        example_serverQ_L_34procG_methods.__call__ = ($R (*) (example_serverQ_L_34proc, $Cont))example_serverQ_L_34procD___call__;
        example_serverQ_L_34procG_methods.__exec__ = ($R (*) (example_serverQ_L_34proc, $Cont))example_serverQ_L_34procD___exec__;
        example_serverQ_L_34procG_methods.__serialize__ = example_serverQ_L_34procD___serialize__;
        example_serverQ_L_34procG_methods.__deserialize__ = example_serverQ_L_34procD___deserialize__;
        $register(&example_serverQ_L_34procG_methods);
    }
    {
        example_serverQ_L_35procG_methods.$GCINFO = "example_serverQ_L_35proc";
        example_serverQ_L_35procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        example_serverQ_L_35procG_methods.__bool__ = (B_bool (*) (example_serverQ_L_35proc))B_valueG_methods.__bool__;
        example_serverQ_L_35procG_methods.__str__ = (B_str (*) (example_serverQ_L_35proc))B_valueG_methods.__str__;
        example_serverQ_L_35procG_methods.__repr__ = (B_str (*) (example_serverQ_L_35proc))B_valueG_methods.__repr__;
        example_serverQ_L_35procG_methods.__init__ = (B_NoneType (*) (example_serverQ_L_35proc, example_serverQ_main, sshQ_ServerChannel, B_bytes))example_serverQ_L_35procD___init__;
        example_serverQ_L_35procG_methods.__call__ = ($R (*) (example_serverQ_L_35proc, $Cont))example_serverQ_L_35procD___call__;
        example_serverQ_L_35procG_methods.__exec__ = ($R (*) (example_serverQ_L_35proc, $Cont))example_serverQ_L_35procD___exec__;
        example_serverQ_L_35procG_methods.__serialize__ = example_serverQ_L_35procD___serialize__;
        example_serverQ_L_35procG_methods.__deserialize__ = example_serverQ_L_35procD___deserialize__;
        $register(&example_serverQ_L_35procG_methods);
    }
    {
        example_serverQ_L_36procG_methods.$GCINFO = "example_serverQ_L_36proc";
        example_serverQ_L_36procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        example_serverQ_L_36procG_methods.__bool__ = (B_bool (*) (example_serverQ_L_36proc))B_valueG_methods.__bool__;
        example_serverQ_L_36procG_methods.__str__ = (B_str (*) (example_serverQ_L_36proc))B_valueG_methods.__str__;
        example_serverQ_L_36procG_methods.__repr__ = (B_str (*) (example_serverQ_L_36proc))B_valueG_methods.__repr__;
        example_serverQ_L_36procG_methods.__init__ = (B_NoneType (*) (example_serverQ_L_36proc, example_serverQ_main, sshQ_ServerChannel, B_str))example_serverQ_L_36procD___init__;
        example_serverQ_L_36procG_methods.__call__ = ($R (*) (example_serverQ_L_36proc, $Cont))example_serverQ_L_36procD___call__;
        example_serverQ_L_36procG_methods.__exec__ = ($R (*) (example_serverQ_L_36proc, $Cont))example_serverQ_L_36procD___exec__;
        example_serverQ_L_36procG_methods.__serialize__ = example_serverQ_L_36procD___serialize__;
        example_serverQ_L_36procG_methods.__deserialize__ = example_serverQ_L_36procD___deserialize__;
        $register(&example_serverQ_L_36procG_methods);
    }
    {
        example_serverQ_L_37procG_methods.$GCINFO = "example_serverQ_L_37proc";
        example_serverQ_L_37procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        example_serverQ_L_37procG_methods.__bool__ = (B_bool (*) (example_serverQ_L_37proc))B_valueG_methods.__bool__;
        example_serverQ_L_37procG_methods.__str__ = (B_str (*) (example_serverQ_L_37proc))B_valueG_methods.__str__;
        example_serverQ_L_37procG_methods.__repr__ = (B_str (*) (example_serverQ_L_37proc))B_valueG_methods.__repr__;
        example_serverQ_L_37procG_methods.__init__ = (B_NoneType (*) (example_serverQ_L_37proc, example_serverQ_main, sshQ_ServerSession))example_serverQ_L_37procD___init__;
        example_serverQ_L_37procG_methods.__call__ = ($R (*) (example_serverQ_L_37proc, $Cont))example_serverQ_L_37procD___call__;
        example_serverQ_L_37procG_methods.__exec__ = ($R (*) (example_serverQ_L_37proc, $Cont))example_serverQ_L_37procD___exec__;
        example_serverQ_L_37procG_methods.__serialize__ = example_serverQ_L_37procD___serialize__;
        example_serverQ_L_37procG_methods.__deserialize__ = example_serverQ_L_37procD___deserialize__;
        $register(&example_serverQ_L_37procG_methods);
    }
    {
        example_serverQ_L_38procG_methods.$GCINFO = "example_serverQ_L_38proc";
        example_serverQ_L_38procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        example_serverQ_L_38procG_methods.__bool__ = (B_bool (*) (example_serverQ_L_38proc))B_valueG_methods.__bool__;
        example_serverQ_L_38procG_methods.__str__ = (B_str (*) (example_serverQ_L_38proc))B_valueG_methods.__str__;
        example_serverQ_L_38procG_methods.__repr__ = (B_str (*) (example_serverQ_L_38proc))B_valueG_methods.__repr__;
        example_serverQ_L_38procG_methods.__init__ = (B_NoneType (*) (example_serverQ_L_38proc, example_serverQ_main, sshQ_ServerSession, sshQ_ServerChannel, B_str))example_serverQ_L_38procD___init__;
        example_serverQ_L_38procG_methods.__call__ = ($R (*) (example_serverQ_L_38proc, $Cont))example_serverQ_L_38procD___call__;
        example_serverQ_L_38procG_methods.__exec__ = ($R (*) (example_serverQ_L_38proc, $Cont))example_serverQ_L_38procD___exec__;
        example_serverQ_L_38procG_methods.__serialize__ = example_serverQ_L_38procD___serialize__;
        example_serverQ_L_38procG_methods.__deserialize__ = example_serverQ_L_38procD___deserialize__;
        $register(&example_serverQ_L_38procG_methods);
    }
    {
        example_serverQ_L_40ContG_methods.$GCINFO = "example_serverQ_L_40Cont";
        example_serverQ_L_40ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        example_serverQ_L_40ContG_methods.__bool__ = (B_bool (*) (example_serverQ_L_40Cont))B_valueG_methods.__bool__;
        example_serverQ_L_40ContG_methods.__str__ = (B_str (*) (example_serverQ_L_40Cont))B_valueG_methods.__str__;
        example_serverQ_L_40ContG_methods.__repr__ = (B_str (*) (example_serverQ_L_40Cont))B_valueG_methods.__repr__;
        example_serverQ_L_40ContG_methods.__init__ = (B_NoneType (*) (example_serverQ_L_40Cont, $Cont, example_serverQ_main))example_serverQ_L_40ContD___init__;
        example_serverQ_L_40ContG_methods.__call__ = ($R (*) (example_serverQ_L_40Cont, B_NoneType))example_serverQ_L_40ContD___call__;
        example_serverQ_L_40ContG_methods.__serialize__ = example_serverQ_L_40ContD___serialize__;
        example_serverQ_L_40ContG_methods.__deserialize__ = example_serverQ_L_40ContD___deserialize__;
        $register(&example_serverQ_L_40ContG_methods);
    }
    {
        example_serverQ_L_41procG_methods.$GCINFO = "example_serverQ_L_41proc";
        example_serverQ_L_41procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        example_serverQ_L_41procG_methods.__bool__ = (B_bool (*) (example_serverQ_L_41proc))B_valueG_methods.__bool__;
        example_serverQ_L_41procG_methods.__str__ = (B_str (*) (example_serverQ_L_41proc))B_valueG_methods.__str__;
        example_serverQ_L_41procG_methods.__repr__ = (B_str (*) (example_serverQ_L_41proc))B_valueG_methods.__repr__;
        example_serverQ_L_41procG_methods.__init__ = (B_NoneType (*) (example_serverQ_L_41proc, example_serverQ_main, B_Env))example_serverQ_L_41procD___init__;
        example_serverQ_L_41procG_methods.__call__ = ($R (*) (example_serverQ_L_41proc, $Cont))example_serverQ_L_41procD___call__;
        example_serverQ_L_41procG_methods.__exec__ = ($R (*) (example_serverQ_L_41proc, $Cont))example_serverQ_L_41procD___exec__;
        example_serverQ_L_41procG_methods.__serialize__ = example_serverQ_L_41procD___serialize__;
        example_serverQ_L_41procG_methods.__deserialize__ = example_serverQ_L_41procD___deserialize__;
        $register(&example_serverQ_L_41procG_methods);
    }
    {
        example_serverQ_mainG_methods.$GCINFO = "example_serverQ_main";
        example_serverQ_mainG_methods.$superclass = ($SuperG_class)&$ActorG_methods;
        example_serverQ_mainG_methods.__bool__ = (B_bool (*) (example_serverQ_main))$ActorG_methods.__bool__;
        example_serverQ_mainG_methods.__str__ = (B_str (*) (example_serverQ_main))$ActorG_methods.__str__;
        example_serverQ_mainG_methods.__repr__ = (B_str (*) (example_serverQ_main))$ActorG_methods.__repr__;
        example_serverQ_mainG_methods.__resume__ = (B_NoneType (*) (example_serverQ_main))$ActorG_methods.__resume__;
        example_serverQ_mainG_methods.__cleanup__ = (B_NoneType (*) (example_serverQ_main))$ActorG_methods.__cleanup__;
        example_serverQ_mainG_methods.__init__ = ($R (*) (example_serverQ_main, $Cont, B_Env))example_serverQ_mainD___init__;
        example_serverQ_mainG_methods.on_listenG_local = ($R (*) (example_serverQ_main, $Cont, sshQ_Server, B_str))example_serverQ_mainD_on_listenG_local;
        example_serverQ_mainG_methods.on_server_closeG_local = ($R (*) (example_serverQ_main, $Cont, sshQ_Server, B_str))example_serverQ_mainD_on_server_closeG_local;
        example_serverQ_mainG_methods.on_sessionG_local = ($R (*) (example_serverQ_main, $Cont, sshQ_ServerSession))example_serverQ_mainD_on_sessionG_local;
        example_serverQ_mainG_methods.on_session_closeG_local = ($R (*) (example_serverQ_main, $Cont, sshQ_ServerSession, B_str))example_serverQ_mainD_on_session_closeG_local;
        example_serverQ_mainG_methods.on_authG_local = ($R (*) (example_serverQ_main, $Cont, sshQ_ServerSession, sshQ_AuthRequest))example_serverQ_mainD_on_authG_local;
        example_serverQ_mainG_methods.srv_on_dataG_local = ($R (*) (example_serverQ_main, $Cont, sshQ_ServerChannel, B_bytes))example_serverQ_mainD_srv_on_dataG_local;
        example_serverQ_mainG_methods.srv_on_stderrG_local = ($R (*) (example_serverQ_main, $Cont, sshQ_ServerChannel, B_bytes))example_serverQ_mainD_srv_on_stderrG_local;
        example_serverQ_mainG_methods.srv_on_closeG_local = ($R (*) (example_serverQ_main, $Cont, sshQ_ServerChannel, B_str))example_serverQ_mainD_srv_on_closeG_local;
        example_serverQ_mainG_methods.on_channel_openG_local = ($R (*) (example_serverQ_main, $Cont, sshQ_ServerSession))example_serverQ_mainD_on_channel_openG_local;
        example_serverQ_mainG_methods.on_execG_local = ($R (*) (example_serverQ_main, $Cont, sshQ_ServerSession, sshQ_ServerChannel, B_str))example_serverQ_mainD_on_execG_local;
        example_serverQ_mainG_methods.on_listen = (B_Msg (*) (example_serverQ_main, sshQ_Server, B_str))example_serverQ_mainD_on_listen;
        example_serverQ_mainG_methods.on_server_close = (B_Msg (*) (example_serverQ_main, sshQ_Server, B_str))example_serverQ_mainD_on_server_close;
        example_serverQ_mainG_methods.on_session = (B_Msg (*) (example_serverQ_main, sshQ_ServerSession))example_serverQ_mainD_on_session;
        example_serverQ_mainG_methods.on_session_close = (B_Msg (*) (example_serverQ_main, sshQ_ServerSession, B_str))example_serverQ_mainD_on_session_close;
        example_serverQ_mainG_methods.on_auth = (B_Msg (*) (example_serverQ_main, sshQ_ServerSession, sshQ_AuthRequest))example_serverQ_mainD_on_auth;
        example_serverQ_mainG_methods.srv_on_data = (B_Msg (*) (example_serverQ_main, sshQ_ServerChannel, B_bytes))example_serverQ_mainD_srv_on_data;
        example_serverQ_mainG_methods.srv_on_stderr = (B_Msg (*) (example_serverQ_main, sshQ_ServerChannel, B_bytes))example_serverQ_mainD_srv_on_stderr;
        example_serverQ_mainG_methods.srv_on_close = (B_Msg (*) (example_serverQ_main, sshQ_ServerChannel, B_str))example_serverQ_mainD_srv_on_close;
        example_serverQ_mainG_methods.on_channel_open = (B_Msg (*) (example_serverQ_main, sshQ_ServerSession))example_serverQ_mainD_on_channel_open;
        example_serverQ_mainG_methods.on_exec = (B_Msg (*) (example_serverQ_main, sshQ_ServerSession, sshQ_ServerChannel, B_str))example_serverQ_mainD_on_exec;
        example_serverQ_mainG_methods.__serialize__ = example_serverQ_mainD___serialize__;
        example_serverQ_mainG_methods.__deserialize__ = example_serverQ_mainD___deserialize__;
        $register(&example_serverQ_mainG_methods);
    }
    B_Eq W_main_489 = (B_Eq)B_OrdD_strG_witness;
    example_serverQ_W_main_489 = W_main_489;
    B_Collection W_main_20 = (B_Collection)B_SequenceD_listG_witness->W_Collection;
    example_serverQ_W_main_20 = W_main_20;
    B_Plus W_main_268 = (B_Plus)B_TimesD_strG_witness;
    example_serverQ_W_main_268 = W_main_268;
}