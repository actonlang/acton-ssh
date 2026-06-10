/* Acton impl hash: b05d265ed7e923b3cbb70f104820aa571f841bad02a0cb8ae0ff133699ea0e45 */
#include "rts/common.h"
#include "out/types/soak.h"
B_Collection soakQ_W_main_27;
$R soakQ_L_1C_2cont (soakQ_main self, $Cont C_cont, sshQ_Server C_3res) {
    #line 102 "src/soak.act"
    ((soakQ_main)(self))->server = C_3res;
    return $R_CONT(C_cont, B_None);
}
B_NoneType soakQ_L_2ContD___init__ (soakQ_L_2Cont L_self, soakQ_main self, $Cont C_cont) {
    ((soakQ_L_2Cont)(L_self))->self = self;
    ((soakQ_L_2Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R soakQ_L_2ContD___call__ (soakQ_L_2Cont L_self, sshQ_Server G_1) {
    soakQ_main self = ((soakQ_L_2Cont)(L_self))->self;
    $Cont C_cont = ((soakQ_L_2Cont)(L_self))->C_cont;
    return soakQ_L_1C_2cont(self, C_cont, G_1);
}
void soakQ_L_2ContD___serialize__ (soakQ_L_2Cont self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->C_cont, state);
}
soakQ_L_2Cont soakQ_L_2ContD___deserialize__ (soakQ_L_2Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct soakQ_L_2Cont));
            self->$class = &soakQ_L_2ContG_methods;
            return self;
        }
        self = $DNEW(soakQ_L_2Cont, state);
    }
    self->self = $step_deserialize(state);
    self->C_cont = $step_deserialize(state);
    return self;
}
soakQ_L_2Cont soakQ_L_2ContG_new(soakQ_main G_1, $Cont G_2) {
    soakQ_L_2Cont $tmp = acton_malloc(sizeof(struct soakQ_L_2Cont));
    $tmp->$class = &soakQ_L_2ContG_methods;
    soakQ_L_2ContG_methods.__init__($tmp, G_1, G_2);
    return $tmp;
}
struct soakQ_L_2ContG_class soakQ_L_2ContG_methods;
B_NoneType soakQ_L_4actionD___init__ (soakQ_L_4action L_self, soakQ_main L_3obj) {
    ((soakQ_L_4action)(L_self))->L_3obj = L_3obj;
    return B_None;
}
$R soakQ_L_4actionD___call__ (soakQ_L_4action L_self, $Cont L_cont, sshQ_Server G_1, B_str G_2) {
    return $AWAIT(L_cont, ((B_Msg (*) ($WORD, sshQ_Server, B_str))((soakQ_L_4action)(L_self))->$class->__asyn__)(L_self, G_1, G_2));
}
$R soakQ_L_4actionD___exec__ (soakQ_L_4action L_self, $Cont L_cont, sshQ_Server G_1, B_str G_2) {
    return $R_CONT(L_cont, ((B_Msg (*) ($WORD, sshQ_Server, B_str))((soakQ_L_4action)(L_self))->$class->__asyn__)(L_self, G_1, G_2));
}
B_Msg soakQ_L_4actionD___asyn__ (soakQ_L_4action L_self, sshQ_Server G_1, B_str G_2) {
    soakQ_main L_3obj = ((soakQ_L_4action)(L_self))->L_3obj;
    return ((B_Msg (*) ($WORD, sshQ_Server, B_str))((soakQ_main)(L_3obj))->$class->on_listen)(L_3obj, G_1, G_2);
}
void soakQ_L_4actionD___serialize__ (soakQ_L_4action self, $Serial$state state) {
    $step_serialize(self->L_3obj, state);
}
soakQ_L_4action soakQ_L_4actionD___deserialize__ (soakQ_L_4action self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct soakQ_L_4action));
            self->$class = &soakQ_L_4actionG_methods;
            return self;
        }
        self = $DNEW(soakQ_L_4action, state);
    }
    self->L_3obj = $step_deserialize(state);
    return self;
}
soakQ_L_4action soakQ_L_4actionG_new(soakQ_main G_1) {
    soakQ_L_4action $tmp = acton_malloc(sizeof(struct soakQ_L_4action));
    $tmp->$class = &soakQ_L_4actionG_methods;
    soakQ_L_4actionG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct soakQ_L_4actionG_class soakQ_L_4actionG_methods;
B_NoneType soakQ_L_6actionD___init__ (soakQ_L_6action L_self, soakQ_main L_5obj) {
    ((soakQ_L_6action)(L_self))->L_5obj = L_5obj;
    return B_None;
}
$R soakQ_L_6actionD___call__ (soakQ_L_6action L_self, $Cont L_cont, sshQ_Server G_1, B_str G_2) {
    return $AWAIT(L_cont, ((B_Msg (*) ($WORD, sshQ_Server, B_str))((soakQ_L_6action)(L_self))->$class->__asyn__)(L_self, G_1, G_2));
}
$R soakQ_L_6actionD___exec__ (soakQ_L_6action L_self, $Cont L_cont, sshQ_Server G_1, B_str G_2) {
    return $R_CONT(L_cont, ((B_Msg (*) ($WORD, sshQ_Server, B_str))((soakQ_L_6action)(L_self))->$class->__asyn__)(L_self, G_1, G_2));
}
B_Msg soakQ_L_6actionD___asyn__ (soakQ_L_6action L_self, sshQ_Server G_1, B_str G_2) {
    soakQ_main L_5obj = ((soakQ_L_6action)(L_self))->L_5obj;
    return ((B_Msg (*) ($WORD, sshQ_Server, B_str))((soakQ_main)(L_5obj))->$class->on_server_close)(L_5obj, G_1, G_2);
}
void soakQ_L_6actionD___serialize__ (soakQ_L_6action self, $Serial$state state) {
    $step_serialize(self->L_5obj, state);
}
soakQ_L_6action soakQ_L_6actionD___deserialize__ (soakQ_L_6action self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct soakQ_L_6action));
            self->$class = &soakQ_L_6actionG_methods;
            return self;
        }
        self = $DNEW(soakQ_L_6action, state);
    }
    self->L_5obj = $step_deserialize(state);
    return self;
}
soakQ_L_6action soakQ_L_6actionG_new(soakQ_main G_1) {
    soakQ_L_6action $tmp = acton_malloc(sizeof(struct soakQ_L_6action));
    $tmp->$class = &soakQ_L_6actionG_methods;
    soakQ_L_6actionG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct soakQ_L_6actionG_class soakQ_L_6actionG_methods;
B_NoneType soakQ_L_8actionD___init__ (soakQ_L_8action L_self, soakQ_main L_7obj) {
    ((soakQ_L_8action)(L_self))->L_7obj = L_7obj;
    return B_None;
}
$R soakQ_L_8actionD___call__ (soakQ_L_8action L_self, $Cont L_cont, sshQ_ServerSession G_1) {
    return $AWAIT(L_cont, ((B_Msg (*) ($WORD, sshQ_ServerSession))((soakQ_L_8action)(L_self))->$class->__asyn__)(L_self, G_1));
}
$R soakQ_L_8actionD___exec__ (soakQ_L_8action L_self, $Cont L_cont, sshQ_ServerSession G_1) {
    return $R_CONT(L_cont, ((B_Msg (*) ($WORD, sshQ_ServerSession))((soakQ_L_8action)(L_self))->$class->__asyn__)(L_self, G_1));
}
B_Msg soakQ_L_8actionD___asyn__ (soakQ_L_8action L_self, sshQ_ServerSession G_1) {
    soakQ_main L_7obj = ((soakQ_L_8action)(L_self))->L_7obj;
    return ((B_Msg (*) ($WORD, sshQ_ServerSession))((soakQ_main)(L_7obj))->$class->on_session)(L_7obj, G_1);
}
void soakQ_L_8actionD___serialize__ (soakQ_L_8action self, $Serial$state state) {
    $step_serialize(self->L_7obj, state);
}
soakQ_L_8action soakQ_L_8actionD___deserialize__ (soakQ_L_8action self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct soakQ_L_8action));
            self->$class = &soakQ_L_8actionG_methods;
            return self;
        }
        self = $DNEW(soakQ_L_8action, state);
    }
    self->L_7obj = $step_deserialize(state);
    return self;
}
soakQ_L_8action soakQ_L_8actionG_new(soakQ_main G_1) {
    soakQ_L_8action $tmp = acton_malloc(sizeof(struct soakQ_L_8action));
    $tmp->$class = &soakQ_L_8actionG_methods;
    soakQ_L_8actionG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct soakQ_L_8actionG_class soakQ_L_8actionG_methods;
B_NoneType soakQ_L_10actionD___init__ (soakQ_L_10action L_self, soakQ_main L_9obj) {
    ((soakQ_L_10action)(L_self))->L_9obj = L_9obj;
    return B_None;
}
$R soakQ_L_10actionD___call__ (soakQ_L_10action L_self, $Cont L_cont, sshQ_ServerSession G_1, sshQ_AuthRequest G_2) {
    return $AWAIT(L_cont, ((B_Msg (*) ($WORD, sshQ_ServerSession, sshQ_AuthRequest))((soakQ_L_10action)(L_self))->$class->__asyn__)(L_self, G_1, G_2));
}
$R soakQ_L_10actionD___exec__ (soakQ_L_10action L_self, $Cont L_cont, sshQ_ServerSession G_1, sshQ_AuthRequest G_2) {
    return $R_CONT(L_cont, ((B_Msg (*) ($WORD, sshQ_ServerSession, sshQ_AuthRequest))((soakQ_L_10action)(L_self))->$class->__asyn__)(L_self, G_1, G_2));
}
B_Msg soakQ_L_10actionD___asyn__ (soakQ_L_10action L_self, sshQ_ServerSession G_1, sshQ_AuthRequest G_2) {
    soakQ_main L_9obj = ((soakQ_L_10action)(L_self))->L_9obj;
    return ((B_Msg (*) ($WORD, sshQ_ServerSession, sshQ_AuthRequest))((soakQ_main)(L_9obj))->$class->on_auth)(L_9obj, G_1, G_2);
}
void soakQ_L_10actionD___serialize__ (soakQ_L_10action self, $Serial$state state) {
    $step_serialize(self->L_9obj, state);
}
soakQ_L_10action soakQ_L_10actionD___deserialize__ (soakQ_L_10action self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct soakQ_L_10action));
            self->$class = &soakQ_L_10actionG_methods;
            return self;
        }
        self = $DNEW(soakQ_L_10action, state);
    }
    self->L_9obj = $step_deserialize(state);
    return self;
}
soakQ_L_10action soakQ_L_10actionG_new(soakQ_main G_1) {
    soakQ_L_10action $tmp = acton_malloc(sizeof(struct soakQ_L_10action));
    $tmp->$class = &soakQ_L_10actionG_methods;
    soakQ_L_10actionG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct soakQ_L_10actionG_class soakQ_L_10actionG_methods;
B_NoneType soakQ_L_12actionD___init__ (soakQ_L_12action L_self, soakQ_main L_11obj) {
    ((soakQ_L_12action)(L_self))->L_11obj = L_11obj;
    return B_None;
}
$R soakQ_L_12actionD___call__ (soakQ_L_12action L_self, $Cont L_cont, sshQ_ServerSession G_1) {
    return $AWAIT(L_cont, ((B_Msg (*) ($WORD, sshQ_ServerSession))((soakQ_L_12action)(L_self))->$class->__asyn__)(L_self, G_1));
}
$R soakQ_L_12actionD___exec__ (soakQ_L_12action L_self, $Cont L_cont, sshQ_ServerSession G_1) {
    return $R_CONT(L_cont, ((B_Msg (*) ($WORD, sshQ_ServerSession))((soakQ_L_12action)(L_self))->$class->__asyn__)(L_self, G_1));
}
B_Msg soakQ_L_12actionD___asyn__ (soakQ_L_12action L_self, sshQ_ServerSession G_1) {
    soakQ_main L_11obj = ((soakQ_L_12action)(L_self))->L_11obj;
    return ((B_Msg (*) ($WORD, sshQ_ServerSession))((soakQ_main)(L_11obj))->$class->on_channel_open)(L_11obj, G_1);
}
void soakQ_L_12actionD___serialize__ (soakQ_L_12action self, $Serial$state state) {
    $step_serialize(self->L_11obj, state);
}
soakQ_L_12action soakQ_L_12actionD___deserialize__ (soakQ_L_12action self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct soakQ_L_12action));
            self->$class = &soakQ_L_12actionG_methods;
            return self;
        }
        self = $DNEW(soakQ_L_12action, state);
    }
    self->L_11obj = $step_deserialize(state);
    return self;
}
soakQ_L_12action soakQ_L_12actionG_new(soakQ_main G_1) {
    soakQ_L_12action $tmp = acton_malloc(sizeof(struct soakQ_L_12action));
    $tmp->$class = &soakQ_L_12actionG_methods;
    soakQ_L_12actionG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct soakQ_L_12actionG_class soakQ_L_12actionG_methods;
B_NoneType soakQ_L_14actionD___init__ (soakQ_L_14action L_self, soakQ_main L_13obj) {
    ((soakQ_L_14action)(L_self))->L_13obj = L_13obj;
    return B_None;
}
$R soakQ_L_14actionD___call__ (soakQ_L_14action L_self, $Cont L_cont, sshQ_ServerSession G_1, sshQ_ServerChannel G_2, B_str G_3) {
    return $AWAIT(L_cont, ((B_Msg (*) ($WORD, sshQ_ServerSession, sshQ_ServerChannel, B_str))((soakQ_L_14action)(L_self))->$class->__asyn__)(L_self, G_1, G_2, G_3));
}
$R soakQ_L_14actionD___exec__ (soakQ_L_14action L_self, $Cont L_cont, sshQ_ServerSession G_1, sshQ_ServerChannel G_2, B_str G_3) {
    return $R_CONT(L_cont, ((B_Msg (*) ($WORD, sshQ_ServerSession, sshQ_ServerChannel, B_str))((soakQ_L_14action)(L_self))->$class->__asyn__)(L_self, G_1, G_2, G_3));
}
B_Msg soakQ_L_14actionD___asyn__ (soakQ_L_14action L_self, sshQ_ServerSession G_1, sshQ_ServerChannel G_2, B_str G_3) {
    soakQ_main L_13obj = ((soakQ_L_14action)(L_self))->L_13obj;
    return ((B_Msg (*) ($WORD, sshQ_ServerSession, sshQ_ServerChannel, B_str))((soakQ_main)(L_13obj))->$class->on_exec)(L_13obj, G_1, G_2, G_3);
}
void soakQ_L_14actionD___serialize__ (soakQ_L_14action self, $Serial$state state) {
    $step_serialize(self->L_13obj, state);
}
soakQ_L_14action soakQ_L_14actionD___deserialize__ (soakQ_L_14action self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct soakQ_L_14action));
            self->$class = &soakQ_L_14actionG_methods;
            return self;
        }
        self = $DNEW(soakQ_L_14action, state);
    }
    self->L_13obj = $step_deserialize(state);
    return self;
}
soakQ_L_14action soakQ_L_14actionG_new(soakQ_main G_1) {
    soakQ_L_14action $tmp = acton_malloc(sizeof(struct soakQ_L_14action));
    $tmp->$class = &soakQ_L_14actionG_methods;
    soakQ_L_14actionG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct soakQ_L_14actionG_class soakQ_L_14actionG_methods;
$R soakQ_L_17C_8cont ($Cont C_cont, B_NoneType C_9res) {
    return $R_CONT(C_cont, B_None);
}
B_NoneType soakQ_L_18ContD___init__ (soakQ_L_18Cont L_self, $Cont C_cont) {
    ((soakQ_L_18Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R soakQ_L_18ContD___call__ (soakQ_L_18Cont L_self, B_NoneType G_1) {
    $Cont C_cont = ((soakQ_L_18Cont)(L_self))->C_cont;
    return soakQ_L_17C_8cont(C_cont, G_1);
}
void soakQ_L_18ContD___serialize__ (soakQ_L_18Cont self, $Serial$state state) {
    $step_serialize(self->C_cont, state);
}
soakQ_L_18Cont soakQ_L_18ContD___deserialize__ (soakQ_L_18Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct soakQ_L_18Cont));
            self->$class = &soakQ_L_18ContG_methods;
            return self;
        }
        self = $DNEW(soakQ_L_18Cont, state);
    }
    self->C_cont = $step_deserialize(state);
    return self;
}
soakQ_L_18Cont soakQ_L_18ContG_new($Cont G_1) {
    soakQ_L_18Cont $tmp = acton_malloc(sizeof(struct soakQ_L_18Cont));
    $tmp->$class = &soakQ_L_18ContG_methods;
    soakQ_L_18ContG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct soakQ_L_18ContG_class soakQ_L_18ContG_methods;
$R soakQ_L_16C_6cont (soakQ_main self, $Cont C_cont, uint16_t C_7res) {
    #line 32 "src/soak.act"
    ((soakQ_main)(self))->port = C_7res;
    return (($R (*) ($WORD, $Cont))((soakQ_main)(self))->$class->start_cycleG_local)(self, (($Cont)soakQ_L_18ContG_new(C_cont)));
}
B_NoneType soakQ_L_19ContD___init__ (soakQ_L_19Cont L_self, soakQ_main self, $Cont C_cont) {
    ((soakQ_L_19Cont)(L_self))->self = self;
    ((soakQ_L_19Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R soakQ_L_19ContD___call__ (soakQ_L_19Cont L_self, B_u16 G_1) {
    soakQ_main self = ((soakQ_L_19Cont)(L_self))->self;
    $Cont C_cont = ((soakQ_L_19Cont)(L_self))->C_cont;
    return soakQ_L_16C_6cont(self, C_cont, ((B_u16)G_1)->val);
}
void soakQ_L_19ContD___serialize__ (soakQ_L_19Cont self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->C_cont, state);
}
soakQ_L_19Cont soakQ_L_19ContD___deserialize__ (soakQ_L_19Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct soakQ_L_19Cont));
            self->$class = &soakQ_L_19ContG_methods;
            return self;
        }
        self = $DNEW(soakQ_L_19Cont, state);
    }
    self->self = $step_deserialize(state);
    self->C_cont = $step_deserialize(state);
    return self;
}
soakQ_L_19Cont soakQ_L_19ContG_new(soakQ_main G_1, $Cont G_2) {
    soakQ_L_19Cont $tmp = acton_malloc(sizeof(struct soakQ_L_19Cont));
    $tmp->$class = &soakQ_L_19ContG_methods;
    soakQ_L_19ContG_methods.__init__($tmp, G_1, G_2);
    return $tmp;
}
struct soakQ_L_19ContG_class soakQ_L_19ContG_methods;
$R soakQ_L_15C_4cont (soakQ_main self, $Cont C_cont, sshQ_Server s, B_NoneType C_5res) {
    return $AWAIT((($Cont)soakQ_L_19ContG_new(self, C_cont)), ((B_Msg (*) ($WORD))((sshQ_Server)(s))->$class->bound_port)(s));
}
$R soakQ_L_20C_10cont ($Cont C_cont, B_NoneType C_11res) {
    return $R_CONT(C_cont, B_None);
}
B_NoneType soakQ_L_21ContD___init__ (soakQ_L_21Cont L_self, $Cont C_cont) {
    ((soakQ_L_21Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R soakQ_L_21ContD___call__ (soakQ_L_21Cont L_self, B_NoneType G_1) {
    $Cont C_cont = ((soakQ_L_21Cont)(L_self))->C_cont;
    return soakQ_L_20C_10cont(C_cont, G_1);
}
void soakQ_L_21ContD___serialize__ (soakQ_L_21Cont self, $Serial$state state) {
    $step_serialize(self->C_cont, state);
}
soakQ_L_21Cont soakQ_L_21ContD___deserialize__ (soakQ_L_21Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct soakQ_L_21Cont));
            self->$class = &soakQ_L_21ContG_methods;
            return self;
        }
        self = $DNEW(soakQ_L_21Cont, state);
    }
    self->C_cont = $step_deserialize(state);
    return self;
}
soakQ_L_21Cont soakQ_L_21ContG_new($Cont G_1) {
    soakQ_L_21Cont $tmp = acton_malloc(sizeof(struct soakQ_L_21Cont));
    $tmp->$class = &soakQ_L_21ContG_methods;
    soakQ_L_21ContG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct soakQ_L_21ContG_class soakQ_L_21ContG_methods;
B_NoneType soakQ_L_22ContD___init__ (soakQ_L_22Cont L_self, soakQ_main self, $Cont C_cont, sshQ_Server s) {
    ((soakQ_L_22Cont)(L_self))->self = self;
    ((soakQ_L_22Cont)(L_self))->C_cont = C_cont;
    ((soakQ_L_22Cont)(L_self))->s = s;
    return B_None;
}
$R soakQ_L_22ContD___call__ (soakQ_L_22Cont L_self, B_NoneType G_1) {
    soakQ_main self = ((soakQ_L_22Cont)(L_self))->self;
    $Cont C_cont = ((soakQ_L_22Cont)(L_self))->C_cont;
    sshQ_Server s = ((soakQ_L_22Cont)(L_self))->s;
    return soakQ_L_15C_4cont(self, C_cont, s, G_1);
}
void soakQ_L_22ContD___serialize__ (soakQ_L_22Cont self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->C_cont, state);
    $step_serialize(self->s, state);
}
soakQ_L_22Cont soakQ_L_22ContD___deserialize__ (soakQ_L_22Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct soakQ_L_22Cont));
            self->$class = &soakQ_L_22ContG_methods;
            return self;
        }
        self = $DNEW(soakQ_L_22Cont, state);
    }
    self->self = $step_deserialize(state);
    self->C_cont = $step_deserialize(state);
    self->s = $step_deserialize(state);
    return self;
}
soakQ_L_22Cont soakQ_L_22ContG_new(soakQ_main G_1, $Cont G_2, sshQ_Server G_3) {
    soakQ_L_22Cont $tmp = acton_malloc(sizeof(struct soakQ_L_22Cont));
    $tmp->$class = &soakQ_L_22ContG_methods;
    soakQ_L_22ContG_methods.__init__($tmp, G_1, G_2, G_3);
    return $tmp;
}
struct soakQ_L_22ContG_class soakQ_L_22ContG_methods;
$R soakQ_L_23C_12cont (sshQ_ServerSession sess, $Cont C_cont, sshQ_ServerChannel C_13res) {
    sshQ_ServerChannel C_1pre = C_13res;
    #line 54 "src/soak.act"
    ((B_Msg (*) ($WORD, sshQ_ServerChannel))((sshQ_ServerSession)(sess))->$class->accept_channel)(sess, C_1pre);
    return $R_CONT(C_cont, B_None);
}
B_NoneType soakQ_L_24ContD___init__ (soakQ_L_24Cont L_self, sshQ_ServerSession sess, $Cont C_cont) {
    ((soakQ_L_24Cont)(L_self))->sess = sess;
    ((soakQ_L_24Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R soakQ_L_24ContD___call__ (soakQ_L_24Cont L_self, sshQ_ServerChannel G_1) {
    sshQ_ServerSession sess = ((soakQ_L_24Cont)(L_self))->sess;
    $Cont C_cont = ((soakQ_L_24Cont)(L_self))->C_cont;
    return soakQ_L_23C_12cont(sess, C_cont, G_1);
}
void soakQ_L_24ContD___serialize__ (soakQ_L_24Cont self, $Serial$state state) {
    $step_serialize(self->sess, state);
    $step_serialize(self->C_cont, state);
}
soakQ_L_24Cont soakQ_L_24ContD___deserialize__ (soakQ_L_24Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct soakQ_L_24Cont));
            self->$class = &soakQ_L_24ContG_methods;
            return self;
        }
        self = $DNEW(soakQ_L_24Cont, state);
    }
    self->sess = $step_deserialize(state);
    self->C_cont = $step_deserialize(state);
    return self;
}
soakQ_L_24Cont soakQ_L_24ContG_new(sshQ_ServerSession G_1, $Cont G_2) {
    soakQ_L_24Cont $tmp = acton_malloc(sizeof(struct soakQ_L_24Cont));
    $tmp->$class = &soakQ_L_24ContG_methods;
    soakQ_L_24ContG_methods.__init__($tmp, G_1, G_2);
    return $tmp;
}
struct soakQ_L_24ContG_class soakQ_L_24ContG_methods;
B_NoneType soakQ_L_26actionD___init__ (soakQ_L_26action L_self, soakQ_main L_25obj) {
    ((soakQ_L_26action)(L_self))->L_25obj = L_25obj;
    return B_None;
}
$R soakQ_L_26actionD___call__ (soakQ_L_26action L_self, $Cont L_cont, sshQ_ServerChannel G_1, B_bytes G_2) {
    return $AWAIT(L_cont, ((B_Msg (*) ($WORD, sshQ_ServerChannel, B_bytes))((soakQ_L_26action)(L_self))->$class->__asyn__)(L_self, G_1, G_2));
}
$R soakQ_L_26actionD___exec__ (soakQ_L_26action L_self, $Cont L_cont, sshQ_ServerChannel G_1, B_bytes G_2) {
    return $R_CONT(L_cont, ((B_Msg (*) ($WORD, sshQ_ServerChannel, B_bytes))((soakQ_L_26action)(L_self))->$class->__asyn__)(L_self, G_1, G_2));
}
B_Msg soakQ_L_26actionD___asyn__ (soakQ_L_26action L_self, sshQ_ServerChannel G_1, B_bytes G_2) {
    soakQ_main L_25obj = ((soakQ_L_26action)(L_self))->L_25obj;
    return ((B_Msg (*) ($WORD, sshQ_ServerChannel, B_bytes))((soakQ_main)(L_25obj))->$class->srv_on_data)(L_25obj, G_1, G_2);
}
void soakQ_L_26actionD___serialize__ (soakQ_L_26action self, $Serial$state state) {
    $step_serialize(self->L_25obj, state);
}
soakQ_L_26action soakQ_L_26actionD___deserialize__ (soakQ_L_26action self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct soakQ_L_26action));
            self->$class = &soakQ_L_26actionG_methods;
            return self;
        }
        self = $DNEW(soakQ_L_26action, state);
    }
    self->L_25obj = $step_deserialize(state);
    return self;
}
soakQ_L_26action soakQ_L_26actionG_new(soakQ_main G_1) {
    soakQ_L_26action $tmp = acton_malloc(sizeof(struct soakQ_L_26action));
    $tmp->$class = &soakQ_L_26actionG_methods;
    soakQ_L_26actionG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct soakQ_L_26actionG_class soakQ_L_26actionG_methods;
B_NoneType soakQ_L_28actionD___init__ (soakQ_L_28action L_self, soakQ_main L_27obj) {
    ((soakQ_L_28action)(L_self))->L_27obj = L_27obj;
    return B_None;
}
$R soakQ_L_28actionD___call__ (soakQ_L_28action L_self, $Cont L_cont, sshQ_ServerChannel G_1, B_bytes G_2) {
    return $AWAIT(L_cont, ((B_Msg (*) ($WORD, sshQ_ServerChannel, B_bytes))((soakQ_L_28action)(L_self))->$class->__asyn__)(L_self, G_1, G_2));
}
$R soakQ_L_28actionD___exec__ (soakQ_L_28action L_self, $Cont L_cont, sshQ_ServerChannel G_1, B_bytes G_2) {
    return $R_CONT(L_cont, ((B_Msg (*) ($WORD, sshQ_ServerChannel, B_bytes))((soakQ_L_28action)(L_self))->$class->__asyn__)(L_self, G_1, G_2));
}
B_Msg soakQ_L_28actionD___asyn__ (soakQ_L_28action L_self, sshQ_ServerChannel G_1, B_bytes G_2) {
    soakQ_main L_27obj = ((soakQ_L_28action)(L_self))->L_27obj;
    return ((B_Msg (*) ($WORD, sshQ_ServerChannel, B_bytes))((soakQ_main)(L_27obj))->$class->srv_on_stderr)(L_27obj, G_1, G_2);
}
void soakQ_L_28actionD___serialize__ (soakQ_L_28action self, $Serial$state state) {
    $step_serialize(self->L_27obj, state);
}
soakQ_L_28action soakQ_L_28actionD___deserialize__ (soakQ_L_28action self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct soakQ_L_28action));
            self->$class = &soakQ_L_28actionG_methods;
            return self;
        }
        self = $DNEW(soakQ_L_28action, state);
    }
    self->L_27obj = $step_deserialize(state);
    return self;
}
soakQ_L_28action soakQ_L_28actionG_new(soakQ_main G_1) {
    soakQ_L_28action $tmp = acton_malloc(sizeof(struct soakQ_L_28action));
    $tmp->$class = &soakQ_L_28actionG_methods;
    soakQ_L_28actionG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct soakQ_L_28actionG_class soakQ_L_28actionG_methods;
B_NoneType soakQ_L_30actionD___init__ (soakQ_L_30action L_self, soakQ_main L_29obj) {
    ((soakQ_L_30action)(L_self))->L_29obj = L_29obj;
    return B_None;
}
$R soakQ_L_30actionD___call__ (soakQ_L_30action L_self, $Cont L_cont, sshQ_ServerChannel G_1, B_str G_2) {
    return $AWAIT(L_cont, ((B_Msg (*) ($WORD, sshQ_ServerChannel, B_str))((soakQ_L_30action)(L_self))->$class->__asyn__)(L_self, G_1, G_2));
}
$R soakQ_L_30actionD___exec__ (soakQ_L_30action L_self, $Cont L_cont, sshQ_ServerChannel G_1, B_str G_2) {
    return $R_CONT(L_cont, ((B_Msg (*) ($WORD, sshQ_ServerChannel, B_str))((soakQ_L_30action)(L_self))->$class->__asyn__)(L_self, G_1, G_2));
}
B_Msg soakQ_L_30actionD___asyn__ (soakQ_L_30action L_self, sshQ_ServerChannel G_1, B_str G_2) {
    soakQ_main L_29obj = ((soakQ_L_30action)(L_self))->L_29obj;
    return ((B_Msg (*) ($WORD, sshQ_ServerChannel, B_str))((soakQ_main)(L_29obj))->$class->srv_on_close)(L_29obj, G_1, G_2);
}
void soakQ_L_30actionD___serialize__ (soakQ_L_30action self, $Serial$state state) {
    $step_serialize(self->L_29obj, state);
}
soakQ_L_30action soakQ_L_30actionD___deserialize__ (soakQ_L_30action self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct soakQ_L_30action));
            self->$class = &soakQ_L_30actionG_methods;
            return self;
        }
        self = $DNEW(soakQ_L_30action, state);
    }
    self->L_29obj = $step_deserialize(state);
    return self;
}
soakQ_L_30action soakQ_L_30actionG_new(soakQ_main G_1) {
    soakQ_L_30action $tmp = acton_malloc(sizeof(struct soakQ_L_30action));
    $tmp->$class = &soakQ_L_30actionG_methods;
    soakQ_L_30actionG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct soakQ_L_30actionG_class soakQ_L_30actionG_methods;
$R soakQ_L_33C_18cont ($Cont C_cont, B_NoneType C_19res) {
    return $R_CONT(C_cont, B_None);
}
B_NoneType soakQ_L_34ContD___init__ (soakQ_L_34Cont L_self, $Cont C_cont) {
    ((soakQ_L_34Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R soakQ_L_34ContD___call__ (soakQ_L_34Cont L_self, B_NoneType G_1) {
    $Cont C_cont = ((soakQ_L_34Cont)(L_self))->C_cont;
    return soakQ_L_33C_18cont(C_cont, G_1);
}
void soakQ_L_34ContD___serialize__ (soakQ_L_34Cont self, $Serial$state state) {
    $step_serialize(self->C_cont, state);
}
soakQ_L_34Cont soakQ_L_34ContD___deserialize__ (soakQ_L_34Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct soakQ_L_34Cont));
            self->$class = &soakQ_L_34ContG_methods;
            return self;
        }
        self = $DNEW(soakQ_L_34Cont, state);
    }
    self->C_cont = $step_deserialize(state);
    return self;
}
soakQ_L_34Cont soakQ_L_34ContG_new($Cont G_1) {
    soakQ_L_34Cont $tmp = acton_malloc(sizeof(struct soakQ_L_34Cont));
    $tmp->$class = &soakQ_L_34ContG_methods;
    soakQ_L_34ContG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct soakQ_L_34ContG_class soakQ_L_34ContG_methods;
$R soakQ_L_32C_16cont ($Cont C_cont, soakQ_main self, B_NoneType C_17res) {
    return (($R (*) ($WORD, $Cont))((soakQ_main)(self))->$class->start_cycleG_local)(self, (($Cont)soakQ_L_34ContG_new(C_cont)));
}
B_NoneType soakQ_L_35ContD___init__ (soakQ_L_35Cont L_self, $Cont C_cont, soakQ_main self) {
    ((soakQ_L_35Cont)(L_self))->C_cont = C_cont;
    ((soakQ_L_35Cont)(L_self))->self = self;
    return B_None;
}
$R soakQ_L_35ContD___call__ (soakQ_L_35Cont L_self, B_NoneType G_1) {
    $Cont C_cont = ((soakQ_L_35Cont)(L_self))->C_cont;
    soakQ_main self = ((soakQ_L_35Cont)(L_self))->self;
    return soakQ_L_32C_16cont(C_cont, self, G_1);
}
void soakQ_L_35ContD___serialize__ (soakQ_L_35Cont self, $Serial$state state) {
    $step_serialize(self->C_cont, state);
    $step_serialize(self->self, state);
}
soakQ_L_35Cont soakQ_L_35ContD___deserialize__ (soakQ_L_35Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct soakQ_L_35Cont));
            self->$class = &soakQ_L_35ContG_methods;
            return self;
        }
        self = $DNEW(soakQ_L_35Cont, state);
    }
    self->C_cont = $step_deserialize(state);
    self->self = $step_deserialize(state);
    return self;
}
soakQ_L_35Cont soakQ_L_35ContG_new($Cont G_1, soakQ_main G_2) {
    soakQ_L_35Cont $tmp = acton_malloc(sizeof(struct soakQ_L_35Cont));
    $tmp->$class = &soakQ_L_35ContG_methods;
    soakQ_L_35ContG_methods.__init__($tmp, G_1, G_2);
    return $tmp;
}
struct soakQ_L_35ContG_class soakQ_L_35ContG_methods;
$R soakQ_L_31C_14cont ($Cont C_cont, soakQ_main self, B_NoneType C_15res) {
    if (((int64_t)((soakQ_main)(self))->done) >= ((int64_t)((soakQ_main)(self))->cycles)) {
        #line 70 "src/soak.act"
        ((B_NoneType (*) (B_tuple, B_str, B_str, B_bool, B_bool))B_print)($NEWTUPLE(4, to$str("SOAK-DONE ok"), toB_int(((int64_t)((soakQ_main)(self))->ok)), to$str("of"), toB_int(((int64_t)((soakQ_main)(self))->cycles))), B_None, B_None, B_None, B_None);
        #line 71 "src/soak.act"
        if ($ISNOTNONE0(((soakQ_main)(self))->server)) {
            #line 72 "src/soak.act"
            ({ sshQ_Server $tmp = ((sshQ_Server)((soakQ_main)(self))->server);
               ((B_Msg (*) ($WORD))((sshQ_Server)($tmp))->$class->close)($tmp); });
        }
        #line 73 "src/soak.act"
        ((B_Msg (*) ($WORD, int64_t))((B_Env)(((soakQ_main)(self))->env))->$class->exit)(((soakQ_main)(self))->env, (((((int64_t)((soakQ_main)(self))->ok) == ((int64_t)((soakQ_main)(self))->cycles))) ? 0LL : 1LL));
        return $R_CONT(C_cont, B_None);
    }
    else {
        return $R_CONT((($Cont)soakQ_L_35ContG_new(C_cont, self)), B_None);
    }
}
B_NoneType soakQ_L_36ContD___init__ (soakQ_L_36Cont L_self, $Cont C_cont, soakQ_main self) {
    ((soakQ_L_36Cont)(L_self))->C_cont = C_cont;
    ((soakQ_L_36Cont)(L_self))->self = self;
    return B_None;
}
$R soakQ_L_36ContD___call__ (soakQ_L_36Cont L_self, B_NoneType G_1) {
    $Cont C_cont = ((soakQ_L_36Cont)(L_self))->C_cont;
    soakQ_main self = ((soakQ_L_36Cont)(L_self))->self;
    return soakQ_L_31C_14cont(C_cont, self, G_1);
}
void soakQ_L_36ContD___serialize__ (soakQ_L_36Cont self, $Serial$state state) {
    $step_serialize(self->C_cont, state);
    $step_serialize(self->self, state);
}
soakQ_L_36Cont soakQ_L_36ContD___deserialize__ (soakQ_L_36Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct soakQ_L_36Cont));
            self->$class = &soakQ_L_36ContG_methods;
            return self;
        }
        self = $DNEW(soakQ_L_36Cont, state);
    }
    self->C_cont = $step_deserialize(state);
    self->self = $step_deserialize(state);
    return self;
}
soakQ_L_36Cont soakQ_L_36ContG_new($Cont G_1, soakQ_main G_2) {
    soakQ_L_36Cont $tmp = acton_malloc(sizeof(struct soakQ_L_36Cont));
    $tmp->$class = &soakQ_L_36ContG_methods;
    soakQ_L_36ContG_methods.__init__($tmp, G_1, G_2);
    return $tmp;
}
struct soakQ_L_36ContG_class soakQ_L_36ContG_methods;
B_NoneType soakQ_L_37ContD___init__ (soakQ_L_37Cont L_self, $Cont C_cont, soakQ_main self) {
    ((soakQ_L_37Cont)(L_self))->C_cont = C_cont;
    ((soakQ_L_37Cont)(L_self))->self = self;
    return B_None;
}
$R soakQ_L_37ContD___call__ (soakQ_L_37Cont L_self, B_NoneType G_1) {
    $Cont C_cont = ((soakQ_L_37Cont)(L_self))->C_cont;
    soakQ_main self = ((soakQ_L_37Cont)(L_self))->self;
    return soakQ_L_31C_14cont(C_cont, self, G_1);
}
void soakQ_L_37ContD___serialize__ (soakQ_L_37Cont self, $Serial$state state) {
    $step_serialize(self->C_cont, state);
    $step_serialize(self->self, state);
}
soakQ_L_37Cont soakQ_L_37ContD___deserialize__ (soakQ_L_37Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct soakQ_L_37Cont));
            self->$class = &soakQ_L_37ContG_methods;
            return self;
        }
        self = $DNEW(soakQ_L_37Cont, state);
    }
    self->C_cont = $step_deserialize(state);
    self->self = $step_deserialize(state);
    return self;
}
soakQ_L_37Cont soakQ_L_37ContG_new($Cont G_1, soakQ_main G_2) {
    soakQ_L_37Cont $tmp = acton_malloc(sizeof(struct soakQ_L_37Cont));
    $tmp->$class = &soakQ_L_37ContG_methods;
    soakQ_L_37ContG_methods.__init__($tmp, G_1, G_2);
    return $tmp;
}
struct soakQ_L_37ContG_class soakQ_L_37ContG_methods;
#line 82 "src/soak.act"
$R soakQ_L_40on_run_exit (soakQ_main self, sshQ_Client c, $Cont C_cont, sshQ_Channel ch, int64_t code, B_str sig, B_bytes out, B_bytes eb, B_str error) {
    B_Eq W_main_577 = (B_Eq)B_OrdD_bytesG_witness;
    #line 83 "src/soak.act"
    if (((B_bool)$AND(B_bool, $AND(B_bool, toB_bool($ISNONE0(error)), toB_bool((code == 0LL))), ((B_bool (*) ($WORD, B_bytes, B_bytes))((B_Eq)(W_main_577))->$class->__eq__)(W_main_577, out, to$bytesD_len("ok\n", 3))))->val) {
        ((soakQ_main)(self))->ok += 1LL;
    }
    #line 85 "src/soak.act"
    ((B_Msg (*) ($WORD))((sshQ_Client)(c))->$class->close)(c);
    return $R_CONT(C_cont, B_None);
}
$R soakQ_L_41C_22cont ($Cont C_cont, sshQ_RunCommand C_23res) {
    return $R_CONT(C_cont, B_None);
}
B_NoneType soakQ_L_42ContD___init__ (soakQ_L_42Cont L_self, $Cont C_cont) {
    ((soakQ_L_42Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R soakQ_L_42ContD___call__ (soakQ_L_42Cont L_self, sshQ_RunCommand G_1) {
    $Cont C_cont = ((soakQ_L_42Cont)(L_self))->C_cont;
    return soakQ_L_41C_22cont(C_cont, G_1);
}
void soakQ_L_42ContD___serialize__ (soakQ_L_42Cont self, $Serial$state state) {
    $step_serialize(self->C_cont, state);
}
soakQ_L_42Cont soakQ_L_42ContD___deserialize__ (soakQ_L_42Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct soakQ_L_42Cont));
            self->$class = &soakQ_L_42ContG_methods;
            return self;
        }
        self = $DNEW(soakQ_L_42Cont, state);
    }
    self->C_cont = $step_deserialize(state);
    return self;
}
soakQ_L_42Cont soakQ_L_42ContG_new($Cont G_1) {
    soakQ_L_42Cont $tmp = acton_malloc(sizeof(struct soakQ_L_42Cont));
    $tmp->$class = &soakQ_L_42ContG_methods;
    soakQ_L_42ContG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct soakQ_L_42ContG_class soakQ_L_42ContG_methods;
B_NoneType soakQ_L_43procD___init__ (soakQ_L_43proc L_self, sshQ_Channel G_1, int64_t G_2, B_str G_3, B_bytes G_4, B_bytes G_5, B_str G_6, sshQ_Client c, soakQ_main self) {
    ((soakQ_L_43proc)(L_self))->G_1 = G_1;
    ((soakQ_L_43proc)(L_self))->G_2 = G_2;
    ((soakQ_L_43proc)(L_self))->G_3 = G_3;
    ((soakQ_L_43proc)(L_self))->G_4 = G_4;
    ((soakQ_L_43proc)(L_self))->G_5 = G_5;
    ((soakQ_L_43proc)(L_self))->G_6 = G_6;
    ((soakQ_L_43proc)(L_self))->c = c;
    ((soakQ_L_43proc)(L_self))->self = self;
    return B_None;
}
$R soakQ_L_43procD___call__ (soakQ_L_43proc L_self, $Cont C_cont) {
    sshQ_Channel G_1 = ((soakQ_L_43proc)(L_self))->G_1;
    int64_t G_2 = ((int64_t)((soakQ_L_43proc)(L_self))->G_2);
    B_str G_3 = ((soakQ_L_43proc)(L_self))->G_3;
    B_bytes G_4 = ((soakQ_L_43proc)(L_self))->G_4;
    B_bytes G_5 = ((soakQ_L_43proc)(L_self))->G_5;
    B_str G_6 = ((soakQ_L_43proc)(L_self))->G_6;
    sshQ_Client c = ((soakQ_L_43proc)(L_self))->c;
    soakQ_main self = ((soakQ_L_43proc)(L_self))->self;
    return soakQ_L_40on_run_exit(self, c, C_cont, G_1, G_2, G_3, G_4, G_5, G_6);
}
$R soakQ_L_43procD___exec__ (soakQ_L_43proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((soakQ_L_43proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void soakQ_L_43procD___serialize__ (soakQ_L_43proc self, $Serial$state state) {
    $step_serialize(self->G_1, state);
    $val_serialize(I64_ID, &self->G_2, state);
    $step_serialize(self->G_3, state);
    $step_serialize(self->G_4, state);
    $step_serialize(self->G_5, state);
    $step_serialize(self->G_6, state);
    $step_serialize(self->c, state);
    $step_serialize(self->self, state);
}
soakQ_L_43proc soakQ_L_43procD___deserialize__ (soakQ_L_43proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct soakQ_L_43proc));
            self->$class = &soakQ_L_43procG_methods;
            return self;
        }
        self = $DNEW(soakQ_L_43proc, state);
    }
    self->G_1 = $step_deserialize(state);
    $tmp = $val_deserialize(state);
    memcpy(&self->G_2, &$tmp, sizeof(self->G_2));
    self->G_3 = $step_deserialize(state);
    self->G_4 = $step_deserialize(state);
    self->G_5 = $step_deserialize(state);
    self->G_6 = $step_deserialize(state);
    self->c = $step_deserialize(state);
    self->self = $step_deserialize(state);
    return self;
}
soakQ_L_43proc soakQ_L_43procG_new(sshQ_Channel G_1, int64_t G_2, B_str G_3, B_bytes G_4, B_bytes G_5, B_str G_6, sshQ_Client G_7, soakQ_main G_8) {
    soakQ_L_43proc $tmp = acton_malloc(sizeof(struct soakQ_L_43proc));
    $tmp->$class = &soakQ_L_43procG_methods;
    soakQ_L_43procG_methods.__init__($tmp, G_1, G_2, G_3, G_4, G_5, G_6, G_7, G_8);
    return $tmp;
}
struct soakQ_L_43procG_class soakQ_L_43procG_methods;
B_NoneType soakQ_L_44actionD___init__ (soakQ_L_44action L_self, sshQ_Client c, soakQ_main self) {
    ((soakQ_L_44action)(L_self))->c = c;
    ((soakQ_L_44action)(L_self))->self = self;
    return B_None;
}
$R soakQ_L_44actionD___call__ (soakQ_L_44action L_self, $Cont L_cont, sshQ_Channel G_1, B_int G_2, B_str G_3, B_bytes G_4, B_bytes G_5, B_str G_6) {
    return $AWAIT(L_cont, ((B_Msg (*) ($WORD, sshQ_Channel, B_int, B_str, B_bytes, B_bytes, B_str))((soakQ_L_44action)(L_self))->$class->__asyn__)(L_self, G_1, G_2, G_3, G_4, G_5, G_6));
}
$R soakQ_L_44actionD___exec__ (soakQ_L_44action L_self, $Cont L_cont, sshQ_Channel G_1, B_int G_2, B_str G_3, B_bytes G_4, B_bytes G_5, B_str G_6) {
    return $R_CONT(L_cont, ((B_Msg (*) ($WORD, sshQ_Channel, B_int, B_str, B_bytes, B_bytes, B_str))((soakQ_L_44action)(L_self))->$class->__asyn__)(L_self, G_1, G_2, G_3, G_4, G_5, G_6));
}
B_Msg soakQ_L_44actionD___asyn__ (soakQ_L_44action L_self, sshQ_Channel G_1, B_int G_2, B_str G_3, B_bytes G_4, B_bytes G_5, B_str G_6) {
    sshQ_Client c = ((soakQ_L_44action)(L_self))->c;
    soakQ_main self = ((soakQ_L_44action)(L_self))->self;
    return $ASYNC((($Actor)self), (($Cont)soakQ_L_43procG_new(G_1, ((B_int)G_2)->val, G_3, G_4, G_5, G_6, c, self)));
}
void soakQ_L_44actionD___serialize__ (soakQ_L_44action self, $Serial$state state) {
    $step_serialize(self->c, state);
    $step_serialize(self->self, state);
}
soakQ_L_44action soakQ_L_44actionD___deserialize__ (soakQ_L_44action self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct soakQ_L_44action));
            self->$class = &soakQ_L_44actionG_methods;
            return self;
        }
        self = $DNEW(soakQ_L_44action, state);
    }
    self->c = $step_deserialize(state);
    self->self = $step_deserialize(state);
    return self;
}
soakQ_L_44action soakQ_L_44actionG_new(sshQ_Client G_1, soakQ_main G_2) {
    soakQ_L_44action $tmp = acton_malloc(sizeof(struct soakQ_L_44action));
    $tmp->$class = &soakQ_L_44actionG_methods;
    soakQ_L_44actionG_methods.__init__($tmp, G_1, G_2);
    return $tmp;
}
struct soakQ_L_44actionG_class soakQ_L_44actionG_methods;
$R soakQ_L_39C_20cont (soakQ_main self, sshQ_Client c, $Cont C_cont, B_NoneType C_21res) {
    return sshQ_RunCommandG_newact((($Cont)soakQ_L_42ContG_new(C_cont)), c, to$str("go"), (($action)soakQ_L_44actionG_new(c, self)), toB_float(10.0));
}
$R soakQ_L_45C_24cont ($Cont C_cont, B_NoneType C_25res) {
    return $R_CONT(C_cont, B_None);
}
B_NoneType soakQ_L_46ContD___init__ (soakQ_L_46Cont L_self, $Cont C_cont) {
    ((soakQ_L_46Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R soakQ_L_46ContD___call__ (soakQ_L_46Cont L_self, B_NoneType G_1) {
    $Cont C_cont = ((soakQ_L_46Cont)(L_self))->C_cont;
    return soakQ_L_45C_24cont(C_cont, G_1);
}
void soakQ_L_46ContD___serialize__ (soakQ_L_46Cont self, $Serial$state state) {
    $step_serialize(self->C_cont, state);
}
soakQ_L_46Cont soakQ_L_46ContD___deserialize__ (soakQ_L_46Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct soakQ_L_46Cont));
            self->$class = &soakQ_L_46ContG_methods;
            return self;
        }
        self = $DNEW(soakQ_L_46Cont, state);
    }
    self->C_cont = $step_deserialize(state);
    return self;
}
soakQ_L_46Cont soakQ_L_46ContG_new($Cont G_1) {
    soakQ_L_46Cont $tmp = acton_malloc(sizeof(struct soakQ_L_46Cont));
    $tmp->$class = &soakQ_L_46ContG_methods;
    soakQ_L_46ContG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct soakQ_L_46ContG_class soakQ_L_46ContG_methods;
B_NoneType soakQ_L_47ContD___init__ (soakQ_L_47Cont L_self, soakQ_main self, sshQ_Client c, $Cont C_cont) {
    ((soakQ_L_47Cont)(L_self))->self = self;
    ((soakQ_L_47Cont)(L_self))->c = c;
    ((soakQ_L_47Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R soakQ_L_47ContD___call__ (soakQ_L_47Cont L_self, B_NoneType G_1) {
    soakQ_main self = ((soakQ_L_47Cont)(L_self))->self;
    sshQ_Client c = ((soakQ_L_47Cont)(L_self))->c;
    $Cont C_cont = ((soakQ_L_47Cont)(L_self))->C_cont;
    return soakQ_L_39C_20cont(self, c, C_cont, G_1);
}
void soakQ_L_47ContD___serialize__ (soakQ_L_47Cont self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->c, state);
    $step_serialize(self->C_cont, state);
}
soakQ_L_47Cont soakQ_L_47ContD___deserialize__ (soakQ_L_47Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct soakQ_L_47Cont));
            self->$class = &soakQ_L_47ContG_methods;
            return self;
        }
        self = $DNEW(soakQ_L_47Cont, state);
    }
    self->self = $step_deserialize(state);
    self->c = $step_deserialize(state);
    self->C_cont = $step_deserialize(state);
    return self;
}
soakQ_L_47Cont soakQ_L_47ContG_new(soakQ_main G_1, sshQ_Client G_2, $Cont G_3) {
    soakQ_L_47Cont $tmp = acton_malloc(sizeof(struct soakQ_L_47Cont));
    $tmp->$class = &soakQ_L_47ContG_methods;
    soakQ_L_47ContG_methods.__init__($tmp, G_1, G_2, G_3);
    return $tmp;
}
struct soakQ_L_47ContG_class soakQ_L_47ContG_methods;
#line 78 "src/soak.act"
$R soakQ_L_38on_connect (soakQ_main self, $Cont C_cont, sshQ_Client c, B_str err) {
    B_Plus W_main_559 = (B_Plus)B_TimesD_strG_witness;
    if ($ISNOTNONE0(err)) {
        return (($R (*) ($WORD, $Cont, B_str))((soakQ_main)(self))->$class->failG_local)(self, (($Cont)soakQ_L_46ContG_new(C_cont)), ((B_str (*) ($WORD, B_str, B_str))((B_Plus)(W_main_559))->$class->__add__)(W_main_559, to$str("connect: "), ((B_str)err)));
    }
    else {
        return $R_CONT((($Cont)soakQ_L_47ContG_new(self, c, C_cont)), B_None);
    }
}
$R soakQ_L_49C_26cont ($Cont C_cont, B_NoneType C_27res) {
    return $R_CONT(C_cont, B_None);
}
B_NoneType soakQ_L_50ContD___init__ (soakQ_L_50Cont L_self, $Cont C_cont) {
    ((soakQ_L_50Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R soakQ_L_50ContD___call__ (soakQ_L_50Cont L_self, B_NoneType G_1) {
    $Cont C_cont = ((soakQ_L_50Cont)(L_self))->C_cont;
    return soakQ_L_49C_26cont(C_cont, G_1);
}
void soakQ_L_50ContD___serialize__ (soakQ_L_50Cont self, $Serial$state state) {
    $step_serialize(self->C_cont, state);
}
soakQ_L_50Cont soakQ_L_50ContD___deserialize__ (soakQ_L_50Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct soakQ_L_50Cont));
            self->$class = &soakQ_L_50ContG_methods;
            return self;
        }
        self = $DNEW(soakQ_L_50Cont, state);
    }
    self->C_cont = $step_deserialize(state);
    return self;
}
soakQ_L_50Cont soakQ_L_50ContG_new($Cont G_1) {
    soakQ_L_50Cont $tmp = acton_malloc(sizeof(struct soakQ_L_50Cont));
    $tmp->$class = &soakQ_L_50ContG_methods;
    soakQ_L_50ContG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct soakQ_L_50ContG_class soakQ_L_50ContG_methods;
#line 88 "src/soak.act"
$R soakQ_L_48on_close (soakQ_main self, $Cont C_cont, sshQ_Client c, B_str reason) {
    return (($R (*) ($WORD, $Cont))((soakQ_main)(self))->$class->next_cycleG_local)(self, (($Cont)soakQ_L_50ContG_new(C_cont)));
}
$R soakQ_L_51C_28cont ($Cont C_cont, sshQ_Client C_29res) {
    return $R_CONT(C_cont, B_None);
}
B_NoneType soakQ_L_52ContD___init__ (soakQ_L_52Cont L_self, $Cont C_cont) {
    ((soakQ_L_52Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R soakQ_L_52ContD___call__ (soakQ_L_52Cont L_self, sshQ_Client G_1) {
    $Cont C_cont = ((soakQ_L_52Cont)(L_self))->C_cont;
    return soakQ_L_51C_28cont(C_cont, G_1);
}
void soakQ_L_52ContD___serialize__ (soakQ_L_52Cont self, $Serial$state state) {
    $step_serialize(self->C_cont, state);
}
soakQ_L_52Cont soakQ_L_52ContD___deserialize__ (soakQ_L_52Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct soakQ_L_52Cont));
            self->$class = &soakQ_L_52ContG_methods;
            return self;
        }
        self = $DNEW(soakQ_L_52Cont, state);
    }
    self->C_cont = $step_deserialize(state);
    return self;
}
soakQ_L_52Cont soakQ_L_52ContG_new($Cont G_1) {
    soakQ_L_52Cont $tmp = acton_malloc(sizeof(struct soakQ_L_52Cont));
    $tmp->$class = &soakQ_L_52ContG_methods;
    soakQ_L_52ContG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct soakQ_L_52ContG_class soakQ_L_52ContG_methods;
B_NoneType soakQ_L_53procD___init__ (soakQ_L_53proc L_self, sshQ_Client G_1, B_str G_2, soakQ_main self) {
    ((soakQ_L_53proc)(L_self))->G_1 = G_1;
    ((soakQ_L_53proc)(L_self))->G_2 = G_2;
    ((soakQ_L_53proc)(L_self))->self = self;
    return B_None;
}
$R soakQ_L_53procD___call__ (soakQ_L_53proc L_self, $Cont C_cont) {
    sshQ_Client G_1 = ((soakQ_L_53proc)(L_self))->G_1;
    B_str G_2 = ((soakQ_L_53proc)(L_self))->G_2;
    soakQ_main self = ((soakQ_L_53proc)(L_self))->self;
    return soakQ_L_38on_connect(self, C_cont, G_1, G_2);
}
$R soakQ_L_53procD___exec__ (soakQ_L_53proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((soakQ_L_53proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void soakQ_L_53procD___serialize__ (soakQ_L_53proc self, $Serial$state state) {
    $step_serialize(self->G_1, state);
    $step_serialize(self->G_2, state);
    $step_serialize(self->self, state);
}
soakQ_L_53proc soakQ_L_53procD___deserialize__ (soakQ_L_53proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct soakQ_L_53proc));
            self->$class = &soakQ_L_53procG_methods;
            return self;
        }
        self = $DNEW(soakQ_L_53proc, state);
    }
    self->G_1 = $step_deserialize(state);
    self->G_2 = $step_deserialize(state);
    self->self = $step_deserialize(state);
    return self;
}
soakQ_L_53proc soakQ_L_53procG_new(sshQ_Client G_1, B_str G_2, soakQ_main G_3) {
    soakQ_L_53proc $tmp = acton_malloc(sizeof(struct soakQ_L_53proc));
    $tmp->$class = &soakQ_L_53procG_methods;
    soakQ_L_53procG_methods.__init__($tmp, G_1, G_2, G_3);
    return $tmp;
}
struct soakQ_L_53procG_class soakQ_L_53procG_methods;
B_NoneType soakQ_L_54actionD___init__ (soakQ_L_54action L_self, soakQ_main self) {
    ((soakQ_L_54action)(L_self))->self = self;
    return B_None;
}
$R soakQ_L_54actionD___call__ (soakQ_L_54action L_self, $Cont L_cont, sshQ_Client G_1, B_str G_2) {
    return $AWAIT(L_cont, ((B_Msg (*) ($WORD, sshQ_Client, B_str))((soakQ_L_54action)(L_self))->$class->__asyn__)(L_self, G_1, G_2));
}
$R soakQ_L_54actionD___exec__ (soakQ_L_54action L_self, $Cont L_cont, sshQ_Client G_1, B_str G_2) {
    return $R_CONT(L_cont, ((B_Msg (*) ($WORD, sshQ_Client, B_str))((soakQ_L_54action)(L_self))->$class->__asyn__)(L_self, G_1, G_2));
}
B_Msg soakQ_L_54actionD___asyn__ (soakQ_L_54action L_self, sshQ_Client G_1, B_str G_2) {
    soakQ_main self = ((soakQ_L_54action)(L_self))->self;
    return $ASYNC((($Actor)self), (($Cont)soakQ_L_53procG_new(G_1, G_2, self)));
}
void soakQ_L_54actionD___serialize__ (soakQ_L_54action self, $Serial$state state) {
    $step_serialize(self->self, state);
}
soakQ_L_54action soakQ_L_54actionD___deserialize__ (soakQ_L_54action self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct soakQ_L_54action));
            self->$class = &soakQ_L_54actionG_methods;
            return self;
        }
        self = $DNEW(soakQ_L_54action, state);
    }
    self->self = $step_deserialize(state);
    return self;
}
soakQ_L_54action soakQ_L_54actionG_new(soakQ_main G_1) {
    soakQ_L_54action $tmp = acton_malloc(sizeof(struct soakQ_L_54action));
    $tmp->$class = &soakQ_L_54actionG_methods;
    soakQ_L_54actionG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct soakQ_L_54actionG_class soakQ_L_54actionG_methods;
B_NoneType soakQ_L_55procD___init__ (soakQ_L_55proc L_self, sshQ_Client G_1, B_str G_2, soakQ_main self) {
    ((soakQ_L_55proc)(L_self))->G_1 = G_1;
    ((soakQ_L_55proc)(L_self))->G_2 = G_2;
    ((soakQ_L_55proc)(L_self))->self = self;
    return B_None;
}
$R soakQ_L_55procD___call__ (soakQ_L_55proc L_self, $Cont C_cont) {
    sshQ_Client G_1 = ((soakQ_L_55proc)(L_self))->G_1;
    B_str G_2 = ((soakQ_L_55proc)(L_self))->G_2;
    soakQ_main self = ((soakQ_L_55proc)(L_self))->self;
    return soakQ_L_48on_close(self, C_cont, G_1, G_2);
}
$R soakQ_L_55procD___exec__ (soakQ_L_55proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((soakQ_L_55proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void soakQ_L_55procD___serialize__ (soakQ_L_55proc self, $Serial$state state) {
    $step_serialize(self->G_1, state);
    $step_serialize(self->G_2, state);
    $step_serialize(self->self, state);
}
soakQ_L_55proc soakQ_L_55procD___deserialize__ (soakQ_L_55proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct soakQ_L_55proc));
            self->$class = &soakQ_L_55procG_methods;
            return self;
        }
        self = $DNEW(soakQ_L_55proc, state);
    }
    self->G_1 = $step_deserialize(state);
    self->G_2 = $step_deserialize(state);
    self->self = $step_deserialize(state);
    return self;
}
soakQ_L_55proc soakQ_L_55procG_new(sshQ_Client G_1, B_str G_2, soakQ_main G_3) {
    soakQ_L_55proc $tmp = acton_malloc(sizeof(struct soakQ_L_55proc));
    $tmp->$class = &soakQ_L_55procG_methods;
    soakQ_L_55procG_methods.__init__($tmp, G_1, G_2, G_3);
    return $tmp;
}
struct soakQ_L_55procG_class soakQ_L_55procG_methods;
B_NoneType soakQ_L_56actionD___init__ (soakQ_L_56action L_self, soakQ_main self) {
    ((soakQ_L_56action)(L_self))->self = self;
    return B_None;
}
$R soakQ_L_56actionD___call__ (soakQ_L_56action L_self, $Cont L_cont, sshQ_Client G_1, B_str G_2) {
    return $AWAIT(L_cont, ((B_Msg (*) ($WORD, sshQ_Client, B_str))((soakQ_L_56action)(L_self))->$class->__asyn__)(L_self, G_1, G_2));
}
$R soakQ_L_56actionD___exec__ (soakQ_L_56action L_self, $Cont L_cont, sshQ_Client G_1, B_str G_2) {
    return $R_CONT(L_cont, ((B_Msg (*) ($WORD, sshQ_Client, B_str))((soakQ_L_56action)(L_self))->$class->__asyn__)(L_self, G_1, G_2));
}
B_Msg soakQ_L_56actionD___asyn__ (soakQ_L_56action L_self, sshQ_Client G_1, B_str G_2) {
    soakQ_main self = ((soakQ_L_56action)(L_self))->self;
    return $ASYNC((($Actor)self), (($Cont)soakQ_L_55procG_new(G_1, G_2, self)));
}
void soakQ_L_56actionD___serialize__ (soakQ_L_56action self, $Serial$state state) {
    $step_serialize(self->self, state);
}
soakQ_L_56action soakQ_L_56actionD___deserialize__ (soakQ_L_56action self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct soakQ_L_56action));
            self->$class = &soakQ_L_56actionG_methods;
            return self;
        }
        self = $DNEW(soakQ_L_56action, state);
    }
    self->self = $step_deserialize(state);
    return self;
}
soakQ_L_56action soakQ_L_56actionG_new(soakQ_main G_1) {
    soakQ_L_56action $tmp = acton_malloc(sizeof(struct soakQ_L_56action));
    $tmp->$class = &soakQ_L_56actionG_methods;
    soakQ_L_56actionG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct soakQ_L_56actionG_class soakQ_L_56actionG_methods;
B_NoneType soakQ_L_58actionD___init__ (soakQ_L_58action L_self, soakQ_main L_57obj) {
    ((soakQ_L_58action)(L_self))->L_57obj = L_57obj;
    return B_None;
}
$R soakQ_L_58actionD___call__ (soakQ_L_58action L_self, $Cont L_cont, sshQ_Client G_1, B_str G_2, sshQ_HostKeyInfo G_3) {
    return $AWAIT(L_cont, ((B_Msg (*) ($WORD, sshQ_Client, B_str, sshQ_HostKeyInfo))((soakQ_L_58action)(L_self))->$class->__asyn__)(L_self, G_1, G_2, G_3));
}
$R soakQ_L_58actionD___exec__ (soakQ_L_58action L_self, $Cont L_cont, sshQ_Client G_1, B_str G_2, sshQ_HostKeyInfo G_3) {
    return $R_CONT(L_cont, ((B_Msg (*) ($WORD, sshQ_Client, B_str, sshQ_HostKeyInfo))((soakQ_L_58action)(L_self))->$class->__asyn__)(L_self, G_1, G_2, G_3));
}
B_Msg soakQ_L_58actionD___asyn__ (soakQ_L_58action L_self, sshQ_Client G_1, B_str G_2, sshQ_HostKeyInfo G_3) {
    soakQ_main L_57obj = ((soakQ_L_58action)(L_self))->L_57obj;
    return ((B_Msg (*) ($WORD, sshQ_Client, B_str, sshQ_HostKeyInfo))((soakQ_main)(L_57obj))->$class->on_hostkey)(L_57obj, G_1, G_2, G_3);
}
void soakQ_L_58actionD___serialize__ (soakQ_L_58action self, $Serial$state state) {
    $step_serialize(self->L_57obj, state);
}
soakQ_L_58action soakQ_L_58actionD___deserialize__ (soakQ_L_58action self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct soakQ_L_58action));
            self->$class = &soakQ_L_58actionG_methods;
            return self;
        }
        self = $DNEW(soakQ_L_58action, state);
    }
    self->L_57obj = $step_deserialize(state);
    return self;
}
soakQ_L_58action soakQ_L_58actionG_new(soakQ_main G_1) {
    soakQ_L_58action $tmp = acton_malloc(sizeof(struct soakQ_L_58action));
    $tmp->$class = &soakQ_L_58actionG_methods;
    soakQ_L_58actionG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct soakQ_L_58actionG_class soakQ_L_58actionG_methods;
B_NoneType soakQ_L_59procD___init__ (soakQ_L_59proc L_self, soakQ_main self) {
    ((soakQ_L_59proc)(L_self))->self = self;
    return B_None;
}
$R soakQ_L_59procD___call__ (soakQ_L_59proc L_self, $Cont C_cont) {
    soakQ_main self = ((soakQ_L_59proc)(L_self))->self;
    return (($R (*) ($WORD, $Cont))((soakQ_main)(self))->$class->reportG_local)(self, C_cont);
}
$R soakQ_L_59procD___exec__ (soakQ_L_59proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((soakQ_L_59proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void soakQ_L_59procD___serialize__ (soakQ_L_59proc self, $Serial$state state) {
    $step_serialize(self->self, state);
}
soakQ_L_59proc soakQ_L_59procD___deserialize__ (soakQ_L_59proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct soakQ_L_59proc));
            self->$class = &soakQ_L_59procG_methods;
            return self;
        }
        self = $DNEW(soakQ_L_59proc, state);
    }
    self->self = $step_deserialize(state);
    return self;
}
soakQ_L_59proc soakQ_L_59procG_new(soakQ_main G_1) {
    soakQ_L_59proc $tmp = acton_malloc(sizeof(struct soakQ_L_59proc));
    $tmp->$class = &soakQ_L_59procG_methods;
    soakQ_L_59procG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct soakQ_L_59procG_class soakQ_L_59procG_methods;
B_NoneType soakQ_L_60procD___init__ (soakQ_L_60proc L_self, soakQ_main self, B_str msg) {
    ((soakQ_L_60proc)(L_self))->self = self;
    ((soakQ_L_60proc)(L_self))->msg = msg;
    return B_None;
}
$R soakQ_L_60procD___call__ (soakQ_L_60proc L_self, $Cont C_cont) {
    soakQ_main self = ((soakQ_L_60proc)(L_self))->self;
    B_str msg = ((soakQ_L_60proc)(L_self))->msg;
    return (($R (*) ($WORD, $Cont, B_str))((soakQ_main)(self))->$class->failG_local)(self, C_cont, msg);
}
$R soakQ_L_60procD___exec__ (soakQ_L_60proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((soakQ_L_60proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void soakQ_L_60procD___serialize__ (soakQ_L_60proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->msg, state);
}
soakQ_L_60proc soakQ_L_60procD___deserialize__ (soakQ_L_60proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct soakQ_L_60proc));
            self->$class = &soakQ_L_60procG_methods;
            return self;
        }
        self = $DNEW(soakQ_L_60proc, state);
    }
    self->self = $step_deserialize(state);
    self->msg = $step_deserialize(state);
    return self;
}
soakQ_L_60proc soakQ_L_60procG_new(soakQ_main G_1, B_str G_2) {
    soakQ_L_60proc $tmp = acton_malloc(sizeof(struct soakQ_L_60proc));
    $tmp->$class = &soakQ_L_60procG_methods;
    soakQ_L_60procG_methods.__init__($tmp, G_1, G_2);
    return $tmp;
}
struct soakQ_L_60procG_class soakQ_L_60procG_methods;
B_NoneType soakQ_L_61procD___init__ (soakQ_L_61proc L_self, soakQ_main self, sshQ_Server s, B_str err) {
    ((soakQ_L_61proc)(L_self))->self = self;
    ((soakQ_L_61proc)(L_self))->s = s;
    ((soakQ_L_61proc)(L_self))->err = err;
    return B_None;
}
$R soakQ_L_61procD___call__ (soakQ_L_61proc L_self, $Cont C_cont) {
    soakQ_main self = ((soakQ_L_61proc)(L_self))->self;
    sshQ_Server s = ((soakQ_L_61proc)(L_self))->s;
    B_str err = ((soakQ_L_61proc)(L_self))->err;
    return (($R (*) ($WORD, $Cont, sshQ_Server, B_str))((soakQ_main)(self))->$class->on_listenG_local)(self, C_cont, s, err);
}
$R soakQ_L_61procD___exec__ (soakQ_L_61proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((soakQ_L_61proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void soakQ_L_61procD___serialize__ (soakQ_L_61proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->s, state);
    $step_serialize(self->err, state);
}
soakQ_L_61proc soakQ_L_61procD___deserialize__ (soakQ_L_61proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct soakQ_L_61proc));
            self->$class = &soakQ_L_61procG_methods;
            return self;
        }
        self = $DNEW(soakQ_L_61proc, state);
    }
    self->self = $step_deserialize(state);
    self->s = $step_deserialize(state);
    self->err = $step_deserialize(state);
    return self;
}
soakQ_L_61proc soakQ_L_61procG_new(soakQ_main G_1, sshQ_Server G_2, B_str G_3) {
    soakQ_L_61proc $tmp = acton_malloc(sizeof(struct soakQ_L_61proc));
    $tmp->$class = &soakQ_L_61procG_methods;
    soakQ_L_61procG_methods.__init__($tmp, G_1, G_2, G_3);
    return $tmp;
}
struct soakQ_L_61procG_class soakQ_L_61procG_methods;
B_NoneType soakQ_L_62procD___init__ (soakQ_L_62proc L_self, soakQ_main self, sshQ_Server s, B_str reason) {
    ((soakQ_L_62proc)(L_self))->self = self;
    ((soakQ_L_62proc)(L_self))->s = s;
    ((soakQ_L_62proc)(L_self))->reason = reason;
    return B_None;
}
$R soakQ_L_62procD___call__ (soakQ_L_62proc L_self, $Cont C_cont) {
    soakQ_main self = ((soakQ_L_62proc)(L_self))->self;
    sshQ_Server s = ((soakQ_L_62proc)(L_self))->s;
    B_str reason = ((soakQ_L_62proc)(L_self))->reason;
    return (($R (*) ($WORD, $Cont, sshQ_Server, B_str))((soakQ_main)(self))->$class->on_server_closeG_local)(self, C_cont, s, reason);
}
$R soakQ_L_62procD___exec__ (soakQ_L_62proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((soakQ_L_62proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void soakQ_L_62procD___serialize__ (soakQ_L_62proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->s, state);
    $step_serialize(self->reason, state);
}
soakQ_L_62proc soakQ_L_62procD___deserialize__ (soakQ_L_62proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct soakQ_L_62proc));
            self->$class = &soakQ_L_62procG_methods;
            return self;
        }
        self = $DNEW(soakQ_L_62proc, state);
    }
    self->self = $step_deserialize(state);
    self->s = $step_deserialize(state);
    self->reason = $step_deserialize(state);
    return self;
}
soakQ_L_62proc soakQ_L_62procG_new(soakQ_main G_1, sshQ_Server G_2, B_str G_3) {
    soakQ_L_62proc $tmp = acton_malloc(sizeof(struct soakQ_L_62proc));
    $tmp->$class = &soakQ_L_62procG_methods;
    soakQ_L_62procG_methods.__init__($tmp, G_1, G_2, G_3);
    return $tmp;
}
struct soakQ_L_62procG_class soakQ_L_62procG_methods;
B_NoneType soakQ_L_63procD___init__ (soakQ_L_63proc L_self, soakQ_main self, sshQ_ServerSession sess) {
    ((soakQ_L_63proc)(L_self))->self = self;
    ((soakQ_L_63proc)(L_self))->sess = sess;
    return B_None;
}
$R soakQ_L_63procD___call__ (soakQ_L_63proc L_self, $Cont C_cont) {
    soakQ_main self = ((soakQ_L_63proc)(L_self))->self;
    sshQ_ServerSession sess = ((soakQ_L_63proc)(L_self))->sess;
    return (($R (*) ($WORD, $Cont, sshQ_ServerSession))((soakQ_main)(self))->$class->on_sessionG_local)(self, C_cont, sess);
}
$R soakQ_L_63procD___exec__ (soakQ_L_63proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((soakQ_L_63proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void soakQ_L_63procD___serialize__ (soakQ_L_63proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->sess, state);
}
soakQ_L_63proc soakQ_L_63procD___deserialize__ (soakQ_L_63proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct soakQ_L_63proc));
            self->$class = &soakQ_L_63procG_methods;
            return self;
        }
        self = $DNEW(soakQ_L_63proc, state);
    }
    self->self = $step_deserialize(state);
    self->sess = $step_deserialize(state);
    return self;
}
soakQ_L_63proc soakQ_L_63procG_new(soakQ_main G_1, sshQ_ServerSession G_2) {
    soakQ_L_63proc $tmp = acton_malloc(sizeof(struct soakQ_L_63proc));
    $tmp->$class = &soakQ_L_63procG_methods;
    soakQ_L_63procG_methods.__init__($tmp, G_1, G_2);
    return $tmp;
}
struct soakQ_L_63procG_class soakQ_L_63procG_methods;
B_NoneType soakQ_L_64procD___init__ (soakQ_L_64proc L_self, soakQ_main self, sshQ_ServerSession sess, sshQ_AuthRequest req) {
    ((soakQ_L_64proc)(L_self))->self = self;
    ((soakQ_L_64proc)(L_self))->sess = sess;
    ((soakQ_L_64proc)(L_self))->req = req;
    return B_None;
}
$R soakQ_L_64procD___call__ (soakQ_L_64proc L_self, $Cont C_cont) {
    soakQ_main self = ((soakQ_L_64proc)(L_self))->self;
    sshQ_ServerSession sess = ((soakQ_L_64proc)(L_self))->sess;
    sshQ_AuthRequest req = ((soakQ_L_64proc)(L_self))->req;
    return (($R (*) ($WORD, $Cont, sshQ_ServerSession, sshQ_AuthRequest))((soakQ_main)(self))->$class->on_authG_local)(self, C_cont, sess, req);
}
$R soakQ_L_64procD___exec__ (soakQ_L_64proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((soakQ_L_64proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void soakQ_L_64procD___serialize__ (soakQ_L_64proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->sess, state);
    $step_serialize(self->req, state);
}
soakQ_L_64proc soakQ_L_64procD___deserialize__ (soakQ_L_64proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct soakQ_L_64proc));
            self->$class = &soakQ_L_64procG_methods;
            return self;
        }
        self = $DNEW(soakQ_L_64proc, state);
    }
    self->self = $step_deserialize(state);
    self->sess = $step_deserialize(state);
    self->req = $step_deserialize(state);
    return self;
}
soakQ_L_64proc soakQ_L_64procG_new(soakQ_main G_1, sshQ_ServerSession G_2, sshQ_AuthRequest G_3) {
    soakQ_L_64proc $tmp = acton_malloc(sizeof(struct soakQ_L_64proc));
    $tmp->$class = &soakQ_L_64procG_methods;
    soakQ_L_64procG_methods.__init__($tmp, G_1, G_2, G_3);
    return $tmp;
}
struct soakQ_L_64procG_class soakQ_L_64procG_methods;
B_NoneType soakQ_L_65procD___init__ (soakQ_L_65proc L_self, soakQ_main self, sshQ_ServerChannel ch, B_bytes data) {
    ((soakQ_L_65proc)(L_self))->self = self;
    ((soakQ_L_65proc)(L_self))->ch = ch;
    ((soakQ_L_65proc)(L_self))->data = data;
    return B_None;
}
$R soakQ_L_65procD___call__ (soakQ_L_65proc L_self, $Cont C_cont) {
    soakQ_main self = ((soakQ_L_65proc)(L_self))->self;
    sshQ_ServerChannel ch = ((soakQ_L_65proc)(L_self))->ch;
    B_bytes data = ((soakQ_L_65proc)(L_self))->data;
    return (($R (*) ($WORD, $Cont, sshQ_ServerChannel, B_bytes))((soakQ_main)(self))->$class->srv_on_dataG_local)(self, C_cont, ch, data);
}
$R soakQ_L_65procD___exec__ (soakQ_L_65proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((soakQ_L_65proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void soakQ_L_65procD___serialize__ (soakQ_L_65proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->ch, state);
    $step_serialize(self->data, state);
}
soakQ_L_65proc soakQ_L_65procD___deserialize__ (soakQ_L_65proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct soakQ_L_65proc));
            self->$class = &soakQ_L_65procG_methods;
            return self;
        }
        self = $DNEW(soakQ_L_65proc, state);
    }
    self->self = $step_deserialize(state);
    self->ch = $step_deserialize(state);
    self->data = $step_deserialize(state);
    return self;
}
soakQ_L_65proc soakQ_L_65procG_new(soakQ_main G_1, sshQ_ServerChannel G_2, B_bytes G_3) {
    soakQ_L_65proc $tmp = acton_malloc(sizeof(struct soakQ_L_65proc));
    $tmp->$class = &soakQ_L_65procG_methods;
    soakQ_L_65procG_methods.__init__($tmp, G_1, G_2, G_3);
    return $tmp;
}
struct soakQ_L_65procG_class soakQ_L_65procG_methods;
B_NoneType soakQ_L_66procD___init__ (soakQ_L_66proc L_self, soakQ_main self, sshQ_ServerChannel ch, B_bytes data) {
    ((soakQ_L_66proc)(L_self))->self = self;
    ((soakQ_L_66proc)(L_self))->ch = ch;
    ((soakQ_L_66proc)(L_self))->data = data;
    return B_None;
}
$R soakQ_L_66procD___call__ (soakQ_L_66proc L_self, $Cont C_cont) {
    soakQ_main self = ((soakQ_L_66proc)(L_self))->self;
    sshQ_ServerChannel ch = ((soakQ_L_66proc)(L_self))->ch;
    B_bytes data = ((soakQ_L_66proc)(L_self))->data;
    return (($R (*) ($WORD, $Cont, sshQ_ServerChannel, B_bytes))((soakQ_main)(self))->$class->srv_on_stderrG_local)(self, C_cont, ch, data);
}
$R soakQ_L_66procD___exec__ (soakQ_L_66proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((soakQ_L_66proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void soakQ_L_66procD___serialize__ (soakQ_L_66proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->ch, state);
    $step_serialize(self->data, state);
}
soakQ_L_66proc soakQ_L_66procD___deserialize__ (soakQ_L_66proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct soakQ_L_66proc));
            self->$class = &soakQ_L_66procG_methods;
            return self;
        }
        self = $DNEW(soakQ_L_66proc, state);
    }
    self->self = $step_deserialize(state);
    self->ch = $step_deserialize(state);
    self->data = $step_deserialize(state);
    return self;
}
soakQ_L_66proc soakQ_L_66procG_new(soakQ_main G_1, sshQ_ServerChannel G_2, B_bytes G_3) {
    soakQ_L_66proc $tmp = acton_malloc(sizeof(struct soakQ_L_66proc));
    $tmp->$class = &soakQ_L_66procG_methods;
    soakQ_L_66procG_methods.__init__($tmp, G_1, G_2, G_3);
    return $tmp;
}
struct soakQ_L_66procG_class soakQ_L_66procG_methods;
B_NoneType soakQ_L_67procD___init__ (soakQ_L_67proc L_self, soakQ_main self, sshQ_ServerChannel ch, B_str reason) {
    ((soakQ_L_67proc)(L_self))->self = self;
    ((soakQ_L_67proc)(L_self))->ch = ch;
    ((soakQ_L_67proc)(L_self))->reason = reason;
    return B_None;
}
$R soakQ_L_67procD___call__ (soakQ_L_67proc L_self, $Cont C_cont) {
    soakQ_main self = ((soakQ_L_67proc)(L_self))->self;
    sshQ_ServerChannel ch = ((soakQ_L_67proc)(L_self))->ch;
    B_str reason = ((soakQ_L_67proc)(L_self))->reason;
    return (($R (*) ($WORD, $Cont, sshQ_ServerChannel, B_str))((soakQ_main)(self))->$class->srv_on_closeG_local)(self, C_cont, ch, reason);
}
$R soakQ_L_67procD___exec__ (soakQ_L_67proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((soakQ_L_67proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void soakQ_L_67procD___serialize__ (soakQ_L_67proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->ch, state);
    $step_serialize(self->reason, state);
}
soakQ_L_67proc soakQ_L_67procD___deserialize__ (soakQ_L_67proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct soakQ_L_67proc));
            self->$class = &soakQ_L_67procG_methods;
            return self;
        }
        self = $DNEW(soakQ_L_67proc, state);
    }
    self->self = $step_deserialize(state);
    self->ch = $step_deserialize(state);
    self->reason = $step_deserialize(state);
    return self;
}
soakQ_L_67proc soakQ_L_67procG_new(soakQ_main G_1, sshQ_ServerChannel G_2, B_str G_3) {
    soakQ_L_67proc $tmp = acton_malloc(sizeof(struct soakQ_L_67proc));
    $tmp->$class = &soakQ_L_67procG_methods;
    soakQ_L_67procG_methods.__init__($tmp, G_1, G_2, G_3);
    return $tmp;
}
struct soakQ_L_67procG_class soakQ_L_67procG_methods;
B_NoneType soakQ_L_68procD___init__ (soakQ_L_68proc L_self, soakQ_main self, sshQ_ServerSession sess) {
    ((soakQ_L_68proc)(L_self))->self = self;
    ((soakQ_L_68proc)(L_self))->sess = sess;
    return B_None;
}
$R soakQ_L_68procD___call__ (soakQ_L_68proc L_self, $Cont C_cont) {
    soakQ_main self = ((soakQ_L_68proc)(L_self))->self;
    sshQ_ServerSession sess = ((soakQ_L_68proc)(L_self))->sess;
    return (($R (*) ($WORD, $Cont, sshQ_ServerSession))((soakQ_main)(self))->$class->on_channel_openG_local)(self, C_cont, sess);
}
$R soakQ_L_68procD___exec__ (soakQ_L_68proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((soakQ_L_68proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void soakQ_L_68procD___serialize__ (soakQ_L_68proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->sess, state);
}
soakQ_L_68proc soakQ_L_68procD___deserialize__ (soakQ_L_68proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct soakQ_L_68proc));
            self->$class = &soakQ_L_68procG_methods;
            return self;
        }
        self = $DNEW(soakQ_L_68proc, state);
    }
    self->self = $step_deserialize(state);
    self->sess = $step_deserialize(state);
    return self;
}
soakQ_L_68proc soakQ_L_68procG_new(soakQ_main G_1, sshQ_ServerSession G_2) {
    soakQ_L_68proc $tmp = acton_malloc(sizeof(struct soakQ_L_68proc));
    $tmp->$class = &soakQ_L_68procG_methods;
    soakQ_L_68procG_methods.__init__($tmp, G_1, G_2);
    return $tmp;
}
struct soakQ_L_68procG_class soakQ_L_68procG_methods;
B_NoneType soakQ_L_69procD___init__ (soakQ_L_69proc L_self, soakQ_main self, sshQ_ServerSession sess, sshQ_ServerChannel ch, B_str cmd) {
    ((soakQ_L_69proc)(L_self))->self = self;
    ((soakQ_L_69proc)(L_self))->sess = sess;
    ((soakQ_L_69proc)(L_self))->ch = ch;
    ((soakQ_L_69proc)(L_self))->cmd = cmd;
    return B_None;
}
$R soakQ_L_69procD___call__ (soakQ_L_69proc L_self, $Cont C_cont) {
    soakQ_main self = ((soakQ_L_69proc)(L_self))->self;
    sshQ_ServerSession sess = ((soakQ_L_69proc)(L_self))->sess;
    sshQ_ServerChannel ch = ((soakQ_L_69proc)(L_self))->ch;
    B_str cmd = ((soakQ_L_69proc)(L_self))->cmd;
    return (($R (*) ($WORD, $Cont, sshQ_ServerSession, sshQ_ServerChannel, B_str))((soakQ_main)(self))->$class->on_execG_local)(self, C_cont, sess, ch, cmd);
}
$R soakQ_L_69procD___exec__ (soakQ_L_69proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((soakQ_L_69proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void soakQ_L_69procD___serialize__ (soakQ_L_69proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->sess, state);
    $step_serialize(self->ch, state);
    $step_serialize(self->cmd, state);
}
soakQ_L_69proc soakQ_L_69procD___deserialize__ (soakQ_L_69proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct soakQ_L_69proc));
            self->$class = &soakQ_L_69procG_methods;
            return self;
        }
        self = $DNEW(soakQ_L_69proc, state);
    }
    self->self = $step_deserialize(state);
    self->sess = $step_deserialize(state);
    self->ch = $step_deserialize(state);
    self->cmd = $step_deserialize(state);
    return self;
}
soakQ_L_69proc soakQ_L_69procG_new(soakQ_main G_1, sshQ_ServerSession G_2, sshQ_ServerChannel G_3, B_str G_4) {
    soakQ_L_69proc $tmp = acton_malloc(sizeof(struct soakQ_L_69proc));
    $tmp->$class = &soakQ_L_69procG_methods;
    soakQ_L_69procG_methods.__init__($tmp, G_1, G_2, G_3, G_4);
    return $tmp;
}
struct soakQ_L_69procG_class soakQ_L_69procG_methods;
B_NoneType soakQ_L_70procD___init__ (soakQ_L_70proc L_self, soakQ_main self, sshQ_Client c, B_str state, sshQ_HostKeyInfo info) {
    ((soakQ_L_70proc)(L_self))->self = self;
    ((soakQ_L_70proc)(L_self))->c = c;
    ((soakQ_L_70proc)(L_self))->state = state;
    ((soakQ_L_70proc)(L_self))->info = info;
    return B_None;
}
$R soakQ_L_70procD___call__ (soakQ_L_70proc L_self, $Cont C_cont) {
    soakQ_main self = ((soakQ_L_70proc)(L_self))->self;
    sshQ_Client c = ((soakQ_L_70proc)(L_self))->c;
    B_str state = ((soakQ_L_70proc)(L_self))->state;
    sshQ_HostKeyInfo info = ((soakQ_L_70proc)(L_self))->info;
    return (($R (*) ($WORD, $Cont, sshQ_Client, B_str, sshQ_HostKeyInfo))((soakQ_main)(self))->$class->on_hostkeyG_local)(self, C_cont, c, state, info);
}
$R soakQ_L_70procD___exec__ (soakQ_L_70proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((soakQ_L_70proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void soakQ_L_70procD___serialize__ (soakQ_L_70proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->c, state);
    $step_serialize(self->state, state);
    $step_serialize(self->info, state);
}
soakQ_L_70proc soakQ_L_70procD___deserialize__ (soakQ_L_70proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct soakQ_L_70proc));
            self->$class = &soakQ_L_70procG_methods;
            return self;
        }
        self = $DNEW(soakQ_L_70proc, state);
    }
    self->self = $step_deserialize(state);
    self->c = $step_deserialize(state);
    self->state = $step_deserialize(state);
    self->info = $step_deserialize(state);
    return self;
}
soakQ_L_70proc soakQ_L_70procG_new(soakQ_main G_1, sshQ_Client G_2, B_str G_3, sshQ_HostKeyInfo G_4) {
    soakQ_L_70proc $tmp = acton_malloc(sizeof(struct soakQ_L_70proc));
    $tmp->$class = &soakQ_L_70procG_methods;
    soakQ_L_70procG_methods.__init__($tmp, G_1, G_2, G_3, G_4);
    return $tmp;
}
struct soakQ_L_70procG_class soakQ_L_70procG_methods;
B_NoneType soakQ_L_71procD___init__ (soakQ_L_71proc L_self, soakQ_main self) {
    ((soakQ_L_71proc)(L_self))->self = self;
    return B_None;
}
$R soakQ_L_71procD___call__ (soakQ_L_71proc L_self, $Cont C_cont) {
    soakQ_main self = ((soakQ_L_71proc)(L_self))->self;
    return (($R (*) ($WORD, $Cont))((soakQ_main)(self))->$class->next_cycleG_local)(self, C_cont);
}
$R soakQ_L_71procD___exec__ (soakQ_L_71proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((soakQ_L_71proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void soakQ_L_71procD___serialize__ (soakQ_L_71proc self, $Serial$state state) {
    $step_serialize(self->self, state);
}
soakQ_L_71proc soakQ_L_71procD___deserialize__ (soakQ_L_71proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct soakQ_L_71proc));
            self->$class = &soakQ_L_71procG_methods;
            return self;
        }
        self = $DNEW(soakQ_L_71proc, state);
    }
    self->self = $step_deserialize(state);
    return self;
}
soakQ_L_71proc soakQ_L_71procG_new(soakQ_main G_1) {
    soakQ_L_71proc $tmp = acton_malloc(sizeof(struct soakQ_L_71proc));
    $tmp->$class = &soakQ_L_71procG_methods;
    soakQ_L_71procG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct soakQ_L_71procG_class soakQ_L_71procG_methods;
B_NoneType soakQ_L_72procD___init__ (soakQ_L_72proc L_self, soakQ_main self) {
    ((soakQ_L_72proc)(L_self))->self = self;
    return B_None;
}
$R soakQ_L_72procD___call__ (soakQ_L_72proc L_self, $Cont C_cont) {
    soakQ_main self = ((soakQ_L_72proc)(L_self))->self;
    return (($R (*) ($WORD, $Cont))((soakQ_main)(self))->$class->start_cycleG_local)(self, C_cont);
}
$R soakQ_L_72procD___exec__ (soakQ_L_72proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((soakQ_L_72proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void soakQ_L_72procD___serialize__ (soakQ_L_72proc self, $Serial$state state) {
    $step_serialize(self->self, state);
}
soakQ_L_72proc soakQ_L_72procD___deserialize__ (soakQ_L_72proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct soakQ_L_72proc));
            self->$class = &soakQ_L_72procG_methods;
            return self;
        }
        self = $DNEW(soakQ_L_72proc, state);
    }
    self->self = $step_deserialize(state);
    return self;
}
soakQ_L_72proc soakQ_L_72procG_new(soakQ_main G_1) {
    soakQ_L_72proc $tmp = acton_malloc(sizeof(struct soakQ_L_72proc));
    $tmp->$class = &soakQ_L_72procG_methods;
    soakQ_L_72procG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct soakQ_L_72procG_class soakQ_L_72procG_methods;
$R soakQ_L_73C_30cont ($Cont C_cont, soakQ_main G_act, B_NoneType C_31res) {
    return $R_CONT(C_cont, G_act);
}
B_NoneType soakQ_L_74ContD___init__ (soakQ_L_74Cont L_self, $Cont C_cont, soakQ_main G_act) {
    ((soakQ_L_74Cont)(L_self))->C_cont = C_cont;
    ((soakQ_L_74Cont)(L_self))->G_act = G_act;
    return B_None;
}
$R soakQ_L_74ContD___call__ (soakQ_L_74Cont L_self, B_NoneType G_1) {
    $Cont C_cont = ((soakQ_L_74Cont)(L_self))->C_cont;
    soakQ_main G_act = ((soakQ_L_74Cont)(L_self))->G_act;
    return soakQ_L_73C_30cont(C_cont, G_act, G_1);
}
void soakQ_L_74ContD___serialize__ (soakQ_L_74Cont self, $Serial$state state) {
    $step_serialize(self->C_cont, state);
    $step_serialize(self->G_act, state);
}
soakQ_L_74Cont soakQ_L_74ContD___deserialize__ (soakQ_L_74Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct soakQ_L_74Cont));
            self->$class = &soakQ_L_74ContG_methods;
            return self;
        }
        self = $DNEW(soakQ_L_74Cont, state);
    }
    self->C_cont = $step_deserialize(state);
    self->G_act = $step_deserialize(state);
    return self;
}
soakQ_L_74Cont soakQ_L_74ContG_new($Cont G_1, soakQ_main G_2) {
    soakQ_L_74Cont $tmp = acton_malloc(sizeof(struct soakQ_L_74Cont));
    $tmp->$class = &soakQ_L_74ContG_methods;
    soakQ_L_74ContG_methods.__init__($tmp, G_1, G_2);
    return $tmp;
}
struct soakQ_L_74ContG_class soakQ_L_74ContG_methods;
B_NoneType soakQ_L_75procD___init__ (soakQ_L_75proc L_self, soakQ_main G_act, B_Env env) {
    ((soakQ_L_75proc)(L_self))->G_act = G_act;
    ((soakQ_L_75proc)(L_self))->env = env;
    return B_None;
}
$R soakQ_L_75procD___call__ (soakQ_L_75proc L_self, $Cont C_cont) {
    soakQ_main G_act = ((soakQ_L_75proc)(L_self))->G_act;
    B_Env env = ((soakQ_L_75proc)(L_self))->env;
    return (($R (*) ($WORD, $Cont, B_Env))((soakQ_main)(G_act))->$class->__init__)(G_act, C_cont, env);
}
$R soakQ_L_75procD___exec__ (soakQ_L_75proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((soakQ_L_75proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void soakQ_L_75procD___serialize__ (soakQ_L_75proc self, $Serial$state state) {
    $step_serialize(self->G_act, state);
    $step_serialize(self->env, state);
}
soakQ_L_75proc soakQ_L_75procD___deserialize__ (soakQ_L_75proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct soakQ_L_75proc));
            self->$class = &soakQ_L_75procG_methods;
            return self;
        }
        self = $DNEW(soakQ_L_75proc, state);
    }
    self->G_act = $step_deserialize(state);
    self->env = $step_deserialize(state);
    return self;
}
soakQ_L_75proc soakQ_L_75procG_new(soakQ_main G_1, B_Env G_2) {
    soakQ_L_75proc $tmp = acton_malloc(sizeof(struct soakQ_L_75proc));
    $tmp->$class = &soakQ_L_75procG_methods;
    soakQ_L_75procG_methods.__init__($tmp, G_1, G_2);
    return $tmp;
}
struct soakQ_L_75procG_class soakQ_L_75procG_methods;
$R soakQ_mainD___init__ (soakQ_main self, $Cont C_cont, B_Env env) {
    ((soakQ_main)(self))->env = env;
    #line 12 "src/soak.act"
    ((soakQ_main)(self))->cycles = 2000LL;
    #line 13 "src/soak.act"
    if (((int64_t (*) (B_Collection, B_list))B_len)(soakQ_W_main_27, ((B_Env)(((soakQ_main)(self))->env))->argv) > 1LL) {
        #line 14 "src/soak.act"
        ((soakQ_main)(self))->cycles = B_intG_new(((B_atom)$listD_U__getitem__(((B_Env)(((soakQ_main)(self))->env))->argv, 1LL)), B_None);
    }
    #line 16 "src/soak.act"
    ((soakQ_main)(self))->server = B_None;
    #line 17 "src/soak.act"
    ((soakQ_main)(self))->port = 0;
    #line 18 "src/soak.act"
    ((soakQ_main)(self))->done = 0LL;
    #line 19 "src/soak.act"
    ((soakQ_main)(self))->ok = 0LL;
    return sshQ_ServerG_newact((($Cont)soakQ_L_2ContG_new(self, C_cont)), netQ_TCPListenCapG_new(netQ_TCPCapG_new(netQ_NetCapG_new(((B_Env)(((soakQ_main)(self))->env))->cap))), to$str("127.0.0.1"), B_u16G_new(((B_atom)toB_int(0LL)), B_None), (($action)soakQ_L_4actionG_new(self)), (($action)soakQ_L_6actionG_new(self)), (($action)soakQ_L_8actionG_new(self)), (($action)soakQ_L_10actionG_new(self)), (($action)soakQ_L_12actionG_new(self)), (($action)soakQ_L_14actionG_new(self)), B_None, B_None, B_None, B_None, B_None, B_None, B_None, B_None, B_None, B_None, B_None);
}
#line 21 "src/soak.act"
$R soakQ_mainD_reportG_local (soakQ_main self, $Cont C_cont) {
    #line 22 "src/soak.act"
    ((B_NoneType (*) (B_tuple, B_str, B_str, B_bool, B_bool))B_print)($NEWTUPLE(6, to$str("cycle"), toB_int(((int64_t)((soakQ_main)(self))->done)), to$str("of"), toB_int(((int64_t)((soakQ_main)(self))->cycles)), to$str("ok"), toB_int(((int64_t)((soakQ_main)(self))->ok))), B_None, B_None, B_None, B_None);
    return $R_CONT(C_cont, B_None);
}
#line 24 "src/soak.act"
$R soakQ_mainD_failG_local (soakQ_main self, $Cont C_cont, B_str msg) {
    #line 25 "src/soak.act"
    ((B_NoneType (*) (B_tuple, B_str, B_str, B_bool, B_bool))B_print)($NEWTUPLE(2, to$str("SOAK-FAIL:"), msg), B_None, B_None, B_None, B_None);
    #line 26 "src/soak.act"
    ((B_Msg (*) ($WORD, int64_t))((B_Env)(((soakQ_main)(self))->env))->$class->exit)(((soakQ_main)(self))->env, 1LL);
    return $R_CONT(C_cont, B_None);
}
#line 28 "src/soak.act"
$R soakQ_mainD_on_listenG_local (soakQ_main self, $Cont C_cont, sshQ_Server s, B_str err) {
    B_Plus W_main_182 = (B_Plus)B_TimesD_strG_witness;
    if ($ISNOTNONE0(err)) {
        return (($R (*) ($WORD, $Cont, B_str))((soakQ_main)(self))->$class->failG_local)(self, (($Cont)soakQ_L_21ContG_new(C_cont)), ((B_str (*) ($WORD, B_str, B_str))((B_Plus)(W_main_182))->$class->__add__)(W_main_182, to$str("listen: "), ((B_str)err)));
    }
    else {
        return $R_CONT((($Cont)soakQ_L_22ContG_new(self, C_cont, s)), B_None);
    }
}
#line 35 "src/soak.act"
$R soakQ_mainD_on_server_closeG_local (soakQ_main self, $Cont C_cont, sshQ_Server s, B_str reason) {
    #line 36 "src/soak.act"
    return $R_CONT(C_cont, B_None);
}
#line 38 "src/soak.act"
$R soakQ_mainD_on_sessionG_local (soakQ_main self, $Cont C_cont, sshQ_ServerSession sess) {
    #line 39 "src/soak.act"
    return $R_CONT(C_cont, B_None);
}
#line 41 "src/soak.act"
$R soakQ_mainD_on_authG_local (soakQ_main self, $Cont C_cont, sshQ_ServerSession sess, sshQ_AuthRequest req) {
    #line 42 "src/soak.act"
    ((B_Msg (*) ($WORD))((sshQ_ServerSession)(sess))->$class->accept_auth)(sess);
    return $R_CONT(C_cont, B_None);
}
#line 44 "src/soak.act"
$R soakQ_mainD_srv_on_dataG_local (soakQ_main self, $Cont C_cont, sshQ_ServerChannel ch, B_bytes data) {
    #line 45 "src/soak.act"
    return $R_CONT(C_cont, B_None);
}
#line 47 "src/soak.act"
$R soakQ_mainD_srv_on_stderrG_local (soakQ_main self, $Cont C_cont, sshQ_ServerChannel ch, B_bytes data) {
    #line 48 "src/soak.act"
    return $R_CONT(C_cont, B_None);
}
#line 50 "src/soak.act"
$R soakQ_mainD_srv_on_closeG_local (soakQ_main self, $Cont C_cont, sshQ_ServerChannel ch, B_str reason) {
    #line 51 "src/soak.act"
    return $R_CONT(C_cont, B_None);
}
#line 53 "src/soak.act"
$R soakQ_mainD_on_channel_openG_local (soakQ_main self, $Cont C_cont, sshQ_ServerSession sess) {
    return sshQ_ServerChannelG_newact((($Cont)soakQ_L_24ContG_new(sess, C_cont)), sess, (($action)soakQ_L_26actionG_new(self)), (($action)soakQ_L_28actionG_new(self)), (($action)soakQ_L_30actionG_new(self)));
}
#line 56 "src/soak.act"
$R soakQ_mainD_on_execG_local (soakQ_main self, $Cont C_cont, sshQ_ServerSession sess, sshQ_ServerChannel ch, B_str cmd) {
    #line 57 "src/soak.act"
    ((B_Msg (*) ($WORD))((sshQ_ServerChannel)(ch))->$class->accept_request)(ch);
    #line 58 "src/soak.act"
    ((B_Msg (*) ($WORD, B_bytes))((sshQ_ServerChannel)(ch))->$class->write)(ch, to$bytesD_len("ok\n", 3));
    #line 59 "src/soak.act"
    ((B_Msg (*) ($WORD, int64_t))((sshQ_ServerChannel)(ch))->$class->send_exit_status)(ch, 0LL);
    #line 60 "src/soak.act"
    ((B_Msg (*) ($WORD))((sshQ_ServerChannel)(ch))->$class->close)(ch);
    return $R_CONT(C_cont, B_None);
}
#line 62 "src/soak.act"
$R soakQ_mainD_on_hostkeyG_local (soakQ_main self, $Cont C_cont, sshQ_Client c, B_str state, sshQ_HostKeyInfo info) {
    #line 63 "src/soak.act"
    ((B_Msg (*) ($WORD))((sshQ_Client)(c))->$class->accept_hostkey)(c);
    return $R_CONT(C_cont, B_None);
}
#line 65 "src/soak.act"
$R soakQ_mainD_next_cycleG_local (soakQ_main self, $Cont C_cont) {
    ((soakQ_main)(self))->done += 1LL;
    if ((int_MOD(((int64_t)((soakQ_main)(self))->done), 200LL)) == 0LL) {
        return (($R (*) ($WORD, $Cont))((soakQ_main)(self))->$class->reportG_local)(self, (($Cont)soakQ_L_36ContG_new(C_cont, self)));
    }
    else {
        return $R_CONT((($Cont)soakQ_L_37ContG_new(C_cont, self)), B_None);
    }
}
#line 77 "src/soak.act"
$R soakQ_mainD_start_cycleG_local (soakQ_main self, $Cont C_cont) {
    return sshQ_ClientG_newact((($Cont)soakQ_L_52ContG_new(C_cont)), netQ_TCPConnectCapG_new(netQ_TCPCapG_new(netQ_NetCapG_new(((B_Env)(((soakQ_main)(self))->env))->cap))), to$str("127.0.0.1"), to$str("soak"), (($action)soakQ_L_54actionG_new(self)), (($action)soakQ_L_56actionG_new(self)), (($action)soakQ_L_58actionG_new(self)), to$str("soak"), B_None, B_None, toB_u16(((uint16_t)((soakQ_main)(self))->port)), B_None, B_None, B_None, B_None, B_None, B_None);
}
B_Msg soakQ_mainD_report (soakQ_main self) {
    return $ASYNC((($Actor)self), (($Cont)soakQ_L_59procG_new(self)));
}
B_Msg soakQ_mainD_fail (soakQ_main self, B_str msg) {
    return $ASYNC((($Actor)self), (($Cont)soakQ_L_60procG_new(self, msg)));
}
B_Msg soakQ_mainD_on_listen (soakQ_main self, sshQ_Server s, B_str err) {
    return $ASYNC((($Actor)self), (($Cont)soakQ_L_61procG_new(self, s, err)));
}
B_Msg soakQ_mainD_on_server_close (soakQ_main self, sshQ_Server s, B_str reason) {
    return $ASYNC((($Actor)self), (($Cont)soakQ_L_62procG_new(self, s, reason)));
}
B_Msg soakQ_mainD_on_session (soakQ_main self, sshQ_ServerSession sess) {
    return $ASYNC((($Actor)self), (($Cont)soakQ_L_63procG_new(self, sess)));
}
B_Msg soakQ_mainD_on_auth (soakQ_main self, sshQ_ServerSession sess, sshQ_AuthRequest req) {
    return $ASYNC((($Actor)self), (($Cont)soakQ_L_64procG_new(self, sess, req)));
}
B_Msg soakQ_mainD_srv_on_data (soakQ_main self, sshQ_ServerChannel ch, B_bytes data) {
    return $ASYNC((($Actor)self), (($Cont)soakQ_L_65procG_new(self, ch, data)));
}
B_Msg soakQ_mainD_srv_on_stderr (soakQ_main self, sshQ_ServerChannel ch, B_bytes data) {
    return $ASYNC((($Actor)self), (($Cont)soakQ_L_66procG_new(self, ch, data)));
}
B_Msg soakQ_mainD_srv_on_close (soakQ_main self, sshQ_ServerChannel ch, B_str reason) {
    return $ASYNC((($Actor)self), (($Cont)soakQ_L_67procG_new(self, ch, reason)));
}
B_Msg soakQ_mainD_on_channel_open (soakQ_main self, sshQ_ServerSession sess) {
    return $ASYNC((($Actor)self), (($Cont)soakQ_L_68procG_new(self, sess)));
}
B_Msg soakQ_mainD_on_exec (soakQ_main self, sshQ_ServerSession sess, sshQ_ServerChannel ch, B_str cmd) {
    return $ASYNC((($Actor)self), (($Cont)soakQ_L_69procG_new(self, sess, ch, cmd)));
}
B_Msg soakQ_mainD_on_hostkey (soakQ_main self, sshQ_Client c, B_str state, sshQ_HostKeyInfo info) {
    return $ASYNC((($Actor)self), (($Cont)soakQ_L_70procG_new(self, c, state, info)));
}
B_Msg soakQ_mainD_next_cycle (soakQ_main self) {
    return $ASYNC((($Actor)self), (($Cont)soakQ_L_71procG_new(self)));
}
B_Msg soakQ_mainD_start_cycle (soakQ_main self) {
    return $ASYNC((($Actor)self), (($Cont)soakQ_L_72procG_new(self)));
}
void soakQ_mainD___serialize__ (soakQ_main self, $Serial$state state) {
    $ActorG_methods.__serialize__(($Actor)self, state);
    $step_serialize(self->env, state);
    $val_serialize(I64_ID, &self->cycles, state);
    $step_serialize(self->server, state);
    $val_serialize(U16_ID, &self->port, state);
    $val_serialize(I64_ID, &self->done, state);
    $val_serialize(I64_ID, &self->ok, state);
}
soakQ_main soakQ_mainD___deserialize__ (soakQ_main self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct soakQ_main));
            self->$class = &soakQ_mainG_methods;
            return self;
        }
        self = $DNEW(soakQ_main, state);
    }
    $ActorG_methods.__deserialize__(($Actor)self, state);
    self->env = $step_deserialize(state);
    $tmp = $val_deserialize(state);
    memcpy(&self->cycles, &$tmp, sizeof(self->cycles));
    self->server = $step_deserialize(state);
    $tmp = $val_deserialize(state);
    memcpy(&self->port, &$tmp, sizeof(self->port));
    $tmp = $val_deserialize(state);
    memcpy(&self->done, &$tmp, sizeof(self->done));
    $tmp = $val_deserialize(state);
    memcpy(&self->ok, &$tmp, sizeof(self->ok));
    return self;
}
void soakQ_mainD_GCfinalizer (void *obj, void *cdata) {
    soakQ_main self = (soakQ_main)obj;
    self->$class->__cleanup__(self);
}
$R soakQ_mainG_new($Cont G_1, B_Env G_2) {
    soakQ_main $tmp = acton_malloc(sizeof(struct soakQ_main));
    $tmp->$class = &soakQ_mainG_methods;
    return soakQ_mainG_methods.__init__($tmp, $CONSTCONT($tmp, G_1), G_2);
}
struct soakQ_mainG_class soakQ_mainG_methods;
$R soakQ_mainG_newact ($Cont C_cont, B_Env env) {
    soakQ_main G_act = $NEWACTOR(soakQ_main);
    if ((void*)G_act->$class->__cleanup__ != (void*)$ActorD___cleanup__) $InstallFinalizer(G_act, soakQ_mainD_GCfinalizer);
    return $AWAIT((($Cont)soakQ_L_74ContG_new(C_cont, G_act)), $ASYNC((($Actor)G_act), (($Cont)soakQ_L_75procG_new(G_act, env))));
}
int soakQ_done$ = 0;
void soakQ___init__ () {
    if (soakQ_done$) return;
    soakQ_done$ = 1;
    netQ___init__();
    sshQ___init__();
    {
        soakQ_L_2ContG_methods.$GCINFO = "soakQ_L_2Cont";
        soakQ_L_2ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        soakQ_L_2ContG_methods.__bool__ = (B_bool (*) (soakQ_L_2Cont))B_valueG_methods.__bool__;
        soakQ_L_2ContG_methods.__str__ = (B_str (*) (soakQ_L_2Cont))B_valueG_methods.__str__;
        soakQ_L_2ContG_methods.__repr__ = (B_str (*) (soakQ_L_2Cont))B_valueG_methods.__repr__;
        soakQ_L_2ContG_methods.__init__ = (B_NoneType (*) (soakQ_L_2Cont, soakQ_main, $Cont))soakQ_L_2ContD___init__;
        soakQ_L_2ContG_methods.__call__ = ($R (*) (soakQ_L_2Cont, sshQ_Server))soakQ_L_2ContD___call__;
        soakQ_L_2ContG_methods.__serialize__ = soakQ_L_2ContD___serialize__;
        soakQ_L_2ContG_methods.__deserialize__ = soakQ_L_2ContD___deserialize__;
        $register(&soakQ_L_2ContG_methods);
    }
    {
        soakQ_L_4actionG_methods.$GCINFO = "soakQ_L_4action";
        soakQ_L_4actionG_methods.$superclass = ($SuperG_class)&$actionG_methods;
        soakQ_L_4actionG_methods.__bool__ = (B_bool (*) (soakQ_L_4action))B_valueG_methods.__bool__;
        soakQ_L_4actionG_methods.__str__ = (B_str (*) (soakQ_L_4action))B_valueG_methods.__str__;
        soakQ_L_4actionG_methods.__repr__ = (B_str (*) (soakQ_L_4action))B_valueG_methods.__repr__;
        soakQ_L_4actionG_methods.__init__ = (B_NoneType (*) (soakQ_L_4action, soakQ_main))soakQ_L_4actionD___init__;
        soakQ_L_4actionG_methods.__call__ = ($R (*) (soakQ_L_4action, $Cont, sshQ_Server, B_str))soakQ_L_4actionD___call__;
        soakQ_L_4actionG_methods.__exec__ = ($R (*) (soakQ_L_4action, $Cont, sshQ_Server, B_str))soakQ_L_4actionD___exec__;
        soakQ_L_4actionG_methods.__asyn__ = (B_Msg (*) (soakQ_L_4action, sshQ_Server, B_str))soakQ_L_4actionD___asyn__;
        soakQ_L_4actionG_methods.__serialize__ = soakQ_L_4actionD___serialize__;
        soakQ_L_4actionG_methods.__deserialize__ = soakQ_L_4actionD___deserialize__;
        $register(&soakQ_L_4actionG_methods);
    }
    {
        soakQ_L_6actionG_methods.$GCINFO = "soakQ_L_6action";
        soakQ_L_6actionG_methods.$superclass = ($SuperG_class)&$actionG_methods;
        soakQ_L_6actionG_methods.__bool__ = (B_bool (*) (soakQ_L_6action))B_valueG_methods.__bool__;
        soakQ_L_6actionG_methods.__str__ = (B_str (*) (soakQ_L_6action))B_valueG_methods.__str__;
        soakQ_L_6actionG_methods.__repr__ = (B_str (*) (soakQ_L_6action))B_valueG_methods.__repr__;
        soakQ_L_6actionG_methods.__init__ = (B_NoneType (*) (soakQ_L_6action, soakQ_main))soakQ_L_6actionD___init__;
        soakQ_L_6actionG_methods.__call__ = ($R (*) (soakQ_L_6action, $Cont, sshQ_Server, B_str))soakQ_L_6actionD___call__;
        soakQ_L_6actionG_methods.__exec__ = ($R (*) (soakQ_L_6action, $Cont, sshQ_Server, B_str))soakQ_L_6actionD___exec__;
        soakQ_L_6actionG_methods.__asyn__ = (B_Msg (*) (soakQ_L_6action, sshQ_Server, B_str))soakQ_L_6actionD___asyn__;
        soakQ_L_6actionG_methods.__serialize__ = soakQ_L_6actionD___serialize__;
        soakQ_L_6actionG_methods.__deserialize__ = soakQ_L_6actionD___deserialize__;
        $register(&soakQ_L_6actionG_methods);
    }
    {
        soakQ_L_8actionG_methods.$GCINFO = "soakQ_L_8action";
        soakQ_L_8actionG_methods.$superclass = ($SuperG_class)&$actionG_methods;
        soakQ_L_8actionG_methods.__bool__ = (B_bool (*) (soakQ_L_8action))B_valueG_methods.__bool__;
        soakQ_L_8actionG_methods.__str__ = (B_str (*) (soakQ_L_8action))B_valueG_methods.__str__;
        soakQ_L_8actionG_methods.__repr__ = (B_str (*) (soakQ_L_8action))B_valueG_methods.__repr__;
        soakQ_L_8actionG_methods.__init__ = (B_NoneType (*) (soakQ_L_8action, soakQ_main))soakQ_L_8actionD___init__;
        soakQ_L_8actionG_methods.__call__ = ($R (*) (soakQ_L_8action, $Cont, sshQ_ServerSession))soakQ_L_8actionD___call__;
        soakQ_L_8actionG_methods.__exec__ = ($R (*) (soakQ_L_8action, $Cont, sshQ_ServerSession))soakQ_L_8actionD___exec__;
        soakQ_L_8actionG_methods.__asyn__ = (B_Msg (*) (soakQ_L_8action, sshQ_ServerSession))soakQ_L_8actionD___asyn__;
        soakQ_L_8actionG_methods.__serialize__ = soakQ_L_8actionD___serialize__;
        soakQ_L_8actionG_methods.__deserialize__ = soakQ_L_8actionD___deserialize__;
        $register(&soakQ_L_8actionG_methods);
    }
    {
        soakQ_L_10actionG_methods.$GCINFO = "soakQ_L_10action";
        soakQ_L_10actionG_methods.$superclass = ($SuperG_class)&$actionG_methods;
        soakQ_L_10actionG_methods.__bool__ = (B_bool (*) (soakQ_L_10action))B_valueG_methods.__bool__;
        soakQ_L_10actionG_methods.__str__ = (B_str (*) (soakQ_L_10action))B_valueG_methods.__str__;
        soakQ_L_10actionG_methods.__repr__ = (B_str (*) (soakQ_L_10action))B_valueG_methods.__repr__;
        soakQ_L_10actionG_methods.__init__ = (B_NoneType (*) (soakQ_L_10action, soakQ_main))soakQ_L_10actionD___init__;
        soakQ_L_10actionG_methods.__call__ = ($R (*) (soakQ_L_10action, $Cont, sshQ_ServerSession, sshQ_AuthRequest))soakQ_L_10actionD___call__;
        soakQ_L_10actionG_methods.__exec__ = ($R (*) (soakQ_L_10action, $Cont, sshQ_ServerSession, sshQ_AuthRequest))soakQ_L_10actionD___exec__;
        soakQ_L_10actionG_methods.__asyn__ = (B_Msg (*) (soakQ_L_10action, sshQ_ServerSession, sshQ_AuthRequest))soakQ_L_10actionD___asyn__;
        soakQ_L_10actionG_methods.__serialize__ = soakQ_L_10actionD___serialize__;
        soakQ_L_10actionG_methods.__deserialize__ = soakQ_L_10actionD___deserialize__;
        $register(&soakQ_L_10actionG_methods);
    }
    {
        soakQ_L_12actionG_methods.$GCINFO = "soakQ_L_12action";
        soakQ_L_12actionG_methods.$superclass = ($SuperG_class)&$actionG_methods;
        soakQ_L_12actionG_methods.__bool__ = (B_bool (*) (soakQ_L_12action))B_valueG_methods.__bool__;
        soakQ_L_12actionG_methods.__str__ = (B_str (*) (soakQ_L_12action))B_valueG_methods.__str__;
        soakQ_L_12actionG_methods.__repr__ = (B_str (*) (soakQ_L_12action))B_valueG_methods.__repr__;
        soakQ_L_12actionG_methods.__init__ = (B_NoneType (*) (soakQ_L_12action, soakQ_main))soakQ_L_12actionD___init__;
        soakQ_L_12actionG_methods.__call__ = ($R (*) (soakQ_L_12action, $Cont, sshQ_ServerSession))soakQ_L_12actionD___call__;
        soakQ_L_12actionG_methods.__exec__ = ($R (*) (soakQ_L_12action, $Cont, sshQ_ServerSession))soakQ_L_12actionD___exec__;
        soakQ_L_12actionG_methods.__asyn__ = (B_Msg (*) (soakQ_L_12action, sshQ_ServerSession))soakQ_L_12actionD___asyn__;
        soakQ_L_12actionG_methods.__serialize__ = soakQ_L_12actionD___serialize__;
        soakQ_L_12actionG_methods.__deserialize__ = soakQ_L_12actionD___deserialize__;
        $register(&soakQ_L_12actionG_methods);
    }
    {
        soakQ_L_14actionG_methods.$GCINFO = "soakQ_L_14action";
        soakQ_L_14actionG_methods.$superclass = ($SuperG_class)&$actionG_methods;
        soakQ_L_14actionG_methods.__bool__ = (B_bool (*) (soakQ_L_14action))B_valueG_methods.__bool__;
        soakQ_L_14actionG_methods.__str__ = (B_str (*) (soakQ_L_14action))B_valueG_methods.__str__;
        soakQ_L_14actionG_methods.__repr__ = (B_str (*) (soakQ_L_14action))B_valueG_methods.__repr__;
        soakQ_L_14actionG_methods.__init__ = (B_NoneType (*) (soakQ_L_14action, soakQ_main))soakQ_L_14actionD___init__;
        soakQ_L_14actionG_methods.__call__ = ($R (*) (soakQ_L_14action, $Cont, sshQ_ServerSession, sshQ_ServerChannel, B_str))soakQ_L_14actionD___call__;
        soakQ_L_14actionG_methods.__exec__ = ($R (*) (soakQ_L_14action, $Cont, sshQ_ServerSession, sshQ_ServerChannel, B_str))soakQ_L_14actionD___exec__;
        soakQ_L_14actionG_methods.__asyn__ = (B_Msg (*) (soakQ_L_14action, sshQ_ServerSession, sshQ_ServerChannel, B_str))soakQ_L_14actionD___asyn__;
        soakQ_L_14actionG_methods.__serialize__ = soakQ_L_14actionD___serialize__;
        soakQ_L_14actionG_methods.__deserialize__ = soakQ_L_14actionD___deserialize__;
        $register(&soakQ_L_14actionG_methods);
    }
    {
        soakQ_L_18ContG_methods.$GCINFO = "soakQ_L_18Cont";
        soakQ_L_18ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        soakQ_L_18ContG_methods.__bool__ = (B_bool (*) (soakQ_L_18Cont))B_valueG_methods.__bool__;
        soakQ_L_18ContG_methods.__str__ = (B_str (*) (soakQ_L_18Cont))B_valueG_methods.__str__;
        soakQ_L_18ContG_methods.__repr__ = (B_str (*) (soakQ_L_18Cont))B_valueG_methods.__repr__;
        soakQ_L_18ContG_methods.__init__ = (B_NoneType (*) (soakQ_L_18Cont, $Cont))soakQ_L_18ContD___init__;
        soakQ_L_18ContG_methods.__call__ = ($R (*) (soakQ_L_18Cont, B_NoneType))soakQ_L_18ContD___call__;
        soakQ_L_18ContG_methods.__serialize__ = soakQ_L_18ContD___serialize__;
        soakQ_L_18ContG_methods.__deserialize__ = soakQ_L_18ContD___deserialize__;
        $register(&soakQ_L_18ContG_methods);
    }
    {
        soakQ_L_19ContG_methods.$GCINFO = "soakQ_L_19Cont";
        soakQ_L_19ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        soakQ_L_19ContG_methods.__bool__ = (B_bool (*) (soakQ_L_19Cont))B_valueG_methods.__bool__;
        soakQ_L_19ContG_methods.__str__ = (B_str (*) (soakQ_L_19Cont))B_valueG_methods.__str__;
        soakQ_L_19ContG_methods.__repr__ = (B_str (*) (soakQ_L_19Cont))B_valueG_methods.__repr__;
        soakQ_L_19ContG_methods.__init__ = (B_NoneType (*) (soakQ_L_19Cont, soakQ_main, $Cont))soakQ_L_19ContD___init__;
        soakQ_L_19ContG_methods.__call__ = ($R (*) (soakQ_L_19Cont, B_u16))soakQ_L_19ContD___call__;
        soakQ_L_19ContG_methods.__serialize__ = soakQ_L_19ContD___serialize__;
        soakQ_L_19ContG_methods.__deserialize__ = soakQ_L_19ContD___deserialize__;
        $register(&soakQ_L_19ContG_methods);
    }
    {
        soakQ_L_21ContG_methods.$GCINFO = "soakQ_L_21Cont";
        soakQ_L_21ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        soakQ_L_21ContG_methods.__bool__ = (B_bool (*) (soakQ_L_21Cont))B_valueG_methods.__bool__;
        soakQ_L_21ContG_methods.__str__ = (B_str (*) (soakQ_L_21Cont))B_valueG_methods.__str__;
        soakQ_L_21ContG_methods.__repr__ = (B_str (*) (soakQ_L_21Cont))B_valueG_methods.__repr__;
        soakQ_L_21ContG_methods.__init__ = (B_NoneType (*) (soakQ_L_21Cont, $Cont))soakQ_L_21ContD___init__;
        soakQ_L_21ContG_methods.__call__ = ($R (*) (soakQ_L_21Cont, B_NoneType))soakQ_L_21ContD___call__;
        soakQ_L_21ContG_methods.__serialize__ = soakQ_L_21ContD___serialize__;
        soakQ_L_21ContG_methods.__deserialize__ = soakQ_L_21ContD___deserialize__;
        $register(&soakQ_L_21ContG_methods);
    }
    {
        soakQ_L_22ContG_methods.$GCINFO = "soakQ_L_22Cont";
        soakQ_L_22ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        soakQ_L_22ContG_methods.__bool__ = (B_bool (*) (soakQ_L_22Cont))B_valueG_methods.__bool__;
        soakQ_L_22ContG_methods.__str__ = (B_str (*) (soakQ_L_22Cont))B_valueG_methods.__str__;
        soakQ_L_22ContG_methods.__repr__ = (B_str (*) (soakQ_L_22Cont))B_valueG_methods.__repr__;
        soakQ_L_22ContG_methods.__init__ = (B_NoneType (*) (soakQ_L_22Cont, soakQ_main, $Cont, sshQ_Server))soakQ_L_22ContD___init__;
        soakQ_L_22ContG_methods.__call__ = ($R (*) (soakQ_L_22Cont, B_NoneType))soakQ_L_22ContD___call__;
        soakQ_L_22ContG_methods.__serialize__ = soakQ_L_22ContD___serialize__;
        soakQ_L_22ContG_methods.__deserialize__ = soakQ_L_22ContD___deserialize__;
        $register(&soakQ_L_22ContG_methods);
    }
    {
        soakQ_L_24ContG_methods.$GCINFO = "soakQ_L_24Cont";
        soakQ_L_24ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        soakQ_L_24ContG_methods.__bool__ = (B_bool (*) (soakQ_L_24Cont))B_valueG_methods.__bool__;
        soakQ_L_24ContG_methods.__str__ = (B_str (*) (soakQ_L_24Cont))B_valueG_methods.__str__;
        soakQ_L_24ContG_methods.__repr__ = (B_str (*) (soakQ_L_24Cont))B_valueG_methods.__repr__;
        soakQ_L_24ContG_methods.__init__ = (B_NoneType (*) (soakQ_L_24Cont, sshQ_ServerSession, $Cont))soakQ_L_24ContD___init__;
        soakQ_L_24ContG_methods.__call__ = ($R (*) (soakQ_L_24Cont, sshQ_ServerChannel))soakQ_L_24ContD___call__;
        soakQ_L_24ContG_methods.__serialize__ = soakQ_L_24ContD___serialize__;
        soakQ_L_24ContG_methods.__deserialize__ = soakQ_L_24ContD___deserialize__;
        $register(&soakQ_L_24ContG_methods);
    }
    {
        soakQ_L_26actionG_methods.$GCINFO = "soakQ_L_26action";
        soakQ_L_26actionG_methods.$superclass = ($SuperG_class)&$actionG_methods;
        soakQ_L_26actionG_methods.__bool__ = (B_bool (*) (soakQ_L_26action))B_valueG_methods.__bool__;
        soakQ_L_26actionG_methods.__str__ = (B_str (*) (soakQ_L_26action))B_valueG_methods.__str__;
        soakQ_L_26actionG_methods.__repr__ = (B_str (*) (soakQ_L_26action))B_valueG_methods.__repr__;
        soakQ_L_26actionG_methods.__init__ = (B_NoneType (*) (soakQ_L_26action, soakQ_main))soakQ_L_26actionD___init__;
        soakQ_L_26actionG_methods.__call__ = ($R (*) (soakQ_L_26action, $Cont, sshQ_ServerChannel, B_bytes))soakQ_L_26actionD___call__;
        soakQ_L_26actionG_methods.__exec__ = ($R (*) (soakQ_L_26action, $Cont, sshQ_ServerChannel, B_bytes))soakQ_L_26actionD___exec__;
        soakQ_L_26actionG_methods.__asyn__ = (B_Msg (*) (soakQ_L_26action, sshQ_ServerChannel, B_bytes))soakQ_L_26actionD___asyn__;
        soakQ_L_26actionG_methods.__serialize__ = soakQ_L_26actionD___serialize__;
        soakQ_L_26actionG_methods.__deserialize__ = soakQ_L_26actionD___deserialize__;
        $register(&soakQ_L_26actionG_methods);
    }
    {
        soakQ_L_28actionG_methods.$GCINFO = "soakQ_L_28action";
        soakQ_L_28actionG_methods.$superclass = ($SuperG_class)&$actionG_methods;
        soakQ_L_28actionG_methods.__bool__ = (B_bool (*) (soakQ_L_28action))B_valueG_methods.__bool__;
        soakQ_L_28actionG_methods.__str__ = (B_str (*) (soakQ_L_28action))B_valueG_methods.__str__;
        soakQ_L_28actionG_methods.__repr__ = (B_str (*) (soakQ_L_28action))B_valueG_methods.__repr__;
        soakQ_L_28actionG_methods.__init__ = (B_NoneType (*) (soakQ_L_28action, soakQ_main))soakQ_L_28actionD___init__;
        soakQ_L_28actionG_methods.__call__ = ($R (*) (soakQ_L_28action, $Cont, sshQ_ServerChannel, B_bytes))soakQ_L_28actionD___call__;
        soakQ_L_28actionG_methods.__exec__ = ($R (*) (soakQ_L_28action, $Cont, sshQ_ServerChannel, B_bytes))soakQ_L_28actionD___exec__;
        soakQ_L_28actionG_methods.__asyn__ = (B_Msg (*) (soakQ_L_28action, sshQ_ServerChannel, B_bytes))soakQ_L_28actionD___asyn__;
        soakQ_L_28actionG_methods.__serialize__ = soakQ_L_28actionD___serialize__;
        soakQ_L_28actionG_methods.__deserialize__ = soakQ_L_28actionD___deserialize__;
        $register(&soakQ_L_28actionG_methods);
    }
    {
        soakQ_L_30actionG_methods.$GCINFO = "soakQ_L_30action";
        soakQ_L_30actionG_methods.$superclass = ($SuperG_class)&$actionG_methods;
        soakQ_L_30actionG_methods.__bool__ = (B_bool (*) (soakQ_L_30action))B_valueG_methods.__bool__;
        soakQ_L_30actionG_methods.__str__ = (B_str (*) (soakQ_L_30action))B_valueG_methods.__str__;
        soakQ_L_30actionG_methods.__repr__ = (B_str (*) (soakQ_L_30action))B_valueG_methods.__repr__;
        soakQ_L_30actionG_methods.__init__ = (B_NoneType (*) (soakQ_L_30action, soakQ_main))soakQ_L_30actionD___init__;
        soakQ_L_30actionG_methods.__call__ = ($R (*) (soakQ_L_30action, $Cont, sshQ_ServerChannel, B_str))soakQ_L_30actionD___call__;
        soakQ_L_30actionG_methods.__exec__ = ($R (*) (soakQ_L_30action, $Cont, sshQ_ServerChannel, B_str))soakQ_L_30actionD___exec__;
        soakQ_L_30actionG_methods.__asyn__ = (B_Msg (*) (soakQ_L_30action, sshQ_ServerChannel, B_str))soakQ_L_30actionD___asyn__;
        soakQ_L_30actionG_methods.__serialize__ = soakQ_L_30actionD___serialize__;
        soakQ_L_30actionG_methods.__deserialize__ = soakQ_L_30actionD___deserialize__;
        $register(&soakQ_L_30actionG_methods);
    }
    {
        soakQ_L_34ContG_methods.$GCINFO = "soakQ_L_34Cont";
        soakQ_L_34ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        soakQ_L_34ContG_methods.__bool__ = (B_bool (*) (soakQ_L_34Cont))B_valueG_methods.__bool__;
        soakQ_L_34ContG_methods.__str__ = (B_str (*) (soakQ_L_34Cont))B_valueG_methods.__str__;
        soakQ_L_34ContG_methods.__repr__ = (B_str (*) (soakQ_L_34Cont))B_valueG_methods.__repr__;
        soakQ_L_34ContG_methods.__init__ = (B_NoneType (*) (soakQ_L_34Cont, $Cont))soakQ_L_34ContD___init__;
        soakQ_L_34ContG_methods.__call__ = ($R (*) (soakQ_L_34Cont, B_NoneType))soakQ_L_34ContD___call__;
        soakQ_L_34ContG_methods.__serialize__ = soakQ_L_34ContD___serialize__;
        soakQ_L_34ContG_methods.__deserialize__ = soakQ_L_34ContD___deserialize__;
        $register(&soakQ_L_34ContG_methods);
    }
    {
        soakQ_L_35ContG_methods.$GCINFO = "soakQ_L_35Cont";
        soakQ_L_35ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        soakQ_L_35ContG_methods.__bool__ = (B_bool (*) (soakQ_L_35Cont))B_valueG_methods.__bool__;
        soakQ_L_35ContG_methods.__str__ = (B_str (*) (soakQ_L_35Cont))B_valueG_methods.__str__;
        soakQ_L_35ContG_methods.__repr__ = (B_str (*) (soakQ_L_35Cont))B_valueG_methods.__repr__;
        soakQ_L_35ContG_methods.__init__ = (B_NoneType (*) (soakQ_L_35Cont, $Cont, soakQ_main))soakQ_L_35ContD___init__;
        soakQ_L_35ContG_methods.__call__ = ($R (*) (soakQ_L_35Cont, B_NoneType))soakQ_L_35ContD___call__;
        soakQ_L_35ContG_methods.__serialize__ = soakQ_L_35ContD___serialize__;
        soakQ_L_35ContG_methods.__deserialize__ = soakQ_L_35ContD___deserialize__;
        $register(&soakQ_L_35ContG_methods);
    }
    {
        soakQ_L_36ContG_methods.$GCINFO = "soakQ_L_36Cont";
        soakQ_L_36ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        soakQ_L_36ContG_methods.__bool__ = (B_bool (*) (soakQ_L_36Cont))B_valueG_methods.__bool__;
        soakQ_L_36ContG_methods.__str__ = (B_str (*) (soakQ_L_36Cont))B_valueG_methods.__str__;
        soakQ_L_36ContG_methods.__repr__ = (B_str (*) (soakQ_L_36Cont))B_valueG_methods.__repr__;
        soakQ_L_36ContG_methods.__init__ = (B_NoneType (*) (soakQ_L_36Cont, $Cont, soakQ_main))soakQ_L_36ContD___init__;
        soakQ_L_36ContG_methods.__call__ = ($R (*) (soakQ_L_36Cont, B_NoneType))soakQ_L_36ContD___call__;
        soakQ_L_36ContG_methods.__serialize__ = soakQ_L_36ContD___serialize__;
        soakQ_L_36ContG_methods.__deserialize__ = soakQ_L_36ContD___deserialize__;
        $register(&soakQ_L_36ContG_methods);
    }
    {
        soakQ_L_37ContG_methods.$GCINFO = "soakQ_L_37Cont";
        soakQ_L_37ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        soakQ_L_37ContG_methods.__bool__ = (B_bool (*) (soakQ_L_37Cont))B_valueG_methods.__bool__;
        soakQ_L_37ContG_methods.__str__ = (B_str (*) (soakQ_L_37Cont))B_valueG_methods.__str__;
        soakQ_L_37ContG_methods.__repr__ = (B_str (*) (soakQ_L_37Cont))B_valueG_methods.__repr__;
        soakQ_L_37ContG_methods.__init__ = (B_NoneType (*) (soakQ_L_37Cont, $Cont, soakQ_main))soakQ_L_37ContD___init__;
        soakQ_L_37ContG_methods.__call__ = ($R (*) (soakQ_L_37Cont, B_NoneType))soakQ_L_37ContD___call__;
        soakQ_L_37ContG_methods.__serialize__ = soakQ_L_37ContD___serialize__;
        soakQ_L_37ContG_methods.__deserialize__ = soakQ_L_37ContD___deserialize__;
        $register(&soakQ_L_37ContG_methods);
    }
    {
        soakQ_L_42ContG_methods.$GCINFO = "soakQ_L_42Cont";
        soakQ_L_42ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        soakQ_L_42ContG_methods.__bool__ = (B_bool (*) (soakQ_L_42Cont))B_valueG_methods.__bool__;
        soakQ_L_42ContG_methods.__str__ = (B_str (*) (soakQ_L_42Cont))B_valueG_methods.__str__;
        soakQ_L_42ContG_methods.__repr__ = (B_str (*) (soakQ_L_42Cont))B_valueG_methods.__repr__;
        soakQ_L_42ContG_methods.__init__ = (B_NoneType (*) (soakQ_L_42Cont, $Cont))soakQ_L_42ContD___init__;
        soakQ_L_42ContG_methods.__call__ = ($R (*) (soakQ_L_42Cont, sshQ_RunCommand))soakQ_L_42ContD___call__;
        soakQ_L_42ContG_methods.__serialize__ = soakQ_L_42ContD___serialize__;
        soakQ_L_42ContG_methods.__deserialize__ = soakQ_L_42ContD___deserialize__;
        $register(&soakQ_L_42ContG_methods);
    }
    {
        soakQ_L_43procG_methods.$GCINFO = "soakQ_L_43proc";
        soakQ_L_43procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        soakQ_L_43procG_methods.__bool__ = (B_bool (*) (soakQ_L_43proc))B_valueG_methods.__bool__;
        soakQ_L_43procG_methods.__str__ = (B_str (*) (soakQ_L_43proc))B_valueG_methods.__str__;
        soakQ_L_43procG_methods.__repr__ = (B_str (*) (soakQ_L_43proc))B_valueG_methods.__repr__;
        soakQ_L_43procG_methods.__init__ = (B_NoneType (*) (soakQ_L_43proc, sshQ_Channel, int64_t, B_str, B_bytes, B_bytes, B_str, sshQ_Client, soakQ_main))soakQ_L_43procD___init__;
        soakQ_L_43procG_methods.__call__ = ($R (*) (soakQ_L_43proc, $Cont))soakQ_L_43procD___call__;
        soakQ_L_43procG_methods.__exec__ = ($R (*) (soakQ_L_43proc, $Cont))soakQ_L_43procD___exec__;
        soakQ_L_43procG_methods.__serialize__ = soakQ_L_43procD___serialize__;
        soakQ_L_43procG_methods.__deserialize__ = soakQ_L_43procD___deserialize__;
        $register(&soakQ_L_43procG_methods);
    }
    {
        soakQ_L_44actionG_methods.$GCINFO = "soakQ_L_44action";
        soakQ_L_44actionG_methods.$superclass = ($SuperG_class)&$actionG_methods;
        soakQ_L_44actionG_methods.__bool__ = (B_bool (*) (soakQ_L_44action))B_valueG_methods.__bool__;
        soakQ_L_44actionG_methods.__str__ = (B_str (*) (soakQ_L_44action))B_valueG_methods.__str__;
        soakQ_L_44actionG_methods.__repr__ = (B_str (*) (soakQ_L_44action))B_valueG_methods.__repr__;
        soakQ_L_44actionG_methods.__init__ = (B_NoneType (*) (soakQ_L_44action, sshQ_Client, soakQ_main))soakQ_L_44actionD___init__;
        soakQ_L_44actionG_methods.__call__ = ($R (*) (soakQ_L_44action, $Cont, sshQ_Channel, B_int, B_str, B_bytes, B_bytes, B_str))soakQ_L_44actionD___call__;
        soakQ_L_44actionG_methods.__exec__ = ($R (*) (soakQ_L_44action, $Cont, sshQ_Channel, B_int, B_str, B_bytes, B_bytes, B_str))soakQ_L_44actionD___exec__;
        soakQ_L_44actionG_methods.__asyn__ = (B_Msg (*) (soakQ_L_44action, sshQ_Channel, B_int, B_str, B_bytes, B_bytes, B_str))soakQ_L_44actionD___asyn__;
        soakQ_L_44actionG_methods.__serialize__ = soakQ_L_44actionD___serialize__;
        soakQ_L_44actionG_methods.__deserialize__ = soakQ_L_44actionD___deserialize__;
        $register(&soakQ_L_44actionG_methods);
    }
    {
        soakQ_L_46ContG_methods.$GCINFO = "soakQ_L_46Cont";
        soakQ_L_46ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        soakQ_L_46ContG_methods.__bool__ = (B_bool (*) (soakQ_L_46Cont))B_valueG_methods.__bool__;
        soakQ_L_46ContG_methods.__str__ = (B_str (*) (soakQ_L_46Cont))B_valueG_methods.__str__;
        soakQ_L_46ContG_methods.__repr__ = (B_str (*) (soakQ_L_46Cont))B_valueG_methods.__repr__;
        soakQ_L_46ContG_methods.__init__ = (B_NoneType (*) (soakQ_L_46Cont, $Cont))soakQ_L_46ContD___init__;
        soakQ_L_46ContG_methods.__call__ = ($R (*) (soakQ_L_46Cont, B_NoneType))soakQ_L_46ContD___call__;
        soakQ_L_46ContG_methods.__serialize__ = soakQ_L_46ContD___serialize__;
        soakQ_L_46ContG_methods.__deserialize__ = soakQ_L_46ContD___deserialize__;
        $register(&soakQ_L_46ContG_methods);
    }
    {
        soakQ_L_47ContG_methods.$GCINFO = "soakQ_L_47Cont";
        soakQ_L_47ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        soakQ_L_47ContG_methods.__bool__ = (B_bool (*) (soakQ_L_47Cont))B_valueG_methods.__bool__;
        soakQ_L_47ContG_methods.__str__ = (B_str (*) (soakQ_L_47Cont))B_valueG_methods.__str__;
        soakQ_L_47ContG_methods.__repr__ = (B_str (*) (soakQ_L_47Cont))B_valueG_methods.__repr__;
        soakQ_L_47ContG_methods.__init__ = (B_NoneType (*) (soakQ_L_47Cont, soakQ_main, sshQ_Client, $Cont))soakQ_L_47ContD___init__;
        soakQ_L_47ContG_methods.__call__ = ($R (*) (soakQ_L_47Cont, B_NoneType))soakQ_L_47ContD___call__;
        soakQ_L_47ContG_methods.__serialize__ = soakQ_L_47ContD___serialize__;
        soakQ_L_47ContG_methods.__deserialize__ = soakQ_L_47ContD___deserialize__;
        $register(&soakQ_L_47ContG_methods);
    }
    {
        soakQ_L_50ContG_methods.$GCINFO = "soakQ_L_50Cont";
        soakQ_L_50ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        soakQ_L_50ContG_methods.__bool__ = (B_bool (*) (soakQ_L_50Cont))B_valueG_methods.__bool__;
        soakQ_L_50ContG_methods.__str__ = (B_str (*) (soakQ_L_50Cont))B_valueG_methods.__str__;
        soakQ_L_50ContG_methods.__repr__ = (B_str (*) (soakQ_L_50Cont))B_valueG_methods.__repr__;
        soakQ_L_50ContG_methods.__init__ = (B_NoneType (*) (soakQ_L_50Cont, $Cont))soakQ_L_50ContD___init__;
        soakQ_L_50ContG_methods.__call__ = ($R (*) (soakQ_L_50Cont, B_NoneType))soakQ_L_50ContD___call__;
        soakQ_L_50ContG_methods.__serialize__ = soakQ_L_50ContD___serialize__;
        soakQ_L_50ContG_methods.__deserialize__ = soakQ_L_50ContD___deserialize__;
        $register(&soakQ_L_50ContG_methods);
    }
    {
        soakQ_L_52ContG_methods.$GCINFO = "soakQ_L_52Cont";
        soakQ_L_52ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        soakQ_L_52ContG_methods.__bool__ = (B_bool (*) (soakQ_L_52Cont))B_valueG_methods.__bool__;
        soakQ_L_52ContG_methods.__str__ = (B_str (*) (soakQ_L_52Cont))B_valueG_methods.__str__;
        soakQ_L_52ContG_methods.__repr__ = (B_str (*) (soakQ_L_52Cont))B_valueG_methods.__repr__;
        soakQ_L_52ContG_methods.__init__ = (B_NoneType (*) (soakQ_L_52Cont, $Cont))soakQ_L_52ContD___init__;
        soakQ_L_52ContG_methods.__call__ = ($R (*) (soakQ_L_52Cont, sshQ_Client))soakQ_L_52ContD___call__;
        soakQ_L_52ContG_methods.__serialize__ = soakQ_L_52ContD___serialize__;
        soakQ_L_52ContG_methods.__deserialize__ = soakQ_L_52ContD___deserialize__;
        $register(&soakQ_L_52ContG_methods);
    }
    {
        soakQ_L_53procG_methods.$GCINFO = "soakQ_L_53proc";
        soakQ_L_53procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        soakQ_L_53procG_methods.__bool__ = (B_bool (*) (soakQ_L_53proc))B_valueG_methods.__bool__;
        soakQ_L_53procG_methods.__str__ = (B_str (*) (soakQ_L_53proc))B_valueG_methods.__str__;
        soakQ_L_53procG_methods.__repr__ = (B_str (*) (soakQ_L_53proc))B_valueG_methods.__repr__;
        soakQ_L_53procG_methods.__init__ = (B_NoneType (*) (soakQ_L_53proc, sshQ_Client, B_str, soakQ_main))soakQ_L_53procD___init__;
        soakQ_L_53procG_methods.__call__ = ($R (*) (soakQ_L_53proc, $Cont))soakQ_L_53procD___call__;
        soakQ_L_53procG_methods.__exec__ = ($R (*) (soakQ_L_53proc, $Cont))soakQ_L_53procD___exec__;
        soakQ_L_53procG_methods.__serialize__ = soakQ_L_53procD___serialize__;
        soakQ_L_53procG_methods.__deserialize__ = soakQ_L_53procD___deserialize__;
        $register(&soakQ_L_53procG_methods);
    }
    {
        soakQ_L_54actionG_methods.$GCINFO = "soakQ_L_54action";
        soakQ_L_54actionG_methods.$superclass = ($SuperG_class)&$actionG_methods;
        soakQ_L_54actionG_methods.__bool__ = (B_bool (*) (soakQ_L_54action))B_valueG_methods.__bool__;
        soakQ_L_54actionG_methods.__str__ = (B_str (*) (soakQ_L_54action))B_valueG_methods.__str__;
        soakQ_L_54actionG_methods.__repr__ = (B_str (*) (soakQ_L_54action))B_valueG_methods.__repr__;
        soakQ_L_54actionG_methods.__init__ = (B_NoneType (*) (soakQ_L_54action, soakQ_main))soakQ_L_54actionD___init__;
        soakQ_L_54actionG_methods.__call__ = ($R (*) (soakQ_L_54action, $Cont, sshQ_Client, B_str))soakQ_L_54actionD___call__;
        soakQ_L_54actionG_methods.__exec__ = ($R (*) (soakQ_L_54action, $Cont, sshQ_Client, B_str))soakQ_L_54actionD___exec__;
        soakQ_L_54actionG_methods.__asyn__ = (B_Msg (*) (soakQ_L_54action, sshQ_Client, B_str))soakQ_L_54actionD___asyn__;
        soakQ_L_54actionG_methods.__serialize__ = soakQ_L_54actionD___serialize__;
        soakQ_L_54actionG_methods.__deserialize__ = soakQ_L_54actionD___deserialize__;
        $register(&soakQ_L_54actionG_methods);
    }
    {
        soakQ_L_55procG_methods.$GCINFO = "soakQ_L_55proc";
        soakQ_L_55procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        soakQ_L_55procG_methods.__bool__ = (B_bool (*) (soakQ_L_55proc))B_valueG_methods.__bool__;
        soakQ_L_55procG_methods.__str__ = (B_str (*) (soakQ_L_55proc))B_valueG_methods.__str__;
        soakQ_L_55procG_methods.__repr__ = (B_str (*) (soakQ_L_55proc))B_valueG_methods.__repr__;
        soakQ_L_55procG_methods.__init__ = (B_NoneType (*) (soakQ_L_55proc, sshQ_Client, B_str, soakQ_main))soakQ_L_55procD___init__;
        soakQ_L_55procG_methods.__call__ = ($R (*) (soakQ_L_55proc, $Cont))soakQ_L_55procD___call__;
        soakQ_L_55procG_methods.__exec__ = ($R (*) (soakQ_L_55proc, $Cont))soakQ_L_55procD___exec__;
        soakQ_L_55procG_methods.__serialize__ = soakQ_L_55procD___serialize__;
        soakQ_L_55procG_methods.__deserialize__ = soakQ_L_55procD___deserialize__;
        $register(&soakQ_L_55procG_methods);
    }
    {
        soakQ_L_56actionG_methods.$GCINFO = "soakQ_L_56action";
        soakQ_L_56actionG_methods.$superclass = ($SuperG_class)&$actionG_methods;
        soakQ_L_56actionG_methods.__bool__ = (B_bool (*) (soakQ_L_56action))B_valueG_methods.__bool__;
        soakQ_L_56actionG_methods.__str__ = (B_str (*) (soakQ_L_56action))B_valueG_methods.__str__;
        soakQ_L_56actionG_methods.__repr__ = (B_str (*) (soakQ_L_56action))B_valueG_methods.__repr__;
        soakQ_L_56actionG_methods.__init__ = (B_NoneType (*) (soakQ_L_56action, soakQ_main))soakQ_L_56actionD___init__;
        soakQ_L_56actionG_methods.__call__ = ($R (*) (soakQ_L_56action, $Cont, sshQ_Client, B_str))soakQ_L_56actionD___call__;
        soakQ_L_56actionG_methods.__exec__ = ($R (*) (soakQ_L_56action, $Cont, sshQ_Client, B_str))soakQ_L_56actionD___exec__;
        soakQ_L_56actionG_methods.__asyn__ = (B_Msg (*) (soakQ_L_56action, sshQ_Client, B_str))soakQ_L_56actionD___asyn__;
        soakQ_L_56actionG_methods.__serialize__ = soakQ_L_56actionD___serialize__;
        soakQ_L_56actionG_methods.__deserialize__ = soakQ_L_56actionD___deserialize__;
        $register(&soakQ_L_56actionG_methods);
    }
    {
        soakQ_L_58actionG_methods.$GCINFO = "soakQ_L_58action";
        soakQ_L_58actionG_methods.$superclass = ($SuperG_class)&$actionG_methods;
        soakQ_L_58actionG_methods.__bool__ = (B_bool (*) (soakQ_L_58action))B_valueG_methods.__bool__;
        soakQ_L_58actionG_methods.__str__ = (B_str (*) (soakQ_L_58action))B_valueG_methods.__str__;
        soakQ_L_58actionG_methods.__repr__ = (B_str (*) (soakQ_L_58action))B_valueG_methods.__repr__;
        soakQ_L_58actionG_methods.__init__ = (B_NoneType (*) (soakQ_L_58action, soakQ_main))soakQ_L_58actionD___init__;
        soakQ_L_58actionG_methods.__call__ = ($R (*) (soakQ_L_58action, $Cont, sshQ_Client, B_str, sshQ_HostKeyInfo))soakQ_L_58actionD___call__;
        soakQ_L_58actionG_methods.__exec__ = ($R (*) (soakQ_L_58action, $Cont, sshQ_Client, B_str, sshQ_HostKeyInfo))soakQ_L_58actionD___exec__;
        soakQ_L_58actionG_methods.__asyn__ = (B_Msg (*) (soakQ_L_58action, sshQ_Client, B_str, sshQ_HostKeyInfo))soakQ_L_58actionD___asyn__;
        soakQ_L_58actionG_methods.__serialize__ = soakQ_L_58actionD___serialize__;
        soakQ_L_58actionG_methods.__deserialize__ = soakQ_L_58actionD___deserialize__;
        $register(&soakQ_L_58actionG_methods);
    }
    {
        soakQ_L_59procG_methods.$GCINFO = "soakQ_L_59proc";
        soakQ_L_59procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        soakQ_L_59procG_methods.__bool__ = (B_bool (*) (soakQ_L_59proc))B_valueG_methods.__bool__;
        soakQ_L_59procG_methods.__str__ = (B_str (*) (soakQ_L_59proc))B_valueG_methods.__str__;
        soakQ_L_59procG_methods.__repr__ = (B_str (*) (soakQ_L_59proc))B_valueG_methods.__repr__;
        soakQ_L_59procG_methods.__init__ = (B_NoneType (*) (soakQ_L_59proc, soakQ_main))soakQ_L_59procD___init__;
        soakQ_L_59procG_methods.__call__ = ($R (*) (soakQ_L_59proc, $Cont))soakQ_L_59procD___call__;
        soakQ_L_59procG_methods.__exec__ = ($R (*) (soakQ_L_59proc, $Cont))soakQ_L_59procD___exec__;
        soakQ_L_59procG_methods.__serialize__ = soakQ_L_59procD___serialize__;
        soakQ_L_59procG_methods.__deserialize__ = soakQ_L_59procD___deserialize__;
        $register(&soakQ_L_59procG_methods);
    }
    {
        soakQ_L_60procG_methods.$GCINFO = "soakQ_L_60proc";
        soakQ_L_60procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        soakQ_L_60procG_methods.__bool__ = (B_bool (*) (soakQ_L_60proc))B_valueG_methods.__bool__;
        soakQ_L_60procG_methods.__str__ = (B_str (*) (soakQ_L_60proc))B_valueG_methods.__str__;
        soakQ_L_60procG_methods.__repr__ = (B_str (*) (soakQ_L_60proc))B_valueG_methods.__repr__;
        soakQ_L_60procG_methods.__init__ = (B_NoneType (*) (soakQ_L_60proc, soakQ_main, B_str))soakQ_L_60procD___init__;
        soakQ_L_60procG_methods.__call__ = ($R (*) (soakQ_L_60proc, $Cont))soakQ_L_60procD___call__;
        soakQ_L_60procG_methods.__exec__ = ($R (*) (soakQ_L_60proc, $Cont))soakQ_L_60procD___exec__;
        soakQ_L_60procG_methods.__serialize__ = soakQ_L_60procD___serialize__;
        soakQ_L_60procG_methods.__deserialize__ = soakQ_L_60procD___deserialize__;
        $register(&soakQ_L_60procG_methods);
    }
    {
        soakQ_L_61procG_methods.$GCINFO = "soakQ_L_61proc";
        soakQ_L_61procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        soakQ_L_61procG_methods.__bool__ = (B_bool (*) (soakQ_L_61proc))B_valueG_methods.__bool__;
        soakQ_L_61procG_methods.__str__ = (B_str (*) (soakQ_L_61proc))B_valueG_methods.__str__;
        soakQ_L_61procG_methods.__repr__ = (B_str (*) (soakQ_L_61proc))B_valueG_methods.__repr__;
        soakQ_L_61procG_methods.__init__ = (B_NoneType (*) (soakQ_L_61proc, soakQ_main, sshQ_Server, B_str))soakQ_L_61procD___init__;
        soakQ_L_61procG_methods.__call__ = ($R (*) (soakQ_L_61proc, $Cont))soakQ_L_61procD___call__;
        soakQ_L_61procG_methods.__exec__ = ($R (*) (soakQ_L_61proc, $Cont))soakQ_L_61procD___exec__;
        soakQ_L_61procG_methods.__serialize__ = soakQ_L_61procD___serialize__;
        soakQ_L_61procG_methods.__deserialize__ = soakQ_L_61procD___deserialize__;
        $register(&soakQ_L_61procG_methods);
    }
    {
        soakQ_L_62procG_methods.$GCINFO = "soakQ_L_62proc";
        soakQ_L_62procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        soakQ_L_62procG_methods.__bool__ = (B_bool (*) (soakQ_L_62proc))B_valueG_methods.__bool__;
        soakQ_L_62procG_methods.__str__ = (B_str (*) (soakQ_L_62proc))B_valueG_methods.__str__;
        soakQ_L_62procG_methods.__repr__ = (B_str (*) (soakQ_L_62proc))B_valueG_methods.__repr__;
        soakQ_L_62procG_methods.__init__ = (B_NoneType (*) (soakQ_L_62proc, soakQ_main, sshQ_Server, B_str))soakQ_L_62procD___init__;
        soakQ_L_62procG_methods.__call__ = ($R (*) (soakQ_L_62proc, $Cont))soakQ_L_62procD___call__;
        soakQ_L_62procG_methods.__exec__ = ($R (*) (soakQ_L_62proc, $Cont))soakQ_L_62procD___exec__;
        soakQ_L_62procG_methods.__serialize__ = soakQ_L_62procD___serialize__;
        soakQ_L_62procG_methods.__deserialize__ = soakQ_L_62procD___deserialize__;
        $register(&soakQ_L_62procG_methods);
    }
    {
        soakQ_L_63procG_methods.$GCINFO = "soakQ_L_63proc";
        soakQ_L_63procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        soakQ_L_63procG_methods.__bool__ = (B_bool (*) (soakQ_L_63proc))B_valueG_methods.__bool__;
        soakQ_L_63procG_methods.__str__ = (B_str (*) (soakQ_L_63proc))B_valueG_methods.__str__;
        soakQ_L_63procG_methods.__repr__ = (B_str (*) (soakQ_L_63proc))B_valueG_methods.__repr__;
        soakQ_L_63procG_methods.__init__ = (B_NoneType (*) (soakQ_L_63proc, soakQ_main, sshQ_ServerSession))soakQ_L_63procD___init__;
        soakQ_L_63procG_methods.__call__ = ($R (*) (soakQ_L_63proc, $Cont))soakQ_L_63procD___call__;
        soakQ_L_63procG_methods.__exec__ = ($R (*) (soakQ_L_63proc, $Cont))soakQ_L_63procD___exec__;
        soakQ_L_63procG_methods.__serialize__ = soakQ_L_63procD___serialize__;
        soakQ_L_63procG_methods.__deserialize__ = soakQ_L_63procD___deserialize__;
        $register(&soakQ_L_63procG_methods);
    }
    {
        soakQ_L_64procG_methods.$GCINFO = "soakQ_L_64proc";
        soakQ_L_64procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        soakQ_L_64procG_methods.__bool__ = (B_bool (*) (soakQ_L_64proc))B_valueG_methods.__bool__;
        soakQ_L_64procG_methods.__str__ = (B_str (*) (soakQ_L_64proc))B_valueG_methods.__str__;
        soakQ_L_64procG_methods.__repr__ = (B_str (*) (soakQ_L_64proc))B_valueG_methods.__repr__;
        soakQ_L_64procG_methods.__init__ = (B_NoneType (*) (soakQ_L_64proc, soakQ_main, sshQ_ServerSession, sshQ_AuthRequest))soakQ_L_64procD___init__;
        soakQ_L_64procG_methods.__call__ = ($R (*) (soakQ_L_64proc, $Cont))soakQ_L_64procD___call__;
        soakQ_L_64procG_methods.__exec__ = ($R (*) (soakQ_L_64proc, $Cont))soakQ_L_64procD___exec__;
        soakQ_L_64procG_methods.__serialize__ = soakQ_L_64procD___serialize__;
        soakQ_L_64procG_methods.__deserialize__ = soakQ_L_64procD___deserialize__;
        $register(&soakQ_L_64procG_methods);
    }
    {
        soakQ_L_65procG_methods.$GCINFO = "soakQ_L_65proc";
        soakQ_L_65procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        soakQ_L_65procG_methods.__bool__ = (B_bool (*) (soakQ_L_65proc))B_valueG_methods.__bool__;
        soakQ_L_65procG_methods.__str__ = (B_str (*) (soakQ_L_65proc))B_valueG_methods.__str__;
        soakQ_L_65procG_methods.__repr__ = (B_str (*) (soakQ_L_65proc))B_valueG_methods.__repr__;
        soakQ_L_65procG_methods.__init__ = (B_NoneType (*) (soakQ_L_65proc, soakQ_main, sshQ_ServerChannel, B_bytes))soakQ_L_65procD___init__;
        soakQ_L_65procG_methods.__call__ = ($R (*) (soakQ_L_65proc, $Cont))soakQ_L_65procD___call__;
        soakQ_L_65procG_methods.__exec__ = ($R (*) (soakQ_L_65proc, $Cont))soakQ_L_65procD___exec__;
        soakQ_L_65procG_methods.__serialize__ = soakQ_L_65procD___serialize__;
        soakQ_L_65procG_methods.__deserialize__ = soakQ_L_65procD___deserialize__;
        $register(&soakQ_L_65procG_methods);
    }
    {
        soakQ_L_66procG_methods.$GCINFO = "soakQ_L_66proc";
        soakQ_L_66procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        soakQ_L_66procG_methods.__bool__ = (B_bool (*) (soakQ_L_66proc))B_valueG_methods.__bool__;
        soakQ_L_66procG_methods.__str__ = (B_str (*) (soakQ_L_66proc))B_valueG_methods.__str__;
        soakQ_L_66procG_methods.__repr__ = (B_str (*) (soakQ_L_66proc))B_valueG_methods.__repr__;
        soakQ_L_66procG_methods.__init__ = (B_NoneType (*) (soakQ_L_66proc, soakQ_main, sshQ_ServerChannel, B_bytes))soakQ_L_66procD___init__;
        soakQ_L_66procG_methods.__call__ = ($R (*) (soakQ_L_66proc, $Cont))soakQ_L_66procD___call__;
        soakQ_L_66procG_methods.__exec__ = ($R (*) (soakQ_L_66proc, $Cont))soakQ_L_66procD___exec__;
        soakQ_L_66procG_methods.__serialize__ = soakQ_L_66procD___serialize__;
        soakQ_L_66procG_methods.__deserialize__ = soakQ_L_66procD___deserialize__;
        $register(&soakQ_L_66procG_methods);
    }
    {
        soakQ_L_67procG_methods.$GCINFO = "soakQ_L_67proc";
        soakQ_L_67procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        soakQ_L_67procG_methods.__bool__ = (B_bool (*) (soakQ_L_67proc))B_valueG_methods.__bool__;
        soakQ_L_67procG_methods.__str__ = (B_str (*) (soakQ_L_67proc))B_valueG_methods.__str__;
        soakQ_L_67procG_methods.__repr__ = (B_str (*) (soakQ_L_67proc))B_valueG_methods.__repr__;
        soakQ_L_67procG_methods.__init__ = (B_NoneType (*) (soakQ_L_67proc, soakQ_main, sshQ_ServerChannel, B_str))soakQ_L_67procD___init__;
        soakQ_L_67procG_methods.__call__ = ($R (*) (soakQ_L_67proc, $Cont))soakQ_L_67procD___call__;
        soakQ_L_67procG_methods.__exec__ = ($R (*) (soakQ_L_67proc, $Cont))soakQ_L_67procD___exec__;
        soakQ_L_67procG_methods.__serialize__ = soakQ_L_67procD___serialize__;
        soakQ_L_67procG_methods.__deserialize__ = soakQ_L_67procD___deserialize__;
        $register(&soakQ_L_67procG_methods);
    }
    {
        soakQ_L_68procG_methods.$GCINFO = "soakQ_L_68proc";
        soakQ_L_68procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        soakQ_L_68procG_methods.__bool__ = (B_bool (*) (soakQ_L_68proc))B_valueG_methods.__bool__;
        soakQ_L_68procG_methods.__str__ = (B_str (*) (soakQ_L_68proc))B_valueG_methods.__str__;
        soakQ_L_68procG_methods.__repr__ = (B_str (*) (soakQ_L_68proc))B_valueG_methods.__repr__;
        soakQ_L_68procG_methods.__init__ = (B_NoneType (*) (soakQ_L_68proc, soakQ_main, sshQ_ServerSession))soakQ_L_68procD___init__;
        soakQ_L_68procG_methods.__call__ = ($R (*) (soakQ_L_68proc, $Cont))soakQ_L_68procD___call__;
        soakQ_L_68procG_methods.__exec__ = ($R (*) (soakQ_L_68proc, $Cont))soakQ_L_68procD___exec__;
        soakQ_L_68procG_methods.__serialize__ = soakQ_L_68procD___serialize__;
        soakQ_L_68procG_methods.__deserialize__ = soakQ_L_68procD___deserialize__;
        $register(&soakQ_L_68procG_methods);
    }
    {
        soakQ_L_69procG_methods.$GCINFO = "soakQ_L_69proc";
        soakQ_L_69procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        soakQ_L_69procG_methods.__bool__ = (B_bool (*) (soakQ_L_69proc))B_valueG_methods.__bool__;
        soakQ_L_69procG_methods.__str__ = (B_str (*) (soakQ_L_69proc))B_valueG_methods.__str__;
        soakQ_L_69procG_methods.__repr__ = (B_str (*) (soakQ_L_69proc))B_valueG_methods.__repr__;
        soakQ_L_69procG_methods.__init__ = (B_NoneType (*) (soakQ_L_69proc, soakQ_main, sshQ_ServerSession, sshQ_ServerChannel, B_str))soakQ_L_69procD___init__;
        soakQ_L_69procG_methods.__call__ = ($R (*) (soakQ_L_69proc, $Cont))soakQ_L_69procD___call__;
        soakQ_L_69procG_methods.__exec__ = ($R (*) (soakQ_L_69proc, $Cont))soakQ_L_69procD___exec__;
        soakQ_L_69procG_methods.__serialize__ = soakQ_L_69procD___serialize__;
        soakQ_L_69procG_methods.__deserialize__ = soakQ_L_69procD___deserialize__;
        $register(&soakQ_L_69procG_methods);
    }
    {
        soakQ_L_70procG_methods.$GCINFO = "soakQ_L_70proc";
        soakQ_L_70procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        soakQ_L_70procG_methods.__bool__ = (B_bool (*) (soakQ_L_70proc))B_valueG_methods.__bool__;
        soakQ_L_70procG_methods.__str__ = (B_str (*) (soakQ_L_70proc))B_valueG_methods.__str__;
        soakQ_L_70procG_methods.__repr__ = (B_str (*) (soakQ_L_70proc))B_valueG_methods.__repr__;
        soakQ_L_70procG_methods.__init__ = (B_NoneType (*) (soakQ_L_70proc, soakQ_main, sshQ_Client, B_str, sshQ_HostKeyInfo))soakQ_L_70procD___init__;
        soakQ_L_70procG_methods.__call__ = ($R (*) (soakQ_L_70proc, $Cont))soakQ_L_70procD___call__;
        soakQ_L_70procG_methods.__exec__ = ($R (*) (soakQ_L_70proc, $Cont))soakQ_L_70procD___exec__;
        soakQ_L_70procG_methods.__serialize__ = soakQ_L_70procD___serialize__;
        soakQ_L_70procG_methods.__deserialize__ = soakQ_L_70procD___deserialize__;
        $register(&soakQ_L_70procG_methods);
    }
    {
        soakQ_L_71procG_methods.$GCINFO = "soakQ_L_71proc";
        soakQ_L_71procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        soakQ_L_71procG_methods.__bool__ = (B_bool (*) (soakQ_L_71proc))B_valueG_methods.__bool__;
        soakQ_L_71procG_methods.__str__ = (B_str (*) (soakQ_L_71proc))B_valueG_methods.__str__;
        soakQ_L_71procG_methods.__repr__ = (B_str (*) (soakQ_L_71proc))B_valueG_methods.__repr__;
        soakQ_L_71procG_methods.__init__ = (B_NoneType (*) (soakQ_L_71proc, soakQ_main))soakQ_L_71procD___init__;
        soakQ_L_71procG_methods.__call__ = ($R (*) (soakQ_L_71proc, $Cont))soakQ_L_71procD___call__;
        soakQ_L_71procG_methods.__exec__ = ($R (*) (soakQ_L_71proc, $Cont))soakQ_L_71procD___exec__;
        soakQ_L_71procG_methods.__serialize__ = soakQ_L_71procD___serialize__;
        soakQ_L_71procG_methods.__deserialize__ = soakQ_L_71procD___deserialize__;
        $register(&soakQ_L_71procG_methods);
    }
    {
        soakQ_L_72procG_methods.$GCINFO = "soakQ_L_72proc";
        soakQ_L_72procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        soakQ_L_72procG_methods.__bool__ = (B_bool (*) (soakQ_L_72proc))B_valueG_methods.__bool__;
        soakQ_L_72procG_methods.__str__ = (B_str (*) (soakQ_L_72proc))B_valueG_methods.__str__;
        soakQ_L_72procG_methods.__repr__ = (B_str (*) (soakQ_L_72proc))B_valueG_methods.__repr__;
        soakQ_L_72procG_methods.__init__ = (B_NoneType (*) (soakQ_L_72proc, soakQ_main))soakQ_L_72procD___init__;
        soakQ_L_72procG_methods.__call__ = ($R (*) (soakQ_L_72proc, $Cont))soakQ_L_72procD___call__;
        soakQ_L_72procG_methods.__exec__ = ($R (*) (soakQ_L_72proc, $Cont))soakQ_L_72procD___exec__;
        soakQ_L_72procG_methods.__serialize__ = soakQ_L_72procD___serialize__;
        soakQ_L_72procG_methods.__deserialize__ = soakQ_L_72procD___deserialize__;
        $register(&soakQ_L_72procG_methods);
    }
    {
        soakQ_L_74ContG_methods.$GCINFO = "soakQ_L_74Cont";
        soakQ_L_74ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        soakQ_L_74ContG_methods.__bool__ = (B_bool (*) (soakQ_L_74Cont))B_valueG_methods.__bool__;
        soakQ_L_74ContG_methods.__str__ = (B_str (*) (soakQ_L_74Cont))B_valueG_methods.__str__;
        soakQ_L_74ContG_methods.__repr__ = (B_str (*) (soakQ_L_74Cont))B_valueG_methods.__repr__;
        soakQ_L_74ContG_methods.__init__ = (B_NoneType (*) (soakQ_L_74Cont, $Cont, soakQ_main))soakQ_L_74ContD___init__;
        soakQ_L_74ContG_methods.__call__ = ($R (*) (soakQ_L_74Cont, B_NoneType))soakQ_L_74ContD___call__;
        soakQ_L_74ContG_methods.__serialize__ = soakQ_L_74ContD___serialize__;
        soakQ_L_74ContG_methods.__deserialize__ = soakQ_L_74ContD___deserialize__;
        $register(&soakQ_L_74ContG_methods);
    }
    {
        soakQ_L_75procG_methods.$GCINFO = "soakQ_L_75proc";
        soakQ_L_75procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        soakQ_L_75procG_methods.__bool__ = (B_bool (*) (soakQ_L_75proc))B_valueG_methods.__bool__;
        soakQ_L_75procG_methods.__str__ = (B_str (*) (soakQ_L_75proc))B_valueG_methods.__str__;
        soakQ_L_75procG_methods.__repr__ = (B_str (*) (soakQ_L_75proc))B_valueG_methods.__repr__;
        soakQ_L_75procG_methods.__init__ = (B_NoneType (*) (soakQ_L_75proc, soakQ_main, B_Env))soakQ_L_75procD___init__;
        soakQ_L_75procG_methods.__call__ = ($R (*) (soakQ_L_75proc, $Cont))soakQ_L_75procD___call__;
        soakQ_L_75procG_methods.__exec__ = ($R (*) (soakQ_L_75proc, $Cont))soakQ_L_75procD___exec__;
        soakQ_L_75procG_methods.__serialize__ = soakQ_L_75procD___serialize__;
        soakQ_L_75procG_methods.__deserialize__ = soakQ_L_75procD___deserialize__;
        $register(&soakQ_L_75procG_methods);
    }
    {
        soakQ_mainG_methods.$GCINFO = "soakQ_main";
        soakQ_mainG_methods.$superclass = ($SuperG_class)&$ActorG_methods;
        soakQ_mainG_methods.__bool__ = (B_bool (*) (soakQ_main))$ActorG_methods.__bool__;
        soakQ_mainG_methods.__str__ = (B_str (*) (soakQ_main))$ActorG_methods.__str__;
        soakQ_mainG_methods.__repr__ = (B_str (*) (soakQ_main))$ActorG_methods.__repr__;
        soakQ_mainG_methods.__resume__ = (B_NoneType (*) (soakQ_main))$ActorG_methods.__resume__;
        soakQ_mainG_methods.__cleanup__ = (B_NoneType (*) (soakQ_main))$ActorG_methods.__cleanup__;
        soakQ_mainG_methods.__init__ = ($R (*) (soakQ_main, $Cont, B_Env))soakQ_mainD___init__;
        soakQ_mainG_methods.reportG_local = ($R (*) (soakQ_main, $Cont))soakQ_mainD_reportG_local;
        soakQ_mainG_methods.failG_local = ($R (*) (soakQ_main, $Cont, B_str))soakQ_mainD_failG_local;
        soakQ_mainG_methods.on_listenG_local = ($R (*) (soakQ_main, $Cont, sshQ_Server, B_str))soakQ_mainD_on_listenG_local;
        soakQ_mainG_methods.on_server_closeG_local = ($R (*) (soakQ_main, $Cont, sshQ_Server, B_str))soakQ_mainD_on_server_closeG_local;
        soakQ_mainG_methods.on_sessionG_local = ($R (*) (soakQ_main, $Cont, sshQ_ServerSession))soakQ_mainD_on_sessionG_local;
        soakQ_mainG_methods.on_authG_local = ($R (*) (soakQ_main, $Cont, sshQ_ServerSession, sshQ_AuthRequest))soakQ_mainD_on_authG_local;
        soakQ_mainG_methods.srv_on_dataG_local = ($R (*) (soakQ_main, $Cont, sshQ_ServerChannel, B_bytes))soakQ_mainD_srv_on_dataG_local;
        soakQ_mainG_methods.srv_on_stderrG_local = ($R (*) (soakQ_main, $Cont, sshQ_ServerChannel, B_bytes))soakQ_mainD_srv_on_stderrG_local;
        soakQ_mainG_methods.srv_on_closeG_local = ($R (*) (soakQ_main, $Cont, sshQ_ServerChannel, B_str))soakQ_mainD_srv_on_closeG_local;
        soakQ_mainG_methods.on_channel_openG_local = ($R (*) (soakQ_main, $Cont, sshQ_ServerSession))soakQ_mainD_on_channel_openG_local;
        soakQ_mainG_methods.on_execG_local = ($R (*) (soakQ_main, $Cont, sshQ_ServerSession, sshQ_ServerChannel, B_str))soakQ_mainD_on_execG_local;
        soakQ_mainG_methods.on_hostkeyG_local = ($R (*) (soakQ_main, $Cont, sshQ_Client, B_str, sshQ_HostKeyInfo))soakQ_mainD_on_hostkeyG_local;
        soakQ_mainG_methods.next_cycleG_local = ($R (*) (soakQ_main, $Cont))soakQ_mainD_next_cycleG_local;
        soakQ_mainG_methods.start_cycleG_local = ($R (*) (soakQ_main, $Cont))soakQ_mainD_start_cycleG_local;
        soakQ_mainG_methods.report = (B_Msg (*) (soakQ_main))soakQ_mainD_report;
        soakQ_mainG_methods.fail = (B_Msg (*) (soakQ_main, B_str))soakQ_mainD_fail;
        soakQ_mainG_methods.on_listen = (B_Msg (*) (soakQ_main, sshQ_Server, B_str))soakQ_mainD_on_listen;
        soakQ_mainG_methods.on_server_close = (B_Msg (*) (soakQ_main, sshQ_Server, B_str))soakQ_mainD_on_server_close;
        soakQ_mainG_methods.on_session = (B_Msg (*) (soakQ_main, sshQ_ServerSession))soakQ_mainD_on_session;
        soakQ_mainG_methods.on_auth = (B_Msg (*) (soakQ_main, sshQ_ServerSession, sshQ_AuthRequest))soakQ_mainD_on_auth;
        soakQ_mainG_methods.srv_on_data = (B_Msg (*) (soakQ_main, sshQ_ServerChannel, B_bytes))soakQ_mainD_srv_on_data;
        soakQ_mainG_methods.srv_on_stderr = (B_Msg (*) (soakQ_main, sshQ_ServerChannel, B_bytes))soakQ_mainD_srv_on_stderr;
        soakQ_mainG_methods.srv_on_close = (B_Msg (*) (soakQ_main, sshQ_ServerChannel, B_str))soakQ_mainD_srv_on_close;
        soakQ_mainG_methods.on_channel_open = (B_Msg (*) (soakQ_main, sshQ_ServerSession))soakQ_mainD_on_channel_open;
        soakQ_mainG_methods.on_exec = (B_Msg (*) (soakQ_main, sshQ_ServerSession, sshQ_ServerChannel, B_str))soakQ_mainD_on_exec;
        soakQ_mainG_methods.on_hostkey = (B_Msg (*) (soakQ_main, sshQ_Client, B_str, sshQ_HostKeyInfo))soakQ_mainD_on_hostkey;
        soakQ_mainG_methods.next_cycle = (B_Msg (*) (soakQ_main))soakQ_mainD_next_cycle;
        soakQ_mainG_methods.start_cycle = (B_Msg (*) (soakQ_main))soakQ_mainD_start_cycle;
        soakQ_mainG_methods.__serialize__ = soakQ_mainD___serialize__;
        soakQ_mainG_methods.__deserialize__ = soakQ_mainD___deserialize__;
        $register(&soakQ_mainG_methods);
    }
    B_Collection W_main_27 = (B_Collection)B_SequenceD_listG_witness->W_Collection;
    soakQ_W_main_27 = W_main_27;
}