/* Acton impl hash: 6b69f73fd0903b8307bcae77aea5aa342cdbc77193dc8959b003e7410289d3f5 */
#include "rts/common.h"
#include "out/types/interop_server.h"
B_Eq interop_serverQ_W_main_1090;
B_Eq interop_serverQ_W_main_336;
B_Eq interop_serverQ_W_main_294;
$R interop_serverQ_L_1C_5cont (interop_serverQ_main self, $Cont C_cont, sshQ_Server C_6res) {
    #line 125 "src/interop_server.act"
    ((interop_serverQ_main)(self))->server = C_6res;
    return $R_CONT(C_cont, B_None);
}
B_NoneType interop_serverQ_L_2ContD___init__ (interop_serverQ_L_2Cont L_self, interop_serverQ_main self, $Cont C_cont) {
    ((interop_serverQ_L_2Cont)(L_self))->self = self;
    ((interop_serverQ_L_2Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R interop_serverQ_L_2ContD___call__ (interop_serverQ_L_2Cont L_self, sshQ_Server G_1) {
    interop_serverQ_main self = ((interop_serverQ_L_2Cont)(L_self))->self;
    $Cont C_cont = ((interop_serverQ_L_2Cont)(L_self))->C_cont;
    return interop_serverQ_L_1C_5cont(self, C_cont, G_1);
}
void interop_serverQ_L_2ContD___serialize__ (interop_serverQ_L_2Cont self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->C_cont, state);
}
interop_serverQ_L_2Cont interop_serverQ_L_2ContD___deserialize__ (interop_serverQ_L_2Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct interop_serverQ_L_2Cont));
            self->$class = &interop_serverQ_L_2ContG_methods;
            return self;
        }
        self = $DNEW(interop_serverQ_L_2Cont, state);
    }
    self->self = $step_deserialize(state);
    self->C_cont = $step_deserialize(state);
    return self;
}
interop_serverQ_L_2Cont interop_serverQ_L_2ContG_new(interop_serverQ_main G_1, $Cont G_2) {
    interop_serverQ_L_2Cont $tmp = acton_malloc(sizeof(struct interop_serverQ_L_2Cont));
    $tmp->$class = &interop_serverQ_L_2ContG_methods;
    interop_serverQ_L_2ContG_methods.__init__($tmp, G_1, G_2);
    return $tmp;
}
struct interop_serverQ_L_2ContG_class interop_serverQ_L_2ContG_methods;
B_NoneType interop_serverQ_L_4actionD___init__ (interop_serverQ_L_4action L_self, interop_serverQ_main L_3obj) {
    ((interop_serverQ_L_4action)(L_self))->L_3obj = L_3obj;
    return B_None;
}
$R interop_serverQ_L_4actionD___call__ (interop_serverQ_L_4action L_self, $Cont L_cont, sshQ_Server G_1, B_str G_2) {
    return $AWAIT(L_cont, ((B_Msg (*) ($WORD, sshQ_Server, B_str))((interop_serverQ_L_4action)(L_self))->$class->__asyn__)(L_self, G_1, G_2));
}
$R interop_serverQ_L_4actionD___exec__ (interop_serverQ_L_4action L_self, $Cont L_cont, sshQ_Server G_1, B_str G_2) {
    return $R_CONT(L_cont, ((B_Msg (*) ($WORD, sshQ_Server, B_str))((interop_serverQ_L_4action)(L_self))->$class->__asyn__)(L_self, G_1, G_2));
}
B_Msg interop_serverQ_L_4actionD___asyn__ (interop_serverQ_L_4action L_self, sshQ_Server G_1, B_str G_2) {
    interop_serverQ_main L_3obj = ((interop_serverQ_L_4action)(L_self))->L_3obj;
    return ((B_Msg (*) ($WORD, sshQ_Server, B_str))((interop_serverQ_main)(L_3obj))->$class->on_listen)(L_3obj, G_1, G_2);
}
void interop_serverQ_L_4actionD___serialize__ (interop_serverQ_L_4action self, $Serial$state state) {
    $step_serialize(self->L_3obj, state);
}
interop_serverQ_L_4action interop_serverQ_L_4actionD___deserialize__ (interop_serverQ_L_4action self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct interop_serverQ_L_4action));
            self->$class = &interop_serverQ_L_4actionG_methods;
            return self;
        }
        self = $DNEW(interop_serverQ_L_4action, state);
    }
    self->L_3obj = $step_deserialize(state);
    return self;
}
interop_serverQ_L_4action interop_serverQ_L_4actionG_new(interop_serverQ_main G_1) {
    interop_serverQ_L_4action $tmp = acton_malloc(sizeof(struct interop_serverQ_L_4action));
    $tmp->$class = &interop_serverQ_L_4actionG_methods;
    interop_serverQ_L_4actionG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct interop_serverQ_L_4actionG_class interop_serverQ_L_4actionG_methods;
B_NoneType interop_serverQ_L_6actionD___init__ (interop_serverQ_L_6action L_self, interop_serverQ_main L_5obj) {
    ((interop_serverQ_L_6action)(L_self))->L_5obj = L_5obj;
    return B_None;
}
$R interop_serverQ_L_6actionD___call__ (interop_serverQ_L_6action L_self, $Cont L_cont, sshQ_Server G_1, B_str G_2) {
    return $AWAIT(L_cont, ((B_Msg (*) ($WORD, sshQ_Server, B_str))((interop_serverQ_L_6action)(L_self))->$class->__asyn__)(L_self, G_1, G_2));
}
$R interop_serverQ_L_6actionD___exec__ (interop_serverQ_L_6action L_self, $Cont L_cont, sshQ_Server G_1, B_str G_2) {
    return $R_CONT(L_cont, ((B_Msg (*) ($WORD, sshQ_Server, B_str))((interop_serverQ_L_6action)(L_self))->$class->__asyn__)(L_self, G_1, G_2));
}
B_Msg interop_serverQ_L_6actionD___asyn__ (interop_serverQ_L_6action L_self, sshQ_Server G_1, B_str G_2) {
    interop_serverQ_main L_5obj = ((interop_serverQ_L_6action)(L_self))->L_5obj;
    return ((B_Msg (*) ($WORD, sshQ_Server, B_str))((interop_serverQ_main)(L_5obj))->$class->on_server_close)(L_5obj, G_1, G_2);
}
void interop_serverQ_L_6actionD___serialize__ (interop_serverQ_L_6action self, $Serial$state state) {
    $step_serialize(self->L_5obj, state);
}
interop_serverQ_L_6action interop_serverQ_L_6actionD___deserialize__ (interop_serverQ_L_6action self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct interop_serverQ_L_6action));
            self->$class = &interop_serverQ_L_6actionG_methods;
            return self;
        }
        self = $DNEW(interop_serverQ_L_6action, state);
    }
    self->L_5obj = $step_deserialize(state);
    return self;
}
interop_serverQ_L_6action interop_serverQ_L_6actionG_new(interop_serverQ_main G_1) {
    interop_serverQ_L_6action $tmp = acton_malloc(sizeof(struct interop_serverQ_L_6action));
    $tmp->$class = &interop_serverQ_L_6actionG_methods;
    interop_serverQ_L_6actionG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct interop_serverQ_L_6actionG_class interop_serverQ_L_6actionG_methods;
B_NoneType interop_serverQ_L_8actionD___init__ (interop_serverQ_L_8action L_self, interop_serverQ_main L_7obj) {
    ((interop_serverQ_L_8action)(L_self))->L_7obj = L_7obj;
    return B_None;
}
$R interop_serverQ_L_8actionD___call__ (interop_serverQ_L_8action L_self, $Cont L_cont, sshQ_ServerSession G_1) {
    return $AWAIT(L_cont, ((B_Msg (*) ($WORD, sshQ_ServerSession))((interop_serverQ_L_8action)(L_self))->$class->__asyn__)(L_self, G_1));
}
$R interop_serverQ_L_8actionD___exec__ (interop_serverQ_L_8action L_self, $Cont L_cont, sshQ_ServerSession G_1) {
    return $R_CONT(L_cont, ((B_Msg (*) ($WORD, sshQ_ServerSession))((interop_serverQ_L_8action)(L_self))->$class->__asyn__)(L_self, G_1));
}
B_Msg interop_serverQ_L_8actionD___asyn__ (interop_serverQ_L_8action L_self, sshQ_ServerSession G_1) {
    interop_serverQ_main L_7obj = ((interop_serverQ_L_8action)(L_self))->L_7obj;
    return ((B_Msg (*) ($WORD, sshQ_ServerSession))((interop_serverQ_main)(L_7obj))->$class->on_session)(L_7obj, G_1);
}
void interop_serverQ_L_8actionD___serialize__ (interop_serverQ_L_8action self, $Serial$state state) {
    $step_serialize(self->L_7obj, state);
}
interop_serverQ_L_8action interop_serverQ_L_8actionD___deserialize__ (interop_serverQ_L_8action self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct interop_serverQ_L_8action));
            self->$class = &interop_serverQ_L_8actionG_methods;
            return self;
        }
        self = $DNEW(interop_serverQ_L_8action, state);
    }
    self->L_7obj = $step_deserialize(state);
    return self;
}
interop_serverQ_L_8action interop_serverQ_L_8actionG_new(interop_serverQ_main G_1) {
    interop_serverQ_L_8action $tmp = acton_malloc(sizeof(struct interop_serverQ_L_8action));
    $tmp->$class = &interop_serverQ_L_8actionG_methods;
    interop_serverQ_L_8actionG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct interop_serverQ_L_8actionG_class interop_serverQ_L_8actionG_methods;
B_NoneType interop_serverQ_L_10actionD___init__ (interop_serverQ_L_10action L_self, interop_serverQ_main L_9obj) {
    ((interop_serverQ_L_10action)(L_self))->L_9obj = L_9obj;
    return B_None;
}
$R interop_serverQ_L_10actionD___call__ (interop_serverQ_L_10action L_self, $Cont L_cont, sshQ_ServerSession G_1, sshQ_AuthRequest G_2) {
    return $AWAIT(L_cont, ((B_Msg (*) ($WORD, sshQ_ServerSession, sshQ_AuthRequest))((interop_serverQ_L_10action)(L_self))->$class->__asyn__)(L_self, G_1, G_2));
}
$R interop_serverQ_L_10actionD___exec__ (interop_serverQ_L_10action L_self, $Cont L_cont, sshQ_ServerSession G_1, sshQ_AuthRequest G_2) {
    return $R_CONT(L_cont, ((B_Msg (*) ($WORD, sshQ_ServerSession, sshQ_AuthRequest))((interop_serverQ_L_10action)(L_self))->$class->__asyn__)(L_self, G_1, G_2));
}
B_Msg interop_serverQ_L_10actionD___asyn__ (interop_serverQ_L_10action L_self, sshQ_ServerSession G_1, sshQ_AuthRequest G_2) {
    interop_serverQ_main L_9obj = ((interop_serverQ_L_10action)(L_self))->L_9obj;
    return ((B_Msg (*) ($WORD, sshQ_ServerSession, sshQ_AuthRequest))((interop_serverQ_main)(L_9obj))->$class->on_auth)(L_9obj, G_1, G_2);
}
void interop_serverQ_L_10actionD___serialize__ (interop_serverQ_L_10action self, $Serial$state state) {
    $step_serialize(self->L_9obj, state);
}
interop_serverQ_L_10action interop_serverQ_L_10actionD___deserialize__ (interop_serverQ_L_10action self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct interop_serverQ_L_10action));
            self->$class = &interop_serverQ_L_10actionG_methods;
            return self;
        }
        self = $DNEW(interop_serverQ_L_10action, state);
    }
    self->L_9obj = $step_deserialize(state);
    return self;
}
interop_serverQ_L_10action interop_serverQ_L_10actionG_new(interop_serverQ_main G_1) {
    interop_serverQ_L_10action $tmp = acton_malloc(sizeof(struct interop_serverQ_L_10action));
    $tmp->$class = &interop_serverQ_L_10actionG_methods;
    interop_serverQ_L_10actionG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct interop_serverQ_L_10actionG_class interop_serverQ_L_10actionG_methods;
B_NoneType interop_serverQ_L_12actionD___init__ (interop_serverQ_L_12action L_self, interop_serverQ_main L_11obj) {
    ((interop_serverQ_L_12action)(L_self))->L_11obj = L_11obj;
    return B_None;
}
$R interop_serverQ_L_12actionD___call__ (interop_serverQ_L_12action L_self, $Cont L_cont, sshQ_ServerSession G_1) {
    return $AWAIT(L_cont, ((B_Msg (*) ($WORD, sshQ_ServerSession))((interop_serverQ_L_12action)(L_self))->$class->__asyn__)(L_self, G_1));
}
$R interop_serverQ_L_12actionD___exec__ (interop_serverQ_L_12action L_self, $Cont L_cont, sshQ_ServerSession G_1) {
    return $R_CONT(L_cont, ((B_Msg (*) ($WORD, sshQ_ServerSession))((interop_serverQ_L_12action)(L_self))->$class->__asyn__)(L_self, G_1));
}
B_Msg interop_serverQ_L_12actionD___asyn__ (interop_serverQ_L_12action L_self, sshQ_ServerSession G_1) {
    interop_serverQ_main L_11obj = ((interop_serverQ_L_12action)(L_self))->L_11obj;
    return ((B_Msg (*) ($WORD, sshQ_ServerSession))((interop_serverQ_main)(L_11obj))->$class->on_channel_open)(L_11obj, G_1);
}
void interop_serverQ_L_12actionD___serialize__ (interop_serverQ_L_12action self, $Serial$state state) {
    $step_serialize(self->L_11obj, state);
}
interop_serverQ_L_12action interop_serverQ_L_12actionD___deserialize__ (interop_serverQ_L_12action self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct interop_serverQ_L_12action));
            self->$class = &interop_serverQ_L_12actionG_methods;
            return self;
        }
        self = $DNEW(interop_serverQ_L_12action, state);
    }
    self->L_11obj = $step_deserialize(state);
    return self;
}
interop_serverQ_L_12action interop_serverQ_L_12actionG_new(interop_serverQ_main G_1) {
    interop_serverQ_L_12action $tmp = acton_malloc(sizeof(struct interop_serverQ_L_12action));
    $tmp->$class = &interop_serverQ_L_12actionG_methods;
    interop_serverQ_L_12actionG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct interop_serverQ_L_12actionG_class interop_serverQ_L_12actionG_methods;
B_NoneType interop_serverQ_L_14actionD___init__ (interop_serverQ_L_14action L_self, interop_serverQ_main L_13obj) {
    ((interop_serverQ_L_14action)(L_self))->L_13obj = L_13obj;
    return B_None;
}
$R interop_serverQ_L_14actionD___call__ (interop_serverQ_L_14action L_self, $Cont L_cont, sshQ_ServerSession G_1, sshQ_ServerChannel G_2, B_str G_3) {
    return $AWAIT(L_cont, ((B_Msg (*) ($WORD, sshQ_ServerSession, sshQ_ServerChannel, B_str))((interop_serverQ_L_14action)(L_self))->$class->__asyn__)(L_self, G_1, G_2, G_3));
}
$R interop_serverQ_L_14actionD___exec__ (interop_serverQ_L_14action L_self, $Cont L_cont, sshQ_ServerSession G_1, sshQ_ServerChannel G_2, B_str G_3) {
    return $R_CONT(L_cont, ((B_Msg (*) ($WORD, sshQ_ServerSession, sshQ_ServerChannel, B_str))((interop_serverQ_L_14action)(L_self))->$class->__asyn__)(L_self, G_1, G_2, G_3));
}
B_Msg interop_serverQ_L_14actionD___asyn__ (interop_serverQ_L_14action L_self, sshQ_ServerSession G_1, sshQ_ServerChannel G_2, B_str G_3) {
    interop_serverQ_main L_13obj = ((interop_serverQ_L_14action)(L_self))->L_13obj;
    return ((B_Msg (*) ($WORD, sshQ_ServerSession, sshQ_ServerChannel, B_str))((interop_serverQ_main)(L_13obj))->$class->on_exec)(L_13obj, G_1, G_2, G_3);
}
void interop_serverQ_L_14actionD___serialize__ (interop_serverQ_L_14action self, $Serial$state state) {
    $step_serialize(self->L_13obj, state);
}
interop_serverQ_L_14action interop_serverQ_L_14actionD___deserialize__ (interop_serverQ_L_14action self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct interop_serverQ_L_14action));
            self->$class = &interop_serverQ_L_14actionG_methods;
            return self;
        }
        self = $DNEW(interop_serverQ_L_14action, state);
    }
    self->L_13obj = $step_deserialize(state);
    return self;
}
interop_serverQ_L_14action interop_serverQ_L_14actionG_new(interop_serverQ_main G_1) {
    interop_serverQ_L_14action $tmp = acton_malloc(sizeof(struct interop_serverQ_L_14action));
    $tmp->$class = &interop_serverQ_L_14actionG_methods;
    interop_serverQ_L_14actionG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct interop_serverQ_L_14actionG_class interop_serverQ_L_14actionG_methods;
B_NoneType interop_serverQ_L_16actionD___init__ (interop_serverQ_L_16action L_self, interop_serverQ_main L_15obj) {
    ((interop_serverQ_L_16action)(L_self))->L_15obj = L_15obj;
    return B_None;
}
$R interop_serverQ_L_16actionD___call__ (interop_serverQ_L_16action L_self, $Cont L_cont, sshQ_ServerSession G_1, sshQ_ServerChannel G_2, B_str G_3) {
    return $AWAIT(L_cont, ((B_Msg (*) ($WORD, sshQ_ServerSession, sshQ_ServerChannel, B_str))((interop_serverQ_L_16action)(L_self))->$class->__asyn__)(L_self, G_1, G_2, G_3));
}
$R interop_serverQ_L_16actionD___exec__ (interop_serverQ_L_16action L_self, $Cont L_cont, sshQ_ServerSession G_1, sshQ_ServerChannel G_2, B_str G_3) {
    return $R_CONT(L_cont, ((B_Msg (*) ($WORD, sshQ_ServerSession, sshQ_ServerChannel, B_str))((interop_serverQ_L_16action)(L_self))->$class->__asyn__)(L_self, G_1, G_2, G_3));
}
B_Msg interop_serverQ_L_16actionD___asyn__ (interop_serverQ_L_16action L_self, sshQ_ServerSession G_1, sshQ_ServerChannel G_2, B_str G_3) {
    interop_serverQ_main L_15obj = ((interop_serverQ_L_16action)(L_self))->L_15obj;
    return ((B_Msg (*) ($WORD, sshQ_ServerSession, sshQ_ServerChannel, B_str))((interop_serverQ_main)(L_15obj))->$class->on_subsystem)(L_15obj, G_1, G_2, G_3);
}
void interop_serverQ_L_16actionD___serialize__ (interop_serverQ_L_16action self, $Serial$state state) {
    $step_serialize(self->L_15obj, state);
}
interop_serverQ_L_16action interop_serverQ_L_16actionD___deserialize__ (interop_serverQ_L_16action self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct interop_serverQ_L_16action));
            self->$class = &interop_serverQ_L_16actionG_methods;
            return self;
        }
        self = $DNEW(interop_serverQ_L_16action, state);
    }
    self->L_15obj = $step_deserialize(state);
    return self;
}
interop_serverQ_L_16action interop_serverQ_L_16actionG_new(interop_serverQ_main G_1) {
    interop_serverQ_L_16action $tmp = acton_malloc(sizeof(struct interop_serverQ_L_16action));
    $tmp->$class = &interop_serverQ_L_16actionG_methods;
    interop_serverQ_L_16actionG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct interop_serverQ_L_16actionG_class interop_serverQ_L_16actionG_methods;
B_NoneType interop_serverQ_L_18actionD___init__ (interop_serverQ_L_18action L_self, interop_serverQ_main L_17obj) {
    ((interop_serverQ_L_18action)(L_self))->L_17obj = L_17obj;
    return B_None;
}
$R interop_serverQ_L_18actionD___call__ (interop_serverQ_L_18action L_self, $Cont L_cont, sshQ_ServerSession G_1, B_str G_2) {
    return $AWAIT(L_cont, ((B_Msg (*) ($WORD, sshQ_ServerSession, B_str))((interop_serverQ_L_18action)(L_self))->$class->__asyn__)(L_self, G_1, G_2));
}
$R interop_serverQ_L_18actionD___exec__ (interop_serverQ_L_18action L_self, $Cont L_cont, sshQ_ServerSession G_1, B_str G_2) {
    return $R_CONT(L_cont, ((B_Msg (*) ($WORD, sshQ_ServerSession, B_str))((interop_serverQ_L_18action)(L_self))->$class->__asyn__)(L_self, G_1, G_2));
}
B_Msg interop_serverQ_L_18actionD___asyn__ (interop_serverQ_L_18action L_self, sshQ_ServerSession G_1, B_str G_2) {
    interop_serverQ_main L_17obj = ((interop_serverQ_L_18action)(L_self))->L_17obj;
    return ((B_Msg (*) ($WORD, sshQ_ServerSession, B_str))((interop_serverQ_main)(L_17obj))->$class->on_session_close)(L_17obj, G_1, G_2);
}
void interop_serverQ_L_18actionD___serialize__ (interop_serverQ_L_18action self, $Serial$state state) {
    $step_serialize(self->L_17obj, state);
}
interop_serverQ_L_18action interop_serverQ_L_18actionD___deserialize__ (interop_serverQ_L_18action self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct interop_serverQ_L_18action));
            self->$class = &interop_serverQ_L_18actionG_methods;
            return self;
        }
        self = $DNEW(interop_serverQ_L_18action, state);
    }
    self->L_17obj = $step_deserialize(state);
    return self;
}
interop_serverQ_L_18action interop_serverQ_L_18actionG_new(interop_serverQ_main G_1) {
    interop_serverQ_L_18action $tmp = acton_malloc(sizeof(struct interop_serverQ_L_18action));
    $tmp->$class = &interop_serverQ_L_18actionG_methods;
    interop_serverQ_L_18actionG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct interop_serverQ_L_18actionG_class interop_serverQ_L_18actionG_methods;
$R interop_serverQ_L_19C_7cont ($Cont C_cont, B_NoneType C_8res) {
    return $R_CONT(C_cont, to$str("pending"));
}
B_NoneType interop_serverQ_L_22ContD___init__ (interop_serverQ_L_22Cont L_self, $Cont C_cont) {
    ((interop_serverQ_L_22Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R interop_serverQ_L_22ContD___call__ (interop_serverQ_L_22Cont L_self, B_NoneType G_1) {
    $Cont C_cont = ((interop_serverQ_L_22Cont)(L_self))->C_cont;
    return interop_serverQ_L_19C_7cont(C_cont, G_1);
}
void interop_serverQ_L_22ContD___serialize__ (interop_serverQ_L_22Cont self, $Serial$state state) {
    $step_serialize(self->C_cont, state);
}
interop_serverQ_L_22Cont interop_serverQ_L_22ContD___deserialize__ (interop_serverQ_L_22Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct interop_serverQ_L_22Cont));
            self->$class = &interop_serverQ_L_22ContG_methods;
            return self;
        }
        self = $DNEW(interop_serverQ_L_22Cont, state);
    }
    self->C_cont = $step_deserialize(state);
    return self;
}
interop_serverQ_L_22Cont interop_serverQ_L_22ContG_new($Cont G_1) {
    interop_serverQ_L_22Cont $tmp = acton_malloc(sizeof(struct interop_serverQ_L_22Cont));
    $tmp->$class = &interop_serverQ_L_22ContG_methods;
    interop_serverQ_L_22ContG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct interop_serverQ_L_22ContG_class interop_serverQ_L_22ContG_methods;
$R interop_serverQ_L_21C_11cont ($Cont C_cont, B_NoneType C_12res) {
    $DROP_C();
    return $R_CONT((($Cont)interop_serverQ_L_22ContG_new(C_cont)), B_None);
}
B_NoneType interop_serverQ_L_25ContD___init__ (interop_serverQ_L_25Cont L_self, B_Iterator N_iter, B_Identity W_main_69, sshQ_ServerChannel ch, $Cont C_cont) {
    ((interop_serverQ_L_25Cont)(L_self))->N_iter = N_iter;
    ((interop_serverQ_L_25Cont)(L_self))->W_main_69 = W_main_69;
    ((interop_serverQ_L_25Cont)(L_self))->ch = ch;
    ((interop_serverQ_L_25Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R interop_serverQ_L_25ContD___call__ (interop_serverQ_L_25Cont L_self, B_NoneType G_1) {
    B_Iterator N_iter = ((interop_serverQ_L_25Cont)(L_self))->N_iter;
    B_Identity W_main_69 = ((interop_serverQ_L_25Cont)(L_self))->W_main_69;
    sshQ_ServerChannel ch = ((interop_serverQ_L_25Cont)(L_self))->ch;
    $Cont C_cont = ((interop_serverQ_L_25Cont)(L_self))->C_cont;
    return interop_serverQ_L_23C_13loop(N_iter, W_main_69, ch, C_cont, G_1);
}
void interop_serverQ_L_25ContD___serialize__ (interop_serverQ_L_25Cont self, $Serial$state state) {
    $step_serialize(self->N_iter, state);
    $step_serialize(self->W_main_69, state);
    $step_serialize(self->ch, state);
    $step_serialize(self->C_cont, state);
}
interop_serverQ_L_25Cont interop_serverQ_L_25ContD___deserialize__ (interop_serverQ_L_25Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct interop_serverQ_L_25Cont));
            self->$class = &interop_serverQ_L_25ContG_methods;
            return self;
        }
        self = $DNEW(interop_serverQ_L_25Cont, state);
    }
    self->N_iter = $step_deserialize(state);
    self->W_main_69 = $step_deserialize(state);
    self->ch = $step_deserialize(state);
    self->C_cont = $step_deserialize(state);
    return self;
}
interop_serverQ_L_25Cont interop_serverQ_L_25ContG_new(B_Iterator G_1, B_Identity G_2, sshQ_ServerChannel G_3, $Cont G_4) {
    interop_serverQ_L_25Cont $tmp = acton_malloc(sizeof(struct interop_serverQ_L_25Cont));
    $tmp->$class = &interop_serverQ_L_25ContG_methods;
    interop_serverQ_L_25ContG_methods.__init__($tmp, G_1, G_2, G_3, G_4);
    return $tmp;
}
struct interop_serverQ_L_25ContG_class interop_serverQ_L_25ContG_methods;
$R interop_serverQ_L_24C_15cont (B_Iterator N_iter, B_Identity W_main_69, sshQ_ServerChannel ch, $Cont C_cont, B_NoneType C_16res) {
    B_tuple N_1val = ((B_tuple (*) ($WORD))((B_Iterator)(N_iter))->$class->__next__)(N_iter);
    B_tuple N_2tup = N_1val;
    sshQ_ServerChannel k = (((B_tuple)(N_2tup))->components[0]);
    B_str v = (((B_tuple)(N_2tup))->components[1]);
    if (((B_bool)((B_bool (*) ($WORD, sshQ_ServerChannel, sshQ_ServerChannel))((B_Identity)(W_main_69))->$class->__is__)(W_main_69, k, ch))->val) {
        $DROP_C();
        return $R_CONT(C_cont, v);
    }
    else {
        return $R_CONT((($Cont)interop_serverQ_L_25ContG_new(N_iter, W_main_69, ch, C_cont)), B_None);
    }
}
B_NoneType interop_serverQ_L_26ContD___init__ (interop_serverQ_L_26Cont L_self, B_Iterator N_iter, B_Identity W_main_69, sshQ_ServerChannel ch, $Cont C_cont) {
    ((interop_serverQ_L_26Cont)(L_self))->N_iter = N_iter;
    ((interop_serverQ_L_26Cont)(L_self))->W_main_69 = W_main_69;
    ((interop_serverQ_L_26Cont)(L_self))->ch = ch;
    ((interop_serverQ_L_26Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R interop_serverQ_L_26ContD___call__ (interop_serverQ_L_26Cont L_self, B_NoneType G_1) {
    B_Iterator N_iter = ((interop_serverQ_L_26Cont)(L_self))->N_iter;
    B_Identity W_main_69 = ((interop_serverQ_L_26Cont)(L_self))->W_main_69;
    sshQ_ServerChannel ch = ((interop_serverQ_L_26Cont)(L_self))->ch;
    $Cont C_cont = ((interop_serverQ_L_26Cont)(L_self))->C_cont;
    return interop_serverQ_L_24C_15cont(N_iter, W_main_69, ch, C_cont, G_1);
}
void interop_serverQ_L_26ContD___serialize__ (interop_serverQ_L_26Cont self, $Serial$state state) {
    $step_serialize(self->N_iter, state);
    $step_serialize(self->W_main_69, state);
    $step_serialize(self->ch, state);
    $step_serialize(self->C_cont, state);
}
interop_serverQ_L_26Cont interop_serverQ_L_26ContD___deserialize__ (interop_serverQ_L_26Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct interop_serverQ_L_26Cont));
            self->$class = &interop_serverQ_L_26ContG_methods;
            return self;
        }
        self = $DNEW(interop_serverQ_L_26Cont, state);
    }
    self->N_iter = $step_deserialize(state);
    self->W_main_69 = $step_deserialize(state);
    self->ch = $step_deserialize(state);
    self->C_cont = $step_deserialize(state);
    return self;
}
interop_serverQ_L_26Cont interop_serverQ_L_26ContG_new(B_Iterator G_1, B_Identity G_2, sshQ_ServerChannel G_3, $Cont G_4) {
    interop_serverQ_L_26Cont $tmp = acton_malloc(sizeof(struct interop_serverQ_L_26Cont));
    $tmp->$class = &interop_serverQ_L_26ContG_methods;
    interop_serverQ_L_26ContG_methods.__init__($tmp, G_1, G_2, G_3, G_4);
    return $tmp;
}
struct interop_serverQ_L_26ContG_class interop_serverQ_L_26ContG_methods;
B_NoneType interop_serverQ_L_27ContD___init__ (interop_serverQ_L_27Cont L_self, $Cont C_cont) {
    ((interop_serverQ_L_27Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R interop_serverQ_L_27ContD___call__ (interop_serverQ_L_27Cont L_self, B_NoneType G_1) {
    $Cont C_cont = ((interop_serverQ_L_27Cont)(L_self))->C_cont;
    return interop_serverQ_L_21C_11cont(C_cont, G_1);
}
void interop_serverQ_L_27ContD___serialize__ (interop_serverQ_L_27Cont self, $Serial$state state) {
    $step_serialize(self->C_cont, state);
}
interop_serverQ_L_27Cont interop_serverQ_L_27ContD___deserialize__ (interop_serverQ_L_27Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct interop_serverQ_L_27Cont));
            self->$class = &interop_serverQ_L_27ContG_methods;
            return self;
        }
        self = $DNEW(interop_serverQ_L_27Cont, state);
    }
    self->C_cont = $step_deserialize(state);
    return self;
}
interop_serverQ_L_27Cont interop_serverQ_L_27ContG_new($Cont G_1) {
    interop_serverQ_L_27Cont $tmp = acton_malloc(sizeof(struct interop_serverQ_L_27Cont));
    $tmp->$class = &interop_serverQ_L_27ContG_methods;
    interop_serverQ_L_27ContG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct interop_serverQ_L_27ContG_class interop_serverQ_L_27ContG_methods;
B_NoneType interop_serverQ_L_28ContD___init__ (interop_serverQ_L_28Cont L_self, $Cont C_cont) {
    ((interop_serverQ_L_28Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R interop_serverQ_L_28ContD___call__ (interop_serverQ_L_28Cont L_self, B_NoneType G_1) {
    $Cont C_cont = ((interop_serverQ_L_28Cont)(L_self))->C_cont;
    return interop_serverQ_L_21C_11cont(C_cont, G_1);
}
void interop_serverQ_L_28ContD___serialize__ (interop_serverQ_L_28Cont self, $Serial$state state) {
    $step_serialize(self->C_cont, state);
}
interop_serverQ_L_28Cont interop_serverQ_L_28ContD___deserialize__ (interop_serverQ_L_28Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct interop_serverQ_L_28Cont));
            self->$class = &interop_serverQ_L_28ContG_methods;
            return self;
        }
        self = $DNEW(interop_serverQ_L_28Cont, state);
    }
    self->C_cont = $step_deserialize(state);
    return self;
}
interop_serverQ_L_28Cont interop_serverQ_L_28ContG_new($Cont G_1) {
    interop_serverQ_L_28Cont $tmp = acton_malloc(sizeof(struct interop_serverQ_L_28Cont));
    $tmp->$class = &interop_serverQ_L_28ContG_methods;
    interop_serverQ_L_28ContG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct interop_serverQ_L_28ContG_class interop_serverQ_L_28ContG_methods;
$R interop_serverQ_L_23C_13loop (B_Iterator N_iter, B_Identity W_main_69, sshQ_ServerChannel ch, $Cont C_cont, B_NoneType C_14res) {
    if (true) {
        if (true) {
            return $R_CONT((($Cont)interop_serverQ_L_26ContG_new(N_iter, W_main_69, ch, C_cont)), B_None);
        }
        else {
            return $R_CONT((($Cont)interop_serverQ_L_27ContG_new(C_cont)), B_None);
        }
    }
    else {
        return $R_CONT((($Cont)interop_serverQ_L_28ContG_new(C_cont)), B_None);
    }
}
B_NoneType interop_serverQ_L_29ContD___init__ (interop_serverQ_L_29Cont L_self, $Cont C_cont) {
    ((interop_serverQ_L_29Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R interop_serverQ_L_29ContD___call__ (interop_serverQ_L_29Cont L_self, B_NoneType G_1) {
    $Cont C_cont = ((interop_serverQ_L_29Cont)(L_self))->C_cont;
    return interop_serverQ_L_19C_7cont(C_cont, G_1);
}
void interop_serverQ_L_29ContD___serialize__ (interop_serverQ_L_29Cont self, $Serial$state state) {
    $step_serialize(self->C_cont, state);
}
interop_serverQ_L_29Cont interop_serverQ_L_29ContD___deserialize__ (interop_serverQ_L_29Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct interop_serverQ_L_29Cont));
            self->$class = &interop_serverQ_L_29ContG_methods;
            return self;
        }
        self = $DNEW(interop_serverQ_L_29Cont, state);
    }
    self->C_cont = $step_deserialize(state);
    return self;
}
interop_serverQ_L_29Cont interop_serverQ_L_29ContG_new($Cont G_1) {
    interop_serverQ_L_29Cont $tmp = acton_malloc(sizeof(struct interop_serverQ_L_29Cont));
    $tmp->$class = &interop_serverQ_L_29ContG_methods;
    interop_serverQ_L_29ContG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct interop_serverQ_L_29ContG_class interop_serverQ_L_29ContG_methods;
$R interop_serverQ_L_20C_9try (B_Iterator N_iter, B_Identity W_main_69, sshQ_ServerChannel ch, $Cont C_cont, B_bool C_10res) {
    if (((B_bool)C_10res)->val) {
        return interop_serverQ_L_23C_13loop(N_iter, W_main_69, ch, C_cont, B_None);
    }
    else {
        B_BaseException N_3x = $POP_C();
        if ($ISINSTANCE0(N_3x, B_StopIteration)) {
        }
        else {
            $RAISE(N_3x);
            __builtin_unreachable();
        }
        return $R_CONT((($Cont)interop_serverQ_L_29ContG_new(C_cont)), B_None);
    }
}
B_NoneType interop_serverQ_L_30ContD___init__ (interop_serverQ_L_30Cont L_self, B_Iterator N_iter, B_Identity W_main_69, sshQ_ServerChannel ch, $Cont C_cont) {
    ((interop_serverQ_L_30Cont)(L_self))->N_iter = N_iter;
    ((interop_serverQ_L_30Cont)(L_self))->W_main_69 = W_main_69;
    ((interop_serverQ_L_30Cont)(L_self))->ch = ch;
    ((interop_serverQ_L_30Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R interop_serverQ_L_30ContD___call__ (interop_serverQ_L_30Cont L_self, B_bool G_1) {
    B_Iterator N_iter = ((interop_serverQ_L_30Cont)(L_self))->N_iter;
    B_Identity W_main_69 = ((interop_serverQ_L_30Cont)(L_self))->W_main_69;
    sshQ_ServerChannel ch = ((interop_serverQ_L_30Cont)(L_self))->ch;
    $Cont C_cont = ((interop_serverQ_L_30Cont)(L_self))->C_cont;
    return interop_serverQ_L_20C_9try(N_iter, W_main_69, ch, C_cont, G_1);
}
void interop_serverQ_L_30ContD___serialize__ (interop_serverQ_L_30Cont self, $Serial$state state) {
    $step_serialize(self->N_iter, state);
    $step_serialize(self->W_main_69, state);
    $step_serialize(self->ch, state);
    $step_serialize(self->C_cont, state);
}
interop_serverQ_L_30Cont interop_serverQ_L_30ContD___deserialize__ (interop_serverQ_L_30Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct interop_serverQ_L_30Cont));
            self->$class = &interop_serverQ_L_30ContG_methods;
            return self;
        }
        self = $DNEW(interop_serverQ_L_30Cont, state);
    }
    self->N_iter = $step_deserialize(state);
    self->W_main_69 = $step_deserialize(state);
    self->ch = $step_deserialize(state);
    self->C_cont = $step_deserialize(state);
    return self;
}
interop_serverQ_L_30Cont interop_serverQ_L_30ContG_new(B_Iterator G_1, B_Identity G_2, sshQ_ServerChannel G_3, $Cont G_4) {
    interop_serverQ_L_30Cont $tmp = acton_malloc(sizeof(struct interop_serverQ_L_30Cont));
    $tmp->$class = &interop_serverQ_L_30ContG_methods;
    interop_serverQ_L_30ContG_methods.__init__($tmp, G_1, G_2, G_3, G_4);
    return $tmp;
}
struct interop_serverQ_L_30ContG_class interop_serverQ_L_30ContG_methods;
$R interop_serverQ_L_31C_17cont ($Cont C_cont, B_NoneType C_18res) {
    return $R_CONT(C_cont, B_False);
}
B_NoneType interop_serverQ_L_34ContD___init__ (interop_serverQ_L_34Cont L_self, $Cont C_cont) {
    ((interop_serverQ_L_34Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R interop_serverQ_L_34ContD___call__ (interop_serverQ_L_34Cont L_self, B_NoneType G_1) {
    $Cont C_cont = ((interop_serverQ_L_34Cont)(L_self))->C_cont;
    return interop_serverQ_L_31C_17cont(C_cont, G_1);
}
void interop_serverQ_L_34ContD___serialize__ (interop_serverQ_L_34Cont self, $Serial$state state) {
    $step_serialize(self->C_cont, state);
}
interop_serverQ_L_34Cont interop_serverQ_L_34ContD___deserialize__ (interop_serverQ_L_34Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct interop_serverQ_L_34Cont));
            self->$class = &interop_serverQ_L_34ContG_methods;
            return self;
        }
        self = $DNEW(interop_serverQ_L_34Cont, state);
    }
    self->C_cont = $step_deserialize(state);
    return self;
}
interop_serverQ_L_34Cont interop_serverQ_L_34ContG_new($Cont G_1) {
    interop_serverQ_L_34Cont $tmp = acton_malloc(sizeof(struct interop_serverQ_L_34Cont));
    $tmp->$class = &interop_serverQ_L_34ContG_methods;
    interop_serverQ_L_34ContG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct interop_serverQ_L_34ContG_class interop_serverQ_L_34ContG_methods;
$R interop_serverQ_L_33C_21cont ($Cont C_cont, B_NoneType C_22res) {
    $DROP_C();
    return $R_CONT((($Cont)interop_serverQ_L_34ContG_new(C_cont)), B_None);
}
B_NoneType interop_serverQ_L_37ContD___init__ (interop_serverQ_L_37Cont L_self, B_Iterator N_4iter, B_Identity W_main_103, sshQ_ServerChannel ch, $Cont C_cont) {
    ((interop_serverQ_L_37Cont)(L_self))->N_4iter = N_4iter;
    ((interop_serverQ_L_37Cont)(L_self))->W_main_103 = W_main_103;
    ((interop_serverQ_L_37Cont)(L_self))->ch = ch;
    ((interop_serverQ_L_37Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R interop_serverQ_L_37ContD___call__ (interop_serverQ_L_37Cont L_self, B_NoneType G_1) {
    B_Iterator N_4iter = ((interop_serverQ_L_37Cont)(L_self))->N_4iter;
    B_Identity W_main_103 = ((interop_serverQ_L_37Cont)(L_self))->W_main_103;
    sshQ_ServerChannel ch = ((interop_serverQ_L_37Cont)(L_self))->ch;
    $Cont C_cont = ((interop_serverQ_L_37Cont)(L_self))->C_cont;
    return interop_serverQ_L_35C_23loop(N_4iter, W_main_103, ch, C_cont, G_1);
}
void interop_serverQ_L_37ContD___serialize__ (interop_serverQ_L_37Cont self, $Serial$state state) {
    $step_serialize(self->N_4iter, state);
    $step_serialize(self->W_main_103, state);
    $step_serialize(self->ch, state);
    $step_serialize(self->C_cont, state);
}
interop_serverQ_L_37Cont interop_serverQ_L_37ContD___deserialize__ (interop_serverQ_L_37Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct interop_serverQ_L_37Cont));
            self->$class = &interop_serverQ_L_37ContG_methods;
            return self;
        }
        self = $DNEW(interop_serverQ_L_37Cont, state);
    }
    self->N_4iter = $step_deserialize(state);
    self->W_main_103 = $step_deserialize(state);
    self->ch = $step_deserialize(state);
    self->C_cont = $step_deserialize(state);
    return self;
}
interop_serverQ_L_37Cont interop_serverQ_L_37ContG_new(B_Iterator G_1, B_Identity G_2, sshQ_ServerChannel G_3, $Cont G_4) {
    interop_serverQ_L_37Cont $tmp = acton_malloc(sizeof(struct interop_serverQ_L_37Cont));
    $tmp->$class = &interop_serverQ_L_37ContG_methods;
    interop_serverQ_L_37ContG_methods.__init__($tmp, G_1, G_2, G_3, G_4);
    return $tmp;
}
struct interop_serverQ_L_37ContG_class interop_serverQ_L_37ContG_methods;
$R interop_serverQ_L_36C_25cont (B_Iterator N_4iter, B_Identity W_main_103, sshQ_ServerChannel ch, $Cont C_cont, B_NoneType C_26res) {
    sshQ_ServerChannel k = ((sshQ_ServerChannel (*) ($WORD))((B_Iterator)(N_4iter))->$class->__next__)(N_4iter);
    if (((B_bool)((B_bool (*) ($WORD, sshQ_ServerChannel, sshQ_ServerChannel))((B_Identity)(W_main_103))->$class->__is__)(W_main_103, k, ch))->val) {
        $DROP_C();
        return $R_CONT(C_cont, B_True);
    }
    else {
        return $R_CONT((($Cont)interop_serverQ_L_37ContG_new(N_4iter, W_main_103, ch, C_cont)), B_None);
    }
}
B_NoneType interop_serverQ_L_38ContD___init__ (interop_serverQ_L_38Cont L_self, B_Iterator N_4iter, B_Identity W_main_103, sshQ_ServerChannel ch, $Cont C_cont) {
    ((interop_serverQ_L_38Cont)(L_self))->N_4iter = N_4iter;
    ((interop_serverQ_L_38Cont)(L_self))->W_main_103 = W_main_103;
    ((interop_serverQ_L_38Cont)(L_self))->ch = ch;
    ((interop_serverQ_L_38Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R interop_serverQ_L_38ContD___call__ (interop_serverQ_L_38Cont L_self, B_NoneType G_1) {
    B_Iterator N_4iter = ((interop_serverQ_L_38Cont)(L_self))->N_4iter;
    B_Identity W_main_103 = ((interop_serverQ_L_38Cont)(L_self))->W_main_103;
    sshQ_ServerChannel ch = ((interop_serverQ_L_38Cont)(L_self))->ch;
    $Cont C_cont = ((interop_serverQ_L_38Cont)(L_self))->C_cont;
    return interop_serverQ_L_36C_25cont(N_4iter, W_main_103, ch, C_cont, G_1);
}
void interop_serverQ_L_38ContD___serialize__ (interop_serverQ_L_38Cont self, $Serial$state state) {
    $step_serialize(self->N_4iter, state);
    $step_serialize(self->W_main_103, state);
    $step_serialize(self->ch, state);
    $step_serialize(self->C_cont, state);
}
interop_serverQ_L_38Cont interop_serverQ_L_38ContD___deserialize__ (interop_serverQ_L_38Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct interop_serverQ_L_38Cont));
            self->$class = &interop_serverQ_L_38ContG_methods;
            return self;
        }
        self = $DNEW(interop_serverQ_L_38Cont, state);
    }
    self->N_4iter = $step_deserialize(state);
    self->W_main_103 = $step_deserialize(state);
    self->ch = $step_deserialize(state);
    self->C_cont = $step_deserialize(state);
    return self;
}
interop_serverQ_L_38Cont interop_serverQ_L_38ContG_new(B_Iterator G_1, B_Identity G_2, sshQ_ServerChannel G_3, $Cont G_4) {
    interop_serverQ_L_38Cont $tmp = acton_malloc(sizeof(struct interop_serverQ_L_38Cont));
    $tmp->$class = &interop_serverQ_L_38ContG_methods;
    interop_serverQ_L_38ContG_methods.__init__($tmp, G_1, G_2, G_3, G_4);
    return $tmp;
}
struct interop_serverQ_L_38ContG_class interop_serverQ_L_38ContG_methods;
B_NoneType interop_serverQ_L_39ContD___init__ (interop_serverQ_L_39Cont L_self, $Cont C_cont) {
    ((interop_serverQ_L_39Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R interop_serverQ_L_39ContD___call__ (interop_serverQ_L_39Cont L_self, B_NoneType G_1) {
    $Cont C_cont = ((interop_serverQ_L_39Cont)(L_self))->C_cont;
    return interop_serverQ_L_33C_21cont(C_cont, G_1);
}
void interop_serverQ_L_39ContD___serialize__ (interop_serverQ_L_39Cont self, $Serial$state state) {
    $step_serialize(self->C_cont, state);
}
interop_serverQ_L_39Cont interop_serverQ_L_39ContD___deserialize__ (interop_serverQ_L_39Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct interop_serverQ_L_39Cont));
            self->$class = &interop_serverQ_L_39ContG_methods;
            return self;
        }
        self = $DNEW(interop_serverQ_L_39Cont, state);
    }
    self->C_cont = $step_deserialize(state);
    return self;
}
interop_serverQ_L_39Cont interop_serverQ_L_39ContG_new($Cont G_1) {
    interop_serverQ_L_39Cont $tmp = acton_malloc(sizeof(struct interop_serverQ_L_39Cont));
    $tmp->$class = &interop_serverQ_L_39ContG_methods;
    interop_serverQ_L_39ContG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct interop_serverQ_L_39ContG_class interop_serverQ_L_39ContG_methods;
B_NoneType interop_serverQ_L_40ContD___init__ (interop_serverQ_L_40Cont L_self, $Cont C_cont) {
    ((interop_serverQ_L_40Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R interop_serverQ_L_40ContD___call__ (interop_serverQ_L_40Cont L_self, B_NoneType G_1) {
    $Cont C_cont = ((interop_serverQ_L_40Cont)(L_self))->C_cont;
    return interop_serverQ_L_33C_21cont(C_cont, G_1);
}
void interop_serverQ_L_40ContD___serialize__ (interop_serverQ_L_40Cont self, $Serial$state state) {
    $step_serialize(self->C_cont, state);
}
interop_serverQ_L_40Cont interop_serverQ_L_40ContD___deserialize__ (interop_serverQ_L_40Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct interop_serverQ_L_40Cont));
            self->$class = &interop_serverQ_L_40ContG_methods;
            return self;
        }
        self = $DNEW(interop_serverQ_L_40Cont, state);
    }
    self->C_cont = $step_deserialize(state);
    return self;
}
interop_serverQ_L_40Cont interop_serverQ_L_40ContG_new($Cont G_1) {
    interop_serverQ_L_40Cont $tmp = acton_malloc(sizeof(struct interop_serverQ_L_40Cont));
    $tmp->$class = &interop_serverQ_L_40ContG_methods;
    interop_serverQ_L_40ContG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct interop_serverQ_L_40ContG_class interop_serverQ_L_40ContG_methods;
$R interop_serverQ_L_35C_23loop (B_Iterator N_4iter, B_Identity W_main_103, sshQ_ServerChannel ch, $Cont C_cont, B_NoneType C_24res) {
    if (true) {
        if (true) {
            return $R_CONT((($Cont)interop_serverQ_L_38ContG_new(N_4iter, W_main_103, ch, C_cont)), B_None);
        }
        else {
            return $R_CONT((($Cont)interop_serverQ_L_39ContG_new(C_cont)), B_None);
        }
    }
    else {
        return $R_CONT((($Cont)interop_serverQ_L_40ContG_new(C_cont)), B_None);
    }
}
B_NoneType interop_serverQ_L_41ContD___init__ (interop_serverQ_L_41Cont L_self, $Cont C_cont) {
    ((interop_serverQ_L_41Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R interop_serverQ_L_41ContD___call__ (interop_serverQ_L_41Cont L_self, B_NoneType G_1) {
    $Cont C_cont = ((interop_serverQ_L_41Cont)(L_self))->C_cont;
    return interop_serverQ_L_31C_17cont(C_cont, G_1);
}
void interop_serverQ_L_41ContD___serialize__ (interop_serverQ_L_41Cont self, $Serial$state state) {
    $step_serialize(self->C_cont, state);
}
interop_serverQ_L_41Cont interop_serverQ_L_41ContD___deserialize__ (interop_serverQ_L_41Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct interop_serverQ_L_41Cont));
            self->$class = &interop_serverQ_L_41ContG_methods;
            return self;
        }
        self = $DNEW(interop_serverQ_L_41Cont, state);
    }
    self->C_cont = $step_deserialize(state);
    return self;
}
interop_serverQ_L_41Cont interop_serverQ_L_41ContG_new($Cont G_1) {
    interop_serverQ_L_41Cont $tmp = acton_malloc(sizeof(struct interop_serverQ_L_41Cont));
    $tmp->$class = &interop_serverQ_L_41ContG_methods;
    interop_serverQ_L_41ContG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct interop_serverQ_L_41ContG_class interop_serverQ_L_41ContG_methods;
$R interop_serverQ_L_32C_19try (B_Iterator N_4iter, B_Identity W_main_103, sshQ_ServerChannel ch, $Cont C_cont, B_bool C_20res) {
    if (((B_bool)C_20res)->val) {
        return interop_serverQ_L_35C_23loop(N_4iter, W_main_103, ch, C_cont, B_None);
    }
    else {
        B_BaseException N_6x = $POP_C();
        if ($ISINSTANCE0(N_6x, B_StopIteration)) {
        }
        else {
            $RAISE(N_6x);
            __builtin_unreachable();
        }
        return $R_CONT((($Cont)interop_serverQ_L_41ContG_new(C_cont)), B_None);
    }
}
B_NoneType interop_serverQ_L_42ContD___init__ (interop_serverQ_L_42Cont L_self, B_Iterator N_4iter, B_Identity W_main_103, sshQ_ServerChannel ch, $Cont C_cont) {
    ((interop_serverQ_L_42Cont)(L_self))->N_4iter = N_4iter;
    ((interop_serverQ_L_42Cont)(L_self))->W_main_103 = W_main_103;
    ((interop_serverQ_L_42Cont)(L_self))->ch = ch;
    ((interop_serverQ_L_42Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R interop_serverQ_L_42ContD___call__ (interop_serverQ_L_42Cont L_self, B_bool G_1) {
    B_Iterator N_4iter = ((interop_serverQ_L_42Cont)(L_self))->N_4iter;
    B_Identity W_main_103 = ((interop_serverQ_L_42Cont)(L_self))->W_main_103;
    sshQ_ServerChannel ch = ((interop_serverQ_L_42Cont)(L_self))->ch;
    $Cont C_cont = ((interop_serverQ_L_42Cont)(L_self))->C_cont;
    return interop_serverQ_L_32C_19try(N_4iter, W_main_103, ch, C_cont, G_1);
}
void interop_serverQ_L_42ContD___serialize__ (interop_serverQ_L_42Cont self, $Serial$state state) {
    $step_serialize(self->N_4iter, state);
    $step_serialize(self->W_main_103, state);
    $step_serialize(self->ch, state);
    $step_serialize(self->C_cont, state);
}
interop_serverQ_L_42Cont interop_serverQ_L_42ContD___deserialize__ (interop_serverQ_L_42Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct interop_serverQ_L_42Cont));
            self->$class = &interop_serverQ_L_42ContG_methods;
            return self;
        }
        self = $DNEW(interop_serverQ_L_42Cont, state);
    }
    self->N_4iter = $step_deserialize(state);
    self->W_main_103 = $step_deserialize(state);
    self->ch = $step_deserialize(state);
    self->C_cont = $step_deserialize(state);
    return self;
}
interop_serverQ_L_42Cont interop_serverQ_L_42ContG_new(B_Iterator G_1, B_Identity G_2, sshQ_ServerChannel G_3, $Cont G_4) {
    interop_serverQ_L_42Cont $tmp = acton_malloc(sizeof(struct interop_serverQ_L_42Cont));
    $tmp->$class = &interop_serverQ_L_42ContG_methods;
    interop_serverQ_L_42ContG_methods.__init__($tmp, G_1, G_2, G_3, G_4);
    return $tmp;
}
struct interop_serverQ_L_42ContG_class interop_serverQ_L_42ContG_methods;
$R interop_serverQ_L_44C_29cont ($Cont C_cont, uint16_t C_30res) {
    #line 60 "src/interop_server.act"
    uint16_t port = C_30res;
    #line 61 "src/interop_server.act"
    ((B_NoneType (*) (B_tuple, B_str, B_str, B_bool, B_bool))B_print)($NEWTUPLE(2, to$str("PORT"), toB_u16(port)), B_None, B_None, B_None, B_None);
    return $R_CONT(C_cont, B_None);
}
B_NoneType interop_serverQ_L_45ContD___init__ (interop_serverQ_L_45Cont L_self, $Cont C_cont) {
    ((interop_serverQ_L_45Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R interop_serverQ_L_45ContD___call__ (interop_serverQ_L_45Cont L_self, B_u16 G_1) {
    $Cont C_cont = ((interop_serverQ_L_45Cont)(L_self))->C_cont;
    return interop_serverQ_L_44C_29cont(C_cont, ((B_u16)G_1)->val);
}
void interop_serverQ_L_45ContD___serialize__ (interop_serverQ_L_45Cont self, $Serial$state state) {
    $step_serialize(self->C_cont, state);
}
interop_serverQ_L_45Cont interop_serverQ_L_45ContD___deserialize__ (interop_serverQ_L_45Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct interop_serverQ_L_45Cont));
            self->$class = &interop_serverQ_L_45ContG_methods;
            return self;
        }
        self = $DNEW(interop_serverQ_L_45Cont, state);
    }
    self->C_cont = $step_deserialize(state);
    return self;
}
interop_serverQ_L_45Cont interop_serverQ_L_45ContG_new($Cont G_1) {
    interop_serverQ_L_45Cont $tmp = acton_malloc(sizeof(struct interop_serverQ_L_45Cont));
    $tmp->$class = &interop_serverQ_L_45ContG_methods;
    interop_serverQ_L_45ContG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct interop_serverQ_L_45ContG_class interop_serverQ_L_45ContG_methods;
$R interop_serverQ_L_43C_27cont ($Cont C_cont, sshQ_Server s, B_NoneType C_28res) {
    return $AWAIT((($Cont)interop_serverQ_L_45ContG_new(C_cont)), ((B_Msg (*) ($WORD))((sshQ_Server)(s))->$class->bound_port)(s));
}
B_NoneType interop_serverQ_L_46ContD___init__ (interop_serverQ_L_46Cont L_self, $Cont C_cont, sshQ_Server s) {
    ((interop_serverQ_L_46Cont)(L_self))->C_cont = C_cont;
    ((interop_serverQ_L_46Cont)(L_self))->s = s;
    return B_None;
}
$R interop_serverQ_L_46ContD___call__ (interop_serverQ_L_46Cont L_self, B_NoneType G_1) {
    $Cont C_cont = ((interop_serverQ_L_46Cont)(L_self))->C_cont;
    sshQ_Server s = ((interop_serverQ_L_46Cont)(L_self))->s;
    return interop_serverQ_L_43C_27cont(C_cont, s, G_1);
}
void interop_serverQ_L_46ContD___serialize__ (interop_serverQ_L_46Cont self, $Serial$state state) {
    $step_serialize(self->C_cont, state);
    $step_serialize(self->s, state);
}
interop_serverQ_L_46Cont interop_serverQ_L_46ContD___deserialize__ (interop_serverQ_L_46Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct interop_serverQ_L_46Cont));
            self->$class = &interop_serverQ_L_46ContG_methods;
            return self;
        }
        self = $DNEW(interop_serverQ_L_46Cont, state);
    }
    self->C_cont = $step_deserialize(state);
    self->s = $step_deserialize(state);
    return self;
}
interop_serverQ_L_46Cont interop_serverQ_L_46ContG_new($Cont G_1, sshQ_Server G_2) {
    interop_serverQ_L_46Cont $tmp = acton_malloc(sizeof(struct interop_serverQ_L_46Cont));
    $tmp->$class = &interop_serverQ_L_46ContG_methods;
    interop_serverQ_L_46ContG_methods.__init__($tmp, G_1, G_2);
    return $tmp;
}
struct interop_serverQ_L_46ContG_class interop_serverQ_L_46ContG_methods;
$R interop_serverQ_L_49C_35cont ($Cont C_cont, B_NoneType C_36res) {
    return $R_CONT(C_cont, B_None);
}
B_NoneType interop_serverQ_L_50ContD___init__ (interop_serverQ_L_50Cont L_self, $Cont C_cont) {
    ((interop_serverQ_L_50Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R interop_serverQ_L_50ContD___call__ (interop_serverQ_L_50Cont L_self, B_NoneType G_1) {
    $Cont C_cont = ((interop_serverQ_L_50Cont)(L_self))->C_cont;
    return interop_serverQ_L_49C_35cont(C_cont, G_1);
}
void interop_serverQ_L_50ContD___serialize__ (interop_serverQ_L_50Cont self, $Serial$state state) {
    $step_serialize(self->C_cont, state);
}
interop_serverQ_L_50Cont interop_serverQ_L_50ContD___deserialize__ (interop_serverQ_L_50Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct interop_serverQ_L_50Cont));
            self->$class = &interop_serverQ_L_50ContG_methods;
            return self;
        }
        self = $DNEW(interop_serverQ_L_50Cont, state);
    }
    self->C_cont = $step_deserialize(state);
    return self;
}
interop_serverQ_L_50Cont interop_serverQ_L_50ContG_new($Cont G_1) {
    interop_serverQ_L_50Cont $tmp = acton_malloc(sizeof(struct interop_serverQ_L_50Cont));
    $tmp->$class = &interop_serverQ_L_50ContG_methods;
    interop_serverQ_L_50ContG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct interop_serverQ_L_50ContG_class interop_serverQ_L_50ContG_methods;
B_NoneType interop_serverQ_L_53ContD___init__ (interop_serverQ_L_53Cont L_self, $Cont C_cont) {
    ((interop_serverQ_L_53Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R interop_serverQ_L_53ContD___call__ (interop_serverQ_L_53Cont L_self, B_NoneType G_1) {
    $Cont C_cont = ((interop_serverQ_L_53Cont)(L_self))->C_cont;
    return interop_serverQ_L_49C_35cont(C_cont, G_1);
}
void interop_serverQ_L_53ContD___serialize__ (interop_serverQ_L_53Cont self, $Serial$state state) {
    $step_serialize(self->C_cont, state);
}
interop_serverQ_L_53Cont interop_serverQ_L_53ContD___deserialize__ (interop_serverQ_L_53Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct interop_serverQ_L_53Cont));
            self->$class = &interop_serverQ_L_53ContG_methods;
            return self;
        }
        self = $DNEW(interop_serverQ_L_53Cont, state);
    }
    self->C_cont = $step_deserialize(state);
    return self;
}
interop_serverQ_L_53Cont interop_serverQ_L_53ContG_new($Cont G_1) {
    interop_serverQ_L_53Cont $tmp = acton_malloc(sizeof(struct interop_serverQ_L_53Cont));
    $tmp->$class = &interop_serverQ_L_53ContG_methods;
    interop_serverQ_L_53ContG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct interop_serverQ_L_53ContG_class interop_serverQ_L_53ContG_methods;
B_NoneType interop_serverQ_L_54ContD___init__ (interop_serverQ_L_54Cont L_self, $Cont C_cont) {
    ((interop_serverQ_L_54Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R interop_serverQ_L_54ContD___call__ (interop_serverQ_L_54Cont L_self, B_NoneType G_1) {
    $Cont C_cont = ((interop_serverQ_L_54Cont)(L_self))->C_cont;
    return interop_serverQ_L_49C_35cont(C_cont, G_1);
}
void interop_serverQ_L_54ContD___serialize__ (interop_serverQ_L_54Cont self, $Serial$state state) {
    $step_serialize(self->C_cont, state);
}
interop_serverQ_L_54Cont interop_serverQ_L_54ContD___deserialize__ (interop_serverQ_L_54Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct interop_serverQ_L_54Cont));
            self->$class = &interop_serverQ_L_54ContG_methods;
            return self;
        }
        self = $DNEW(interop_serverQ_L_54Cont, state);
    }
    self->C_cont = $step_deserialize(state);
    return self;
}
interop_serverQ_L_54Cont interop_serverQ_L_54ContG_new($Cont G_1) {
    interop_serverQ_L_54Cont $tmp = acton_malloc(sizeof(struct interop_serverQ_L_54Cont));
    $tmp->$class = &interop_serverQ_L_54ContG_methods;
    interop_serverQ_L_54ContG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct interop_serverQ_L_54ContG_class interop_serverQ_L_54ContG_methods;
$R interop_serverQ_L_52C_39cont (interop_serverQ_main self, sshQ_ServerChannel ch, $Cont C_cont, B_str C_40res) {
    B_str C_2pre = C_40res;
    if (((B_bool)((B_bool (*) ($WORD, B_str, B_str))((B_Eq)(interop_serverQ_W_main_1090))->$class->__eq__)(interop_serverQ_W_main_1090, C_2pre, to$str("echo")))->val) {
        return (($R (*) ($WORD, $Cont, sshQ_ServerChannel))((interop_serverQ_main)(self))->$class->close_echoG_local)(self, (($Cont)interop_serverQ_L_53ContG_new(C_cont)), ch);
    }
    else {
        return $R_CONT((($Cont)interop_serverQ_L_54ContG_new(C_cont)), B_None);
    }
}
B_NoneType interop_serverQ_L_55ContD___init__ (interop_serverQ_L_55Cont L_self, interop_serverQ_main self, sshQ_ServerChannel ch, $Cont C_cont) {
    ((interop_serverQ_L_55Cont)(L_self))->self = self;
    ((interop_serverQ_L_55Cont)(L_self))->ch = ch;
    ((interop_serverQ_L_55Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R interop_serverQ_L_55ContD___call__ (interop_serverQ_L_55Cont L_self, B_str G_1) {
    interop_serverQ_main self = ((interop_serverQ_L_55Cont)(L_self))->self;
    sshQ_ServerChannel ch = ((interop_serverQ_L_55Cont)(L_self))->ch;
    $Cont C_cont = ((interop_serverQ_L_55Cont)(L_self))->C_cont;
    return interop_serverQ_L_52C_39cont(self, ch, C_cont, G_1);
}
void interop_serverQ_L_55ContD___serialize__ (interop_serverQ_L_55Cont self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->ch, state);
    $step_serialize(self->C_cont, state);
}
interop_serverQ_L_55Cont interop_serverQ_L_55ContD___deserialize__ (interop_serverQ_L_55Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct interop_serverQ_L_55Cont));
            self->$class = &interop_serverQ_L_55ContG_methods;
            return self;
        }
        self = $DNEW(interop_serverQ_L_55Cont, state);
    }
    self->self = $step_deserialize(state);
    self->ch = $step_deserialize(state);
    self->C_cont = $step_deserialize(state);
    return self;
}
interop_serverQ_L_55Cont interop_serverQ_L_55ContG_new(interop_serverQ_main G_1, sshQ_ServerChannel G_2, $Cont G_3) {
    interop_serverQ_L_55Cont $tmp = acton_malloc(sizeof(struct interop_serverQ_L_55Cont));
    $tmp->$class = &interop_serverQ_L_55ContG_methods;
    interop_serverQ_L_55ContG_methods.__init__($tmp, G_1, G_2, G_3);
    return $tmp;
}
struct interop_serverQ_L_55ContG_class interop_serverQ_L_55ContG_methods;
$R interop_serverQ_L_51C_37cont (interop_serverQ_main self, sshQ_ServerChannel ch, $Cont C_cont, B_NoneType C_38res) {
    return (($R (*) ($WORD, $Cont, sshQ_ServerChannel))((interop_serverQ_main)(self))->$class->mode_ofG_local)(self, (($Cont)interop_serverQ_L_55ContG_new(self, ch, C_cont)), ch);
}
B_NoneType interop_serverQ_L_56ContD___init__ (interop_serverQ_L_56Cont L_self, interop_serverQ_main self, sshQ_ServerChannel ch, $Cont C_cont) {
    ((interop_serverQ_L_56Cont)(L_self))->self = self;
    ((interop_serverQ_L_56Cont)(L_self))->ch = ch;
    ((interop_serverQ_L_56Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R interop_serverQ_L_56ContD___call__ (interop_serverQ_L_56Cont L_self, B_NoneType G_1) {
    interop_serverQ_main self = ((interop_serverQ_L_56Cont)(L_self))->self;
    sshQ_ServerChannel ch = ((interop_serverQ_L_56Cont)(L_self))->ch;
    $Cont C_cont = ((interop_serverQ_L_56Cont)(L_self))->C_cont;
    return interop_serverQ_L_51C_37cont(self, ch, C_cont, G_1);
}
void interop_serverQ_L_56ContD___serialize__ (interop_serverQ_L_56Cont self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->ch, state);
    $step_serialize(self->C_cont, state);
}
interop_serverQ_L_56Cont interop_serverQ_L_56ContD___deserialize__ (interop_serverQ_L_56Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct interop_serverQ_L_56Cont));
            self->$class = &interop_serverQ_L_56ContG_methods;
            return self;
        }
        self = $DNEW(interop_serverQ_L_56Cont, state);
    }
    self->self = $step_deserialize(state);
    self->ch = $step_deserialize(state);
    self->C_cont = $step_deserialize(state);
    return self;
}
interop_serverQ_L_56Cont interop_serverQ_L_56ContG_new(interop_serverQ_main G_1, sshQ_ServerChannel G_2, $Cont G_3) {
    interop_serverQ_L_56Cont $tmp = acton_malloc(sizeof(struct interop_serverQ_L_56Cont));
    $tmp->$class = &interop_serverQ_L_56ContG_methods;
    interop_serverQ_L_56ContG_methods.__init__($tmp, G_1, G_2, G_3);
    return $tmp;
}
struct interop_serverQ_L_56ContG_class interop_serverQ_L_56ContG_methods;
$R interop_serverQ_L_48C_33cont ($Cont C_cont, B_bytes data, sshQ_ServerChannel ch, interop_serverQ_main self, B_NoneType C_34res) {
    if ($ISNOTNONE0(data)) {
        #line 88 "src/interop_server.act"
        ((B_Msg (*) ($WORD, B_bytes))((sshQ_ServerChannel)(ch))->$class->write)(ch, ((B_bytes)data));
        return $R_CONT((($Cont)interop_serverQ_L_50ContG_new(C_cont)), B_None);
    }
    else {
        return (($R (*) ($WORD, $Cont, sshQ_ServerChannel))((interop_serverQ_main)(self))->$class->mark_eofG_local)(self, (($Cont)interop_serverQ_L_56ContG_new(self, ch, C_cont)), ch);
    }
}
B_NoneType interop_serverQ_L_57ContD___init__ (interop_serverQ_L_57Cont L_self, $Cont C_cont, B_bytes data, sshQ_ServerChannel ch, interop_serverQ_main self) {
    ((interop_serverQ_L_57Cont)(L_self))->C_cont = C_cont;
    ((interop_serverQ_L_57Cont)(L_self))->data = data;
    ((interop_serverQ_L_57Cont)(L_self))->ch = ch;
    ((interop_serverQ_L_57Cont)(L_self))->self = self;
    return B_None;
}
$R interop_serverQ_L_57ContD___call__ (interop_serverQ_L_57Cont L_self, B_NoneType G_1) {
    $Cont C_cont = ((interop_serverQ_L_57Cont)(L_self))->C_cont;
    B_bytes data = ((interop_serverQ_L_57Cont)(L_self))->data;
    sshQ_ServerChannel ch = ((interop_serverQ_L_57Cont)(L_self))->ch;
    interop_serverQ_main self = ((interop_serverQ_L_57Cont)(L_self))->self;
    return interop_serverQ_L_48C_33cont(C_cont, data, ch, self, G_1);
}
void interop_serverQ_L_57ContD___serialize__ (interop_serverQ_L_57Cont self, $Serial$state state) {
    $step_serialize(self->C_cont, state);
    $step_serialize(self->data, state);
    $step_serialize(self->ch, state);
    $step_serialize(self->self, state);
}
interop_serverQ_L_57Cont interop_serverQ_L_57ContD___deserialize__ (interop_serverQ_L_57Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct interop_serverQ_L_57Cont));
            self->$class = &interop_serverQ_L_57ContG_methods;
            return self;
        }
        self = $DNEW(interop_serverQ_L_57Cont, state);
    }
    self->C_cont = $step_deserialize(state);
    self->data = $step_deserialize(state);
    self->ch = $step_deserialize(state);
    self->self = $step_deserialize(state);
    return self;
}
interop_serverQ_L_57Cont interop_serverQ_L_57ContG_new($Cont G_1, B_bytes G_2, sshQ_ServerChannel G_3, interop_serverQ_main G_4) {
    interop_serverQ_L_57Cont $tmp = acton_malloc(sizeof(struct interop_serverQ_L_57Cont));
    $tmp->$class = &interop_serverQ_L_57ContG_methods;
    interop_serverQ_L_57ContG_methods.__init__($tmp, G_1, G_2, G_3, G_4);
    return $tmp;
}
struct interop_serverQ_L_57ContG_class interop_serverQ_L_57ContG_methods;
$R interop_serverQ_L_47C_31cont ($Cont C_cont, B_bytes data, sshQ_ServerChannel ch, interop_serverQ_main self, B_str C_32res) {
    B_str C_1pre = C_32res;
    if (((B_bool)((B_bool (*) ($WORD, B_str, B_str))((B_Eq)(interop_serverQ_W_main_1090))->$class->__eq__)(interop_serverQ_W_main_1090, C_1pre, to$str("exec")))->val) {
        return $R_CONT(C_cont, B_None);
    }
    else {
        return $R_CONT((($Cont)interop_serverQ_L_57ContG_new(C_cont, data, ch, self)), B_None);
    }
}
B_NoneType interop_serverQ_L_58ContD___init__ (interop_serverQ_L_58Cont L_self, $Cont C_cont, B_bytes data, sshQ_ServerChannel ch, interop_serverQ_main self) {
    ((interop_serverQ_L_58Cont)(L_self))->C_cont = C_cont;
    ((interop_serverQ_L_58Cont)(L_self))->data = data;
    ((interop_serverQ_L_58Cont)(L_self))->ch = ch;
    ((interop_serverQ_L_58Cont)(L_self))->self = self;
    return B_None;
}
$R interop_serverQ_L_58ContD___call__ (interop_serverQ_L_58Cont L_self, B_str G_1) {
    $Cont C_cont = ((interop_serverQ_L_58Cont)(L_self))->C_cont;
    B_bytes data = ((interop_serverQ_L_58Cont)(L_self))->data;
    sshQ_ServerChannel ch = ((interop_serverQ_L_58Cont)(L_self))->ch;
    interop_serverQ_main self = ((interop_serverQ_L_58Cont)(L_self))->self;
    return interop_serverQ_L_47C_31cont(C_cont, data, ch, self, G_1);
}
void interop_serverQ_L_58ContD___serialize__ (interop_serverQ_L_58Cont self, $Serial$state state) {
    $step_serialize(self->C_cont, state);
    $step_serialize(self->data, state);
    $step_serialize(self->ch, state);
    $step_serialize(self->self, state);
}
interop_serverQ_L_58Cont interop_serverQ_L_58ContD___deserialize__ (interop_serverQ_L_58Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct interop_serverQ_L_58Cont));
            self->$class = &interop_serverQ_L_58ContG_methods;
            return self;
        }
        self = $DNEW(interop_serverQ_L_58Cont, state);
    }
    self->C_cont = $step_deserialize(state);
    self->data = $step_deserialize(state);
    self->ch = $step_deserialize(state);
    self->self = $step_deserialize(state);
    return self;
}
interop_serverQ_L_58Cont interop_serverQ_L_58ContG_new($Cont G_1, B_bytes G_2, sshQ_ServerChannel G_3, interop_serverQ_main G_4) {
    interop_serverQ_L_58Cont $tmp = acton_malloc(sizeof(struct interop_serverQ_L_58Cont));
    $tmp->$class = &interop_serverQ_L_58ContG_methods;
    interop_serverQ_L_58ContG_methods.__init__($tmp, G_1, G_2, G_3, G_4);
    return $tmp;
}
struct interop_serverQ_L_58ContG_class interop_serverQ_L_58ContG_methods;
$R interop_serverQ_L_59C_41cont (sshQ_ServerSession sess, $Cont C_cont, sshQ_ServerChannel C_42res) {
    sshQ_ServerChannel C_3pre = C_42res;
    #line 101 "src/interop_server.act"
    ((B_Msg (*) ($WORD, sshQ_ServerChannel))((sshQ_ServerSession)(sess))->$class->accept_channel)(sess, C_3pre);
    return $R_CONT(C_cont, B_None);
}
B_NoneType interop_serverQ_L_60ContD___init__ (interop_serverQ_L_60Cont L_self, sshQ_ServerSession sess, $Cont C_cont) {
    ((interop_serverQ_L_60Cont)(L_self))->sess = sess;
    ((interop_serverQ_L_60Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R interop_serverQ_L_60ContD___call__ (interop_serverQ_L_60Cont L_self, sshQ_ServerChannel G_1) {
    sshQ_ServerSession sess = ((interop_serverQ_L_60Cont)(L_self))->sess;
    $Cont C_cont = ((interop_serverQ_L_60Cont)(L_self))->C_cont;
    return interop_serverQ_L_59C_41cont(sess, C_cont, G_1);
}
void interop_serverQ_L_60ContD___serialize__ (interop_serverQ_L_60Cont self, $Serial$state state) {
    $step_serialize(self->sess, state);
    $step_serialize(self->C_cont, state);
}
interop_serverQ_L_60Cont interop_serverQ_L_60ContD___deserialize__ (interop_serverQ_L_60Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct interop_serverQ_L_60Cont));
            self->$class = &interop_serverQ_L_60ContG_methods;
            return self;
        }
        self = $DNEW(interop_serverQ_L_60Cont, state);
    }
    self->sess = $step_deserialize(state);
    self->C_cont = $step_deserialize(state);
    return self;
}
interop_serverQ_L_60Cont interop_serverQ_L_60ContG_new(sshQ_ServerSession G_1, $Cont G_2) {
    interop_serverQ_L_60Cont $tmp = acton_malloc(sizeof(struct interop_serverQ_L_60Cont));
    $tmp->$class = &interop_serverQ_L_60ContG_methods;
    interop_serverQ_L_60ContG_methods.__init__($tmp, G_1, G_2);
    return $tmp;
}
struct interop_serverQ_L_60ContG_class interop_serverQ_L_60ContG_methods;
B_NoneType interop_serverQ_L_62actionD___init__ (interop_serverQ_L_62action L_self, interop_serverQ_main L_61obj) {
    ((interop_serverQ_L_62action)(L_self))->L_61obj = L_61obj;
    return B_None;
}
$R interop_serverQ_L_62actionD___call__ (interop_serverQ_L_62action L_self, $Cont L_cont, sshQ_ServerChannel G_1, B_bytes G_2) {
    return $AWAIT(L_cont, ((B_Msg (*) ($WORD, sshQ_ServerChannel, B_bytes))((interop_serverQ_L_62action)(L_self))->$class->__asyn__)(L_self, G_1, G_2));
}
$R interop_serverQ_L_62actionD___exec__ (interop_serverQ_L_62action L_self, $Cont L_cont, sshQ_ServerChannel G_1, B_bytes G_2) {
    return $R_CONT(L_cont, ((B_Msg (*) ($WORD, sshQ_ServerChannel, B_bytes))((interop_serverQ_L_62action)(L_self))->$class->__asyn__)(L_self, G_1, G_2));
}
B_Msg interop_serverQ_L_62actionD___asyn__ (interop_serverQ_L_62action L_self, sshQ_ServerChannel G_1, B_bytes G_2) {
    interop_serverQ_main L_61obj = ((interop_serverQ_L_62action)(L_self))->L_61obj;
    return ((B_Msg (*) ($WORD, sshQ_ServerChannel, B_bytes))((interop_serverQ_main)(L_61obj))->$class->srv_on_data)(L_61obj, G_1, G_2);
}
void interop_serverQ_L_62actionD___serialize__ (interop_serverQ_L_62action self, $Serial$state state) {
    $step_serialize(self->L_61obj, state);
}
interop_serverQ_L_62action interop_serverQ_L_62actionD___deserialize__ (interop_serverQ_L_62action self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct interop_serverQ_L_62action));
            self->$class = &interop_serverQ_L_62actionG_methods;
            return self;
        }
        self = $DNEW(interop_serverQ_L_62action, state);
    }
    self->L_61obj = $step_deserialize(state);
    return self;
}
interop_serverQ_L_62action interop_serverQ_L_62actionG_new(interop_serverQ_main G_1) {
    interop_serverQ_L_62action $tmp = acton_malloc(sizeof(struct interop_serverQ_L_62action));
    $tmp->$class = &interop_serverQ_L_62actionG_methods;
    interop_serverQ_L_62actionG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct interop_serverQ_L_62actionG_class interop_serverQ_L_62actionG_methods;
B_NoneType interop_serverQ_L_64actionD___init__ (interop_serverQ_L_64action L_self, interop_serverQ_main L_63obj) {
    ((interop_serverQ_L_64action)(L_self))->L_63obj = L_63obj;
    return B_None;
}
$R interop_serverQ_L_64actionD___call__ (interop_serverQ_L_64action L_self, $Cont L_cont, sshQ_ServerChannel G_1, B_bytes G_2) {
    return $AWAIT(L_cont, ((B_Msg (*) ($WORD, sshQ_ServerChannel, B_bytes))((interop_serverQ_L_64action)(L_self))->$class->__asyn__)(L_self, G_1, G_2));
}
$R interop_serverQ_L_64actionD___exec__ (interop_serverQ_L_64action L_self, $Cont L_cont, sshQ_ServerChannel G_1, B_bytes G_2) {
    return $R_CONT(L_cont, ((B_Msg (*) ($WORD, sshQ_ServerChannel, B_bytes))((interop_serverQ_L_64action)(L_self))->$class->__asyn__)(L_self, G_1, G_2));
}
B_Msg interop_serverQ_L_64actionD___asyn__ (interop_serverQ_L_64action L_self, sshQ_ServerChannel G_1, B_bytes G_2) {
    interop_serverQ_main L_63obj = ((interop_serverQ_L_64action)(L_self))->L_63obj;
    return ((B_Msg (*) ($WORD, sshQ_ServerChannel, B_bytes))((interop_serverQ_main)(L_63obj))->$class->srv_on_stderr)(L_63obj, G_1, G_2);
}
void interop_serverQ_L_64actionD___serialize__ (interop_serverQ_L_64action self, $Serial$state state) {
    $step_serialize(self->L_63obj, state);
}
interop_serverQ_L_64action interop_serverQ_L_64actionD___deserialize__ (interop_serverQ_L_64action self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct interop_serverQ_L_64action));
            self->$class = &interop_serverQ_L_64actionG_methods;
            return self;
        }
        self = $DNEW(interop_serverQ_L_64action, state);
    }
    self->L_63obj = $step_deserialize(state);
    return self;
}
interop_serverQ_L_64action interop_serverQ_L_64actionG_new(interop_serverQ_main G_1) {
    interop_serverQ_L_64action $tmp = acton_malloc(sizeof(struct interop_serverQ_L_64action));
    $tmp->$class = &interop_serverQ_L_64actionG_methods;
    interop_serverQ_L_64actionG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct interop_serverQ_L_64actionG_class interop_serverQ_L_64actionG_methods;
B_NoneType interop_serverQ_L_66actionD___init__ (interop_serverQ_L_66action L_self, interop_serverQ_main L_65obj) {
    ((interop_serverQ_L_66action)(L_self))->L_65obj = L_65obj;
    return B_None;
}
$R interop_serverQ_L_66actionD___call__ (interop_serverQ_L_66action L_self, $Cont L_cont, sshQ_ServerChannel G_1, B_str G_2) {
    return $AWAIT(L_cont, ((B_Msg (*) ($WORD, sshQ_ServerChannel, B_str))((interop_serverQ_L_66action)(L_self))->$class->__asyn__)(L_self, G_1, G_2));
}
$R interop_serverQ_L_66actionD___exec__ (interop_serverQ_L_66action L_self, $Cont L_cont, sshQ_ServerChannel G_1, B_str G_2) {
    return $R_CONT(L_cont, ((B_Msg (*) ($WORD, sshQ_ServerChannel, B_str))((interop_serverQ_L_66action)(L_self))->$class->__asyn__)(L_self, G_1, G_2));
}
B_Msg interop_serverQ_L_66actionD___asyn__ (interop_serverQ_L_66action L_self, sshQ_ServerChannel G_1, B_str G_2) {
    interop_serverQ_main L_65obj = ((interop_serverQ_L_66action)(L_self))->L_65obj;
    return ((B_Msg (*) ($WORD, sshQ_ServerChannel, B_str))((interop_serverQ_main)(L_65obj))->$class->srv_on_close)(L_65obj, G_1, G_2);
}
void interop_serverQ_L_66actionD___serialize__ (interop_serverQ_L_66action self, $Serial$state state) {
    $step_serialize(self->L_65obj, state);
}
interop_serverQ_L_66action interop_serverQ_L_66actionD___deserialize__ (interop_serverQ_L_66action self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct interop_serverQ_L_66action));
            self->$class = &interop_serverQ_L_66actionG_methods;
            return self;
        }
        self = $DNEW(interop_serverQ_L_66action, state);
    }
    self->L_65obj = $step_deserialize(state);
    return self;
}
interop_serverQ_L_66action interop_serverQ_L_66actionG_new(interop_serverQ_main G_1) {
    interop_serverQ_L_66action $tmp = acton_malloc(sizeof(struct interop_serverQ_L_66action));
    $tmp->$class = &interop_serverQ_L_66actionG_methods;
    interop_serverQ_L_66actionG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct interop_serverQ_L_66actionG_class interop_serverQ_L_66actionG_methods;
$R interop_serverQ_L_67C_43cont (B_str cmd, sshQ_ServerChannel ch, $Cont C_cont, B_NoneType C_44res) {
    #line 105 "src/interop_server.act"
    if (((B_bool)((B_bool (*) ($WORD, B_str, B_str))((B_Eq)(interop_serverQ_W_main_1090))->$class->__eq__)(interop_serverQ_W_main_1090, cmd, to$str("ping")))->val) {
        #line 106 "src/interop_server.act"
        ((B_Msg (*) ($WORD))((sshQ_ServerChannel)(ch))->$class->accept_request)(ch);
        #line 107 "src/interop_server.act"
        ((B_Msg (*) ($WORD, B_bytes))((sshQ_ServerChannel)(ch))->$class->write)(ch, to$bytesD_len("pong\n", 5));
        #line 108 "src/interop_server.act"
        ((B_Msg (*) ($WORD, int64_t))((sshQ_ServerChannel)(ch))->$class->send_exit_status)(ch, 0LL);
        #line 109 "src/interop_server.act"
        ((B_Msg (*) ($WORD))((sshQ_ServerChannel)(ch))->$class->close)(ch);
    }
    else {
        #line 111 "src/interop_server.act"
        ((B_Msg (*) ($WORD))((sshQ_ServerChannel)(ch))->$class->accept_request)(ch);
        #line 112 "src/interop_server.act"
        ((B_Msg (*) ($WORD, B_bytes))((sshQ_ServerChannel)(ch))->$class->write_stderr)(ch, to$bytesD_len("unknown command\n", 16));
        #line 113 "src/interop_server.act"
        ((B_Msg (*) ($WORD, int64_t))((sshQ_ServerChannel)(ch))->$class->send_exit_status)(ch, 127LL);
        #line 114 "src/interop_server.act"
        ((B_Msg (*) ($WORD))((sshQ_ServerChannel)(ch))->$class->close)(ch);
    }
    return $R_CONT(C_cont, B_None);
}
B_NoneType interop_serverQ_L_68ContD___init__ (interop_serverQ_L_68Cont L_self, B_str cmd, sshQ_ServerChannel ch, $Cont C_cont) {
    ((interop_serverQ_L_68Cont)(L_self))->cmd = cmd;
    ((interop_serverQ_L_68Cont)(L_self))->ch = ch;
    ((interop_serverQ_L_68Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R interop_serverQ_L_68ContD___call__ (interop_serverQ_L_68Cont L_self, B_NoneType G_1) {
    B_str cmd = ((interop_serverQ_L_68Cont)(L_self))->cmd;
    sshQ_ServerChannel ch = ((interop_serverQ_L_68Cont)(L_self))->ch;
    $Cont C_cont = ((interop_serverQ_L_68Cont)(L_self))->C_cont;
    return interop_serverQ_L_67C_43cont(cmd, ch, C_cont, G_1);
}
void interop_serverQ_L_68ContD___serialize__ (interop_serverQ_L_68Cont self, $Serial$state state) {
    $step_serialize(self->cmd, state);
    $step_serialize(self->ch, state);
    $step_serialize(self->C_cont, state);
}
interop_serverQ_L_68Cont interop_serverQ_L_68ContD___deserialize__ (interop_serverQ_L_68Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct interop_serverQ_L_68Cont));
            self->$class = &interop_serverQ_L_68ContG_methods;
            return self;
        }
        self = $DNEW(interop_serverQ_L_68Cont, state);
    }
    self->cmd = $step_deserialize(state);
    self->ch = $step_deserialize(state);
    self->C_cont = $step_deserialize(state);
    return self;
}
interop_serverQ_L_68Cont interop_serverQ_L_68ContG_new(B_str G_1, sshQ_ServerChannel G_2, $Cont G_3) {
    interop_serverQ_L_68Cont $tmp = acton_malloc(sizeof(struct interop_serverQ_L_68Cont));
    $tmp->$class = &interop_serverQ_L_68ContG_methods;
    interop_serverQ_L_68ContG_methods.__init__($tmp, G_1, G_2, G_3);
    return $tmp;
}
struct interop_serverQ_L_68ContG_class interop_serverQ_L_68ContG_methods;
$R interop_serverQ_L_69C_45cont ($Cont C_cont, B_NoneType C_46res) {
    return $R_CONT(C_cont, B_None);
}
B_NoneType interop_serverQ_L_72ContD___init__ (interop_serverQ_L_72Cont L_self, $Cont C_cont) {
    ((interop_serverQ_L_72Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R interop_serverQ_L_72ContD___call__ (interop_serverQ_L_72Cont L_self, B_NoneType G_1) {
    $Cont C_cont = ((interop_serverQ_L_72Cont)(L_self))->C_cont;
    return interop_serverQ_L_69C_45cont(C_cont, G_1);
}
void interop_serverQ_L_72ContD___serialize__ (interop_serverQ_L_72Cont self, $Serial$state state) {
    $step_serialize(self->C_cont, state);
}
interop_serverQ_L_72Cont interop_serverQ_L_72ContD___deserialize__ (interop_serverQ_L_72Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct interop_serverQ_L_72Cont));
            self->$class = &interop_serverQ_L_72ContG_methods;
            return self;
        }
        self = $DNEW(interop_serverQ_L_72Cont, state);
    }
    self->C_cont = $step_deserialize(state);
    return self;
}
interop_serverQ_L_72Cont interop_serverQ_L_72ContG_new($Cont G_1) {
    interop_serverQ_L_72Cont $tmp = acton_malloc(sizeof(struct interop_serverQ_L_72Cont));
    $tmp->$class = &interop_serverQ_L_72ContG_methods;
    interop_serverQ_L_72ContG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct interop_serverQ_L_72ContG_class interop_serverQ_L_72ContG_methods;
B_NoneType interop_serverQ_L_73ContD___init__ (interop_serverQ_L_73Cont L_self, $Cont C_cont) {
    ((interop_serverQ_L_73Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R interop_serverQ_L_73ContD___call__ (interop_serverQ_L_73Cont L_self, B_NoneType G_1) {
    $Cont C_cont = ((interop_serverQ_L_73Cont)(L_self))->C_cont;
    return interop_serverQ_L_69C_45cont(C_cont, G_1);
}
void interop_serverQ_L_73ContD___serialize__ (interop_serverQ_L_73Cont self, $Serial$state state) {
    $step_serialize(self->C_cont, state);
}
interop_serverQ_L_73Cont interop_serverQ_L_73ContD___deserialize__ (interop_serverQ_L_73Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct interop_serverQ_L_73Cont));
            self->$class = &interop_serverQ_L_73ContG_methods;
            return self;
        }
        self = $DNEW(interop_serverQ_L_73Cont, state);
    }
    self->C_cont = $step_deserialize(state);
    return self;
}
interop_serverQ_L_73Cont interop_serverQ_L_73ContG_new($Cont G_1) {
    interop_serverQ_L_73Cont $tmp = acton_malloc(sizeof(struct interop_serverQ_L_73Cont));
    $tmp->$class = &interop_serverQ_L_73ContG_methods;
    interop_serverQ_L_73ContG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct interop_serverQ_L_73ContG_class interop_serverQ_L_73ContG_methods;
$R interop_serverQ_L_71C_49cont (interop_serverQ_main self, sshQ_ServerChannel ch, $Cont C_cont, B_bool C_50res) {
    B_bool C_4pre = C_50res;
    if (((B_bool)C_4pre)->val) {
        return (($R (*) ($WORD, $Cont, sshQ_ServerChannel))((interop_serverQ_main)(self))->$class->close_echoG_local)(self, (($Cont)interop_serverQ_L_72ContG_new(C_cont)), ch);
    }
    else {
        return $R_CONT((($Cont)interop_serverQ_L_73ContG_new(C_cont)), B_None);
    }
}
B_NoneType interop_serverQ_L_74ContD___init__ (interop_serverQ_L_74Cont L_self, interop_serverQ_main self, sshQ_ServerChannel ch, $Cont C_cont) {
    ((interop_serverQ_L_74Cont)(L_self))->self = self;
    ((interop_serverQ_L_74Cont)(L_self))->ch = ch;
    ((interop_serverQ_L_74Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R interop_serverQ_L_74ContD___call__ (interop_serverQ_L_74Cont L_self, B_bool G_1) {
    interop_serverQ_main self = ((interop_serverQ_L_74Cont)(L_self))->self;
    sshQ_ServerChannel ch = ((interop_serverQ_L_74Cont)(L_self))->ch;
    $Cont C_cont = ((interop_serverQ_L_74Cont)(L_self))->C_cont;
    return interop_serverQ_L_71C_49cont(self, ch, C_cont, G_1);
}
void interop_serverQ_L_74ContD___serialize__ (interop_serverQ_L_74Cont self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->ch, state);
    $step_serialize(self->C_cont, state);
}
interop_serverQ_L_74Cont interop_serverQ_L_74ContD___deserialize__ (interop_serverQ_L_74Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct interop_serverQ_L_74Cont));
            self->$class = &interop_serverQ_L_74ContG_methods;
            return self;
        }
        self = $DNEW(interop_serverQ_L_74Cont, state);
    }
    self->self = $step_deserialize(state);
    self->ch = $step_deserialize(state);
    self->C_cont = $step_deserialize(state);
    return self;
}
interop_serverQ_L_74Cont interop_serverQ_L_74ContG_new(interop_serverQ_main G_1, sshQ_ServerChannel G_2, $Cont G_3) {
    interop_serverQ_L_74Cont $tmp = acton_malloc(sizeof(struct interop_serverQ_L_74Cont));
    $tmp->$class = &interop_serverQ_L_74ContG_methods;
    interop_serverQ_L_74ContG_methods.__init__($tmp, G_1, G_2, G_3);
    return $tmp;
}
struct interop_serverQ_L_74ContG_class interop_serverQ_L_74ContG_methods;
$R interop_serverQ_L_70C_47cont (sshQ_ServerChannel ch, interop_serverQ_main self, $Cont C_cont, B_NoneType C_48res) {
    #line 119 "src/interop_server.act"
    ((B_Msg (*) ($WORD))((sshQ_ServerChannel)(ch))->$class->accept_request)(ch);
    return (($R (*) ($WORD, $Cont, sshQ_ServerChannel))((interop_serverQ_main)(self))->$class->saw_eofG_local)(self, (($Cont)interop_serverQ_L_74ContG_new(self, ch, C_cont)), ch);
}
B_NoneType interop_serverQ_L_75ContD___init__ (interop_serverQ_L_75Cont L_self, sshQ_ServerChannel ch, interop_serverQ_main self, $Cont C_cont) {
    ((interop_serverQ_L_75Cont)(L_self))->ch = ch;
    ((interop_serverQ_L_75Cont)(L_self))->self = self;
    ((interop_serverQ_L_75Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R interop_serverQ_L_75ContD___call__ (interop_serverQ_L_75Cont L_self, B_NoneType G_1) {
    sshQ_ServerChannel ch = ((interop_serverQ_L_75Cont)(L_self))->ch;
    interop_serverQ_main self = ((interop_serverQ_L_75Cont)(L_self))->self;
    $Cont C_cont = ((interop_serverQ_L_75Cont)(L_self))->C_cont;
    return interop_serverQ_L_70C_47cont(ch, self, C_cont, G_1);
}
void interop_serverQ_L_75ContD___serialize__ (interop_serverQ_L_75Cont self, $Serial$state state) {
    $step_serialize(self->ch, state);
    $step_serialize(self->self, state);
    $step_serialize(self->C_cont, state);
}
interop_serverQ_L_75Cont interop_serverQ_L_75ContD___deserialize__ (interop_serverQ_L_75Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct interop_serverQ_L_75Cont));
            self->$class = &interop_serverQ_L_75ContG_methods;
            return self;
        }
        self = $DNEW(interop_serverQ_L_75Cont, state);
    }
    self->ch = $step_deserialize(state);
    self->self = $step_deserialize(state);
    self->C_cont = $step_deserialize(state);
    return self;
}
interop_serverQ_L_75Cont interop_serverQ_L_75ContG_new(sshQ_ServerChannel G_1, interop_serverQ_main G_2, $Cont G_3) {
    interop_serverQ_L_75Cont $tmp = acton_malloc(sizeof(struct interop_serverQ_L_75Cont));
    $tmp->$class = &interop_serverQ_L_75ContG_methods;
    interop_serverQ_L_75ContG_methods.__init__($tmp, G_1, G_2, G_3);
    return $tmp;
}
struct interop_serverQ_L_75ContG_class interop_serverQ_L_75ContG_methods;
B_NoneType interop_serverQ_L_76ContD___init__ (interop_serverQ_L_76Cont L_self, $Cont C_cont) {
    ((interop_serverQ_L_76Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R interop_serverQ_L_76ContD___call__ (interop_serverQ_L_76Cont L_self, B_NoneType G_1) {
    $Cont C_cont = ((interop_serverQ_L_76Cont)(L_self))->C_cont;
    return interop_serverQ_L_69C_45cont(C_cont, G_1);
}
void interop_serverQ_L_76ContD___serialize__ (interop_serverQ_L_76Cont self, $Serial$state state) {
    $step_serialize(self->C_cont, state);
}
interop_serverQ_L_76Cont interop_serverQ_L_76ContD___deserialize__ (interop_serverQ_L_76Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct interop_serverQ_L_76Cont));
            self->$class = &interop_serverQ_L_76ContG_methods;
            return self;
        }
        self = $DNEW(interop_serverQ_L_76Cont, state);
    }
    self->C_cont = $step_deserialize(state);
    return self;
}
interop_serverQ_L_76Cont interop_serverQ_L_76ContG_new($Cont G_1) {
    interop_serverQ_L_76Cont $tmp = acton_malloc(sizeof(struct interop_serverQ_L_76Cont));
    $tmp->$class = &interop_serverQ_L_76ContG_methods;
    interop_serverQ_L_76ContG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct interop_serverQ_L_76ContG_class interop_serverQ_L_76ContG_methods;
B_NoneType interop_serverQ_L_77procD___init__ (interop_serverQ_L_77proc L_self, interop_serverQ_main self, sshQ_ServerChannel ch, B_str mode) {
    ((interop_serverQ_L_77proc)(L_self))->self = self;
    ((interop_serverQ_L_77proc)(L_self))->ch = ch;
    ((interop_serverQ_L_77proc)(L_self))->mode = mode;
    return B_None;
}
$R interop_serverQ_L_77procD___call__ (interop_serverQ_L_77proc L_self, $Cont C_cont) {
    interop_serverQ_main self = ((interop_serverQ_L_77proc)(L_self))->self;
    sshQ_ServerChannel ch = ((interop_serverQ_L_77proc)(L_self))->ch;
    B_str mode = ((interop_serverQ_L_77proc)(L_self))->mode;
    return (($R (*) ($WORD, $Cont, sshQ_ServerChannel, B_str))((interop_serverQ_main)(self))->$class->set_modeG_local)(self, C_cont, ch, mode);
}
$R interop_serverQ_L_77procD___exec__ (interop_serverQ_L_77proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((interop_serverQ_L_77proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void interop_serverQ_L_77procD___serialize__ (interop_serverQ_L_77proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->ch, state);
    $step_serialize(self->mode, state);
}
interop_serverQ_L_77proc interop_serverQ_L_77procD___deserialize__ (interop_serverQ_L_77proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct interop_serverQ_L_77proc));
            self->$class = &interop_serverQ_L_77procG_methods;
            return self;
        }
        self = $DNEW(interop_serverQ_L_77proc, state);
    }
    self->self = $step_deserialize(state);
    self->ch = $step_deserialize(state);
    self->mode = $step_deserialize(state);
    return self;
}
interop_serverQ_L_77proc interop_serverQ_L_77procG_new(interop_serverQ_main G_1, sshQ_ServerChannel G_2, B_str G_3) {
    interop_serverQ_L_77proc $tmp = acton_malloc(sizeof(struct interop_serverQ_L_77proc));
    $tmp->$class = &interop_serverQ_L_77procG_methods;
    interop_serverQ_L_77procG_methods.__init__($tmp, G_1, G_2, G_3);
    return $tmp;
}
struct interop_serverQ_L_77procG_class interop_serverQ_L_77procG_methods;
B_NoneType interop_serverQ_L_78procD___init__ (interop_serverQ_L_78proc L_self, interop_serverQ_main self, sshQ_ServerChannel ch) {
    ((interop_serverQ_L_78proc)(L_self))->self = self;
    ((interop_serverQ_L_78proc)(L_self))->ch = ch;
    return B_None;
}
$R interop_serverQ_L_78procD___call__ (interop_serverQ_L_78proc L_self, $Cont C_cont) {
    interop_serverQ_main self = ((interop_serverQ_L_78proc)(L_self))->self;
    sshQ_ServerChannel ch = ((interop_serverQ_L_78proc)(L_self))->ch;
    return (($R (*) ($WORD, $Cont, sshQ_ServerChannel))((interop_serverQ_main)(self))->$class->mode_ofG_local)(self, C_cont, ch);
}
$R interop_serverQ_L_78procD___exec__ (interop_serverQ_L_78proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((interop_serverQ_L_78proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void interop_serverQ_L_78procD___serialize__ (interop_serverQ_L_78proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->ch, state);
}
interop_serverQ_L_78proc interop_serverQ_L_78procD___deserialize__ (interop_serverQ_L_78proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct interop_serverQ_L_78proc));
            self->$class = &interop_serverQ_L_78procG_methods;
            return self;
        }
        self = $DNEW(interop_serverQ_L_78proc, state);
    }
    self->self = $step_deserialize(state);
    self->ch = $step_deserialize(state);
    return self;
}
interop_serverQ_L_78proc interop_serverQ_L_78procG_new(interop_serverQ_main G_1, sshQ_ServerChannel G_2) {
    interop_serverQ_L_78proc $tmp = acton_malloc(sizeof(struct interop_serverQ_L_78proc));
    $tmp->$class = &interop_serverQ_L_78procG_methods;
    interop_serverQ_L_78procG_methods.__init__($tmp, G_1, G_2);
    return $tmp;
}
struct interop_serverQ_L_78procG_class interop_serverQ_L_78procG_methods;
B_NoneType interop_serverQ_L_79procD___init__ (interop_serverQ_L_79proc L_self, interop_serverQ_main self, sshQ_ServerChannel ch) {
    ((interop_serverQ_L_79proc)(L_self))->self = self;
    ((interop_serverQ_L_79proc)(L_self))->ch = ch;
    return B_None;
}
$R interop_serverQ_L_79procD___call__ (interop_serverQ_L_79proc L_self, $Cont C_cont) {
    interop_serverQ_main self = ((interop_serverQ_L_79proc)(L_self))->self;
    sshQ_ServerChannel ch = ((interop_serverQ_L_79proc)(L_self))->ch;
    return (($R (*) ($WORD, $Cont, sshQ_ServerChannel))((interop_serverQ_main)(self))->$class->mark_eofG_local)(self, C_cont, ch);
}
$R interop_serverQ_L_79procD___exec__ (interop_serverQ_L_79proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((interop_serverQ_L_79proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void interop_serverQ_L_79procD___serialize__ (interop_serverQ_L_79proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->ch, state);
}
interop_serverQ_L_79proc interop_serverQ_L_79procD___deserialize__ (interop_serverQ_L_79proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct interop_serverQ_L_79proc));
            self->$class = &interop_serverQ_L_79procG_methods;
            return self;
        }
        self = $DNEW(interop_serverQ_L_79proc, state);
    }
    self->self = $step_deserialize(state);
    self->ch = $step_deserialize(state);
    return self;
}
interop_serverQ_L_79proc interop_serverQ_L_79procG_new(interop_serverQ_main G_1, sshQ_ServerChannel G_2) {
    interop_serverQ_L_79proc $tmp = acton_malloc(sizeof(struct interop_serverQ_L_79proc));
    $tmp->$class = &interop_serverQ_L_79procG_methods;
    interop_serverQ_L_79procG_methods.__init__($tmp, G_1, G_2);
    return $tmp;
}
struct interop_serverQ_L_79procG_class interop_serverQ_L_79procG_methods;
B_NoneType interop_serverQ_L_80procD___init__ (interop_serverQ_L_80proc L_self, interop_serverQ_main self, sshQ_ServerChannel ch) {
    ((interop_serverQ_L_80proc)(L_self))->self = self;
    ((interop_serverQ_L_80proc)(L_self))->ch = ch;
    return B_None;
}
$R interop_serverQ_L_80procD___call__ (interop_serverQ_L_80proc L_self, $Cont C_cont) {
    interop_serverQ_main self = ((interop_serverQ_L_80proc)(L_self))->self;
    sshQ_ServerChannel ch = ((interop_serverQ_L_80proc)(L_self))->ch;
    return (($R (*) ($WORD, $Cont, sshQ_ServerChannel))((interop_serverQ_main)(self))->$class->saw_eofG_local)(self, C_cont, ch);
}
$R interop_serverQ_L_80procD___exec__ (interop_serverQ_L_80proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((interop_serverQ_L_80proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void interop_serverQ_L_80procD___serialize__ (interop_serverQ_L_80proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->ch, state);
}
interop_serverQ_L_80proc interop_serverQ_L_80procD___deserialize__ (interop_serverQ_L_80proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct interop_serverQ_L_80proc));
            self->$class = &interop_serverQ_L_80procG_methods;
            return self;
        }
        self = $DNEW(interop_serverQ_L_80proc, state);
    }
    self->self = $step_deserialize(state);
    self->ch = $step_deserialize(state);
    return self;
}
interop_serverQ_L_80proc interop_serverQ_L_80procG_new(interop_serverQ_main G_1, sshQ_ServerChannel G_2) {
    interop_serverQ_L_80proc $tmp = acton_malloc(sizeof(struct interop_serverQ_L_80proc));
    $tmp->$class = &interop_serverQ_L_80procG_methods;
    interop_serverQ_L_80procG_methods.__init__($tmp, G_1, G_2);
    return $tmp;
}
struct interop_serverQ_L_80procG_class interop_serverQ_L_80procG_methods;
B_NoneType interop_serverQ_L_81procD___init__ (interop_serverQ_L_81proc L_self, interop_serverQ_main self, sshQ_ServerChannel ch) {
    ((interop_serverQ_L_81proc)(L_self))->self = self;
    ((interop_serverQ_L_81proc)(L_self))->ch = ch;
    return B_None;
}
$R interop_serverQ_L_81procD___call__ (interop_serverQ_L_81proc L_self, $Cont C_cont) {
    interop_serverQ_main self = ((interop_serverQ_L_81proc)(L_self))->self;
    sshQ_ServerChannel ch = ((interop_serverQ_L_81proc)(L_self))->ch;
    return (($R (*) ($WORD, $Cont, sshQ_ServerChannel))((interop_serverQ_main)(self))->$class->close_echoG_local)(self, C_cont, ch);
}
$R interop_serverQ_L_81procD___exec__ (interop_serverQ_L_81proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((interop_serverQ_L_81proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void interop_serverQ_L_81procD___serialize__ (interop_serverQ_L_81proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->ch, state);
}
interop_serverQ_L_81proc interop_serverQ_L_81procD___deserialize__ (interop_serverQ_L_81proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct interop_serverQ_L_81proc));
            self->$class = &interop_serverQ_L_81procG_methods;
            return self;
        }
        self = $DNEW(interop_serverQ_L_81proc, state);
    }
    self->self = $step_deserialize(state);
    self->ch = $step_deserialize(state);
    return self;
}
interop_serverQ_L_81proc interop_serverQ_L_81procG_new(interop_serverQ_main G_1, sshQ_ServerChannel G_2) {
    interop_serverQ_L_81proc $tmp = acton_malloc(sizeof(struct interop_serverQ_L_81proc));
    $tmp->$class = &interop_serverQ_L_81procG_methods;
    interop_serverQ_L_81procG_methods.__init__($tmp, G_1, G_2);
    return $tmp;
}
struct interop_serverQ_L_81procG_class interop_serverQ_L_81procG_methods;
B_NoneType interop_serverQ_L_82procD___init__ (interop_serverQ_L_82proc L_self, interop_serverQ_main self, sshQ_Server s, B_str err) {
    ((interop_serverQ_L_82proc)(L_self))->self = self;
    ((interop_serverQ_L_82proc)(L_self))->s = s;
    ((interop_serverQ_L_82proc)(L_self))->err = err;
    return B_None;
}
$R interop_serverQ_L_82procD___call__ (interop_serverQ_L_82proc L_self, $Cont C_cont) {
    interop_serverQ_main self = ((interop_serverQ_L_82proc)(L_self))->self;
    sshQ_Server s = ((interop_serverQ_L_82proc)(L_self))->s;
    B_str err = ((interop_serverQ_L_82proc)(L_self))->err;
    return (($R (*) ($WORD, $Cont, sshQ_Server, B_str))((interop_serverQ_main)(self))->$class->on_listenG_local)(self, C_cont, s, err);
}
$R interop_serverQ_L_82procD___exec__ (interop_serverQ_L_82proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((interop_serverQ_L_82proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void interop_serverQ_L_82procD___serialize__ (interop_serverQ_L_82proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->s, state);
    $step_serialize(self->err, state);
}
interop_serverQ_L_82proc interop_serverQ_L_82procD___deserialize__ (interop_serverQ_L_82proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct interop_serverQ_L_82proc));
            self->$class = &interop_serverQ_L_82procG_methods;
            return self;
        }
        self = $DNEW(interop_serverQ_L_82proc, state);
    }
    self->self = $step_deserialize(state);
    self->s = $step_deserialize(state);
    self->err = $step_deserialize(state);
    return self;
}
interop_serverQ_L_82proc interop_serverQ_L_82procG_new(interop_serverQ_main G_1, sshQ_Server G_2, B_str G_3) {
    interop_serverQ_L_82proc $tmp = acton_malloc(sizeof(struct interop_serverQ_L_82proc));
    $tmp->$class = &interop_serverQ_L_82procG_methods;
    interop_serverQ_L_82procG_methods.__init__($tmp, G_1, G_2, G_3);
    return $tmp;
}
struct interop_serverQ_L_82procG_class interop_serverQ_L_82procG_methods;
B_NoneType interop_serverQ_L_83procD___init__ (interop_serverQ_L_83proc L_self, interop_serverQ_main self, sshQ_Server s, B_str reason) {
    ((interop_serverQ_L_83proc)(L_self))->self = self;
    ((interop_serverQ_L_83proc)(L_self))->s = s;
    ((interop_serverQ_L_83proc)(L_self))->reason = reason;
    return B_None;
}
$R interop_serverQ_L_83procD___call__ (interop_serverQ_L_83proc L_self, $Cont C_cont) {
    interop_serverQ_main self = ((interop_serverQ_L_83proc)(L_self))->self;
    sshQ_Server s = ((interop_serverQ_L_83proc)(L_self))->s;
    B_str reason = ((interop_serverQ_L_83proc)(L_self))->reason;
    return (($R (*) ($WORD, $Cont, sshQ_Server, B_str))((interop_serverQ_main)(self))->$class->on_server_closeG_local)(self, C_cont, s, reason);
}
$R interop_serverQ_L_83procD___exec__ (interop_serverQ_L_83proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((interop_serverQ_L_83proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void interop_serverQ_L_83procD___serialize__ (interop_serverQ_L_83proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->s, state);
    $step_serialize(self->reason, state);
}
interop_serverQ_L_83proc interop_serverQ_L_83procD___deserialize__ (interop_serverQ_L_83proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct interop_serverQ_L_83proc));
            self->$class = &interop_serverQ_L_83procG_methods;
            return self;
        }
        self = $DNEW(interop_serverQ_L_83proc, state);
    }
    self->self = $step_deserialize(state);
    self->s = $step_deserialize(state);
    self->reason = $step_deserialize(state);
    return self;
}
interop_serverQ_L_83proc interop_serverQ_L_83procG_new(interop_serverQ_main G_1, sshQ_Server G_2, B_str G_3) {
    interop_serverQ_L_83proc $tmp = acton_malloc(sizeof(struct interop_serverQ_L_83proc));
    $tmp->$class = &interop_serverQ_L_83procG_methods;
    interop_serverQ_L_83procG_methods.__init__($tmp, G_1, G_2, G_3);
    return $tmp;
}
struct interop_serverQ_L_83procG_class interop_serverQ_L_83procG_methods;
B_NoneType interop_serverQ_L_84procD___init__ (interop_serverQ_L_84proc L_self, interop_serverQ_main self, sshQ_ServerSession sess) {
    ((interop_serverQ_L_84proc)(L_self))->self = self;
    ((interop_serverQ_L_84proc)(L_self))->sess = sess;
    return B_None;
}
$R interop_serverQ_L_84procD___call__ (interop_serverQ_L_84proc L_self, $Cont C_cont) {
    interop_serverQ_main self = ((interop_serverQ_L_84proc)(L_self))->self;
    sshQ_ServerSession sess = ((interop_serverQ_L_84proc)(L_self))->sess;
    return (($R (*) ($WORD, $Cont, sshQ_ServerSession))((interop_serverQ_main)(self))->$class->on_sessionG_local)(self, C_cont, sess);
}
$R interop_serverQ_L_84procD___exec__ (interop_serverQ_L_84proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((interop_serverQ_L_84proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void interop_serverQ_L_84procD___serialize__ (interop_serverQ_L_84proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->sess, state);
}
interop_serverQ_L_84proc interop_serverQ_L_84procD___deserialize__ (interop_serverQ_L_84proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct interop_serverQ_L_84proc));
            self->$class = &interop_serverQ_L_84procG_methods;
            return self;
        }
        self = $DNEW(interop_serverQ_L_84proc, state);
    }
    self->self = $step_deserialize(state);
    self->sess = $step_deserialize(state);
    return self;
}
interop_serverQ_L_84proc interop_serverQ_L_84procG_new(interop_serverQ_main G_1, sshQ_ServerSession G_2) {
    interop_serverQ_L_84proc $tmp = acton_malloc(sizeof(struct interop_serverQ_L_84proc));
    $tmp->$class = &interop_serverQ_L_84procG_methods;
    interop_serverQ_L_84procG_methods.__init__($tmp, G_1, G_2);
    return $tmp;
}
struct interop_serverQ_L_84procG_class interop_serverQ_L_84procG_methods;
B_NoneType interop_serverQ_L_85procD___init__ (interop_serverQ_L_85proc L_self, interop_serverQ_main self, sshQ_ServerSession sess, B_str reason) {
    ((interop_serverQ_L_85proc)(L_self))->self = self;
    ((interop_serverQ_L_85proc)(L_self))->sess = sess;
    ((interop_serverQ_L_85proc)(L_self))->reason = reason;
    return B_None;
}
$R interop_serverQ_L_85procD___call__ (interop_serverQ_L_85proc L_self, $Cont C_cont) {
    interop_serverQ_main self = ((interop_serverQ_L_85proc)(L_self))->self;
    sshQ_ServerSession sess = ((interop_serverQ_L_85proc)(L_self))->sess;
    B_str reason = ((interop_serverQ_L_85proc)(L_self))->reason;
    return (($R (*) ($WORD, $Cont, sshQ_ServerSession, B_str))((interop_serverQ_main)(self))->$class->on_session_closeG_local)(self, C_cont, sess, reason);
}
$R interop_serverQ_L_85procD___exec__ (interop_serverQ_L_85proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((interop_serverQ_L_85proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void interop_serverQ_L_85procD___serialize__ (interop_serverQ_L_85proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->sess, state);
    $step_serialize(self->reason, state);
}
interop_serverQ_L_85proc interop_serverQ_L_85procD___deserialize__ (interop_serverQ_L_85proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct interop_serverQ_L_85proc));
            self->$class = &interop_serverQ_L_85procG_methods;
            return self;
        }
        self = $DNEW(interop_serverQ_L_85proc, state);
    }
    self->self = $step_deserialize(state);
    self->sess = $step_deserialize(state);
    self->reason = $step_deserialize(state);
    return self;
}
interop_serverQ_L_85proc interop_serverQ_L_85procG_new(interop_serverQ_main G_1, sshQ_ServerSession G_2, B_str G_3) {
    interop_serverQ_L_85proc $tmp = acton_malloc(sizeof(struct interop_serverQ_L_85proc));
    $tmp->$class = &interop_serverQ_L_85procG_methods;
    interop_serverQ_L_85procG_methods.__init__($tmp, G_1, G_2, G_3);
    return $tmp;
}
struct interop_serverQ_L_85procG_class interop_serverQ_L_85procG_methods;
B_NoneType interop_serverQ_L_86procD___init__ (interop_serverQ_L_86proc L_self, interop_serverQ_main self, sshQ_ServerSession sess, sshQ_AuthRequest req) {
    ((interop_serverQ_L_86proc)(L_self))->self = self;
    ((interop_serverQ_L_86proc)(L_self))->sess = sess;
    ((interop_serverQ_L_86proc)(L_self))->req = req;
    return B_None;
}
$R interop_serverQ_L_86procD___call__ (interop_serverQ_L_86proc L_self, $Cont C_cont) {
    interop_serverQ_main self = ((interop_serverQ_L_86proc)(L_self))->self;
    sshQ_ServerSession sess = ((interop_serverQ_L_86proc)(L_self))->sess;
    sshQ_AuthRequest req = ((interop_serverQ_L_86proc)(L_self))->req;
    return (($R (*) ($WORD, $Cont, sshQ_ServerSession, sshQ_AuthRequest))((interop_serverQ_main)(self))->$class->on_authG_local)(self, C_cont, sess, req);
}
$R interop_serverQ_L_86procD___exec__ (interop_serverQ_L_86proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((interop_serverQ_L_86proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void interop_serverQ_L_86procD___serialize__ (interop_serverQ_L_86proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->sess, state);
    $step_serialize(self->req, state);
}
interop_serverQ_L_86proc interop_serverQ_L_86procD___deserialize__ (interop_serverQ_L_86proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct interop_serverQ_L_86proc));
            self->$class = &interop_serverQ_L_86procG_methods;
            return self;
        }
        self = $DNEW(interop_serverQ_L_86proc, state);
    }
    self->self = $step_deserialize(state);
    self->sess = $step_deserialize(state);
    self->req = $step_deserialize(state);
    return self;
}
interop_serverQ_L_86proc interop_serverQ_L_86procG_new(interop_serverQ_main G_1, sshQ_ServerSession G_2, sshQ_AuthRequest G_3) {
    interop_serverQ_L_86proc $tmp = acton_malloc(sizeof(struct interop_serverQ_L_86proc));
    $tmp->$class = &interop_serverQ_L_86procG_methods;
    interop_serverQ_L_86procG_methods.__init__($tmp, G_1, G_2, G_3);
    return $tmp;
}
struct interop_serverQ_L_86procG_class interop_serverQ_L_86procG_methods;
B_NoneType interop_serverQ_L_87procD___init__ (interop_serverQ_L_87proc L_self, interop_serverQ_main self, sshQ_ServerChannel ch, B_bytes data) {
    ((interop_serverQ_L_87proc)(L_self))->self = self;
    ((interop_serverQ_L_87proc)(L_self))->ch = ch;
    ((interop_serverQ_L_87proc)(L_self))->data = data;
    return B_None;
}
$R interop_serverQ_L_87procD___call__ (interop_serverQ_L_87proc L_self, $Cont C_cont) {
    interop_serverQ_main self = ((interop_serverQ_L_87proc)(L_self))->self;
    sshQ_ServerChannel ch = ((interop_serverQ_L_87proc)(L_self))->ch;
    B_bytes data = ((interop_serverQ_L_87proc)(L_self))->data;
    return (($R (*) ($WORD, $Cont, sshQ_ServerChannel, B_bytes))((interop_serverQ_main)(self))->$class->srv_on_dataG_local)(self, C_cont, ch, data);
}
$R interop_serverQ_L_87procD___exec__ (interop_serverQ_L_87proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((interop_serverQ_L_87proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void interop_serverQ_L_87procD___serialize__ (interop_serverQ_L_87proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->ch, state);
    $step_serialize(self->data, state);
}
interop_serverQ_L_87proc interop_serverQ_L_87procD___deserialize__ (interop_serverQ_L_87proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct interop_serverQ_L_87proc));
            self->$class = &interop_serverQ_L_87procG_methods;
            return self;
        }
        self = $DNEW(interop_serverQ_L_87proc, state);
    }
    self->self = $step_deserialize(state);
    self->ch = $step_deserialize(state);
    self->data = $step_deserialize(state);
    return self;
}
interop_serverQ_L_87proc interop_serverQ_L_87procG_new(interop_serverQ_main G_1, sshQ_ServerChannel G_2, B_bytes G_3) {
    interop_serverQ_L_87proc $tmp = acton_malloc(sizeof(struct interop_serverQ_L_87proc));
    $tmp->$class = &interop_serverQ_L_87procG_methods;
    interop_serverQ_L_87procG_methods.__init__($tmp, G_1, G_2, G_3);
    return $tmp;
}
struct interop_serverQ_L_87procG_class interop_serverQ_L_87procG_methods;
B_NoneType interop_serverQ_L_88procD___init__ (interop_serverQ_L_88proc L_self, interop_serverQ_main self, sshQ_ServerChannel ch, B_bytes data) {
    ((interop_serverQ_L_88proc)(L_self))->self = self;
    ((interop_serverQ_L_88proc)(L_self))->ch = ch;
    ((interop_serverQ_L_88proc)(L_self))->data = data;
    return B_None;
}
$R interop_serverQ_L_88procD___call__ (interop_serverQ_L_88proc L_self, $Cont C_cont) {
    interop_serverQ_main self = ((interop_serverQ_L_88proc)(L_self))->self;
    sshQ_ServerChannel ch = ((interop_serverQ_L_88proc)(L_self))->ch;
    B_bytes data = ((interop_serverQ_L_88proc)(L_self))->data;
    return (($R (*) ($WORD, $Cont, sshQ_ServerChannel, B_bytes))((interop_serverQ_main)(self))->$class->srv_on_stderrG_local)(self, C_cont, ch, data);
}
$R interop_serverQ_L_88procD___exec__ (interop_serverQ_L_88proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((interop_serverQ_L_88proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void interop_serverQ_L_88procD___serialize__ (interop_serverQ_L_88proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->ch, state);
    $step_serialize(self->data, state);
}
interop_serverQ_L_88proc interop_serverQ_L_88procD___deserialize__ (interop_serverQ_L_88proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct interop_serverQ_L_88proc));
            self->$class = &interop_serverQ_L_88procG_methods;
            return self;
        }
        self = $DNEW(interop_serverQ_L_88proc, state);
    }
    self->self = $step_deserialize(state);
    self->ch = $step_deserialize(state);
    self->data = $step_deserialize(state);
    return self;
}
interop_serverQ_L_88proc interop_serverQ_L_88procG_new(interop_serverQ_main G_1, sshQ_ServerChannel G_2, B_bytes G_3) {
    interop_serverQ_L_88proc $tmp = acton_malloc(sizeof(struct interop_serverQ_L_88proc));
    $tmp->$class = &interop_serverQ_L_88procG_methods;
    interop_serverQ_L_88procG_methods.__init__($tmp, G_1, G_2, G_3);
    return $tmp;
}
struct interop_serverQ_L_88procG_class interop_serverQ_L_88procG_methods;
B_NoneType interop_serverQ_L_89procD___init__ (interop_serverQ_L_89proc L_self, interop_serverQ_main self, sshQ_ServerChannel ch, B_str reason) {
    ((interop_serverQ_L_89proc)(L_self))->self = self;
    ((interop_serverQ_L_89proc)(L_self))->ch = ch;
    ((interop_serverQ_L_89proc)(L_self))->reason = reason;
    return B_None;
}
$R interop_serverQ_L_89procD___call__ (interop_serverQ_L_89proc L_self, $Cont C_cont) {
    interop_serverQ_main self = ((interop_serverQ_L_89proc)(L_self))->self;
    sshQ_ServerChannel ch = ((interop_serverQ_L_89proc)(L_self))->ch;
    B_str reason = ((interop_serverQ_L_89proc)(L_self))->reason;
    return (($R (*) ($WORD, $Cont, sshQ_ServerChannel, B_str))((interop_serverQ_main)(self))->$class->srv_on_closeG_local)(self, C_cont, ch, reason);
}
$R interop_serverQ_L_89procD___exec__ (interop_serverQ_L_89proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((interop_serverQ_L_89proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void interop_serverQ_L_89procD___serialize__ (interop_serverQ_L_89proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->ch, state);
    $step_serialize(self->reason, state);
}
interop_serverQ_L_89proc interop_serverQ_L_89procD___deserialize__ (interop_serverQ_L_89proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct interop_serverQ_L_89proc));
            self->$class = &interop_serverQ_L_89procG_methods;
            return self;
        }
        self = $DNEW(interop_serverQ_L_89proc, state);
    }
    self->self = $step_deserialize(state);
    self->ch = $step_deserialize(state);
    self->reason = $step_deserialize(state);
    return self;
}
interop_serverQ_L_89proc interop_serverQ_L_89procG_new(interop_serverQ_main G_1, sshQ_ServerChannel G_2, B_str G_3) {
    interop_serverQ_L_89proc $tmp = acton_malloc(sizeof(struct interop_serverQ_L_89proc));
    $tmp->$class = &interop_serverQ_L_89procG_methods;
    interop_serverQ_L_89procG_methods.__init__($tmp, G_1, G_2, G_3);
    return $tmp;
}
struct interop_serverQ_L_89procG_class interop_serverQ_L_89procG_methods;
B_NoneType interop_serverQ_L_90procD___init__ (interop_serverQ_L_90proc L_self, interop_serverQ_main self, sshQ_ServerSession sess) {
    ((interop_serverQ_L_90proc)(L_self))->self = self;
    ((interop_serverQ_L_90proc)(L_self))->sess = sess;
    return B_None;
}
$R interop_serverQ_L_90procD___call__ (interop_serverQ_L_90proc L_self, $Cont C_cont) {
    interop_serverQ_main self = ((interop_serverQ_L_90proc)(L_self))->self;
    sshQ_ServerSession sess = ((interop_serverQ_L_90proc)(L_self))->sess;
    return (($R (*) ($WORD, $Cont, sshQ_ServerSession))((interop_serverQ_main)(self))->$class->on_channel_openG_local)(self, C_cont, sess);
}
$R interop_serverQ_L_90procD___exec__ (interop_serverQ_L_90proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((interop_serverQ_L_90proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void interop_serverQ_L_90procD___serialize__ (interop_serverQ_L_90proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->sess, state);
}
interop_serverQ_L_90proc interop_serverQ_L_90procD___deserialize__ (interop_serverQ_L_90proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct interop_serverQ_L_90proc));
            self->$class = &interop_serverQ_L_90procG_methods;
            return self;
        }
        self = $DNEW(interop_serverQ_L_90proc, state);
    }
    self->self = $step_deserialize(state);
    self->sess = $step_deserialize(state);
    return self;
}
interop_serverQ_L_90proc interop_serverQ_L_90procG_new(interop_serverQ_main G_1, sshQ_ServerSession G_2) {
    interop_serverQ_L_90proc $tmp = acton_malloc(sizeof(struct interop_serverQ_L_90proc));
    $tmp->$class = &interop_serverQ_L_90procG_methods;
    interop_serverQ_L_90procG_methods.__init__($tmp, G_1, G_2);
    return $tmp;
}
struct interop_serverQ_L_90procG_class interop_serverQ_L_90procG_methods;
B_NoneType interop_serverQ_L_91procD___init__ (interop_serverQ_L_91proc L_self, interop_serverQ_main self, sshQ_ServerSession sess, sshQ_ServerChannel ch, B_str cmd) {
    ((interop_serverQ_L_91proc)(L_self))->self = self;
    ((interop_serverQ_L_91proc)(L_self))->sess = sess;
    ((interop_serverQ_L_91proc)(L_self))->ch = ch;
    ((interop_serverQ_L_91proc)(L_self))->cmd = cmd;
    return B_None;
}
$R interop_serverQ_L_91procD___call__ (interop_serverQ_L_91proc L_self, $Cont C_cont) {
    interop_serverQ_main self = ((interop_serverQ_L_91proc)(L_self))->self;
    sshQ_ServerSession sess = ((interop_serverQ_L_91proc)(L_self))->sess;
    sshQ_ServerChannel ch = ((interop_serverQ_L_91proc)(L_self))->ch;
    B_str cmd = ((interop_serverQ_L_91proc)(L_self))->cmd;
    return (($R (*) ($WORD, $Cont, sshQ_ServerSession, sshQ_ServerChannel, B_str))((interop_serverQ_main)(self))->$class->on_execG_local)(self, C_cont, sess, ch, cmd);
}
$R interop_serverQ_L_91procD___exec__ (interop_serverQ_L_91proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((interop_serverQ_L_91proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void interop_serverQ_L_91procD___serialize__ (interop_serverQ_L_91proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->sess, state);
    $step_serialize(self->ch, state);
    $step_serialize(self->cmd, state);
}
interop_serverQ_L_91proc interop_serverQ_L_91procD___deserialize__ (interop_serverQ_L_91proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct interop_serverQ_L_91proc));
            self->$class = &interop_serverQ_L_91procG_methods;
            return self;
        }
        self = $DNEW(interop_serverQ_L_91proc, state);
    }
    self->self = $step_deserialize(state);
    self->sess = $step_deserialize(state);
    self->ch = $step_deserialize(state);
    self->cmd = $step_deserialize(state);
    return self;
}
interop_serverQ_L_91proc interop_serverQ_L_91procG_new(interop_serverQ_main G_1, sshQ_ServerSession G_2, sshQ_ServerChannel G_3, B_str G_4) {
    interop_serverQ_L_91proc $tmp = acton_malloc(sizeof(struct interop_serverQ_L_91proc));
    $tmp->$class = &interop_serverQ_L_91procG_methods;
    interop_serverQ_L_91procG_methods.__init__($tmp, G_1, G_2, G_3, G_4);
    return $tmp;
}
struct interop_serverQ_L_91procG_class interop_serverQ_L_91procG_methods;
B_NoneType interop_serverQ_L_92procD___init__ (interop_serverQ_L_92proc L_self, interop_serverQ_main self, sshQ_ServerSession sess, sshQ_ServerChannel ch, B_str name) {
    ((interop_serverQ_L_92proc)(L_self))->self = self;
    ((interop_serverQ_L_92proc)(L_self))->sess = sess;
    ((interop_serverQ_L_92proc)(L_self))->ch = ch;
    ((interop_serverQ_L_92proc)(L_self))->name = name;
    return B_None;
}
$R interop_serverQ_L_92procD___call__ (interop_serverQ_L_92proc L_self, $Cont C_cont) {
    interop_serverQ_main self = ((interop_serverQ_L_92proc)(L_self))->self;
    sshQ_ServerSession sess = ((interop_serverQ_L_92proc)(L_self))->sess;
    sshQ_ServerChannel ch = ((interop_serverQ_L_92proc)(L_self))->ch;
    B_str name = ((interop_serverQ_L_92proc)(L_self))->name;
    return (($R (*) ($WORD, $Cont, sshQ_ServerSession, sshQ_ServerChannel, B_str))((interop_serverQ_main)(self))->$class->on_subsystemG_local)(self, C_cont, sess, ch, name);
}
$R interop_serverQ_L_92procD___exec__ (interop_serverQ_L_92proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((interop_serverQ_L_92proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void interop_serverQ_L_92procD___serialize__ (interop_serverQ_L_92proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->sess, state);
    $step_serialize(self->ch, state);
    $step_serialize(self->name, state);
}
interop_serverQ_L_92proc interop_serverQ_L_92procD___deserialize__ (interop_serverQ_L_92proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct interop_serverQ_L_92proc));
            self->$class = &interop_serverQ_L_92procG_methods;
            return self;
        }
        self = $DNEW(interop_serverQ_L_92proc, state);
    }
    self->self = $step_deserialize(state);
    self->sess = $step_deserialize(state);
    self->ch = $step_deserialize(state);
    self->name = $step_deserialize(state);
    return self;
}
interop_serverQ_L_92proc interop_serverQ_L_92procG_new(interop_serverQ_main G_1, sshQ_ServerSession G_2, sshQ_ServerChannel G_3, B_str G_4) {
    interop_serverQ_L_92proc $tmp = acton_malloc(sizeof(struct interop_serverQ_L_92proc));
    $tmp->$class = &interop_serverQ_L_92procG_methods;
    interop_serverQ_L_92procG_methods.__init__($tmp, G_1, G_2, G_3, G_4);
    return $tmp;
}
struct interop_serverQ_L_92procG_class interop_serverQ_L_92procG_methods;
$R interop_serverQ_L_93C_51cont ($Cont C_cont, interop_serverQ_main G_act, B_NoneType C_52res) {
    return $R_CONT(C_cont, G_act);
}
B_NoneType interop_serverQ_L_94ContD___init__ (interop_serverQ_L_94Cont L_self, $Cont C_cont, interop_serverQ_main G_act) {
    ((interop_serverQ_L_94Cont)(L_self))->C_cont = C_cont;
    ((interop_serverQ_L_94Cont)(L_self))->G_act = G_act;
    return B_None;
}
$R interop_serverQ_L_94ContD___call__ (interop_serverQ_L_94Cont L_self, B_NoneType G_1) {
    $Cont C_cont = ((interop_serverQ_L_94Cont)(L_self))->C_cont;
    interop_serverQ_main G_act = ((interop_serverQ_L_94Cont)(L_self))->G_act;
    return interop_serverQ_L_93C_51cont(C_cont, G_act, G_1);
}
void interop_serverQ_L_94ContD___serialize__ (interop_serverQ_L_94Cont self, $Serial$state state) {
    $step_serialize(self->C_cont, state);
    $step_serialize(self->G_act, state);
}
interop_serverQ_L_94Cont interop_serverQ_L_94ContD___deserialize__ (interop_serverQ_L_94Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct interop_serverQ_L_94Cont));
            self->$class = &interop_serverQ_L_94ContG_methods;
            return self;
        }
        self = $DNEW(interop_serverQ_L_94Cont, state);
    }
    self->C_cont = $step_deserialize(state);
    self->G_act = $step_deserialize(state);
    return self;
}
interop_serverQ_L_94Cont interop_serverQ_L_94ContG_new($Cont G_1, interop_serverQ_main G_2) {
    interop_serverQ_L_94Cont $tmp = acton_malloc(sizeof(struct interop_serverQ_L_94Cont));
    $tmp->$class = &interop_serverQ_L_94ContG_methods;
    interop_serverQ_L_94ContG_methods.__init__($tmp, G_1, G_2);
    return $tmp;
}
struct interop_serverQ_L_94ContG_class interop_serverQ_L_94ContG_methods;
B_NoneType interop_serverQ_L_95procD___init__ (interop_serverQ_L_95proc L_self, interop_serverQ_main G_act, B_Env env) {
    ((interop_serverQ_L_95proc)(L_self))->G_act = G_act;
    ((interop_serverQ_L_95proc)(L_self))->env = env;
    return B_None;
}
$R interop_serverQ_L_95procD___call__ (interop_serverQ_L_95proc L_self, $Cont C_cont) {
    interop_serverQ_main G_act = ((interop_serverQ_L_95proc)(L_self))->G_act;
    B_Env env = ((interop_serverQ_L_95proc)(L_self))->env;
    return (($R (*) ($WORD, $Cont, B_Env))((interop_serverQ_main)(G_act))->$class->__init__)(G_act, C_cont, env);
}
$R interop_serverQ_L_95procD___exec__ (interop_serverQ_L_95proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((interop_serverQ_L_95proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void interop_serverQ_L_95procD___serialize__ (interop_serverQ_L_95proc self, $Serial$state state) {
    $step_serialize(self->G_act, state);
    $step_serialize(self->env, state);
}
interop_serverQ_L_95proc interop_serverQ_L_95procD___deserialize__ (interop_serverQ_L_95proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct interop_serverQ_L_95proc));
            self->$class = &interop_serverQ_L_95procG_methods;
            return self;
        }
        self = $DNEW(interop_serverQ_L_95proc, state);
    }
    self->G_act = $step_deserialize(state);
    self->env = $step_deserialize(state);
    return self;
}
interop_serverQ_L_95proc interop_serverQ_L_95procG_new(interop_serverQ_main G_1, B_Env G_2) {
    interop_serverQ_L_95proc $tmp = acton_malloc(sizeof(struct interop_serverQ_L_95proc));
    $tmp->$class = &interop_serverQ_L_95procG_methods;
    interop_serverQ_L_95procG_methods.__init__($tmp, G_1, G_2);
    return $tmp;
}
struct interop_serverQ_L_95procG_class interop_serverQ_L_95procG_methods;
$R interop_serverQ_mainD___init__ (interop_serverQ_main self, $Cont C_cont, B_Env env) {
    ((interop_serverQ_main)(self))->env = env;
    #line 20 "src/interop_server.act"
    ((interop_serverQ_main)(self))->USER = to$str("interop");
    #line 21 "src/interop_server.act"
    ((interop_serverQ_main)(self))->PASS = to$str("interop-pass");
    #line 23 "src/interop_server.act"
    ((interop_serverQ_main)(self))->server = B_None;
    #line 26 "src/interop_server.act"
    ((interop_serverQ_main)(self))->modes = B_mk_list(0);
    #line 31 "src/interop_server.act"
    ((interop_serverQ_main)(self))->eofed = B_mk_list(0);
    return sshQ_ServerG_newact((($Cont)interop_serverQ_L_2ContG_new(self, C_cont)), netQ_TCPListenCapG_new(netQ_TCPCapG_new(netQ_NetCapG_new(((B_Env)(((interop_serverQ_main)(self))->env))->cap))), to$str("127.0.0.1"), B_u16G_new(((B_atom)toB_int(0LL)), B_None), (($action)interop_serverQ_L_4actionG_new(self)), (($action)interop_serverQ_L_6actionG_new(self)), (($action)interop_serverQ_L_8actionG_new(self)), (($action)interop_serverQ_L_10actionG_new(self)), (($action)interop_serverQ_L_12actionG_new(self)), (($action)interop_serverQ_L_14actionG_new(self)), (($action)interop_serverQ_L_16actionG_new(self)), (($action)interop_serverQ_L_18actionG_new(self)), B_None, B_None, B_None, B_None, B_None, B_None, B_None, B_None, B_None);
}
#line 33 "src/interop_server.act"
$R interop_serverQ_mainD_set_modeG_local (interop_serverQ_main self, $Cont C_cont, sshQ_ServerChannel ch, B_str mode) {
    B_Sequence W_main_45 = (B_Sequence)B_SequenceD_listG_witness;
    #line 34 "src/interop_server.act"
    ((B_NoneType (*) ($WORD, B_list, B_tuple))((B_Sequence)(W_main_45))->$class->append)(W_main_45, ((interop_serverQ_main)(self))->modes, $NEWTUPLE(2, ch, mode));
    return $R_CONT(C_cont, B_None);
}
#line 36 "src/interop_server.act"
$R interop_serverQ_mainD_mode_ofG_local (interop_serverQ_main self, $Cont C_cont, sshQ_ServerChannel ch) {
    B_Identity W_main_69 = ((B_Identity)$IdentityActorG_new());
    B_Iterable W_main_71 = (B_Iterable)B_SequenceD_listG_witness->W_Collection;
    B_Iterator N_iter = ((B_Iterator (*) ($WORD, B_list))((B_Iterable)(W_main_71))->$class->__iter__)(W_main_71, ((interop_serverQ_main)(self))->modes);
    return $PUSH_C((($Cont)interop_serverQ_L_30ContG_new(N_iter, W_main_69, ch, C_cont)));
}
#line 42 "src/interop_server.act"
$R interop_serverQ_mainD_mark_eofG_local (interop_serverQ_main self, $Cont C_cont, sshQ_ServerChannel ch) {
    B_Sequence W_main_88 = (B_Sequence)B_SequenceD_listG_witness;
    #line 43 "src/interop_server.act"
    ((B_NoneType (*) ($WORD, B_list, sshQ_ServerChannel))((B_Sequence)(W_main_88))->$class->append)(W_main_88, ((interop_serverQ_main)(self))->eofed, ch);
    return $R_CONT(C_cont, B_None);
}
#line 45 "src/interop_server.act"
$R interop_serverQ_mainD_saw_eofG_local (interop_serverQ_main self, $Cont C_cont, sshQ_ServerChannel ch) {
    B_Identity W_main_103 = ((B_Identity)$IdentityActorG_new());
    B_Iterable W_main_105 = (B_Iterable)B_SequenceD_listG_witness->W_Collection;
    B_Iterator N_4iter = ((B_Iterator (*) ($WORD, B_list))((B_Iterable)(W_main_105))->$class->__iter__)(W_main_105, ((interop_serverQ_main)(self))->eofed);
    return $PUSH_C((($Cont)interop_serverQ_L_42ContG_new(N_4iter, W_main_103, ch, C_cont)));
}
#line 51 "src/interop_server.act"
$R interop_serverQ_mainD_close_echoG_local (interop_serverQ_main self, $Cont C_cont, sshQ_ServerChannel ch) {
    #line 52 "src/interop_server.act"
    ((B_Msg (*) ($WORD, int64_t))((sshQ_ServerChannel)(ch))->$class->send_exit_status)(ch, 0LL);
    #line 53 "src/interop_server.act"
    ((B_Msg (*) ($WORD))((sshQ_ServerChannel)(ch))->$class->close)(ch);
    return $R_CONT(C_cont, B_None);
}
#line 55 "src/interop_server.act"
$R interop_serverQ_mainD_on_listenG_local (interop_serverQ_main self, $Cont C_cont, sshQ_Server s, B_str err) {
    if ($ISNOTNONE0(err)) {
        #line 57 "src/interop_server.act"
        ((B_NoneType (*) (B_tuple, B_str, B_str, B_bool, B_bool))B_print)($NEWTUPLE(2, to$str("LISTEN-ERROR"), ((B_str)err)), B_None, B_None, B_None, B_None);
        #line 58 "src/interop_server.act"
        ((B_Msg (*) ($WORD, int64_t))((B_Env)(((interop_serverQ_main)(self))->env))->$class->exit)(((interop_serverQ_main)(self))->env, 1LL);
        return $R_CONT(C_cont, B_None);
    }
    else {
        return $R_CONT((($Cont)interop_serverQ_L_46ContG_new(C_cont, s)), B_None);
    }
}
#line 63 "src/interop_server.act"
$R interop_serverQ_mainD_on_server_closeG_local (interop_serverQ_main self, $Cont C_cont, sshQ_Server s, B_str reason) {
    #line 64 "src/interop_server.act"
    ((B_NoneType (*) (B_tuple, B_str, B_str, B_bool, B_bool))B_print)($NEWTUPLE(2, to$str("SERVER-CLOSED"), reason), B_None, B_None, B_None, B_None);
    #line 65 "src/interop_server.act"
    ((B_Msg (*) ($WORD, int64_t))((B_Env)(((interop_serverQ_main)(self))->env))->$class->exit)(((interop_serverQ_main)(self))->env, 0LL);
    return $R_CONT(C_cont, B_None);
}
#line 67 "src/interop_server.act"
$R interop_serverQ_mainD_on_sessionG_local (interop_serverQ_main self, $Cont C_cont, sshQ_ServerSession sess) {
    #line 68 "src/interop_server.act"
    return $R_CONT(C_cont, B_None);
}
#line 70 "src/interop_server.act"
$R interop_serverQ_mainD_on_session_closeG_local (interop_serverQ_main self, $Cont C_cont, sshQ_ServerSession sess, B_str reason) {
    #line 71 "src/interop_server.act"
    return $R_CONT(C_cont, B_None);
}
#line 73 "src/interop_server.act"
$R interop_serverQ_mainD_on_authG_local (interop_serverQ_main self, $Cont C_cont, sshQ_ServerSession sess, sshQ_AuthRequest req) {
    B_Eq W_main_303 = ((B_Eq)$EqOptG_new(interop_serverQ_W_main_336));
    #line 74 "src/interop_server.act"
    if (((B_bool)$AND(B_bool, $AND(B_bool, ((B_bool (*) ($WORD, B_str, B_str))((B_Eq)(interop_serverQ_W_main_1090))->$class->__eq__)(interop_serverQ_W_main_1090, ((sshQ_AuthRequest)(req))->method, to$str("password")), ((B_bool (*) ($WORD, B_str, B_str))((B_Eq)(interop_serverQ_W_main_294))->$class->__eq__)(interop_serverQ_W_main_294, ((sshQ_AuthRequest)(req))->user, ((interop_serverQ_main)(self))->USER)), ((B_bool (*) ($WORD, B_str, B_str))((B_Eq)(W_main_303))->$class->__eq__)(W_main_303, ((sshQ_AuthRequest)(req))->password, ((interop_serverQ_main)(self))->PASS)))->val) {
        #line 75 "src/interop_server.act"
        ((B_Msg (*) ($WORD))((sshQ_ServerSession)(sess))->$class->accept_auth)(sess);
    }
    else {
        #line 77 "src/interop_server.act"
        ((B_Msg (*) ($WORD, B_str))((sshQ_ServerSession)(sess))->$class->reject_auth)(sess, to$str("invalid credentials"));
    }
    return $R_CONT(C_cont, B_None);
}
#line 79 "src/interop_server.act"
$R interop_serverQ_mainD_srv_on_dataG_local (interop_serverQ_main self, $Cont C_cont, sshQ_ServerChannel ch, B_bytes data) {
    return (($R (*) ($WORD, $Cont, sshQ_ServerChannel))((interop_serverQ_main)(self))->$class->mode_ofG_local)(self, (($Cont)interop_serverQ_L_58ContG_new(C_cont, data, ch, self)), ch);
}
#line 94 "src/interop_server.act"
$R interop_serverQ_mainD_srv_on_stderrG_local (interop_serverQ_main self, $Cont C_cont, sshQ_ServerChannel ch, B_bytes data) {
    #line 95 "src/interop_server.act"
    return $R_CONT(C_cont, B_None);
}
#line 97 "src/interop_server.act"
$R interop_serverQ_mainD_srv_on_closeG_local (interop_serverQ_main self, $Cont C_cont, sshQ_ServerChannel ch, B_str reason) {
    #line 98 "src/interop_server.act"
    return $R_CONT(C_cont, B_None);
}
#line 100 "src/interop_server.act"
$R interop_serverQ_mainD_on_channel_openG_local (interop_serverQ_main self, $Cont C_cont, sshQ_ServerSession sess) {
    return sshQ_ServerChannelG_newact((($Cont)interop_serverQ_L_60ContG_new(sess, C_cont)), sess, (($action)interop_serverQ_L_62actionG_new(self)), (($action)interop_serverQ_L_64actionG_new(self)), (($action)interop_serverQ_L_66actionG_new(self)));
}
#line 103 "src/interop_server.act"
$R interop_serverQ_mainD_on_execG_local (interop_serverQ_main self, $Cont C_cont, sshQ_ServerSession sess, sshQ_ServerChannel ch, B_str cmd) {
    return (($R (*) ($WORD, $Cont, sshQ_ServerChannel, B_str))((interop_serverQ_main)(self))->$class->set_modeG_local)(self, (($Cont)interop_serverQ_L_68ContG_new(cmd, ch, C_cont)), ch, to$str("exec"));
}
#line 116 "src/interop_server.act"
$R interop_serverQ_mainD_on_subsystemG_local (interop_serverQ_main self, $Cont C_cont, sshQ_ServerSession sess, sshQ_ServerChannel ch, B_str name) {
    if (((B_bool)((B_bool (*) ($WORD, B_str, B_str))((B_Eq)(interop_serverQ_W_main_1090))->$class->__eq__)(interop_serverQ_W_main_1090, name, to$str("echo")))->val) {
        return (($R (*) ($WORD, $Cont, sshQ_ServerChannel, B_str))((interop_serverQ_main)(self))->$class->set_modeG_local)(self, (($Cont)interop_serverQ_L_75ContG_new(ch, self, C_cont)), ch, to$str("echo"));
    }
    else {
        #line 123 "src/interop_server.act"
        ((B_Msg (*) ($WORD, B_str))((sshQ_ServerChannel)(ch))->$class->reject_request)(ch, to$str("unsupported subsystem"));
        return $R_CONT((($Cont)interop_serverQ_L_76ContG_new(C_cont)), B_None);
    }
}
B_Msg interop_serverQ_mainD_set_mode (interop_serverQ_main self, sshQ_ServerChannel ch, B_str mode) {
    return $ASYNC((($Actor)self), (($Cont)interop_serverQ_L_77procG_new(self, ch, mode)));
}
B_Msg interop_serverQ_mainD_mode_of (interop_serverQ_main self, sshQ_ServerChannel ch) {
    return ((B_Msg)$ASYNC((($Actor)self), (($Cont)interop_serverQ_L_78procG_new(self, ch))));
}
B_Msg interop_serverQ_mainD_mark_eof (interop_serverQ_main self, sshQ_ServerChannel ch) {
    return $ASYNC((($Actor)self), (($Cont)interop_serverQ_L_79procG_new(self, ch)));
}
B_Msg interop_serverQ_mainD_saw_eof (interop_serverQ_main self, sshQ_ServerChannel ch) {
    return ((B_Msg)$ASYNC((($Actor)self), (($Cont)interop_serverQ_L_80procG_new(self, ch))));
}
B_Msg interop_serverQ_mainD_close_echo (interop_serverQ_main self, sshQ_ServerChannel ch) {
    return $ASYNC((($Actor)self), (($Cont)interop_serverQ_L_81procG_new(self, ch)));
}
B_Msg interop_serverQ_mainD_on_listen (interop_serverQ_main self, sshQ_Server s, B_str err) {
    return $ASYNC((($Actor)self), (($Cont)interop_serverQ_L_82procG_new(self, s, err)));
}
B_Msg interop_serverQ_mainD_on_server_close (interop_serverQ_main self, sshQ_Server s, B_str reason) {
    return $ASYNC((($Actor)self), (($Cont)interop_serverQ_L_83procG_new(self, s, reason)));
}
B_Msg interop_serverQ_mainD_on_session (interop_serverQ_main self, sshQ_ServerSession sess) {
    return $ASYNC((($Actor)self), (($Cont)interop_serverQ_L_84procG_new(self, sess)));
}
B_Msg interop_serverQ_mainD_on_session_close (interop_serverQ_main self, sshQ_ServerSession sess, B_str reason) {
    return $ASYNC((($Actor)self), (($Cont)interop_serverQ_L_85procG_new(self, sess, reason)));
}
B_Msg interop_serverQ_mainD_on_auth (interop_serverQ_main self, sshQ_ServerSession sess, sshQ_AuthRequest req) {
    return $ASYNC((($Actor)self), (($Cont)interop_serverQ_L_86procG_new(self, sess, req)));
}
B_Msg interop_serverQ_mainD_srv_on_data (interop_serverQ_main self, sshQ_ServerChannel ch, B_bytes data) {
    return $ASYNC((($Actor)self), (($Cont)interop_serverQ_L_87procG_new(self, ch, data)));
}
B_Msg interop_serverQ_mainD_srv_on_stderr (interop_serverQ_main self, sshQ_ServerChannel ch, B_bytes data) {
    return $ASYNC((($Actor)self), (($Cont)interop_serverQ_L_88procG_new(self, ch, data)));
}
B_Msg interop_serverQ_mainD_srv_on_close (interop_serverQ_main self, sshQ_ServerChannel ch, B_str reason) {
    return $ASYNC((($Actor)self), (($Cont)interop_serverQ_L_89procG_new(self, ch, reason)));
}
B_Msg interop_serverQ_mainD_on_channel_open (interop_serverQ_main self, sshQ_ServerSession sess) {
    return $ASYNC((($Actor)self), (($Cont)interop_serverQ_L_90procG_new(self, sess)));
}
B_Msg interop_serverQ_mainD_on_exec (interop_serverQ_main self, sshQ_ServerSession sess, sshQ_ServerChannel ch, B_str cmd) {
    return $ASYNC((($Actor)self), (($Cont)interop_serverQ_L_91procG_new(self, sess, ch, cmd)));
}
B_Msg interop_serverQ_mainD_on_subsystem (interop_serverQ_main self, sshQ_ServerSession sess, sshQ_ServerChannel ch, B_str name) {
    return $ASYNC((($Actor)self), (($Cont)interop_serverQ_L_92procG_new(self, sess, ch, name)));
}
void interop_serverQ_mainD___serialize__ (interop_serverQ_main self, $Serial$state state) {
    $ActorG_methods.__serialize__(($Actor)self, state);
    $step_serialize(self->env, state);
    $step_serialize(self->USER, state);
    $step_serialize(self->PASS, state);
    $step_serialize(self->server, state);
    $step_serialize(self->modes, state);
    $step_serialize(self->eofed, state);
}
interop_serverQ_main interop_serverQ_mainD___deserialize__ (interop_serverQ_main self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct interop_serverQ_main));
            self->$class = &interop_serverQ_mainG_methods;
            return self;
        }
        self = $DNEW(interop_serverQ_main, state);
    }
    $ActorG_methods.__deserialize__(($Actor)self, state);
    self->env = $step_deserialize(state);
    self->USER = $step_deserialize(state);
    self->PASS = $step_deserialize(state);
    self->server = $step_deserialize(state);
    self->modes = $step_deserialize(state);
    self->eofed = $step_deserialize(state);
    return self;
}
void interop_serverQ_mainD_GCfinalizer (void *obj, void *cdata) {
    interop_serverQ_main self = (interop_serverQ_main)obj;
    self->$class->__cleanup__(self);
}
$R interop_serverQ_mainG_new($Cont G_1, B_Env G_2) {
    interop_serverQ_main $tmp = acton_malloc(sizeof(struct interop_serverQ_main));
    $tmp->$class = &interop_serverQ_mainG_methods;
    return interop_serverQ_mainG_methods.__init__($tmp, $CONSTCONT($tmp, G_1), G_2);
}
struct interop_serverQ_mainG_class interop_serverQ_mainG_methods;
$R interop_serverQ_mainG_newact ($Cont C_cont, B_Env env) {
    interop_serverQ_main G_act = $NEWACTOR(interop_serverQ_main);
    if ((void*)G_act->$class->__cleanup__ != (void*)$ActorD___cleanup__) $InstallFinalizer(G_act, interop_serverQ_mainD_GCfinalizer);
    return $AWAIT((($Cont)interop_serverQ_L_94ContG_new(C_cont, G_act)), $ASYNC((($Actor)G_act), (($Cont)interop_serverQ_L_95procG_new(G_act, env))));
}
int interop_serverQ_done$ = 0;
void interop_serverQ___init__ () {
    if (interop_serverQ_done$) return;
    interop_serverQ_done$ = 1;
    netQ___init__();
    sshQ___init__();
    {
        interop_serverQ_L_2ContG_methods.$GCINFO = "interop_serverQ_L_2Cont";
        interop_serverQ_L_2ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        interop_serverQ_L_2ContG_methods.__bool__ = (B_bool (*) (interop_serverQ_L_2Cont))B_valueG_methods.__bool__;
        interop_serverQ_L_2ContG_methods.__str__ = (B_str (*) (interop_serverQ_L_2Cont))B_valueG_methods.__str__;
        interop_serverQ_L_2ContG_methods.__repr__ = (B_str (*) (interop_serverQ_L_2Cont))B_valueG_methods.__repr__;
        interop_serverQ_L_2ContG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_2Cont, interop_serverQ_main, $Cont))interop_serverQ_L_2ContD___init__;
        interop_serverQ_L_2ContG_methods.__call__ = ($R (*) (interop_serverQ_L_2Cont, sshQ_Server))interop_serverQ_L_2ContD___call__;
        interop_serverQ_L_2ContG_methods.__serialize__ = interop_serverQ_L_2ContD___serialize__;
        interop_serverQ_L_2ContG_methods.__deserialize__ = interop_serverQ_L_2ContD___deserialize__;
        $register(&interop_serverQ_L_2ContG_methods);
    }
    {
        interop_serverQ_L_4actionG_methods.$GCINFO = "interop_serverQ_L_4action";
        interop_serverQ_L_4actionG_methods.$superclass = ($SuperG_class)&$actionG_methods;
        interop_serverQ_L_4actionG_methods.__bool__ = (B_bool (*) (interop_serverQ_L_4action))B_valueG_methods.__bool__;
        interop_serverQ_L_4actionG_methods.__str__ = (B_str (*) (interop_serverQ_L_4action))B_valueG_methods.__str__;
        interop_serverQ_L_4actionG_methods.__repr__ = (B_str (*) (interop_serverQ_L_4action))B_valueG_methods.__repr__;
        interop_serverQ_L_4actionG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_4action, interop_serverQ_main))interop_serverQ_L_4actionD___init__;
        interop_serverQ_L_4actionG_methods.__call__ = ($R (*) (interop_serverQ_L_4action, $Cont, sshQ_Server, B_str))interop_serverQ_L_4actionD___call__;
        interop_serverQ_L_4actionG_methods.__exec__ = ($R (*) (interop_serverQ_L_4action, $Cont, sshQ_Server, B_str))interop_serverQ_L_4actionD___exec__;
        interop_serverQ_L_4actionG_methods.__asyn__ = (B_Msg (*) (interop_serverQ_L_4action, sshQ_Server, B_str))interop_serverQ_L_4actionD___asyn__;
        interop_serverQ_L_4actionG_methods.__serialize__ = interop_serverQ_L_4actionD___serialize__;
        interop_serverQ_L_4actionG_methods.__deserialize__ = interop_serverQ_L_4actionD___deserialize__;
        $register(&interop_serverQ_L_4actionG_methods);
    }
    {
        interop_serverQ_L_6actionG_methods.$GCINFO = "interop_serverQ_L_6action";
        interop_serverQ_L_6actionG_methods.$superclass = ($SuperG_class)&$actionG_methods;
        interop_serverQ_L_6actionG_methods.__bool__ = (B_bool (*) (interop_serverQ_L_6action))B_valueG_methods.__bool__;
        interop_serverQ_L_6actionG_methods.__str__ = (B_str (*) (interop_serverQ_L_6action))B_valueG_methods.__str__;
        interop_serverQ_L_6actionG_methods.__repr__ = (B_str (*) (interop_serverQ_L_6action))B_valueG_methods.__repr__;
        interop_serverQ_L_6actionG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_6action, interop_serverQ_main))interop_serverQ_L_6actionD___init__;
        interop_serverQ_L_6actionG_methods.__call__ = ($R (*) (interop_serverQ_L_6action, $Cont, sshQ_Server, B_str))interop_serverQ_L_6actionD___call__;
        interop_serverQ_L_6actionG_methods.__exec__ = ($R (*) (interop_serverQ_L_6action, $Cont, sshQ_Server, B_str))interop_serverQ_L_6actionD___exec__;
        interop_serverQ_L_6actionG_methods.__asyn__ = (B_Msg (*) (interop_serverQ_L_6action, sshQ_Server, B_str))interop_serverQ_L_6actionD___asyn__;
        interop_serverQ_L_6actionG_methods.__serialize__ = interop_serverQ_L_6actionD___serialize__;
        interop_serverQ_L_6actionG_methods.__deserialize__ = interop_serverQ_L_6actionD___deserialize__;
        $register(&interop_serverQ_L_6actionG_methods);
    }
    {
        interop_serverQ_L_8actionG_methods.$GCINFO = "interop_serverQ_L_8action";
        interop_serverQ_L_8actionG_methods.$superclass = ($SuperG_class)&$actionG_methods;
        interop_serverQ_L_8actionG_methods.__bool__ = (B_bool (*) (interop_serverQ_L_8action))B_valueG_methods.__bool__;
        interop_serverQ_L_8actionG_methods.__str__ = (B_str (*) (interop_serverQ_L_8action))B_valueG_methods.__str__;
        interop_serverQ_L_8actionG_methods.__repr__ = (B_str (*) (interop_serverQ_L_8action))B_valueG_methods.__repr__;
        interop_serverQ_L_8actionG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_8action, interop_serverQ_main))interop_serverQ_L_8actionD___init__;
        interop_serverQ_L_8actionG_methods.__call__ = ($R (*) (interop_serverQ_L_8action, $Cont, sshQ_ServerSession))interop_serverQ_L_8actionD___call__;
        interop_serverQ_L_8actionG_methods.__exec__ = ($R (*) (interop_serverQ_L_8action, $Cont, sshQ_ServerSession))interop_serverQ_L_8actionD___exec__;
        interop_serverQ_L_8actionG_methods.__asyn__ = (B_Msg (*) (interop_serverQ_L_8action, sshQ_ServerSession))interop_serverQ_L_8actionD___asyn__;
        interop_serverQ_L_8actionG_methods.__serialize__ = interop_serverQ_L_8actionD___serialize__;
        interop_serverQ_L_8actionG_methods.__deserialize__ = interop_serverQ_L_8actionD___deserialize__;
        $register(&interop_serverQ_L_8actionG_methods);
    }
    {
        interop_serverQ_L_10actionG_methods.$GCINFO = "interop_serverQ_L_10action";
        interop_serverQ_L_10actionG_methods.$superclass = ($SuperG_class)&$actionG_methods;
        interop_serverQ_L_10actionG_methods.__bool__ = (B_bool (*) (interop_serverQ_L_10action))B_valueG_methods.__bool__;
        interop_serverQ_L_10actionG_methods.__str__ = (B_str (*) (interop_serverQ_L_10action))B_valueG_methods.__str__;
        interop_serverQ_L_10actionG_methods.__repr__ = (B_str (*) (interop_serverQ_L_10action))B_valueG_methods.__repr__;
        interop_serverQ_L_10actionG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_10action, interop_serverQ_main))interop_serverQ_L_10actionD___init__;
        interop_serverQ_L_10actionG_methods.__call__ = ($R (*) (interop_serverQ_L_10action, $Cont, sshQ_ServerSession, sshQ_AuthRequest))interop_serverQ_L_10actionD___call__;
        interop_serverQ_L_10actionG_methods.__exec__ = ($R (*) (interop_serverQ_L_10action, $Cont, sshQ_ServerSession, sshQ_AuthRequest))interop_serverQ_L_10actionD___exec__;
        interop_serverQ_L_10actionG_methods.__asyn__ = (B_Msg (*) (interop_serverQ_L_10action, sshQ_ServerSession, sshQ_AuthRequest))interop_serverQ_L_10actionD___asyn__;
        interop_serverQ_L_10actionG_methods.__serialize__ = interop_serverQ_L_10actionD___serialize__;
        interop_serverQ_L_10actionG_methods.__deserialize__ = interop_serverQ_L_10actionD___deserialize__;
        $register(&interop_serverQ_L_10actionG_methods);
    }
    {
        interop_serverQ_L_12actionG_methods.$GCINFO = "interop_serverQ_L_12action";
        interop_serverQ_L_12actionG_methods.$superclass = ($SuperG_class)&$actionG_methods;
        interop_serverQ_L_12actionG_methods.__bool__ = (B_bool (*) (interop_serverQ_L_12action))B_valueG_methods.__bool__;
        interop_serverQ_L_12actionG_methods.__str__ = (B_str (*) (interop_serverQ_L_12action))B_valueG_methods.__str__;
        interop_serverQ_L_12actionG_methods.__repr__ = (B_str (*) (interop_serverQ_L_12action))B_valueG_methods.__repr__;
        interop_serverQ_L_12actionG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_12action, interop_serverQ_main))interop_serverQ_L_12actionD___init__;
        interop_serverQ_L_12actionG_methods.__call__ = ($R (*) (interop_serverQ_L_12action, $Cont, sshQ_ServerSession))interop_serverQ_L_12actionD___call__;
        interop_serverQ_L_12actionG_methods.__exec__ = ($R (*) (interop_serverQ_L_12action, $Cont, sshQ_ServerSession))interop_serverQ_L_12actionD___exec__;
        interop_serverQ_L_12actionG_methods.__asyn__ = (B_Msg (*) (interop_serverQ_L_12action, sshQ_ServerSession))interop_serverQ_L_12actionD___asyn__;
        interop_serverQ_L_12actionG_methods.__serialize__ = interop_serverQ_L_12actionD___serialize__;
        interop_serverQ_L_12actionG_methods.__deserialize__ = interop_serverQ_L_12actionD___deserialize__;
        $register(&interop_serverQ_L_12actionG_methods);
    }
    {
        interop_serverQ_L_14actionG_methods.$GCINFO = "interop_serverQ_L_14action";
        interop_serverQ_L_14actionG_methods.$superclass = ($SuperG_class)&$actionG_methods;
        interop_serverQ_L_14actionG_methods.__bool__ = (B_bool (*) (interop_serverQ_L_14action))B_valueG_methods.__bool__;
        interop_serverQ_L_14actionG_methods.__str__ = (B_str (*) (interop_serverQ_L_14action))B_valueG_methods.__str__;
        interop_serverQ_L_14actionG_methods.__repr__ = (B_str (*) (interop_serverQ_L_14action))B_valueG_methods.__repr__;
        interop_serverQ_L_14actionG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_14action, interop_serverQ_main))interop_serverQ_L_14actionD___init__;
        interop_serverQ_L_14actionG_methods.__call__ = ($R (*) (interop_serverQ_L_14action, $Cont, sshQ_ServerSession, sshQ_ServerChannel, B_str))interop_serverQ_L_14actionD___call__;
        interop_serverQ_L_14actionG_methods.__exec__ = ($R (*) (interop_serverQ_L_14action, $Cont, sshQ_ServerSession, sshQ_ServerChannel, B_str))interop_serverQ_L_14actionD___exec__;
        interop_serverQ_L_14actionG_methods.__asyn__ = (B_Msg (*) (interop_serverQ_L_14action, sshQ_ServerSession, sshQ_ServerChannel, B_str))interop_serverQ_L_14actionD___asyn__;
        interop_serverQ_L_14actionG_methods.__serialize__ = interop_serverQ_L_14actionD___serialize__;
        interop_serverQ_L_14actionG_methods.__deserialize__ = interop_serverQ_L_14actionD___deserialize__;
        $register(&interop_serverQ_L_14actionG_methods);
    }
    {
        interop_serverQ_L_16actionG_methods.$GCINFO = "interop_serverQ_L_16action";
        interop_serverQ_L_16actionG_methods.$superclass = ($SuperG_class)&$actionG_methods;
        interop_serverQ_L_16actionG_methods.__bool__ = (B_bool (*) (interop_serverQ_L_16action))B_valueG_methods.__bool__;
        interop_serverQ_L_16actionG_methods.__str__ = (B_str (*) (interop_serverQ_L_16action))B_valueG_methods.__str__;
        interop_serverQ_L_16actionG_methods.__repr__ = (B_str (*) (interop_serverQ_L_16action))B_valueG_methods.__repr__;
        interop_serverQ_L_16actionG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_16action, interop_serverQ_main))interop_serverQ_L_16actionD___init__;
        interop_serverQ_L_16actionG_methods.__call__ = ($R (*) (interop_serverQ_L_16action, $Cont, sshQ_ServerSession, sshQ_ServerChannel, B_str))interop_serverQ_L_16actionD___call__;
        interop_serverQ_L_16actionG_methods.__exec__ = ($R (*) (interop_serverQ_L_16action, $Cont, sshQ_ServerSession, sshQ_ServerChannel, B_str))interop_serverQ_L_16actionD___exec__;
        interop_serverQ_L_16actionG_methods.__asyn__ = (B_Msg (*) (interop_serverQ_L_16action, sshQ_ServerSession, sshQ_ServerChannel, B_str))interop_serverQ_L_16actionD___asyn__;
        interop_serverQ_L_16actionG_methods.__serialize__ = interop_serverQ_L_16actionD___serialize__;
        interop_serverQ_L_16actionG_methods.__deserialize__ = interop_serverQ_L_16actionD___deserialize__;
        $register(&interop_serverQ_L_16actionG_methods);
    }
    {
        interop_serverQ_L_18actionG_methods.$GCINFO = "interop_serverQ_L_18action";
        interop_serverQ_L_18actionG_methods.$superclass = ($SuperG_class)&$actionG_methods;
        interop_serverQ_L_18actionG_methods.__bool__ = (B_bool (*) (interop_serverQ_L_18action))B_valueG_methods.__bool__;
        interop_serverQ_L_18actionG_methods.__str__ = (B_str (*) (interop_serverQ_L_18action))B_valueG_methods.__str__;
        interop_serverQ_L_18actionG_methods.__repr__ = (B_str (*) (interop_serverQ_L_18action))B_valueG_methods.__repr__;
        interop_serverQ_L_18actionG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_18action, interop_serverQ_main))interop_serverQ_L_18actionD___init__;
        interop_serverQ_L_18actionG_methods.__call__ = ($R (*) (interop_serverQ_L_18action, $Cont, sshQ_ServerSession, B_str))interop_serverQ_L_18actionD___call__;
        interop_serverQ_L_18actionG_methods.__exec__ = ($R (*) (interop_serverQ_L_18action, $Cont, sshQ_ServerSession, B_str))interop_serverQ_L_18actionD___exec__;
        interop_serverQ_L_18actionG_methods.__asyn__ = (B_Msg (*) (interop_serverQ_L_18action, sshQ_ServerSession, B_str))interop_serverQ_L_18actionD___asyn__;
        interop_serverQ_L_18actionG_methods.__serialize__ = interop_serverQ_L_18actionD___serialize__;
        interop_serverQ_L_18actionG_methods.__deserialize__ = interop_serverQ_L_18actionD___deserialize__;
        $register(&interop_serverQ_L_18actionG_methods);
    }
    {
        interop_serverQ_L_22ContG_methods.$GCINFO = "interop_serverQ_L_22Cont";
        interop_serverQ_L_22ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        interop_serverQ_L_22ContG_methods.__bool__ = (B_bool (*) (interop_serverQ_L_22Cont))B_valueG_methods.__bool__;
        interop_serverQ_L_22ContG_methods.__str__ = (B_str (*) (interop_serverQ_L_22Cont))B_valueG_methods.__str__;
        interop_serverQ_L_22ContG_methods.__repr__ = (B_str (*) (interop_serverQ_L_22Cont))B_valueG_methods.__repr__;
        interop_serverQ_L_22ContG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_22Cont, $Cont))interop_serverQ_L_22ContD___init__;
        interop_serverQ_L_22ContG_methods.__call__ = ($R (*) (interop_serverQ_L_22Cont, B_NoneType))interop_serverQ_L_22ContD___call__;
        interop_serverQ_L_22ContG_methods.__serialize__ = interop_serverQ_L_22ContD___serialize__;
        interop_serverQ_L_22ContG_methods.__deserialize__ = interop_serverQ_L_22ContD___deserialize__;
        $register(&interop_serverQ_L_22ContG_methods);
    }
    {
        interop_serverQ_L_25ContG_methods.$GCINFO = "interop_serverQ_L_25Cont";
        interop_serverQ_L_25ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        interop_serverQ_L_25ContG_methods.__bool__ = (B_bool (*) (interop_serverQ_L_25Cont))B_valueG_methods.__bool__;
        interop_serverQ_L_25ContG_methods.__str__ = (B_str (*) (interop_serverQ_L_25Cont))B_valueG_methods.__str__;
        interop_serverQ_L_25ContG_methods.__repr__ = (B_str (*) (interop_serverQ_L_25Cont))B_valueG_methods.__repr__;
        interop_serverQ_L_25ContG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_25Cont, B_Iterator, B_Identity, sshQ_ServerChannel, $Cont))interop_serverQ_L_25ContD___init__;
        interop_serverQ_L_25ContG_methods.__call__ = ($R (*) (interop_serverQ_L_25Cont, B_NoneType))interop_serverQ_L_25ContD___call__;
        interop_serverQ_L_25ContG_methods.__serialize__ = interop_serverQ_L_25ContD___serialize__;
        interop_serverQ_L_25ContG_methods.__deserialize__ = interop_serverQ_L_25ContD___deserialize__;
        $register(&interop_serverQ_L_25ContG_methods);
    }
    {
        interop_serverQ_L_26ContG_methods.$GCINFO = "interop_serverQ_L_26Cont";
        interop_serverQ_L_26ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        interop_serverQ_L_26ContG_methods.__bool__ = (B_bool (*) (interop_serverQ_L_26Cont))B_valueG_methods.__bool__;
        interop_serverQ_L_26ContG_methods.__str__ = (B_str (*) (interop_serverQ_L_26Cont))B_valueG_methods.__str__;
        interop_serverQ_L_26ContG_methods.__repr__ = (B_str (*) (interop_serverQ_L_26Cont))B_valueG_methods.__repr__;
        interop_serverQ_L_26ContG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_26Cont, B_Iterator, B_Identity, sshQ_ServerChannel, $Cont))interop_serverQ_L_26ContD___init__;
        interop_serverQ_L_26ContG_methods.__call__ = ($R (*) (interop_serverQ_L_26Cont, B_NoneType))interop_serverQ_L_26ContD___call__;
        interop_serverQ_L_26ContG_methods.__serialize__ = interop_serverQ_L_26ContD___serialize__;
        interop_serverQ_L_26ContG_methods.__deserialize__ = interop_serverQ_L_26ContD___deserialize__;
        $register(&interop_serverQ_L_26ContG_methods);
    }
    {
        interop_serverQ_L_27ContG_methods.$GCINFO = "interop_serverQ_L_27Cont";
        interop_serverQ_L_27ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        interop_serverQ_L_27ContG_methods.__bool__ = (B_bool (*) (interop_serverQ_L_27Cont))B_valueG_methods.__bool__;
        interop_serverQ_L_27ContG_methods.__str__ = (B_str (*) (interop_serverQ_L_27Cont))B_valueG_methods.__str__;
        interop_serverQ_L_27ContG_methods.__repr__ = (B_str (*) (interop_serverQ_L_27Cont))B_valueG_methods.__repr__;
        interop_serverQ_L_27ContG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_27Cont, $Cont))interop_serverQ_L_27ContD___init__;
        interop_serverQ_L_27ContG_methods.__call__ = ($R (*) (interop_serverQ_L_27Cont, B_NoneType))interop_serverQ_L_27ContD___call__;
        interop_serverQ_L_27ContG_methods.__serialize__ = interop_serverQ_L_27ContD___serialize__;
        interop_serverQ_L_27ContG_methods.__deserialize__ = interop_serverQ_L_27ContD___deserialize__;
        $register(&interop_serverQ_L_27ContG_methods);
    }
    {
        interop_serverQ_L_28ContG_methods.$GCINFO = "interop_serverQ_L_28Cont";
        interop_serverQ_L_28ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        interop_serverQ_L_28ContG_methods.__bool__ = (B_bool (*) (interop_serverQ_L_28Cont))B_valueG_methods.__bool__;
        interop_serverQ_L_28ContG_methods.__str__ = (B_str (*) (interop_serverQ_L_28Cont))B_valueG_methods.__str__;
        interop_serverQ_L_28ContG_methods.__repr__ = (B_str (*) (interop_serverQ_L_28Cont))B_valueG_methods.__repr__;
        interop_serverQ_L_28ContG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_28Cont, $Cont))interop_serverQ_L_28ContD___init__;
        interop_serverQ_L_28ContG_methods.__call__ = ($R (*) (interop_serverQ_L_28Cont, B_NoneType))interop_serverQ_L_28ContD___call__;
        interop_serverQ_L_28ContG_methods.__serialize__ = interop_serverQ_L_28ContD___serialize__;
        interop_serverQ_L_28ContG_methods.__deserialize__ = interop_serverQ_L_28ContD___deserialize__;
        $register(&interop_serverQ_L_28ContG_methods);
    }
    {
        interop_serverQ_L_29ContG_methods.$GCINFO = "interop_serverQ_L_29Cont";
        interop_serverQ_L_29ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        interop_serverQ_L_29ContG_methods.__bool__ = (B_bool (*) (interop_serverQ_L_29Cont))B_valueG_methods.__bool__;
        interop_serverQ_L_29ContG_methods.__str__ = (B_str (*) (interop_serverQ_L_29Cont))B_valueG_methods.__str__;
        interop_serverQ_L_29ContG_methods.__repr__ = (B_str (*) (interop_serverQ_L_29Cont))B_valueG_methods.__repr__;
        interop_serverQ_L_29ContG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_29Cont, $Cont))interop_serverQ_L_29ContD___init__;
        interop_serverQ_L_29ContG_methods.__call__ = ($R (*) (interop_serverQ_L_29Cont, B_NoneType))interop_serverQ_L_29ContD___call__;
        interop_serverQ_L_29ContG_methods.__serialize__ = interop_serverQ_L_29ContD___serialize__;
        interop_serverQ_L_29ContG_methods.__deserialize__ = interop_serverQ_L_29ContD___deserialize__;
        $register(&interop_serverQ_L_29ContG_methods);
    }
    {
        interop_serverQ_L_30ContG_methods.$GCINFO = "interop_serverQ_L_30Cont";
        interop_serverQ_L_30ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        interop_serverQ_L_30ContG_methods.__bool__ = (B_bool (*) (interop_serverQ_L_30Cont))B_valueG_methods.__bool__;
        interop_serverQ_L_30ContG_methods.__str__ = (B_str (*) (interop_serverQ_L_30Cont))B_valueG_methods.__str__;
        interop_serverQ_L_30ContG_methods.__repr__ = (B_str (*) (interop_serverQ_L_30Cont))B_valueG_methods.__repr__;
        interop_serverQ_L_30ContG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_30Cont, B_Iterator, B_Identity, sshQ_ServerChannel, $Cont))interop_serverQ_L_30ContD___init__;
        interop_serverQ_L_30ContG_methods.__call__ = ($R (*) (interop_serverQ_L_30Cont, B_bool))interop_serverQ_L_30ContD___call__;
        interop_serverQ_L_30ContG_methods.__serialize__ = interop_serverQ_L_30ContD___serialize__;
        interop_serverQ_L_30ContG_methods.__deserialize__ = interop_serverQ_L_30ContD___deserialize__;
        $register(&interop_serverQ_L_30ContG_methods);
    }
    {
        interop_serverQ_L_34ContG_methods.$GCINFO = "interop_serverQ_L_34Cont";
        interop_serverQ_L_34ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        interop_serverQ_L_34ContG_methods.__bool__ = (B_bool (*) (interop_serverQ_L_34Cont))B_valueG_methods.__bool__;
        interop_serverQ_L_34ContG_methods.__str__ = (B_str (*) (interop_serverQ_L_34Cont))B_valueG_methods.__str__;
        interop_serverQ_L_34ContG_methods.__repr__ = (B_str (*) (interop_serverQ_L_34Cont))B_valueG_methods.__repr__;
        interop_serverQ_L_34ContG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_34Cont, $Cont))interop_serverQ_L_34ContD___init__;
        interop_serverQ_L_34ContG_methods.__call__ = ($R (*) (interop_serverQ_L_34Cont, B_NoneType))interop_serverQ_L_34ContD___call__;
        interop_serverQ_L_34ContG_methods.__serialize__ = interop_serverQ_L_34ContD___serialize__;
        interop_serverQ_L_34ContG_methods.__deserialize__ = interop_serverQ_L_34ContD___deserialize__;
        $register(&interop_serverQ_L_34ContG_methods);
    }
    {
        interop_serverQ_L_37ContG_methods.$GCINFO = "interop_serverQ_L_37Cont";
        interop_serverQ_L_37ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        interop_serverQ_L_37ContG_methods.__bool__ = (B_bool (*) (interop_serverQ_L_37Cont))B_valueG_methods.__bool__;
        interop_serverQ_L_37ContG_methods.__str__ = (B_str (*) (interop_serverQ_L_37Cont))B_valueG_methods.__str__;
        interop_serverQ_L_37ContG_methods.__repr__ = (B_str (*) (interop_serverQ_L_37Cont))B_valueG_methods.__repr__;
        interop_serverQ_L_37ContG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_37Cont, B_Iterator, B_Identity, sshQ_ServerChannel, $Cont))interop_serverQ_L_37ContD___init__;
        interop_serverQ_L_37ContG_methods.__call__ = ($R (*) (interop_serverQ_L_37Cont, B_NoneType))interop_serverQ_L_37ContD___call__;
        interop_serverQ_L_37ContG_methods.__serialize__ = interop_serverQ_L_37ContD___serialize__;
        interop_serverQ_L_37ContG_methods.__deserialize__ = interop_serverQ_L_37ContD___deserialize__;
        $register(&interop_serverQ_L_37ContG_methods);
    }
    {
        interop_serverQ_L_38ContG_methods.$GCINFO = "interop_serverQ_L_38Cont";
        interop_serverQ_L_38ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        interop_serverQ_L_38ContG_methods.__bool__ = (B_bool (*) (interop_serverQ_L_38Cont))B_valueG_methods.__bool__;
        interop_serverQ_L_38ContG_methods.__str__ = (B_str (*) (interop_serverQ_L_38Cont))B_valueG_methods.__str__;
        interop_serverQ_L_38ContG_methods.__repr__ = (B_str (*) (interop_serverQ_L_38Cont))B_valueG_methods.__repr__;
        interop_serverQ_L_38ContG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_38Cont, B_Iterator, B_Identity, sshQ_ServerChannel, $Cont))interop_serverQ_L_38ContD___init__;
        interop_serverQ_L_38ContG_methods.__call__ = ($R (*) (interop_serverQ_L_38Cont, B_NoneType))interop_serverQ_L_38ContD___call__;
        interop_serverQ_L_38ContG_methods.__serialize__ = interop_serverQ_L_38ContD___serialize__;
        interop_serverQ_L_38ContG_methods.__deserialize__ = interop_serverQ_L_38ContD___deserialize__;
        $register(&interop_serverQ_L_38ContG_methods);
    }
    {
        interop_serverQ_L_39ContG_methods.$GCINFO = "interop_serverQ_L_39Cont";
        interop_serverQ_L_39ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        interop_serverQ_L_39ContG_methods.__bool__ = (B_bool (*) (interop_serverQ_L_39Cont))B_valueG_methods.__bool__;
        interop_serverQ_L_39ContG_methods.__str__ = (B_str (*) (interop_serverQ_L_39Cont))B_valueG_methods.__str__;
        interop_serverQ_L_39ContG_methods.__repr__ = (B_str (*) (interop_serverQ_L_39Cont))B_valueG_methods.__repr__;
        interop_serverQ_L_39ContG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_39Cont, $Cont))interop_serverQ_L_39ContD___init__;
        interop_serverQ_L_39ContG_methods.__call__ = ($R (*) (interop_serverQ_L_39Cont, B_NoneType))interop_serverQ_L_39ContD___call__;
        interop_serverQ_L_39ContG_methods.__serialize__ = interop_serverQ_L_39ContD___serialize__;
        interop_serverQ_L_39ContG_methods.__deserialize__ = interop_serverQ_L_39ContD___deserialize__;
        $register(&interop_serverQ_L_39ContG_methods);
    }
    {
        interop_serverQ_L_40ContG_methods.$GCINFO = "interop_serverQ_L_40Cont";
        interop_serverQ_L_40ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        interop_serverQ_L_40ContG_methods.__bool__ = (B_bool (*) (interop_serverQ_L_40Cont))B_valueG_methods.__bool__;
        interop_serverQ_L_40ContG_methods.__str__ = (B_str (*) (interop_serverQ_L_40Cont))B_valueG_methods.__str__;
        interop_serverQ_L_40ContG_methods.__repr__ = (B_str (*) (interop_serverQ_L_40Cont))B_valueG_methods.__repr__;
        interop_serverQ_L_40ContG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_40Cont, $Cont))interop_serverQ_L_40ContD___init__;
        interop_serverQ_L_40ContG_methods.__call__ = ($R (*) (interop_serverQ_L_40Cont, B_NoneType))interop_serverQ_L_40ContD___call__;
        interop_serverQ_L_40ContG_methods.__serialize__ = interop_serverQ_L_40ContD___serialize__;
        interop_serverQ_L_40ContG_methods.__deserialize__ = interop_serverQ_L_40ContD___deserialize__;
        $register(&interop_serverQ_L_40ContG_methods);
    }
    {
        interop_serverQ_L_41ContG_methods.$GCINFO = "interop_serverQ_L_41Cont";
        interop_serverQ_L_41ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        interop_serverQ_L_41ContG_methods.__bool__ = (B_bool (*) (interop_serverQ_L_41Cont))B_valueG_methods.__bool__;
        interop_serverQ_L_41ContG_methods.__str__ = (B_str (*) (interop_serverQ_L_41Cont))B_valueG_methods.__str__;
        interop_serverQ_L_41ContG_methods.__repr__ = (B_str (*) (interop_serverQ_L_41Cont))B_valueG_methods.__repr__;
        interop_serverQ_L_41ContG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_41Cont, $Cont))interop_serverQ_L_41ContD___init__;
        interop_serverQ_L_41ContG_methods.__call__ = ($R (*) (interop_serverQ_L_41Cont, B_NoneType))interop_serverQ_L_41ContD___call__;
        interop_serverQ_L_41ContG_methods.__serialize__ = interop_serverQ_L_41ContD___serialize__;
        interop_serverQ_L_41ContG_methods.__deserialize__ = interop_serverQ_L_41ContD___deserialize__;
        $register(&interop_serverQ_L_41ContG_methods);
    }
    {
        interop_serverQ_L_42ContG_methods.$GCINFO = "interop_serverQ_L_42Cont";
        interop_serverQ_L_42ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        interop_serverQ_L_42ContG_methods.__bool__ = (B_bool (*) (interop_serverQ_L_42Cont))B_valueG_methods.__bool__;
        interop_serverQ_L_42ContG_methods.__str__ = (B_str (*) (interop_serverQ_L_42Cont))B_valueG_methods.__str__;
        interop_serverQ_L_42ContG_methods.__repr__ = (B_str (*) (interop_serverQ_L_42Cont))B_valueG_methods.__repr__;
        interop_serverQ_L_42ContG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_42Cont, B_Iterator, B_Identity, sshQ_ServerChannel, $Cont))interop_serverQ_L_42ContD___init__;
        interop_serverQ_L_42ContG_methods.__call__ = ($R (*) (interop_serverQ_L_42Cont, B_bool))interop_serverQ_L_42ContD___call__;
        interop_serverQ_L_42ContG_methods.__serialize__ = interop_serverQ_L_42ContD___serialize__;
        interop_serverQ_L_42ContG_methods.__deserialize__ = interop_serverQ_L_42ContD___deserialize__;
        $register(&interop_serverQ_L_42ContG_methods);
    }
    {
        interop_serverQ_L_45ContG_methods.$GCINFO = "interop_serverQ_L_45Cont";
        interop_serverQ_L_45ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        interop_serverQ_L_45ContG_methods.__bool__ = (B_bool (*) (interop_serverQ_L_45Cont))B_valueG_methods.__bool__;
        interop_serverQ_L_45ContG_methods.__str__ = (B_str (*) (interop_serverQ_L_45Cont))B_valueG_methods.__str__;
        interop_serverQ_L_45ContG_methods.__repr__ = (B_str (*) (interop_serverQ_L_45Cont))B_valueG_methods.__repr__;
        interop_serverQ_L_45ContG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_45Cont, $Cont))interop_serverQ_L_45ContD___init__;
        interop_serverQ_L_45ContG_methods.__call__ = ($R (*) (interop_serverQ_L_45Cont, B_u16))interop_serverQ_L_45ContD___call__;
        interop_serverQ_L_45ContG_methods.__serialize__ = interop_serverQ_L_45ContD___serialize__;
        interop_serverQ_L_45ContG_methods.__deserialize__ = interop_serverQ_L_45ContD___deserialize__;
        $register(&interop_serverQ_L_45ContG_methods);
    }
    {
        interop_serverQ_L_46ContG_methods.$GCINFO = "interop_serverQ_L_46Cont";
        interop_serverQ_L_46ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        interop_serverQ_L_46ContG_methods.__bool__ = (B_bool (*) (interop_serverQ_L_46Cont))B_valueG_methods.__bool__;
        interop_serverQ_L_46ContG_methods.__str__ = (B_str (*) (interop_serverQ_L_46Cont))B_valueG_methods.__str__;
        interop_serverQ_L_46ContG_methods.__repr__ = (B_str (*) (interop_serverQ_L_46Cont))B_valueG_methods.__repr__;
        interop_serverQ_L_46ContG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_46Cont, $Cont, sshQ_Server))interop_serverQ_L_46ContD___init__;
        interop_serverQ_L_46ContG_methods.__call__ = ($R (*) (interop_serverQ_L_46Cont, B_NoneType))interop_serverQ_L_46ContD___call__;
        interop_serverQ_L_46ContG_methods.__serialize__ = interop_serverQ_L_46ContD___serialize__;
        interop_serverQ_L_46ContG_methods.__deserialize__ = interop_serverQ_L_46ContD___deserialize__;
        $register(&interop_serverQ_L_46ContG_methods);
    }
    {
        interop_serverQ_L_50ContG_methods.$GCINFO = "interop_serverQ_L_50Cont";
        interop_serverQ_L_50ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        interop_serverQ_L_50ContG_methods.__bool__ = (B_bool (*) (interop_serverQ_L_50Cont))B_valueG_methods.__bool__;
        interop_serverQ_L_50ContG_methods.__str__ = (B_str (*) (interop_serverQ_L_50Cont))B_valueG_methods.__str__;
        interop_serverQ_L_50ContG_methods.__repr__ = (B_str (*) (interop_serverQ_L_50Cont))B_valueG_methods.__repr__;
        interop_serverQ_L_50ContG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_50Cont, $Cont))interop_serverQ_L_50ContD___init__;
        interop_serverQ_L_50ContG_methods.__call__ = ($R (*) (interop_serverQ_L_50Cont, B_NoneType))interop_serverQ_L_50ContD___call__;
        interop_serverQ_L_50ContG_methods.__serialize__ = interop_serverQ_L_50ContD___serialize__;
        interop_serverQ_L_50ContG_methods.__deserialize__ = interop_serverQ_L_50ContD___deserialize__;
        $register(&interop_serverQ_L_50ContG_methods);
    }
    {
        interop_serverQ_L_53ContG_methods.$GCINFO = "interop_serverQ_L_53Cont";
        interop_serverQ_L_53ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        interop_serverQ_L_53ContG_methods.__bool__ = (B_bool (*) (interop_serverQ_L_53Cont))B_valueG_methods.__bool__;
        interop_serverQ_L_53ContG_methods.__str__ = (B_str (*) (interop_serverQ_L_53Cont))B_valueG_methods.__str__;
        interop_serverQ_L_53ContG_methods.__repr__ = (B_str (*) (interop_serverQ_L_53Cont))B_valueG_methods.__repr__;
        interop_serverQ_L_53ContG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_53Cont, $Cont))interop_serverQ_L_53ContD___init__;
        interop_serverQ_L_53ContG_methods.__call__ = ($R (*) (interop_serverQ_L_53Cont, B_NoneType))interop_serverQ_L_53ContD___call__;
        interop_serverQ_L_53ContG_methods.__serialize__ = interop_serverQ_L_53ContD___serialize__;
        interop_serverQ_L_53ContG_methods.__deserialize__ = interop_serverQ_L_53ContD___deserialize__;
        $register(&interop_serverQ_L_53ContG_methods);
    }
    {
        interop_serverQ_L_54ContG_methods.$GCINFO = "interop_serverQ_L_54Cont";
        interop_serverQ_L_54ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        interop_serverQ_L_54ContG_methods.__bool__ = (B_bool (*) (interop_serverQ_L_54Cont))B_valueG_methods.__bool__;
        interop_serverQ_L_54ContG_methods.__str__ = (B_str (*) (interop_serverQ_L_54Cont))B_valueG_methods.__str__;
        interop_serverQ_L_54ContG_methods.__repr__ = (B_str (*) (interop_serverQ_L_54Cont))B_valueG_methods.__repr__;
        interop_serverQ_L_54ContG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_54Cont, $Cont))interop_serverQ_L_54ContD___init__;
        interop_serverQ_L_54ContG_methods.__call__ = ($R (*) (interop_serverQ_L_54Cont, B_NoneType))interop_serverQ_L_54ContD___call__;
        interop_serverQ_L_54ContG_methods.__serialize__ = interop_serverQ_L_54ContD___serialize__;
        interop_serverQ_L_54ContG_methods.__deserialize__ = interop_serverQ_L_54ContD___deserialize__;
        $register(&interop_serverQ_L_54ContG_methods);
    }
    {
        interop_serverQ_L_55ContG_methods.$GCINFO = "interop_serverQ_L_55Cont";
        interop_serverQ_L_55ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        interop_serverQ_L_55ContG_methods.__bool__ = (B_bool (*) (interop_serverQ_L_55Cont))B_valueG_methods.__bool__;
        interop_serverQ_L_55ContG_methods.__str__ = (B_str (*) (interop_serverQ_L_55Cont))B_valueG_methods.__str__;
        interop_serverQ_L_55ContG_methods.__repr__ = (B_str (*) (interop_serverQ_L_55Cont))B_valueG_methods.__repr__;
        interop_serverQ_L_55ContG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_55Cont, interop_serverQ_main, sshQ_ServerChannel, $Cont))interop_serverQ_L_55ContD___init__;
        interop_serverQ_L_55ContG_methods.__call__ = ($R (*) (interop_serverQ_L_55Cont, B_str))interop_serverQ_L_55ContD___call__;
        interop_serverQ_L_55ContG_methods.__serialize__ = interop_serverQ_L_55ContD___serialize__;
        interop_serverQ_L_55ContG_methods.__deserialize__ = interop_serverQ_L_55ContD___deserialize__;
        $register(&interop_serverQ_L_55ContG_methods);
    }
    {
        interop_serverQ_L_56ContG_methods.$GCINFO = "interop_serverQ_L_56Cont";
        interop_serverQ_L_56ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        interop_serverQ_L_56ContG_methods.__bool__ = (B_bool (*) (interop_serverQ_L_56Cont))B_valueG_methods.__bool__;
        interop_serverQ_L_56ContG_methods.__str__ = (B_str (*) (interop_serverQ_L_56Cont))B_valueG_methods.__str__;
        interop_serverQ_L_56ContG_methods.__repr__ = (B_str (*) (interop_serverQ_L_56Cont))B_valueG_methods.__repr__;
        interop_serverQ_L_56ContG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_56Cont, interop_serverQ_main, sshQ_ServerChannel, $Cont))interop_serverQ_L_56ContD___init__;
        interop_serverQ_L_56ContG_methods.__call__ = ($R (*) (interop_serverQ_L_56Cont, B_NoneType))interop_serverQ_L_56ContD___call__;
        interop_serverQ_L_56ContG_methods.__serialize__ = interop_serverQ_L_56ContD___serialize__;
        interop_serverQ_L_56ContG_methods.__deserialize__ = interop_serverQ_L_56ContD___deserialize__;
        $register(&interop_serverQ_L_56ContG_methods);
    }
    {
        interop_serverQ_L_57ContG_methods.$GCINFO = "interop_serverQ_L_57Cont";
        interop_serverQ_L_57ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        interop_serverQ_L_57ContG_methods.__bool__ = (B_bool (*) (interop_serverQ_L_57Cont))B_valueG_methods.__bool__;
        interop_serverQ_L_57ContG_methods.__str__ = (B_str (*) (interop_serverQ_L_57Cont))B_valueG_methods.__str__;
        interop_serverQ_L_57ContG_methods.__repr__ = (B_str (*) (interop_serverQ_L_57Cont))B_valueG_methods.__repr__;
        interop_serverQ_L_57ContG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_57Cont, $Cont, B_bytes, sshQ_ServerChannel, interop_serverQ_main))interop_serverQ_L_57ContD___init__;
        interop_serverQ_L_57ContG_methods.__call__ = ($R (*) (interop_serverQ_L_57Cont, B_NoneType))interop_serverQ_L_57ContD___call__;
        interop_serverQ_L_57ContG_methods.__serialize__ = interop_serverQ_L_57ContD___serialize__;
        interop_serverQ_L_57ContG_methods.__deserialize__ = interop_serverQ_L_57ContD___deserialize__;
        $register(&interop_serverQ_L_57ContG_methods);
    }
    {
        interop_serverQ_L_58ContG_methods.$GCINFO = "interop_serverQ_L_58Cont";
        interop_serverQ_L_58ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        interop_serverQ_L_58ContG_methods.__bool__ = (B_bool (*) (interop_serverQ_L_58Cont))B_valueG_methods.__bool__;
        interop_serverQ_L_58ContG_methods.__str__ = (B_str (*) (interop_serverQ_L_58Cont))B_valueG_methods.__str__;
        interop_serverQ_L_58ContG_methods.__repr__ = (B_str (*) (interop_serverQ_L_58Cont))B_valueG_methods.__repr__;
        interop_serverQ_L_58ContG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_58Cont, $Cont, B_bytes, sshQ_ServerChannel, interop_serverQ_main))interop_serverQ_L_58ContD___init__;
        interop_serverQ_L_58ContG_methods.__call__ = ($R (*) (interop_serverQ_L_58Cont, B_str))interop_serverQ_L_58ContD___call__;
        interop_serverQ_L_58ContG_methods.__serialize__ = interop_serverQ_L_58ContD___serialize__;
        interop_serverQ_L_58ContG_methods.__deserialize__ = interop_serverQ_L_58ContD___deserialize__;
        $register(&interop_serverQ_L_58ContG_methods);
    }
    {
        interop_serverQ_L_60ContG_methods.$GCINFO = "interop_serverQ_L_60Cont";
        interop_serverQ_L_60ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        interop_serverQ_L_60ContG_methods.__bool__ = (B_bool (*) (interop_serverQ_L_60Cont))B_valueG_methods.__bool__;
        interop_serverQ_L_60ContG_methods.__str__ = (B_str (*) (interop_serverQ_L_60Cont))B_valueG_methods.__str__;
        interop_serverQ_L_60ContG_methods.__repr__ = (B_str (*) (interop_serverQ_L_60Cont))B_valueG_methods.__repr__;
        interop_serverQ_L_60ContG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_60Cont, sshQ_ServerSession, $Cont))interop_serverQ_L_60ContD___init__;
        interop_serverQ_L_60ContG_methods.__call__ = ($R (*) (interop_serverQ_L_60Cont, sshQ_ServerChannel))interop_serverQ_L_60ContD___call__;
        interop_serverQ_L_60ContG_methods.__serialize__ = interop_serverQ_L_60ContD___serialize__;
        interop_serverQ_L_60ContG_methods.__deserialize__ = interop_serverQ_L_60ContD___deserialize__;
        $register(&interop_serverQ_L_60ContG_methods);
    }
    {
        interop_serverQ_L_62actionG_methods.$GCINFO = "interop_serverQ_L_62action";
        interop_serverQ_L_62actionG_methods.$superclass = ($SuperG_class)&$actionG_methods;
        interop_serverQ_L_62actionG_methods.__bool__ = (B_bool (*) (interop_serverQ_L_62action))B_valueG_methods.__bool__;
        interop_serverQ_L_62actionG_methods.__str__ = (B_str (*) (interop_serverQ_L_62action))B_valueG_methods.__str__;
        interop_serverQ_L_62actionG_methods.__repr__ = (B_str (*) (interop_serverQ_L_62action))B_valueG_methods.__repr__;
        interop_serverQ_L_62actionG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_62action, interop_serverQ_main))interop_serverQ_L_62actionD___init__;
        interop_serverQ_L_62actionG_methods.__call__ = ($R (*) (interop_serverQ_L_62action, $Cont, sshQ_ServerChannel, B_bytes))interop_serverQ_L_62actionD___call__;
        interop_serverQ_L_62actionG_methods.__exec__ = ($R (*) (interop_serverQ_L_62action, $Cont, sshQ_ServerChannel, B_bytes))interop_serverQ_L_62actionD___exec__;
        interop_serverQ_L_62actionG_methods.__asyn__ = (B_Msg (*) (interop_serverQ_L_62action, sshQ_ServerChannel, B_bytes))interop_serverQ_L_62actionD___asyn__;
        interop_serverQ_L_62actionG_methods.__serialize__ = interop_serverQ_L_62actionD___serialize__;
        interop_serverQ_L_62actionG_methods.__deserialize__ = interop_serverQ_L_62actionD___deserialize__;
        $register(&interop_serverQ_L_62actionG_methods);
    }
    {
        interop_serverQ_L_64actionG_methods.$GCINFO = "interop_serverQ_L_64action";
        interop_serverQ_L_64actionG_methods.$superclass = ($SuperG_class)&$actionG_methods;
        interop_serverQ_L_64actionG_methods.__bool__ = (B_bool (*) (interop_serverQ_L_64action))B_valueG_methods.__bool__;
        interop_serverQ_L_64actionG_methods.__str__ = (B_str (*) (interop_serverQ_L_64action))B_valueG_methods.__str__;
        interop_serverQ_L_64actionG_methods.__repr__ = (B_str (*) (interop_serverQ_L_64action))B_valueG_methods.__repr__;
        interop_serverQ_L_64actionG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_64action, interop_serverQ_main))interop_serverQ_L_64actionD___init__;
        interop_serverQ_L_64actionG_methods.__call__ = ($R (*) (interop_serverQ_L_64action, $Cont, sshQ_ServerChannel, B_bytes))interop_serverQ_L_64actionD___call__;
        interop_serverQ_L_64actionG_methods.__exec__ = ($R (*) (interop_serverQ_L_64action, $Cont, sshQ_ServerChannel, B_bytes))interop_serverQ_L_64actionD___exec__;
        interop_serverQ_L_64actionG_methods.__asyn__ = (B_Msg (*) (interop_serverQ_L_64action, sshQ_ServerChannel, B_bytes))interop_serverQ_L_64actionD___asyn__;
        interop_serverQ_L_64actionG_methods.__serialize__ = interop_serverQ_L_64actionD___serialize__;
        interop_serverQ_L_64actionG_methods.__deserialize__ = interop_serverQ_L_64actionD___deserialize__;
        $register(&interop_serverQ_L_64actionG_methods);
    }
    {
        interop_serverQ_L_66actionG_methods.$GCINFO = "interop_serverQ_L_66action";
        interop_serverQ_L_66actionG_methods.$superclass = ($SuperG_class)&$actionG_methods;
        interop_serverQ_L_66actionG_methods.__bool__ = (B_bool (*) (interop_serverQ_L_66action))B_valueG_methods.__bool__;
        interop_serverQ_L_66actionG_methods.__str__ = (B_str (*) (interop_serverQ_L_66action))B_valueG_methods.__str__;
        interop_serverQ_L_66actionG_methods.__repr__ = (B_str (*) (interop_serverQ_L_66action))B_valueG_methods.__repr__;
        interop_serverQ_L_66actionG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_66action, interop_serverQ_main))interop_serverQ_L_66actionD___init__;
        interop_serverQ_L_66actionG_methods.__call__ = ($R (*) (interop_serverQ_L_66action, $Cont, sshQ_ServerChannel, B_str))interop_serverQ_L_66actionD___call__;
        interop_serverQ_L_66actionG_methods.__exec__ = ($R (*) (interop_serverQ_L_66action, $Cont, sshQ_ServerChannel, B_str))interop_serverQ_L_66actionD___exec__;
        interop_serverQ_L_66actionG_methods.__asyn__ = (B_Msg (*) (interop_serverQ_L_66action, sshQ_ServerChannel, B_str))interop_serverQ_L_66actionD___asyn__;
        interop_serverQ_L_66actionG_methods.__serialize__ = interop_serverQ_L_66actionD___serialize__;
        interop_serverQ_L_66actionG_methods.__deserialize__ = interop_serverQ_L_66actionD___deserialize__;
        $register(&interop_serverQ_L_66actionG_methods);
    }
    {
        interop_serverQ_L_68ContG_methods.$GCINFO = "interop_serverQ_L_68Cont";
        interop_serverQ_L_68ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        interop_serverQ_L_68ContG_methods.__bool__ = (B_bool (*) (interop_serverQ_L_68Cont))B_valueG_methods.__bool__;
        interop_serverQ_L_68ContG_methods.__str__ = (B_str (*) (interop_serverQ_L_68Cont))B_valueG_methods.__str__;
        interop_serverQ_L_68ContG_methods.__repr__ = (B_str (*) (interop_serverQ_L_68Cont))B_valueG_methods.__repr__;
        interop_serverQ_L_68ContG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_68Cont, B_str, sshQ_ServerChannel, $Cont))interop_serverQ_L_68ContD___init__;
        interop_serverQ_L_68ContG_methods.__call__ = ($R (*) (interop_serverQ_L_68Cont, B_NoneType))interop_serverQ_L_68ContD___call__;
        interop_serverQ_L_68ContG_methods.__serialize__ = interop_serverQ_L_68ContD___serialize__;
        interop_serverQ_L_68ContG_methods.__deserialize__ = interop_serverQ_L_68ContD___deserialize__;
        $register(&interop_serverQ_L_68ContG_methods);
    }
    {
        interop_serverQ_L_72ContG_methods.$GCINFO = "interop_serverQ_L_72Cont";
        interop_serverQ_L_72ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        interop_serverQ_L_72ContG_methods.__bool__ = (B_bool (*) (interop_serverQ_L_72Cont))B_valueG_methods.__bool__;
        interop_serverQ_L_72ContG_methods.__str__ = (B_str (*) (interop_serverQ_L_72Cont))B_valueG_methods.__str__;
        interop_serverQ_L_72ContG_methods.__repr__ = (B_str (*) (interop_serverQ_L_72Cont))B_valueG_methods.__repr__;
        interop_serverQ_L_72ContG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_72Cont, $Cont))interop_serverQ_L_72ContD___init__;
        interop_serverQ_L_72ContG_methods.__call__ = ($R (*) (interop_serverQ_L_72Cont, B_NoneType))interop_serverQ_L_72ContD___call__;
        interop_serverQ_L_72ContG_methods.__serialize__ = interop_serverQ_L_72ContD___serialize__;
        interop_serverQ_L_72ContG_methods.__deserialize__ = interop_serverQ_L_72ContD___deserialize__;
        $register(&interop_serverQ_L_72ContG_methods);
    }
    {
        interop_serverQ_L_73ContG_methods.$GCINFO = "interop_serverQ_L_73Cont";
        interop_serverQ_L_73ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        interop_serverQ_L_73ContG_methods.__bool__ = (B_bool (*) (interop_serverQ_L_73Cont))B_valueG_methods.__bool__;
        interop_serverQ_L_73ContG_methods.__str__ = (B_str (*) (interop_serverQ_L_73Cont))B_valueG_methods.__str__;
        interop_serverQ_L_73ContG_methods.__repr__ = (B_str (*) (interop_serverQ_L_73Cont))B_valueG_methods.__repr__;
        interop_serverQ_L_73ContG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_73Cont, $Cont))interop_serverQ_L_73ContD___init__;
        interop_serverQ_L_73ContG_methods.__call__ = ($R (*) (interop_serverQ_L_73Cont, B_NoneType))interop_serverQ_L_73ContD___call__;
        interop_serverQ_L_73ContG_methods.__serialize__ = interop_serverQ_L_73ContD___serialize__;
        interop_serverQ_L_73ContG_methods.__deserialize__ = interop_serverQ_L_73ContD___deserialize__;
        $register(&interop_serverQ_L_73ContG_methods);
    }
    {
        interop_serverQ_L_74ContG_methods.$GCINFO = "interop_serverQ_L_74Cont";
        interop_serverQ_L_74ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        interop_serverQ_L_74ContG_methods.__bool__ = (B_bool (*) (interop_serverQ_L_74Cont))B_valueG_methods.__bool__;
        interop_serverQ_L_74ContG_methods.__str__ = (B_str (*) (interop_serverQ_L_74Cont))B_valueG_methods.__str__;
        interop_serverQ_L_74ContG_methods.__repr__ = (B_str (*) (interop_serverQ_L_74Cont))B_valueG_methods.__repr__;
        interop_serverQ_L_74ContG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_74Cont, interop_serverQ_main, sshQ_ServerChannel, $Cont))interop_serverQ_L_74ContD___init__;
        interop_serverQ_L_74ContG_methods.__call__ = ($R (*) (interop_serverQ_L_74Cont, B_bool))interop_serverQ_L_74ContD___call__;
        interop_serverQ_L_74ContG_methods.__serialize__ = interop_serverQ_L_74ContD___serialize__;
        interop_serverQ_L_74ContG_methods.__deserialize__ = interop_serverQ_L_74ContD___deserialize__;
        $register(&interop_serverQ_L_74ContG_methods);
    }
    {
        interop_serverQ_L_75ContG_methods.$GCINFO = "interop_serverQ_L_75Cont";
        interop_serverQ_L_75ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        interop_serverQ_L_75ContG_methods.__bool__ = (B_bool (*) (interop_serverQ_L_75Cont))B_valueG_methods.__bool__;
        interop_serverQ_L_75ContG_methods.__str__ = (B_str (*) (interop_serverQ_L_75Cont))B_valueG_methods.__str__;
        interop_serverQ_L_75ContG_methods.__repr__ = (B_str (*) (interop_serverQ_L_75Cont))B_valueG_methods.__repr__;
        interop_serverQ_L_75ContG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_75Cont, sshQ_ServerChannel, interop_serverQ_main, $Cont))interop_serverQ_L_75ContD___init__;
        interop_serverQ_L_75ContG_methods.__call__ = ($R (*) (interop_serverQ_L_75Cont, B_NoneType))interop_serverQ_L_75ContD___call__;
        interop_serverQ_L_75ContG_methods.__serialize__ = interop_serverQ_L_75ContD___serialize__;
        interop_serverQ_L_75ContG_methods.__deserialize__ = interop_serverQ_L_75ContD___deserialize__;
        $register(&interop_serverQ_L_75ContG_methods);
    }
    {
        interop_serverQ_L_76ContG_methods.$GCINFO = "interop_serverQ_L_76Cont";
        interop_serverQ_L_76ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        interop_serverQ_L_76ContG_methods.__bool__ = (B_bool (*) (interop_serverQ_L_76Cont))B_valueG_methods.__bool__;
        interop_serverQ_L_76ContG_methods.__str__ = (B_str (*) (interop_serverQ_L_76Cont))B_valueG_methods.__str__;
        interop_serverQ_L_76ContG_methods.__repr__ = (B_str (*) (interop_serverQ_L_76Cont))B_valueG_methods.__repr__;
        interop_serverQ_L_76ContG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_76Cont, $Cont))interop_serverQ_L_76ContD___init__;
        interop_serverQ_L_76ContG_methods.__call__ = ($R (*) (interop_serverQ_L_76Cont, B_NoneType))interop_serverQ_L_76ContD___call__;
        interop_serverQ_L_76ContG_methods.__serialize__ = interop_serverQ_L_76ContD___serialize__;
        interop_serverQ_L_76ContG_methods.__deserialize__ = interop_serverQ_L_76ContD___deserialize__;
        $register(&interop_serverQ_L_76ContG_methods);
    }
    {
        interop_serverQ_L_77procG_methods.$GCINFO = "interop_serverQ_L_77proc";
        interop_serverQ_L_77procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        interop_serverQ_L_77procG_methods.__bool__ = (B_bool (*) (interop_serverQ_L_77proc))B_valueG_methods.__bool__;
        interop_serverQ_L_77procG_methods.__str__ = (B_str (*) (interop_serverQ_L_77proc))B_valueG_methods.__str__;
        interop_serverQ_L_77procG_methods.__repr__ = (B_str (*) (interop_serverQ_L_77proc))B_valueG_methods.__repr__;
        interop_serverQ_L_77procG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_77proc, interop_serverQ_main, sshQ_ServerChannel, B_str))interop_serverQ_L_77procD___init__;
        interop_serverQ_L_77procG_methods.__call__ = ($R (*) (interop_serverQ_L_77proc, $Cont))interop_serverQ_L_77procD___call__;
        interop_serverQ_L_77procG_methods.__exec__ = ($R (*) (interop_serverQ_L_77proc, $Cont))interop_serverQ_L_77procD___exec__;
        interop_serverQ_L_77procG_methods.__serialize__ = interop_serverQ_L_77procD___serialize__;
        interop_serverQ_L_77procG_methods.__deserialize__ = interop_serverQ_L_77procD___deserialize__;
        $register(&interop_serverQ_L_77procG_methods);
    }
    {
        interop_serverQ_L_78procG_methods.$GCINFO = "interop_serverQ_L_78proc";
        interop_serverQ_L_78procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        interop_serverQ_L_78procG_methods.__bool__ = (B_bool (*) (interop_serverQ_L_78proc))B_valueG_methods.__bool__;
        interop_serverQ_L_78procG_methods.__str__ = (B_str (*) (interop_serverQ_L_78proc))B_valueG_methods.__str__;
        interop_serverQ_L_78procG_methods.__repr__ = (B_str (*) (interop_serverQ_L_78proc))B_valueG_methods.__repr__;
        interop_serverQ_L_78procG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_78proc, interop_serverQ_main, sshQ_ServerChannel))interop_serverQ_L_78procD___init__;
        interop_serverQ_L_78procG_methods.__call__ = ($R (*) (interop_serverQ_L_78proc, $Cont))interop_serverQ_L_78procD___call__;
        interop_serverQ_L_78procG_methods.__exec__ = ($R (*) (interop_serverQ_L_78proc, $Cont))interop_serverQ_L_78procD___exec__;
        interop_serverQ_L_78procG_methods.__serialize__ = interop_serverQ_L_78procD___serialize__;
        interop_serverQ_L_78procG_methods.__deserialize__ = interop_serverQ_L_78procD___deserialize__;
        $register(&interop_serverQ_L_78procG_methods);
    }
    {
        interop_serverQ_L_79procG_methods.$GCINFO = "interop_serverQ_L_79proc";
        interop_serverQ_L_79procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        interop_serverQ_L_79procG_methods.__bool__ = (B_bool (*) (interop_serverQ_L_79proc))B_valueG_methods.__bool__;
        interop_serverQ_L_79procG_methods.__str__ = (B_str (*) (interop_serverQ_L_79proc))B_valueG_methods.__str__;
        interop_serverQ_L_79procG_methods.__repr__ = (B_str (*) (interop_serverQ_L_79proc))B_valueG_methods.__repr__;
        interop_serverQ_L_79procG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_79proc, interop_serverQ_main, sshQ_ServerChannel))interop_serverQ_L_79procD___init__;
        interop_serverQ_L_79procG_methods.__call__ = ($R (*) (interop_serverQ_L_79proc, $Cont))interop_serverQ_L_79procD___call__;
        interop_serverQ_L_79procG_methods.__exec__ = ($R (*) (interop_serverQ_L_79proc, $Cont))interop_serverQ_L_79procD___exec__;
        interop_serverQ_L_79procG_methods.__serialize__ = interop_serverQ_L_79procD___serialize__;
        interop_serverQ_L_79procG_methods.__deserialize__ = interop_serverQ_L_79procD___deserialize__;
        $register(&interop_serverQ_L_79procG_methods);
    }
    {
        interop_serverQ_L_80procG_methods.$GCINFO = "interop_serverQ_L_80proc";
        interop_serverQ_L_80procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        interop_serverQ_L_80procG_methods.__bool__ = (B_bool (*) (interop_serverQ_L_80proc))B_valueG_methods.__bool__;
        interop_serverQ_L_80procG_methods.__str__ = (B_str (*) (interop_serverQ_L_80proc))B_valueG_methods.__str__;
        interop_serverQ_L_80procG_methods.__repr__ = (B_str (*) (interop_serverQ_L_80proc))B_valueG_methods.__repr__;
        interop_serverQ_L_80procG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_80proc, interop_serverQ_main, sshQ_ServerChannel))interop_serverQ_L_80procD___init__;
        interop_serverQ_L_80procG_methods.__call__ = ($R (*) (interop_serverQ_L_80proc, $Cont))interop_serverQ_L_80procD___call__;
        interop_serverQ_L_80procG_methods.__exec__ = ($R (*) (interop_serverQ_L_80proc, $Cont))interop_serverQ_L_80procD___exec__;
        interop_serverQ_L_80procG_methods.__serialize__ = interop_serverQ_L_80procD___serialize__;
        interop_serverQ_L_80procG_methods.__deserialize__ = interop_serverQ_L_80procD___deserialize__;
        $register(&interop_serverQ_L_80procG_methods);
    }
    {
        interop_serverQ_L_81procG_methods.$GCINFO = "interop_serverQ_L_81proc";
        interop_serverQ_L_81procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        interop_serverQ_L_81procG_methods.__bool__ = (B_bool (*) (interop_serverQ_L_81proc))B_valueG_methods.__bool__;
        interop_serverQ_L_81procG_methods.__str__ = (B_str (*) (interop_serverQ_L_81proc))B_valueG_methods.__str__;
        interop_serverQ_L_81procG_methods.__repr__ = (B_str (*) (interop_serverQ_L_81proc))B_valueG_methods.__repr__;
        interop_serverQ_L_81procG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_81proc, interop_serverQ_main, sshQ_ServerChannel))interop_serverQ_L_81procD___init__;
        interop_serverQ_L_81procG_methods.__call__ = ($R (*) (interop_serverQ_L_81proc, $Cont))interop_serverQ_L_81procD___call__;
        interop_serverQ_L_81procG_methods.__exec__ = ($R (*) (interop_serverQ_L_81proc, $Cont))interop_serverQ_L_81procD___exec__;
        interop_serverQ_L_81procG_methods.__serialize__ = interop_serverQ_L_81procD___serialize__;
        interop_serverQ_L_81procG_methods.__deserialize__ = interop_serverQ_L_81procD___deserialize__;
        $register(&interop_serverQ_L_81procG_methods);
    }
    {
        interop_serverQ_L_82procG_methods.$GCINFO = "interop_serverQ_L_82proc";
        interop_serverQ_L_82procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        interop_serverQ_L_82procG_methods.__bool__ = (B_bool (*) (interop_serverQ_L_82proc))B_valueG_methods.__bool__;
        interop_serverQ_L_82procG_methods.__str__ = (B_str (*) (interop_serverQ_L_82proc))B_valueG_methods.__str__;
        interop_serverQ_L_82procG_methods.__repr__ = (B_str (*) (interop_serverQ_L_82proc))B_valueG_methods.__repr__;
        interop_serverQ_L_82procG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_82proc, interop_serverQ_main, sshQ_Server, B_str))interop_serverQ_L_82procD___init__;
        interop_serverQ_L_82procG_methods.__call__ = ($R (*) (interop_serverQ_L_82proc, $Cont))interop_serverQ_L_82procD___call__;
        interop_serverQ_L_82procG_methods.__exec__ = ($R (*) (interop_serverQ_L_82proc, $Cont))interop_serverQ_L_82procD___exec__;
        interop_serverQ_L_82procG_methods.__serialize__ = interop_serverQ_L_82procD___serialize__;
        interop_serverQ_L_82procG_methods.__deserialize__ = interop_serverQ_L_82procD___deserialize__;
        $register(&interop_serverQ_L_82procG_methods);
    }
    {
        interop_serverQ_L_83procG_methods.$GCINFO = "interop_serverQ_L_83proc";
        interop_serverQ_L_83procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        interop_serverQ_L_83procG_methods.__bool__ = (B_bool (*) (interop_serverQ_L_83proc))B_valueG_methods.__bool__;
        interop_serverQ_L_83procG_methods.__str__ = (B_str (*) (interop_serverQ_L_83proc))B_valueG_methods.__str__;
        interop_serverQ_L_83procG_methods.__repr__ = (B_str (*) (interop_serverQ_L_83proc))B_valueG_methods.__repr__;
        interop_serverQ_L_83procG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_83proc, interop_serverQ_main, sshQ_Server, B_str))interop_serverQ_L_83procD___init__;
        interop_serverQ_L_83procG_methods.__call__ = ($R (*) (interop_serverQ_L_83proc, $Cont))interop_serverQ_L_83procD___call__;
        interop_serverQ_L_83procG_methods.__exec__ = ($R (*) (interop_serverQ_L_83proc, $Cont))interop_serverQ_L_83procD___exec__;
        interop_serverQ_L_83procG_methods.__serialize__ = interop_serverQ_L_83procD___serialize__;
        interop_serverQ_L_83procG_methods.__deserialize__ = interop_serverQ_L_83procD___deserialize__;
        $register(&interop_serverQ_L_83procG_methods);
    }
    {
        interop_serverQ_L_84procG_methods.$GCINFO = "interop_serverQ_L_84proc";
        interop_serverQ_L_84procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        interop_serverQ_L_84procG_methods.__bool__ = (B_bool (*) (interop_serverQ_L_84proc))B_valueG_methods.__bool__;
        interop_serverQ_L_84procG_methods.__str__ = (B_str (*) (interop_serverQ_L_84proc))B_valueG_methods.__str__;
        interop_serverQ_L_84procG_methods.__repr__ = (B_str (*) (interop_serverQ_L_84proc))B_valueG_methods.__repr__;
        interop_serverQ_L_84procG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_84proc, interop_serverQ_main, sshQ_ServerSession))interop_serverQ_L_84procD___init__;
        interop_serverQ_L_84procG_methods.__call__ = ($R (*) (interop_serverQ_L_84proc, $Cont))interop_serverQ_L_84procD___call__;
        interop_serverQ_L_84procG_methods.__exec__ = ($R (*) (interop_serverQ_L_84proc, $Cont))interop_serverQ_L_84procD___exec__;
        interop_serverQ_L_84procG_methods.__serialize__ = interop_serverQ_L_84procD___serialize__;
        interop_serverQ_L_84procG_methods.__deserialize__ = interop_serverQ_L_84procD___deserialize__;
        $register(&interop_serverQ_L_84procG_methods);
    }
    {
        interop_serverQ_L_85procG_methods.$GCINFO = "interop_serverQ_L_85proc";
        interop_serverQ_L_85procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        interop_serverQ_L_85procG_methods.__bool__ = (B_bool (*) (interop_serverQ_L_85proc))B_valueG_methods.__bool__;
        interop_serverQ_L_85procG_methods.__str__ = (B_str (*) (interop_serverQ_L_85proc))B_valueG_methods.__str__;
        interop_serverQ_L_85procG_methods.__repr__ = (B_str (*) (interop_serverQ_L_85proc))B_valueG_methods.__repr__;
        interop_serverQ_L_85procG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_85proc, interop_serverQ_main, sshQ_ServerSession, B_str))interop_serverQ_L_85procD___init__;
        interop_serverQ_L_85procG_methods.__call__ = ($R (*) (interop_serverQ_L_85proc, $Cont))interop_serverQ_L_85procD___call__;
        interop_serverQ_L_85procG_methods.__exec__ = ($R (*) (interop_serverQ_L_85proc, $Cont))interop_serverQ_L_85procD___exec__;
        interop_serverQ_L_85procG_methods.__serialize__ = interop_serverQ_L_85procD___serialize__;
        interop_serverQ_L_85procG_methods.__deserialize__ = interop_serverQ_L_85procD___deserialize__;
        $register(&interop_serverQ_L_85procG_methods);
    }
    {
        interop_serverQ_L_86procG_methods.$GCINFO = "interop_serverQ_L_86proc";
        interop_serverQ_L_86procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        interop_serverQ_L_86procG_methods.__bool__ = (B_bool (*) (interop_serverQ_L_86proc))B_valueG_methods.__bool__;
        interop_serverQ_L_86procG_methods.__str__ = (B_str (*) (interop_serverQ_L_86proc))B_valueG_methods.__str__;
        interop_serverQ_L_86procG_methods.__repr__ = (B_str (*) (interop_serverQ_L_86proc))B_valueG_methods.__repr__;
        interop_serverQ_L_86procG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_86proc, interop_serverQ_main, sshQ_ServerSession, sshQ_AuthRequest))interop_serverQ_L_86procD___init__;
        interop_serverQ_L_86procG_methods.__call__ = ($R (*) (interop_serverQ_L_86proc, $Cont))interop_serverQ_L_86procD___call__;
        interop_serverQ_L_86procG_methods.__exec__ = ($R (*) (interop_serverQ_L_86proc, $Cont))interop_serverQ_L_86procD___exec__;
        interop_serverQ_L_86procG_methods.__serialize__ = interop_serverQ_L_86procD___serialize__;
        interop_serverQ_L_86procG_methods.__deserialize__ = interop_serverQ_L_86procD___deserialize__;
        $register(&interop_serverQ_L_86procG_methods);
    }
    {
        interop_serverQ_L_87procG_methods.$GCINFO = "interop_serverQ_L_87proc";
        interop_serverQ_L_87procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        interop_serverQ_L_87procG_methods.__bool__ = (B_bool (*) (interop_serverQ_L_87proc))B_valueG_methods.__bool__;
        interop_serverQ_L_87procG_methods.__str__ = (B_str (*) (interop_serverQ_L_87proc))B_valueG_methods.__str__;
        interop_serverQ_L_87procG_methods.__repr__ = (B_str (*) (interop_serverQ_L_87proc))B_valueG_methods.__repr__;
        interop_serverQ_L_87procG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_87proc, interop_serverQ_main, sshQ_ServerChannel, B_bytes))interop_serverQ_L_87procD___init__;
        interop_serverQ_L_87procG_methods.__call__ = ($R (*) (interop_serverQ_L_87proc, $Cont))interop_serverQ_L_87procD___call__;
        interop_serverQ_L_87procG_methods.__exec__ = ($R (*) (interop_serverQ_L_87proc, $Cont))interop_serverQ_L_87procD___exec__;
        interop_serverQ_L_87procG_methods.__serialize__ = interop_serverQ_L_87procD___serialize__;
        interop_serverQ_L_87procG_methods.__deserialize__ = interop_serverQ_L_87procD___deserialize__;
        $register(&interop_serverQ_L_87procG_methods);
    }
    {
        interop_serverQ_L_88procG_methods.$GCINFO = "interop_serverQ_L_88proc";
        interop_serverQ_L_88procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        interop_serverQ_L_88procG_methods.__bool__ = (B_bool (*) (interop_serverQ_L_88proc))B_valueG_methods.__bool__;
        interop_serverQ_L_88procG_methods.__str__ = (B_str (*) (interop_serverQ_L_88proc))B_valueG_methods.__str__;
        interop_serverQ_L_88procG_methods.__repr__ = (B_str (*) (interop_serverQ_L_88proc))B_valueG_methods.__repr__;
        interop_serverQ_L_88procG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_88proc, interop_serverQ_main, sshQ_ServerChannel, B_bytes))interop_serverQ_L_88procD___init__;
        interop_serverQ_L_88procG_methods.__call__ = ($R (*) (interop_serverQ_L_88proc, $Cont))interop_serverQ_L_88procD___call__;
        interop_serverQ_L_88procG_methods.__exec__ = ($R (*) (interop_serverQ_L_88proc, $Cont))interop_serverQ_L_88procD___exec__;
        interop_serverQ_L_88procG_methods.__serialize__ = interop_serverQ_L_88procD___serialize__;
        interop_serverQ_L_88procG_methods.__deserialize__ = interop_serverQ_L_88procD___deserialize__;
        $register(&interop_serverQ_L_88procG_methods);
    }
    {
        interop_serverQ_L_89procG_methods.$GCINFO = "interop_serverQ_L_89proc";
        interop_serverQ_L_89procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        interop_serverQ_L_89procG_methods.__bool__ = (B_bool (*) (interop_serverQ_L_89proc))B_valueG_methods.__bool__;
        interop_serverQ_L_89procG_methods.__str__ = (B_str (*) (interop_serverQ_L_89proc))B_valueG_methods.__str__;
        interop_serverQ_L_89procG_methods.__repr__ = (B_str (*) (interop_serverQ_L_89proc))B_valueG_methods.__repr__;
        interop_serverQ_L_89procG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_89proc, interop_serverQ_main, sshQ_ServerChannel, B_str))interop_serverQ_L_89procD___init__;
        interop_serverQ_L_89procG_methods.__call__ = ($R (*) (interop_serverQ_L_89proc, $Cont))interop_serverQ_L_89procD___call__;
        interop_serverQ_L_89procG_methods.__exec__ = ($R (*) (interop_serverQ_L_89proc, $Cont))interop_serverQ_L_89procD___exec__;
        interop_serverQ_L_89procG_methods.__serialize__ = interop_serverQ_L_89procD___serialize__;
        interop_serverQ_L_89procG_methods.__deserialize__ = interop_serverQ_L_89procD___deserialize__;
        $register(&interop_serverQ_L_89procG_methods);
    }
    {
        interop_serverQ_L_90procG_methods.$GCINFO = "interop_serverQ_L_90proc";
        interop_serverQ_L_90procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        interop_serverQ_L_90procG_methods.__bool__ = (B_bool (*) (interop_serverQ_L_90proc))B_valueG_methods.__bool__;
        interop_serverQ_L_90procG_methods.__str__ = (B_str (*) (interop_serverQ_L_90proc))B_valueG_methods.__str__;
        interop_serverQ_L_90procG_methods.__repr__ = (B_str (*) (interop_serverQ_L_90proc))B_valueG_methods.__repr__;
        interop_serverQ_L_90procG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_90proc, interop_serverQ_main, sshQ_ServerSession))interop_serverQ_L_90procD___init__;
        interop_serverQ_L_90procG_methods.__call__ = ($R (*) (interop_serverQ_L_90proc, $Cont))interop_serverQ_L_90procD___call__;
        interop_serverQ_L_90procG_methods.__exec__ = ($R (*) (interop_serverQ_L_90proc, $Cont))interop_serverQ_L_90procD___exec__;
        interop_serverQ_L_90procG_methods.__serialize__ = interop_serverQ_L_90procD___serialize__;
        interop_serverQ_L_90procG_methods.__deserialize__ = interop_serverQ_L_90procD___deserialize__;
        $register(&interop_serverQ_L_90procG_methods);
    }
    {
        interop_serverQ_L_91procG_methods.$GCINFO = "interop_serverQ_L_91proc";
        interop_serverQ_L_91procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        interop_serverQ_L_91procG_methods.__bool__ = (B_bool (*) (interop_serverQ_L_91proc))B_valueG_methods.__bool__;
        interop_serverQ_L_91procG_methods.__str__ = (B_str (*) (interop_serverQ_L_91proc))B_valueG_methods.__str__;
        interop_serverQ_L_91procG_methods.__repr__ = (B_str (*) (interop_serverQ_L_91proc))B_valueG_methods.__repr__;
        interop_serverQ_L_91procG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_91proc, interop_serverQ_main, sshQ_ServerSession, sshQ_ServerChannel, B_str))interop_serverQ_L_91procD___init__;
        interop_serverQ_L_91procG_methods.__call__ = ($R (*) (interop_serverQ_L_91proc, $Cont))interop_serverQ_L_91procD___call__;
        interop_serverQ_L_91procG_methods.__exec__ = ($R (*) (interop_serverQ_L_91proc, $Cont))interop_serverQ_L_91procD___exec__;
        interop_serverQ_L_91procG_methods.__serialize__ = interop_serverQ_L_91procD___serialize__;
        interop_serverQ_L_91procG_methods.__deserialize__ = interop_serverQ_L_91procD___deserialize__;
        $register(&interop_serverQ_L_91procG_methods);
    }
    {
        interop_serverQ_L_92procG_methods.$GCINFO = "interop_serverQ_L_92proc";
        interop_serverQ_L_92procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        interop_serverQ_L_92procG_methods.__bool__ = (B_bool (*) (interop_serverQ_L_92proc))B_valueG_methods.__bool__;
        interop_serverQ_L_92procG_methods.__str__ = (B_str (*) (interop_serverQ_L_92proc))B_valueG_methods.__str__;
        interop_serverQ_L_92procG_methods.__repr__ = (B_str (*) (interop_serverQ_L_92proc))B_valueG_methods.__repr__;
        interop_serverQ_L_92procG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_92proc, interop_serverQ_main, sshQ_ServerSession, sshQ_ServerChannel, B_str))interop_serverQ_L_92procD___init__;
        interop_serverQ_L_92procG_methods.__call__ = ($R (*) (interop_serverQ_L_92proc, $Cont))interop_serverQ_L_92procD___call__;
        interop_serverQ_L_92procG_methods.__exec__ = ($R (*) (interop_serverQ_L_92proc, $Cont))interop_serverQ_L_92procD___exec__;
        interop_serverQ_L_92procG_methods.__serialize__ = interop_serverQ_L_92procD___serialize__;
        interop_serverQ_L_92procG_methods.__deserialize__ = interop_serverQ_L_92procD___deserialize__;
        $register(&interop_serverQ_L_92procG_methods);
    }
    {
        interop_serverQ_L_94ContG_methods.$GCINFO = "interop_serverQ_L_94Cont";
        interop_serverQ_L_94ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        interop_serverQ_L_94ContG_methods.__bool__ = (B_bool (*) (interop_serverQ_L_94Cont))B_valueG_methods.__bool__;
        interop_serverQ_L_94ContG_methods.__str__ = (B_str (*) (interop_serverQ_L_94Cont))B_valueG_methods.__str__;
        interop_serverQ_L_94ContG_methods.__repr__ = (B_str (*) (interop_serverQ_L_94Cont))B_valueG_methods.__repr__;
        interop_serverQ_L_94ContG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_94Cont, $Cont, interop_serverQ_main))interop_serverQ_L_94ContD___init__;
        interop_serverQ_L_94ContG_methods.__call__ = ($R (*) (interop_serverQ_L_94Cont, B_NoneType))interop_serverQ_L_94ContD___call__;
        interop_serverQ_L_94ContG_methods.__serialize__ = interop_serverQ_L_94ContD___serialize__;
        interop_serverQ_L_94ContG_methods.__deserialize__ = interop_serverQ_L_94ContD___deserialize__;
        $register(&interop_serverQ_L_94ContG_methods);
    }
    {
        interop_serverQ_L_95procG_methods.$GCINFO = "interop_serverQ_L_95proc";
        interop_serverQ_L_95procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        interop_serverQ_L_95procG_methods.__bool__ = (B_bool (*) (interop_serverQ_L_95proc))B_valueG_methods.__bool__;
        interop_serverQ_L_95procG_methods.__str__ = (B_str (*) (interop_serverQ_L_95proc))B_valueG_methods.__str__;
        interop_serverQ_L_95procG_methods.__repr__ = (B_str (*) (interop_serverQ_L_95proc))B_valueG_methods.__repr__;
        interop_serverQ_L_95procG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_95proc, interop_serverQ_main, B_Env))interop_serverQ_L_95procD___init__;
        interop_serverQ_L_95procG_methods.__call__ = ($R (*) (interop_serverQ_L_95proc, $Cont))interop_serverQ_L_95procD___call__;
        interop_serverQ_L_95procG_methods.__exec__ = ($R (*) (interop_serverQ_L_95proc, $Cont))interop_serverQ_L_95procD___exec__;
        interop_serverQ_L_95procG_methods.__serialize__ = interop_serverQ_L_95procD___serialize__;
        interop_serverQ_L_95procG_methods.__deserialize__ = interop_serverQ_L_95procD___deserialize__;
        $register(&interop_serverQ_L_95procG_methods);
    }
    {
        interop_serverQ_mainG_methods.$GCINFO = "interop_serverQ_main";
        interop_serverQ_mainG_methods.$superclass = ($SuperG_class)&$ActorG_methods;
        interop_serverQ_mainG_methods.__bool__ = (B_bool (*) (interop_serverQ_main))$ActorG_methods.__bool__;
        interop_serverQ_mainG_methods.__str__ = (B_str (*) (interop_serverQ_main))$ActorG_methods.__str__;
        interop_serverQ_mainG_methods.__repr__ = (B_str (*) (interop_serverQ_main))$ActorG_methods.__repr__;
        interop_serverQ_mainG_methods.__resume__ = (B_NoneType (*) (interop_serverQ_main))$ActorG_methods.__resume__;
        interop_serverQ_mainG_methods.__cleanup__ = (B_NoneType (*) (interop_serverQ_main))$ActorG_methods.__cleanup__;
        interop_serverQ_mainG_methods.__init__ = ($R (*) (interop_serverQ_main, $Cont, B_Env))interop_serverQ_mainD___init__;
        interop_serverQ_mainG_methods.set_modeG_local = ($R (*) (interop_serverQ_main, $Cont, sshQ_ServerChannel, B_str))interop_serverQ_mainD_set_modeG_local;
        interop_serverQ_mainG_methods.mode_ofG_local = ($R (*) (interop_serverQ_main, $Cont, sshQ_ServerChannel))interop_serverQ_mainD_mode_ofG_local;
        interop_serverQ_mainG_methods.mark_eofG_local = ($R (*) (interop_serverQ_main, $Cont, sshQ_ServerChannel))interop_serverQ_mainD_mark_eofG_local;
        interop_serverQ_mainG_methods.saw_eofG_local = ($R (*) (interop_serverQ_main, $Cont, sshQ_ServerChannel))interop_serverQ_mainD_saw_eofG_local;
        interop_serverQ_mainG_methods.close_echoG_local = ($R (*) (interop_serverQ_main, $Cont, sshQ_ServerChannel))interop_serverQ_mainD_close_echoG_local;
        interop_serverQ_mainG_methods.on_listenG_local = ($R (*) (interop_serverQ_main, $Cont, sshQ_Server, B_str))interop_serverQ_mainD_on_listenG_local;
        interop_serverQ_mainG_methods.on_server_closeG_local = ($R (*) (interop_serverQ_main, $Cont, sshQ_Server, B_str))interop_serverQ_mainD_on_server_closeG_local;
        interop_serverQ_mainG_methods.on_sessionG_local = ($R (*) (interop_serverQ_main, $Cont, sshQ_ServerSession))interop_serverQ_mainD_on_sessionG_local;
        interop_serverQ_mainG_methods.on_session_closeG_local = ($R (*) (interop_serverQ_main, $Cont, sshQ_ServerSession, B_str))interop_serverQ_mainD_on_session_closeG_local;
        interop_serverQ_mainG_methods.on_authG_local = ($R (*) (interop_serverQ_main, $Cont, sshQ_ServerSession, sshQ_AuthRequest))interop_serverQ_mainD_on_authG_local;
        interop_serverQ_mainG_methods.srv_on_dataG_local = ($R (*) (interop_serverQ_main, $Cont, sshQ_ServerChannel, B_bytes))interop_serverQ_mainD_srv_on_dataG_local;
        interop_serverQ_mainG_methods.srv_on_stderrG_local = ($R (*) (interop_serverQ_main, $Cont, sshQ_ServerChannel, B_bytes))interop_serverQ_mainD_srv_on_stderrG_local;
        interop_serverQ_mainG_methods.srv_on_closeG_local = ($R (*) (interop_serverQ_main, $Cont, sshQ_ServerChannel, B_str))interop_serverQ_mainD_srv_on_closeG_local;
        interop_serverQ_mainG_methods.on_channel_openG_local = ($R (*) (interop_serverQ_main, $Cont, sshQ_ServerSession))interop_serverQ_mainD_on_channel_openG_local;
        interop_serverQ_mainG_methods.on_execG_local = ($R (*) (interop_serverQ_main, $Cont, sshQ_ServerSession, sshQ_ServerChannel, B_str))interop_serverQ_mainD_on_execG_local;
        interop_serverQ_mainG_methods.on_subsystemG_local = ($R (*) (interop_serverQ_main, $Cont, sshQ_ServerSession, sshQ_ServerChannel, B_str))interop_serverQ_mainD_on_subsystemG_local;
        interop_serverQ_mainG_methods.set_mode = (B_Msg (*) (interop_serverQ_main, sshQ_ServerChannel, B_str))interop_serverQ_mainD_set_mode;
        interop_serverQ_mainG_methods.mode_of = (B_Msg (*) (interop_serverQ_main, sshQ_ServerChannel))interop_serverQ_mainD_mode_of;
        interop_serverQ_mainG_methods.mark_eof = (B_Msg (*) (interop_serverQ_main, sshQ_ServerChannel))interop_serverQ_mainD_mark_eof;
        interop_serverQ_mainG_methods.saw_eof = (B_Msg (*) (interop_serverQ_main, sshQ_ServerChannel))interop_serverQ_mainD_saw_eof;
        interop_serverQ_mainG_methods.close_echo = (B_Msg (*) (interop_serverQ_main, sshQ_ServerChannel))interop_serverQ_mainD_close_echo;
        interop_serverQ_mainG_methods.on_listen = (B_Msg (*) (interop_serverQ_main, sshQ_Server, B_str))interop_serverQ_mainD_on_listen;
        interop_serverQ_mainG_methods.on_server_close = (B_Msg (*) (interop_serverQ_main, sshQ_Server, B_str))interop_serverQ_mainD_on_server_close;
        interop_serverQ_mainG_methods.on_session = (B_Msg (*) (interop_serverQ_main, sshQ_ServerSession))interop_serverQ_mainD_on_session;
        interop_serverQ_mainG_methods.on_session_close = (B_Msg (*) (interop_serverQ_main, sshQ_ServerSession, B_str))interop_serverQ_mainD_on_session_close;
        interop_serverQ_mainG_methods.on_auth = (B_Msg (*) (interop_serverQ_main, sshQ_ServerSession, sshQ_AuthRequest))interop_serverQ_mainD_on_auth;
        interop_serverQ_mainG_methods.srv_on_data = (B_Msg (*) (interop_serverQ_main, sshQ_ServerChannel, B_bytes))interop_serverQ_mainD_srv_on_data;
        interop_serverQ_mainG_methods.srv_on_stderr = (B_Msg (*) (interop_serverQ_main, sshQ_ServerChannel, B_bytes))interop_serverQ_mainD_srv_on_stderr;
        interop_serverQ_mainG_methods.srv_on_close = (B_Msg (*) (interop_serverQ_main, sshQ_ServerChannel, B_str))interop_serverQ_mainD_srv_on_close;
        interop_serverQ_mainG_methods.on_channel_open = (B_Msg (*) (interop_serverQ_main, sshQ_ServerSession))interop_serverQ_mainD_on_channel_open;
        interop_serverQ_mainG_methods.on_exec = (B_Msg (*) (interop_serverQ_main, sshQ_ServerSession, sshQ_ServerChannel, B_str))interop_serverQ_mainD_on_exec;
        interop_serverQ_mainG_methods.on_subsystem = (B_Msg (*) (interop_serverQ_main, sshQ_ServerSession, sshQ_ServerChannel, B_str))interop_serverQ_mainD_on_subsystem;
        interop_serverQ_mainG_methods.__serialize__ = interop_serverQ_mainD___serialize__;
        interop_serverQ_mainG_methods.__deserialize__ = interop_serverQ_mainD___deserialize__;
        $register(&interop_serverQ_mainG_methods);
    }
    B_Eq W_main_1090 = (B_Eq)B_OrdD_strG_witness;
    interop_serverQ_W_main_1090 = W_main_1090;
    B_Eq W_main_336 = ((B_Eq)$EqOptG_new(interop_serverQ_W_main_1090));
    interop_serverQ_W_main_336 = W_main_336;
    B_Eq W_main_294 = ((B_Eq)$EqOptG_new(interop_serverQ_W_main_1090));
    interop_serverQ_W_main_294 = W_main_294;
}