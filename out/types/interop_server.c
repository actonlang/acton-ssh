/* Acton impl hash: a28049b4d1563e8111e2797a60905ee834418d282872971b9d2971d36bfe4c22 */
#include "rts/common.h"
#include "out/types/interop_server.h"
B_Eq interop_serverQ_W_main_341;
B_Eq interop_serverQ_W_main_1194;
B_Eq interop_serverQ_W_main_424;
B_Eq interop_serverQ_W_main_322;
$R interop_serverQ_L_2C_7cont (interop_serverQ_main self, $Cont C_cont, sshQ_Server C_8res) {
    #line 138 "src/interop_server.act"
    ((interop_serverQ_main)(self))->server = C_8res;
    return $R_CONT(C_cont, B_None);
}
B_NoneType interop_serverQ_L_3ContD___init__ (interop_serverQ_L_3Cont L_self, interop_serverQ_main self, $Cont C_cont) {
    ((interop_serverQ_L_3Cont)(L_self))->self = self;
    ((interop_serverQ_L_3Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R interop_serverQ_L_3ContD___call__ (interop_serverQ_L_3Cont L_self, sshQ_Server G_1) {
    interop_serverQ_main self = ((interop_serverQ_L_3Cont)(L_self))->self;
    $Cont C_cont = ((interop_serverQ_L_3Cont)(L_self))->C_cont;
    return interop_serverQ_L_2C_7cont(self, C_cont, G_1);
}
void interop_serverQ_L_3ContD___serialize__ (interop_serverQ_L_3Cont self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->C_cont, state);
}
interop_serverQ_L_3Cont interop_serverQ_L_3ContD___deserialize__ (interop_serverQ_L_3Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct interop_serverQ_L_3Cont));
            self->$class = &interop_serverQ_L_3ContG_methods;
            return self;
        }
        self = $DNEW(interop_serverQ_L_3Cont, state);
    }
    self->self = $step_deserialize(state);
    self->C_cont = $step_deserialize(state);
    return self;
}
interop_serverQ_L_3Cont interop_serverQ_L_3ContG_new(interop_serverQ_main G_1, $Cont G_2) {
    interop_serverQ_L_3Cont $tmp = acton_malloc(sizeof(struct interop_serverQ_L_3Cont));
    $tmp->$class = &interop_serverQ_L_3ContG_methods;
    interop_serverQ_L_3ContG_methods.__init__($tmp, G_1, G_2);
    return $tmp;
}
struct interop_serverQ_L_3ContG_class interop_serverQ_L_3ContG_methods;
B_NoneType interop_serverQ_L_5actionD___init__ (interop_serverQ_L_5action L_self, interop_serverQ_main L_4obj) {
    ((interop_serverQ_L_5action)(L_self))->L_4obj = L_4obj;
    return B_None;
}
$R interop_serverQ_L_5actionD___call__ (interop_serverQ_L_5action L_self, $Cont L_cont, sshQ_Server G_1, B_str G_2) {
    return $AWAIT(L_cont, ((B_Msg (*) ($WORD, sshQ_Server, B_str))((interop_serverQ_L_5action)(L_self))->$class->__asyn__)(L_self, G_1, G_2));
}
$R interop_serverQ_L_5actionD___exec__ (interop_serverQ_L_5action L_self, $Cont L_cont, sshQ_Server G_1, B_str G_2) {
    return $R_CONT(L_cont, ((B_Msg (*) ($WORD, sshQ_Server, B_str))((interop_serverQ_L_5action)(L_self))->$class->__asyn__)(L_self, G_1, G_2));
}
B_Msg interop_serverQ_L_5actionD___asyn__ (interop_serverQ_L_5action L_self, sshQ_Server G_1, B_str G_2) {
    interop_serverQ_main L_4obj = ((interop_serverQ_L_5action)(L_self))->L_4obj;
    return ((B_Msg (*) ($WORD, sshQ_Server, B_str))((interop_serverQ_main)(L_4obj))->$class->on_listen)(L_4obj, G_1, G_2);
}
void interop_serverQ_L_5actionD___serialize__ (interop_serverQ_L_5action self, $Serial$state state) {
    $step_serialize(self->L_4obj, state);
}
interop_serverQ_L_5action interop_serverQ_L_5actionD___deserialize__ (interop_serverQ_L_5action self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct interop_serverQ_L_5action));
            self->$class = &interop_serverQ_L_5actionG_methods;
            return self;
        }
        self = $DNEW(interop_serverQ_L_5action, state);
    }
    self->L_4obj = $step_deserialize(state);
    return self;
}
interop_serverQ_L_5action interop_serverQ_L_5actionG_new(interop_serverQ_main G_1) {
    interop_serverQ_L_5action $tmp = acton_malloc(sizeof(struct interop_serverQ_L_5action));
    $tmp->$class = &interop_serverQ_L_5actionG_methods;
    interop_serverQ_L_5actionG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct interop_serverQ_L_5actionG_class interop_serverQ_L_5actionG_methods;
B_NoneType interop_serverQ_L_7actionD___init__ (interop_serverQ_L_7action L_self, interop_serverQ_main L_6obj) {
    ((interop_serverQ_L_7action)(L_self))->L_6obj = L_6obj;
    return B_None;
}
$R interop_serverQ_L_7actionD___call__ (interop_serverQ_L_7action L_self, $Cont L_cont, sshQ_Server G_1, B_str G_2) {
    return $AWAIT(L_cont, ((B_Msg (*) ($WORD, sshQ_Server, B_str))((interop_serverQ_L_7action)(L_self))->$class->__asyn__)(L_self, G_1, G_2));
}
$R interop_serverQ_L_7actionD___exec__ (interop_serverQ_L_7action L_self, $Cont L_cont, sshQ_Server G_1, B_str G_2) {
    return $R_CONT(L_cont, ((B_Msg (*) ($WORD, sshQ_Server, B_str))((interop_serverQ_L_7action)(L_self))->$class->__asyn__)(L_self, G_1, G_2));
}
B_Msg interop_serverQ_L_7actionD___asyn__ (interop_serverQ_L_7action L_self, sshQ_Server G_1, B_str G_2) {
    interop_serverQ_main L_6obj = ((interop_serverQ_L_7action)(L_self))->L_6obj;
    return ((B_Msg (*) ($WORD, sshQ_Server, B_str))((interop_serverQ_main)(L_6obj))->$class->on_server_close)(L_6obj, G_1, G_2);
}
void interop_serverQ_L_7actionD___serialize__ (interop_serverQ_L_7action self, $Serial$state state) {
    $step_serialize(self->L_6obj, state);
}
interop_serverQ_L_7action interop_serverQ_L_7actionD___deserialize__ (interop_serverQ_L_7action self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct interop_serverQ_L_7action));
            self->$class = &interop_serverQ_L_7actionG_methods;
            return self;
        }
        self = $DNEW(interop_serverQ_L_7action, state);
    }
    self->L_6obj = $step_deserialize(state);
    return self;
}
interop_serverQ_L_7action interop_serverQ_L_7actionG_new(interop_serverQ_main G_1) {
    interop_serverQ_L_7action $tmp = acton_malloc(sizeof(struct interop_serverQ_L_7action));
    $tmp->$class = &interop_serverQ_L_7actionG_methods;
    interop_serverQ_L_7actionG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct interop_serverQ_L_7actionG_class interop_serverQ_L_7actionG_methods;
B_NoneType interop_serverQ_L_9actionD___init__ (interop_serverQ_L_9action L_self, interop_serverQ_main L_8obj) {
    ((interop_serverQ_L_9action)(L_self))->L_8obj = L_8obj;
    return B_None;
}
$R interop_serverQ_L_9actionD___call__ (interop_serverQ_L_9action L_self, $Cont L_cont, sshQ_ServerSession G_1) {
    return $AWAIT(L_cont, ((B_Msg (*) ($WORD, sshQ_ServerSession))((interop_serverQ_L_9action)(L_self))->$class->__asyn__)(L_self, G_1));
}
$R interop_serverQ_L_9actionD___exec__ (interop_serverQ_L_9action L_self, $Cont L_cont, sshQ_ServerSession G_1) {
    return $R_CONT(L_cont, ((B_Msg (*) ($WORD, sshQ_ServerSession))((interop_serverQ_L_9action)(L_self))->$class->__asyn__)(L_self, G_1));
}
B_Msg interop_serverQ_L_9actionD___asyn__ (interop_serverQ_L_9action L_self, sshQ_ServerSession G_1) {
    interop_serverQ_main L_8obj = ((interop_serverQ_L_9action)(L_self))->L_8obj;
    return ((B_Msg (*) ($WORD, sshQ_ServerSession))((interop_serverQ_main)(L_8obj))->$class->on_session)(L_8obj, G_1);
}
void interop_serverQ_L_9actionD___serialize__ (interop_serverQ_L_9action self, $Serial$state state) {
    $step_serialize(self->L_8obj, state);
}
interop_serverQ_L_9action interop_serverQ_L_9actionD___deserialize__ (interop_serverQ_L_9action self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct interop_serverQ_L_9action));
            self->$class = &interop_serverQ_L_9actionG_methods;
            return self;
        }
        self = $DNEW(interop_serverQ_L_9action, state);
    }
    self->L_8obj = $step_deserialize(state);
    return self;
}
interop_serverQ_L_9action interop_serverQ_L_9actionG_new(interop_serverQ_main G_1) {
    interop_serverQ_L_9action $tmp = acton_malloc(sizeof(struct interop_serverQ_L_9action));
    $tmp->$class = &interop_serverQ_L_9actionG_methods;
    interop_serverQ_L_9actionG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct interop_serverQ_L_9actionG_class interop_serverQ_L_9actionG_methods;
B_NoneType interop_serverQ_L_11actionD___init__ (interop_serverQ_L_11action L_self, interop_serverQ_main L_10obj) {
    ((interop_serverQ_L_11action)(L_self))->L_10obj = L_10obj;
    return B_None;
}
$R interop_serverQ_L_11actionD___call__ (interop_serverQ_L_11action L_self, $Cont L_cont, sshQ_ServerSession G_1, sshQ_AuthRequest G_2) {
    return $AWAIT(L_cont, ((B_Msg (*) ($WORD, sshQ_ServerSession, sshQ_AuthRequest))((interop_serverQ_L_11action)(L_self))->$class->__asyn__)(L_self, G_1, G_2));
}
$R interop_serverQ_L_11actionD___exec__ (interop_serverQ_L_11action L_self, $Cont L_cont, sshQ_ServerSession G_1, sshQ_AuthRequest G_2) {
    return $R_CONT(L_cont, ((B_Msg (*) ($WORD, sshQ_ServerSession, sshQ_AuthRequest))((interop_serverQ_L_11action)(L_self))->$class->__asyn__)(L_self, G_1, G_2));
}
B_Msg interop_serverQ_L_11actionD___asyn__ (interop_serverQ_L_11action L_self, sshQ_ServerSession G_1, sshQ_AuthRequest G_2) {
    interop_serverQ_main L_10obj = ((interop_serverQ_L_11action)(L_self))->L_10obj;
    return ((B_Msg (*) ($WORD, sshQ_ServerSession, sshQ_AuthRequest))((interop_serverQ_main)(L_10obj))->$class->on_auth)(L_10obj, G_1, G_2);
}
void interop_serverQ_L_11actionD___serialize__ (interop_serverQ_L_11action self, $Serial$state state) {
    $step_serialize(self->L_10obj, state);
}
interop_serverQ_L_11action interop_serverQ_L_11actionD___deserialize__ (interop_serverQ_L_11action self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct interop_serverQ_L_11action));
            self->$class = &interop_serverQ_L_11actionG_methods;
            return self;
        }
        self = $DNEW(interop_serverQ_L_11action, state);
    }
    self->L_10obj = $step_deserialize(state);
    return self;
}
interop_serverQ_L_11action interop_serverQ_L_11actionG_new(interop_serverQ_main G_1) {
    interop_serverQ_L_11action $tmp = acton_malloc(sizeof(struct interop_serverQ_L_11action));
    $tmp->$class = &interop_serverQ_L_11actionG_methods;
    interop_serverQ_L_11actionG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct interop_serverQ_L_11actionG_class interop_serverQ_L_11actionG_methods;
B_NoneType interop_serverQ_L_13actionD___init__ (interop_serverQ_L_13action L_self, interop_serverQ_main L_12obj) {
    ((interop_serverQ_L_13action)(L_self))->L_12obj = L_12obj;
    return B_None;
}
$R interop_serverQ_L_13actionD___call__ (interop_serverQ_L_13action L_self, $Cont L_cont, sshQ_ServerSession G_1) {
    return $AWAIT(L_cont, ((B_Msg (*) ($WORD, sshQ_ServerSession))((interop_serverQ_L_13action)(L_self))->$class->__asyn__)(L_self, G_1));
}
$R interop_serverQ_L_13actionD___exec__ (interop_serverQ_L_13action L_self, $Cont L_cont, sshQ_ServerSession G_1) {
    return $R_CONT(L_cont, ((B_Msg (*) ($WORD, sshQ_ServerSession))((interop_serverQ_L_13action)(L_self))->$class->__asyn__)(L_self, G_1));
}
B_Msg interop_serverQ_L_13actionD___asyn__ (interop_serverQ_L_13action L_self, sshQ_ServerSession G_1) {
    interop_serverQ_main L_12obj = ((interop_serverQ_L_13action)(L_self))->L_12obj;
    return ((B_Msg (*) ($WORD, sshQ_ServerSession))((interop_serverQ_main)(L_12obj))->$class->on_channel_open)(L_12obj, G_1);
}
void interop_serverQ_L_13actionD___serialize__ (interop_serverQ_L_13action self, $Serial$state state) {
    $step_serialize(self->L_12obj, state);
}
interop_serverQ_L_13action interop_serverQ_L_13actionD___deserialize__ (interop_serverQ_L_13action self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct interop_serverQ_L_13action));
            self->$class = &interop_serverQ_L_13actionG_methods;
            return self;
        }
        self = $DNEW(interop_serverQ_L_13action, state);
    }
    self->L_12obj = $step_deserialize(state);
    return self;
}
interop_serverQ_L_13action interop_serverQ_L_13actionG_new(interop_serverQ_main G_1) {
    interop_serverQ_L_13action $tmp = acton_malloc(sizeof(struct interop_serverQ_L_13action));
    $tmp->$class = &interop_serverQ_L_13actionG_methods;
    interop_serverQ_L_13actionG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct interop_serverQ_L_13actionG_class interop_serverQ_L_13actionG_methods;
B_NoneType interop_serverQ_L_15actionD___init__ (interop_serverQ_L_15action L_self, interop_serverQ_main L_14obj) {
    ((interop_serverQ_L_15action)(L_self))->L_14obj = L_14obj;
    return B_None;
}
$R interop_serverQ_L_15actionD___call__ (interop_serverQ_L_15action L_self, $Cont L_cont, sshQ_ServerSession G_1, sshQ_ServerChannel G_2, B_str G_3) {
    return $AWAIT(L_cont, ((B_Msg (*) ($WORD, sshQ_ServerSession, sshQ_ServerChannel, B_str))((interop_serverQ_L_15action)(L_self))->$class->__asyn__)(L_self, G_1, G_2, G_3));
}
$R interop_serverQ_L_15actionD___exec__ (interop_serverQ_L_15action L_self, $Cont L_cont, sshQ_ServerSession G_1, sshQ_ServerChannel G_2, B_str G_3) {
    return $R_CONT(L_cont, ((B_Msg (*) ($WORD, sshQ_ServerSession, sshQ_ServerChannel, B_str))((interop_serverQ_L_15action)(L_self))->$class->__asyn__)(L_self, G_1, G_2, G_3));
}
B_Msg interop_serverQ_L_15actionD___asyn__ (interop_serverQ_L_15action L_self, sshQ_ServerSession G_1, sshQ_ServerChannel G_2, B_str G_3) {
    interop_serverQ_main L_14obj = ((interop_serverQ_L_15action)(L_self))->L_14obj;
    return ((B_Msg (*) ($WORD, sshQ_ServerSession, sshQ_ServerChannel, B_str))((interop_serverQ_main)(L_14obj))->$class->on_exec)(L_14obj, G_1, G_2, G_3);
}
void interop_serverQ_L_15actionD___serialize__ (interop_serverQ_L_15action self, $Serial$state state) {
    $step_serialize(self->L_14obj, state);
}
interop_serverQ_L_15action interop_serverQ_L_15actionD___deserialize__ (interop_serverQ_L_15action self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct interop_serverQ_L_15action));
            self->$class = &interop_serverQ_L_15actionG_methods;
            return self;
        }
        self = $DNEW(interop_serverQ_L_15action, state);
    }
    self->L_14obj = $step_deserialize(state);
    return self;
}
interop_serverQ_L_15action interop_serverQ_L_15actionG_new(interop_serverQ_main G_1) {
    interop_serverQ_L_15action $tmp = acton_malloc(sizeof(struct interop_serverQ_L_15action));
    $tmp->$class = &interop_serverQ_L_15actionG_methods;
    interop_serverQ_L_15actionG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct interop_serverQ_L_15actionG_class interop_serverQ_L_15actionG_methods;
B_NoneType interop_serverQ_L_17actionD___init__ (interop_serverQ_L_17action L_self, interop_serverQ_main L_16obj) {
    ((interop_serverQ_L_17action)(L_self))->L_16obj = L_16obj;
    return B_None;
}
$R interop_serverQ_L_17actionD___call__ (interop_serverQ_L_17action L_self, $Cont L_cont, sshQ_ServerSession G_1, sshQ_ServerChannel G_2, B_str G_3) {
    return $AWAIT(L_cont, ((B_Msg (*) ($WORD, sshQ_ServerSession, sshQ_ServerChannel, B_str))((interop_serverQ_L_17action)(L_self))->$class->__asyn__)(L_self, G_1, G_2, G_3));
}
$R interop_serverQ_L_17actionD___exec__ (interop_serverQ_L_17action L_self, $Cont L_cont, sshQ_ServerSession G_1, sshQ_ServerChannel G_2, B_str G_3) {
    return $R_CONT(L_cont, ((B_Msg (*) ($WORD, sshQ_ServerSession, sshQ_ServerChannel, B_str))((interop_serverQ_L_17action)(L_self))->$class->__asyn__)(L_self, G_1, G_2, G_3));
}
B_Msg interop_serverQ_L_17actionD___asyn__ (interop_serverQ_L_17action L_self, sshQ_ServerSession G_1, sshQ_ServerChannel G_2, B_str G_3) {
    interop_serverQ_main L_16obj = ((interop_serverQ_L_17action)(L_self))->L_16obj;
    return ((B_Msg (*) ($WORD, sshQ_ServerSession, sshQ_ServerChannel, B_str))((interop_serverQ_main)(L_16obj))->$class->on_subsystem)(L_16obj, G_1, G_2, G_3);
}
void interop_serverQ_L_17actionD___serialize__ (interop_serverQ_L_17action self, $Serial$state state) {
    $step_serialize(self->L_16obj, state);
}
interop_serverQ_L_17action interop_serverQ_L_17actionD___deserialize__ (interop_serverQ_L_17action self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct interop_serverQ_L_17action));
            self->$class = &interop_serverQ_L_17actionG_methods;
            return self;
        }
        self = $DNEW(interop_serverQ_L_17action, state);
    }
    self->L_16obj = $step_deserialize(state);
    return self;
}
interop_serverQ_L_17action interop_serverQ_L_17actionG_new(interop_serverQ_main G_1) {
    interop_serverQ_L_17action $tmp = acton_malloc(sizeof(struct interop_serverQ_L_17action));
    $tmp->$class = &interop_serverQ_L_17actionG_methods;
    interop_serverQ_L_17actionG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct interop_serverQ_L_17actionG_class interop_serverQ_L_17actionG_methods;
B_NoneType interop_serverQ_L_19actionD___init__ (interop_serverQ_L_19action L_self, interop_serverQ_main L_18obj) {
    ((interop_serverQ_L_19action)(L_self))->L_18obj = L_18obj;
    return B_None;
}
$R interop_serverQ_L_19actionD___call__ (interop_serverQ_L_19action L_self, $Cont L_cont, sshQ_ServerSession G_1, B_str G_2) {
    return $AWAIT(L_cont, ((B_Msg (*) ($WORD, sshQ_ServerSession, B_str))((interop_serverQ_L_19action)(L_self))->$class->__asyn__)(L_self, G_1, G_2));
}
$R interop_serverQ_L_19actionD___exec__ (interop_serverQ_L_19action L_self, $Cont L_cont, sshQ_ServerSession G_1, B_str G_2) {
    return $R_CONT(L_cont, ((B_Msg (*) ($WORD, sshQ_ServerSession, B_str))((interop_serverQ_L_19action)(L_self))->$class->__asyn__)(L_self, G_1, G_2));
}
B_Msg interop_serverQ_L_19actionD___asyn__ (interop_serverQ_L_19action L_self, sshQ_ServerSession G_1, B_str G_2) {
    interop_serverQ_main L_18obj = ((interop_serverQ_L_19action)(L_self))->L_18obj;
    return ((B_Msg (*) ($WORD, sshQ_ServerSession, B_str))((interop_serverQ_main)(L_18obj))->$class->on_session_close)(L_18obj, G_1, G_2);
}
void interop_serverQ_L_19actionD___serialize__ (interop_serverQ_L_19action self, $Serial$state state) {
    $step_serialize(self->L_18obj, state);
}
interop_serverQ_L_19action interop_serverQ_L_19actionD___deserialize__ (interop_serverQ_L_19action self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct interop_serverQ_L_19action));
            self->$class = &interop_serverQ_L_19actionG_methods;
            return self;
        }
        self = $DNEW(interop_serverQ_L_19action, state);
    }
    self->L_18obj = $step_deserialize(state);
    return self;
}
interop_serverQ_L_19action interop_serverQ_L_19actionG_new(interop_serverQ_main G_1) {
    interop_serverQ_L_19action $tmp = acton_malloc(sizeof(struct interop_serverQ_L_19action));
    $tmp->$class = &interop_serverQ_L_19actionG_methods;
    interop_serverQ_L_19actionG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct interop_serverQ_L_19actionG_class interop_serverQ_L_19actionG_methods;
$R interop_serverQ_L_1C_5cont (interop_serverQ_main self, $Cont C_cont, B_str C_6res) {
    #line 76 "src/interop_server.act"
    ((interop_serverQ_main)(self))->auth_key = C_6res;
    return sshQ_ServerG_newact((($Cont)interop_serverQ_L_3ContG_new(self, C_cont)), netQ_TCPListenCapG_new(netQ_TCPCapG_new(netQ_NetCapG_new(((B_Env)(((interop_serverQ_main)(self))->env))->cap))), to$str("127.0.0.1"), B_u16G_new(((B_atom)toB_int(0LL)), B_None), (($action)interop_serverQ_L_5actionG_new(self)), (($action)interop_serverQ_L_7actionG_new(self)), (($action)interop_serverQ_L_9actionG_new(self)), (($action)interop_serverQ_L_11actionG_new(self)), (($action)interop_serverQ_L_13actionG_new(self)), (($action)interop_serverQ_L_15actionG_new(self)), (($action)interop_serverQ_L_17actionG_new(self)), (($action)interop_serverQ_L_19actionG_new(self)), B_None, B_None, B_None, B_None, B_None, B_None, B_None, B_None, B_None, B_None);
}
B_NoneType interop_serverQ_L_20ContD___init__ (interop_serverQ_L_20Cont L_self, interop_serverQ_main self, $Cont C_cont) {
    ((interop_serverQ_L_20Cont)(L_self))->self = self;
    ((interop_serverQ_L_20Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R interop_serverQ_L_20ContD___call__ (interop_serverQ_L_20Cont L_self, B_str G_1) {
    interop_serverQ_main self = ((interop_serverQ_L_20Cont)(L_self))->self;
    $Cont C_cont = ((interop_serverQ_L_20Cont)(L_self))->C_cont;
    return interop_serverQ_L_1C_5cont(self, C_cont, G_1);
}
void interop_serverQ_L_20ContD___serialize__ (interop_serverQ_L_20Cont self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->C_cont, state);
}
interop_serverQ_L_20Cont interop_serverQ_L_20ContD___deserialize__ (interop_serverQ_L_20Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct interop_serverQ_L_20Cont));
            self->$class = &interop_serverQ_L_20ContG_methods;
            return self;
        }
        self = $DNEW(interop_serverQ_L_20Cont, state);
    }
    self->self = $step_deserialize(state);
    self->C_cont = $step_deserialize(state);
    return self;
}
interop_serverQ_L_20Cont interop_serverQ_L_20ContG_new(interop_serverQ_main G_1, $Cont G_2) {
    interop_serverQ_L_20Cont $tmp = acton_malloc(sizeof(struct interop_serverQ_L_20Cont));
    $tmp->$class = &interop_serverQ_L_20ContG_methods;
    interop_serverQ_L_20ContG_methods.__init__($tmp, G_1, G_2);
    return $tmp;
}
struct interop_serverQ_L_20ContG_class interop_serverQ_L_20ContG_methods;
$R interop_serverQ_L_21C_9cont ($Cont C_cont, B_NoneType C_10res) {
    return $R_CONT(C_cont, to$str("pending"));
}
B_NoneType interop_serverQ_L_24ContD___init__ (interop_serverQ_L_24Cont L_self, $Cont C_cont) {
    ((interop_serverQ_L_24Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R interop_serverQ_L_24ContD___call__ (interop_serverQ_L_24Cont L_self, B_NoneType G_1) {
    $Cont C_cont = ((interop_serverQ_L_24Cont)(L_self))->C_cont;
    return interop_serverQ_L_21C_9cont(C_cont, G_1);
}
void interop_serverQ_L_24ContD___serialize__ (interop_serverQ_L_24Cont self, $Serial$state state) {
    $step_serialize(self->C_cont, state);
}
interop_serverQ_L_24Cont interop_serverQ_L_24ContD___deserialize__ (interop_serverQ_L_24Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct interop_serverQ_L_24Cont));
            self->$class = &interop_serverQ_L_24ContG_methods;
            return self;
        }
        self = $DNEW(interop_serverQ_L_24Cont, state);
    }
    self->C_cont = $step_deserialize(state);
    return self;
}
interop_serverQ_L_24Cont interop_serverQ_L_24ContG_new($Cont G_1) {
    interop_serverQ_L_24Cont $tmp = acton_malloc(sizeof(struct interop_serverQ_L_24Cont));
    $tmp->$class = &interop_serverQ_L_24ContG_methods;
    interop_serverQ_L_24ContG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct interop_serverQ_L_24ContG_class interop_serverQ_L_24ContG_methods;
$R interop_serverQ_L_23C_13cont ($Cont C_cont, B_NoneType C_14res) {
    $DROP_C();
    return $R_CONT((($Cont)interop_serverQ_L_24ContG_new(C_cont)), B_None);
}
B_NoneType interop_serverQ_L_27ContD___init__ (interop_serverQ_L_27Cont L_self, B_Iterator N_iter, B_Identity W_main_70, sshQ_ServerChannel ch, $Cont C_cont) {
    ((interop_serverQ_L_27Cont)(L_self))->N_iter = N_iter;
    ((interop_serverQ_L_27Cont)(L_self))->W_main_70 = W_main_70;
    ((interop_serverQ_L_27Cont)(L_self))->ch = ch;
    ((interop_serverQ_L_27Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R interop_serverQ_L_27ContD___call__ (interop_serverQ_L_27Cont L_self, B_NoneType G_1) {
    B_Iterator N_iter = ((interop_serverQ_L_27Cont)(L_self))->N_iter;
    B_Identity W_main_70 = ((interop_serverQ_L_27Cont)(L_self))->W_main_70;
    sshQ_ServerChannel ch = ((interop_serverQ_L_27Cont)(L_self))->ch;
    $Cont C_cont = ((interop_serverQ_L_27Cont)(L_self))->C_cont;
    return interop_serverQ_L_25C_15loop(N_iter, W_main_70, ch, C_cont, G_1);
}
void interop_serverQ_L_27ContD___serialize__ (interop_serverQ_L_27Cont self, $Serial$state state) {
    $step_serialize(self->N_iter, state);
    $step_serialize(self->W_main_70, state);
    $step_serialize(self->ch, state);
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
    self->N_iter = $step_deserialize(state);
    self->W_main_70 = $step_deserialize(state);
    self->ch = $step_deserialize(state);
    self->C_cont = $step_deserialize(state);
    return self;
}
interop_serverQ_L_27Cont interop_serverQ_L_27ContG_new(B_Iterator G_1, B_Identity G_2, sshQ_ServerChannel G_3, $Cont G_4) {
    interop_serverQ_L_27Cont $tmp = acton_malloc(sizeof(struct interop_serverQ_L_27Cont));
    $tmp->$class = &interop_serverQ_L_27ContG_methods;
    interop_serverQ_L_27ContG_methods.__init__($tmp, G_1, G_2, G_3, G_4);
    return $tmp;
}
struct interop_serverQ_L_27ContG_class interop_serverQ_L_27ContG_methods;
$R interop_serverQ_L_26C_17cont (B_Iterator N_iter, B_Identity W_main_70, sshQ_ServerChannel ch, $Cont C_cont, B_NoneType C_18res) {
    B_tuple N_1val = ((B_tuple (*) ($WORD))((B_Iterator)(N_iter))->$class->__next__)(N_iter);
    B_tuple N_2tup = N_1val;
    sshQ_ServerChannel k = (((B_tuple)(N_2tup))->components[0]);
    B_str v = (((B_tuple)(N_2tup))->components[1]);
    if (((B_bool)((B_bool (*) ($WORD, sshQ_ServerChannel, sshQ_ServerChannel))((B_Identity)(W_main_70))->$class->__is__)(W_main_70, k, ch))->val) {
        $DROP_C();
        return $R_CONT(C_cont, v);
    }
    else {
        return $R_CONT((($Cont)interop_serverQ_L_27ContG_new(N_iter, W_main_70, ch, C_cont)), B_None);
    }
}
B_NoneType interop_serverQ_L_28ContD___init__ (interop_serverQ_L_28Cont L_self, B_Iterator N_iter, B_Identity W_main_70, sshQ_ServerChannel ch, $Cont C_cont) {
    ((interop_serverQ_L_28Cont)(L_self))->N_iter = N_iter;
    ((interop_serverQ_L_28Cont)(L_self))->W_main_70 = W_main_70;
    ((interop_serverQ_L_28Cont)(L_self))->ch = ch;
    ((interop_serverQ_L_28Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R interop_serverQ_L_28ContD___call__ (interop_serverQ_L_28Cont L_self, B_NoneType G_1) {
    B_Iterator N_iter = ((interop_serverQ_L_28Cont)(L_self))->N_iter;
    B_Identity W_main_70 = ((interop_serverQ_L_28Cont)(L_self))->W_main_70;
    sshQ_ServerChannel ch = ((interop_serverQ_L_28Cont)(L_self))->ch;
    $Cont C_cont = ((interop_serverQ_L_28Cont)(L_self))->C_cont;
    return interop_serverQ_L_26C_17cont(N_iter, W_main_70, ch, C_cont, G_1);
}
void interop_serverQ_L_28ContD___serialize__ (interop_serverQ_L_28Cont self, $Serial$state state) {
    $step_serialize(self->N_iter, state);
    $step_serialize(self->W_main_70, state);
    $step_serialize(self->ch, state);
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
    self->N_iter = $step_deserialize(state);
    self->W_main_70 = $step_deserialize(state);
    self->ch = $step_deserialize(state);
    self->C_cont = $step_deserialize(state);
    return self;
}
interop_serverQ_L_28Cont interop_serverQ_L_28ContG_new(B_Iterator G_1, B_Identity G_2, sshQ_ServerChannel G_3, $Cont G_4) {
    interop_serverQ_L_28Cont $tmp = acton_malloc(sizeof(struct interop_serverQ_L_28Cont));
    $tmp->$class = &interop_serverQ_L_28ContG_methods;
    interop_serverQ_L_28ContG_methods.__init__($tmp, G_1, G_2, G_3, G_4);
    return $tmp;
}
struct interop_serverQ_L_28ContG_class interop_serverQ_L_28ContG_methods;
B_NoneType interop_serverQ_L_29ContD___init__ (interop_serverQ_L_29Cont L_self, $Cont C_cont) {
    ((interop_serverQ_L_29Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R interop_serverQ_L_29ContD___call__ (interop_serverQ_L_29Cont L_self, B_NoneType G_1) {
    $Cont C_cont = ((interop_serverQ_L_29Cont)(L_self))->C_cont;
    return interop_serverQ_L_23C_13cont(C_cont, G_1);
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
B_NoneType interop_serverQ_L_30ContD___init__ (interop_serverQ_L_30Cont L_self, $Cont C_cont) {
    ((interop_serverQ_L_30Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R interop_serverQ_L_30ContD___call__ (interop_serverQ_L_30Cont L_self, B_NoneType G_1) {
    $Cont C_cont = ((interop_serverQ_L_30Cont)(L_self))->C_cont;
    return interop_serverQ_L_23C_13cont(C_cont, G_1);
}
void interop_serverQ_L_30ContD___serialize__ (interop_serverQ_L_30Cont self, $Serial$state state) {
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
    self->C_cont = $step_deserialize(state);
    return self;
}
interop_serverQ_L_30Cont interop_serverQ_L_30ContG_new($Cont G_1) {
    interop_serverQ_L_30Cont $tmp = acton_malloc(sizeof(struct interop_serverQ_L_30Cont));
    $tmp->$class = &interop_serverQ_L_30ContG_methods;
    interop_serverQ_L_30ContG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct interop_serverQ_L_30ContG_class interop_serverQ_L_30ContG_methods;
$R interop_serverQ_L_25C_15loop (B_Iterator N_iter, B_Identity W_main_70, sshQ_ServerChannel ch, $Cont C_cont, B_NoneType C_16res) {
    if (true) {
        if (true) {
            return $R_CONT((($Cont)interop_serverQ_L_28ContG_new(N_iter, W_main_70, ch, C_cont)), B_None);
        }
        else {
            return $R_CONT((($Cont)interop_serverQ_L_29ContG_new(C_cont)), B_None);
        }
    }
    else {
        return $R_CONT((($Cont)interop_serverQ_L_30ContG_new(C_cont)), B_None);
    }
}
B_NoneType interop_serverQ_L_31ContD___init__ (interop_serverQ_L_31Cont L_self, $Cont C_cont) {
    ((interop_serverQ_L_31Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R interop_serverQ_L_31ContD___call__ (interop_serverQ_L_31Cont L_self, B_NoneType G_1) {
    $Cont C_cont = ((interop_serverQ_L_31Cont)(L_self))->C_cont;
    return interop_serverQ_L_21C_9cont(C_cont, G_1);
}
void interop_serverQ_L_31ContD___serialize__ (interop_serverQ_L_31Cont self, $Serial$state state) {
    $step_serialize(self->C_cont, state);
}
interop_serverQ_L_31Cont interop_serverQ_L_31ContD___deserialize__ (interop_serverQ_L_31Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct interop_serverQ_L_31Cont));
            self->$class = &interop_serverQ_L_31ContG_methods;
            return self;
        }
        self = $DNEW(interop_serverQ_L_31Cont, state);
    }
    self->C_cont = $step_deserialize(state);
    return self;
}
interop_serverQ_L_31Cont interop_serverQ_L_31ContG_new($Cont G_1) {
    interop_serverQ_L_31Cont $tmp = acton_malloc(sizeof(struct interop_serverQ_L_31Cont));
    $tmp->$class = &interop_serverQ_L_31ContG_methods;
    interop_serverQ_L_31ContG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct interop_serverQ_L_31ContG_class interop_serverQ_L_31ContG_methods;
$R interop_serverQ_L_22C_11try (B_Iterator N_iter, B_Identity W_main_70, sshQ_ServerChannel ch, $Cont C_cont, B_bool C_12res) {
    if (((B_bool)C_12res)->val) {
        return interop_serverQ_L_25C_15loop(N_iter, W_main_70, ch, C_cont, B_None);
    }
    else {
        B_BaseException N_3x = $POP_C();
        if ($ISINSTANCE0(N_3x, B_StopIteration)) {
        }
        else {
            $RAISE(N_3x);
            __builtin_unreachable();
        }
        return $R_CONT((($Cont)interop_serverQ_L_31ContG_new(C_cont)), B_None);
    }
}
B_NoneType interop_serverQ_L_32ContD___init__ (interop_serverQ_L_32Cont L_self, B_Iterator N_iter, B_Identity W_main_70, sshQ_ServerChannel ch, $Cont C_cont) {
    ((interop_serverQ_L_32Cont)(L_self))->N_iter = N_iter;
    ((interop_serverQ_L_32Cont)(L_self))->W_main_70 = W_main_70;
    ((interop_serverQ_L_32Cont)(L_self))->ch = ch;
    ((interop_serverQ_L_32Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R interop_serverQ_L_32ContD___call__ (interop_serverQ_L_32Cont L_self, B_bool G_1) {
    B_Iterator N_iter = ((interop_serverQ_L_32Cont)(L_self))->N_iter;
    B_Identity W_main_70 = ((interop_serverQ_L_32Cont)(L_self))->W_main_70;
    sshQ_ServerChannel ch = ((interop_serverQ_L_32Cont)(L_self))->ch;
    $Cont C_cont = ((interop_serverQ_L_32Cont)(L_self))->C_cont;
    return interop_serverQ_L_22C_11try(N_iter, W_main_70, ch, C_cont, G_1);
}
void interop_serverQ_L_32ContD___serialize__ (interop_serverQ_L_32Cont self, $Serial$state state) {
    $step_serialize(self->N_iter, state);
    $step_serialize(self->W_main_70, state);
    $step_serialize(self->ch, state);
    $step_serialize(self->C_cont, state);
}
interop_serverQ_L_32Cont interop_serverQ_L_32ContD___deserialize__ (interop_serverQ_L_32Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct interop_serverQ_L_32Cont));
            self->$class = &interop_serverQ_L_32ContG_methods;
            return self;
        }
        self = $DNEW(interop_serverQ_L_32Cont, state);
    }
    self->N_iter = $step_deserialize(state);
    self->W_main_70 = $step_deserialize(state);
    self->ch = $step_deserialize(state);
    self->C_cont = $step_deserialize(state);
    return self;
}
interop_serverQ_L_32Cont interop_serverQ_L_32ContG_new(B_Iterator G_1, B_Identity G_2, sshQ_ServerChannel G_3, $Cont G_4) {
    interop_serverQ_L_32Cont $tmp = acton_malloc(sizeof(struct interop_serverQ_L_32Cont));
    $tmp->$class = &interop_serverQ_L_32ContG_methods;
    interop_serverQ_L_32ContG_methods.__init__($tmp, G_1, G_2, G_3, G_4);
    return $tmp;
}
struct interop_serverQ_L_32ContG_class interop_serverQ_L_32ContG_methods;
$R interop_serverQ_L_33C_19cont ($Cont C_cont, B_NoneType C_20res) {
    return $R_CONT(C_cont, B_False);
}
B_NoneType interop_serverQ_L_36ContD___init__ (interop_serverQ_L_36Cont L_self, $Cont C_cont) {
    ((interop_serverQ_L_36Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R interop_serverQ_L_36ContD___call__ (interop_serverQ_L_36Cont L_self, B_NoneType G_1) {
    $Cont C_cont = ((interop_serverQ_L_36Cont)(L_self))->C_cont;
    return interop_serverQ_L_33C_19cont(C_cont, G_1);
}
void interop_serverQ_L_36ContD___serialize__ (interop_serverQ_L_36Cont self, $Serial$state state) {
    $step_serialize(self->C_cont, state);
}
interop_serverQ_L_36Cont interop_serverQ_L_36ContD___deserialize__ (interop_serverQ_L_36Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct interop_serverQ_L_36Cont));
            self->$class = &interop_serverQ_L_36ContG_methods;
            return self;
        }
        self = $DNEW(interop_serverQ_L_36Cont, state);
    }
    self->C_cont = $step_deserialize(state);
    return self;
}
interop_serverQ_L_36Cont interop_serverQ_L_36ContG_new($Cont G_1) {
    interop_serverQ_L_36Cont $tmp = acton_malloc(sizeof(struct interop_serverQ_L_36Cont));
    $tmp->$class = &interop_serverQ_L_36ContG_methods;
    interop_serverQ_L_36ContG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct interop_serverQ_L_36ContG_class interop_serverQ_L_36ContG_methods;
$R interop_serverQ_L_35C_23cont ($Cont C_cont, B_NoneType C_24res) {
    $DROP_C();
    return $R_CONT((($Cont)interop_serverQ_L_36ContG_new(C_cont)), B_None);
}
B_NoneType interop_serverQ_L_39ContD___init__ (interop_serverQ_L_39Cont L_self, B_Iterator N_4iter, B_Identity W_main_104, sshQ_ServerChannel ch, $Cont C_cont) {
    ((interop_serverQ_L_39Cont)(L_self))->N_4iter = N_4iter;
    ((interop_serverQ_L_39Cont)(L_self))->W_main_104 = W_main_104;
    ((interop_serverQ_L_39Cont)(L_self))->ch = ch;
    ((interop_serverQ_L_39Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R interop_serverQ_L_39ContD___call__ (interop_serverQ_L_39Cont L_self, B_NoneType G_1) {
    B_Iterator N_4iter = ((interop_serverQ_L_39Cont)(L_self))->N_4iter;
    B_Identity W_main_104 = ((interop_serverQ_L_39Cont)(L_self))->W_main_104;
    sshQ_ServerChannel ch = ((interop_serverQ_L_39Cont)(L_self))->ch;
    $Cont C_cont = ((interop_serverQ_L_39Cont)(L_self))->C_cont;
    return interop_serverQ_L_37C_25loop(N_4iter, W_main_104, ch, C_cont, G_1);
}
void interop_serverQ_L_39ContD___serialize__ (interop_serverQ_L_39Cont self, $Serial$state state) {
    $step_serialize(self->N_4iter, state);
    $step_serialize(self->W_main_104, state);
    $step_serialize(self->ch, state);
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
    self->N_4iter = $step_deserialize(state);
    self->W_main_104 = $step_deserialize(state);
    self->ch = $step_deserialize(state);
    self->C_cont = $step_deserialize(state);
    return self;
}
interop_serverQ_L_39Cont interop_serverQ_L_39ContG_new(B_Iterator G_1, B_Identity G_2, sshQ_ServerChannel G_3, $Cont G_4) {
    interop_serverQ_L_39Cont $tmp = acton_malloc(sizeof(struct interop_serverQ_L_39Cont));
    $tmp->$class = &interop_serverQ_L_39ContG_methods;
    interop_serverQ_L_39ContG_methods.__init__($tmp, G_1, G_2, G_3, G_4);
    return $tmp;
}
struct interop_serverQ_L_39ContG_class interop_serverQ_L_39ContG_methods;
$R interop_serverQ_L_38C_27cont (B_Iterator N_4iter, B_Identity W_main_104, sshQ_ServerChannel ch, $Cont C_cont, B_NoneType C_28res) {
    sshQ_ServerChannel k = ((sshQ_ServerChannel (*) ($WORD))((B_Iterator)(N_4iter))->$class->__next__)(N_4iter);
    if (((B_bool)((B_bool (*) ($WORD, sshQ_ServerChannel, sshQ_ServerChannel))((B_Identity)(W_main_104))->$class->__is__)(W_main_104, k, ch))->val) {
        $DROP_C();
        return $R_CONT(C_cont, B_True);
    }
    else {
        return $R_CONT((($Cont)interop_serverQ_L_39ContG_new(N_4iter, W_main_104, ch, C_cont)), B_None);
    }
}
B_NoneType interop_serverQ_L_40ContD___init__ (interop_serverQ_L_40Cont L_self, B_Iterator N_4iter, B_Identity W_main_104, sshQ_ServerChannel ch, $Cont C_cont) {
    ((interop_serverQ_L_40Cont)(L_self))->N_4iter = N_4iter;
    ((interop_serverQ_L_40Cont)(L_self))->W_main_104 = W_main_104;
    ((interop_serverQ_L_40Cont)(L_self))->ch = ch;
    ((interop_serverQ_L_40Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R interop_serverQ_L_40ContD___call__ (interop_serverQ_L_40Cont L_self, B_NoneType G_1) {
    B_Iterator N_4iter = ((interop_serverQ_L_40Cont)(L_self))->N_4iter;
    B_Identity W_main_104 = ((interop_serverQ_L_40Cont)(L_self))->W_main_104;
    sshQ_ServerChannel ch = ((interop_serverQ_L_40Cont)(L_self))->ch;
    $Cont C_cont = ((interop_serverQ_L_40Cont)(L_self))->C_cont;
    return interop_serverQ_L_38C_27cont(N_4iter, W_main_104, ch, C_cont, G_1);
}
void interop_serverQ_L_40ContD___serialize__ (interop_serverQ_L_40Cont self, $Serial$state state) {
    $step_serialize(self->N_4iter, state);
    $step_serialize(self->W_main_104, state);
    $step_serialize(self->ch, state);
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
    self->N_4iter = $step_deserialize(state);
    self->W_main_104 = $step_deserialize(state);
    self->ch = $step_deserialize(state);
    self->C_cont = $step_deserialize(state);
    return self;
}
interop_serverQ_L_40Cont interop_serverQ_L_40ContG_new(B_Iterator G_1, B_Identity G_2, sshQ_ServerChannel G_3, $Cont G_4) {
    interop_serverQ_L_40Cont $tmp = acton_malloc(sizeof(struct interop_serverQ_L_40Cont));
    $tmp->$class = &interop_serverQ_L_40ContG_methods;
    interop_serverQ_L_40ContG_methods.__init__($tmp, G_1, G_2, G_3, G_4);
    return $tmp;
}
struct interop_serverQ_L_40ContG_class interop_serverQ_L_40ContG_methods;
B_NoneType interop_serverQ_L_41ContD___init__ (interop_serverQ_L_41Cont L_self, $Cont C_cont) {
    ((interop_serverQ_L_41Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R interop_serverQ_L_41ContD___call__ (interop_serverQ_L_41Cont L_self, B_NoneType G_1) {
    $Cont C_cont = ((interop_serverQ_L_41Cont)(L_self))->C_cont;
    return interop_serverQ_L_35C_23cont(C_cont, G_1);
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
B_NoneType interop_serverQ_L_42ContD___init__ (interop_serverQ_L_42Cont L_self, $Cont C_cont) {
    ((interop_serverQ_L_42Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R interop_serverQ_L_42ContD___call__ (interop_serverQ_L_42Cont L_self, B_NoneType G_1) {
    $Cont C_cont = ((interop_serverQ_L_42Cont)(L_self))->C_cont;
    return interop_serverQ_L_35C_23cont(C_cont, G_1);
}
void interop_serverQ_L_42ContD___serialize__ (interop_serverQ_L_42Cont self, $Serial$state state) {
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
    self->C_cont = $step_deserialize(state);
    return self;
}
interop_serverQ_L_42Cont interop_serverQ_L_42ContG_new($Cont G_1) {
    interop_serverQ_L_42Cont $tmp = acton_malloc(sizeof(struct interop_serverQ_L_42Cont));
    $tmp->$class = &interop_serverQ_L_42ContG_methods;
    interop_serverQ_L_42ContG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct interop_serverQ_L_42ContG_class interop_serverQ_L_42ContG_methods;
$R interop_serverQ_L_37C_25loop (B_Iterator N_4iter, B_Identity W_main_104, sshQ_ServerChannel ch, $Cont C_cont, B_NoneType C_26res) {
    if (true) {
        if (true) {
            return $R_CONT((($Cont)interop_serverQ_L_40ContG_new(N_4iter, W_main_104, ch, C_cont)), B_None);
        }
        else {
            return $R_CONT((($Cont)interop_serverQ_L_41ContG_new(C_cont)), B_None);
        }
    }
    else {
        return $R_CONT((($Cont)interop_serverQ_L_42ContG_new(C_cont)), B_None);
    }
}
B_NoneType interop_serverQ_L_43ContD___init__ (interop_serverQ_L_43Cont L_self, $Cont C_cont) {
    ((interop_serverQ_L_43Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R interop_serverQ_L_43ContD___call__ (interop_serverQ_L_43Cont L_self, B_NoneType G_1) {
    $Cont C_cont = ((interop_serverQ_L_43Cont)(L_self))->C_cont;
    return interop_serverQ_L_33C_19cont(C_cont, G_1);
}
void interop_serverQ_L_43ContD___serialize__ (interop_serverQ_L_43Cont self, $Serial$state state) {
    $step_serialize(self->C_cont, state);
}
interop_serverQ_L_43Cont interop_serverQ_L_43ContD___deserialize__ (interop_serverQ_L_43Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct interop_serverQ_L_43Cont));
            self->$class = &interop_serverQ_L_43ContG_methods;
            return self;
        }
        self = $DNEW(interop_serverQ_L_43Cont, state);
    }
    self->C_cont = $step_deserialize(state);
    return self;
}
interop_serverQ_L_43Cont interop_serverQ_L_43ContG_new($Cont G_1) {
    interop_serverQ_L_43Cont $tmp = acton_malloc(sizeof(struct interop_serverQ_L_43Cont));
    $tmp->$class = &interop_serverQ_L_43ContG_methods;
    interop_serverQ_L_43ContG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct interop_serverQ_L_43ContG_class interop_serverQ_L_43ContG_methods;
$R interop_serverQ_L_34C_21try (B_Iterator N_4iter, B_Identity W_main_104, sshQ_ServerChannel ch, $Cont C_cont, B_bool C_22res) {
    if (((B_bool)C_22res)->val) {
        return interop_serverQ_L_37C_25loop(N_4iter, W_main_104, ch, C_cont, B_None);
    }
    else {
        B_BaseException N_6x = $POP_C();
        if ($ISINSTANCE0(N_6x, B_StopIteration)) {
        }
        else {
            $RAISE(N_6x);
            __builtin_unreachable();
        }
        return $R_CONT((($Cont)interop_serverQ_L_43ContG_new(C_cont)), B_None);
    }
}
B_NoneType interop_serverQ_L_44ContD___init__ (interop_serverQ_L_44Cont L_self, B_Iterator N_4iter, B_Identity W_main_104, sshQ_ServerChannel ch, $Cont C_cont) {
    ((interop_serverQ_L_44Cont)(L_self))->N_4iter = N_4iter;
    ((interop_serverQ_L_44Cont)(L_self))->W_main_104 = W_main_104;
    ((interop_serverQ_L_44Cont)(L_self))->ch = ch;
    ((interop_serverQ_L_44Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R interop_serverQ_L_44ContD___call__ (interop_serverQ_L_44Cont L_self, B_bool G_1) {
    B_Iterator N_4iter = ((interop_serverQ_L_44Cont)(L_self))->N_4iter;
    B_Identity W_main_104 = ((interop_serverQ_L_44Cont)(L_self))->W_main_104;
    sshQ_ServerChannel ch = ((interop_serverQ_L_44Cont)(L_self))->ch;
    $Cont C_cont = ((interop_serverQ_L_44Cont)(L_self))->C_cont;
    return interop_serverQ_L_34C_21try(N_4iter, W_main_104, ch, C_cont, G_1);
}
void interop_serverQ_L_44ContD___serialize__ (interop_serverQ_L_44Cont self, $Serial$state state) {
    $step_serialize(self->N_4iter, state);
    $step_serialize(self->W_main_104, state);
    $step_serialize(self->ch, state);
    $step_serialize(self->C_cont, state);
}
interop_serverQ_L_44Cont interop_serverQ_L_44ContD___deserialize__ (interop_serverQ_L_44Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct interop_serverQ_L_44Cont));
            self->$class = &interop_serverQ_L_44ContG_methods;
            return self;
        }
        self = $DNEW(interop_serverQ_L_44Cont, state);
    }
    self->N_4iter = $step_deserialize(state);
    self->W_main_104 = $step_deserialize(state);
    self->ch = $step_deserialize(state);
    self->C_cont = $step_deserialize(state);
    return self;
}
interop_serverQ_L_44Cont interop_serverQ_L_44ContG_new(B_Iterator G_1, B_Identity G_2, sshQ_ServerChannel G_3, $Cont G_4) {
    interop_serverQ_L_44Cont $tmp = acton_malloc(sizeof(struct interop_serverQ_L_44Cont));
    $tmp->$class = &interop_serverQ_L_44ContG_methods;
    interop_serverQ_L_44ContG_methods.__init__($tmp, G_1, G_2, G_3, G_4);
    return $tmp;
}
struct interop_serverQ_L_44ContG_class interop_serverQ_L_44ContG_methods;
$R interop_serverQ_L_46C_31cont ($Cont C_cont, uint16_t C_32res) {
    #line 60 "src/interop_server.act"
    uint16_t port = C_32res;
    #line 61 "src/interop_server.act"
    ((B_NoneType (*) (B_tuple, B_str, B_str, B_bool, B_bool))B_print)($NEWTUPLE(2, to$str("PORT"), toB_u16(port)), B_None, B_None, B_None, B_None);
    return $R_CONT(C_cont, B_None);
}
B_NoneType interop_serverQ_L_47ContD___init__ (interop_serverQ_L_47Cont L_self, $Cont C_cont) {
    ((interop_serverQ_L_47Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R interop_serverQ_L_47ContD___call__ (interop_serverQ_L_47Cont L_self, B_u16 G_1) {
    $Cont C_cont = ((interop_serverQ_L_47Cont)(L_self))->C_cont;
    return interop_serverQ_L_46C_31cont(C_cont, ((B_u16)G_1)->val);
}
void interop_serverQ_L_47ContD___serialize__ (interop_serverQ_L_47Cont self, $Serial$state state) {
    $step_serialize(self->C_cont, state);
}
interop_serverQ_L_47Cont interop_serverQ_L_47ContD___deserialize__ (interop_serverQ_L_47Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct interop_serverQ_L_47Cont));
            self->$class = &interop_serverQ_L_47ContG_methods;
            return self;
        }
        self = $DNEW(interop_serverQ_L_47Cont, state);
    }
    self->C_cont = $step_deserialize(state);
    return self;
}
interop_serverQ_L_47Cont interop_serverQ_L_47ContG_new($Cont G_1) {
    interop_serverQ_L_47Cont $tmp = acton_malloc(sizeof(struct interop_serverQ_L_47Cont));
    $tmp->$class = &interop_serverQ_L_47ContG_methods;
    interop_serverQ_L_47ContG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct interop_serverQ_L_47ContG_class interop_serverQ_L_47ContG_methods;
$R interop_serverQ_L_45C_29cont ($Cont C_cont, sshQ_Server s, B_NoneType C_30res) {
    return $AWAIT((($Cont)interop_serverQ_L_47ContG_new(C_cont)), ((B_Msg (*) ($WORD))((sshQ_Server)(s))->$class->bound_port)(s));
}
B_NoneType interop_serverQ_L_48ContD___init__ (interop_serverQ_L_48Cont L_self, $Cont C_cont, sshQ_Server s) {
    ((interop_serverQ_L_48Cont)(L_self))->C_cont = C_cont;
    ((interop_serverQ_L_48Cont)(L_self))->s = s;
    return B_None;
}
$R interop_serverQ_L_48ContD___call__ (interop_serverQ_L_48Cont L_self, B_NoneType G_1) {
    $Cont C_cont = ((interop_serverQ_L_48Cont)(L_self))->C_cont;
    sshQ_Server s = ((interop_serverQ_L_48Cont)(L_self))->s;
    return interop_serverQ_L_45C_29cont(C_cont, s, G_1);
}
void interop_serverQ_L_48ContD___serialize__ (interop_serverQ_L_48Cont self, $Serial$state state) {
    $step_serialize(self->C_cont, state);
    $step_serialize(self->s, state);
}
interop_serverQ_L_48Cont interop_serverQ_L_48ContD___deserialize__ (interop_serverQ_L_48Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct interop_serverQ_L_48Cont));
            self->$class = &interop_serverQ_L_48ContG_methods;
            return self;
        }
        self = $DNEW(interop_serverQ_L_48Cont, state);
    }
    self->C_cont = $step_deserialize(state);
    self->s = $step_deserialize(state);
    return self;
}
interop_serverQ_L_48Cont interop_serverQ_L_48ContG_new($Cont G_1, sshQ_Server G_2) {
    interop_serverQ_L_48Cont $tmp = acton_malloc(sizeof(struct interop_serverQ_L_48Cont));
    $tmp->$class = &interop_serverQ_L_48ContG_methods;
    interop_serverQ_L_48ContG_methods.__init__($tmp, G_1, G_2);
    return $tmp;
}
struct interop_serverQ_L_48ContG_class interop_serverQ_L_48ContG_methods;
$R interop_serverQ_L_49C_33cont (sshQ_AuthRequest req, interop_serverQ_main self, B_Eq W_main_389, sshQ_ServerSession sess, $Cont C_cont, B_NoneType C_34res) {
    #line 87 "src/interop_server.act"
    if (((B_bool)$AND(B_bool, $AND(B_bool, ((B_bool (*) ($WORD, B_str, B_str))((B_Eq)(interop_serverQ_W_main_1194))->$class->__eq__)(interop_serverQ_W_main_1194, ((sshQ_AuthRequest)(req))->method, to$str("password")), ((B_bool (*) ($WORD, B_str, B_str))((B_Eq)(interop_serverQ_W_main_1194))->$class->__eq__)(interop_serverQ_W_main_1194, ((sshQ_AuthRequest)(req))->user, ((interop_serverQ_main)(self))->USER)), ((B_bool (*) ($WORD, B_str, B_str))((B_Eq)(W_main_389))->$class->__eq__)(W_main_389, ((sshQ_AuthRequest)(req))->password, ((interop_serverQ_main)(self))->PASS)))->val) {
        #line 88 "src/interop_server.act"
        ((B_Msg (*) ($WORD))((sshQ_ServerSession)(sess))->$class->accept_auth)(sess);
    }
    else {
        #line 90 "src/interop_server.act"
        ((B_Msg (*) ($WORD, B_str))((sshQ_ServerSession)(sess))->$class->reject_auth)(sess, to$str("invalid credentials"));
    }
    return $R_CONT(C_cont, B_None);
}
B_NoneType interop_serverQ_L_50ContD___init__ (interop_serverQ_L_50Cont L_self, sshQ_AuthRequest req, interop_serverQ_main self, B_Eq W_main_389, sshQ_ServerSession sess, $Cont C_cont) {
    ((interop_serverQ_L_50Cont)(L_self))->req = req;
    ((interop_serverQ_L_50Cont)(L_self))->self = self;
    ((interop_serverQ_L_50Cont)(L_self))->W_main_389 = W_main_389;
    ((interop_serverQ_L_50Cont)(L_self))->sess = sess;
    ((interop_serverQ_L_50Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R interop_serverQ_L_50ContD___call__ (interop_serverQ_L_50Cont L_self, B_NoneType G_1) {
    sshQ_AuthRequest req = ((interop_serverQ_L_50Cont)(L_self))->req;
    interop_serverQ_main self = ((interop_serverQ_L_50Cont)(L_self))->self;
    B_Eq W_main_389 = ((interop_serverQ_L_50Cont)(L_self))->W_main_389;
    sshQ_ServerSession sess = ((interop_serverQ_L_50Cont)(L_self))->sess;
    $Cont C_cont = ((interop_serverQ_L_50Cont)(L_self))->C_cont;
    return interop_serverQ_L_49C_33cont(req, self, W_main_389, sess, C_cont, G_1);
}
void interop_serverQ_L_50ContD___serialize__ (interop_serverQ_L_50Cont self, $Serial$state state) {
    $step_serialize(self->req, state);
    $step_serialize(self->self, state);
    $step_serialize(self->W_main_389, state);
    $step_serialize(self->sess, state);
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
    self->req = $step_deserialize(state);
    self->self = $step_deserialize(state);
    self->W_main_389 = $step_deserialize(state);
    self->sess = $step_deserialize(state);
    self->C_cont = $step_deserialize(state);
    return self;
}
interop_serverQ_L_50Cont interop_serverQ_L_50ContG_new(sshQ_AuthRequest G_1, interop_serverQ_main G_2, B_Eq G_3, sshQ_ServerSession G_4, $Cont G_5) {
    interop_serverQ_L_50Cont $tmp = acton_malloc(sizeof(struct interop_serverQ_L_50Cont));
    $tmp->$class = &interop_serverQ_L_50ContG_methods;
    interop_serverQ_L_50ContG_methods.__init__($tmp, G_1, G_2, G_3, G_4, G_5);
    return $tmp;
}
struct interop_serverQ_L_50ContG_class interop_serverQ_L_50ContG_methods;
$R interop_serverQ_L_53C_39cont ($Cont C_cont, B_NoneType C_40res) {
    return $R_CONT(C_cont, B_None);
}
B_NoneType interop_serverQ_L_54ContD___init__ (interop_serverQ_L_54Cont L_self, $Cont C_cont) {
    ((interop_serverQ_L_54Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R interop_serverQ_L_54ContD___call__ (interop_serverQ_L_54Cont L_self, B_NoneType G_1) {
    $Cont C_cont = ((interop_serverQ_L_54Cont)(L_self))->C_cont;
    return interop_serverQ_L_53C_39cont(C_cont, G_1);
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
B_NoneType interop_serverQ_L_57ContD___init__ (interop_serverQ_L_57Cont L_self, $Cont C_cont) {
    ((interop_serverQ_L_57Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R interop_serverQ_L_57ContD___call__ (interop_serverQ_L_57Cont L_self, B_NoneType G_1) {
    $Cont C_cont = ((interop_serverQ_L_57Cont)(L_self))->C_cont;
    return interop_serverQ_L_53C_39cont(C_cont, G_1);
}
void interop_serverQ_L_57ContD___serialize__ (interop_serverQ_L_57Cont self, $Serial$state state) {
    $step_serialize(self->C_cont, state);
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
    return self;
}
interop_serverQ_L_57Cont interop_serverQ_L_57ContG_new($Cont G_1) {
    interop_serverQ_L_57Cont $tmp = acton_malloc(sizeof(struct interop_serverQ_L_57Cont));
    $tmp->$class = &interop_serverQ_L_57ContG_methods;
    interop_serverQ_L_57ContG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct interop_serverQ_L_57ContG_class interop_serverQ_L_57ContG_methods;
B_NoneType interop_serverQ_L_58ContD___init__ (interop_serverQ_L_58Cont L_self, $Cont C_cont) {
    ((interop_serverQ_L_58Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R interop_serverQ_L_58ContD___call__ (interop_serverQ_L_58Cont L_self, B_NoneType G_1) {
    $Cont C_cont = ((interop_serverQ_L_58Cont)(L_self))->C_cont;
    return interop_serverQ_L_53C_39cont(C_cont, G_1);
}
void interop_serverQ_L_58ContD___serialize__ (interop_serverQ_L_58Cont self, $Serial$state state) {
    $step_serialize(self->C_cont, state);
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
    return self;
}
interop_serverQ_L_58Cont interop_serverQ_L_58ContG_new($Cont G_1) {
    interop_serverQ_L_58Cont $tmp = acton_malloc(sizeof(struct interop_serverQ_L_58Cont));
    $tmp->$class = &interop_serverQ_L_58ContG_methods;
    interop_serverQ_L_58ContG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct interop_serverQ_L_58ContG_class interop_serverQ_L_58ContG_methods;
$R interop_serverQ_L_56C_43cont (interop_serverQ_main self, sshQ_ServerChannel ch, $Cont C_cont, B_str C_44res) {
    B_str C_2pre = C_44res;
    if (((B_bool)((B_bool (*) ($WORD, B_str, B_str))((B_Eq)(interop_serverQ_W_main_1194))->$class->__eq__)(interop_serverQ_W_main_1194, C_2pre, to$str("echo")))->val) {
        return (($R (*) ($WORD, $Cont, sshQ_ServerChannel))((interop_serverQ_main)(self))->$class->close_echoG_local)(self, (($Cont)interop_serverQ_L_57ContG_new(C_cont)), ch);
    }
    else {
        return $R_CONT((($Cont)interop_serverQ_L_58ContG_new(C_cont)), B_None);
    }
}
B_NoneType interop_serverQ_L_59ContD___init__ (interop_serverQ_L_59Cont L_self, interop_serverQ_main self, sshQ_ServerChannel ch, $Cont C_cont) {
    ((interop_serverQ_L_59Cont)(L_self))->self = self;
    ((interop_serverQ_L_59Cont)(L_self))->ch = ch;
    ((interop_serverQ_L_59Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R interop_serverQ_L_59ContD___call__ (interop_serverQ_L_59Cont L_self, B_str G_1) {
    interop_serverQ_main self = ((interop_serverQ_L_59Cont)(L_self))->self;
    sshQ_ServerChannel ch = ((interop_serverQ_L_59Cont)(L_self))->ch;
    $Cont C_cont = ((interop_serverQ_L_59Cont)(L_self))->C_cont;
    return interop_serverQ_L_56C_43cont(self, ch, C_cont, G_1);
}
void interop_serverQ_L_59ContD___serialize__ (interop_serverQ_L_59Cont self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->ch, state);
    $step_serialize(self->C_cont, state);
}
interop_serverQ_L_59Cont interop_serverQ_L_59ContD___deserialize__ (interop_serverQ_L_59Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct interop_serverQ_L_59Cont));
            self->$class = &interop_serverQ_L_59ContG_methods;
            return self;
        }
        self = $DNEW(interop_serverQ_L_59Cont, state);
    }
    self->self = $step_deserialize(state);
    self->ch = $step_deserialize(state);
    self->C_cont = $step_deserialize(state);
    return self;
}
interop_serverQ_L_59Cont interop_serverQ_L_59ContG_new(interop_serverQ_main G_1, sshQ_ServerChannel G_2, $Cont G_3) {
    interop_serverQ_L_59Cont $tmp = acton_malloc(sizeof(struct interop_serverQ_L_59Cont));
    $tmp->$class = &interop_serverQ_L_59ContG_methods;
    interop_serverQ_L_59ContG_methods.__init__($tmp, G_1, G_2, G_3);
    return $tmp;
}
struct interop_serverQ_L_59ContG_class interop_serverQ_L_59ContG_methods;
$R interop_serverQ_L_55C_41cont (interop_serverQ_main self, sshQ_ServerChannel ch, $Cont C_cont, B_NoneType C_42res) {
    return (($R (*) ($WORD, $Cont, sshQ_ServerChannel))((interop_serverQ_main)(self))->$class->mode_ofG_local)(self, (($Cont)interop_serverQ_L_59ContG_new(self, ch, C_cont)), ch);
}
B_NoneType interop_serverQ_L_60ContD___init__ (interop_serverQ_L_60Cont L_self, interop_serverQ_main self, sshQ_ServerChannel ch, $Cont C_cont) {
    ((interop_serverQ_L_60Cont)(L_self))->self = self;
    ((interop_serverQ_L_60Cont)(L_self))->ch = ch;
    ((interop_serverQ_L_60Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R interop_serverQ_L_60ContD___call__ (interop_serverQ_L_60Cont L_self, B_NoneType G_1) {
    interop_serverQ_main self = ((interop_serverQ_L_60Cont)(L_self))->self;
    sshQ_ServerChannel ch = ((interop_serverQ_L_60Cont)(L_self))->ch;
    $Cont C_cont = ((interop_serverQ_L_60Cont)(L_self))->C_cont;
    return interop_serverQ_L_55C_41cont(self, ch, C_cont, G_1);
}
void interop_serverQ_L_60ContD___serialize__ (interop_serverQ_L_60Cont self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->ch, state);
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
    self->self = $step_deserialize(state);
    self->ch = $step_deserialize(state);
    self->C_cont = $step_deserialize(state);
    return self;
}
interop_serverQ_L_60Cont interop_serverQ_L_60ContG_new(interop_serverQ_main G_1, sshQ_ServerChannel G_2, $Cont G_3) {
    interop_serverQ_L_60Cont $tmp = acton_malloc(sizeof(struct interop_serverQ_L_60Cont));
    $tmp->$class = &interop_serverQ_L_60ContG_methods;
    interop_serverQ_L_60ContG_methods.__init__($tmp, G_1, G_2, G_3);
    return $tmp;
}
struct interop_serverQ_L_60ContG_class interop_serverQ_L_60ContG_methods;
$R interop_serverQ_L_52C_37cont ($Cont C_cont, B_bytes data, sshQ_ServerChannel ch, interop_serverQ_main self, B_NoneType C_38res) {
    if ($ISNOTNONE0(data)) {
        #line 101 "src/interop_server.act"
        ((B_Msg (*) ($WORD, B_bytes))((sshQ_ServerChannel)(ch))->$class->write)(ch, ((B_bytes)data));
        return $R_CONT((($Cont)interop_serverQ_L_54ContG_new(C_cont)), B_None);
    }
    else {
        return (($R (*) ($WORD, $Cont, sshQ_ServerChannel))((interop_serverQ_main)(self))->$class->mark_eofG_local)(self, (($Cont)interop_serverQ_L_60ContG_new(self, ch, C_cont)), ch);
    }
}
B_NoneType interop_serverQ_L_61ContD___init__ (interop_serverQ_L_61Cont L_self, $Cont C_cont, B_bytes data, sshQ_ServerChannel ch, interop_serverQ_main self) {
    ((interop_serverQ_L_61Cont)(L_self))->C_cont = C_cont;
    ((interop_serverQ_L_61Cont)(L_self))->data = data;
    ((interop_serverQ_L_61Cont)(L_self))->ch = ch;
    ((interop_serverQ_L_61Cont)(L_self))->self = self;
    return B_None;
}
$R interop_serverQ_L_61ContD___call__ (interop_serverQ_L_61Cont L_self, B_NoneType G_1) {
    $Cont C_cont = ((interop_serverQ_L_61Cont)(L_self))->C_cont;
    B_bytes data = ((interop_serverQ_L_61Cont)(L_self))->data;
    sshQ_ServerChannel ch = ((interop_serverQ_L_61Cont)(L_self))->ch;
    interop_serverQ_main self = ((interop_serverQ_L_61Cont)(L_self))->self;
    return interop_serverQ_L_52C_37cont(C_cont, data, ch, self, G_1);
}
void interop_serverQ_L_61ContD___serialize__ (interop_serverQ_L_61Cont self, $Serial$state state) {
    $step_serialize(self->C_cont, state);
    $step_serialize(self->data, state);
    $step_serialize(self->ch, state);
    $step_serialize(self->self, state);
}
interop_serverQ_L_61Cont interop_serverQ_L_61ContD___deserialize__ (interop_serverQ_L_61Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct interop_serverQ_L_61Cont));
            self->$class = &interop_serverQ_L_61ContG_methods;
            return self;
        }
        self = $DNEW(interop_serverQ_L_61Cont, state);
    }
    self->C_cont = $step_deserialize(state);
    self->data = $step_deserialize(state);
    self->ch = $step_deserialize(state);
    self->self = $step_deserialize(state);
    return self;
}
interop_serverQ_L_61Cont interop_serverQ_L_61ContG_new($Cont G_1, B_bytes G_2, sshQ_ServerChannel G_3, interop_serverQ_main G_4) {
    interop_serverQ_L_61Cont $tmp = acton_malloc(sizeof(struct interop_serverQ_L_61Cont));
    $tmp->$class = &interop_serverQ_L_61ContG_methods;
    interop_serverQ_L_61ContG_methods.__init__($tmp, G_1, G_2, G_3, G_4);
    return $tmp;
}
struct interop_serverQ_L_61ContG_class interop_serverQ_L_61ContG_methods;
$R interop_serverQ_L_51C_35cont ($Cont C_cont, B_bytes data, sshQ_ServerChannel ch, interop_serverQ_main self, B_str C_36res) {
    B_str C_1pre = C_36res;
    if (((B_bool)((B_bool (*) ($WORD, B_str, B_str))((B_Eq)(interop_serverQ_W_main_1194))->$class->__eq__)(interop_serverQ_W_main_1194, C_1pre, to$str("exec")))->val) {
        return $R_CONT(C_cont, B_None);
    }
    else {
        return $R_CONT((($Cont)interop_serverQ_L_61ContG_new(C_cont, data, ch, self)), B_None);
    }
}
B_NoneType interop_serverQ_L_62ContD___init__ (interop_serverQ_L_62Cont L_self, $Cont C_cont, B_bytes data, sshQ_ServerChannel ch, interop_serverQ_main self) {
    ((interop_serverQ_L_62Cont)(L_self))->C_cont = C_cont;
    ((interop_serverQ_L_62Cont)(L_self))->data = data;
    ((interop_serverQ_L_62Cont)(L_self))->ch = ch;
    ((interop_serverQ_L_62Cont)(L_self))->self = self;
    return B_None;
}
$R interop_serverQ_L_62ContD___call__ (interop_serverQ_L_62Cont L_self, B_str G_1) {
    $Cont C_cont = ((interop_serverQ_L_62Cont)(L_self))->C_cont;
    B_bytes data = ((interop_serverQ_L_62Cont)(L_self))->data;
    sshQ_ServerChannel ch = ((interop_serverQ_L_62Cont)(L_self))->ch;
    interop_serverQ_main self = ((interop_serverQ_L_62Cont)(L_self))->self;
    return interop_serverQ_L_51C_35cont(C_cont, data, ch, self, G_1);
}
void interop_serverQ_L_62ContD___serialize__ (interop_serverQ_L_62Cont self, $Serial$state state) {
    $step_serialize(self->C_cont, state);
    $step_serialize(self->data, state);
    $step_serialize(self->ch, state);
    $step_serialize(self->self, state);
}
interop_serverQ_L_62Cont interop_serverQ_L_62ContD___deserialize__ (interop_serverQ_L_62Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct interop_serverQ_L_62Cont));
            self->$class = &interop_serverQ_L_62ContG_methods;
            return self;
        }
        self = $DNEW(interop_serverQ_L_62Cont, state);
    }
    self->C_cont = $step_deserialize(state);
    self->data = $step_deserialize(state);
    self->ch = $step_deserialize(state);
    self->self = $step_deserialize(state);
    return self;
}
interop_serverQ_L_62Cont interop_serverQ_L_62ContG_new($Cont G_1, B_bytes G_2, sshQ_ServerChannel G_3, interop_serverQ_main G_4) {
    interop_serverQ_L_62Cont $tmp = acton_malloc(sizeof(struct interop_serverQ_L_62Cont));
    $tmp->$class = &interop_serverQ_L_62ContG_methods;
    interop_serverQ_L_62ContG_methods.__init__($tmp, G_1, G_2, G_3, G_4);
    return $tmp;
}
struct interop_serverQ_L_62ContG_class interop_serverQ_L_62ContG_methods;
$R interop_serverQ_L_63C_45cont (sshQ_ServerSession sess, $Cont C_cont, sshQ_ServerChannel C_46res) {
    sshQ_ServerChannel C_3pre = C_46res;
    #line 114 "src/interop_server.act"
    ((B_Msg (*) ($WORD, sshQ_ServerChannel))((sshQ_ServerSession)(sess))->$class->accept_channel)(sess, C_3pre);
    return $R_CONT(C_cont, B_None);
}
B_NoneType interop_serverQ_L_64ContD___init__ (interop_serverQ_L_64Cont L_self, sshQ_ServerSession sess, $Cont C_cont) {
    ((interop_serverQ_L_64Cont)(L_self))->sess = sess;
    ((interop_serverQ_L_64Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R interop_serverQ_L_64ContD___call__ (interop_serverQ_L_64Cont L_self, sshQ_ServerChannel G_1) {
    sshQ_ServerSession sess = ((interop_serverQ_L_64Cont)(L_self))->sess;
    $Cont C_cont = ((interop_serverQ_L_64Cont)(L_self))->C_cont;
    return interop_serverQ_L_63C_45cont(sess, C_cont, G_1);
}
void interop_serverQ_L_64ContD___serialize__ (interop_serverQ_L_64Cont self, $Serial$state state) {
    $step_serialize(self->sess, state);
    $step_serialize(self->C_cont, state);
}
interop_serverQ_L_64Cont interop_serverQ_L_64ContD___deserialize__ (interop_serverQ_L_64Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct interop_serverQ_L_64Cont));
            self->$class = &interop_serverQ_L_64ContG_methods;
            return self;
        }
        self = $DNEW(interop_serverQ_L_64Cont, state);
    }
    self->sess = $step_deserialize(state);
    self->C_cont = $step_deserialize(state);
    return self;
}
interop_serverQ_L_64Cont interop_serverQ_L_64ContG_new(sshQ_ServerSession G_1, $Cont G_2) {
    interop_serverQ_L_64Cont $tmp = acton_malloc(sizeof(struct interop_serverQ_L_64Cont));
    $tmp->$class = &interop_serverQ_L_64ContG_methods;
    interop_serverQ_L_64ContG_methods.__init__($tmp, G_1, G_2);
    return $tmp;
}
struct interop_serverQ_L_64ContG_class interop_serverQ_L_64ContG_methods;
B_NoneType interop_serverQ_L_66actionD___init__ (interop_serverQ_L_66action L_self, interop_serverQ_main L_65obj) {
    ((interop_serverQ_L_66action)(L_self))->L_65obj = L_65obj;
    return B_None;
}
$R interop_serverQ_L_66actionD___call__ (interop_serverQ_L_66action L_self, $Cont L_cont, sshQ_ServerChannel G_1, B_bytes G_2) {
    return $AWAIT(L_cont, ((B_Msg (*) ($WORD, sshQ_ServerChannel, B_bytes))((interop_serverQ_L_66action)(L_self))->$class->__asyn__)(L_self, G_1, G_2));
}
$R interop_serverQ_L_66actionD___exec__ (interop_serverQ_L_66action L_self, $Cont L_cont, sshQ_ServerChannel G_1, B_bytes G_2) {
    return $R_CONT(L_cont, ((B_Msg (*) ($WORD, sshQ_ServerChannel, B_bytes))((interop_serverQ_L_66action)(L_self))->$class->__asyn__)(L_self, G_1, G_2));
}
B_Msg interop_serverQ_L_66actionD___asyn__ (interop_serverQ_L_66action L_self, sshQ_ServerChannel G_1, B_bytes G_2) {
    interop_serverQ_main L_65obj = ((interop_serverQ_L_66action)(L_self))->L_65obj;
    return ((B_Msg (*) ($WORD, sshQ_ServerChannel, B_bytes))((interop_serverQ_main)(L_65obj))->$class->srv_on_data)(L_65obj, G_1, G_2);
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
B_NoneType interop_serverQ_L_68actionD___init__ (interop_serverQ_L_68action L_self, interop_serverQ_main L_67obj) {
    ((interop_serverQ_L_68action)(L_self))->L_67obj = L_67obj;
    return B_None;
}
$R interop_serverQ_L_68actionD___call__ (interop_serverQ_L_68action L_self, $Cont L_cont, sshQ_ServerChannel G_1, B_bytes G_2) {
    return $AWAIT(L_cont, ((B_Msg (*) ($WORD, sshQ_ServerChannel, B_bytes))((interop_serverQ_L_68action)(L_self))->$class->__asyn__)(L_self, G_1, G_2));
}
$R interop_serverQ_L_68actionD___exec__ (interop_serverQ_L_68action L_self, $Cont L_cont, sshQ_ServerChannel G_1, B_bytes G_2) {
    return $R_CONT(L_cont, ((B_Msg (*) ($WORD, sshQ_ServerChannel, B_bytes))((interop_serverQ_L_68action)(L_self))->$class->__asyn__)(L_self, G_1, G_2));
}
B_Msg interop_serverQ_L_68actionD___asyn__ (interop_serverQ_L_68action L_self, sshQ_ServerChannel G_1, B_bytes G_2) {
    interop_serverQ_main L_67obj = ((interop_serverQ_L_68action)(L_self))->L_67obj;
    return ((B_Msg (*) ($WORD, sshQ_ServerChannel, B_bytes))((interop_serverQ_main)(L_67obj))->$class->srv_on_stderr)(L_67obj, G_1, G_2);
}
void interop_serverQ_L_68actionD___serialize__ (interop_serverQ_L_68action self, $Serial$state state) {
    $step_serialize(self->L_67obj, state);
}
interop_serverQ_L_68action interop_serverQ_L_68actionD___deserialize__ (interop_serverQ_L_68action self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct interop_serverQ_L_68action));
            self->$class = &interop_serverQ_L_68actionG_methods;
            return self;
        }
        self = $DNEW(interop_serverQ_L_68action, state);
    }
    self->L_67obj = $step_deserialize(state);
    return self;
}
interop_serverQ_L_68action interop_serverQ_L_68actionG_new(interop_serverQ_main G_1) {
    interop_serverQ_L_68action $tmp = acton_malloc(sizeof(struct interop_serverQ_L_68action));
    $tmp->$class = &interop_serverQ_L_68actionG_methods;
    interop_serverQ_L_68actionG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct interop_serverQ_L_68actionG_class interop_serverQ_L_68actionG_methods;
B_NoneType interop_serverQ_L_70actionD___init__ (interop_serverQ_L_70action L_self, interop_serverQ_main L_69obj) {
    ((interop_serverQ_L_70action)(L_self))->L_69obj = L_69obj;
    return B_None;
}
$R interop_serverQ_L_70actionD___call__ (interop_serverQ_L_70action L_self, $Cont L_cont, sshQ_ServerChannel G_1, B_str G_2) {
    return $AWAIT(L_cont, ((B_Msg (*) ($WORD, sshQ_ServerChannel, B_str))((interop_serverQ_L_70action)(L_self))->$class->__asyn__)(L_self, G_1, G_2));
}
$R interop_serverQ_L_70actionD___exec__ (interop_serverQ_L_70action L_self, $Cont L_cont, sshQ_ServerChannel G_1, B_str G_2) {
    return $R_CONT(L_cont, ((B_Msg (*) ($WORD, sshQ_ServerChannel, B_str))((interop_serverQ_L_70action)(L_self))->$class->__asyn__)(L_self, G_1, G_2));
}
B_Msg interop_serverQ_L_70actionD___asyn__ (interop_serverQ_L_70action L_self, sshQ_ServerChannel G_1, B_str G_2) {
    interop_serverQ_main L_69obj = ((interop_serverQ_L_70action)(L_self))->L_69obj;
    return ((B_Msg (*) ($WORD, sshQ_ServerChannel, B_str))((interop_serverQ_main)(L_69obj))->$class->srv_on_close)(L_69obj, G_1, G_2);
}
void interop_serverQ_L_70actionD___serialize__ (interop_serverQ_L_70action self, $Serial$state state) {
    $step_serialize(self->L_69obj, state);
}
interop_serverQ_L_70action interop_serverQ_L_70actionD___deserialize__ (interop_serverQ_L_70action self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct interop_serverQ_L_70action));
            self->$class = &interop_serverQ_L_70actionG_methods;
            return self;
        }
        self = $DNEW(interop_serverQ_L_70action, state);
    }
    self->L_69obj = $step_deserialize(state);
    return self;
}
interop_serverQ_L_70action interop_serverQ_L_70actionG_new(interop_serverQ_main G_1) {
    interop_serverQ_L_70action $tmp = acton_malloc(sizeof(struct interop_serverQ_L_70action));
    $tmp->$class = &interop_serverQ_L_70actionG_methods;
    interop_serverQ_L_70actionG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct interop_serverQ_L_70actionG_class interop_serverQ_L_70actionG_methods;
$R interop_serverQ_L_71C_47cont (B_str cmd, sshQ_ServerChannel ch, $Cont C_cont, B_NoneType C_48res) {
    #line 118 "src/interop_server.act"
    if (((B_bool)((B_bool (*) ($WORD, B_str, B_str))((B_Eq)(interop_serverQ_W_main_1194))->$class->__eq__)(interop_serverQ_W_main_1194, cmd, to$str("ping")))->val) {
        #line 119 "src/interop_server.act"
        ((B_Msg (*) ($WORD))((sshQ_ServerChannel)(ch))->$class->accept_request)(ch);
        #line 120 "src/interop_server.act"
        ((B_Msg (*) ($WORD, B_bytes))((sshQ_ServerChannel)(ch))->$class->write)(ch, to$bytesD_len("pong\n", 5));
        #line 121 "src/interop_server.act"
        ((B_Msg (*) ($WORD, int64_t))((sshQ_ServerChannel)(ch))->$class->send_exit_status)(ch, 0LL);
        #line 122 "src/interop_server.act"
        ((B_Msg (*) ($WORD))((sshQ_ServerChannel)(ch))->$class->close)(ch);
    }
    else {
        #line 124 "src/interop_server.act"
        ((B_Msg (*) ($WORD))((sshQ_ServerChannel)(ch))->$class->accept_request)(ch);
        #line 125 "src/interop_server.act"
        ((B_Msg (*) ($WORD, B_bytes))((sshQ_ServerChannel)(ch))->$class->write_stderr)(ch, to$bytesD_len("unknown command\n", 16));
        #line 126 "src/interop_server.act"
        ((B_Msg (*) ($WORD, int64_t))((sshQ_ServerChannel)(ch))->$class->send_exit_status)(ch, 127LL);
        #line 127 "src/interop_server.act"
        ((B_Msg (*) ($WORD))((sshQ_ServerChannel)(ch))->$class->close)(ch);
    }
    return $R_CONT(C_cont, B_None);
}
B_NoneType interop_serverQ_L_72ContD___init__ (interop_serverQ_L_72Cont L_self, B_str cmd, sshQ_ServerChannel ch, $Cont C_cont) {
    ((interop_serverQ_L_72Cont)(L_self))->cmd = cmd;
    ((interop_serverQ_L_72Cont)(L_self))->ch = ch;
    ((interop_serverQ_L_72Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R interop_serverQ_L_72ContD___call__ (interop_serverQ_L_72Cont L_self, B_NoneType G_1) {
    B_str cmd = ((interop_serverQ_L_72Cont)(L_self))->cmd;
    sshQ_ServerChannel ch = ((interop_serverQ_L_72Cont)(L_self))->ch;
    $Cont C_cont = ((interop_serverQ_L_72Cont)(L_self))->C_cont;
    return interop_serverQ_L_71C_47cont(cmd, ch, C_cont, G_1);
}
void interop_serverQ_L_72ContD___serialize__ (interop_serverQ_L_72Cont self, $Serial$state state) {
    $step_serialize(self->cmd, state);
    $step_serialize(self->ch, state);
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
    self->cmd = $step_deserialize(state);
    self->ch = $step_deserialize(state);
    self->C_cont = $step_deserialize(state);
    return self;
}
interop_serverQ_L_72Cont interop_serverQ_L_72ContG_new(B_str G_1, sshQ_ServerChannel G_2, $Cont G_3) {
    interop_serverQ_L_72Cont $tmp = acton_malloc(sizeof(struct interop_serverQ_L_72Cont));
    $tmp->$class = &interop_serverQ_L_72ContG_methods;
    interop_serverQ_L_72ContG_methods.__init__($tmp, G_1, G_2, G_3);
    return $tmp;
}
struct interop_serverQ_L_72ContG_class interop_serverQ_L_72ContG_methods;
$R interop_serverQ_L_73C_49cont ($Cont C_cont, B_NoneType C_50res) {
    return $R_CONT(C_cont, B_None);
}
B_NoneType interop_serverQ_L_76ContD___init__ (interop_serverQ_L_76Cont L_self, $Cont C_cont) {
    ((interop_serverQ_L_76Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R interop_serverQ_L_76ContD___call__ (interop_serverQ_L_76Cont L_self, B_NoneType G_1) {
    $Cont C_cont = ((interop_serverQ_L_76Cont)(L_self))->C_cont;
    return interop_serverQ_L_73C_49cont(C_cont, G_1);
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
B_NoneType interop_serverQ_L_77ContD___init__ (interop_serverQ_L_77Cont L_self, $Cont C_cont) {
    ((interop_serverQ_L_77Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R interop_serverQ_L_77ContD___call__ (interop_serverQ_L_77Cont L_self, B_NoneType G_1) {
    $Cont C_cont = ((interop_serverQ_L_77Cont)(L_self))->C_cont;
    return interop_serverQ_L_73C_49cont(C_cont, G_1);
}
void interop_serverQ_L_77ContD___serialize__ (interop_serverQ_L_77Cont self, $Serial$state state) {
    $step_serialize(self->C_cont, state);
}
interop_serverQ_L_77Cont interop_serverQ_L_77ContD___deserialize__ (interop_serverQ_L_77Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct interop_serverQ_L_77Cont));
            self->$class = &interop_serverQ_L_77ContG_methods;
            return self;
        }
        self = $DNEW(interop_serverQ_L_77Cont, state);
    }
    self->C_cont = $step_deserialize(state);
    return self;
}
interop_serverQ_L_77Cont interop_serverQ_L_77ContG_new($Cont G_1) {
    interop_serverQ_L_77Cont $tmp = acton_malloc(sizeof(struct interop_serverQ_L_77Cont));
    $tmp->$class = &interop_serverQ_L_77ContG_methods;
    interop_serverQ_L_77ContG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct interop_serverQ_L_77ContG_class interop_serverQ_L_77ContG_methods;
$R interop_serverQ_L_75C_53cont (interop_serverQ_main self, sshQ_ServerChannel ch, $Cont C_cont, B_bool C_54res) {
    B_bool C_4pre = C_54res;
    if (((B_bool)C_4pre)->val) {
        return (($R (*) ($WORD, $Cont, sshQ_ServerChannel))((interop_serverQ_main)(self))->$class->close_echoG_local)(self, (($Cont)interop_serverQ_L_76ContG_new(C_cont)), ch);
    }
    else {
        return $R_CONT((($Cont)interop_serverQ_L_77ContG_new(C_cont)), B_None);
    }
}
B_NoneType interop_serverQ_L_78ContD___init__ (interop_serverQ_L_78Cont L_self, interop_serverQ_main self, sshQ_ServerChannel ch, $Cont C_cont) {
    ((interop_serverQ_L_78Cont)(L_self))->self = self;
    ((interop_serverQ_L_78Cont)(L_self))->ch = ch;
    ((interop_serverQ_L_78Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R interop_serverQ_L_78ContD___call__ (interop_serverQ_L_78Cont L_self, B_bool G_1) {
    interop_serverQ_main self = ((interop_serverQ_L_78Cont)(L_self))->self;
    sshQ_ServerChannel ch = ((interop_serverQ_L_78Cont)(L_self))->ch;
    $Cont C_cont = ((interop_serverQ_L_78Cont)(L_self))->C_cont;
    return interop_serverQ_L_75C_53cont(self, ch, C_cont, G_1);
}
void interop_serverQ_L_78ContD___serialize__ (interop_serverQ_L_78Cont self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->ch, state);
    $step_serialize(self->C_cont, state);
}
interop_serverQ_L_78Cont interop_serverQ_L_78ContD___deserialize__ (interop_serverQ_L_78Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct interop_serverQ_L_78Cont));
            self->$class = &interop_serverQ_L_78ContG_methods;
            return self;
        }
        self = $DNEW(interop_serverQ_L_78Cont, state);
    }
    self->self = $step_deserialize(state);
    self->ch = $step_deserialize(state);
    self->C_cont = $step_deserialize(state);
    return self;
}
interop_serverQ_L_78Cont interop_serverQ_L_78ContG_new(interop_serverQ_main G_1, sshQ_ServerChannel G_2, $Cont G_3) {
    interop_serverQ_L_78Cont $tmp = acton_malloc(sizeof(struct interop_serverQ_L_78Cont));
    $tmp->$class = &interop_serverQ_L_78ContG_methods;
    interop_serverQ_L_78ContG_methods.__init__($tmp, G_1, G_2, G_3);
    return $tmp;
}
struct interop_serverQ_L_78ContG_class interop_serverQ_L_78ContG_methods;
$R interop_serverQ_L_74C_51cont (sshQ_ServerChannel ch, interop_serverQ_main self, $Cont C_cont, B_NoneType C_52res) {
    #line 132 "src/interop_server.act"
    ((B_Msg (*) ($WORD))((sshQ_ServerChannel)(ch))->$class->accept_request)(ch);
    return (($R (*) ($WORD, $Cont, sshQ_ServerChannel))((interop_serverQ_main)(self))->$class->saw_eofG_local)(self, (($Cont)interop_serverQ_L_78ContG_new(self, ch, C_cont)), ch);
}
B_NoneType interop_serverQ_L_79ContD___init__ (interop_serverQ_L_79Cont L_self, sshQ_ServerChannel ch, interop_serverQ_main self, $Cont C_cont) {
    ((interop_serverQ_L_79Cont)(L_self))->ch = ch;
    ((interop_serverQ_L_79Cont)(L_self))->self = self;
    ((interop_serverQ_L_79Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R interop_serverQ_L_79ContD___call__ (interop_serverQ_L_79Cont L_self, B_NoneType G_1) {
    sshQ_ServerChannel ch = ((interop_serverQ_L_79Cont)(L_self))->ch;
    interop_serverQ_main self = ((interop_serverQ_L_79Cont)(L_self))->self;
    $Cont C_cont = ((interop_serverQ_L_79Cont)(L_self))->C_cont;
    return interop_serverQ_L_74C_51cont(ch, self, C_cont, G_1);
}
void interop_serverQ_L_79ContD___serialize__ (interop_serverQ_L_79Cont self, $Serial$state state) {
    $step_serialize(self->ch, state);
    $step_serialize(self->self, state);
    $step_serialize(self->C_cont, state);
}
interop_serverQ_L_79Cont interop_serverQ_L_79ContD___deserialize__ (interop_serverQ_L_79Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct interop_serverQ_L_79Cont));
            self->$class = &interop_serverQ_L_79ContG_methods;
            return self;
        }
        self = $DNEW(interop_serverQ_L_79Cont, state);
    }
    self->ch = $step_deserialize(state);
    self->self = $step_deserialize(state);
    self->C_cont = $step_deserialize(state);
    return self;
}
interop_serverQ_L_79Cont interop_serverQ_L_79ContG_new(sshQ_ServerChannel G_1, interop_serverQ_main G_2, $Cont G_3) {
    interop_serverQ_L_79Cont $tmp = acton_malloc(sizeof(struct interop_serverQ_L_79Cont));
    $tmp->$class = &interop_serverQ_L_79ContG_methods;
    interop_serverQ_L_79ContG_methods.__init__($tmp, G_1, G_2, G_3);
    return $tmp;
}
struct interop_serverQ_L_79ContG_class interop_serverQ_L_79ContG_methods;
B_NoneType interop_serverQ_L_80ContD___init__ (interop_serverQ_L_80Cont L_self, $Cont C_cont) {
    ((interop_serverQ_L_80Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R interop_serverQ_L_80ContD___call__ (interop_serverQ_L_80Cont L_self, B_NoneType G_1) {
    $Cont C_cont = ((interop_serverQ_L_80Cont)(L_self))->C_cont;
    return interop_serverQ_L_73C_49cont(C_cont, G_1);
}
void interop_serverQ_L_80ContD___serialize__ (interop_serverQ_L_80Cont self, $Serial$state state) {
    $step_serialize(self->C_cont, state);
}
interop_serverQ_L_80Cont interop_serverQ_L_80ContD___deserialize__ (interop_serverQ_L_80Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct interop_serverQ_L_80Cont));
            self->$class = &interop_serverQ_L_80ContG_methods;
            return self;
        }
        self = $DNEW(interop_serverQ_L_80Cont, state);
    }
    self->C_cont = $step_deserialize(state);
    return self;
}
interop_serverQ_L_80Cont interop_serverQ_L_80ContG_new($Cont G_1) {
    interop_serverQ_L_80Cont $tmp = acton_malloc(sizeof(struct interop_serverQ_L_80Cont));
    $tmp->$class = &interop_serverQ_L_80ContG_methods;
    interop_serverQ_L_80ContG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct interop_serverQ_L_80ContG_class interop_serverQ_L_80ContG_methods;
B_NoneType interop_serverQ_L_81procD___init__ (interop_serverQ_L_81proc L_self, interop_serverQ_main self, sshQ_ServerChannel ch, B_str mode) {
    ((interop_serverQ_L_81proc)(L_self))->self = self;
    ((interop_serverQ_L_81proc)(L_self))->ch = ch;
    ((interop_serverQ_L_81proc)(L_self))->mode = mode;
    return B_None;
}
$R interop_serverQ_L_81procD___call__ (interop_serverQ_L_81proc L_self, $Cont C_cont) {
    interop_serverQ_main self = ((interop_serverQ_L_81proc)(L_self))->self;
    sshQ_ServerChannel ch = ((interop_serverQ_L_81proc)(L_self))->ch;
    B_str mode = ((interop_serverQ_L_81proc)(L_self))->mode;
    return (($R (*) ($WORD, $Cont, sshQ_ServerChannel, B_str))((interop_serverQ_main)(self))->$class->set_modeG_local)(self, C_cont, ch, mode);
}
$R interop_serverQ_L_81procD___exec__ (interop_serverQ_L_81proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((interop_serverQ_L_81proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void interop_serverQ_L_81procD___serialize__ (interop_serverQ_L_81proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->ch, state);
    $step_serialize(self->mode, state);
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
    self->mode = $step_deserialize(state);
    return self;
}
interop_serverQ_L_81proc interop_serverQ_L_81procG_new(interop_serverQ_main G_1, sshQ_ServerChannel G_2, B_str G_3) {
    interop_serverQ_L_81proc $tmp = acton_malloc(sizeof(struct interop_serverQ_L_81proc));
    $tmp->$class = &interop_serverQ_L_81procG_methods;
    interop_serverQ_L_81procG_methods.__init__($tmp, G_1, G_2, G_3);
    return $tmp;
}
struct interop_serverQ_L_81procG_class interop_serverQ_L_81procG_methods;
B_NoneType interop_serverQ_L_82procD___init__ (interop_serverQ_L_82proc L_self, interop_serverQ_main self, sshQ_ServerChannel ch) {
    ((interop_serverQ_L_82proc)(L_self))->self = self;
    ((interop_serverQ_L_82proc)(L_self))->ch = ch;
    return B_None;
}
$R interop_serverQ_L_82procD___call__ (interop_serverQ_L_82proc L_self, $Cont C_cont) {
    interop_serverQ_main self = ((interop_serverQ_L_82proc)(L_self))->self;
    sshQ_ServerChannel ch = ((interop_serverQ_L_82proc)(L_self))->ch;
    return (($R (*) ($WORD, $Cont, sshQ_ServerChannel))((interop_serverQ_main)(self))->$class->mode_ofG_local)(self, C_cont, ch);
}
$R interop_serverQ_L_82procD___exec__ (interop_serverQ_L_82proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((interop_serverQ_L_82proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void interop_serverQ_L_82procD___serialize__ (interop_serverQ_L_82proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->ch, state);
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
    self->ch = $step_deserialize(state);
    return self;
}
interop_serverQ_L_82proc interop_serverQ_L_82procG_new(interop_serverQ_main G_1, sshQ_ServerChannel G_2) {
    interop_serverQ_L_82proc $tmp = acton_malloc(sizeof(struct interop_serverQ_L_82proc));
    $tmp->$class = &interop_serverQ_L_82procG_methods;
    interop_serverQ_L_82procG_methods.__init__($tmp, G_1, G_2);
    return $tmp;
}
struct interop_serverQ_L_82procG_class interop_serverQ_L_82procG_methods;
B_NoneType interop_serverQ_L_83procD___init__ (interop_serverQ_L_83proc L_self, interop_serverQ_main self, sshQ_ServerChannel ch) {
    ((interop_serverQ_L_83proc)(L_self))->self = self;
    ((interop_serverQ_L_83proc)(L_self))->ch = ch;
    return B_None;
}
$R interop_serverQ_L_83procD___call__ (interop_serverQ_L_83proc L_self, $Cont C_cont) {
    interop_serverQ_main self = ((interop_serverQ_L_83proc)(L_self))->self;
    sshQ_ServerChannel ch = ((interop_serverQ_L_83proc)(L_self))->ch;
    return (($R (*) ($WORD, $Cont, sshQ_ServerChannel))((interop_serverQ_main)(self))->$class->mark_eofG_local)(self, C_cont, ch);
}
$R interop_serverQ_L_83procD___exec__ (interop_serverQ_L_83proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((interop_serverQ_L_83proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void interop_serverQ_L_83procD___serialize__ (interop_serverQ_L_83proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->ch, state);
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
    self->ch = $step_deserialize(state);
    return self;
}
interop_serverQ_L_83proc interop_serverQ_L_83procG_new(interop_serverQ_main G_1, sshQ_ServerChannel G_2) {
    interop_serverQ_L_83proc $tmp = acton_malloc(sizeof(struct interop_serverQ_L_83proc));
    $tmp->$class = &interop_serverQ_L_83procG_methods;
    interop_serverQ_L_83procG_methods.__init__($tmp, G_1, G_2);
    return $tmp;
}
struct interop_serverQ_L_83procG_class interop_serverQ_L_83procG_methods;
B_NoneType interop_serverQ_L_84procD___init__ (interop_serverQ_L_84proc L_self, interop_serverQ_main self, sshQ_ServerChannel ch) {
    ((interop_serverQ_L_84proc)(L_self))->self = self;
    ((interop_serverQ_L_84proc)(L_self))->ch = ch;
    return B_None;
}
$R interop_serverQ_L_84procD___call__ (interop_serverQ_L_84proc L_self, $Cont C_cont) {
    interop_serverQ_main self = ((interop_serverQ_L_84proc)(L_self))->self;
    sshQ_ServerChannel ch = ((interop_serverQ_L_84proc)(L_self))->ch;
    return (($R (*) ($WORD, $Cont, sshQ_ServerChannel))((interop_serverQ_main)(self))->$class->saw_eofG_local)(self, C_cont, ch);
}
$R interop_serverQ_L_84procD___exec__ (interop_serverQ_L_84proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((interop_serverQ_L_84proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void interop_serverQ_L_84procD___serialize__ (interop_serverQ_L_84proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->ch, state);
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
    self->ch = $step_deserialize(state);
    return self;
}
interop_serverQ_L_84proc interop_serverQ_L_84procG_new(interop_serverQ_main G_1, sshQ_ServerChannel G_2) {
    interop_serverQ_L_84proc $tmp = acton_malloc(sizeof(struct interop_serverQ_L_84proc));
    $tmp->$class = &interop_serverQ_L_84procG_methods;
    interop_serverQ_L_84procG_methods.__init__($tmp, G_1, G_2);
    return $tmp;
}
struct interop_serverQ_L_84procG_class interop_serverQ_L_84procG_methods;
B_NoneType interop_serverQ_L_85procD___init__ (interop_serverQ_L_85proc L_self, interop_serverQ_main self, sshQ_ServerChannel ch) {
    ((interop_serverQ_L_85proc)(L_self))->self = self;
    ((interop_serverQ_L_85proc)(L_self))->ch = ch;
    return B_None;
}
$R interop_serverQ_L_85procD___call__ (interop_serverQ_L_85proc L_self, $Cont C_cont) {
    interop_serverQ_main self = ((interop_serverQ_L_85proc)(L_self))->self;
    sshQ_ServerChannel ch = ((interop_serverQ_L_85proc)(L_self))->ch;
    return (($R (*) ($WORD, $Cont, sshQ_ServerChannel))((interop_serverQ_main)(self))->$class->close_echoG_local)(self, C_cont, ch);
}
$R interop_serverQ_L_85procD___exec__ (interop_serverQ_L_85proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((interop_serverQ_L_85proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void interop_serverQ_L_85procD___serialize__ (interop_serverQ_L_85proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->ch, state);
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
    self->ch = $step_deserialize(state);
    return self;
}
interop_serverQ_L_85proc interop_serverQ_L_85procG_new(interop_serverQ_main G_1, sshQ_ServerChannel G_2) {
    interop_serverQ_L_85proc $tmp = acton_malloc(sizeof(struct interop_serverQ_L_85proc));
    $tmp->$class = &interop_serverQ_L_85procG_methods;
    interop_serverQ_L_85procG_methods.__init__($tmp, G_1, G_2);
    return $tmp;
}
struct interop_serverQ_L_85procG_class interop_serverQ_L_85procG_methods;
B_NoneType interop_serverQ_L_86procD___init__ (interop_serverQ_L_86proc L_self, interop_serverQ_main self, sshQ_Server s, B_str err) {
    ((interop_serverQ_L_86proc)(L_self))->self = self;
    ((interop_serverQ_L_86proc)(L_self))->s = s;
    ((interop_serverQ_L_86proc)(L_self))->err = err;
    return B_None;
}
$R interop_serverQ_L_86procD___call__ (interop_serverQ_L_86proc L_self, $Cont C_cont) {
    interop_serverQ_main self = ((interop_serverQ_L_86proc)(L_self))->self;
    sshQ_Server s = ((interop_serverQ_L_86proc)(L_self))->s;
    B_str err = ((interop_serverQ_L_86proc)(L_self))->err;
    return (($R (*) ($WORD, $Cont, sshQ_Server, B_str))((interop_serverQ_main)(self))->$class->on_listenG_local)(self, C_cont, s, err);
}
$R interop_serverQ_L_86procD___exec__ (interop_serverQ_L_86proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((interop_serverQ_L_86proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void interop_serverQ_L_86procD___serialize__ (interop_serverQ_L_86proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->s, state);
    $step_serialize(self->err, state);
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
    self->s = $step_deserialize(state);
    self->err = $step_deserialize(state);
    return self;
}
interop_serverQ_L_86proc interop_serverQ_L_86procG_new(interop_serverQ_main G_1, sshQ_Server G_2, B_str G_3) {
    interop_serverQ_L_86proc $tmp = acton_malloc(sizeof(struct interop_serverQ_L_86proc));
    $tmp->$class = &interop_serverQ_L_86procG_methods;
    interop_serverQ_L_86procG_methods.__init__($tmp, G_1, G_2, G_3);
    return $tmp;
}
struct interop_serverQ_L_86procG_class interop_serverQ_L_86procG_methods;
B_NoneType interop_serverQ_L_87procD___init__ (interop_serverQ_L_87proc L_self, interop_serverQ_main self, sshQ_Server s, B_str reason) {
    ((interop_serverQ_L_87proc)(L_self))->self = self;
    ((interop_serverQ_L_87proc)(L_self))->s = s;
    ((interop_serverQ_L_87proc)(L_self))->reason = reason;
    return B_None;
}
$R interop_serverQ_L_87procD___call__ (interop_serverQ_L_87proc L_self, $Cont C_cont) {
    interop_serverQ_main self = ((interop_serverQ_L_87proc)(L_self))->self;
    sshQ_Server s = ((interop_serverQ_L_87proc)(L_self))->s;
    B_str reason = ((interop_serverQ_L_87proc)(L_self))->reason;
    return (($R (*) ($WORD, $Cont, sshQ_Server, B_str))((interop_serverQ_main)(self))->$class->on_server_closeG_local)(self, C_cont, s, reason);
}
$R interop_serverQ_L_87procD___exec__ (interop_serverQ_L_87proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((interop_serverQ_L_87proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void interop_serverQ_L_87procD___serialize__ (interop_serverQ_L_87proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->s, state);
    $step_serialize(self->reason, state);
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
    self->s = $step_deserialize(state);
    self->reason = $step_deserialize(state);
    return self;
}
interop_serverQ_L_87proc interop_serverQ_L_87procG_new(interop_serverQ_main G_1, sshQ_Server G_2, B_str G_3) {
    interop_serverQ_L_87proc $tmp = acton_malloc(sizeof(struct interop_serverQ_L_87proc));
    $tmp->$class = &interop_serverQ_L_87procG_methods;
    interop_serverQ_L_87procG_methods.__init__($tmp, G_1, G_2, G_3);
    return $tmp;
}
struct interop_serverQ_L_87procG_class interop_serverQ_L_87procG_methods;
B_NoneType interop_serverQ_L_88procD___init__ (interop_serverQ_L_88proc L_self, interop_serverQ_main self, sshQ_ServerSession sess) {
    ((interop_serverQ_L_88proc)(L_self))->self = self;
    ((interop_serverQ_L_88proc)(L_self))->sess = sess;
    return B_None;
}
$R interop_serverQ_L_88procD___call__ (interop_serverQ_L_88proc L_self, $Cont C_cont) {
    interop_serverQ_main self = ((interop_serverQ_L_88proc)(L_self))->self;
    sshQ_ServerSession sess = ((interop_serverQ_L_88proc)(L_self))->sess;
    return (($R (*) ($WORD, $Cont, sshQ_ServerSession))((interop_serverQ_main)(self))->$class->on_sessionG_local)(self, C_cont, sess);
}
$R interop_serverQ_L_88procD___exec__ (interop_serverQ_L_88proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((interop_serverQ_L_88proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void interop_serverQ_L_88procD___serialize__ (interop_serverQ_L_88proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->sess, state);
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
    self->sess = $step_deserialize(state);
    return self;
}
interop_serverQ_L_88proc interop_serverQ_L_88procG_new(interop_serverQ_main G_1, sshQ_ServerSession G_2) {
    interop_serverQ_L_88proc $tmp = acton_malloc(sizeof(struct interop_serverQ_L_88proc));
    $tmp->$class = &interop_serverQ_L_88procG_methods;
    interop_serverQ_L_88procG_methods.__init__($tmp, G_1, G_2);
    return $tmp;
}
struct interop_serverQ_L_88procG_class interop_serverQ_L_88procG_methods;
B_NoneType interop_serverQ_L_89procD___init__ (interop_serverQ_L_89proc L_self, interop_serverQ_main self, sshQ_ServerSession sess, B_str reason) {
    ((interop_serverQ_L_89proc)(L_self))->self = self;
    ((interop_serverQ_L_89proc)(L_self))->sess = sess;
    ((interop_serverQ_L_89proc)(L_self))->reason = reason;
    return B_None;
}
$R interop_serverQ_L_89procD___call__ (interop_serverQ_L_89proc L_self, $Cont C_cont) {
    interop_serverQ_main self = ((interop_serverQ_L_89proc)(L_self))->self;
    sshQ_ServerSession sess = ((interop_serverQ_L_89proc)(L_self))->sess;
    B_str reason = ((interop_serverQ_L_89proc)(L_self))->reason;
    return (($R (*) ($WORD, $Cont, sshQ_ServerSession, B_str))((interop_serverQ_main)(self))->$class->on_session_closeG_local)(self, C_cont, sess, reason);
}
$R interop_serverQ_L_89procD___exec__ (interop_serverQ_L_89proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((interop_serverQ_L_89proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void interop_serverQ_L_89procD___serialize__ (interop_serverQ_L_89proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->sess, state);
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
    self->sess = $step_deserialize(state);
    self->reason = $step_deserialize(state);
    return self;
}
interop_serverQ_L_89proc interop_serverQ_L_89procG_new(interop_serverQ_main G_1, sshQ_ServerSession G_2, B_str G_3) {
    interop_serverQ_L_89proc $tmp = acton_malloc(sizeof(struct interop_serverQ_L_89proc));
    $tmp->$class = &interop_serverQ_L_89procG_methods;
    interop_serverQ_L_89procG_methods.__init__($tmp, G_1, G_2, G_3);
    return $tmp;
}
struct interop_serverQ_L_89procG_class interop_serverQ_L_89procG_methods;
B_NoneType interop_serverQ_L_90procD___init__ (interop_serverQ_L_90proc L_self, interop_serverQ_main self, sshQ_ServerSession sess, sshQ_AuthRequest req) {
    ((interop_serverQ_L_90proc)(L_self))->self = self;
    ((interop_serverQ_L_90proc)(L_self))->sess = sess;
    ((interop_serverQ_L_90proc)(L_self))->req = req;
    return B_None;
}
$R interop_serverQ_L_90procD___call__ (interop_serverQ_L_90proc L_self, $Cont C_cont) {
    interop_serverQ_main self = ((interop_serverQ_L_90proc)(L_self))->self;
    sshQ_ServerSession sess = ((interop_serverQ_L_90proc)(L_self))->sess;
    sshQ_AuthRequest req = ((interop_serverQ_L_90proc)(L_self))->req;
    return (($R (*) ($WORD, $Cont, sshQ_ServerSession, sshQ_AuthRequest))((interop_serverQ_main)(self))->$class->on_authG_local)(self, C_cont, sess, req);
}
$R interop_serverQ_L_90procD___exec__ (interop_serverQ_L_90proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((interop_serverQ_L_90proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void interop_serverQ_L_90procD___serialize__ (interop_serverQ_L_90proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->sess, state);
    $step_serialize(self->req, state);
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
    self->req = $step_deserialize(state);
    return self;
}
interop_serverQ_L_90proc interop_serverQ_L_90procG_new(interop_serverQ_main G_1, sshQ_ServerSession G_2, sshQ_AuthRequest G_3) {
    interop_serverQ_L_90proc $tmp = acton_malloc(sizeof(struct interop_serverQ_L_90proc));
    $tmp->$class = &interop_serverQ_L_90procG_methods;
    interop_serverQ_L_90procG_methods.__init__($tmp, G_1, G_2, G_3);
    return $tmp;
}
struct interop_serverQ_L_90procG_class interop_serverQ_L_90procG_methods;
B_NoneType interop_serverQ_L_91procD___init__ (interop_serverQ_L_91proc L_self, interop_serverQ_main self, sshQ_ServerChannel ch, B_bytes data) {
    ((interop_serverQ_L_91proc)(L_self))->self = self;
    ((interop_serverQ_L_91proc)(L_self))->ch = ch;
    ((interop_serverQ_L_91proc)(L_self))->data = data;
    return B_None;
}
$R interop_serverQ_L_91procD___call__ (interop_serverQ_L_91proc L_self, $Cont C_cont) {
    interop_serverQ_main self = ((interop_serverQ_L_91proc)(L_self))->self;
    sshQ_ServerChannel ch = ((interop_serverQ_L_91proc)(L_self))->ch;
    B_bytes data = ((interop_serverQ_L_91proc)(L_self))->data;
    return (($R (*) ($WORD, $Cont, sshQ_ServerChannel, B_bytes))((interop_serverQ_main)(self))->$class->srv_on_dataG_local)(self, C_cont, ch, data);
}
$R interop_serverQ_L_91procD___exec__ (interop_serverQ_L_91proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((interop_serverQ_L_91proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void interop_serverQ_L_91procD___serialize__ (interop_serverQ_L_91proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->ch, state);
    $step_serialize(self->data, state);
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
    self->ch = $step_deserialize(state);
    self->data = $step_deserialize(state);
    return self;
}
interop_serverQ_L_91proc interop_serverQ_L_91procG_new(interop_serverQ_main G_1, sshQ_ServerChannel G_2, B_bytes G_3) {
    interop_serverQ_L_91proc $tmp = acton_malloc(sizeof(struct interop_serverQ_L_91proc));
    $tmp->$class = &interop_serverQ_L_91procG_methods;
    interop_serverQ_L_91procG_methods.__init__($tmp, G_1, G_2, G_3);
    return $tmp;
}
struct interop_serverQ_L_91procG_class interop_serverQ_L_91procG_methods;
B_NoneType interop_serverQ_L_92procD___init__ (interop_serverQ_L_92proc L_self, interop_serverQ_main self, sshQ_ServerChannel ch, B_bytes data) {
    ((interop_serverQ_L_92proc)(L_self))->self = self;
    ((interop_serverQ_L_92proc)(L_self))->ch = ch;
    ((interop_serverQ_L_92proc)(L_self))->data = data;
    return B_None;
}
$R interop_serverQ_L_92procD___call__ (interop_serverQ_L_92proc L_self, $Cont C_cont) {
    interop_serverQ_main self = ((interop_serverQ_L_92proc)(L_self))->self;
    sshQ_ServerChannel ch = ((interop_serverQ_L_92proc)(L_self))->ch;
    B_bytes data = ((interop_serverQ_L_92proc)(L_self))->data;
    return (($R (*) ($WORD, $Cont, sshQ_ServerChannel, B_bytes))((interop_serverQ_main)(self))->$class->srv_on_stderrG_local)(self, C_cont, ch, data);
}
$R interop_serverQ_L_92procD___exec__ (interop_serverQ_L_92proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((interop_serverQ_L_92proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void interop_serverQ_L_92procD___serialize__ (interop_serverQ_L_92proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->ch, state);
    $step_serialize(self->data, state);
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
    self->ch = $step_deserialize(state);
    self->data = $step_deserialize(state);
    return self;
}
interop_serverQ_L_92proc interop_serverQ_L_92procG_new(interop_serverQ_main G_1, sshQ_ServerChannel G_2, B_bytes G_3) {
    interop_serverQ_L_92proc $tmp = acton_malloc(sizeof(struct interop_serverQ_L_92proc));
    $tmp->$class = &interop_serverQ_L_92procG_methods;
    interop_serverQ_L_92procG_methods.__init__($tmp, G_1, G_2, G_3);
    return $tmp;
}
struct interop_serverQ_L_92procG_class interop_serverQ_L_92procG_methods;
B_NoneType interop_serverQ_L_93procD___init__ (interop_serverQ_L_93proc L_self, interop_serverQ_main self, sshQ_ServerChannel ch, B_str reason) {
    ((interop_serverQ_L_93proc)(L_self))->self = self;
    ((interop_serverQ_L_93proc)(L_self))->ch = ch;
    ((interop_serverQ_L_93proc)(L_self))->reason = reason;
    return B_None;
}
$R interop_serverQ_L_93procD___call__ (interop_serverQ_L_93proc L_self, $Cont C_cont) {
    interop_serverQ_main self = ((interop_serverQ_L_93proc)(L_self))->self;
    sshQ_ServerChannel ch = ((interop_serverQ_L_93proc)(L_self))->ch;
    B_str reason = ((interop_serverQ_L_93proc)(L_self))->reason;
    return (($R (*) ($WORD, $Cont, sshQ_ServerChannel, B_str))((interop_serverQ_main)(self))->$class->srv_on_closeG_local)(self, C_cont, ch, reason);
}
$R interop_serverQ_L_93procD___exec__ (interop_serverQ_L_93proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((interop_serverQ_L_93proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void interop_serverQ_L_93procD___serialize__ (interop_serverQ_L_93proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->ch, state);
    $step_serialize(self->reason, state);
}
interop_serverQ_L_93proc interop_serverQ_L_93procD___deserialize__ (interop_serverQ_L_93proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct interop_serverQ_L_93proc));
            self->$class = &interop_serverQ_L_93procG_methods;
            return self;
        }
        self = $DNEW(interop_serverQ_L_93proc, state);
    }
    self->self = $step_deserialize(state);
    self->ch = $step_deserialize(state);
    self->reason = $step_deserialize(state);
    return self;
}
interop_serverQ_L_93proc interop_serverQ_L_93procG_new(interop_serverQ_main G_1, sshQ_ServerChannel G_2, B_str G_3) {
    interop_serverQ_L_93proc $tmp = acton_malloc(sizeof(struct interop_serverQ_L_93proc));
    $tmp->$class = &interop_serverQ_L_93procG_methods;
    interop_serverQ_L_93procG_methods.__init__($tmp, G_1, G_2, G_3);
    return $tmp;
}
struct interop_serverQ_L_93procG_class interop_serverQ_L_93procG_methods;
B_NoneType interop_serverQ_L_94procD___init__ (interop_serverQ_L_94proc L_self, interop_serverQ_main self, sshQ_ServerSession sess) {
    ((interop_serverQ_L_94proc)(L_self))->self = self;
    ((interop_serverQ_L_94proc)(L_self))->sess = sess;
    return B_None;
}
$R interop_serverQ_L_94procD___call__ (interop_serverQ_L_94proc L_self, $Cont C_cont) {
    interop_serverQ_main self = ((interop_serverQ_L_94proc)(L_self))->self;
    sshQ_ServerSession sess = ((interop_serverQ_L_94proc)(L_self))->sess;
    return (($R (*) ($WORD, $Cont, sshQ_ServerSession))((interop_serverQ_main)(self))->$class->on_channel_openG_local)(self, C_cont, sess);
}
$R interop_serverQ_L_94procD___exec__ (interop_serverQ_L_94proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((interop_serverQ_L_94proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void interop_serverQ_L_94procD___serialize__ (interop_serverQ_L_94proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->sess, state);
}
interop_serverQ_L_94proc interop_serverQ_L_94procD___deserialize__ (interop_serverQ_L_94proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct interop_serverQ_L_94proc));
            self->$class = &interop_serverQ_L_94procG_methods;
            return self;
        }
        self = $DNEW(interop_serverQ_L_94proc, state);
    }
    self->self = $step_deserialize(state);
    self->sess = $step_deserialize(state);
    return self;
}
interop_serverQ_L_94proc interop_serverQ_L_94procG_new(interop_serverQ_main G_1, sshQ_ServerSession G_2) {
    interop_serverQ_L_94proc $tmp = acton_malloc(sizeof(struct interop_serverQ_L_94proc));
    $tmp->$class = &interop_serverQ_L_94procG_methods;
    interop_serverQ_L_94procG_methods.__init__($tmp, G_1, G_2);
    return $tmp;
}
struct interop_serverQ_L_94procG_class interop_serverQ_L_94procG_methods;
B_NoneType interop_serverQ_L_95procD___init__ (interop_serverQ_L_95proc L_self, interop_serverQ_main self, sshQ_ServerSession sess, sshQ_ServerChannel ch, B_str cmd) {
    ((interop_serverQ_L_95proc)(L_self))->self = self;
    ((interop_serverQ_L_95proc)(L_self))->sess = sess;
    ((interop_serverQ_L_95proc)(L_self))->ch = ch;
    ((interop_serverQ_L_95proc)(L_self))->cmd = cmd;
    return B_None;
}
$R interop_serverQ_L_95procD___call__ (interop_serverQ_L_95proc L_self, $Cont C_cont) {
    interop_serverQ_main self = ((interop_serverQ_L_95proc)(L_self))->self;
    sshQ_ServerSession sess = ((interop_serverQ_L_95proc)(L_self))->sess;
    sshQ_ServerChannel ch = ((interop_serverQ_L_95proc)(L_self))->ch;
    B_str cmd = ((interop_serverQ_L_95proc)(L_self))->cmd;
    return (($R (*) ($WORD, $Cont, sshQ_ServerSession, sshQ_ServerChannel, B_str))((interop_serverQ_main)(self))->$class->on_execG_local)(self, C_cont, sess, ch, cmd);
}
$R interop_serverQ_L_95procD___exec__ (interop_serverQ_L_95proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((interop_serverQ_L_95proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void interop_serverQ_L_95procD___serialize__ (interop_serverQ_L_95proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->sess, state);
    $step_serialize(self->ch, state);
    $step_serialize(self->cmd, state);
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
    self->self = $step_deserialize(state);
    self->sess = $step_deserialize(state);
    self->ch = $step_deserialize(state);
    self->cmd = $step_deserialize(state);
    return self;
}
interop_serverQ_L_95proc interop_serverQ_L_95procG_new(interop_serverQ_main G_1, sshQ_ServerSession G_2, sshQ_ServerChannel G_3, B_str G_4) {
    interop_serverQ_L_95proc $tmp = acton_malloc(sizeof(struct interop_serverQ_L_95proc));
    $tmp->$class = &interop_serverQ_L_95procG_methods;
    interop_serverQ_L_95procG_methods.__init__($tmp, G_1, G_2, G_3, G_4);
    return $tmp;
}
struct interop_serverQ_L_95procG_class interop_serverQ_L_95procG_methods;
B_NoneType interop_serverQ_L_96procD___init__ (interop_serverQ_L_96proc L_self, interop_serverQ_main self, sshQ_ServerSession sess, sshQ_ServerChannel ch, B_str name) {
    ((interop_serverQ_L_96proc)(L_self))->self = self;
    ((interop_serverQ_L_96proc)(L_self))->sess = sess;
    ((interop_serverQ_L_96proc)(L_self))->ch = ch;
    ((interop_serverQ_L_96proc)(L_self))->name = name;
    return B_None;
}
$R interop_serverQ_L_96procD___call__ (interop_serverQ_L_96proc L_self, $Cont C_cont) {
    interop_serverQ_main self = ((interop_serverQ_L_96proc)(L_self))->self;
    sshQ_ServerSession sess = ((interop_serverQ_L_96proc)(L_self))->sess;
    sshQ_ServerChannel ch = ((interop_serverQ_L_96proc)(L_self))->ch;
    B_str name = ((interop_serverQ_L_96proc)(L_self))->name;
    return (($R (*) ($WORD, $Cont, sshQ_ServerSession, sshQ_ServerChannel, B_str))((interop_serverQ_main)(self))->$class->on_subsystemG_local)(self, C_cont, sess, ch, name);
}
$R interop_serverQ_L_96procD___exec__ (interop_serverQ_L_96proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((interop_serverQ_L_96proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void interop_serverQ_L_96procD___serialize__ (interop_serverQ_L_96proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->sess, state);
    $step_serialize(self->ch, state);
    $step_serialize(self->name, state);
}
interop_serverQ_L_96proc interop_serverQ_L_96procD___deserialize__ (interop_serverQ_L_96proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct interop_serverQ_L_96proc));
            self->$class = &interop_serverQ_L_96procG_methods;
            return self;
        }
        self = $DNEW(interop_serverQ_L_96proc, state);
    }
    self->self = $step_deserialize(state);
    self->sess = $step_deserialize(state);
    self->ch = $step_deserialize(state);
    self->name = $step_deserialize(state);
    return self;
}
interop_serverQ_L_96proc interop_serverQ_L_96procG_new(interop_serverQ_main G_1, sshQ_ServerSession G_2, sshQ_ServerChannel G_3, B_str G_4) {
    interop_serverQ_L_96proc $tmp = acton_malloc(sizeof(struct interop_serverQ_L_96proc));
    $tmp->$class = &interop_serverQ_L_96procG_methods;
    interop_serverQ_L_96procG_methods.__init__($tmp, G_1, G_2, G_3, G_4);
    return $tmp;
}
struct interop_serverQ_L_96procG_class interop_serverQ_L_96procG_methods;
$R interop_serverQ_L_97C_55cont ($Cont C_cont, interop_serverQ_main G_act, B_NoneType C_56res) {
    return $R_CONT(C_cont, G_act);
}
B_NoneType interop_serverQ_L_98ContD___init__ (interop_serverQ_L_98Cont L_self, $Cont C_cont, interop_serverQ_main G_act) {
    ((interop_serverQ_L_98Cont)(L_self))->C_cont = C_cont;
    ((interop_serverQ_L_98Cont)(L_self))->G_act = G_act;
    return B_None;
}
$R interop_serverQ_L_98ContD___call__ (interop_serverQ_L_98Cont L_self, B_NoneType G_1) {
    $Cont C_cont = ((interop_serverQ_L_98Cont)(L_self))->C_cont;
    interop_serverQ_main G_act = ((interop_serverQ_L_98Cont)(L_self))->G_act;
    return interop_serverQ_L_97C_55cont(C_cont, G_act, G_1);
}
void interop_serverQ_L_98ContD___serialize__ (interop_serverQ_L_98Cont self, $Serial$state state) {
    $step_serialize(self->C_cont, state);
    $step_serialize(self->G_act, state);
}
interop_serverQ_L_98Cont interop_serverQ_L_98ContD___deserialize__ (interop_serverQ_L_98Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct interop_serverQ_L_98Cont));
            self->$class = &interop_serverQ_L_98ContG_methods;
            return self;
        }
        self = $DNEW(interop_serverQ_L_98Cont, state);
    }
    self->C_cont = $step_deserialize(state);
    self->G_act = $step_deserialize(state);
    return self;
}
interop_serverQ_L_98Cont interop_serverQ_L_98ContG_new($Cont G_1, interop_serverQ_main G_2) {
    interop_serverQ_L_98Cont $tmp = acton_malloc(sizeof(struct interop_serverQ_L_98Cont));
    $tmp->$class = &interop_serverQ_L_98ContG_methods;
    interop_serverQ_L_98ContG_methods.__init__($tmp, G_1, G_2);
    return $tmp;
}
struct interop_serverQ_L_98ContG_class interop_serverQ_L_98ContG_methods;
B_NoneType interop_serverQ_L_99procD___init__ (interop_serverQ_L_99proc L_self, interop_serverQ_main G_act, B_Env env) {
    ((interop_serverQ_L_99proc)(L_self))->G_act = G_act;
    ((interop_serverQ_L_99proc)(L_self))->env = env;
    return B_None;
}
$R interop_serverQ_L_99procD___call__ (interop_serverQ_L_99proc L_self, $Cont C_cont) {
    interop_serverQ_main G_act = ((interop_serverQ_L_99proc)(L_self))->G_act;
    B_Env env = ((interop_serverQ_L_99proc)(L_self))->env;
    return (($R (*) ($WORD, $Cont, B_Env))((interop_serverQ_main)(G_act))->$class->__init__)(G_act, C_cont, env);
}
$R interop_serverQ_L_99procD___exec__ (interop_serverQ_L_99proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((interop_serverQ_L_99proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void interop_serverQ_L_99procD___serialize__ (interop_serverQ_L_99proc self, $Serial$state state) {
    $step_serialize(self->G_act, state);
    $step_serialize(self->env, state);
}
interop_serverQ_L_99proc interop_serverQ_L_99procD___deserialize__ (interop_serverQ_L_99proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct interop_serverQ_L_99proc));
            self->$class = &interop_serverQ_L_99procG_methods;
            return self;
        }
        self = $DNEW(interop_serverQ_L_99proc, state);
    }
    self->G_act = $step_deserialize(state);
    self->env = $step_deserialize(state);
    return self;
}
interop_serverQ_L_99proc interop_serverQ_L_99procG_new(interop_serverQ_main G_1, B_Env G_2) {
    interop_serverQ_L_99proc $tmp = acton_malloc(sizeof(struct interop_serverQ_L_99proc));
    $tmp->$class = &interop_serverQ_L_99procG_methods;
    interop_serverQ_L_99procG_methods.__init__($tmp, G_1, G_2);
    return $tmp;
}
struct interop_serverQ_L_99procG_class interop_serverQ_L_99procG_methods;
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
    return $AWAIT((($Cont)interop_serverQ_L_20ContG_new(self, C_cont)), ((B_Msg (*) ($WORD, B_str))((B_Env)(((interop_serverQ_main)(self))->env))->$class->getenv)(((interop_serverQ_main)(self))->env, to$str("ACTON_SSH_AUTH_KEY")));
}
#line 33 "src/interop_server.act"
$R interop_serverQ_mainD_set_modeG_local (interop_serverQ_main self, $Cont C_cont, sshQ_ServerChannel ch, B_str mode) {
    B_Sequence W_main_46 = (B_Sequence)B_SequenceD_listG_witness;
    #line 34 "src/interop_server.act"
    ((B_NoneType (*) ($WORD, B_list, B_tuple))((B_Sequence)(W_main_46))->$class->append)(W_main_46, ((interop_serverQ_main)(self))->modes, $NEWTUPLE(2, ch, mode));
    return $R_CONT(C_cont, B_None);
}
#line 36 "src/interop_server.act"
$R interop_serverQ_mainD_mode_ofG_local (interop_serverQ_main self, $Cont C_cont, sshQ_ServerChannel ch) {
    B_Identity W_main_70 = ((B_Identity)$IdentityActorG_new());
    B_Iterable W_main_72 = (B_Iterable)B_SequenceD_listG_witness->W_Collection;
    B_Iterator N_iter = ((B_Iterator (*) ($WORD, B_list))((B_Iterable)(W_main_72))->$class->__iter__)(W_main_72, ((interop_serverQ_main)(self))->modes);
    return $PUSH_C((($Cont)interop_serverQ_L_32ContG_new(N_iter, W_main_70, ch, C_cont)));
}
#line 42 "src/interop_server.act"
$R interop_serverQ_mainD_mark_eofG_local (interop_serverQ_main self, $Cont C_cont, sshQ_ServerChannel ch) {
    B_Sequence W_main_89 = (B_Sequence)B_SequenceD_listG_witness;
    #line 43 "src/interop_server.act"
    ((B_NoneType (*) ($WORD, B_list, sshQ_ServerChannel))((B_Sequence)(W_main_89))->$class->append)(W_main_89, ((interop_serverQ_main)(self))->eofed, ch);
    return $R_CONT(C_cont, B_None);
}
#line 45 "src/interop_server.act"
$R interop_serverQ_mainD_saw_eofG_local (interop_serverQ_main self, $Cont C_cont, sshQ_ServerChannel ch) {
    B_Identity W_main_104 = ((B_Identity)$IdentityActorG_new());
    B_Iterable W_main_106 = (B_Iterable)B_SequenceD_listG_witness->W_Collection;
    B_Iterator N_4iter = ((B_Iterator (*) ($WORD, B_list))((B_Iterable)(W_main_106))->$class->__iter__)(W_main_106, ((interop_serverQ_main)(self))->eofed);
    return $PUSH_C((($Cont)interop_serverQ_L_44ContG_new(N_4iter, W_main_104, ch, C_cont)));
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
        return $R_CONT((($Cont)interop_serverQ_L_48ContG_new(C_cont, s)), B_None);
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
#line 78 "src/interop_server.act"
$R interop_serverQ_mainD_on_authG_local (interop_serverQ_main self, $Cont C_cont, sshQ_ServerSession sess, sshQ_AuthRequest req) {
    B_Eq W_main_389 = ((B_Eq)$EqOptG_new(interop_serverQ_W_main_424));
    if (((B_bool)((B_bool (*) ($WORD, B_str, B_str))((B_Eq)(interop_serverQ_W_main_1194))->$class->__eq__)(interop_serverQ_W_main_1194, ((sshQ_AuthRequest)(req))->method, to$str("publickey")))->val) {
        #line 80 "src/interop_server.act"
        B_str ak = ((interop_serverQ_main)(self))->auth_key;
        #line 81 "src/interop_server.act"
        B_bytes pk = ((sshQ_AuthRequest)(req))->pubkey;
        #line 82 "src/interop_server.act"
        if (((B_bool)$AND(B_bool, $AND(B_bool, $AND(B_bool, toB_bool($ISNOTNONE0(ak)), toB_bool($ISNOTNONE0(pk))), ((B_bool (*) ($WORD, B_str, B_str))((B_Eq)(interop_serverQ_W_main_322))->$class->__eq__)(interop_serverQ_W_main_322, ((sshQ_AuthRequest)(req))->user, ((interop_serverQ_main)(self))->USER)), ((B_bool (*) ($WORD, B_bytes, B_bytes))((B_Eq)(interop_serverQ_W_main_341))->$class->__eq__)(interop_serverQ_W_main_341, ((B_bytes)pk), ({ B_str $tmp = ((B_str)ak);
                                                                                                                                                                                                                                                                                                                                                                                                                                                            ((B_bytes (*) ($WORD))((B_str)($tmp))->$class->encode)($tmp); }))))->val) {
            #line 83 "src/interop_server.act"
            ((B_Msg (*) ($WORD))((sshQ_ServerSession)(sess))->$class->accept_auth)(sess);
        }
        else {
            #line 85 "src/interop_server.act"
            ((B_Msg (*) ($WORD, B_str))((sshQ_ServerSession)(sess))->$class->reject_auth)(sess, to$str("unauthorized key"));
        }
        return $R_CONT(C_cont, B_None);
    }
    else {
        return $R_CONT((($Cont)interop_serverQ_L_50ContG_new(req, self, W_main_389, sess, C_cont)), B_None);
    }
}
#line 92 "src/interop_server.act"
$R interop_serverQ_mainD_srv_on_dataG_local (interop_serverQ_main self, $Cont C_cont, sshQ_ServerChannel ch, B_bytes data) {
    return (($R (*) ($WORD, $Cont, sshQ_ServerChannel))((interop_serverQ_main)(self))->$class->mode_ofG_local)(self, (($Cont)interop_serverQ_L_62ContG_new(C_cont, data, ch, self)), ch);
}
#line 107 "src/interop_server.act"
$R interop_serverQ_mainD_srv_on_stderrG_local (interop_serverQ_main self, $Cont C_cont, sshQ_ServerChannel ch, B_bytes data) {
    #line 108 "src/interop_server.act"
    return $R_CONT(C_cont, B_None);
}
#line 110 "src/interop_server.act"
$R interop_serverQ_mainD_srv_on_closeG_local (interop_serverQ_main self, $Cont C_cont, sshQ_ServerChannel ch, B_str reason) {
    #line 111 "src/interop_server.act"
    return $R_CONT(C_cont, B_None);
}
#line 113 "src/interop_server.act"
$R interop_serverQ_mainD_on_channel_openG_local (interop_serverQ_main self, $Cont C_cont, sshQ_ServerSession sess) {
    return sshQ_ServerChannelG_newact((($Cont)interop_serverQ_L_64ContG_new(sess, C_cont)), sess, (($action)interop_serverQ_L_66actionG_new(self)), (($action)interop_serverQ_L_68actionG_new(self)), (($action)interop_serverQ_L_70actionG_new(self)));
}
#line 116 "src/interop_server.act"
$R interop_serverQ_mainD_on_execG_local (interop_serverQ_main self, $Cont C_cont, sshQ_ServerSession sess, sshQ_ServerChannel ch, B_str cmd) {
    return (($R (*) ($WORD, $Cont, sshQ_ServerChannel, B_str))((interop_serverQ_main)(self))->$class->set_modeG_local)(self, (($Cont)interop_serverQ_L_72ContG_new(cmd, ch, C_cont)), ch, to$str("exec"));
}
#line 129 "src/interop_server.act"
$R interop_serverQ_mainD_on_subsystemG_local (interop_serverQ_main self, $Cont C_cont, sshQ_ServerSession sess, sshQ_ServerChannel ch, B_str name) {
    if (((B_bool)((B_bool (*) ($WORD, B_str, B_str))((B_Eq)(interop_serverQ_W_main_1194))->$class->__eq__)(interop_serverQ_W_main_1194, name, to$str("echo")))->val) {
        return (($R (*) ($WORD, $Cont, sshQ_ServerChannel, B_str))((interop_serverQ_main)(self))->$class->set_modeG_local)(self, (($Cont)interop_serverQ_L_79ContG_new(ch, self, C_cont)), ch, to$str("echo"));
    }
    else {
        #line 136 "src/interop_server.act"
        ((B_Msg (*) ($WORD, B_str))((sshQ_ServerChannel)(ch))->$class->reject_request)(ch, to$str("unsupported subsystem"));
        return $R_CONT((($Cont)interop_serverQ_L_80ContG_new(C_cont)), B_None);
    }
}
B_Msg interop_serverQ_mainD_set_mode (interop_serverQ_main self, sshQ_ServerChannel ch, B_str mode) {
    return $ASYNC((($Actor)self), (($Cont)interop_serverQ_L_81procG_new(self, ch, mode)));
}
B_Msg interop_serverQ_mainD_mode_of (interop_serverQ_main self, sshQ_ServerChannel ch) {
    return ((B_Msg)$ASYNC((($Actor)self), (($Cont)interop_serverQ_L_82procG_new(self, ch))));
}
B_Msg interop_serverQ_mainD_mark_eof (interop_serverQ_main self, sshQ_ServerChannel ch) {
    return $ASYNC((($Actor)self), (($Cont)interop_serverQ_L_83procG_new(self, ch)));
}
B_Msg interop_serverQ_mainD_saw_eof (interop_serverQ_main self, sshQ_ServerChannel ch) {
    return ((B_Msg)$ASYNC((($Actor)self), (($Cont)interop_serverQ_L_84procG_new(self, ch))));
}
B_Msg interop_serverQ_mainD_close_echo (interop_serverQ_main self, sshQ_ServerChannel ch) {
    return $ASYNC((($Actor)self), (($Cont)interop_serverQ_L_85procG_new(self, ch)));
}
B_Msg interop_serverQ_mainD_on_listen (interop_serverQ_main self, sshQ_Server s, B_str err) {
    return $ASYNC((($Actor)self), (($Cont)interop_serverQ_L_86procG_new(self, s, err)));
}
B_Msg interop_serverQ_mainD_on_server_close (interop_serverQ_main self, sshQ_Server s, B_str reason) {
    return $ASYNC((($Actor)self), (($Cont)interop_serverQ_L_87procG_new(self, s, reason)));
}
B_Msg interop_serverQ_mainD_on_session (interop_serverQ_main self, sshQ_ServerSession sess) {
    return $ASYNC((($Actor)self), (($Cont)interop_serverQ_L_88procG_new(self, sess)));
}
B_Msg interop_serverQ_mainD_on_session_close (interop_serverQ_main self, sshQ_ServerSession sess, B_str reason) {
    return $ASYNC((($Actor)self), (($Cont)interop_serverQ_L_89procG_new(self, sess, reason)));
}
B_Msg interop_serverQ_mainD_on_auth (interop_serverQ_main self, sshQ_ServerSession sess, sshQ_AuthRequest req) {
    return $ASYNC((($Actor)self), (($Cont)interop_serverQ_L_90procG_new(self, sess, req)));
}
B_Msg interop_serverQ_mainD_srv_on_data (interop_serverQ_main self, sshQ_ServerChannel ch, B_bytes data) {
    return $ASYNC((($Actor)self), (($Cont)interop_serverQ_L_91procG_new(self, ch, data)));
}
B_Msg interop_serverQ_mainD_srv_on_stderr (interop_serverQ_main self, sshQ_ServerChannel ch, B_bytes data) {
    return $ASYNC((($Actor)self), (($Cont)interop_serverQ_L_92procG_new(self, ch, data)));
}
B_Msg interop_serverQ_mainD_srv_on_close (interop_serverQ_main self, sshQ_ServerChannel ch, B_str reason) {
    return $ASYNC((($Actor)self), (($Cont)interop_serverQ_L_93procG_new(self, ch, reason)));
}
B_Msg interop_serverQ_mainD_on_channel_open (interop_serverQ_main self, sshQ_ServerSession sess) {
    return $ASYNC((($Actor)self), (($Cont)interop_serverQ_L_94procG_new(self, sess)));
}
B_Msg interop_serverQ_mainD_on_exec (interop_serverQ_main self, sshQ_ServerSession sess, sshQ_ServerChannel ch, B_str cmd) {
    return $ASYNC((($Actor)self), (($Cont)interop_serverQ_L_95procG_new(self, sess, ch, cmd)));
}
B_Msg interop_serverQ_mainD_on_subsystem (interop_serverQ_main self, sshQ_ServerSession sess, sshQ_ServerChannel ch, B_str name) {
    return $ASYNC((($Actor)self), (($Cont)interop_serverQ_L_96procG_new(self, sess, ch, name)));
}
void interop_serverQ_mainD___serialize__ (interop_serverQ_main self, $Serial$state state) {
    $ActorG_methods.__serialize__(($Actor)self, state);
    $step_serialize(self->env, state);
    $step_serialize(self->USER, state);
    $step_serialize(self->PASS, state);
    $step_serialize(self->server, state);
    $step_serialize(self->modes, state);
    $step_serialize(self->eofed, state);
    $step_serialize(self->auth_key, state);
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
    self->auth_key = $step_deserialize(state);
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
    return $AWAIT((($Cont)interop_serverQ_L_98ContG_new(C_cont, G_act)), $ASYNC((($Actor)G_act), (($Cont)interop_serverQ_L_99procG_new(G_act, env))));
}
int interop_serverQ_done$ = 0;
void interop_serverQ___init__ () {
    if (interop_serverQ_done$) return;
    interop_serverQ_done$ = 1;
    netQ___init__();
    sshQ___init__();
    {
        interop_serverQ_L_3ContG_methods.$GCINFO = "interop_serverQ_L_3Cont";
        interop_serverQ_L_3ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        interop_serverQ_L_3ContG_methods.__bool__ = (B_bool (*) (interop_serverQ_L_3Cont))B_valueG_methods.__bool__;
        interop_serverQ_L_3ContG_methods.__str__ = (B_str (*) (interop_serverQ_L_3Cont))B_valueG_methods.__str__;
        interop_serverQ_L_3ContG_methods.__repr__ = (B_str (*) (interop_serverQ_L_3Cont))B_valueG_methods.__repr__;
        interop_serverQ_L_3ContG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_3Cont, interop_serverQ_main, $Cont))interop_serverQ_L_3ContD___init__;
        interop_serverQ_L_3ContG_methods.__call__ = ($R (*) (interop_serverQ_L_3Cont, sshQ_Server))interop_serverQ_L_3ContD___call__;
        interop_serverQ_L_3ContG_methods.__serialize__ = interop_serverQ_L_3ContD___serialize__;
        interop_serverQ_L_3ContG_methods.__deserialize__ = interop_serverQ_L_3ContD___deserialize__;
        $register(&interop_serverQ_L_3ContG_methods);
    }
    {
        interop_serverQ_L_5actionG_methods.$GCINFO = "interop_serverQ_L_5action";
        interop_serverQ_L_5actionG_methods.$superclass = ($SuperG_class)&$actionG_methods;
        interop_serverQ_L_5actionG_methods.__bool__ = (B_bool (*) (interop_serverQ_L_5action))B_valueG_methods.__bool__;
        interop_serverQ_L_5actionG_methods.__str__ = (B_str (*) (interop_serverQ_L_5action))B_valueG_methods.__str__;
        interop_serverQ_L_5actionG_methods.__repr__ = (B_str (*) (interop_serverQ_L_5action))B_valueG_methods.__repr__;
        interop_serverQ_L_5actionG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_5action, interop_serverQ_main))interop_serverQ_L_5actionD___init__;
        interop_serverQ_L_5actionG_methods.__call__ = ($R (*) (interop_serverQ_L_5action, $Cont, sshQ_Server, B_str))interop_serverQ_L_5actionD___call__;
        interop_serverQ_L_5actionG_methods.__exec__ = ($R (*) (interop_serverQ_L_5action, $Cont, sshQ_Server, B_str))interop_serverQ_L_5actionD___exec__;
        interop_serverQ_L_5actionG_methods.__asyn__ = (B_Msg (*) (interop_serverQ_L_5action, sshQ_Server, B_str))interop_serverQ_L_5actionD___asyn__;
        interop_serverQ_L_5actionG_methods.__serialize__ = interop_serverQ_L_5actionD___serialize__;
        interop_serverQ_L_5actionG_methods.__deserialize__ = interop_serverQ_L_5actionD___deserialize__;
        $register(&interop_serverQ_L_5actionG_methods);
    }
    {
        interop_serverQ_L_7actionG_methods.$GCINFO = "interop_serverQ_L_7action";
        interop_serverQ_L_7actionG_methods.$superclass = ($SuperG_class)&$actionG_methods;
        interop_serverQ_L_7actionG_methods.__bool__ = (B_bool (*) (interop_serverQ_L_7action))B_valueG_methods.__bool__;
        interop_serverQ_L_7actionG_methods.__str__ = (B_str (*) (interop_serverQ_L_7action))B_valueG_methods.__str__;
        interop_serverQ_L_7actionG_methods.__repr__ = (B_str (*) (interop_serverQ_L_7action))B_valueG_methods.__repr__;
        interop_serverQ_L_7actionG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_7action, interop_serverQ_main))interop_serverQ_L_7actionD___init__;
        interop_serverQ_L_7actionG_methods.__call__ = ($R (*) (interop_serverQ_L_7action, $Cont, sshQ_Server, B_str))interop_serverQ_L_7actionD___call__;
        interop_serverQ_L_7actionG_methods.__exec__ = ($R (*) (interop_serverQ_L_7action, $Cont, sshQ_Server, B_str))interop_serverQ_L_7actionD___exec__;
        interop_serverQ_L_7actionG_methods.__asyn__ = (B_Msg (*) (interop_serverQ_L_7action, sshQ_Server, B_str))interop_serverQ_L_7actionD___asyn__;
        interop_serverQ_L_7actionG_methods.__serialize__ = interop_serverQ_L_7actionD___serialize__;
        interop_serverQ_L_7actionG_methods.__deserialize__ = interop_serverQ_L_7actionD___deserialize__;
        $register(&interop_serverQ_L_7actionG_methods);
    }
    {
        interop_serverQ_L_9actionG_methods.$GCINFO = "interop_serverQ_L_9action";
        interop_serverQ_L_9actionG_methods.$superclass = ($SuperG_class)&$actionG_methods;
        interop_serverQ_L_9actionG_methods.__bool__ = (B_bool (*) (interop_serverQ_L_9action))B_valueG_methods.__bool__;
        interop_serverQ_L_9actionG_methods.__str__ = (B_str (*) (interop_serverQ_L_9action))B_valueG_methods.__str__;
        interop_serverQ_L_9actionG_methods.__repr__ = (B_str (*) (interop_serverQ_L_9action))B_valueG_methods.__repr__;
        interop_serverQ_L_9actionG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_9action, interop_serverQ_main))interop_serverQ_L_9actionD___init__;
        interop_serverQ_L_9actionG_methods.__call__ = ($R (*) (interop_serverQ_L_9action, $Cont, sshQ_ServerSession))interop_serverQ_L_9actionD___call__;
        interop_serverQ_L_9actionG_methods.__exec__ = ($R (*) (interop_serverQ_L_9action, $Cont, sshQ_ServerSession))interop_serverQ_L_9actionD___exec__;
        interop_serverQ_L_9actionG_methods.__asyn__ = (B_Msg (*) (interop_serverQ_L_9action, sshQ_ServerSession))interop_serverQ_L_9actionD___asyn__;
        interop_serverQ_L_9actionG_methods.__serialize__ = interop_serverQ_L_9actionD___serialize__;
        interop_serverQ_L_9actionG_methods.__deserialize__ = interop_serverQ_L_9actionD___deserialize__;
        $register(&interop_serverQ_L_9actionG_methods);
    }
    {
        interop_serverQ_L_11actionG_methods.$GCINFO = "interop_serverQ_L_11action";
        interop_serverQ_L_11actionG_methods.$superclass = ($SuperG_class)&$actionG_methods;
        interop_serverQ_L_11actionG_methods.__bool__ = (B_bool (*) (interop_serverQ_L_11action))B_valueG_methods.__bool__;
        interop_serverQ_L_11actionG_methods.__str__ = (B_str (*) (interop_serverQ_L_11action))B_valueG_methods.__str__;
        interop_serverQ_L_11actionG_methods.__repr__ = (B_str (*) (interop_serverQ_L_11action))B_valueG_methods.__repr__;
        interop_serverQ_L_11actionG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_11action, interop_serverQ_main))interop_serverQ_L_11actionD___init__;
        interop_serverQ_L_11actionG_methods.__call__ = ($R (*) (interop_serverQ_L_11action, $Cont, sshQ_ServerSession, sshQ_AuthRequest))interop_serverQ_L_11actionD___call__;
        interop_serverQ_L_11actionG_methods.__exec__ = ($R (*) (interop_serverQ_L_11action, $Cont, sshQ_ServerSession, sshQ_AuthRequest))interop_serverQ_L_11actionD___exec__;
        interop_serverQ_L_11actionG_methods.__asyn__ = (B_Msg (*) (interop_serverQ_L_11action, sshQ_ServerSession, sshQ_AuthRequest))interop_serverQ_L_11actionD___asyn__;
        interop_serverQ_L_11actionG_methods.__serialize__ = interop_serverQ_L_11actionD___serialize__;
        interop_serverQ_L_11actionG_methods.__deserialize__ = interop_serverQ_L_11actionD___deserialize__;
        $register(&interop_serverQ_L_11actionG_methods);
    }
    {
        interop_serverQ_L_13actionG_methods.$GCINFO = "interop_serverQ_L_13action";
        interop_serverQ_L_13actionG_methods.$superclass = ($SuperG_class)&$actionG_methods;
        interop_serverQ_L_13actionG_methods.__bool__ = (B_bool (*) (interop_serverQ_L_13action))B_valueG_methods.__bool__;
        interop_serverQ_L_13actionG_methods.__str__ = (B_str (*) (interop_serverQ_L_13action))B_valueG_methods.__str__;
        interop_serverQ_L_13actionG_methods.__repr__ = (B_str (*) (interop_serverQ_L_13action))B_valueG_methods.__repr__;
        interop_serverQ_L_13actionG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_13action, interop_serverQ_main))interop_serverQ_L_13actionD___init__;
        interop_serverQ_L_13actionG_methods.__call__ = ($R (*) (interop_serverQ_L_13action, $Cont, sshQ_ServerSession))interop_serverQ_L_13actionD___call__;
        interop_serverQ_L_13actionG_methods.__exec__ = ($R (*) (interop_serverQ_L_13action, $Cont, sshQ_ServerSession))interop_serverQ_L_13actionD___exec__;
        interop_serverQ_L_13actionG_methods.__asyn__ = (B_Msg (*) (interop_serverQ_L_13action, sshQ_ServerSession))interop_serverQ_L_13actionD___asyn__;
        interop_serverQ_L_13actionG_methods.__serialize__ = interop_serverQ_L_13actionD___serialize__;
        interop_serverQ_L_13actionG_methods.__deserialize__ = interop_serverQ_L_13actionD___deserialize__;
        $register(&interop_serverQ_L_13actionG_methods);
    }
    {
        interop_serverQ_L_15actionG_methods.$GCINFO = "interop_serverQ_L_15action";
        interop_serverQ_L_15actionG_methods.$superclass = ($SuperG_class)&$actionG_methods;
        interop_serverQ_L_15actionG_methods.__bool__ = (B_bool (*) (interop_serverQ_L_15action))B_valueG_methods.__bool__;
        interop_serverQ_L_15actionG_methods.__str__ = (B_str (*) (interop_serverQ_L_15action))B_valueG_methods.__str__;
        interop_serverQ_L_15actionG_methods.__repr__ = (B_str (*) (interop_serverQ_L_15action))B_valueG_methods.__repr__;
        interop_serverQ_L_15actionG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_15action, interop_serverQ_main))interop_serverQ_L_15actionD___init__;
        interop_serverQ_L_15actionG_methods.__call__ = ($R (*) (interop_serverQ_L_15action, $Cont, sshQ_ServerSession, sshQ_ServerChannel, B_str))interop_serverQ_L_15actionD___call__;
        interop_serverQ_L_15actionG_methods.__exec__ = ($R (*) (interop_serverQ_L_15action, $Cont, sshQ_ServerSession, sshQ_ServerChannel, B_str))interop_serverQ_L_15actionD___exec__;
        interop_serverQ_L_15actionG_methods.__asyn__ = (B_Msg (*) (interop_serverQ_L_15action, sshQ_ServerSession, sshQ_ServerChannel, B_str))interop_serverQ_L_15actionD___asyn__;
        interop_serverQ_L_15actionG_methods.__serialize__ = interop_serverQ_L_15actionD___serialize__;
        interop_serverQ_L_15actionG_methods.__deserialize__ = interop_serverQ_L_15actionD___deserialize__;
        $register(&interop_serverQ_L_15actionG_methods);
    }
    {
        interop_serverQ_L_17actionG_methods.$GCINFO = "interop_serverQ_L_17action";
        interop_serverQ_L_17actionG_methods.$superclass = ($SuperG_class)&$actionG_methods;
        interop_serverQ_L_17actionG_methods.__bool__ = (B_bool (*) (interop_serverQ_L_17action))B_valueG_methods.__bool__;
        interop_serverQ_L_17actionG_methods.__str__ = (B_str (*) (interop_serverQ_L_17action))B_valueG_methods.__str__;
        interop_serverQ_L_17actionG_methods.__repr__ = (B_str (*) (interop_serverQ_L_17action))B_valueG_methods.__repr__;
        interop_serverQ_L_17actionG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_17action, interop_serverQ_main))interop_serverQ_L_17actionD___init__;
        interop_serverQ_L_17actionG_methods.__call__ = ($R (*) (interop_serverQ_L_17action, $Cont, sshQ_ServerSession, sshQ_ServerChannel, B_str))interop_serverQ_L_17actionD___call__;
        interop_serverQ_L_17actionG_methods.__exec__ = ($R (*) (interop_serverQ_L_17action, $Cont, sshQ_ServerSession, sshQ_ServerChannel, B_str))interop_serverQ_L_17actionD___exec__;
        interop_serverQ_L_17actionG_methods.__asyn__ = (B_Msg (*) (interop_serverQ_L_17action, sshQ_ServerSession, sshQ_ServerChannel, B_str))interop_serverQ_L_17actionD___asyn__;
        interop_serverQ_L_17actionG_methods.__serialize__ = interop_serverQ_L_17actionD___serialize__;
        interop_serverQ_L_17actionG_methods.__deserialize__ = interop_serverQ_L_17actionD___deserialize__;
        $register(&interop_serverQ_L_17actionG_methods);
    }
    {
        interop_serverQ_L_19actionG_methods.$GCINFO = "interop_serverQ_L_19action";
        interop_serverQ_L_19actionG_methods.$superclass = ($SuperG_class)&$actionG_methods;
        interop_serverQ_L_19actionG_methods.__bool__ = (B_bool (*) (interop_serverQ_L_19action))B_valueG_methods.__bool__;
        interop_serverQ_L_19actionG_methods.__str__ = (B_str (*) (interop_serverQ_L_19action))B_valueG_methods.__str__;
        interop_serverQ_L_19actionG_methods.__repr__ = (B_str (*) (interop_serverQ_L_19action))B_valueG_methods.__repr__;
        interop_serverQ_L_19actionG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_19action, interop_serverQ_main))interop_serverQ_L_19actionD___init__;
        interop_serverQ_L_19actionG_methods.__call__ = ($R (*) (interop_serverQ_L_19action, $Cont, sshQ_ServerSession, B_str))interop_serverQ_L_19actionD___call__;
        interop_serverQ_L_19actionG_methods.__exec__ = ($R (*) (interop_serverQ_L_19action, $Cont, sshQ_ServerSession, B_str))interop_serverQ_L_19actionD___exec__;
        interop_serverQ_L_19actionG_methods.__asyn__ = (B_Msg (*) (interop_serverQ_L_19action, sshQ_ServerSession, B_str))interop_serverQ_L_19actionD___asyn__;
        interop_serverQ_L_19actionG_methods.__serialize__ = interop_serverQ_L_19actionD___serialize__;
        interop_serverQ_L_19actionG_methods.__deserialize__ = interop_serverQ_L_19actionD___deserialize__;
        $register(&interop_serverQ_L_19actionG_methods);
    }
    {
        interop_serverQ_L_20ContG_methods.$GCINFO = "interop_serverQ_L_20Cont";
        interop_serverQ_L_20ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        interop_serverQ_L_20ContG_methods.__bool__ = (B_bool (*) (interop_serverQ_L_20Cont))B_valueG_methods.__bool__;
        interop_serverQ_L_20ContG_methods.__str__ = (B_str (*) (interop_serverQ_L_20Cont))B_valueG_methods.__str__;
        interop_serverQ_L_20ContG_methods.__repr__ = (B_str (*) (interop_serverQ_L_20Cont))B_valueG_methods.__repr__;
        interop_serverQ_L_20ContG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_20Cont, interop_serverQ_main, $Cont))interop_serverQ_L_20ContD___init__;
        interop_serverQ_L_20ContG_methods.__call__ = ($R (*) (interop_serverQ_L_20Cont, B_str))interop_serverQ_L_20ContD___call__;
        interop_serverQ_L_20ContG_methods.__serialize__ = interop_serverQ_L_20ContD___serialize__;
        interop_serverQ_L_20ContG_methods.__deserialize__ = interop_serverQ_L_20ContD___deserialize__;
        $register(&interop_serverQ_L_20ContG_methods);
    }
    {
        interop_serverQ_L_24ContG_methods.$GCINFO = "interop_serverQ_L_24Cont";
        interop_serverQ_L_24ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        interop_serverQ_L_24ContG_methods.__bool__ = (B_bool (*) (interop_serverQ_L_24Cont))B_valueG_methods.__bool__;
        interop_serverQ_L_24ContG_methods.__str__ = (B_str (*) (interop_serverQ_L_24Cont))B_valueG_methods.__str__;
        interop_serverQ_L_24ContG_methods.__repr__ = (B_str (*) (interop_serverQ_L_24Cont))B_valueG_methods.__repr__;
        interop_serverQ_L_24ContG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_24Cont, $Cont))interop_serverQ_L_24ContD___init__;
        interop_serverQ_L_24ContG_methods.__call__ = ($R (*) (interop_serverQ_L_24Cont, B_NoneType))interop_serverQ_L_24ContD___call__;
        interop_serverQ_L_24ContG_methods.__serialize__ = interop_serverQ_L_24ContD___serialize__;
        interop_serverQ_L_24ContG_methods.__deserialize__ = interop_serverQ_L_24ContD___deserialize__;
        $register(&interop_serverQ_L_24ContG_methods);
    }
    {
        interop_serverQ_L_27ContG_methods.$GCINFO = "interop_serverQ_L_27Cont";
        interop_serverQ_L_27ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        interop_serverQ_L_27ContG_methods.__bool__ = (B_bool (*) (interop_serverQ_L_27Cont))B_valueG_methods.__bool__;
        interop_serverQ_L_27ContG_methods.__str__ = (B_str (*) (interop_serverQ_L_27Cont))B_valueG_methods.__str__;
        interop_serverQ_L_27ContG_methods.__repr__ = (B_str (*) (interop_serverQ_L_27Cont))B_valueG_methods.__repr__;
        interop_serverQ_L_27ContG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_27Cont, B_Iterator, B_Identity, sshQ_ServerChannel, $Cont))interop_serverQ_L_27ContD___init__;
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
        interop_serverQ_L_28ContG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_28Cont, B_Iterator, B_Identity, sshQ_ServerChannel, $Cont))interop_serverQ_L_28ContD___init__;
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
        interop_serverQ_L_30ContG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_30Cont, $Cont))interop_serverQ_L_30ContD___init__;
        interop_serverQ_L_30ContG_methods.__call__ = ($R (*) (interop_serverQ_L_30Cont, B_NoneType))interop_serverQ_L_30ContD___call__;
        interop_serverQ_L_30ContG_methods.__serialize__ = interop_serverQ_L_30ContD___serialize__;
        interop_serverQ_L_30ContG_methods.__deserialize__ = interop_serverQ_L_30ContD___deserialize__;
        $register(&interop_serverQ_L_30ContG_methods);
    }
    {
        interop_serverQ_L_31ContG_methods.$GCINFO = "interop_serverQ_L_31Cont";
        interop_serverQ_L_31ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        interop_serverQ_L_31ContG_methods.__bool__ = (B_bool (*) (interop_serverQ_L_31Cont))B_valueG_methods.__bool__;
        interop_serverQ_L_31ContG_methods.__str__ = (B_str (*) (interop_serverQ_L_31Cont))B_valueG_methods.__str__;
        interop_serverQ_L_31ContG_methods.__repr__ = (B_str (*) (interop_serverQ_L_31Cont))B_valueG_methods.__repr__;
        interop_serverQ_L_31ContG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_31Cont, $Cont))interop_serverQ_L_31ContD___init__;
        interop_serverQ_L_31ContG_methods.__call__ = ($R (*) (interop_serverQ_L_31Cont, B_NoneType))interop_serverQ_L_31ContD___call__;
        interop_serverQ_L_31ContG_methods.__serialize__ = interop_serverQ_L_31ContD___serialize__;
        interop_serverQ_L_31ContG_methods.__deserialize__ = interop_serverQ_L_31ContD___deserialize__;
        $register(&interop_serverQ_L_31ContG_methods);
    }
    {
        interop_serverQ_L_32ContG_methods.$GCINFO = "interop_serverQ_L_32Cont";
        interop_serverQ_L_32ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        interop_serverQ_L_32ContG_methods.__bool__ = (B_bool (*) (interop_serverQ_L_32Cont))B_valueG_methods.__bool__;
        interop_serverQ_L_32ContG_methods.__str__ = (B_str (*) (interop_serverQ_L_32Cont))B_valueG_methods.__str__;
        interop_serverQ_L_32ContG_methods.__repr__ = (B_str (*) (interop_serverQ_L_32Cont))B_valueG_methods.__repr__;
        interop_serverQ_L_32ContG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_32Cont, B_Iterator, B_Identity, sshQ_ServerChannel, $Cont))interop_serverQ_L_32ContD___init__;
        interop_serverQ_L_32ContG_methods.__call__ = ($R (*) (interop_serverQ_L_32Cont, B_bool))interop_serverQ_L_32ContD___call__;
        interop_serverQ_L_32ContG_methods.__serialize__ = interop_serverQ_L_32ContD___serialize__;
        interop_serverQ_L_32ContG_methods.__deserialize__ = interop_serverQ_L_32ContD___deserialize__;
        $register(&interop_serverQ_L_32ContG_methods);
    }
    {
        interop_serverQ_L_36ContG_methods.$GCINFO = "interop_serverQ_L_36Cont";
        interop_serverQ_L_36ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        interop_serverQ_L_36ContG_methods.__bool__ = (B_bool (*) (interop_serverQ_L_36Cont))B_valueG_methods.__bool__;
        interop_serverQ_L_36ContG_methods.__str__ = (B_str (*) (interop_serverQ_L_36Cont))B_valueG_methods.__str__;
        interop_serverQ_L_36ContG_methods.__repr__ = (B_str (*) (interop_serverQ_L_36Cont))B_valueG_methods.__repr__;
        interop_serverQ_L_36ContG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_36Cont, $Cont))interop_serverQ_L_36ContD___init__;
        interop_serverQ_L_36ContG_methods.__call__ = ($R (*) (interop_serverQ_L_36Cont, B_NoneType))interop_serverQ_L_36ContD___call__;
        interop_serverQ_L_36ContG_methods.__serialize__ = interop_serverQ_L_36ContD___serialize__;
        interop_serverQ_L_36ContG_methods.__deserialize__ = interop_serverQ_L_36ContD___deserialize__;
        $register(&interop_serverQ_L_36ContG_methods);
    }
    {
        interop_serverQ_L_39ContG_methods.$GCINFO = "interop_serverQ_L_39Cont";
        interop_serverQ_L_39ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        interop_serverQ_L_39ContG_methods.__bool__ = (B_bool (*) (interop_serverQ_L_39Cont))B_valueG_methods.__bool__;
        interop_serverQ_L_39ContG_methods.__str__ = (B_str (*) (interop_serverQ_L_39Cont))B_valueG_methods.__str__;
        interop_serverQ_L_39ContG_methods.__repr__ = (B_str (*) (interop_serverQ_L_39Cont))B_valueG_methods.__repr__;
        interop_serverQ_L_39ContG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_39Cont, B_Iterator, B_Identity, sshQ_ServerChannel, $Cont))interop_serverQ_L_39ContD___init__;
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
        interop_serverQ_L_40ContG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_40Cont, B_Iterator, B_Identity, sshQ_ServerChannel, $Cont))interop_serverQ_L_40ContD___init__;
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
        interop_serverQ_L_42ContG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_42Cont, $Cont))interop_serverQ_L_42ContD___init__;
        interop_serverQ_L_42ContG_methods.__call__ = ($R (*) (interop_serverQ_L_42Cont, B_NoneType))interop_serverQ_L_42ContD___call__;
        interop_serverQ_L_42ContG_methods.__serialize__ = interop_serverQ_L_42ContD___serialize__;
        interop_serverQ_L_42ContG_methods.__deserialize__ = interop_serverQ_L_42ContD___deserialize__;
        $register(&interop_serverQ_L_42ContG_methods);
    }
    {
        interop_serverQ_L_43ContG_methods.$GCINFO = "interop_serverQ_L_43Cont";
        interop_serverQ_L_43ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        interop_serverQ_L_43ContG_methods.__bool__ = (B_bool (*) (interop_serverQ_L_43Cont))B_valueG_methods.__bool__;
        interop_serverQ_L_43ContG_methods.__str__ = (B_str (*) (interop_serverQ_L_43Cont))B_valueG_methods.__str__;
        interop_serverQ_L_43ContG_methods.__repr__ = (B_str (*) (interop_serverQ_L_43Cont))B_valueG_methods.__repr__;
        interop_serverQ_L_43ContG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_43Cont, $Cont))interop_serverQ_L_43ContD___init__;
        interop_serverQ_L_43ContG_methods.__call__ = ($R (*) (interop_serverQ_L_43Cont, B_NoneType))interop_serverQ_L_43ContD___call__;
        interop_serverQ_L_43ContG_methods.__serialize__ = interop_serverQ_L_43ContD___serialize__;
        interop_serverQ_L_43ContG_methods.__deserialize__ = interop_serverQ_L_43ContD___deserialize__;
        $register(&interop_serverQ_L_43ContG_methods);
    }
    {
        interop_serverQ_L_44ContG_methods.$GCINFO = "interop_serverQ_L_44Cont";
        interop_serverQ_L_44ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        interop_serverQ_L_44ContG_methods.__bool__ = (B_bool (*) (interop_serverQ_L_44Cont))B_valueG_methods.__bool__;
        interop_serverQ_L_44ContG_methods.__str__ = (B_str (*) (interop_serverQ_L_44Cont))B_valueG_methods.__str__;
        interop_serverQ_L_44ContG_methods.__repr__ = (B_str (*) (interop_serverQ_L_44Cont))B_valueG_methods.__repr__;
        interop_serverQ_L_44ContG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_44Cont, B_Iterator, B_Identity, sshQ_ServerChannel, $Cont))interop_serverQ_L_44ContD___init__;
        interop_serverQ_L_44ContG_methods.__call__ = ($R (*) (interop_serverQ_L_44Cont, B_bool))interop_serverQ_L_44ContD___call__;
        interop_serverQ_L_44ContG_methods.__serialize__ = interop_serverQ_L_44ContD___serialize__;
        interop_serverQ_L_44ContG_methods.__deserialize__ = interop_serverQ_L_44ContD___deserialize__;
        $register(&interop_serverQ_L_44ContG_methods);
    }
    {
        interop_serverQ_L_47ContG_methods.$GCINFO = "interop_serverQ_L_47Cont";
        interop_serverQ_L_47ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        interop_serverQ_L_47ContG_methods.__bool__ = (B_bool (*) (interop_serverQ_L_47Cont))B_valueG_methods.__bool__;
        interop_serverQ_L_47ContG_methods.__str__ = (B_str (*) (interop_serverQ_L_47Cont))B_valueG_methods.__str__;
        interop_serverQ_L_47ContG_methods.__repr__ = (B_str (*) (interop_serverQ_L_47Cont))B_valueG_methods.__repr__;
        interop_serverQ_L_47ContG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_47Cont, $Cont))interop_serverQ_L_47ContD___init__;
        interop_serverQ_L_47ContG_methods.__call__ = ($R (*) (interop_serverQ_L_47Cont, B_u16))interop_serverQ_L_47ContD___call__;
        interop_serverQ_L_47ContG_methods.__serialize__ = interop_serverQ_L_47ContD___serialize__;
        interop_serverQ_L_47ContG_methods.__deserialize__ = interop_serverQ_L_47ContD___deserialize__;
        $register(&interop_serverQ_L_47ContG_methods);
    }
    {
        interop_serverQ_L_48ContG_methods.$GCINFO = "interop_serverQ_L_48Cont";
        interop_serverQ_L_48ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        interop_serverQ_L_48ContG_methods.__bool__ = (B_bool (*) (interop_serverQ_L_48Cont))B_valueG_methods.__bool__;
        interop_serverQ_L_48ContG_methods.__str__ = (B_str (*) (interop_serverQ_L_48Cont))B_valueG_methods.__str__;
        interop_serverQ_L_48ContG_methods.__repr__ = (B_str (*) (interop_serverQ_L_48Cont))B_valueG_methods.__repr__;
        interop_serverQ_L_48ContG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_48Cont, $Cont, sshQ_Server))interop_serverQ_L_48ContD___init__;
        interop_serverQ_L_48ContG_methods.__call__ = ($R (*) (interop_serverQ_L_48Cont, B_NoneType))interop_serverQ_L_48ContD___call__;
        interop_serverQ_L_48ContG_methods.__serialize__ = interop_serverQ_L_48ContD___serialize__;
        interop_serverQ_L_48ContG_methods.__deserialize__ = interop_serverQ_L_48ContD___deserialize__;
        $register(&interop_serverQ_L_48ContG_methods);
    }
    {
        interop_serverQ_L_50ContG_methods.$GCINFO = "interop_serverQ_L_50Cont";
        interop_serverQ_L_50ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        interop_serverQ_L_50ContG_methods.__bool__ = (B_bool (*) (interop_serverQ_L_50Cont))B_valueG_methods.__bool__;
        interop_serverQ_L_50ContG_methods.__str__ = (B_str (*) (interop_serverQ_L_50Cont))B_valueG_methods.__str__;
        interop_serverQ_L_50ContG_methods.__repr__ = (B_str (*) (interop_serverQ_L_50Cont))B_valueG_methods.__repr__;
        interop_serverQ_L_50ContG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_50Cont, sshQ_AuthRequest, interop_serverQ_main, B_Eq, sshQ_ServerSession, $Cont))interop_serverQ_L_50ContD___init__;
        interop_serverQ_L_50ContG_methods.__call__ = ($R (*) (interop_serverQ_L_50Cont, B_NoneType))interop_serverQ_L_50ContD___call__;
        interop_serverQ_L_50ContG_methods.__serialize__ = interop_serverQ_L_50ContD___serialize__;
        interop_serverQ_L_50ContG_methods.__deserialize__ = interop_serverQ_L_50ContD___deserialize__;
        $register(&interop_serverQ_L_50ContG_methods);
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
        interop_serverQ_L_57ContG_methods.$GCINFO = "interop_serverQ_L_57Cont";
        interop_serverQ_L_57ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        interop_serverQ_L_57ContG_methods.__bool__ = (B_bool (*) (interop_serverQ_L_57Cont))B_valueG_methods.__bool__;
        interop_serverQ_L_57ContG_methods.__str__ = (B_str (*) (interop_serverQ_L_57Cont))B_valueG_methods.__str__;
        interop_serverQ_L_57ContG_methods.__repr__ = (B_str (*) (interop_serverQ_L_57Cont))B_valueG_methods.__repr__;
        interop_serverQ_L_57ContG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_57Cont, $Cont))interop_serverQ_L_57ContD___init__;
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
        interop_serverQ_L_58ContG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_58Cont, $Cont))interop_serverQ_L_58ContD___init__;
        interop_serverQ_L_58ContG_methods.__call__ = ($R (*) (interop_serverQ_L_58Cont, B_NoneType))interop_serverQ_L_58ContD___call__;
        interop_serverQ_L_58ContG_methods.__serialize__ = interop_serverQ_L_58ContD___serialize__;
        interop_serverQ_L_58ContG_methods.__deserialize__ = interop_serverQ_L_58ContD___deserialize__;
        $register(&interop_serverQ_L_58ContG_methods);
    }
    {
        interop_serverQ_L_59ContG_methods.$GCINFO = "interop_serverQ_L_59Cont";
        interop_serverQ_L_59ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        interop_serverQ_L_59ContG_methods.__bool__ = (B_bool (*) (interop_serverQ_L_59Cont))B_valueG_methods.__bool__;
        interop_serverQ_L_59ContG_methods.__str__ = (B_str (*) (interop_serverQ_L_59Cont))B_valueG_methods.__str__;
        interop_serverQ_L_59ContG_methods.__repr__ = (B_str (*) (interop_serverQ_L_59Cont))B_valueG_methods.__repr__;
        interop_serverQ_L_59ContG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_59Cont, interop_serverQ_main, sshQ_ServerChannel, $Cont))interop_serverQ_L_59ContD___init__;
        interop_serverQ_L_59ContG_methods.__call__ = ($R (*) (interop_serverQ_L_59Cont, B_str))interop_serverQ_L_59ContD___call__;
        interop_serverQ_L_59ContG_methods.__serialize__ = interop_serverQ_L_59ContD___serialize__;
        interop_serverQ_L_59ContG_methods.__deserialize__ = interop_serverQ_L_59ContD___deserialize__;
        $register(&interop_serverQ_L_59ContG_methods);
    }
    {
        interop_serverQ_L_60ContG_methods.$GCINFO = "interop_serverQ_L_60Cont";
        interop_serverQ_L_60ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        interop_serverQ_L_60ContG_methods.__bool__ = (B_bool (*) (interop_serverQ_L_60Cont))B_valueG_methods.__bool__;
        interop_serverQ_L_60ContG_methods.__str__ = (B_str (*) (interop_serverQ_L_60Cont))B_valueG_methods.__str__;
        interop_serverQ_L_60ContG_methods.__repr__ = (B_str (*) (interop_serverQ_L_60Cont))B_valueG_methods.__repr__;
        interop_serverQ_L_60ContG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_60Cont, interop_serverQ_main, sshQ_ServerChannel, $Cont))interop_serverQ_L_60ContD___init__;
        interop_serverQ_L_60ContG_methods.__call__ = ($R (*) (interop_serverQ_L_60Cont, B_NoneType))interop_serverQ_L_60ContD___call__;
        interop_serverQ_L_60ContG_methods.__serialize__ = interop_serverQ_L_60ContD___serialize__;
        interop_serverQ_L_60ContG_methods.__deserialize__ = interop_serverQ_L_60ContD___deserialize__;
        $register(&interop_serverQ_L_60ContG_methods);
    }
    {
        interop_serverQ_L_61ContG_methods.$GCINFO = "interop_serverQ_L_61Cont";
        interop_serverQ_L_61ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        interop_serverQ_L_61ContG_methods.__bool__ = (B_bool (*) (interop_serverQ_L_61Cont))B_valueG_methods.__bool__;
        interop_serverQ_L_61ContG_methods.__str__ = (B_str (*) (interop_serverQ_L_61Cont))B_valueG_methods.__str__;
        interop_serverQ_L_61ContG_methods.__repr__ = (B_str (*) (interop_serverQ_L_61Cont))B_valueG_methods.__repr__;
        interop_serverQ_L_61ContG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_61Cont, $Cont, B_bytes, sshQ_ServerChannel, interop_serverQ_main))interop_serverQ_L_61ContD___init__;
        interop_serverQ_L_61ContG_methods.__call__ = ($R (*) (interop_serverQ_L_61Cont, B_NoneType))interop_serverQ_L_61ContD___call__;
        interop_serverQ_L_61ContG_methods.__serialize__ = interop_serverQ_L_61ContD___serialize__;
        interop_serverQ_L_61ContG_methods.__deserialize__ = interop_serverQ_L_61ContD___deserialize__;
        $register(&interop_serverQ_L_61ContG_methods);
    }
    {
        interop_serverQ_L_62ContG_methods.$GCINFO = "interop_serverQ_L_62Cont";
        interop_serverQ_L_62ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        interop_serverQ_L_62ContG_methods.__bool__ = (B_bool (*) (interop_serverQ_L_62Cont))B_valueG_methods.__bool__;
        interop_serverQ_L_62ContG_methods.__str__ = (B_str (*) (interop_serverQ_L_62Cont))B_valueG_methods.__str__;
        interop_serverQ_L_62ContG_methods.__repr__ = (B_str (*) (interop_serverQ_L_62Cont))B_valueG_methods.__repr__;
        interop_serverQ_L_62ContG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_62Cont, $Cont, B_bytes, sshQ_ServerChannel, interop_serverQ_main))interop_serverQ_L_62ContD___init__;
        interop_serverQ_L_62ContG_methods.__call__ = ($R (*) (interop_serverQ_L_62Cont, B_str))interop_serverQ_L_62ContD___call__;
        interop_serverQ_L_62ContG_methods.__serialize__ = interop_serverQ_L_62ContD___serialize__;
        interop_serverQ_L_62ContG_methods.__deserialize__ = interop_serverQ_L_62ContD___deserialize__;
        $register(&interop_serverQ_L_62ContG_methods);
    }
    {
        interop_serverQ_L_64ContG_methods.$GCINFO = "interop_serverQ_L_64Cont";
        interop_serverQ_L_64ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        interop_serverQ_L_64ContG_methods.__bool__ = (B_bool (*) (interop_serverQ_L_64Cont))B_valueG_methods.__bool__;
        interop_serverQ_L_64ContG_methods.__str__ = (B_str (*) (interop_serverQ_L_64Cont))B_valueG_methods.__str__;
        interop_serverQ_L_64ContG_methods.__repr__ = (B_str (*) (interop_serverQ_L_64Cont))B_valueG_methods.__repr__;
        interop_serverQ_L_64ContG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_64Cont, sshQ_ServerSession, $Cont))interop_serverQ_L_64ContD___init__;
        interop_serverQ_L_64ContG_methods.__call__ = ($R (*) (interop_serverQ_L_64Cont, sshQ_ServerChannel))interop_serverQ_L_64ContD___call__;
        interop_serverQ_L_64ContG_methods.__serialize__ = interop_serverQ_L_64ContD___serialize__;
        interop_serverQ_L_64ContG_methods.__deserialize__ = interop_serverQ_L_64ContD___deserialize__;
        $register(&interop_serverQ_L_64ContG_methods);
    }
    {
        interop_serverQ_L_66actionG_methods.$GCINFO = "interop_serverQ_L_66action";
        interop_serverQ_L_66actionG_methods.$superclass = ($SuperG_class)&$actionG_methods;
        interop_serverQ_L_66actionG_methods.__bool__ = (B_bool (*) (interop_serverQ_L_66action))B_valueG_methods.__bool__;
        interop_serverQ_L_66actionG_methods.__str__ = (B_str (*) (interop_serverQ_L_66action))B_valueG_methods.__str__;
        interop_serverQ_L_66actionG_methods.__repr__ = (B_str (*) (interop_serverQ_L_66action))B_valueG_methods.__repr__;
        interop_serverQ_L_66actionG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_66action, interop_serverQ_main))interop_serverQ_L_66actionD___init__;
        interop_serverQ_L_66actionG_methods.__call__ = ($R (*) (interop_serverQ_L_66action, $Cont, sshQ_ServerChannel, B_bytes))interop_serverQ_L_66actionD___call__;
        interop_serverQ_L_66actionG_methods.__exec__ = ($R (*) (interop_serverQ_L_66action, $Cont, sshQ_ServerChannel, B_bytes))interop_serverQ_L_66actionD___exec__;
        interop_serverQ_L_66actionG_methods.__asyn__ = (B_Msg (*) (interop_serverQ_L_66action, sshQ_ServerChannel, B_bytes))interop_serverQ_L_66actionD___asyn__;
        interop_serverQ_L_66actionG_methods.__serialize__ = interop_serverQ_L_66actionD___serialize__;
        interop_serverQ_L_66actionG_methods.__deserialize__ = interop_serverQ_L_66actionD___deserialize__;
        $register(&interop_serverQ_L_66actionG_methods);
    }
    {
        interop_serverQ_L_68actionG_methods.$GCINFO = "interop_serverQ_L_68action";
        interop_serverQ_L_68actionG_methods.$superclass = ($SuperG_class)&$actionG_methods;
        interop_serverQ_L_68actionG_methods.__bool__ = (B_bool (*) (interop_serverQ_L_68action))B_valueG_methods.__bool__;
        interop_serverQ_L_68actionG_methods.__str__ = (B_str (*) (interop_serverQ_L_68action))B_valueG_methods.__str__;
        interop_serverQ_L_68actionG_methods.__repr__ = (B_str (*) (interop_serverQ_L_68action))B_valueG_methods.__repr__;
        interop_serverQ_L_68actionG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_68action, interop_serverQ_main))interop_serverQ_L_68actionD___init__;
        interop_serverQ_L_68actionG_methods.__call__ = ($R (*) (interop_serverQ_L_68action, $Cont, sshQ_ServerChannel, B_bytes))interop_serverQ_L_68actionD___call__;
        interop_serverQ_L_68actionG_methods.__exec__ = ($R (*) (interop_serverQ_L_68action, $Cont, sshQ_ServerChannel, B_bytes))interop_serverQ_L_68actionD___exec__;
        interop_serverQ_L_68actionG_methods.__asyn__ = (B_Msg (*) (interop_serverQ_L_68action, sshQ_ServerChannel, B_bytes))interop_serverQ_L_68actionD___asyn__;
        interop_serverQ_L_68actionG_methods.__serialize__ = interop_serverQ_L_68actionD___serialize__;
        interop_serverQ_L_68actionG_methods.__deserialize__ = interop_serverQ_L_68actionD___deserialize__;
        $register(&interop_serverQ_L_68actionG_methods);
    }
    {
        interop_serverQ_L_70actionG_methods.$GCINFO = "interop_serverQ_L_70action";
        interop_serverQ_L_70actionG_methods.$superclass = ($SuperG_class)&$actionG_methods;
        interop_serverQ_L_70actionG_methods.__bool__ = (B_bool (*) (interop_serverQ_L_70action))B_valueG_methods.__bool__;
        interop_serverQ_L_70actionG_methods.__str__ = (B_str (*) (interop_serverQ_L_70action))B_valueG_methods.__str__;
        interop_serverQ_L_70actionG_methods.__repr__ = (B_str (*) (interop_serverQ_L_70action))B_valueG_methods.__repr__;
        interop_serverQ_L_70actionG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_70action, interop_serverQ_main))interop_serverQ_L_70actionD___init__;
        interop_serverQ_L_70actionG_methods.__call__ = ($R (*) (interop_serverQ_L_70action, $Cont, sshQ_ServerChannel, B_str))interop_serverQ_L_70actionD___call__;
        interop_serverQ_L_70actionG_methods.__exec__ = ($R (*) (interop_serverQ_L_70action, $Cont, sshQ_ServerChannel, B_str))interop_serverQ_L_70actionD___exec__;
        interop_serverQ_L_70actionG_methods.__asyn__ = (B_Msg (*) (interop_serverQ_L_70action, sshQ_ServerChannel, B_str))interop_serverQ_L_70actionD___asyn__;
        interop_serverQ_L_70actionG_methods.__serialize__ = interop_serverQ_L_70actionD___serialize__;
        interop_serverQ_L_70actionG_methods.__deserialize__ = interop_serverQ_L_70actionD___deserialize__;
        $register(&interop_serverQ_L_70actionG_methods);
    }
    {
        interop_serverQ_L_72ContG_methods.$GCINFO = "interop_serverQ_L_72Cont";
        interop_serverQ_L_72ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        interop_serverQ_L_72ContG_methods.__bool__ = (B_bool (*) (interop_serverQ_L_72Cont))B_valueG_methods.__bool__;
        interop_serverQ_L_72ContG_methods.__str__ = (B_str (*) (interop_serverQ_L_72Cont))B_valueG_methods.__str__;
        interop_serverQ_L_72ContG_methods.__repr__ = (B_str (*) (interop_serverQ_L_72Cont))B_valueG_methods.__repr__;
        interop_serverQ_L_72ContG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_72Cont, B_str, sshQ_ServerChannel, $Cont))interop_serverQ_L_72ContD___init__;
        interop_serverQ_L_72ContG_methods.__call__ = ($R (*) (interop_serverQ_L_72Cont, B_NoneType))interop_serverQ_L_72ContD___call__;
        interop_serverQ_L_72ContG_methods.__serialize__ = interop_serverQ_L_72ContD___serialize__;
        interop_serverQ_L_72ContG_methods.__deserialize__ = interop_serverQ_L_72ContD___deserialize__;
        $register(&interop_serverQ_L_72ContG_methods);
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
        interop_serverQ_L_77ContG_methods.$GCINFO = "interop_serverQ_L_77Cont";
        interop_serverQ_L_77ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        interop_serverQ_L_77ContG_methods.__bool__ = (B_bool (*) (interop_serverQ_L_77Cont))B_valueG_methods.__bool__;
        interop_serverQ_L_77ContG_methods.__str__ = (B_str (*) (interop_serverQ_L_77Cont))B_valueG_methods.__str__;
        interop_serverQ_L_77ContG_methods.__repr__ = (B_str (*) (interop_serverQ_L_77Cont))B_valueG_methods.__repr__;
        interop_serverQ_L_77ContG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_77Cont, $Cont))interop_serverQ_L_77ContD___init__;
        interop_serverQ_L_77ContG_methods.__call__ = ($R (*) (interop_serverQ_L_77Cont, B_NoneType))interop_serverQ_L_77ContD___call__;
        interop_serverQ_L_77ContG_methods.__serialize__ = interop_serverQ_L_77ContD___serialize__;
        interop_serverQ_L_77ContG_methods.__deserialize__ = interop_serverQ_L_77ContD___deserialize__;
        $register(&interop_serverQ_L_77ContG_methods);
    }
    {
        interop_serverQ_L_78ContG_methods.$GCINFO = "interop_serverQ_L_78Cont";
        interop_serverQ_L_78ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        interop_serverQ_L_78ContG_methods.__bool__ = (B_bool (*) (interop_serverQ_L_78Cont))B_valueG_methods.__bool__;
        interop_serverQ_L_78ContG_methods.__str__ = (B_str (*) (interop_serverQ_L_78Cont))B_valueG_methods.__str__;
        interop_serverQ_L_78ContG_methods.__repr__ = (B_str (*) (interop_serverQ_L_78Cont))B_valueG_methods.__repr__;
        interop_serverQ_L_78ContG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_78Cont, interop_serverQ_main, sshQ_ServerChannel, $Cont))interop_serverQ_L_78ContD___init__;
        interop_serverQ_L_78ContG_methods.__call__ = ($R (*) (interop_serverQ_L_78Cont, B_bool))interop_serverQ_L_78ContD___call__;
        interop_serverQ_L_78ContG_methods.__serialize__ = interop_serverQ_L_78ContD___serialize__;
        interop_serverQ_L_78ContG_methods.__deserialize__ = interop_serverQ_L_78ContD___deserialize__;
        $register(&interop_serverQ_L_78ContG_methods);
    }
    {
        interop_serverQ_L_79ContG_methods.$GCINFO = "interop_serverQ_L_79Cont";
        interop_serverQ_L_79ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        interop_serverQ_L_79ContG_methods.__bool__ = (B_bool (*) (interop_serverQ_L_79Cont))B_valueG_methods.__bool__;
        interop_serverQ_L_79ContG_methods.__str__ = (B_str (*) (interop_serverQ_L_79Cont))B_valueG_methods.__str__;
        interop_serverQ_L_79ContG_methods.__repr__ = (B_str (*) (interop_serverQ_L_79Cont))B_valueG_methods.__repr__;
        interop_serverQ_L_79ContG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_79Cont, sshQ_ServerChannel, interop_serverQ_main, $Cont))interop_serverQ_L_79ContD___init__;
        interop_serverQ_L_79ContG_methods.__call__ = ($R (*) (interop_serverQ_L_79Cont, B_NoneType))interop_serverQ_L_79ContD___call__;
        interop_serverQ_L_79ContG_methods.__serialize__ = interop_serverQ_L_79ContD___serialize__;
        interop_serverQ_L_79ContG_methods.__deserialize__ = interop_serverQ_L_79ContD___deserialize__;
        $register(&interop_serverQ_L_79ContG_methods);
    }
    {
        interop_serverQ_L_80ContG_methods.$GCINFO = "interop_serverQ_L_80Cont";
        interop_serverQ_L_80ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        interop_serverQ_L_80ContG_methods.__bool__ = (B_bool (*) (interop_serverQ_L_80Cont))B_valueG_methods.__bool__;
        interop_serverQ_L_80ContG_methods.__str__ = (B_str (*) (interop_serverQ_L_80Cont))B_valueG_methods.__str__;
        interop_serverQ_L_80ContG_methods.__repr__ = (B_str (*) (interop_serverQ_L_80Cont))B_valueG_methods.__repr__;
        interop_serverQ_L_80ContG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_80Cont, $Cont))interop_serverQ_L_80ContD___init__;
        interop_serverQ_L_80ContG_methods.__call__ = ($R (*) (interop_serverQ_L_80Cont, B_NoneType))interop_serverQ_L_80ContD___call__;
        interop_serverQ_L_80ContG_methods.__serialize__ = interop_serverQ_L_80ContD___serialize__;
        interop_serverQ_L_80ContG_methods.__deserialize__ = interop_serverQ_L_80ContD___deserialize__;
        $register(&interop_serverQ_L_80ContG_methods);
    }
    {
        interop_serverQ_L_81procG_methods.$GCINFO = "interop_serverQ_L_81proc";
        interop_serverQ_L_81procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        interop_serverQ_L_81procG_methods.__bool__ = (B_bool (*) (interop_serverQ_L_81proc))B_valueG_methods.__bool__;
        interop_serverQ_L_81procG_methods.__str__ = (B_str (*) (interop_serverQ_L_81proc))B_valueG_methods.__str__;
        interop_serverQ_L_81procG_methods.__repr__ = (B_str (*) (interop_serverQ_L_81proc))B_valueG_methods.__repr__;
        interop_serverQ_L_81procG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_81proc, interop_serverQ_main, sshQ_ServerChannel, B_str))interop_serverQ_L_81procD___init__;
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
        interop_serverQ_L_82procG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_82proc, interop_serverQ_main, sshQ_ServerChannel))interop_serverQ_L_82procD___init__;
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
        interop_serverQ_L_83procG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_83proc, interop_serverQ_main, sshQ_ServerChannel))interop_serverQ_L_83procD___init__;
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
        interop_serverQ_L_84procG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_84proc, interop_serverQ_main, sshQ_ServerChannel))interop_serverQ_L_84procD___init__;
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
        interop_serverQ_L_85procG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_85proc, interop_serverQ_main, sshQ_ServerChannel))interop_serverQ_L_85procD___init__;
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
        interop_serverQ_L_86procG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_86proc, interop_serverQ_main, sshQ_Server, B_str))interop_serverQ_L_86procD___init__;
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
        interop_serverQ_L_87procG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_87proc, interop_serverQ_main, sshQ_Server, B_str))interop_serverQ_L_87procD___init__;
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
        interop_serverQ_L_88procG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_88proc, interop_serverQ_main, sshQ_ServerSession))interop_serverQ_L_88procD___init__;
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
        interop_serverQ_L_89procG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_89proc, interop_serverQ_main, sshQ_ServerSession, B_str))interop_serverQ_L_89procD___init__;
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
        interop_serverQ_L_90procG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_90proc, interop_serverQ_main, sshQ_ServerSession, sshQ_AuthRequest))interop_serverQ_L_90procD___init__;
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
        interop_serverQ_L_91procG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_91proc, interop_serverQ_main, sshQ_ServerChannel, B_bytes))interop_serverQ_L_91procD___init__;
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
        interop_serverQ_L_92procG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_92proc, interop_serverQ_main, sshQ_ServerChannel, B_bytes))interop_serverQ_L_92procD___init__;
        interop_serverQ_L_92procG_methods.__call__ = ($R (*) (interop_serverQ_L_92proc, $Cont))interop_serverQ_L_92procD___call__;
        interop_serverQ_L_92procG_methods.__exec__ = ($R (*) (interop_serverQ_L_92proc, $Cont))interop_serverQ_L_92procD___exec__;
        interop_serverQ_L_92procG_methods.__serialize__ = interop_serverQ_L_92procD___serialize__;
        interop_serverQ_L_92procG_methods.__deserialize__ = interop_serverQ_L_92procD___deserialize__;
        $register(&interop_serverQ_L_92procG_methods);
    }
    {
        interop_serverQ_L_93procG_methods.$GCINFO = "interop_serverQ_L_93proc";
        interop_serverQ_L_93procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        interop_serverQ_L_93procG_methods.__bool__ = (B_bool (*) (interop_serverQ_L_93proc))B_valueG_methods.__bool__;
        interop_serverQ_L_93procG_methods.__str__ = (B_str (*) (interop_serverQ_L_93proc))B_valueG_methods.__str__;
        interop_serverQ_L_93procG_methods.__repr__ = (B_str (*) (interop_serverQ_L_93proc))B_valueG_methods.__repr__;
        interop_serverQ_L_93procG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_93proc, interop_serverQ_main, sshQ_ServerChannel, B_str))interop_serverQ_L_93procD___init__;
        interop_serverQ_L_93procG_methods.__call__ = ($R (*) (interop_serverQ_L_93proc, $Cont))interop_serverQ_L_93procD___call__;
        interop_serverQ_L_93procG_methods.__exec__ = ($R (*) (interop_serverQ_L_93proc, $Cont))interop_serverQ_L_93procD___exec__;
        interop_serverQ_L_93procG_methods.__serialize__ = interop_serverQ_L_93procD___serialize__;
        interop_serverQ_L_93procG_methods.__deserialize__ = interop_serverQ_L_93procD___deserialize__;
        $register(&interop_serverQ_L_93procG_methods);
    }
    {
        interop_serverQ_L_94procG_methods.$GCINFO = "interop_serverQ_L_94proc";
        interop_serverQ_L_94procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        interop_serverQ_L_94procG_methods.__bool__ = (B_bool (*) (interop_serverQ_L_94proc))B_valueG_methods.__bool__;
        interop_serverQ_L_94procG_methods.__str__ = (B_str (*) (interop_serverQ_L_94proc))B_valueG_methods.__str__;
        interop_serverQ_L_94procG_methods.__repr__ = (B_str (*) (interop_serverQ_L_94proc))B_valueG_methods.__repr__;
        interop_serverQ_L_94procG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_94proc, interop_serverQ_main, sshQ_ServerSession))interop_serverQ_L_94procD___init__;
        interop_serverQ_L_94procG_methods.__call__ = ($R (*) (interop_serverQ_L_94proc, $Cont))interop_serverQ_L_94procD___call__;
        interop_serverQ_L_94procG_methods.__exec__ = ($R (*) (interop_serverQ_L_94proc, $Cont))interop_serverQ_L_94procD___exec__;
        interop_serverQ_L_94procG_methods.__serialize__ = interop_serverQ_L_94procD___serialize__;
        interop_serverQ_L_94procG_methods.__deserialize__ = interop_serverQ_L_94procD___deserialize__;
        $register(&interop_serverQ_L_94procG_methods);
    }
    {
        interop_serverQ_L_95procG_methods.$GCINFO = "interop_serverQ_L_95proc";
        interop_serverQ_L_95procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        interop_serverQ_L_95procG_methods.__bool__ = (B_bool (*) (interop_serverQ_L_95proc))B_valueG_methods.__bool__;
        interop_serverQ_L_95procG_methods.__str__ = (B_str (*) (interop_serverQ_L_95proc))B_valueG_methods.__str__;
        interop_serverQ_L_95procG_methods.__repr__ = (B_str (*) (interop_serverQ_L_95proc))B_valueG_methods.__repr__;
        interop_serverQ_L_95procG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_95proc, interop_serverQ_main, sshQ_ServerSession, sshQ_ServerChannel, B_str))interop_serverQ_L_95procD___init__;
        interop_serverQ_L_95procG_methods.__call__ = ($R (*) (interop_serverQ_L_95proc, $Cont))interop_serverQ_L_95procD___call__;
        interop_serverQ_L_95procG_methods.__exec__ = ($R (*) (interop_serverQ_L_95proc, $Cont))interop_serverQ_L_95procD___exec__;
        interop_serverQ_L_95procG_methods.__serialize__ = interop_serverQ_L_95procD___serialize__;
        interop_serverQ_L_95procG_methods.__deserialize__ = interop_serverQ_L_95procD___deserialize__;
        $register(&interop_serverQ_L_95procG_methods);
    }
    {
        interop_serverQ_L_96procG_methods.$GCINFO = "interop_serverQ_L_96proc";
        interop_serverQ_L_96procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        interop_serverQ_L_96procG_methods.__bool__ = (B_bool (*) (interop_serverQ_L_96proc))B_valueG_methods.__bool__;
        interop_serverQ_L_96procG_methods.__str__ = (B_str (*) (interop_serverQ_L_96proc))B_valueG_methods.__str__;
        interop_serverQ_L_96procG_methods.__repr__ = (B_str (*) (interop_serverQ_L_96proc))B_valueG_methods.__repr__;
        interop_serverQ_L_96procG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_96proc, interop_serverQ_main, sshQ_ServerSession, sshQ_ServerChannel, B_str))interop_serverQ_L_96procD___init__;
        interop_serverQ_L_96procG_methods.__call__ = ($R (*) (interop_serverQ_L_96proc, $Cont))interop_serverQ_L_96procD___call__;
        interop_serverQ_L_96procG_methods.__exec__ = ($R (*) (interop_serverQ_L_96proc, $Cont))interop_serverQ_L_96procD___exec__;
        interop_serverQ_L_96procG_methods.__serialize__ = interop_serverQ_L_96procD___serialize__;
        interop_serverQ_L_96procG_methods.__deserialize__ = interop_serverQ_L_96procD___deserialize__;
        $register(&interop_serverQ_L_96procG_methods);
    }
    {
        interop_serverQ_L_98ContG_methods.$GCINFO = "interop_serverQ_L_98Cont";
        interop_serverQ_L_98ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        interop_serverQ_L_98ContG_methods.__bool__ = (B_bool (*) (interop_serverQ_L_98Cont))B_valueG_methods.__bool__;
        interop_serverQ_L_98ContG_methods.__str__ = (B_str (*) (interop_serverQ_L_98Cont))B_valueG_methods.__str__;
        interop_serverQ_L_98ContG_methods.__repr__ = (B_str (*) (interop_serverQ_L_98Cont))B_valueG_methods.__repr__;
        interop_serverQ_L_98ContG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_98Cont, $Cont, interop_serverQ_main))interop_serverQ_L_98ContD___init__;
        interop_serverQ_L_98ContG_methods.__call__ = ($R (*) (interop_serverQ_L_98Cont, B_NoneType))interop_serverQ_L_98ContD___call__;
        interop_serverQ_L_98ContG_methods.__serialize__ = interop_serverQ_L_98ContD___serialize__;
        interop_serverQ_L_98ContG_methods.__deserialize__ = interop_serverQ_L_98ContD___deserialize__;
        $register(&interop_serverQ_L_98ContG_methods);
    }
    {
        interop_serverQ_L_99procG_methods.$GCINFO = "interop_serverQ_L_99proc";
        interop_serverQ_L_99procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        interop_serverQ_L_99procG_methods.__bool__ = (B_bool (*) (interop_serverQ_L_99proc))B_valueG_methods.__bool__;
        interop_serverQ_L_99procG_methods.__str__ = (B_str (*) (interop_serverQ_L_99proc))B_valueG_methods.__str__;
        interop_serverQ_L_99procG_methods.__repr__ = (B_str (*) (interop_serverQ_L_99proc))B_valueG_methods.__repr__;
        interop_serverQ_L_99procG_methods.__init__ = (B_NoneType (*) (interop_serverQ_L_99proc, interop_serverQ_main, B_Env))interop_serverQ_L_99procD___init__;
        interop_serverQ_L_99procG_methods.__call__ = ($R (*) (interop_serverQ_L_99proc, $Cont))interop_serverQ_L_99procD___call__;
        interop_serverQ_L_99procG_methods.__exec__ = ($R (*) (interop_serverQ_L_99proc, $Cont))interop_serverQ_L_99procD___exec__;
        interop_serverQ_L_99procG_methods.__serialize__ = interop_serverQ_L_99procD___serialize__;
        interop_serverQ_L_99procG_methods.__deserialize__ = interop_serverQ_L_99procD___deserialize__;
        $register(&interop_serverQ_L_99procG_methods);
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
    B_Eq W_main_341 = (B_Eq)B_OrdD_bytesG_witness;
    interop_serverQ_W_main_341 = W_main_341;
    B_Eq W_main_1194 = (B_Eq)B_OrdD_strG_witness;
    interop_serverQ_W_main_1194 = W_main_1194;
    B_Eq W_main_424 = ((B_Eq)$EqOptG_new(interop_serverQ_W_main_1194));
    interop_serverQ_W_main_424 = W_main_424;
    B_Eq W_main_322 = ((B_Eq)$EqOptG_new(interop_serverQ_W_main_1194));
    interop_serverQ_W_main_322 = W_main_322;
}