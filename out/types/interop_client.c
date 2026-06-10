/* Acton impl hash: 821cb352d08c792ed0977ca7a209403c25722c15559df121f7dbea834f407b54 */
#include "rts/common.h"
#include "out/types/interop_client.h"
B_Collection interop_clientQ_W_main_15;
$R interop_clientQ_L_1C_1cont (interop_clientQ_main self, $Cont C_cont, sshQ_Client C_2res) {
    #line 64 "src/interop_client.act"
    ((interop_clientQ_main)(self))->client = C_2res;
    return $R_CONT(C_cont, B_None);
}
B_NoneType interop_clientQ_L_2ContD___init__ (interop_clientQ_L_2Cont L_self, interop_clientQ_main self, $Cont C_cont) {
    ((interop_clientQ_L_2Cont)(L_self))->self = self;
    ((interop_clientQ_L_2Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R interop_clientQ_L_2ContD___call__ (interop_clientQ_L_2Cont L_self, sshQ_Client G_1) {
    interop_clientQ_main self = ((interop_clientQ_L_2Cont)(L_self))->self;
    $Cont C_cont = ((interop_clientQ_L_2Cont)(L_self))->C_cont;
    return interop_clientQ_L_1C_1cont(self, C_cont, G_1);
}
void interop_clientQ_L_2ContD___serialize__ (interop_clientQ_L_2Cont self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->C_cont, state);
}
interop_clientQ_L_2Cont interop_clientQ_L_2ContD___deserialize__ (interop_clientQ_L_2Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct interop_clientQ_L_2Cont));
            self->$class = &interop_clientQ_L_2ContG_methods;
            return self;
        }
        self = $DNEW(interop_clientQ_L_2Cont, state);
    }
    self->self = $step_deserialize(state);
    self->C_cont = $step_deserialize(state);
    return self;
}
interop_clientQ_L_2Cont interop_clientQ_L_2ContG_new(interop_clientQ_main G_1, $Cont G_2) {
    interop_clientQ_L_2Cont $tmp = acton_malloc(sizeof(struct interop_clientQ_L_2Cont));
    $tmp->$class = &interop_clientQ_L_2ContG_methods;
    interop_clientQ_L_2ContG_methods.__init__($tmp, G_1, G_2);
    return $tmp;
}
struct interop_clientQ_L_2ContG_class interop_clientQ_L_2ContG_methods;
B_NoneType interop_clientQ_L_4actionD___init__ (interop_clientQ_L_4action L_self, interop_clientQ_main L_3obj) {
    ((interop_clientQ_L_4action)(L_self))->L_3obj = L_3obj;
    return B_None;
}
$R interop_clientQ_L_4actionD___call__ (interop_clientQ_L_4action L_self, $Cont L_cont, sshQ_Client G_1, B_str G_2) {
    return $AWAIT(L_cont, ((B_Msg (*) ($WORD, sshQ_Client, B_str))((interop_clientQ_L_4action)(L_self))->$class->__asyn__)(L_self, G_1, G_2));
}
$R interop_clientQ_L_4actionD___exec__ (interop_clientQ_L_4action L_self, $Cont L_cont, sshQ_Client G_1, B_str G_2) {
    return $R_CONT(L_cont, ((B_Msg (*) ($WORD, sshQ_Client, B_str))((interop_clientQ_L_4action)(L_self))->$class->__asyn__)(L_self, G_1, G_2));
}
B_Msg interop_clientQ_L_4actionD___asyn__ (interop_clientQ_L_4action L_self, sshQ_Client G_1, B_str G_2) {
    interop_clientQ_main L_3obj = ((interop_clientQ_L_4action)(L_self))->L_3obj;
    return ((B_Msg (*) ($WORD, sshQ_Client, B_str))((interop_clientQ_main)(L_3obj))->$class->on_connect)(L_3obj, G_1, G_2);
}
void interop_clientQ_L_4actionD___serialize__ (interop_clientQ_L_4action self, $Serial$state state) {
    $step_serialize(self->L_3obj, state);
}
interop_clientQ_L_4action interop_clientQ_L_4actionD___deserialize__ (interop_clientQ_L_4action self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct interop_clientQ_L_4action));
            self->$class = &interop_clientQ_L_4actionG_methods;
            return self;
        }
        self = $DNEW(interop_clientQ_L_4action, state);
    }
    self->L_3obj = $step_deserialize(state);
    return self;
}
interop_clientQ_L_4action interop_clientQ_L_4actionG_new(interop_clientQ_main G_1) {
    interop_clientQ_L_4action $tmp = acton_malloc(sizeof(struct interop_clientQ_L_4action));
    $tmp->$class = &interop_clientQ_L_4actionG_methods;
    interop_clientQ_L_4actionG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct interop_clientQ_L_4actionG_class interop_clientQ_L_4actionG_methods;
B_NoneType interop_clientQ_L_6actionD___init__ (interop_clientQ_L_6action L_self, interop_clientQ_main L_5obj) {
    ((interop_clientQ_L_6action)(L_self))->L_5obj = L_5obj;
    return B_None;
}
$R interop_clientQ_L_6actionD___call__ (interop_clientQ_L_6action L_self, $Cont L_cont, sshQ_Client G_1, B_str G_2) {
    return $AWAIT(L_cont, ((B_Msg (*) ($WORD, sshQ_Client, B_str))((interop_clientQ_L_6action)(L_self))->$class->__asyn__)(L_self, G_1, G_2));
}
$R interop_clientQ_L_6actionD___exec__ (interop_clientQ_L_6action L_self, $Cont L_cont, sshQ_Client G_1, B_str G_2) {
    return $R_CONT(L_cont, ((B_Msg (*) ($WORD, sshQ_Client, B_str))((interop_clientQ_L_6action)(L_self))->$class->__asyn__)(L_self, G_1, G_2));
}
B_Msg interop_clientQ_L_6actionD___asyn__ (interop_clientQ_L_6action L_self, sshQ_Client G_1, B_str G_2) {
    interop_clientQ_main L_5obj = ((interop_clientQ_L_6action)(L_self))->L_5obj;
    return ((B_Msg (*) ($WORD, sshQ_Client, B_str))((interop_clientQ_main)(L_5obj))->$class->on_close)(L_5obj, G_1, G_2);
}
void interop_clientQ_L_6actionD___serialize__ (interop_clientQ_L_6action self, $Serial$state state) {
    $step_serialize(self->L_5obj, state);
}
interop_clientQ_L_6action interop_clientQ_L_6actionD___deserialize__ (interop_clientQ_L_6action self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct interop_clientQ_L_6action));
            self->$class = &interop_clientQ_L_6actionG_methods;
            return self;
        }
        self = $DNEW(interop_clientQ_L_6action, state);
    }
    self->L_5obj = $step_deserialize(state);
    return self;
}
interop_clientQ_L_6action interop_clientQ_L_6actionG_new(interop_clientQ_main G_1) {
    interop_clientQ_L_6action $tmp = acton_malloc(sizeof(struct interop_clientQ_L_6action));
    $tmp->$class = &interop_clientQ_L_6actionG_methods;
    interop_clientQ_L_6actionG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct interop_clientQ_L_6actionG_class interop_clientQ_L_6actionG_methods;
B_NoneType interop_clientQ_L_8actionD___init__ (interop_clientQ_L_8action L_self, interop_clientQ_main L_7obj) {
    ((interop_clientQ_L_8action)(L_self))->L_7obj = L_7obj;
    return B_None;
}
$R interop_clientQ_L_8actionD___call__ (interop_clientQ_L_8action L_self, $Cont L_cont, sshQ_Client G_1, B_str G_2, sshQ_HostKeyInfo G_3) {
    return $AWAIT(L_cont, ((B_Msg (*) ($WORD, sshQ_Client, B_str, sshQ_HostKeyInfo))((interop_clientQ_L_8action)(L_self))->$class->__asyn__)(L_self, G_1, G_2, G_3));
}
$R interop_clientQ_L_8actionD___exec__ (interop_clientQ_L_8action L_self, $Cont L_cont, sshQ_Client G_1, B_str G_2, sshQ_HostKeyInfo G_3) {
    return $R_CONT(L_cont, ((B_Msg (*) ($WORD, sshQ_Client, B_str, sshQ_HostKeyInfo))((interop_clientQ_L_8action)(L_self))->$class->__asyn__)(L_self, G_1, G_2, G_3));
}
B_Msg interop_clientQ_L_8actionD___asyn__ (interop_clientQ_L_8action L_self, sshQ_Client G_1, B_str G_2, sshQ_HostKeyInfo G_3) {
    interop_clientQ_main L_7obj = ((interop_clientQ_L_8action)(L_self))->L_7obj;
    return ((B_Msg (*) ($WORD, sshQ_Client, B_str, sshQ_HostKeyInfo))((interop_clientQ_main)(L_7obj))->$class->on_hostkey)(L_7obj, G_1, G_2, G_3);
}
void interop_clientQ_L_8actionD___serialize__ (interop_clientQ_L_8action self, $Serial$state state) {
    $step_serialize(self->L_7obj, state);
}
interop_clientQ_L_8action interop_clientQ_L_8actionD___deserialize__ (interop_clientQ_L_8action self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct interop_clientQ_L_8action));
            self->$class = &interop_clientQ_L_8actionG_methods;
            return self;
        }
        self = $DNEW(interop_clientQ_L_8action, state);
    }
    self->L_7obj = $step_deserialize(state);
    return self;
}
interop_clientQ_L_8action interop_clientQ_L_8actionG_new(interop_clientQ_main G_1) {
    interop_clientQ_L_8action $tmp = acton_malloc(sizeof(struct interop_clientQ_L_8action));
    $tmp->$class = &interop_clientQ_L_8actionG_methods;
    interop_clientQ_L_8actionG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct interop_clientQ_L_8actionG_class interop_clientQ_L_8actionG_methods;
$R interop_clientQ_L_10C_5cont ($Cont C_cont, sshQ_RunCommand C_6res) {
    return $R_CONT(C_cont, B_None);
}
B_NoneType interop_clientQ_L_11ContD___init__ (interop_clientQ_L_11Cont L_self, $Cont C_cont) {
    ((interop_clientQ_L_11Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R interop_clientQ_L_11ContD___call__ (interop_clientQ_L_11Cont L_self, sshQ_RunCommand G_1) {
    $Cont C_cont = ((interop_clientQ_L_11Cont)(L_self))->C_cont;
    return interop_clientQ_L_10C_5cont(C_cont, G_1);
}
void interop_clientQ_L_11ContD___serialize__ (interop_clientQ_L_11Cont self, $Serial$state state) {
    $step_serialize(self->C_cont, state);
}
interop_clientQ_L_11Cont interop_clientQ_L_11ContD___deserialize__ (interop_clientQ_L_11Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct interop_clientQ_L_11Cont));
            self->$class = &interop_clientQ_L_11ContG_methods;
            return self;
        }
        self = $DNEW(interop_clientQ_L_11Cont, state);
    }
    self->C_cont = $step_deserialize(state);
    return self;
}
interop_clientQ_L_11Cont interop_clientQ_L_11ContG_new($Cont G_1) {
    interop_clientQ_L_11Cont $tmp = acton_malloc(sizeof(struct interop_clientQ_L_11Cont));
    $tmp->$class = &interop_clientQ_L_11ContG_methods;
    interop_clientQ_L_11ContG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct interop_clientQ_L_11ContG_class interop_clientQ_L_11ContG_methods;
B_NoneType interop_clientQ_L_13actionD___init__ (interop_clientQ_L_13action L_self, interop_clientQ_main L_12obj) {
    ((interop_clientQ_L_13action)(L_self))->L_12obj = L_12obj;
    return B_None;
}
$R interop_clientQ_L_13actionD___call__ (interop_clientQ_L_13action L_self, $Cont L_cont, sshQ_Channel G_1, B_int G_2, B_str G_3, B_bytes G_4, B_bytes G_5, B_str G_6) {
    return $AWAIT(L_cont, ((B_Msg (*) ($WORD, sshQ_Channel, B_int, B_str, B_bytes, B_bytes, B_str))((interop_clientQ_L_13action)(L_self))->$class->__asyn__)(L_self, G_1, G_2, G_3, G_4, G_5, G_6));
}
$R interop_clientQ_L_13actionD___exec__ (interop_clientQ_L_13action L_self, $Cont L_cont, sshQ_Channel G_1, B_int G_2, B_str G_3, B_bytes G_4, B_bytes G_5, B_str G_6) {
    return $R_CONT(L_cont, ((B_Msg (*) ($WORD, sshQ_Channel, B_int, B_str, B_bytes, B_bytes, B_str))((interop_clientQ_L_13action)(L_self))->$class->__asyn__)(L_self, G_1, G_2, G_3, G_4, G_5, G_6));
}
B_Msg interop_clientQ_L_13actionD___asyn__ (interop_clientQ_L_13action L_self, sshQ_Channel G_1, B_int G_2, B_str G_3, B_bytes G_4, B_bytes G_5, B_str G_6) {
    interop_clientQ_main L_12obj = ((interop_clientQ_L_13action)(L_self))->L_12obj;
    return ((B_Msg (*) ($WORD, sshQ_Channel, int64_t, B_str, B_bytes, B_bytes, B_str))((interop_clientQ_main)(L_12obj))->$class->on_run_exit)(L_12obj, G_1, ((B_int)G_2)->val, G_3, G_4, G_5, G_6);
}
void interop_clientQ_L_13actionD___serialize__ (interop_clientQ_L_13action self, $Serial$state state) {
    $step_serialize(self->L_12obj, state);
}
interop_clientQ_L_13action interop_clientQ_L_13actionD___deserialize__ (interop_clientQ_L_13action self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct interop_clientQ_L_13action));
            self->$class = &interop_clientQ_L_13actionG_methods;
            return self;
        }
        self = $DNEW(interop_clientQ_L_13action, state);
    }
    self->L_12obj = $step_deserialize(state);
    return self;
}
interop_clientQ_L_13action interop_clientQ_L_13actionG_new(interop_clientQ_main G_1) {
    interop_clientQ_L_13action $tmp = acton_malloc(sizeof(struct interop_clientQ_L_13action));
    $tmp->$class = &interop_clientQ_L_13actionG_methods;
    interop_clientQ_L_13actionG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct interop_clientQ_L_13actionG_class interop_clientQ_L_13actionG_methods;
$R interop_clientQ_L_9C_3cont ($Cont C_cont, sshQ_Client c, interop_clientQ_main self, B_NoneType C_4res) {
    #line 41 "src/interop_client.act"
    ((B_NoneType (*) (B_tuple, B_str, B_str, B_bool, B_bool))B_print)($NEWTUPLE(1, to$str("CONNECTED")), B_None, B_None, B_None, B_None);
    return sshQ_RunCommandG_newact((($Cont)interop_clientQ_L_11ContG_new(C_cont)), c, ((interop_clientQ_main)(self))->cmd, (($action)interop_clientQ_L_13actionG_new(self)), toB_float(15.0));
}
B_NoneType interop_clientQ_L_14ContD___init__ (interop_clientQ_L_14Cont L_self, $Cont C_cont, sshQ_Client c, interop_clientQ_main self) {
    ((interop_clientQ_L_14Cont)(L_self))->C_cont = C_cont;
    ((interop_clientQ_L_14Cont)(L_self))->c = c;
    ((interop_clientQ_L_14Cont)(L_self))->self = self;
    return B_None;
}
$R interop_clientQ_L_14ContD___call__ (interop_clientQ_L_14Cont L_self, B_NoneType G_1) {
    $Cont C_cont = ((interop_clientQ_L_14Cont)(L_self))->C_cont;
    sshQ_Client c = ((interop_clientQ_L_14Cont)(L_self))->c;
    interop_clientQ_main self = ((interop_clientQ_L_14Cont)(L_self))->self;
    return interop_clientQ_L_9C_3cont(C_cont, c, self, G_1);
}
void interop_clientQ_L_14ContD___serialize__ (interop_clientQ_L_14Cont self, $Serial$state state) {
    $step_serialize(self->C_cont, state);
    $step_serialize(self->c, state);
    $step_serialize(self->self, state);
}
interop_clientQ_L_14Cont interop_clientQ_L_14ContD___deserialize__ (interop_clientQ_L_14Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct interop_clientQ_L_14Cont));
            self->$class = &interop_clientQ_L_14ContG_methods;
            return self;
        }
        self = $DNEW(interop_clientQ_L_14Cont, state);
    }
    self->C_cont = $step_deserialize(state);
    self->c = $step_deserialize(state);
    self->self = $step_deserialize(state);
    return self;
}
interop_clientQ_L_14Cont interop_clientQ_L_14ContG_new($Cont G_1, sshQ_Client G_2, interop_clientQ_main G_3) {
    interop_clientQ_L_14Cont $tmp = acton_malloc(sizeof(struct interop_clientQ_L_14Cont));
    $tmp->$class = &interop_clientQ_L_14ContG_methods;
    interop_clientQ_L_14ContG_methods.__init__($tmp, G_1, G_2, G_3);
    return $tmp;
}
struct interop_clientQ_L_14ContG_class interop_clientQ_L_14ContG_methods;
$R interop_clientQ_L_15C_7cont (B_bytes out, B_Collection W_main_472, B_bytes err_out, int64_t code, interop_clientQ_main self, $Cont C_cont, B_NoneType C_8res) {
    #line 52 "src/interop_client.act"
    ((B_NoneType (*) (B_tuple, B_str, B_str, B_bool, B_bool))B_print)($NEWTUPLE(1, to$str("OUT-BEGIN")), B_None, B_None, B_None, B_None);
    #line 53 "src/interop_client.act"
    ((B_NoneType (*) (B_tuple, B_str, B_str, B_bool, B_bool))B_print)($NEWTUPLE(1, ((B_str (*) ($WORD))((B_bytes)(out))->$class->decode)(out)), B_None, B_None, B_None, B_None);
    #line 54 "src/interop_client.act"
    ((B_NoneType (*) (B_tuple, B_str, B_str, B_bool, B_bool))B_print)($NEWTUPLE(1, to$str("OUT-END")), B_None, B_None, B_None, B_None);
    #line 55 "src/interop_client.act"
    if (((int64_t (*) (B_Collection, B_bytes))B_len)(W_main_472, err_out) > 0LL) {
        #line 56 "src/interop_client.act"
        ((B_NoneType (*) (B_tuple, B_str, B_str, B_bool, B_bool))B_print)($NEWTUPLE(1, to$str("ERR-BEGIN")), B_None, B_None, B_None, B_None);
        #line 57 "src/interop_client.act"
        ((B_NoneType (*) (B_tuple, B_str, B_str, B_bool, B_bool))B_print)($NEWTUPLE(1, ((B_str (*) ($WORD))((B_bytes)(err_out))->$class->decode)(err_out)), B_None, B_None, B_None, B_None);
        #line 58 "src/interop_client.act"
        ((B_NoneType (*) (B_tuple, B_str, B_str, B_bool, B_bool))B_print)($NEWTUPLE(1, to$str("ERR-END")), B_None, B_None, B_None, B_None);
    }
    #line 59 "src/interop_client.act"
    ((B_NoneType (*) (B_tuple, B_str, B_str, B_bool, B_bool))B_print)($NEWTUPLE(2, to$str("EXIT"), toB_int(code)), B_None, B_None, B_None, B_None);
    #line 60 "src/interop_client.act"
    if ($ISNOTNONE0(((interop_clientQ_main)(self))->client)) {
        #line 61 "src/interop_client.act"
        ({ sshQ_Client $tmp = ((sshQ_Client)((interop_clientQ_main)(self))->client);
           ((B_Msg (*) ($WORD))((sshQ_Client)($tmp))->$class->close)($tmp); });
    }
    #line 62 "src/interop_client.act"
    ((B_Msg (*) ($WORD, int64_t))((B_Env)(((interop_clientQ_main)(self))->env))->$class->exit)(((interop_clientQ_main)(self))->env, code);
    return $R_CONT(C_cont, B_None);
}
B_NoneType interop_clientQ_L_16ContD___init__ (interop_clientQ_L_16Cont L_self, B_bytes out, B_Collection W_main_472, B_bytes err_out, int64_t code, interop_clientQ_main self, $Cont C_cont) {
    ((interop_clientQ_L_16Cont)(L_self))->out = out;
    ((interop_clientQ_L_16Cont)(L_self))->W_main_472 = W_main_472;
    ((interop_clientQ_L_16Cont)(L_self))->err_out = err_out;
    ((interop_clientQ_L_16Cont)(L_self))->code = code;
    ((interop_clientQ_L_16Cont)(L_self))->self = self;
    ((interop_clientQ_L_16Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R interop_clientQ_L_16ContD___call__ (interop_clientQ_L_16Cont L_self, B_NoneType G_1) {
    B_bytes out = ((interop_clientQ_L_16Cont)(L_self))->out;
    B_Collection W_main_472 = ((interop_clientQ_L_16Cont)(L_self))->W_main_472;
    B_bytes err_out = ((interop_clientQ_L_16Cont)(L_self))->err_out;
    int64_t code = ((int64_t)((interop_clientQ_L_16Cont)(L_self))->code);
    interop_clientQ_main self = ((interop_clientQ_L_16Cont)(L_self))->self;
    $Cont C_cont = ((interop_clientQ_L_16Cont)(L_self))->C_cont;
    return interop_clientQ_L_15C_7cont(out, W_main_472, err_out, code, self, C_cont, G_1);
}
void interop_clientQ_L_16ContD___serialize__ (interop_clientQ_L_16Cont self, $Serial$state state) {
    $step_serialize(self->out, state);
    $step_serialize(self->W_main_472, state);
    $step_serialize(self->err_out, state);
    $val_serialize(I64_ID, &self->code, state);
    $step_serialize(self->self, state);
    $step_serialize(self->C_cont, state);
}
interop_clientQ_L_16Cont interop_clientQ_L_16ContD___deserialize__ (interop_clientQ_L_16Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct interop_clientQ_L_16Cont));
            self->$class = &interop_clientQ_L_16ContG_methods;
            return self;
        }
        self = $DNEW(interop_clientQ_L_16Cont, state);
    }
    self->out = $step_deserialize(state);
    self->W_main_472 = $step_deserialize(state);
    self->err_out = $step_deserialize(state);
    $tmp = $val_deserialize(state);
    memcpy(&self->code, &$tmp, sizeof(self->code));
    self->self = $step_deserialize(state);
    self->C_cont = $step_deserialize(state);
    return self;
}
interop_clientQ_L_16Cont interop_clientQ_L_16ContG_new(B_bytes G_1, B_Collection G_2, B_bytes G_3, int64_t G_4, interop_clientQ_main G_5, $Cont G_6) {
    interop_clientQ_L_16Cont $tmp = acton_malloc(sizeof(struct interop_clientQ_L_16Cont));
    $tmp->$class = &interop_clientQ_L_16ContG_methods;
    interop_clientQ_L_16ContG_methods.__init__($tmp, G_1, G_2, G_3, G_4, G_5, G_6);
    return $tmp;
}
struct interop_clientQ_L_16ContG_class interop_clientQ_L_16ContG_methods;
B_NoneType interop_clientQ_L_17procD___init__ (interop_clientQ_L_17proc L_self, interop_clientQ_main self, sshQ_Client c, B_str state, sshQ_HostKeyInfo info) {
    ((interop_clientQ_L_17proc)(L_self))->self = self;
    ((interop_clientQ_L_17proc)(L_self))->c = c;
    ((interop_clientQ_L_17proc)(L_self))->state = state;
    ((interop_clientQ_L_17proc)(L_self))->info = info;
    return B_None;
}
$R interop_clientQ_L_17procD___call__ (interop_clientQ_L_17proc L_self, $Cont C_cont) {
    interop_clientQ_main self = ((interop_clientQ_L_17proc)(L_self))->self;
    sshQ_Client c = ((interop_clientQ_L_17proc)(L_self))->c;
    B_str state = ((interop_clientQ_L_17proc)(L_self))->state;
    sshQ_HostKeyInfo info = ((interop_clientQ_L_17proc)(L_self))->info;
    return (($R (*) ($WORD, $Cont, sshQ_Client, B_str, sshQ_HostKeyInfo))((interop_clientQ_main)(self))->$class->on_hostkeyG_local)(self, C_cont, c, state, info);
}
$R interop_clientQ_L_17procD___exec__ (interop_clientQ_L_17proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((interop_clientQ_L_17proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void interop_clientQ_L_17procD___serialize__ (interop_clientQ_L_17proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->c, state);
    $step_serialize(self->state, state);
    $step_serialize(self->info, state);
}
interop_clientQ_L_17proc interop_clientQ_L_17procD___deserialize__ (interop_clientQ_L_17proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct interop_clientQ_L_17proc));
            self->$class = &interop_clientQ_L_17procG_methods;
            return self;
        }
        self = $DNEW(interop_clientQ_L_17proc, state);
    }
    self->self = $step_deserialize(state);
    self->c = $step_deserialize(state);
    self->state = $step_deserialize(state);
    self->info = $step_deserialize(state);
    return self;
}
interop_clientQ_L_17proc interop_clientQ_L_17procG_new(interop_clientQ_main G_1, sshQ_Client G_2, B_str G_3, sshQ_HostKeyInfo G_4) {
    interop_clientQ_L_17proc $tmp = acton_malloc(sizeof(struct interop_clientQ_L_17proc));
    $tmp->$class = &interop_clientQ_L_17procG_methods;
    interop_clientQ_L_17procG_methods.__init__($tmp, G_1, G_2, G_3, G_4);
    return $tmp;
}
struct interop_clientQ_L_17procG_class interop_clientQ_L_17procG_methods;
B_NoneType interop_clientQ_L_18procD___init__ (interop_clientQ_L_18proc L_self, interop_clientQ_main self, sshQ_Client c, B_str err) {
    ((interop_clientQ_L_18proc)(L_self))->self = self;
    ((interop_clientQ_L_18proc)(L_self))->c = c;
    ((interop_clientQ_L_18proc)(L_self))->err = err;
    return B_None;
}
$R interop_clientQ_L_18procD___call__ (interop_clientQ_L_18proc L_self, $Cont C_cont) {
    interop_clientQ_main self = ((interop_clientQ_L_18proc)(L_self))->self;
    sshQ_Client c = ((interop_clientQ_L_18proc)(L_self))->c;
    B_str err = ((interop_clientQ_L_18proc)(L_self))->err;
    return (($R (*) ($WORD, $Cont, sshQ_Client, B_str))((interop_clientQ_main)(self))->$class->on_connectG_local)(self, C_cont, c, err);
}
$R interop_clientQ_L_18procD___exec__ (interop_clientQ_L_18proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((interop_clientQ_L_18proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void interop_clientQ_L_18procD___serialize__ (interop_clientQ_L_18proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->c, state);
    $step_serialize(self->err, state);
}
interop_clientQ_L_18proc interop_clientQ_L_18procD___deserialize__ (interop_clientQ_L_18proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct interop_clientQ_L_18proc));
            self->$class = &interop_clientQ_L_18procG_methods;
            return self;
        }
        self = $DNEW(interop_clientQ_L_18proc, state);
    }
    self->self = $step_deserialize(state);
    self->c = $step_deserialize(state);
    self->err = $step_deserialize(state);
    return self;
}
interop_clientQ_L_18proc interop_clientQ_L_18procG_new(interop_clientQ_main G_1, sshQ_Client G_2, B_str G_3) {
    interop_clientQ_L_18proc $tmp = acton_malloc(sizeof(struct interop_clientQ_L_18proc));
    $tmp->$class = &interop_clientQ_L_18procG_methods;
    interop_clientQ_L_18procG_methods.__init__($tmp, G_1, G_2, G_3);
    return $tmp;
}
struct interop_clientQ_L_18procG_class interop_clientQ_L_18procG_methods;
B_NoneType interop_clientQ_L_19procD___init__ (interop_clientQ_L_19proc L_self, interop_clientQ_main self, sshQ_Client c, B_str reason) {
    ((interop_clientQ_L_19proc)(L_self))->self = self;
    ((interop_clientQ_L_19proc)(L_self))->c = c;
    ((interop_clientQ_L_19proc)(L_self))->reason = reason;
    return B_None;
}
$R interop_clientQ_L_19procD___call__ (interop_clientQ_L_19proc L_self, $Cont C_cont) {
    interop_clientQ_main self = ((interop_clientQ_L_19proc)(L_self))->self;
    sshQ_Client c = ((interop_clientQ_L_19proc)(L_self))->c;
    B_str reason = ((interop_clientQ_L_19proc)(L_self))->reason;
    return (($R (*) ($WORD, $Cont, sshQ_Client, B_str))((interop_clientQ_main)(self))->$class->on_closeG_local)(self, C_cont, c, reason);
}
$R interop_clientQ_L_19procD___exec__ (interop_clientQ_L_19proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((interop_clientQ_L_19proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void interop_clientQ_L_19procD___serialize__ (interop_clientQ_L_19proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->c, state);
    $step_serialize(self->reason, state);
}
interop_clientQ_L_19proc interop_clientQ_L_19procD___deserialize__ (interop_clientQ_L_19proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct interop_clientQ_L_19proc));
            self->$class = &interop_clientQ_L_19procG_methods;
            return self;
        }
        self = $DNEW(interop_clientQ_L_19proc, state);
    }
    self->self = $step_deserialize(state);
    self->c = $step_deserialize(state);
    self->reason = $step_deserialize(state);
    return self;
}
interop_clientQ_L_19proc interop_clientQ_L_19procG_new(interop_clientQ_main G_1, sshQ_Client G_2, B_str G_3) {
    interop_clientQ_L_19proc $tmp = acton_malloc(sizeof(struct interop_clientQ_L_19proc));
    $tmp->$class = &interop_clientQ_L_19procG_methods;
    interop_clientQ_L_19procG_methods.__init__($tmp, G_1, G_2, G_3);
    return $tmp;
}
struct interop_clientQ_L_19procG_class interop_clientQ_L_19procG_methods;
B_NoneType interop_clientQ_L_20procD___init__ (interop_clientQ_L_20proc L_self, interop_clientQ_main self, sshQ_Channel ch, int64_t code, B_str sig, B_bytes out, B_bytes err_out, B_str error) {
    ((interop_clientQ_L_20proc)(L_self))->self = self;
    ((interop_clientQ_L_20proc)(L_self))->ch = ch;
    ((interop_clientQ_L_20proc)(L_self))->code = code;
    ((interop_clientQ_L_20proc)(L_self))->sig = sig;
    ((interop_clientQ_L_20proc)(L_self))->out = out;
    ((interop_clientQ_L_20proc)(L_self))->err_out = err_out;
    ((interop_clientQ_L_20proc)(L_self))->error = error;
    return B_None;
}
$R interop_clientQ_L_20procD___call__ (interop_clientQ_L_20proc L_self, $Cont C_cont) {
    interop_clientQ_main self = ((interop_clientQ_L_20proc)(L_self))->self;
    sshQ_Channel ch = ((interop_clientQ_L_20proc)(L_self))->ch;
    int64_t code = ((int64_t)((interop_clientQ_L_20proc)(L_self))->code);
    B_str sig = ((interop_clientQ_L_20proc)(L_self))->sig;
    B_bytes out = ((interop_clientQ_L_20proc)(L_self))->out;
    B_bytes err_out = ((interop_clientQ_L_20proc)(L_self))->err_out;
    B_str error = ((interop_clientQ_L_20proc)(L_self))->error;
    return (($R (*) ($WORD, $Cont, sshQ_Channel, int64_t, B_str, B_bytes, B_bytes, B_str))((interop_clientQ_main)(self))->$class->on_run_exitG_local)(self, C_cont, ch, code, sig, out, err_out, error);
}
$R interop_clientQ_L_20procD___exec__ (interop_clientQ_L_20proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((interop_clientQ_L_20proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void interop_clientQ_L_20procD___serialize__ (interop_clientQ_L_20proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->ch, state);
    $val_serialize(I64_ID, &self->code, state);
    $step_serialize(self->sig, state);
    $step_serialize(self->out, state);
    $step_serialize(self->err_out, state);
    $step_serialize(self->error, state);
}
interop_clientQ_L_20proc interop_clientQ_L_20procD___deserialize__ (interop_clientQ_L_20proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct interop_clientQ_L_20proc));
            self->$class = &interop_clientQ_L_20procG_methods;
            return self;
        }
        self = $DNEW(interop_clientQ_L_20proc, state);
    }
    self->self = $step_deserialize(state);
    self->ch = $step_deserialize(state);
    $tmp = $val_deserialize(state);
    memcpy(&self->code, &$tmp, sizeof(self->code));
    self->sig = $step_deserialize(state);
    self->out = $step_deserialize(state);
    self->err_out = $step_deserialize(state);
    self->error = $step_deserialize(state);
    return self;
}
interop_clientQ_L_20proc interop_clientQ_L_20procG_new(interop_clientQ_main G_1, sshQ_Channel G_2, int64_t G_3, B_str G_4, B_bytes G_5, B_bytes G_6, B_str G_7) {
    interop_clientQ_L_20proc $tmp = acton_malloc(sizeof(struct interop_clientQ_L_20proc));
    $tmp->$class = &interop_clientQ_L_20procG_methods;
    interop_clientQ_L_20procG_methods.__init__($tmp, G_1, G_2, G_3, G_4, G_5, G_6, G_7);
    return $tmp;
}
struct interop_clientQ_L_20procG_class interop_clientQ_L_20procG_methods;
$R interop_clientQ_L_21C_9cont ($Cont C_cont, interop_clientQ_main G_act, B_NoneType C_10res) {
    return $R_CONT(C_cont, G_act);
}
B_NoneType interop_clientQ_L_22ContD___init__ (interop_clientQ_L_22Cont L_self, $Cont C_cont, interop_clientQ_main G_act) {
    ((interop_clientQ_L_22Cont)(L_self))->C_cont = C_cont;
    ((interop_clientQ_L_22Cont)(L_self))->G_act = G_act;
    return B_None;
}
$R interop_clientQ_L_22ContD___call__ (interop_clientQ_L_22Cont L_self, B_NoneType G_1) {
    $Cont C_cont = ((interop_clientQ_L_22Cont)(L_self))->C_cont;
    interop_clientQ_main G_act = ((interop_clientQ_L_22Cont)(L_self))->G_act;
    return interop_clientQ_L_21C_9cont(C_cont, G_act, G_1);
}
void interop_clientQ_L_22ContD___serialize__ (interop_clientQ_L_22Cont self, $Serial$state state) {
    $step_serialize(self->C_cont, state);
    $step_serialize(self->G_act, state);
}
interop_clientQ_L_22Cont interop_clientQ_L_22ContD___deserialize__ (interop_clientQ_L_22Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct interop_clientQ_L_22Cont));
            self->$class = &interop_clientQ_L_22ContG_methods;
            return self;
        }
        self = $DNEW(interop_clientQ_L_22Cont, state);
    }
    self->C_cont = $step_deserialize(state);
    self->G_act = $step_deserialize(state);
    return self;
}
interop_clientQ_L_22Cont interop_clientQ_L_22ContG_new($Cont G_1, interop_clientQ_main G_2) {
    interop_clientQ_L_22Cont $tmp = acton_malloc(sizeof(struct interop_clientQ_L_22Cont));
    $tmp->$class = &interop_clientQ_L_22ContG_methods;
    interop_clientQ_L_22ContG_methods.__init__($tmp, G_1, G_2);
    return $tmp;
}
struct interop_clientQ_L_22ContG_class interop_clientQ_L_22ContG_methods;
B_NoneType interop_clientQ_L_23procD___init__ (interop_clientQ_L_23proc L_self, interop_clientQ_main G_act, B_Env env) {
    ((interop_clientQ_L_23proc)(L_self))->G_act = G_act;
    ((interop_clientQ_L_23proc)(L_self))->env = env;
    return B_None;
}
$R interop_clientQ_L_23procD___call__ (interop_clientQ_L_23proc L_self, $Cont C_cont) {
    interop_clientQ_main G_act = ((interop_clientQ_L_23proc)(L_self))->G_act;
    B_Env env = ((interop_clientQ_L_23proc)(L_self))->env;
    return (($R (*) ($WORD, $Cont, B_Env))((interop_clientQ_main)(G_act))->$class->__init__)(G_act, C_cont, env);
}
$R interop_clientQ_L_23procD___exec__ (interop_clientQ_L_23proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((interop_clientQ_L_23proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void interop_clientQ_L_23procD___serialize__ (interop_clientQ_L_23proc self, $Serial$state state) {
    $step_serialize(self->G_act, state);
    $step_serialize(self->env, state);
}
interop_clientQ_L_23proc interop_clientQ_L_23procD___deserialize__ (interop_clientQ_L_23proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct interop_clientQ_L_23proc));
            self->$class = &interop_clientQ_L_23procG_methods;
            return self;
        }
        self = $DNEW(interop_clientQ_L_23proc, state);
    }
    self->G_act = $step_deserialize(state);
    self->env = $step_deserialize(state);
    return self;
}
interop_clientQ_L_23proc interop_clientQ_L_23procG_new(interop_clientQ_main G_1, B_Env G_2) {
    interop_clientQ_L_23proc $tmp = acton_malloc(sizeof(struct interop_clientQ_L_23proc));
    $tmp->$class = &interop_clientQ_L_23procG_methods;
    interop_clientQ_L_23procG_methods.__init__($tmp, G_1, G_2);
    return $tmp;
}
struct interop_clientQ_L_23procG_class interop_clientQ_L_23procG_methods;
$R interop_clientQ_mainD___init__ (interop_clientQ_main self, $Cont C_cont, B_Env env) {
    ((interop_clientQ_main)(self))->env = env;
    #line 15 "src/interop_client.act"
    if (((int64_t (*) (B_Collection, B_list))B_len)(interop_clientQ_W_main_15, ((B_Env)(((interop_clientQ_main)(self))->env))->argv) < 5LL) {
        #line 16 "src/interop_client.act"
        ((B_NoneType (*) (B_tuple, B_str, B_str, B_bool, B_bool))B_print)($NEWTUPLE(1, to$str("usage: interop_client HOST PORT USER CMD [KEYFILE [PASSWORD]]")), B_None, B_None, B_None, B_None);
        #line 17 "src/interop_client.act"
        ((B_Msg (*) ($WORD, int64_t))((B_Env)(((interop_clientQ_main)(self))->env))->$class->exit)(((interop_clientQ_main)(self))->env, 2LL);
    }
    #line 19 "src/interop_client.act"
    ((interop_clientQ_main)(self))->host = $listD_U__getitem__(((B_Env)(((interop_clientQ_main)(self))->env))->argv, 1LL);
    #line 20 "src/interop_client.act"
    ((interop_clientQ_main)(self))->port = B_u16G_new(((B_atom)toB_int(B_intG_new(((B_atom)$listD_U__getitem__(((B_Env)(((interop_clientQ_main)(self))->env))->argv, 2LL)), B_None))), B_None);
    #line 21 "src/interop_client.act"
    ((interop_clientQ_main)(self))->user = $listD_U__getitem__(((B_Env)(((interop_clientQ_main)(self))->env))->argv, 3LL);
    #line 22 "src/interop_client.act"
    ((interop_clientQ_main)(self))->cmd = $listD_U__getitem__(((B_Env)(((interop_clientQ_main)(self))->env))->argv, 4LL);
    #line 23 "src/interop_client.act"
    ((interop_clientQ_main)(self))->keyfile = B_None;
    #line 24 "src/interop_client.act"
    ((interop_clientQ_main)(self))->password = B_None;
    #line 25 "src/interop_client.act"
    if (((int64_t (*) (B_Collection, B_list))B_len)(interop_clientQ_W_main_15, ((B_Env)(((interop_clientQ_main)(self))->env))->argv) > 5LL) {
        #line 26 "src/interop_client.act"
        ((interop_clientQ_main)(self))->keyfile = $listD_U__getitem__(((B_Env)(((interop_clientQ_main)(self))->env))->argv, 5LL);
    }
    #line 27 "src/interop_client.act"
    if (((int64_t (*) (B_Collection, B_list))B_len)(interop_clientQ_W_main_15, ((B_Env)(((interop_clientQ_main)(self))->env))->argv) > 6LL) {
        #line 28 "src/interop_client.act"
        ((interop_clientQ_main)(self))->password = $listD_U__getitem__(((B_Env)(((interop_clientQ_main)(self))->env))->argv, 6LL);
    }
    #line 30 "src/interop_client.act"
    ((interop_clientQ_main)(self))->client = B_None;
    return sshQ_ClientG_newact((($Cont)interop_clientQ_L_2ContG_new(self, C_cont)), netQ_TCPConnectCapG_new(netQ_TCPCapG_new(netQ_NetCapG_new(((B_Env)(((interop_clientQ_main)(self))->env))->cap))), ((interop_clientQ_main)(self))->host, ((interop_clientQ_main)(self))->user, (($action)interop_clientQ_L_4actionG_new(self)), (($action)interop_clientQ_L_6actionG_new(self)), (($action)interop_clientQ_L_8actionG_new(self)), ((interop_clientQ_main)(self))->password, ((interop_clientQ_main)(self))->keyfile, B_None, toB_u16(((uint16_t)((interop_clientQ_main)(self))->port)), B_None, toB_float(10.0), toB_float(10.0), B_None, B_None, B_None, B_None);
}
#line 32 "src/interop_client.act"
$R interop_clientQ_mainD_on_hostkeyG_local (interop_clientQ_main self, $Cont C_cont, sshQ_Client c, B_str state, sshQ_HostKeyInfo info) {
    #line 33 "src/interop_client.act"
    ((B_NoneType (*) (B_tuple, B_str, B_str, B_bool, B_bool))B_print)($NEWTUPLE(4, to$str("HOSTKEY"), state, ((sshQ_HostKeyInfo)(info))->key_type, ((sshQ_HostKeyInfo)(info))->fingerprint), B_None, B_None, B_None, B_None);
    #line 34 "src/interop_client.act"
    ((B_Msg (*) ($WORD))((sshQ_Client)(c))->$class->accept_hostkey)(c);
    return $R_CONT(C_cont, B_None);
}
#line 36 "src/interop_client.act"
$R interop_clientQ_mainD_on_connectG_local (interop_clientQ_main self, $Cont C_cont, sshQ_Client c, B_str err) {
    if ($ISNOTNONE0(err)) {
        #line 38 "src/interop_client.act"
        ((B_NoneType (*) (B_tuple, B_str, B_str, B_bool, B_bool))B_print)($NEWTUPLE(2, to$str("CONNECT-ERROR"), ((B_str)err)), B_None, B_None, B_None, B_None);
        #line 39 "src/interop_client.act"
        ((B_Msg (*) ($WORD, int64_t))((B_Env)(((interop_clientQ_main)(self))->env))->$class->exit)(((interop_clientQ_main)(self))->env, 1LL);
        return $R_CONT(C_cont, B_None);
    }
    else {
        return $R_CONT((($Cont)interop_clientQ_L_14ContG_new(C_cont, c, self)), B_None);
    }
}
#line 44 "src/interop_client.act"
$R interop_clientQ_mainD_on_closeG_local (interop_clientQ_main self, $Cont C_cont, sshQ_Client c, B_str reason) {
    #line 45 "src/interop_client.act"
    return $R_CONT(C_cont, B_None);
}
#line 47 "src/interop_client.act"
$R interop_clientQ_mainD_on_run_exitG_local (interop_clientQ_main self, $Cont C_cont, sshQ_Channel ch, int64_t code, B_str sig, B_bytes out, B_bytes err_out, B_str error) {
    B_Collection W_main_472 = (B_Collection)B_ContainerD_bytesG_witness;
    if ($ISNOTNONE0(error)) {
        #line 49 "src/interop_client.act"
        ((B_NoneType (*) (B_tuple, B_str, B_str, B_bool, B_bool))B_print)($NEWTUPLE(2, to$str("RUN-ERROR"), ((B_str)error)), B_None, B_None, B_None, B_None);
        #line 50 "src/interop_client.act"
        ((B_Msg (*) ($WORD, int64_t))((B_Env)(((interop_clientQ_main)(self))->env))->$class->exit)(((interop_clientQ_main)(self))->env, 1LL);
        return $R_CONT(C_cont, B_None);
    }
    else {
        return $R_CONT((($Cont)interop_clientQ_L_16ContG_new(out, W_main_472, err_out, code, self, C_cont)), B_None);
    }
}
B_Msg interop_clientQ_mainD_on_hostkey (interop_clientQ_main self, sshQ_Client c, B_str state, sshQ_HostKeyInfo info) {
    return $ASYNC((($Actor)self), (($Cont)interop_clientQ_L_17procG_new(self, c, state, info)));
}
B_Msg interop_clientQ_mainD_on_connect (interop_clientQ_main self, sshQ_Client c, B_str err) {
    return $ASYNC((($Actor)self), (($Cont)interop_clientQ_L_18procG_new(self, c, err)));
}
B_Msg interop_clientQ_mainD_on_close (interop_clientQ_main self, sshQ_Client c, B_str reason) {
    return $ASYNC((($Actor)self), (($Cont)interop_clientQ_L_19procG_new(self, c, reason)));
}
B_Msg interop_clientQ_mainD_on_run_exit (interop_clientQ_main self, sshQ_Channel ch, int64_t code, B_str sig, B_bytes out, B_bytes err_out, B_str error) {
    return $ASYNC((($Actor)self), (($Cont)interop_clientQ_L_20procG_new(self, ch, code, sig, out, err_out, error)));
}
void interop_clientQ_mainD___serialize__ (interop_clientQ_main self, $Serial$state state) {
    $ActorG_methods.__serialize__(($Actor)self, state);
    $step_serialize(self->env, state);
    $step_serialize(self->host, state);
    $val_serialize(U16_ID, &self->port, state);
    $step_serialize(self->user, state);
    $step_serialize(self->cmd, state);
    $step_serialize(self->keyfile, state);
    $step_serialize(self->password, state);
    $step_serialize(self->client, state);
}
interop_clientQ_main interop_clientQ_mainD___deserialize__ (interop_clientQ_main self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct interop_clientQ_main));
            self->$class = &interop_clientQ_mainG_methods;
            return self;
        }
        self = $DNEW(interop_clientQ_main, state);
    }
    $ActorG_methods.__deserialize__(($Actor)self, state);
    self->env = $step_deserialize(state);
    self->host = $step_deserialize(state);
    $tmp = $val_deserialize(state);
    memcpy(&self->port, &$tmp, sizeof(self->port));
    self->user = $step_deserialize(state);
    self->cmd = $step_deserialize(state);
    self->keyfile = $step_deserialize(state);
    self->password = $step_deserialize(state);
    self->client = $step_deserialize(state);
    return self;
}
void interop_clientQ_mainD_GCfinalizer (void *obj, void *cdata) {
    interop_clientQ_main self = (interop_clientQ_main)obj;
    self->$class->__cleanup__(self);
}
$R interop_clientQ_mainG_new($Cont G_1, B_Env G_2) {
    interop_clientQ_main $tmp = acton_malloc(sizeof(struct interop_clientQ_main));
    $tmp->$class = &interop_clientQ_mainG_methods;
    return interop_clientQ_mainG_methods.__init__($tmp, $CONSTCONT($tmp, G_1), G_2);
}
struct interop_clientQ_mainG_class interop_clientQ_mainG_methods;
$R interop_clientQ_mainG_newact ($Cont C_cont, B_Env env) {
    interop_clientQ_main G_act = $NEWACTOR(interop_clientQ_main);
    if ((void*)G_act->$class->__cleanup__ != (void*)$ActorD___cleanup__) $InstallFinalizer(G_act, interop_clientQ_mainD_GCfinalizer);
    return $AWAIT((($Cont)interop_clientQ_L_22ContG_new(C_cont, G_act)), $ASYNC((($Actor)G_act), (($Cont)interop_clientQ_L_23procG_new(G_act, env))));
}
int interop_clientQ_done$ = 0;
void interop_clientQ___init__ () {
    if (interop_clientQ_done$) return;
    interop_clientQ_done$ = 1;
    netQ___init__();
    sshQ___init__();
    {
        interop_clientQ_L_2ContG_methods.$GCINFO = "interop_clientQ_L_2Cont";
        interop_clientQ_L_2ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        interop_clientQ_L_2ContG_methods.__bool__ = (B_bool (*) (interop_clientQ_L_2Cont))B_valueG_methods.__bool__;
        interop_clientQ_L_2ContG_methods.__str__ = (B_str (*) (interop_clientQ_L_2Cont))B_valueG_methods.__str__;
        interop_clientQ_L_2ContG_methods.__repr__ = (B_str (*) (interop_clientQ_L_2Cont))B_valueG_methods.__repr__;
        interop_clientQ_L_2ContG_methods.__init__ = (B_NoneType (*) (interop_clientQ_L_2Cont, interop_clientQ_main, $Cont))interop_clientQ_L_2ContD___init__;
        interop_clientQ_L_2ContG_methods.__call__ = ($R (*) (interop_clientQ_L_2Cont, sshQ_Client))interop_clientQ_L_2ContD___call__;
        interop_clientQ_L_2ContG_methods.__serialize__ = interop_clientQ_L_2ContD___serialize__;
        interop_clientQ_L_2ContG_methods.__deserialize__ = interop_clientQ_L_2ContD___deserialize__;
        $register(&interop_clientQ_L_2ContG_methods);
    }
    {
        interop_clientQ_L_4actionG_methods.$GCINFO = "interop_clientQ_L_4action";
        interop_clientQ_L_4actionG_methods.$superclass = ($SuperG_class)&$actionG_methods;
        interop_clientQ_L_4actionG_methods.__bool__ = (B_bool (*) (interop_clientQ_L_4action))B_valueG_methods.__bool__;
        interop_clientQ_L_4actionG_methods.__str__ = (B_str (*) (interop_clientQ_L_4action))B_valueG_methods.__str__;
        interop_clientQ_L_4actionG_methods.__repr__ = (B_str (*) (interop_clientQ_L_4action))B_valueG_methods.__repr__;
        interop_clientQ_L_4actionG_methods.__init__ = (B_NoneType (*) (interop_clientQ_L_4action, interop_clientQ_main))interop_clientQ_L_4actionD___init__;
        interop_clientQ_L_4actionG_methods.__call__ = ($R (*) (interop_clientQ_L_4action, $Cont, sshQ_Client, B_str))interop_clientQ_L_4actionD___call__;
        interop_clientQ_L_4actionG_methods.__exec__ = ($R (*) (interop_clientQ_L_4action, $Cont, sshQ_Client, B_str))interop_clientQ_L_4actionD___exec__;
        interop_clientQ_L_4actionG_methods.__asyn__ = (B_Msg (*) (interop_clientQ_L_4action, sshQ_Client, B_str))interop_clientQ_L_4actionD___asyn__;
        interop_clientQ_L_4actionG_methods.__serialize__ = interop_clientQ_L_4actionD___serialize__;
        interop_clientQ_L_4actionG_methods.__deserialize__ = interop_clientQ_L_4actionD___deserialize__;
        $register(&interop_clientQ_L_4actionG_methods);
    }
    {
        interop_clientQ_L_6actionG_methods.$GCINFO = "interop_clientQ_L_6action";
        interop_clientQ_L_6actionG_methods.$superclass = ($SuperG_class)&$actionG_methods;
        interop_clientQ_L_6actionG_methods.__bool__ = (B_bool (*) (interop_clientQ_L_6action))B_valueG_methods.__bool__;
        interop_clientQ_L_6actionG_methods.__str__ = (B_str (*) (interop_clientQ_L_6action))B_valueG_methods.__str__;
        interop_clientQ_L_6actionG_methods.__repr__ = (B_str (*) (interop_clientQ_L_6action))B_valueG_methods.__repr__;
        interop_clientQ_L_6actionG_methods.__init__ = (B_NoneType (*) (interop_clientQ_L_6action, interop_clientQ_main))interop_clientQ_L_6actionD___init__;
        interop_clientQ_L_6actionG_methods.__call__ = ($R (*) (interop_clientQ_L_6action, $Cont, sshQ_Client, B_str))interop_clientQ_L_6actionD___call__;
        interop_clientQ_L_6actionG_methods.__exec__ = ($R (*) (interop_clientQ_L_6action, $Cont, sshQ_Client, B_str))interop_clientQ_L_6actionD___exec__;
        interop_clientQ_L_6actionG_methods.__asyn__ = (B_Msg (*) (interop_clientQ_L_6action, sshQ_Client, B_str))interop_clientQ_L_6actionD___asyn__;
        interop_clientQ_L_6actionG_methods.__serialize__ = interop_clientQ_L_6actionD___serialize__;
        interop_clientQ_L_6actionG_methods.__deserialize__ = interop_clientQ_L_6actionD___deserialize__;
        $register(&interop_clientQ_L_6actionG_methods);
    }
    {
        interop_clientQ_L_8actionG_methods.$GCINFO = "interop_clientQ_L_8action";
        interop_clientQ_L_8actionG_methods.$superclass = ($SuperG_class)&$actionG_methods;
        interop_clientQ_L_8actionG_methods.__bool__ = (B_bool (*) (interop_clientQ_L_8action))B_valueG_methods.__bool__;
        interop_clientQ_L_8actionG_methods.__str__ = (B_str (*) (interop_clientQ_L_8action))B_valueG_methods.__str__;
        interop_clientQ_L_8actionG_methods.__repr__ = (B_str (*) (interop_clientQ_L_8action))B_valueG_methods.__repr__;
        interop_clientQ_L_8actionG_methods.__init__ = (B_NoneType (*) (interop_clientQ_L_8action, interop_clientQ_main))interop_clientQ_L_8actionD___init__;
        interop_clientQ_L_8actionG_methods.__call__ = ($R (*) (interop_clientQ_L_8action, $Cont, sshQ_Client, B_str, sshQ_HostKeyInfo))interop_clientQ_L_8actionD___call__;
        interop_clientQ_L_8actionG_methods.__exec__ = ($R (*) (interop_clientQ_L_8action, $Cont, sshQ_Client, B_str, sshQ_HostKeyInfo))interop_clientQ_L_8actionD___exec__;
        interop_clientQ_L_8actionG_methods.__asyn__ = (B_Msg (*) (interop_clientQ_L_8action, sshQ_Client, B_str, sshQ_HostKeyInfo))interop_clientQ_L_8actionD___asyn__;
        interop_clientQ_L_8actionG_methods.__serialize__ = interop_clientQ_L_8actionD___serialize__;
        interop_clientQ_L_8actionG_methods.__deserialize__ = interop_clientQ_L_8actionD___deserialize__;
        $register(&interop_clientQ_L_8actionG_methods);
    }
    {
        interop_clientQ_L_11ContG_methods.$GCINFO = "interop_clientQ_L_11Cont";
        interop_clientQ_L_11ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        interop_clientQ_L_11ContG_methods.__bool__ = (B_bool (*) (interop_clientQ_L_11Cont))B_valueG_methods.__bool__;
        interop_clientQ_L_11ContG_methods.__str__ = (B_str (*) (interop_clientQ_L_11Cont))B_valueG_methods.__str__;
        interop_clientQ_L_11ContG_methods.__repr__ = (B_str (*) (interop_clientQ_L_11Cont))B_valueG_methods.__repr__;
        interop_clientQ_L_11ContG_methods.__init__ = (B_NoneType (*) (interop_clientQ_L_11Cont, $Cont))interop_clientQ_L_11ContD___init__;
        interop_clientQ_L_11ContG_methods.__call__ = ($R (*) (interop_clientQ_L_11Cont, sshQ_RunCommand))interop_clientQ_L_11ContD___call__;
        interop_clientQ_L_11ContG_methods.__serialize__ = interop_clientQ_L_11ContD___serialize__;
        interop_clientQ_L_11ContG_methods.__deserialize__ = interop_clientQ_L_11ContD___deserialize__;
        $register(&interop_clientQ_L_11ContG_methods);
    }
    {
        interop_clientQ_L_13actionG_methods.$GCINFO = "interop_clientQ_L_13action";
        interop_clientQ_L_13actionG_methods.$superclass = ($SuperG_class)&$actionG_methods;
        interop_clientQ_L_13actionG_methods.__bool__ = (B_bool (*) (interop_clientQ_L_13action))B_valueG_methods.__bool__;
        interop_clientQ_L_13actionG_methods.__str__ = (B_str (*) (interop_clientQ_L_13action))B_valueG_methods.__str__;
        interop_clientQ_L_13actionG_methods.__repr__ = (B_str (*) (interop_clientQ_L_13action))B_valueG_methods.__repr__;
        interop_clientQ_L_13actionG_methods.__init__ = (B_NoneType (*) (interop_clientQ_L_13action, interop_clientQ_main))interop_clientQ_L_13actionD___init__;
        interop_clientQ_L_13actionG_methods.__call__ = ($R (*) (interop_clientQ_L_13action, $Cont, sshQ_Channel, B_int, B_str, B_bytes, B_bytes, B_str))interop_clientQ_L_13actionD___call__;
        interop_clientQ_L_13actionG_methods.__exec__ = ($R (*) (interop_clientQ_L_13action, $Cont, sshQ_Channel, B_int, B_str, B_bytes, B_bytes, B_str))interop_clientQ_L_13actionD___exec__;
        interop_clientQ_L_13actionG_methods.__asyn__ = (B_Msg (*) (interop_clientQ_L_13action, sshQ_Channel, B_int, B_str, B_bytes, B_bytes, B_str))interop_clientQ_L_13actionD___asyn__;
        interop_clientQ_L_13actionG_methods.__serialize__ = interop_clientQ_L_13actionD___serialize__;
        interop_clientQ_L_13actionG_methods.__deserialize__ = interop_clientQ_L_13actionD___deserialize__;
        $register(&interop_clientQ_L_13actionG_methods);
    }
    {
        interop_clientQ_L_14ContG_methods.$GCINFO = "interop_clientQ_L_14Cont";
        interop_clientQ_L_14ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        interop_clientQ_L_14ContG_methods.__bool__ = (B_bool (*) (interop_clientQ_L_14Cont))B_valueG_methods.__bool__;
        interop_clientQ_L_14ContG_methods.__str__ = (B_str (*) (interop_clientQ_L_14Cont))B_valueG_methods.__str__;
        interop_clientQ_L_14ContG_methods.__repr__ = (B_str (*) (interop_clientQ_L_14Cont))B_valueG_methods.__repr__;
        interop_clientQ_L_14ContG_methods.__init__ = (B_NoneType (*) (interop_clientQ_L_14Cont, $Cont, sshQ_Client, interop_clientQ_main))interop_clientQ_L_14ContD___init__;
        interop_clientQ_L_14ContG_methods.__call__ = ($R (*) (interop_clientQ_L_14Cont, B_NoneType))interop_clientQ_L_14ContD___call__;
        interop_clientQ_L_14ContG_methods.__serialize__ = interop_clientQ_L_14ContD___serialize__;
        interop_clientQ_L_14ContG_methods.__deserialize__ = interop_clientQ_L_14ContD___deserialize__;
        $register(&interop_clientQ_L_14ContG_methods);
    }
    {
        interop_clientQ_L_16ContG_methods.$GCINFO = "interop_clientQ_L_16Cont";
        interop_clientQ_L_16ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        interop_clientQ_L_16ContG_methods.__bool__ = (B_bool (*) (interop_clientQ_L_16Cont))B_valueG_methods.__bool__;
        interop_clientQ_L_16ContG_methods.__str__ = (B_str (*) (interop_clientQ_L_16Cont))B_valueG_methods.__str__;
        interop_clientQ_L_16ContG_methods.__repr__ = (B_str (*) (interop_clientQ_L_16Cont))B_valueG_methods.__repr__;
        interop_clientQ_L_16ContG_methods.__init__ = (B_NoneType (*) (interop_clientQ_L_16Cont, B_bytes, B_Collection, B_bytes, int64_t, interop_clientQ_main, $Cont))interop_clientQ_L_16ContD___init__;
        interop_clientQ_L_16ContG_methods.__call__ = ($R (*) (interop_clientQ_L_16Cont, B_NoneType))interop_clientQ_L_16ContD___call__;
        interop_clientQ_L_16ContG_methods.__serialize__ = interop_clientQ_L_16ContD___serialize__;
        interop_clientQ_L_16ContG_methods.__deserialize__ = interop_clientQ_L_16ContD___deserialize__;
        $register(&interop_clientQ_L_16ContG_methods);
    }
    {
        interop_clientQ_L_17procG_methods.$GCINFO = "interop_clientQ_L_17proc";
        interop_clientQ_L_17procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        interop_clientQ_L_17procG_methods.__bool__ = (B_bool (*) (interop_clientQ_L_17proc))B_valueG_methods.__bool__;
        interop_clientQ_L_17procG_methods.__str__ = (B_str (*) (interop_clientQ_L_17proc))B_valueG_methods.__str__;
        interop_clientQ_L_17procG_methods.__repr__ = (B_str (*) (interop_clientQ_L_17proc))B_valueG_methods.__repr__;
        interop_clientQ_L_17procG_methods.__init__ = (B_NoneType (*) (interop_clientQ_L_17proc, interop_clientQ_main, sshQ_Client, B_str, sshQ_HostKeyInfo))interop_clientQ_L_17procD___init__;
        interop_clientQ_L_17procG_methods.__call__ = ($R (*) (interop_clientQ_L_17proc, $Cont))interop_clientQ_L_17procD___call__;
        interop_clientQ_L_17procG_methods.__exec__ = ($R (*) (interop_clientQ_L_17proc, $Cont))interop_clientQ_L_17procD___exec__;
        interop_clientQ_L_17procG_methods.__serialize__ = interop_clientQ_L_17procD___serialize__;
        interop_clientQ_L_17procG_methods.__deserialize__ = interop_clientQ_L_17procD___deserialize__;
        $register(&interop_clientQ_L_17procG_methods);
    }
    {
        interop_clientQ_L_18procG_methods.$GCINFO = "interop_clientQ_L_18proc";
        interop_clientQ_L_18procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        interop_clientQ_L_18procG_methods.__bool__ = (B_bool (*) (interop_clientQ_L_18proc))B_valueG_methods.__bool__;
        interop_clientQ_L_18procG_methods.__str__ = (B_str (*) (interop_clientQ_L_18proc))B_valueG_methods.__str__;
        interop_clientQ_L_18procG_methods.__repr__ = (B_str (*) (interop_clientQ_L_18proc))B_valueG_methods.__repr__;
        interop_clientQ_L_18procG_methods.__init__ = (B_NoneType (*) (interop_clientQ_L_18proc, interop_clientQ_main, sshQ_Client, B_str))interop_clientQ_L_18procD___init__;
        interop_clientQ_L_18procG_methods.__call__ = ($R (*) (interop_clientQ_L_18proc, $Cont))interop_clientQ_L_18procD___call__;
        interop_clientQ_L_18procG_methods.__exec__ = ($R (*) (interop_clientQ_L_18proc, $Cont))interop_clientQ_L_18procD___exec__;
        interop_clientQ_L_18procG_methods.__serialize__ = interop_clientQ_L_18procD___serialize__;
        interop_clientQ_L_18procG_methods.__deserialize__ = interop_clientQ_L_18procD___deserialize__;
        $register(&interop_clientQ_L_18procG_methods);
    }
    {
        interop_clientQ_L_19procG_methods.$GCINFO = "interop_clientQ_L_19proc";
        interop_clientQ_L_19procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        interop_clientQ_L_19procG_methods.__bool__ = (B_bool (*) (interop_clientQ_L_19proc))B_valueG_methods.__bool__;
        interop_clientQ_L_19procG_methods.__str__ = (B_str (*) (interop_clientQ_L_19proc))B_valueG_methods.__str__;
        interop_clientQ_L_19procG_methods.__repr__ = (B_str (*) (interop_clientQ_L_19proc))B_valueG_methods.__repr__;
        interop_clientQ_L_19procG_methods.__init__ = (B_NoneType (*) (interop_clientQ_L_19proc, interop_clientQ_main, sshQ_Client, B_str))interop_clientQ_L_19procD___init__;
        interop_clientQ_L_19procG_methods.__call__ = ($R (*) (interop_clientQ_L_19proc, $Cont))interop_clientQ_L_19procD___call__;
        interop_clientQ_L_19procG_methods.__exec__ = ($R (*) (interop_clientQ_L_19proc, $Cont))interop_clientQ_L_19procD___exec__;
        interop_clientQ_L_19procG_methods.__serialize__ = interop_clientQ_L_19procD___serialize__;
        interop_clientQ_L_19procG_methods.__deserialize__ = interop_clientQ_L_19procD___deserialize__;
        $register(&interop_clientQ_L_19procG_methods);
    }
    {
        interop_clientQ_L_20procG_methods.$GCINFO = "interop_clientQ_L_20proc";
        interop_clientQ_L_20procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        interop_clientQ_L_20procG_methods.__bool__ = (B_bool (*) (interop_clientQ_L_20proc))B_valueG_methods.__bool__;
        interop_clientQ_L_20procG_methods.__str__ = (B_str (*) (interop_clientQ_L_20proc))B_valueG_methods.__str__;
        interop_clientQ_L_20procG_methods.__repr__ = (B_str (*) (interop_clientQ_L_20proc))B_valueG_methods.__repr__;
        interop_clientQ_L_20procG_methods.__init__ = (B_NoneType (*) (interop_clientQ_L_20proc, interop_clientQ_main, sshQ_Channel, int64_t, B_str, B_bytes, B_bytes, B_str))interop_clientQ_L_20procD___init__;
        interop_clientQ_L_20procG_methods.__call__ = ($R (*) (interop_clientQ_L_20proc, $Cont))interop_clientQ_L_20procD___call__;
        interop_clientQ_L_20procG_methods.__exec__ = ($R (*) (interop_clientQ_L_20proc, $Cont))interop_clientQ_L_20procD___exec__;
        interop_clientQ_L_20procG_methods.__serialize__ = interop_clientQ_L_20procD___serialize__;
        interop_clientQ_L_20procG_methods.__deserialize__ = interop_clientQ_L_20procD___deserialize__;
        $register(&interop_clientQ_L_20procG_methods);
    }
    {
        interop_clientQ_L_22ContG_methods.$GCINFO = "interop_clientQ_L_22Cont";
        interop_clientQ_L_22ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        interop_clientQ_L_22ContG_methods.__bool__ = (B_bool (*) (interop_clientQ_L_22Cont))B_valueG_methods.__bool__;
        interop_clientQ_L_22ContG_methods.__str__ = (B_str (*) (interop_clientQ_L_22Cont))B_valueG_methods.__str__;
        interop_clientQ_L_22ContG_methods.__repr__ = (B_str (*) (interop_clientQ_L_22Cont))B_valueG_methods.__repr__;
        interop_clientQ_L_22ContG_methods.__init__ = (B_NoneType (*) (interop_clientQ_L_22Cont, $Cont, interop_clientQ_main))interop_clientQ_L_22ContD___init__;
        interop_clientQ_L_22ContG_methods.__call__ = ($R (*) (interop_clientQ_L_22Cont, B_NoneType))interop_clientQ_L_22ContD___call__;
        interop_clientQ_L_22ContG_methods.__serialize__ = interop_clientQ_L_22ContD___serialize__;
        interop_clientQ_L_22ContG_methods.__deserialize__ = interop_clientQ_L_22ContD___deserialize__;
        $register(&interop_clientQ_L_22ContG_methods);
    }
    {
        interop_clientQ_L_23procG_methods.$GCINFO = "interop_clientQ_L_23proc";
        interop_clientQ_L_23procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        interop_clientQ_L_23procG_methods.__bool__ = (B_bool (*) (interop_clientQ_L_23proc))B_valueG_methods.__bool__;
        interop_clientQ_L_23procG_methods.__str__ = (B_str (*) (interop_clientQ_L_23proc))B_valueG_methods.__str__;
        interop_clientQ_L_23procG_methods.__repr__ = (B_str (*) (interop_clientQ_L_23proc))B_valueG_methods.__repr__;
        interop_clientQ_L_23procG_methods.__init__ = (B_NoneType (*) (interop_clientQ_L_23proc, interop_clientQ_main, B_Env))interop_clientQ_L_23procD___init__;
        interop_clientQ_L_23procG_methods.__call__ = ($R (*) (interop_clientQ_L_23proc, $Cont))interop_clientQ_L_23procD___call__;
        interop_clientQ_L_23procG_methods.__exec__ = ($R (*) (interop_clientQ_L_23proc, $Cont))interop_clientQ_L_23procD___exec__;
        interop_clientQ_L_23procG_methods.__serialize__ = interop_clientQ_L_23procD___serialize__;
        interop_clientQ_L_23procG_methods.__deserialize__ = interop_clientQ_L_23procD___deserialize__;
        $register(&interop_clientQ_L_23procG_methods);
    }
    {
        interop_clientQ_mainG_methods.$GCINFO = "interop_clientQ_main";
        interop_clientQ_mainG_methods.$superclass = ($SuperG_class)&$ActorG_methods;
        interop_clientQ_mainG_methods.__bool__ = (B_bool (*) (interop_clientQ_main))$ActorG_methods.__bool__;
        interop_clientQ_mainG_methods.__str__ = (B_str (*) (interop_clientQ_main))$ActorG_methods.__str__;
        interop_clientQ_mainG_methods.__repr__ = (B_str (*) (interop_clientQ_main))$ActorG_methods.__repr__;
        interop_clientQ_mainG_methods.__resume__ = (B_NoneType (*) (interop_clientQ_main))$ActorG_methods.__resume__;
        interop_clientQ_mainG_methods.__cleanup__ = (B_NoneType (*) (interop_clientQ_main))$ActorG_methods.__cleanup__;
        interop_clientQ_mainG_methods.__init__ = ($R (*) (interop_clientQ_main, $Cont, B_Env))interop_clientQ_mainD___init__;
        interop_clientQ_mainG_methods.on_hostkeyG_local = ($R (*) (interop_clientQ_main, $Cont, sshQ_Client, B_str, sshQ_HostKeyInfo))interop_clientQ_mainD_on_hostkeyG_local;
        interop_clientQ_mainG_methods.on_connectG_local = ($R (*) (interop_clientQ_main, $Cont, sshQ_Client, B_str))interop_clientQ_mainD_on_connectG_local;
        interop_clientQ_mainG_methods.on_closeG_local = ($R (*) (interop_clientQ_main, $Cont, sshQ_Client, B_str))interop_clientQ_mainD_on_closeG_local;
        interop_clientQ_mainG_methods.on_run_exitG_local = ($R (*) (interop_clientQ_main, $Cont, sshQ_Channel, int64_t, B_str, B_bytes, B_bytes, B_str))interop_clientQ_mainD_on_run_exitG_local;
        interop_clientQ_mainG_methods.on_hostkey = (B_Msg (*) (interop_clientQ_main, sshQ_Client, B_str, sshQ_HostKeyInfo))interop_clientQ_mainD_on_hostkey;
        interop_clientQ_mainG_methods.on_connect = (B_Msg (*) (interop_clientQ_main, sshQ_Client, B_str))interop_clientQ_mainD_on_connect;
        interop_clientQ_mainG_methods.on_close = (B_Msg (*) (interop_clientQ_main, sshQ_Client, B_str))interop_clientQ_mainD_on_close;
        interop_clientQ_mainG_methods.on_run_exit = (B_Msg (*) (interop_clientQ_main, sshQ_Channel, int64_t, B_str, B_bytes, B_bytes, B_str))interop_clientQ_mainD_on_run_exit;
        interop_clientQ_mainG_methods.__serialize__ = interop_clientQ_mainD___serialize__;
        interop_clientQ_mainG_methods.__deserialize__ = interop_clientQ_mainD___deserialize__;
        $register(&interop_clientQ_mainG_methods);
    }
    B_Collection W_main_15 = (B_Collection)B_SequenceD_listG_witness->W_Collection;
    interop_clientQ_W_main_15 = W_main_15;
}