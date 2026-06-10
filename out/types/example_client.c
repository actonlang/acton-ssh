/* Acton impl hash: 4cefa56d35e387fa3ad3dba417d0ca31a867d1c1ed966781f3be9350d3820462 */
#include "rts/common.h"
#include "out/types/example_client.h"
B_Collection example_clientQ_W_main_15;
B_Plus example_clientQ_W_main_238;
$R example_clientQ_L_2C_3cont (example_clientQ_main self, $Cont C_cont, sshQ_Client C_4res) {
    #line 75 "src/example_client.act"
    ((example_clientQ_main)(self))->client = C_4res;
    return $R_CONT(C_cont, B_None);
}
B_NoneType example_clientQ_L_3ContD___init__ (example_clientQ_L_3Cont L_self, example_clientQ_main self, $Cont C_cont) {
    ((example_clientQ_L_3Cont)(L_self))->self = self;
    ((example_clientQ_L_3Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R example_clientQ_L_3ContD___call__ (example_clientQ_L_3Cont L_self, sshQ_Client G_1) {
    example_clientQ_main self = ((example_clientQ_L_3Cont)(L_self))->self;
    $Cont C_cont = ((example_clientQ_L_3Cont)(L_self))->C_cont;
    return example_clientQ_L_2C_3cont(self, C_cont, G_1);
}
void example_clientQ_L_3ContD___serialize__ (example_clientQ_L_3Cont self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->C_cont, state);
}
example_clientQ_L_3Cont example_clientQ_L_3ContD___deserialize__ (example_clientQ_L_3Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct example_clientQ_L_3Cont));
            self->$class = &example_clientQ_L_3ContG_methods;
            return self;
        }
        self = $DNEW(example_clientQ_L_3Cont, state);
    }
    self->self = $step_deserialize(state);
    self->C_cont = $step_deserialize(state);
    return self;
}
example_clientQ_L_3Cont example_clientQ_L_3ContG_new(example_clientQ_main G_1, $Cont G_2) {
    example_clientQ_L_3Cont $tmp = acton_malloc(sizeof(struct example_clientQ_L_3Cont));
    $tmp->$class = &example_clientQ_L_3ContG_methods;
    example_clientQ_L_3ContG_methods.__init__($tmp, G_1, G_2);
    return $tmp;
}
struct example_clientQ_L_3ContG_class example_clientQ_L_3ContG_methods;
B_NoneType example_clientQ_L_5actionD___init__ (example_clientQ_L_5action L_self, example_clientQ_main L_4obj) {
    ((example_clientQ_L_5action)(L_self))->L_4obj = L_4obj;
    return B_None;
}
$R example_clientQ_L_5actionD___call__ (example_clientQ_L_5action L_self, $Cont L_cont, sshQ_Client G_1, B_str G_2) {
    return $AWAIT(L_cont, ((B_Msg (*) ($WORD, sshQ_Client, B_str))((example_clientQ_L_5action)(L_self))->$class->__asyn__)(L_self, G_1, G_2));
}
$R example_clientQ_L_5actionD___exec__ (example_clientQ_L_5action L_self, $Cont L_cont, sshQ_Client G_1, B_str G_2) {
    return $R_CONT(L_cont, ((B_Msg (*) ($WORD, sshQ_Client, B_str))((example_clientQ_L_5action)(L_self))->$class->__asyn__)(L_self, G_1, G_2));
}
B_Msg example_clientQ_L_5actionD___asyn__ (example_clientQ_L_5action L_self, sshQ_Client G_1, B_str G_2) {
    example_clientQ_main L_4obj = ((example_clientQ_L_5action)(L_self))->L_4obj;
    return ((B_Msg (*) ($WORD, sshQ_Client, B_str))((example_clientQ_main)(L_4obj))->$class->on_connect)(L_4obj, G_1, G_2);
}
void example_clientQ_L_5actionD___serialize__ (example_clientQ_L_5action self, $Serial$state state) {
    $step_serialize(self->L_4obj, state);
}
example_clientQ_L_5action example_clientQ_L_5actionD___deserialize__ (example_clientQ_L_5action self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct example_clientQ_L_5action));
            self->$class = &example_clientQ_L_5actionG_methods;
            return self;
        }
        self = $DNEW(example_clientQ_L_5action, state);
    }
    self->L_4obj = $step_deserialize(state);
    return self;
}
example_clientQ_L_5action example_clientQ_L_5actionG_new(example_clientQ_main G_1) {
    example_clientQ_L_5action $tmp = acton_malloc(sizeof(struct example_clientQ_L_5action));
    $tmp->$class = &example_clientQ_L_5actionG_methods;
    example_clientQ_L_5actionG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct example_clientQ_L_5actionG_class example_clientQ_L_5actionG_methods;
B_NoneType example_clientQ_L_7actionD___init__ (example_clientQ_L_7action L_self, example_clientQ_main L_6obj) {
    ((example_clientQ_L_7action)(L_self))->L_6obj = L_6obj;
    return B_None;
}
$R example_clientQ_L_7actionD___call__ (example_clientQ_L_7action L_self, $Cont L_cont, sshQ_Client G_1, B_str G_2) {
    return $AWAIT(L_cont, ((B_Msg (*) ($WORD, sshQ_Client, B_str))((example_clientQ_L_7action)(L_self))->$class->__asyn__)(L_self, G_1, G_2));
}
$R example_clientQ_L_7actionD___exec__ (example_clientQ_L_7action L_self, $Cont L_cont, sshQ_Client G_1, B_str G_2) {
    return $R_CONT(L_cont, ((B_Msg (*) ($WORD, sshQ_Client, B_str))((example_clientQ_L_7action)(L_self))->$class->__asyn__)(L_self, G_1, G_2));
}
B_Msg example_clientQ_L_7actionD___asyn__ (example_clientQ_L_7action L_self, sshQ_Client G_1, B_str G_2) {
    example_clientQ_main L_6obj = ((example_clientQ_L_7action)(L_self))->L_6obj;
    return ((B_Msg (*) ($WORD, sshQ_Client, B_str))((example_clientQ_main)(L_6obj))->$class->on_close)(L_6obj, G_1, G_2);
}
void example_clientQ_L_7actionD___serialize__ (example_clientQ_L_7action self, $Serial$state state) {
    $step_serialize(self->L_6obj, state);
}
example_clientQ_L_7action example_clientQ_L_7actionD___deserialize__ (example_clientQ_L_7action self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct example_clientQ_L_7action));
            self->$class = &example_clientQ_L_7actionG_methods;
            return self;
        }
        self = $DNEW(example_clientQ_L_7action, state);
    }
    self->L_6obj = $step_deserialize(state);
    return self;
}
example_clientQ_L_7action example_clientQ_L_7actionG_new(example_clientQ_main G_1) {
    example_clientQ_L_7action $tmp = acton_malloc(sizeof(struct example_clientQ_L_7action));
    $tmp->$class = &example_clientQ_L_7actionG_methods;
    example_clientQ_L_7actionG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct example_clientQ_L_7actionG_class example_clientQ_L_7actionG_methods;
B_NoneType example_clientQ_L_9actionD___init__ (example_clientQ_L_9action L_self, example_clientQ_main L_8obj) {
    ((example_clientQ_L_9action)(L_self))->L_8obj = L_8obj;
    return B_None;
}
$R example_clientQ_L_9actionD___call__ (example_clientQ_L_9action L_self, $Cont L_cont, sshQ_Client G_1, B_str G_2, sshQ_HostKeyInfo G_3) {
    return $AWAIT(L_cont, ((B_Msg (*) ($WORD, sshQ_Client, B_str, sshQ_HostKeyInfo))((example_clientQ_L_9action)(L_self))->$class->__asyn__)(L_self, G_1, G_2, G_3));
}
$R example_clientQ_L_9actionD___exec__ (example_clientQ_L_9action L_self, $Cont L_cont, sshQ_Client G_1, B_str G_2, sshQ_HostKeyInfo G_3) {
    return $R_CONT(L_cont, ((B_Msg (*) ($WORD, sshQ_Client, B_str, sshQ_HostKeyInfo))((example_clientQ_L_9action)(L_self))->$class->__asyn__)(L_self, G_1, G_2, G_3));
}
B_Msg example_clientQ_L_9actionD___asyn__ (example_clientQ_L_9action L_self, sshQ_Client G_1, B_str G_2, sshQ_HostKeyInfo G_3) {
    example_clientQ_main L_8obj = ((example_clientQ_L_9action)(L_self))->L_8obj;
    return ((B_Msg (*) ($WORD, sshQ_Client, B_str, sshQ_HostKeyInfo))((example_clientQ_main)(L_8obj))->$class->on_hostkey)(L_8obj, G_1, G_2, G_3);
}
void example_clientQ_L_9actionD___serialize__ (example_clientQ_L_9action self, $Serial$state state) {
    $step_serialize(self->L_8obj, state);
}
example_clientQ_L_9action example_clientQ_L_9actionD___deserialize__ (example_clientQ_L_9action self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct example_clientQ_L_9action));
            self->$class = &example_clientQ_L_9actionG_methods;
            return self;
        }
        self = $DNEW(example_clientQ_L_9action, state);
    }
    self->L_8obj = $step_deserialize(state);
    return self;
}
example_clientQ_L_9action example_clientQ_L_9actionG_new(example_clientQ_main G_1) {
    example_clientQ_L_9action $tmp = acton_malloc(sizeof(struct example_clientQ_L_9action));
    $tmp->$class = &example_clientQ_L_9actionG_methods;
    example_clientQ_L_9actionG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct example_clientQ_L_9actionG_class example_clientQ_L_9actionG_methods;
$R example_clientQ_L_1C_1cont (example_clientQ_main self, $Cont C_cont, B_NoneType C_2res) {
    #line 42 "src/example_client.act"
    ((example_clientQ_main)(self))->client = B_None;
    return sshQ_ClientG_newact((($Cont)example_clientQ_L_3ContG_new(self, C_cont)), netQ_TCPConnectCapG_new(netQ_TCPCapG_new(netQ_NetCapG_new(((B_Env)(((example_clientQ_main)(self))->env))->cap))), ((example_clientQ_main)(self))->host, ((example_clientQ_main)(self))->user, (($action)example_clientQ_L_5actionG_new(self)), (($action)example_clientQ_L_7actionG_new(self)), (($action)example_clientQ_L_9actionG_new(self)), ((example_clientQ_main)(self))->password, ((example_clientQ_main)(self))->key_file, B_None, toB_u16(((uint16_t)((example_clientQ_main)(self))->port)), B_None, B_None, B_None, B_None, B_None, B_None, B_None);
}
B_NoneType example_clientQ_L_10ContD___init__ (example_clientQ_L_10Cont L_self, example_clientQ_main self, $Cont C_cont) {
    ((example_clientQ_L_10Cont)(L_self))->self = self;
    ((example_clientQ_L_10Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R example_clientQ_L_10ContD___call__ (example_clientQ_L_10Cont L_self, B_NoneType G_1) {
    example_clientQ_main self = ((example_clientQ_L_10Cont)(L_self))->self;
    $Cont C_cont = ((example_clientQ_L_10Cont)(L_self))->C_cont;
    return example_clientQ_L_1C_1cont(self, C_cont, G_1);
}
void example_clientQ_L_10ContD___serialize__ (example_clientQ_L_10Cont self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->C_cont, state);
}
example_clientQ_L_10Cont example_clientQ_L_10ContD___deserialize__ (example_clientQ_L_10Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct example_clientQ_L_10Cont));
            self->$class = &example_clientQ_L_10ContG_methods;
            return self;
        }
        self = $DNEW(example_clientQ_L_10Cont, state);
    }
    self->self = $step_deserialize(state);
    self->C_cont = $step_deserialize(state);
    return self;
}
example_clientQ_L_10Cont example_clientQ_L_10ContG_new(example_clientQ_main G_1, $Cont G_2) {
    example_clientQ_L_10Cont $tmp = acton_malloc(sizeof(struct example_clientQ_L_10Cont));
    $tmp->$class = &example_clientQ_L_10ContG_methods;
    example_clientQ_L_10ContG_methods.__init__($tmp, G_1, G_2);
    return $tmp;
}
struct example_clientQ_L_10ContG_class example_clientQ_L_10ContG_methods;
B_NoneType example_clientQ_L_12ContD___init__ (example_clientQ_L_12Cont L_self, example_clientQ_main self, $Cont C_cont) {
    ((example_clientQ_L_12Cont)(L_self))->self = self;
    ((example_clientQ_L_12Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R example_clientQ_L_12ContD___call__ (example_clientQ_L_12Cont L_self, B_NoneType G_1) {
    example_clientQ_main self = ((example_clientQ_L_12Cont)(L_self))->self;
    $Cont C_cont = ((example_clientQ_L_12Cont)(L_self))->C_cont;
    return example_clientQ_L_1C_1cont(self, C_cont, G_1);
}
void example_clientQ_L_12ContD___serialize__ (example_clientQ_L_12Cont self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->C_cont, state);
}
example_clientQ_L_12Cont example_clientQ_L_12ContD___deserialize__ (example_clientQ_L_12Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct example_clientQ_L_12Cont));
            self->$class = &example_clientQ_L_12ContG_methods;
            return self;
        }
        self = $DNEW(example_clientQ_L_12Cont, state);
    }
    self->self = $step_deserialize(state);
    self->C_cont = $step_deserialize(state);
    return self;
}
example_clientQ_L_12Cont example_clientQ_L_12ContG_new(example_clientQ_main G_1, $Cont G_2) {
    example_clientQ_L_12Cont $tmp = acton_malloc(sizeof(struct example_clientQ_L_12Cont));
    $tmp->$class = &example_clientQ_L_12ContG_methods;
    example_clientQ_L_12ContG_methods.__init__($tmp, G_1, G_2);
    return $tmp;
}
struct example_clientQ_L_12ContG_class example_clientQ_L_12ContG_methods;
$R example_clientQ_L_11C_5cont (example_clientQ_main self, $Cont C_cont, B_str C_6res) {
    #line 38 "src/example_client.act"
    B_str home = C_6res;
    #line 39 "src/example_client.act"
    if ($ISNOTNONE0(home)) {
        #line 40 "src/example_client.act"
        ((example_clientQ_main)(self))->key_file = ((B_str (*) ($WORD, B_str, B_str))((B_Plus)(example_clientQ_W_main_238))->$class->__add__)(example_clientQ_W_main_238, ((B_str)home), to$str("/.ssh/id_ed25519"));
    }
    return $R_CONT((($Cont)example_clientQ_L_12ContG_new(self, C_cont)), B_None);
}
B_NoneType example_clientQ_L_13ContD___init__ (example_clientQ_L_13Cont L_self, example_clientQ_main self, $Cont C_cont) {
    ((example_clientQ_L_13Cont)(L_self))->self = self;
    ((example_clientQ_L_13Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R example_clientQ_L_13ContD___call__ (example_clientQ_L_13Cont L_self, B_str G_1) {
    example_clientQ_main self = ((example_clientQ_L_13Cont)(L_self))->self;
    $Cont C_cont = ((example_clientQ_L_13Cont)(L_self))->C_cont;
    return example_clientQ_L_11C_5cont(self, C_cont, G_1);
}
void example_clientQ_L_13ContD___serialize__ (example_clientQ_L_13Cont self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->C_cont, state);
}
example_clientQ_L_13Cont example_clientQ_L_13ContD___deserialize__ (example_clientQ_L_13Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct example_clientQ_L_13Cont));
            self->$class = &example_clientQ_L_13ContG_methods;
            return self;
        }
        self = $DNEW(example_clientQ_L_13Cont, state);
    }
    self->self = $step_deserialize(state);
    self->C_cont = $step_deserialize(state);
    return self;
}
example_clientQ_L_13Cont example_clientQ_L_13ContG_new(example_clientQ_main G_1, $Cont G_2) {
    example_clientQ_L_13Cont $tmp = acton_malloc(sizeof(struct example_clientQ_L_13Cont));
    $tmp->$class = &example_clientQ_L_13ContG_methods;
    example_clientQ_L_13ContG_methods.__init__($tmp, G_1, G_2);
    return $tmp;
}
struct example_clientQ_L_13ContG_class example_clientQ_L_13ContG_methods;
$R example_clientQ_L_15C_9cont ($Cont C_cont, sshQ_RunCommand C_10res) {
    return $R_CONT(C_cont, B_None);
}
B_NoneType example_clientQ_L_16ContD___init__ (example_clientQ_L_16Cont L_self, $Cont C_cont) {
    ((example_clientQ_L_16Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R example_clientQ_L_16ContD___call__ (example_clientQ_L_16Cont L_self, sshQ_RunCommand G_1) {
    $Cont C_cont = ((example_clientQ_L_16Cont)(L_self))->C_cont;
    return example_clientQ_L_15C_9cont(C_cont, G_1);
}
void example_clientQ_L_16ContD___serialize__ (example_clientQ_L_16Cont self, $Serial$state state) {
    $step_serialize(self->C_cont, state);
}
example_clientQ_L_16Cont example_clientQ_L_16ContD___deserialize__ (example_clientQ_L_16Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct example_clientQ_L_16Cont));
            self->$class = &example_clientQ_L_16ContG_methods;
            return self;
        }
        self = $DNEW(example_clientQ_L_16Cont, state);
    }
    self->C_cont = $step_deserialize(state);
    return self;
}
example_clientQ_L_16Cont example_clientQ_L_16ContG_new($Cont G_1) {
    example_clientQ_L_16Cont $tmp = acton_malloc(sizeof(struct example_clientQ_L_16Cont));
    $tmp->$class = &example_clientQ_L_16ContG_methods;
    example_clientQ_L_16ContG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct example_clientQ_L_16ContG_class example_clientQ_L_16ContG_methods;
B_NoneType example_clientQ_L_18actionD___init__ (example_clientQ_L_18action L_self, example_clientQ_main L_17obj) {
    ((example_clientQ_L_18action)(L_self))->L_17obj = L_17obj;
    return B_None;
}
$R example_clientQ_L_18actionD___call__ (example_clientQ_L_18action L_self, $Cont L_cont, sshQ_Channel G_1, B_int G_2, B_str G_3, B_bytes G_4, B_bytes G_5, B_str G_6) {
    return $AWAIT(L_cont, ((B_Msg (*) ($WORD, sshQ_Channel, B_int, B_str, B_bytes, B_bytes, B_str))((example_clientQ_L_18action)(L_self))->$class->__asyn__)(L_self, G_1, G_2, G_3, G_4, G_5, G_6));
}
$R example_clientQ_L_18actionD___exec__ (example_clientQ_L_18action L_self, $Cont L_cont, sshQ_Channel G_1, B_int G_2, B_str G_3, B_bytes G_4, B_bytes G_5, B_str G_6) {
    return $R_CONT(L_cont, ((B_Msg (*) ($WORD, sshQ_Channel, B_int, B_str, B_bytes, B_bytes, B_str))((example_clientQ_L_18action)(L_self))->$class->__asyn__)(L_self, G_1, G_2, G_3, G_4, G_5, G_6));
}
B_Msg example_clientQ_L_18actionD___asyn__ (example_clientQ_L_18action L_self, sshQ_Channel G_1, B_int G_2, B_str G_3, B_bytes G_4, B_bytes G_5, B_str G_6) {
    example_clientQ_main L_17obj = ((example_clientQ_L_18action)(L_self))->L_17obj;
    return ((B_Msg (*) ($WORD, sshQ_Channel, int64_t, B_str, B_bytes, B_bytes, B_str))((example_clientQ_main)(L_17obj))->$class->on_exit)(L_17obj, G_1, ((B_int)G_2)->val, G_3, G_4, G_5, G_6);
}
void example_clientQ_L_18actionD___serialize__ (example_clientQ_L_18action self, $Serial$state state) {
    $step_serialize(self->L_17obj, state);
}
example_clientQ_L_18action example_clientQ_L_18actionD___deserialize__ (example_clientQ_L_18action self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct example_clientQ_L_18action));
            self->$class = &example_clientQ_L_18actionG_methods;
            return self;
        }
        self = $DNEW(example_clientQ_L_18action, state);
    }
    self->L_17obj = $step_deserialize(state);
    return self;
}
example_clientQ_L_18action example_clientQ_L_18actionG_new(example_clientQ_main G_1) {
    example_clientQ_L_18action $tmp = acton_malloc(sizeof(struct example_clientQ_L_18action));
    $tmp->$class = &example_clientQ_L_18actionG_methods;
    example_clientQ_L_18actionG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct example_clientQ_L_18actionG_class example_clientQ_L_18actionG_methods;
$R example_clientQ_L_14C_7cont ($Cont C_cont, sshQ_Client c, example_clientQ_main self, B_NoneType C_8res) {
    return sshQ_RunCommandG_newact((($Cont)example_clientQ_L_16ContG_new(C_cont)), c, ((example_clientQ_main)(self))->cmd, (($action)example_clientQ_L_18actionG_new(self)), toB_float(30.0));
}
B_NoneType example_clientQ_L_19ContD___init__ (example_clientQ_L_19Cont L_self, $Cont C_cont, sshQ_Client c, example_clientQ_main self) {
    ((example_clientQ_L_19Cont)(L_self))->C_cont = C_cont;
    ((example_clientQ_L_19Cont)(L_self))->c = c;
    ((example_clientQ_L_19Cont)(L_self))->self = self;
    return B_None;
}
$R example_clientQ_L_19ContD___call__ (example_clientQ_L_19Cont L_self, B_NoneType G_1) {
    $Cont C_cont = ((example_clientQ_L_19Cont)(L_self))->C_cont;
    sshQ_Client c = ((example_clientQ_L_19Cont)(L_self))->c;
    example_clientQ_main self = ((example_clientQ_L_19Cont)(L_self))->self;
    return example_clientQ_L_14C_7cont(C_cont, c, self, G_1);
}
void example_clientQ_L_19ContD___serialize__ (example_clientQ_L_19Cont self, $Serial$state state) {
    $step_serialize(self->C_cont, state);
    $step_serialize(self->c, state);
    $step_serialize(self->self, state);
}
example_clientQ_L_19Cont example_clientQ_L_19ContD___deserialize__ (example_clientQ_L_19Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct example_clientQ_L_19Cont));
            self->$class = &example_clientQ_L_19ContG_methods;
            return self;
        }
        self = $DNEW(example_clientQ_L_19Cont, state);
    }
    self->C_cont = $step_deserialize(state);
    self->c = $step_deserialize(state);
    self->self = $step_deserialize(state);
    return self;
}
example_clientQ_L_19Cont example_clientQ_L_19ContG_new($Cont G_1, sshQ_Client G_2, example_clientQ_main G_3) {
    example_clientQ_L_19Cont $tmp = acton_malloc(sizeof(struct example_clientQ_L_19Cont));
    $tmp->$class = &example_clientQ_L_19ContG_methods;
    example_clientQ_L_19ContG_methods.__init__($tmp, G_1, G_2, G_3);
    return $tmp;
}
struct example_clientQ_L_19ContG_class example_clientQ_L_19ContG_methods;
$R example_clientQ_L_20C_11cont (B_Collection W_main_427, B_bytes out, B_bytes err_out, example_clientQ_main self, int64_t code, $Cont C_cont, B_NoneType C_12res) {
    #line 67 "src/example_client.act"
    if (((int64_t (*) (B_Collection, B_bytes))B_len)(W_main_427, out) > 0LL) {
        #line 68 "src/example_client.act"
        ((B_NoneType (*) (B_tuple, B_str, B_str, B_bool, B_bool))B_print)($NEWTUPLE(1, ((B_str (*) ($WORD))((B_bytes)(out))->$class->decode)(out)), B_None, to$str(""), B_None, B_None);
    }
    #line 69 "src/example_client.act"
    if (((int64_t (*) (B_Collection, B_bytes))B_len)(W_main_427, err_out) > 0LL) {
        #line 70 "src/example_client.act"
        ((B_NoneType (*) (B_tuple, B_str, B_str, B_bool, B_bool))B_print)($NEWTUPLE(1, ((B_str (*) ($WORD))((B_bytes)(err_out))->$class->decode)(err_out)), B_None, to$str(""), B_None, B_None);
    }
    #line 71 "src/example_client.act"
    if ($ISNOTNONE0(((example_clientQ_main)(self))->client)) {
        #line 72 "src/example_client.act"
        ({ sshQ_Client $tmp = ((sshQ_Client)((example_clientQ_main)(self))->client);
           ((B_Msg (*) ($WORD))((sshQ_Client)($tmp))->$class->close)($tmp); });
    }
    #line 73 "src/example_client.act"
    ((B_Msg (*) ($WORD, int64_t))((B_Env)(((example_clientQ_main)(self))->env))->$class->exit)(((example_clientQ_main)(self))->env, code);
    return $R_CONT(C_cont, B_None);
}
B_NoneType example_clientQ_L_21ContD___init__ (example_clientQ_L_21Cont L_self, B_Collection W_main_427, B_bytes out, B_bytes err_out, example_clientQ_main self, int64_t code, $Cont C_cont) {
    ((example_clientQ_L_21Cont)(L_self))->W_main_427 = W_main_427;
    ((example_clientQ_L_21Cont)(L_self))->out = out;
    ((example_clientQ_L_21Cont)(L_self))->err_out = err_out;
    ((example_clientQ_L_21Cont)(L_self))->self = self;
    ((example_clientQ_L_21Cont)(L_self))->code = code;
    ((example_clientQ_L_21Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R example_clientQ_L_21ContD___call__ (example_clientQ_L_21Cont L_self, B_NoneType G_1) {
    B_Collection W_main_427 = ((example_clientQ_L_21Cont)(L_self))->W_main_427;
    B_bytes out = ((example_clientQ_L_21Cont)(L_self))->out;
    B_bytes err_out = ((example_clientQ_L_21Cont)(L_self))->err_out;
    example_clientQ_main self = ((example_clientQ_L_21Cont)(L_self))->self;
    int64_t code = ((int64_t)((example_clientQ_L_21Cont)(L_self))->code);
    $Cont C_cont = ((example_clientQ_L_21Cont)(L_self))->C_cont;
    return example_clientQ_L_20C_11cont(W_main_427, out, err_out, self, code, C_cont, G_1);
}
void example_clientQ_L_21ContD___serialize__ (example_clientQ_L_21Cont self, $Serial$state state) {
    $step_serialize(self->W_main_427, state);
    $step_serialize(self->out, state);
    $step_serialize(self->err_out, state);
    $step_serialize(self->self, state);
    $val_serialize(I64_ID, &self->code, state);
    $step_serialize(self->C_cont, state);
}
example_clientQ_L_21Cont example_clientQ_L_21ContD___deserialize__ (example_clientQ_L_21Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct example_clientQ_L_21Cont));
            self->$class = &example_clientQ_L_21ContG_methods;
            return self;
        }
        self = $DNEW(example_clientQ_L_21Cont, state);
    }
    self->W_main_427 = $step_deserialize(state);
    self->out = $step_deserialize(state);
    self->err_out = $step_deserialize(state);
    self->self = $step_deserialize(state);
    $tmp = $val_deserialize(state);
    memcpy(&self->code, &$tmp, sizeof(self->code));
    self->C_cont = $step_deserialize(state);
    return self;
}
example_clientQ_L_21Cont example_clientQ_L_21ContG_new(B_Collection G_1, B_bytes G_2, B_bytes G_3, example_clientQ_main G_4, int64_t G_5, $Cont G_6) {
    example_clientQ_L_21Cont $tmp = acton_malloc(sizeof(struct example_clientQ_L_21Cont));
    $tmp->$class = &example_clientQ_L_21ContG_methods;
    example_clientQ_L_21ContG_methods.__init__($tmp, G_1, G_2, G_3, G_4, G_5, G_6);
    return $tmp;
}
struct example_clientQ_L_21ContG_class example_clientQ_L_21ContG_methods;
B_NoneType example_clientQ_L_22procD___init__ (example_clientQ_L_22proc L_self, example_clientQ_main self, sshQ_Client c, B_str state, sshQ_HostKeyInfo info) {
    ((example_clientQ_L_22proc)(L_self))->self = self;
    ((example_clientQ_L_22proc)(L_self))->c = c;
    ((example_clientQ_L_22proc)(L_self))->state = state;
    ((example_clientQ_L_22proc)(L_self))->info = info;
    return B_None;
}
$R example_clientQ_L_22procD___call__ (example_clientQ_L_22proc L_self, $Cont C_cont) {
    example_clientQ_main self = ((example_clientQ_L_22proc)(L_self))->self;
    sshQ_Client c = ((example_clientQ_L_22proc)(L_self))->c;
    B_str state = ((example_clientQ_L_22proc)(L_self))->state;
    sshQ_HostKeyInfo info = ((example_clientQ_L_22proc)(L_self))->info;
    return (($R (*) ($WORD, $Cont, sshQ_Client, B_str, sshQ_HostKeyInfo))((example_clientQ_main)(self))->$class->on_hostkeyG_local)(self, C_cont, c, state, info);
}
$R example_clientQ_L_22procD___exec__ (example_clientQ_L_22proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((example_clientQ_L_22proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void example_clientQ_L_22procD___serialize__ (example_clientQ_L_22proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->c, state);
    $step_serialize(self->state, state);
    $step_serialize(self->info, state);
}
example_clientQ_L_22proc example_clientQ_L_22procD___deserialize__ (example_clientQ_L_22proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct example_clientQ_L_22proc));
            self->$class = &example_clientQ_L_22procG_methods;
            return self;
        }
        self = $DNEW(example_clientQ_L_22proc, state);
    }
    self->self = $step_deserialize(state);
    self->c = $step_deserialize(state);
    self->state = $step_deserialize(state);
    self->info = $step_deserialize(state);
    return self;
}
example_clientQ_L_22proc example_clientQ_L_22procG_new(example_clientQ_main G_1, sshQ_Client G_2, B_str G_3, sshQ_HostKeyInfo G_4) {
    example_clientQ_L_22proc $tmp = acton_malloc(sizeof(struct example_clientQ_L_22proc));
    $tmp->$class = &example_clientQ_L_22procG_methods;
    example_clientQ_L_22procG_methods.__init__($tmp, G_1, G_2, G_3, G_4);
    return $tmp;
}
struct example_clientQ_L_22procG_class example_clientQ_L_22procG_methods;
B_NoneType example_clientQ_L_23procD___init__ (example_clientQ_L_23proc L_self, example_clientQ_main self, sshQ_Client c, B_str err) {
    ((example_clientQ_L_23proc)(L_self))->self = self;
    ((example_clientQ_L_23proc)(L_self))->c = c;
    ((example_clientQ_L_23proc)(L_self))->err = err;
    return B_None;
}
$R example_clientQ_L_23procD___call__ (example_clientQ_L_23proc L_self, $Cont C_cont) {
    example_clientQ_main self = ((example_clientQ_L_23proc)(L_self))->self;
    sshQ_Client c = ((example_clientQ_L_23proc)(L_self))->c;
    B_str err = ((example_clientQ_L_23proc)(L_self))->err;
    return (($R (*) ($WORD, $Cont, sshQ_Client, B_str))((example_clientQ_main)(self))->$class->on_connectG_local)(self, C_cont, c, err);
}
$R example_clientQ_L_23procD___exec__ (example_clientQ_L_23proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((example_clientQ_L_23proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void example_clientQ_L_23procD___serialize__ (example_clientQ_L_23proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->c, state);
    $step_serialize(self->err, state);
}
example_clientQ_L_23proc example_clientQ_L_23procD___deserialize__ (example_clientQ_L_23proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct example_clientQ_L_23proc));
            self->$class = &example_clientQ_L_23procG_methods;
            return self;
        }
        self = $DNEW(example_clientQ_L_23proc, state);
    }
    self->self = $step_deserialize(state);
    self->c = $step_deserialize(state);
    self->err = $step_deserialize(state);
    return self;
}
example_clientQ_L_23proc example_clientQ_L_23procG_new(example_clientQ_main G_1, sshQ_Client G_2, B_str G_3) {
    example_clientQ_L_23proc $tmp = acton_malloc(sizeof(struct example_clientQ_L_23proc));
    $tmp->$class = &example_clientQ_L_23procG_methods;
    example_clientQ_L_23procG_methods.__init__($tmp, G_1, G_2, G_3);
    return $tmp;
}
struct example_clientQ_L_23procG_class example_clientQ_L_23procG_methods;
B_NoneType example_clientQ_L_24procD___init__ (example_clientQ_L_24proc L_self, example_clientQ_main self, sshQ_Client c, B_str reason) {
    ((example_clientQ_L_24proc)(L_self))->self = self;
    ((example_clientQ_L_24proc)(L_self))->c = c;
    ((example_clientQ_L_24proc)(L_self))->reason = reason;
    return B_None;
}
$R example_clientQ_L_24procD___call__ (example_clientQ_L_24proc L_self, $Cont C_cont) {
    example_clientQ_main self = ((example_clientQ_L_24proc)(L_self))->self;
    sshQ_Client c = ((example_clientQ_L_24proc)(L_self))->c;
    B_str reason = ((example_clientQ_L_24proc)(L_self))->reason;
    return (($R (*) ($WORD, $Cont, sshQ_Client, B_str))((example_clientQ_main)(self))->$class->on_closeG_local)(self, C_cont, c, reason);
}
$R example_clientQ_L_24procD___exec__ (example_clientQ_L_24proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((example_clientQ_L_24proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void example_clientQ_L_24procD___serialize__ (example_clientQ_L_24proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->c, state);
    $step_serialize(self->reason, state);
}
example_clientQ_L_24proc example_clientQ_L_24procD___deserialize__ (example_clientQ_L_24proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct example_clientQ_L_24proc));
            self->$class = &example_clientQ_L_24procG_methods;
            return self;
        }
        self = $DNEW(example_clientQ_L_24proc, state);
    }
    self->self = $step_deserialize(state);
    self->c = $step_deserialize(state);
    self->reason = $step_deserialize(state);
    return self;
}
example_clientQ_L_24proc example_clientQ_L_24procG_new(example_clientQ_main G_1, sshQ_Client G_2, B_str G_3) {
    example_clientQ_L_24proc $tmp = acton_malloc(sizeof(struct example_clientQ_L_24proc));
    $tmp->$class = &example_clientQ_L_24procG_methods;
    example_clientQ_L_24procG_methods.__init__($tmp, G_1, G_2, G_3);
    return $tmp;
}
struct example_clientQ_L_24procG_class example_clientQ_L_24procG_methods;
B_NoneType example_clientQ_L_25procD___init__ (example_clientQ_L_25proc L_self, example_clientQ_main self, sshQ_Channel ch, int64_t code, B_str sig, B_bytes out, B_bytes err_out, B_str error) {
    ((example_clientQ_L_25proc)(L_self))->self = self;
    ((example_clientQ_L_25proc)(L_self))->ch = ch;
    ((example_clientQ_L_25proc)(L_self))->code = code;
    ((example_clientQ_L_25proc)(L_self))->sig = sig;
    ((example_clientQ_L_25proc)(L_self))->out = out;
    ((example_clientQ_L_25proc)(L_self))->err_out = err_out;
    ((example_clientQ_L_25proc)(L_self))->error = error;
    return B_None;
}
$R example_clientQ_L_25procD___call__ (example_clientQ_L_25proc L_self, $Cont C_cont) {
    example_clientQ_main self = ((example_clientQ_L_25proc)(L_self))->self;
    sshQ_Channel ch = ((example_clientQ_L_25proc)(L_self))->ch;
    int64_t code = ((int64_t)((example_clientQ_L_25proc)(L_self))->code);
    B_str sig = ((example_clientQ_L_25proc)(L_self))->sig;
    B_bytes out = ((example_clientQ_L_25proc)(L_self))->out;
    B_bytes err_out = ((example_clientQ_L_25proc)(L_self))->err_out;
    B_str error = ((example_clientQ_L_25proc)(L_self))->error;
    return (($R (*) ($WORD, $Cont, sshQ_Channel, int64_t, B_str, B_bytes, B_bytes, B_str))((example_clientQ_main)(self))->$class->on_exitG_local)(self, C_cont, ch, code, sig, out, err_out, error);
}
$R example_clientQ_L_25procD___exec__ (example_clientQ_L_25proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((example_clientQ_L_25proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void example_clientQ_L_25procD___serialize__ (example_clientQ_L_25proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->ch, state);
    $val_serialize(I64_ID, &self->code, state);
    $step_serialize(self->sig, state);
    $step_serialize(self->out, state);
    $step_serialize(self->err_out, state);
    $step_serialize(self->error, state);
}
example_clientQ_L_25proc example_clientQ_L_25procD___deserialize__ (example_clientQ_L_25proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct example_clientQ_L_25proc));
            self->$class = &example_clientQ_L_25procG_methods;
            return self;
        }
        self = $DNEW(example_clientQ_L_25proc, state);
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
example_clientQ_L_25proc example_clientQ_L_25procG_new(example_clientQ_main G_1, sshQ_Channel G_2, int64_t G_3, B_str G_4, B_bytes G_5, B_bytes G_6, B_str G_7) {
    example_clientQ_L_25proc $tmp = acton_malloc(sizeof(struct example_clientQ_L_25proc));
    $tmp->$class = &example_clientQ_L_25procG_methods;
    example_clientQ_L_25procG_methods.__init__($tmp, G_1, G_2, G_3, G_4, G_5, G_6, G_7);
    return $tmp;
}
struct example_clientQ_L_25procG_class example_clientQ_L_25procG_methods;
$R example_clientQ_L_26C_13cont ($Cont C_cont, example_clientQ_main G_act, B_NoneType C_14res) {
    return $R_CONT(C_cont, G_act);
}
B_NoneType example_clientQ_L_27ContD___init__ (example_clientQ_L_27Cont L_self, $Cont C_cont, example_clientQ_main G_act) {
    ((example_clientQ_L_27Cont)(L_self))->C_cont = C_cont;
    ((example_clientQ_L_27Cont)(L_self))->G_act = G_act;
    return B_None;
}
$R example_clientQ_L_27ContD___call__ (example_clientQ_L_27Cont L_self, B_NoneType G_1) {
    $Cont C_cont = ((example_clientQ_L_27Cont)(L_self))->C_cont;
    example_clientQ_main G_act = ((example_clientQ_L_27Cont)(L_self))->G_act;
    return example_clientQ_L_26C_13cont(C_cont, G_act, G_1);
}
void example_clientQ_L_27ContD___serialize__ (example_clientQ_L_27Cont self, $Serial$state state) {
    $step_serialize(self->C_cont, state);
    $step_serialize(self->G_act, state);
}
example_clientQ_L_27Cont example_clientQ_L_27ContD___deserialize__ (example_clientQ_L_27Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct example_clientQ_L_27Cont));
            self->$class = &example_clientQ_L_27ContG_methods;
            return self;
        }
        self = $DNEW(example_clientQ_L_27Cont, state);
    }
    self->C_cont = $step_deserialize(state);
    self->G_act = $step_deserialize(state);
    return self;
}
example_clientQ_L_27Cont example_clientQ_L_27ContG_new($Cont G_1, example_clientQ_main G_2) {
    example_clientQ_L_27Cont $tmp = acton_malloc(sizeof(struct example_clientQ_L_27Cont));
    $tmp->$class = &example_clientQ_L_27ContG_methods;
    example_clientQ_L_27ContG_methods.__init__($tmp, G_1, G_2);
    return $tmp;
}
struct example_clientQ_L_27ContG_class example_clientQ_L_27ContG_methods;
B_NoneType example_clientQ_L_28procD___init__ (example_clientQ_L_28proc L_self, example_clientQ_main G_act, B_Env env) {
    ((example_clientQ_L_28proc)(L_self))->G_act = G_act;
    ((example_clientQ_L_28proc)(L_self))->env = env;
    return B_None;
}
$R example_clientQ_L_28procD___call__ (example_clientQ_L_28proc L_self, $Cont C_cont) {
    example_clientQ_main G_act = ((example_clientQ_L_28proc)(L_self))->G_act;
    B_Env env = ((example_clientQ_L_28proc)(L_self))->env;
    return (($R (*) ($WORD, $Cont, B_Env))((example_clientQ_main)(G_act))->$class->__init__)(G_act, C_cont, env);
}
$R example_clientQ_L_28procD___exec__ (example_clientQ_L_28proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((example_clientQ_L_28proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void example_clientQ_L_28procD___serialize__ (example_clientQ_L_28proc self, $Serial$state state) {
    $step_serialize(self->G_act, state);
    $step_serialize(self->env, state);
}
example_clientQ_L_28proc example_clientQ_L_28procD___deserialize__ (example_clientQ_L_28proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct example_clientQ_L_28proc));
            self->$class = &example_clientQ_L_28procG_methods;
            return self;
        }
        self = $DNEW(example_clientQ_L_28proc, state);
    }
    self->G_act = $step_deserialize(state);
    self->env = $step_deserialize(state);
    return self;
}
example_clientQ_L_28proc example_clientQ_L_28procG_new(example_clientQ_main G_1, B_Env G_2) {
    example_clientQ_L_28proc $tmp = acton_malloc(sizeof(struct example_clientQ_L_28proc));
    $tmp->$class = &example_clientQ_L_28procG_methods;
    example_clientQ_L_28procG_methods.__init__($tmp, G_1, G_2);
    return $tmp;
}
struct example_clientQ_L_28procG_class example_clientQ_L_28procG_methods;
$R example_clientQ_mainD___init__ (example_clientQ_main self, $Cont C_cont, B_Env env) {
    ((example_clientQ_main)(self))->env = env;
    #line 22 "src/example_client.act"
    if (((int64_t (*) (B_Collection, B_list))B_len)(example_clientQ_W_main_15, ((B_Env)(((example_clientQ_main)(self))->env))->argv) < 4LL) {
        #line 23 "src/example_client.act"
        ((B_NoneType (*) (B_tuple, B_str, B_str, B_bool, B_bool))B_print)($NEWTUPLE(1, to$str("usage: example_client HOST USER CMD [PORT] [PASSWORD]")), B_None, B_None, B_None, B_None);
        #line 24 "src/example_client.act"
        ((B_Msg (*) ($WORD, int64_t))((B_Env)(((example_clientQ_main)(self))->env))->$class->exit)(((example_clientQ_main)(self))->env, 2LL);
    }
    #line 26 "src/example_client.act"
    ((example_clientQ_main)(self))->host = $listD_U__getitem__(((B_Env)(((example_clientQ_main)(self))->env))->argv, 1LL);
    #line 27 "src/example_client.act"
    ((example_clientQ_main)(self))->user = $listD_U__getitem__(((B_Env)(((example_clientQ_main)(self))->env))->argv, 2LL);
    #line 28 "src/example_client.act"
    ((example_clientQ_main)(self))->cmd = $listD_U__getitem__(((B_Env)(((example_clientQ_main)(self))->env))->argv, 3LL);
    #line 29 "src/example_client.act"
    ((example_clientQ_main)(self))->port = B_u16G_new(((B_atom)toB_int(22LL)), B_None);
    #line 30 "src/example_client.act"
    if (((int64_t (*) (B_Collection, B_list))B_len)(example_clientQ_W_main_15, ((B_Env)(((example_clientQ_main)(self))->env))->argv) > 4LL) {
        #line 31 "src/example_client.act"
        ((example_clientQ_main)(self))->port = B_u16G_new(((B_atom)toB_int(B_intG_new(((B_atom)$listD_U__getitem__(((B_Env)(((example_clientQ_main)(self))->env))->argv, 4LL)), B_None))), B_None);
    }
    #line 33 "src/example_client.act"
    ((example_clientQ_main)(self))->password = B_None;
    #line 34 "src/example_client.act"
    ((example_clientQ_main)(self))->key_file = B_None;
    if (((int64_t (*) (B_Collection, B_list))B_len)(example_clientQ_W_main_15, ((B_Env)(((example_clientQ_main)(self))->env))->argv) > 5LL) {
        #line 36 "src/example_client.act"
        ((example_clientQ_main)(self))->password = $listD_U__getitem__(((B_Env)(((example_clientQ_main)(self))->env))->argv, 5LL);
        return $R_CONT((($Cont)example_clientQ_L_10ContG_new(self, C_cont)), B_None);
    }
    else {
        return $AWAIT((($Cont)example_clientQ_L_13ContG_new(self, C_cont)), ((B_Msg (*) ($WORD, B_str))((B_Env)(((example_clientQ_main)(self))->env))->$class->getenv)(((example_clientQ_main)(self))->env, to$str("HOME")));
    }
}
#line 44 "src/example_client.act"
$R example_clientQ_mainD_on_hostkeyG_local (example_clientQ_main self, $Cont C_cont, sshQ_Client c, B_str state, sshQ_HostKeyInfo info) {
    #line 47 "src/example_client.act"
    ((B_NoneType (*) (B_tuple, B_str, B_str, B_bool, B_bool))B_print)($NEWTUPLE(3, ((B_str (*) ($WORD, B_str, B_str))((B_Plus)(example_clientQ_W_main_238))->$class->__add__)(example_clientQ_W_main_238, ((B_str (*) ($WORD, B_str, B_str))((B_Plus)(example_clientQ_W_main_238))->$class->__add__)(example_clientQ_W_main_238, to$str("host key ["), state), to$str("]")), ((sshQ_HostKeyInfo)(info))->key_type, ((sshQ_HostKeyInfo)(info))->fingerprint), B_None, B_None, B_None, B_None);
    #line 48 "src/example_client.act"
    ((B_Msg (*) ($WORD))((sshQ_Client)(c))->$class->accept_hostkey)(c);
    return $R_CONT(C_cont, B_None);
}
#line 50 "src/example_client.act"
$R example_clientQ_mainD_on_connectG_local (example_clientQ_main self, $Cont C_cont, sshQ_Client c, B_str err) {
    if ($ISNOTNONE0(err)) {
        #line 52 "src/example_client.act"
        ((B_NoneType (*) (B_tuple, B_str, B_str, B_bool, B_bool))B_print)($NEWTUPLE(2, to$str("connect error:"), ((B_str)err)), B_None, B_None, B_None, B_None);
        #line 53 "src/example_client.act"
        ((B_Msg (*) ($WORD, int64_t))((B_Env)(((example_clientQ_main)(self))->env))->$class->exit)(((example_clientQ_main)(self))->env, 1LL);
        return $R_CONT(C_cont, B_None);
    }
    else {
        return $R_CONT((($Cont)example_clientQ_L_19ContG_new(C_cont, c, self)), B_None);
    }
}
#line 57 "src/example_client.act"
$R example_clientQ_mainD_on_closeG_local (example_clientQ_main self, $Cont C_cont, sshQ_Client c, B_str reason) {
    #line 58 "src/example_client.act"
    return $R_CONT(C_cont, B_None);
}
#line 60 "src/example_client.act"
$R example_clientQ_mainD_on_exitG_local (example_clientQ_main self, $Cont C_cont, sshQ_Channel ch, int64_t code, B_str sig, B_bytes out, B_bytes err_out, B_str error) {
    B_Collection W_main_427 = (B_Collection)B_ContainerD_bytesG_witness;
    if ($ISNOTNONE0(error)) {
        #line 62 "src/example_client.act"
        ((B_NoneType (*) (B_tuple, B_str, B_str, B_bool, B_bool))B_print)($NEWTUPLE(2, to$str("run error:"), ((B_str)error)), B_None, B_None, B_None, B_None);
        #line 63 "src/example_client.act"
        if ($ISNOTNONE0(((example_clientQ_main)(self))->client)) {
            #line 64 "src/example_client.act"
            ({ sshQ_Client $tmp = ((sshQ_Client)((example_clientQ_main)(self))->client);
               ((B_Msg (*) ($WORD))((sshQ_Client)($tmp))->$class->close)($tmp); });
        }
        #line 65 "src/example_client.act"
        ((B_Msg (*) ($WORD, int64_t))((B_Env)(((example_clientQ_main)(self))->env))->$class->exit)(((example_clientQ_main)(self))->env, 1LL);
        return $R_CONT(C_cont, B_None);
    }
    else {
        return $R_CONT((($Cont)example_clientQ_L_21ContG_new(W_main_427, out, err_out, self, code, C_cont)), B_None);
    }
}
B_Msg example_clientQ_mainD_on_hostkey (example_clientQ_main self, sshQ_Client c, B_str state, sshQ_HostKeyInfo info) {
    return $ASYNC((($Actor)self), (($Cont)example_clientQ_L_22procG_new(self, c, state, info)));
}
B_Msg example_clientQ_mainD_on_connect (example_clientQ_main self, sshQ_Client c, B_str err) {
    return $ASYNC((($Actor)self), (($Cont)example_clientQ_L_23procG_new(self, c, err)));
}
B_Msg example_clientQ_mainD_on_close (example_clientQ_main self, sshQ_Client c, B_str reason) {
    return $ASYNC((($Actor)self), (($Cont)example_clientQ_L_24procG_new(self, c, reason)));
}
B_Msg example_clientQ_mainD_on_exit (example_clientQ_main self, sshQ_Channel ch, int64_t code, B_str sig, B_bytes out, B_bytes err_out, B_str error) {
    return $ASYNC((($Actor)self), (($Cont)example_clientQ_L_25procG_new(self, ch, code, sig, out, err_out, error)));
}
void example_clientQ_mainD___serialize__ (example_clientQ_main self, $Serial$state state) {
    $ActorG_methods.__serialize__(($Actor)self, state);
    $step_serialize(self->env, state);
    $step_serialize(self->host, state);
    $step_serialize(self->user, state);
    $step_serialize(self->cmd, state);
    $val_serialize(U16_ID, &self->port, state);
    $step_serialize(self->password, state);
    $step_serialize(self->key_file, state);
    $step_serialize(self->client, state);
}
example_clientQ_main example_clientQ_mainD___deserialize__ (example_clientQ_main self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct example_clientQ_main));
            self->$class = &example_clientQ_mainG_methods;
            return self;
        }
        self = $DNEW(example_clientQ_main, state);
    }
    $ActorG_methods.__deserialize__(($Actor)self, state);
    self->env = $step_deserialize(state);
    self->host = $step_deserialize(state);
    self->user = $step_deserialize(state);
    self->cmd = $step_deserialize(state);
    $tmp = $val_deserialize(state);
    memcpy(&self->port, &$tmp, sizeof(self->port));
    self->password = $step_deserialize(state);
    self->key_file = $step_deserialize(state);
    self->client = $step_deserialize(state);
    return self;
}
void example_clientQ_mainD_GCfinalizer (void *obj, void *cdata) {
    example_clientQ_main self = (example_clientQ_main)obj;
    self->$class->__cleanup__(self);
}
$R example_clientQ_mainG_new($Cont G_1, B_Env G_2) {
    example_clientQ_main $tmp = acton_malloc(sizeof(struct example_clientQ_main));
    $tmp->$class = &example_clientQ_mainG_methods;
    return example_clientQ_mainG_methods.__init__($tmp, $CONSTCONT($tmp, G_1), G_2);
}
struct example_clientQ_mainG_class example_clientQ_mainG_methods;
$R example_clientQ_mainG_newact ($Cont C_cont, B_Env env) {
    example_clientQ_main G_act = $NEWACTOR(example_clientQ_main);
    if ((void*)G_act->$class->__cleanup__ != (void*)$ActorD___cleanup__) $InstallFinalizer(G_act, example_clientQ_mainD_GCfinalizer);
    return $AWAIT((($Cont)example_clientQ_L_27ContG_new(C_cont, G_act)), $ASYNC((($Actor)G_act), (($Cont)example_clientQ_L_28procG_new(G_act, env))));
}
int example_clientQ_done$ = 0;
void example_clientQ___init__ () {
    if (example_clientQ_done$) return;
    example_clientQ_done$ = 1;
    netQ___init__();
    sshQ___init__();
    {
        example_clientQ_L_3ContG_methods.$GCINFO = "example_clientQ_L_3Cont";
        example_clientQ_L_3ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        example_clientQ_L_3ContG_methods.__bool__ = (B_bool (*) (example_clientQ_L_3Cont))B_valueG_methods.__bool__;
        example_clientQ_L_3ContG_methods.__str__ = (B_str (*) (example_clientQ_L_3Cont))B_valueG_methods.__str__;
        example_clientQ_L_3ContG_methods.__repr__ = (B_str (*) (example_clientQ_L_3Cont))B_valueG_methods.__repr__;
        example_clientQ_L_3ContG_methods.__init__ = (B_NoneType (*) (example_clientQ_L_3Cont, example_clientQ_main, $Cont))example_clientQ_L_3ContD___init__;
        example_clientQ_L_3ContG_methods.__call__ = ($R (*) (example_clientQ_L_3Cont, sshQ_Client))example_clientQ_L_3ContD___call__;
        example_clientQ_L_3ContG_methods.__serialize__ = example_clientQ_L_3ContD___serialize__;
        example_clientQ_L_3ContG_methods.__deserialize__ = example_clientQ_L_3ContD___deserialize__;
        $register(&example_clientQ_L_3ContG_methods);
    }
    {
        example_clientQ_L_5actionG_methods.$GCINFO = "example_clientQ_L_5action";
        example_clientQ_L_5actionG_methods.$superclass = ($SuperG_class)&$actionG_methods;
        example_clientQ_L_5actionG_methods.__bool__ = (B_bool (*) (example_clientQ_L_5action))B_valueG_methods.__bool__;
        example_clientQ_L_5actionG_methods.__str__ = (B_str (*) (example_clientQ_L_5action))B_valueG_methods.__str__;
        example_clientQ_L_5actionG_methods.__repr__ = (B_str (*) (example_clientQ_L_5action))B_valueG_methods.__repr__;
        example_clientQ_L_5actionG_methods.__init__ = (B_NoneType (*) (example_clientQ_L_5action, example_clientQ_main))example_clientQ_L_5actionD___init__;
        example_clientQ_L_5actionG_methods.__call__ = ($R (*) (example_clientQ_L_5action, $Cont, sshQ_Client, B_str))example_clientQ_L_5actionD___call__;
        example_clientQ_L_5actionG_methods.__exec__ = ($R (*) (example_clientQ_L_5action, $Cont, sshQ_Client, B_str))example_clientQ_L_5actionD___exec__;
        example_clientQ_L_5actionG_methods.__asyn__ = (B_Msg (*) (example_clientQ_L_5action, sshQ_Client, B_str))example_clientQ_L_5actionD___asyn__;
        example_clientQ_L_5actionG_methods.__serialize__ = example_clientQ_L_5actionD___serialize__;
        example_clientQ_L_5actionG_methods.__deserialize__ = example_clientQ_L_5actionD___deserialize__;
        $register(&example_clientQ_L_5actionG_methods);
    }
    {
        example_clientQ_L_7actionG_methods.$GCINFO = "example_clientQ_L_7action";
        example_clientQ_L_7actionG_methods.$superclass = ($SuperG_class)&$actionG_methods;
        example_clientQ_L_7actionG_methods.__bool__ = (B_bool (*) (example_clientQ_L_7action))B_valueG_methods.__bool__;
        example_clientQ_L_7actionG_methods.__str__ = (B_str (*) (example_clientQ_L_7action))B_valueG_methods.__str__;
        example_clientQ_L_7actionG_methods.__repr__ = (B_str (*) (example_clientQ_L_7action))B_valueG_methods.__repr__;
        example_clientQ_L_7actionG_methods.__init__ = (B_NoneType (*) (example_clientQ_L_7action, example_clientQ_main))example_clientQ_L_7actionD___init__;
        example_clientQ_L_7actionG_methods.__call__ = ($R (*) (example_clientQ_L_7action, $Cont, sshQ_Client, B_str))example_clientQ_L_7actionD___call__;
        example_clientQ_L_7actionG_methods.__exec__ = ($R (*) (example_clientQ_L_7action, $Cont, sshQ_Client, B_str))example_clientQ_L_7actionD___exec__;
        example_clientQ_L_7actionG_methods.__asyn__ = (B_Msg (*) (example_clientQ_L_7action, sshQ_Client, B_str))example_clientQ_L_7actionD___asyn__;
        example_clientQ_L_7actionG_methods.__serialize__ = example_clientQ_L_7actionD___serialize__;
        example_clientQ_L_7actionG_methods.__deserialize__ = example_clientQ_L_7actionD___deserialize__;
        $register(&example_clientQ_L_7actionG_methods);
    }
    {
        example_clientQ_L_9actionG_methods.$GCINFO = "example_clientQ_L_9action";
        example_clientQ_L_9actionG_methods.$superclass = ($SuperG_class)&$actionG_methods;
        example_clientQ_L_9actionG_methods.__bool__ = (B_bool (*) (example_clientQ_L_9action))B_valueG_methods.__bool__;
        example_clientQ_L_9actionG_methods.__str__ = (B_str (*) (example_clientQ_L_9action))B_valueG_methods.__str__;
        example_clientQ_L_9actionG_methods.__repr__ = (B_str (*) (example_clientQ_L_9action))B_valueG_methods.__repr__;
        example_clientQ_L_9actionG_methods.__init__ = (B_NoneType (*) (example_clientQ_L_9action, example_clientQ_main))example_clientQ_L_9actionD___init__;
        example_clientQ_L_9actionG_methods.__call__ = ($R (*) (example_clientQ_L_9action, $Cont, sshQ_Client, B_str, sshQ_HostKeyInfo))example_clientQ_L_9actionD___call__;
        example_clientQ_L_9actionG_methods.__exec__ = ($R (*) (example_clientQ_L_9action, $Cont, sshQ_Client, B_str, sshQ_HostKeyInfo))example_clientQ_L_9actionD___exec__;
        example_clientQ_L_9actionG_methods.__asyn__ = (B_Msg (*) (example_clientQ_L_9action, sshQ_Client, B_str, sshQ_HostKeyInfo))example_clientQ_L_9actionD___asyn__;
        example_clientQ_L_9actionG_methods.__serialize__ = example_clientQ_L_9actionD___serialize__;
        example_clientQ_L_9actionG_methods.__deserialize__ = example_clientQ_L_9actionD___deserialize__;
        $register(&example_clientQ_L_9actionG_methods);
    }
    {
        example_clientQ_L_10ContG_methods.$GCINFO = "example_clientQ_L_10Cont";
        example_clientQ_L_10ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        example_clientQ_L_10ContG_methods.__bool__ = (B_bool (*) (example_clientQ_L_10Cont))B_valueG_methods.__bool__;
        example_clientQ_L_10ContG_methods.__str__ = (B_str (*) (example_clientQ_L_10Cont))B_valueG_methods.__str__;
        example_clientQ_L_10ContG_methods.__repr__ = (B_str (*) (example_clientQ_L_10Cont))B_valueG_methods.__repr__;
        example_clientQ_L_10ContG_methods.__init__ = (B_NoneType (*) (example_clientQ_L_10Cont, example_clientQ_main, $Cont))example_clientQ_L_10ContD___init__;
        example_clientQ_L_10ContG_methods.__call__ = ($R (*) (example_clientQ_L_10Cont, B_NoneType))example_clientQ_L_10ContD___call__;
        example_clientQ_L_10ContG_methods.__serialize__ = example_clientQ_L_10ContD___serialize__;
        example_clientQ_L_10ContG_methods.__deserialize__ = example_clientQ_L_10ContD___deserialize__;
        $register(&example_clientQ_L_10ContG_methods);
    }
    {
        example_clientQ_L_12ContG_methods.$GCINFO = "example_clientQ_L_12Cont";
        example_clientQ_L_12ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        example_clientQ_L_12ContG_methods.__bool__ = (B_bool (*) (example_clientQ_L_12Cont))B_valueG_methods.__bool__;
        example_clientQ_L_12ContG_methods.__str__ = (B_str (*) (example_clientQ_L_12Cont))B_valueG_methods.__str__;
        example_clientQ_L_12ContG_methods.__repr__ = (B_str (*) (example_clientQ_L_12Cont))B_valueG_methods.__repr__;
        example_clientQ_L_12ContG_methods.__init__ = (B_NoneType (*) (example_clientQ_L_12Cont, example_clientQ_main, $Cont))example_clientQ_L_12ContD___init__;
        example_clientQ_L_12ContG_methods.__call__ = ($R (*) (example_clientQ_L_12Cont, B_NoneType))example_clientQ_L_12ContD___call__;
        example_clientQ_L_12ContG_methods.__serialize__ = example_clientQ_L_12ContD___serialize__;
        example_clientQ_L_12ContG_methods.__deserialize__ = example_clientQ_L_12ContD___deserialize__;
        $register(&example_clientQ_L_12ContG_methods);
    }
    {
        example_clientQ_L_13ContG_methods.$GCINFO = "example_clientQ_L_13Cont";
        example_clientQ_L_13ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        example_clientQ_L_13ContG_methods.__bool__ = (B_bool (*) (example_clientQ_L_13Cont))B_valueG_methods.__bool__;
        example_clientQ_L_13ContG_methods.__str__ = (B_str (*) (example_clientQ_L_13Cont))B_valueG_methods.__str__;
        example_clientQ_L_13ContG_methods.__repr__ = (B_str (*) (example_clientQ_L_13Cont))B_valueG_methods.__repr__;
        example_clientQ_L_13ContG_methods.__init__ = (B_NoneType (*) (example_clientQ_L_13Cont, example_clientQ_main, $Cont))example_clientQ_L_13ContD___init__;
        example_clientQ_L_13ContG_methods.__call__ = ($R (*) (example_clientQ_L_13Cont, B_str))example_clientQ_L_13ContD___call__;
        example_clientQ_L_13ContG_methods.__serialize__ = example_clientQ_L_13ContD___serialize__;
        example_clientQ_L_13ContG_methods.__deserialize__ = example_clientQ_L_13ContD___deserialize__;
        $register(&example_clientQ_L_13ContG_methods);
    }
    {
        example_clientQ_L_16ContG_methods.$GCINFO = "example_clientQ_L_16Cont";
        example_clientQ_L_16ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        example_clientQ_L_16ContG_methods.__bool__ = (B_bool (*) (example_clientQ_L_16Cont))B_valueG_methods.__bool__;
        example_clientQ_L_16ContG_methods.__str__ = (B_str (*) (example_clientQ_L_16Cont))B_valueG_methods.__str__;
        example_clientQ_L_16ContG_methods.__repr__ = (B_str (*) (example_clientQ_L_16Cont))B_valueG_methods.__repr__;
        example_clientQ_L_16ContG_methods.__init__ = (B_NoneType (*) (example_clientQ_L_16Cont, $Cont))example_clientQ_L_16ContD___init__;
        example_clientQ_L_16ContG_methods.__call__ = ($R (*) (example_clientQ_L_16Cont, sshQ_RunCommand))example_clientQ_L_16ContD___call__;
        example_clientQ_L_16ContG_methods.__serialize__ = example_clientQ_L_16ContD___serialize__;
        example_clientQ_L_16ContG_methods.__deserialize__ = example_clientQ_L_16ContD___deserialize__;
        $register(&example_clientQ_L_16ContG_methods);
    }
    {
        example_clientQ_L_18actionG_methods.$GCINFO = "example_clientQ_L_18action";
        example_clientQ_L_18actionG_methods.$superclass = ($SuperG_class)&$actionG_methods;
        example_clientQ_L_18actionG_methods.__bool__ = (B_bool (*) (example_clientQ_L_18action))B_valueG_methods.__bool__;
        example_clientQ_L_18actionG_methods.__str__ = (B_str (*) (example_clientQ_L_18action))B_valueG_methods.__str__;
        example_clientQ_L_18actionG_methods.__repr__ = (B_str (*) (example_clientQ_L_18action))B_valueG_methods.__repr__;
        example_clientQ_L_18actionG_methods.__init__ = (B_NoneType (*) (example_clientQ_L_18action, example_clientQ_main))example_clientQ_L_18actionD___init__;
        example_clientQ_L_18actionG_methods.__call__ = ($R (*) (example_clientQ_L_18action, $Cont, sshQ_Channel, B_int, B_str, B_bytes, B_bytes, B_str))example_clientQ_L_18actionD___call__;
        example_clientQ_L_18actionG_methods.__exec__ = ($R (*) (example_clientQ_L_18action, $Cont, sshQ_Channel, B_int, B_str, B_bytes, B_bytes, B_str))example_clientQ_L_18actionD___exec__;
        example_clientQ_L_18actionG_methods.__asyn__ = (B_Msg (*) (example_clientQ_L_18action, sshQ_Channel, B_int, B_str, B_bytes, B_bytes, B_str))example_clientQ_L_18actionD___asyn__;
        example_clientQ_L_18actionG_methods.__serialize__ = example_clientQ_L_18actionD___serialize__;
        example_clientQ_L_18actionG_methods.__deserialize__ = example_clientQ_L_18actionD___deserialize__;
        $register(&example_clientQ_L_18actionG_methods);
    }
    {
        example_clientQ_L_19ContG_methods.$GCINFO = "example_clientQ_L_19Cont";
        example_clientQ_L_19ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        example_clientQ_L_19ContG_methods.__bool__ = (B_bool (*) (example_clientQ_L_19Cont))B_valueG_methods.__bool__;
        example_clientQ_L_19ContG_methods.__str__ = (B_str (*) (example_clientQ_L_19Cont))B_valueG_methods.__str__;
        example_clientQ_L_19ContG_methods.__repr__ = (B_str (*) (example_clientQ_L_19Cont))B_valueG_methods.__repr__;
        example_clientQ_L_19ContG_methods.__init__ = (B_NoneType (*) (example_clientQ_L_19Cont, $Cont, sshQ_Client, example_clientQ_main))example_clientQ_L_19ContD___init__;
        example_clientQ_L_19ContG_methods.__call__ = ($R (*) (example_clientQ_L_19Cont, B_NoneType))example_clientQ_L_19ContD___call__;
        example_clientQ_L_19ContG_methods.__serialize__ = example_clientQ_L_19ContD___serialize__;
        example_clientQ_L_19ContG_methods.__deserialize__ = example_clientQ_L_19ContD___deserialize__;
        $register(&example_clientQ_L_19ContG_methods);
    }
    {
        example_clientQ_L_21ContG_methods.$GCINFO = "example_clientQ_L_21Cont";
        example_clientQ_L_21ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        example_clientQ_L_21ContG_methods.__bool__ = (B_bool (*) (example_clientQ_L_21Cont))B_valueG_methods.__bool__;
        example_clientQ_L_21ContG_methods.__str__ = (B_str (*) (example_clientQ_L_21Cont))B_valueG_methods.__str__;
        example_clientQ_L_21ContG_methods.__repr__ = (B_str (*) (example_clientQ_L_21Cont))B_valueG_methods.__repr__;
        example_clientQ_L_21ContG_methods.__init__ = (B_NoneType (*) (example_clientQ_L_21Cont, B_Collection, B_bytes, B_bytes, example_clientQ_main, int64_t, $Cont))example_clientQ_L_21ContD___init__;
        example_clientQ_L_21ContG_methods.__call__ = ($R (*) (example_clientQ_L_21Cont, B_NoneType))example_clientQ_L_21ContD___call__;
        example_clientQ_L_21ContG_methods.__serialize__ = example_clientQ_L_21ContD___serialize__;
        example_clientQ_L_21ContG_methods.__deserialize__ = example_clientQ_L_21ContD___deserialize__;
        $register(&example_clientQ_L_21ContG_methods);
    }
    {
        example_clientQ_L_22procG_methods.$GCINFO = "example_clientQ_L_22proc";
        example_clientQ_L_22procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        example_clientQ_L_22procG_methods.__bool__ = (B_bool (*) (example_clientQ_L_22proc))B_valueG_methods.__bool__;
        example_clientQ_L_22procG_methods.__str__ = (B_str (*) (example_clientQ_L_22proc))B_valueG_methods.__str__;
        example_clientQ_L_22procG_methods.__repr__ = (B_str (*) (example_clientQ_L_22proc))B_valueG_methods.__repr__;
        example_clientQ_L_22procG_methods.__init__ = (B_NoneType (*) (example_clientQ_L_22proc, example_clientQ_main, sshQ_Client, B_str, sshQ_HostKeyInfo))example_clientQ_L_22procD___init__;
        example_clientQ_L_22procG_methods.__call__ = ($R (*) (example_clientQ_L_22proc, $Cont))example_clientQ_L_22procD___call__;
        example_clientQ_L_22procG_methods.__exec__ = ($R (*) (example_clientQ_L_22proc, $Cont))example_clientQ_L_22procD___exec__;
        example_clientQ_L_22procG_methods.__serialize__ = example_clientQ_L_22procD___serialize__;
        example_clientQ_L_22procG_methods.__deserialize__ = example_clientQ_L_22procD___deserialize__;
        $register(&example_clientQ_L_22procG_methods);
    }
    {
        example_clientQ_L_23procG_methods.$GCINFO = "example_clientQ_L_23proc";
        example_clientQ_L_23procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        example_clientQ_L_23procG_methods.__bool__ = (B_bool (*) (example_clientQ_L_23proc))B_valueG_methods.__bool__;
        example_clientQ_L_23procG_methods.__str__ = (B_str (*) (example_clientQ_L_23proc))B_valueG_methods.__str__;
        example_clientQ_L_23procG_methods.__repr__ = (B_str (*) (example_clientQ_L_23proc))B_valueG_methods.__repr__;
        example_clientQ_L_23procG_methods.__init__ = (B_NoneType (*) (example_clientQ_L_23proc, example_clientQ_main, sshQ_Client, B_str))example_clientQ_L_23procD___init__;
        example_clientQ_L_23procG_methods.__call__ = ($R (*) (example_clientQ_L_23proc, $Cont))example_clientQ_L_23procD___call__;
        example_clientQ_L_23procG_methods.__exec__ = ($R (*) (example_clientQ_L_23proc, $Cont))example_clientQ_L_23procD___exec__;
        example_clientQ_L_23procG_methods.__serialize__ = example_clientQ_L_23procD___serialize__;
        example_clientQ_L_23procG_methods.__deserialize__ = example_clientQ_L_23procD___deserialize__;
        $register(&example_clientQ_L_23procG_methods);
    }
    {
        example_clientQ_L_24procG_methods.$GCINFO = "example_clientQ_L_24proc";
        example_clientQ_L_24procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        example_clientQ_L_24procG_methods.__bool__ = (B_bool (*) (example_clientQ_L_24proc))B_valueG_methods.__bool__;
        example_clientQ_L_24procG_methods.__str__ = (B_str (*) (example_clientQ_L_24proc))B_valueG_methods.__str__;
        example_clientQ_L_24procG_methods.__repr__ = (B_str (*) (example_clientQ_L_24proc))B_valueG_methods.__repr__;
        example_clientQ_L_24procG_methods.__init__ = (B_NoneType (*) (example_clientQ_L_24proc, example_clientQ_main, sshQ_Client, B_str))example_clientQ_L_24procD___init__;
        example_clientQ_L_24procG_methods.__call__ = ($R (*) (example_clientQ_L_24proc, $Cont))example_clientQ_L_24procD___call__;
        example_clientQ_L_24procG_methods.__exec__ = ($R (*) (example_clientQ_L_24proc, $Cont))example_clientQ_L_24procD___exec__;
        example_clientQ_L_24procG_methods.__serialize__ = example_clientQ_L_24procD___serialize__;
        example_clientQ_L_24procG_methods.__deserialize__ = example_clientQ_L_24procD___deserialize__;
        $register(&example_clientQ_L_24procG_methods);
    }
    {
        example_clientQ_L_25procG_methods.$GCINFO = "example_clientQ_L_25proc";
        example_clientQ_L_25procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        example_clientQ_L_25procG_methods.__bool__ = (B_bool (*) (example_clientQ_L_25proc))B_valueG_methods.__bool__;
        example_clientQ_L_25procG_methods.__str__ = (B_str (*) (example_clientQ_L_25proc))B_valueG_methods.__str__;
        example_clientQ_L_25procG_methods.__repr__ = (B_str (*) (example_clientQ_L_25proc))B_valueG_methods.__repr__;
        example_clientQ_L_25procG_methods.__init__ = (B_NoneType (*) (example_clientQ_L_25proc, example_clientQ_main, sshQ_Channel, int64_t, B_str, B_bytes, B_bytes, B_str))example_clientQ_L_25procD___init__;
        example_clientQ_L_25procG_methods.__call__ = ($R (*) (example_clientQ_L_25proc, $Cont))example_clientQ_L_25procD___call__;
        example_clientQ_L_25procG_methods.__exec__ = ($R (*) (example_clientQ_L_25proc, $Cont))example_clientQ_L_25procD___exec__;
        example_clientQ_L_25procG_methods.__serialize__ = example_clientQ_L_25procD___serialize__;
        example_clientQ_L_25procG_methods.__deserialize__ = example_clientQ_L_25procD___deserialize__;
        $register(&example_clientQ_L_25procG_methods);
    }
    {
        example_clientQ_L_27ContG_methods.$GCINFO = "example_clientQ_L_27Cont";
        example_clientQ_L_27ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        example_clientQ_L_27ContG_methods.__bool__ = (B_bool (*) (example_clientQ_L_27Cont))B_valueG_methods.__bool__;
        example_clientQ_L_27ContG_methods.__str__ = (B_str (*) (example_clientQ_L_27Cont))B_valueG_methods.__str__;
        example_clientQ_L_27ContG_methods.__repr__ = (B_str (*) (example_clientQ_L_27Cont))B_valueG_methods.__repr__;
        example_clientQ_L_27ContG_methods.__init__ = (B_NoneType (*) (example_clientQ_L_27Cont, $Cont, example_clientQ_main))example_clientQ_L_27ContD___init__;
        example_clientQ_L_27ContG_methods.__call__ = ($R (*) (example_clientQ_L_27Cont, B_NoneType))example_clientQ_L_27ContD___call__;
        example_clientQ_L_27ContG_methods.__serialize__ = example_clientQ_L_27ContD___serialize__;
        example_clientQ_L_27ContG_methods.__deserialize__ = example_clientQ_L_27ContD___deserialize__;
        $register(&example_clientQ_L_27ContG_methods);
    }
    {
        example_clientQ_L_28procG_methods.$GCINFO = "example_clientQ_L_28proc";
        example_clientQ_L_28procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        example_clientQ_L_28procG_methods.__bool__ = (B_bool (*) (example_clientQ_L_28proc))B_valueG_methods.__bool__;
        example_clientQ_L_28procG_methods.__str__ = (B_str (*) (example_clientQ_L_28proc))B_valueG_methods.__str__;
        example_clientQ_L_28procG_methods.__repr__ = (B_str (*) (example_clientQ_L_28proc))B_valueG_methods.__repr__;
        example_clientQ_L_28procG_methods.__init__ = (B_NoneType (*) (example_clientQ_L_28proc, example_clientQ_main, B_Env))example_clientQ_L_28procD___init__;
        example_clientQ_L_28procG_methods.__call__ = ($R (*) (example_clientQ_L_28proc, $Cont))example_clientQ_L_28procD___call__;
        example_clientQ_L_28procG_methods.__exec__ = ($R (*) (example_clientQ_L_28proc, $Cont))example_clientQ_L_28procD___exec__;
        example_clientQ_L_28procG_methods.__serialize__ = example_clientQ_L_28procD___serialize__;
        example_clientQ_L_28procG_methods.__deserialize__ = example_clientQ_L_28procD___deserialize__;
        $register(&example_clientQ_L_28procG_methods);
    }
    {
        example_clientQ_mainG_methods.$GCINFO = "example_clientQ_main";
        example_clientQ_mainG_methods.$superclass = ($SuperG_class)&$ActorG_methods;
        example_clientQ_mainG_methods.__bool__ = (B_bool (*) (example_clientQ_main))$ActorG_methods.__bool__;
        example_clientQ_mainG_methods.__str__ = (B_str (*) (example_clientQ_main))$ActorG_methods.__str__;
        example_clientQ_mainG_methods.__repr__ = (B_str (*) (example_clientQ_main))$ActorG_methods.__repr__;
        example_clientQ_mainG_methods.__resume__ = (B_NoneType (*) (example_clientQ_main))$ActorG_methods.__resume__;
        example_clientQ_mainG_methods.__cleanup__ = (B_NoneType (*) (example_clientQ_main))$ActorG_methods.__cleanup__;
        example_clientQ_mainG_methods.__init__ = ($R (*) (example_clientQ_main, $Cont, B_Env))example_clientQ_mainD___init__;
        example_clientQ_mainG_methods.on_hostkeyG_local = ($R (*) (example_clientQ_main, $Cont, sshQ_Client, B_str, sshQ_HostKeyInfo))example_clientQ_mainD_on_hostkeyG_local;
        example_clientQ_mainG_methods.on_connectG_local = ($R (*) (example_clientQ_main, $Cont, sshQ_Client, B_str))example_clientQ_mainD_on_connectG_local;
        example_clientQ_mainG_methods.on_closeG_local = ($R (*) (example_clientQ_main, $Cont, sshQ_Client, B_str))example_clientQ_mainD_on_closeG_local;
        example_clientQ_mainG_methods.on_exitG_local = ($R (*) (example_clientQ_main, $Cont, sshQ_Channel, int64_t, B_str, B_bytes, B_bytes, B_str))example_clientQ_mainD_on_exitG_local;
        example_clientQ_mainG_methods.on_hostkey = (B_Msg (*) (example_clientQ_main, sshQ_Client, B_str, sshQ_HostKeyInfo))example_clientQ_mainD_on_hostkey;
        example_clientQ_mainG_methods.on_connect = (B_Msg (*) (example_clientQ_main, sshQ_Client, B_str))example_clientQ_mainD_on_connect;
        example_clientQ_mainG_methods.on_close = (B_Msg (*) (example_clientQ_main, sshQ_Client, B_str))example_clientQ_mainD_on_close;
        example_clientQ_mainG_methods.on_exit = (B_Msg (*) (example_clientQ_main, sshQ_Channel, int64_t, B_str, B_bytes, B_bytes, B_str))example_clientQ_mainD_on_exit;
        example_clientQ_mainG_methods.__serialize__ = example_clientQ_mainD___serialize__;
        example_clientQ_mainG_methods.__deserialize__ = example_clientQ_mainD___deserialize__;
        $register(&example_clientQ_mainG_methods);
    }
    B_Collection W_main_15 = (B_Collection)B_SequenceD_listG_witness->W_Collection;
    example_clientQ_W_main_15 = W_main_15;
    B_Plus W_main_238 = (B_Plus)B_TimesD_strG_witness;
    example_clientQ_W_main_238 = W_main_238;
}