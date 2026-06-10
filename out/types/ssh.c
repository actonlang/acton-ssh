/* Acton impl hash: eb4513c645903bcb131c1508314087f0d03ed41882dd17f9ecd54227a60213e6 */
#include "rts/common.h"
#include "out/types/ssh.h"
#include "src/ssh.ext.c"
B_str sshQ_version ();
/*
#line 72 "src/ssh.act"
B_str sshQ_version () {
    #line 74 "src/ssh.act"
    // NotImplemented
}
*/
B_NoneType sshQ__debug (B_str msg);
/*
#line 77 "src/ssh.act"
B_NoneType sshQ__debug (B_str msg) {
    #line 79 "src/ssh.act"
    // NotImplemented
}
*/
B_str sshQ_HOSTKEY_OK;
B_str sshQ_HOSTKEY_UNKNOWN;
B_str sshQ_HOSTKEY_NOT_FOUND;
B_str sshQ_HOSTKEY_CHANGED;
B_str sshQ_HOSTKEY_OTHER;
B_str sshQ_HOSTKEY_ERROR;
B_Plus sshQ_W_HostKeyInfo_924;
$R sshQ_L_1C_1cont (sshQ_Client self, $Cont C_cont, B_NoneType C_2res) {
    return (($R (*) ($WORD, $Cont))((sshQ_Client)(self))->$class->_initG_local)(self, C_cont);
}
B_NoneType sshQ_L_2ContD___init__ (sshQ_L_2Cont L_self, sshQ_Client self, $Cont C_cont) {
    ((sshQ_L_2Cont)(L_self))->self = self;
    ((sshQ_L_2Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R sshQ_L_2ContD___call__ (sshQ_L_2Cont L_self, B_NoneType G_1) {
    sshQ_Client self = ((sshQ_L_2Cont)(L_self))->self;
    $Cont C_cont = ((sshQ_L_2Cont)(L_self))->C_cont;
    return sshQ_L_1C_1cont(self, C_cont, G_1);
}
void sshQ_L_2ContD___serialize__ (sshQ_L_2Cont self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->C_cont, state);
}
sshQ_L_2Cont sshQ_L_2ContD___deserialize__ (sshQ_L_2Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_2Cont));
            self->$class = &sshQ_L_2ContG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_2Cont, state);
    }
    self->self = $step_deserialize(state);
    self->C_cont = $step_deserialize(state);
    return self;
}
sshQ_L_2Cont sshQ_L_2ContG_new(sshQ_Client G_1, $Cont G_2) {
    sshQ_L_2Cont $tmp = acton_malloc(sizeof(struct sshQ_L_2Cont));
    $tmp->$class = &sshQ_L_2ContG_methods;
    sshQ_L_2ContG_methods.__init__($tmp, G_1, G_2);
    return $tmp;
}
struct sshQ_L_2ContG_class sshQ_L_2ContG_methods;
$R sshQ_L_3C_3cont ($Cont C_cont, B_NoneType C_4res) {
    return $R_CONT(C_cont, B_None);
}
B_NoneType sshQ_L_4ContD___init__ (sshQ_L_4Cont L_self, $Cont C_cont) {
    ((sshQ_L_4Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R sshQ_L_4ContD___call__ (sshQ_L_4Cont L_self, B_NoneType G_1) {
    $Cont C_cont = ((sshQ_L_4Cont)(L_self))->C_cont;
    return sshQ_L_3C_3cont(C_cont, G_1);
}
void sshQ_L_4ContD___serialize__ (sshQ_L_4Cont self, $Serial$state state) {
    $step_serialize(self->C_cont, state);
}
sshQ_L_4Cont sshQ_L_4ContD___deserialize__ (sshQ_L_4Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_4Cont));
            self->$class = &sshQ_L_4ContG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_4Cont, state);
    }
    self->C_cont = $step_deserialize(state);
    return self;
}
sshQ_L_4Cont sshQ_L_4ContG_new($Cont G_1) {
    sshQ_L_4Cont $tmp = acton_malloc(sizeof(struct sshQ_L_4Cont));
    $tmp->$class = &sshQ_L_4ContG_methods;
    sshQ_L_4ContG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct sshQ_L_4ContG_class sshQ_L_4ContG_methods;
B_NoneType sshQ_L_5ContD___init__ (sshQ_L_5Cont L_self, $Cont C_cont) {
    ((sshQ_L_5Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R sshQ_L_5ContD___call__ (sshQ_L_5Cont L_self, B_NoneType G_1) {
    $Cont C_cont = ((sshQ_L_5Cont)(L_self))->C_cont;
    return sshQ_L_3C_3cont(C_cont, G_1);
}
void sshQ_L_5ContD___serialize__ (sshQ_L_5Cont self, $Serial$state state) {
    $step_serialize(self->C_cont, state);
}
sshQ_L_5Cont sshQ_L_5ContD___deserialize__ (sshQ_L_5Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_5Cont));
            self->$class = &sshQ_L_5ContG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_5Cont, state);
    }
    self->C_cont = $step_deserialize(state);
    return self;
}
sshQ_L_5Cont sshQ_L_5ContG_new($Cont G_1) {
    sshQ_L_5Cont $tmp = acton_malloc(sizeof(struct sshQ_L_5Cont));
    $tmp->$class = &sshQ_L_5ContG_methods;
    sshQ_L_5ContG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct sshQ_L_5ContG_class sshQ_L_5ContG_methods;
B_NoneType sshQ_L_6procD___init__ (sshQ_L_6proc L_self, sshQ_Client self) {
    ((sshQ_L_6proc)(L_self))->self = self;
    return B_None;
}
$R sshQ_L_6procD___call__ (sshQ_L_6proc L_self, $Cont C_cont) {
    sshQ_Client self = ((sshQ_L_6proc)(L_self))->self;
    return (($R (*) ($WORD, $Cont))((sshQ_Client)(self))->$class->_pin_affinityG_local)(self, C_cont);
}
$R sshQ_L_6procD___exec__ (sshQ_L_6proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((sshQ_L_6proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void sshQ_L_6procD___serialize__ (sshQ_L_6proc self, $Serial$state state) {
    $step_serialize(self->self, state);
}
sshQ_L_6proc sshQ_L_6procD___deserialize__ (sshQ_L_6proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_6proc));
            self->$class = &sshQ_L_6procG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_6proc, state);
    }
    self->self = $step_deserialize(state);
    return self;
}
sshQ_L_6proc sshQ_L_6procG_new(sshQ_Client G_1) {
    sshQ_L_6proc $tmp = acton_malloc(sizeof(struct sshQ_L_6proc));
    $tmp->$class = &sshQ_L_6procG_methods;
    sshQ_L_6procG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct sshQ_L_6procG_class sshQ_L_6procG_methods;
B_NoneType sshQ_L_7procD___init__ (sshQ_L_7proc L_self, sshQ_Client self) {
    ((sshQ_L_7proc)(L_self))->self = self;
    return B_None;
}
$R sshQ_L_7procD___call__ (sshQ_L_7proc L_self, $Cont C_cont) {
    sshQ_Client self = ((sshQ_L_7proc)(L_self))->self;
    return (($R (*) ($WORD, $Cont))((sshQ_Client)(self))->$class->_initG_local)(self, C_cont);
}
$R sshQ_L_7procD___exec__ (sshQ_L_7proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((sshQ_L_7proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void sshQ_L_7procD___serialize__ (sshQ_L_7proc self, $Serial$state state) {
    $step_serialize(self->self, state);
}
sshQ_L_7proc sshQ_L_7procD___deserialize__ (sshQ_L_7proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_7proc));
            self->$class = &sshQ_L_7procG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_7proc, state);
    }
    self->self = $step_deserialize(state);
    return self;
}
sshQ_L_7proc sshQ_L_7procG_new(sshQ_Client G_1) {
    sshQ_L_7proc $tmp = acton_malloc(sizeof(struct sshQ_L_7proc));
    $tmp->$class = &sshQ_L_7procG_methods;
    sshQ_L_7procG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct sshQ_L_7procG_class sshQ_L_7procG_methods;
B_NoneType sshQ_L_8procD___init__ (sshQ_L_8proc L_self, sshQ_Client self) {
    ((sshQ_L_8proc)(L_self))->self = self;
    return B_None;
}
$R sshQ_L_8procD___call__ (sshQ_L_8proc L_self, $Cont C_cont) {
    sshQ_Client self = ((sshQ_L_8proc)(L_self))->self;
    return (($R (*) ($WORD, $Cont))((sshQ_Client)(self))->$class->accept_hostkeyG_local)(self, C_cont);
}
$R sshQ_L_8procD___exec__ (sshQ_L_8proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((sshQ_L_8proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void sshQ_L_8procD___serialize__ (sshQ_L_8proc self, $Serial$state state) {
    $step_serialize(self->self, state);
}
sshQ_L_8proc sshQ_L_8procD___deserialize__ (sshQ_L_8proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_8proc));
            self->$class = &sshQ_L_8procG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_8proc, state);
    }
    self->self = $step_deserialize(state);
    return self;
}
sshQ_L_8proc sshQ_L_8procG_new(sshQ_Client G_1) {
    sshQ_L_8proc $tmp = acton_malloc(sizeof(struct sshQ_L_8proc));
    $tmp->$class = &sshQ_L_8procG_methods;
    sshQ_L_8procG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct sshQ_L_8procG_class sshQ_L_8procG_methods;
B_NoneType sshQ_L_9procD___init__ (sshQ_L_9proc L_self, sshQ_Client self, B_str reason) {
    ((sshQ_L_9proc)(L_self))->self = self;
    ((sshQ_L_9proc)(L_self))->reason = reason;
    return B_None;
}
$R sshQ_L_9procD___call__ (sshQ_L_9proc L_self, $Cont C_cont) {
    sshQ_Client self = ((sshQ_L_9proc)(L_self))->self;
    B_str reason = ((sshQ_L_9proc)(L_self))->reason;
    return (($R (*) ($WORD, $Cont, B_str))((sshQ_Client)(self))->$class->reject_hostkeyG_local)(self, C_cont, reason);
}
$R sshQ_L_9procD___exec__ (sshQ_L_9proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((sshQ_L_9proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void sshQ_L_9procD___serialize__ (sshQ_L_9proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->reason, state);
}
sshQ_L_9proc sshQ_L_9procD___deserialize__ (sshQ_L_9proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_9proc));
            self->$class = &sshQ_L_9procG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_9proc, state);
    }
    self->self = $step_deserialize(state);
    self->reason = $step_deserialize(state);
    return self;
}
sshQ_L_9proc sshQ_L_9procG_new(sshQ_Client G_1, B_str G_2) {
    sshQ_L_9proc $tmp = acton_malloc(sizeof(struct sshQ_L_9proc));
    $tmp->$class = &sshQ_L_9procG_methods;
    sshQ_L_9procG_methods.__init__($tmp, G_1, G_2);
    return $tmp;
}
struct sshQ_L_9procG_class sshQ_L_9procG_methods;
B_NoneType sshQ_L_10procD___init__ (sshQ_L_10proc L_self, sshQ_Client self) {
    ((sshQ_L_10proc)(L_self))->self = self;
    return B_None;
}
$R sshQ_L_10procD___call__ (sshQ_L_10proc L_self, $Cont C_cont) {
    sshQ_Client self = ((sshQ_L_10proc)(L_self))->self;
    return (($R (*) ($WORD, $Cont))((sshQ_Client)(self))->$class->closeG_local)(self, C_cont);
}
$R sshQ_L_10procD___exec__ (sshQ_L_10proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((sshQ_L_10proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void sshQ_L_10procD___serialize__ (sshQ_L_10proc self, $Serial$state state) {
    $step_serialize(self->self, state);
}
sshQ_L_10proc sshQ_L_10procD___deserialize__ (sshQ_L_10proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_10proc));
            self->$class = &sshQ_L_10procG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_10proc, state);
    }
    self->self = $step_deserialize(state);
    return self;
}
sshQ_L_10proc sshQ_L_10procG_new(sshQ_Client G_1) {
    sshQ_L_10proc $tmp = acton_malloc(sizeof(struct sshQ_L_10proc));
    $tmp->$class = &sshQ_L_10procG_methods;
    sshQ_L_10procG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct sshQ_L_10procG_class sshQ_L_10procG_methods;
B_NoneType sshQ_L_11procD___init__ (sshQ_L_11proc L_self, sshQ_Client self) {
    ((sshQ_L_11proc)(L_self))->self = self;
    return B_None;
}
$R sshQ_L_11procD___call__ (sshQ_L_11proc L_self, $Cont C_cont) {
    sshQ_Client self = ((sshQ_L_11proc)(L_self))->self;
    return (($R (*) ($WORD, $Cont))((sshQ_Client)(self))->$class->_cleanup_nativeG_local)(self, C_cont);
}
$R sshQ_L_11procD___exec__ (sshQ_L_11proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((sshQ_L_11proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void sshQ_L_11procD___serialize__ (sshQ_L_11proc self, $Serial$state state) {
    $step_serialize(self->self, state);
}
sshQ_L_11proc sshQ_L_11procD___deserialize__ (sshQ_L_11proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_11proc));
            self->$class = &sshQ_L_11procG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_11proc, state);
    }
    self->self = $step_deserialize(state);
    return self;
}
sshQ_L_11proc sshQ_L_11procG_new(sshQ_Client G_1) {
    sshQ_L_11proc $tmp = acton_malloc(sizeof(struct sshQ_L_11proc));
    $tmp->$class = &sshQ_L_11procG_methods;
    sshQ_L_11procG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct sshQ_L_11procG_class sshQ_L_11procG_methods;
B_NoneType sshQ_L_12procD___init__ (sshQ_L_12proc L_self, sshQ_Client self) {
    ((sshQ_L_12proc)(L_self))->self = self;
    return B_None;
}
$R sshQ_L_12procD___call__ (sshQ_L_12proc L_self, $Cont C_cont) {
    sshQ_Client self = ((sshQ_L_12proc)(L_self))->self;
    return (($R (*) ($WORD, $Cont))((sshQ_Client)(self))->$class->__cleanup__G_local)(self, C_cont);
}
$R sshQ_L_12procD___exec__ (sshQ_L_12proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((sshQ_L_12proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void sshQ_L_12procD___serialize__ (sshQ_L_12proc self, $Serial$state state) {
    $step_serialize(self->self, state);
}
sshQ_L_12proc sshQ_L_12procD___deserialize__ (sshQ_L_12proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_12proc));
            self->$class = &sshQ_L_12procG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_12proc, state);
    }
    self->self = $step_deserialize(state);
    return self;
}
sshQ_L_12proc sshQ_L_12procG_new(sshQ_Client G_1) {
    sshQ_L_12proc $tmp = acton_malloc(sizeof(struct sshQ_L_12proc));
    $tmp->$class = &sshQ_L_12procG_methods;
    sshQ_L_12procG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct sshQ_L_12procG_class sshQ_L_12procG_methods;
B_NoneType sshQ_L_13procD___init__ (sshQ_L_13proc L_self, sshQ_Client self, sshQ_Channel channel, $action on_open, $action on_stdout, $action on_stderr, $action on_exit, $action on_close) {
    ((sshQ_L_13proc)(L_self))->self = self;
    ((sshQ_L_13proc)(L_self))->channel = channel;
    ((sshQ_L_13proc)(L_self))->on_open = on_open;
    ((sshQ_L_13proc)(L_self))->on_stdout = on_stdout;
    ((sshQ_L_13proc)(L_self))->on_stderr = on_stderr;
    ((sshQ_L_13proc)(L_self))->on_exit = on_exit;
    ((sshQ_L_13proc)(L_self))->on_close = on_close;
    return B_None;
}
$R sshQ_L_13procD___call__ (sshQ_L_13proc L_self, $Cont C_cont) {
    sshQ_Client self = ((sshQ_L_13proc)(L_self))->self;
    sshQ_Channel channel = ((sshQ_L_13proc)(L_self))->channel;
    $action on_open = ((sshQ_L_13proc)(L_self))->on_open;
    $action on_stdout = ((sshQ_L_13proc)(L_self))->on_stdout;
    $action on_stderr = ((sshQ_L_13proc)(L_self))->on_stderr;
    $action on_exit = ((sshQ_L_13proc)(L_self))->on_exit;
    $action on_close = ((sshQ_L_13proc)(L_self))->on_close;
    return (($R (*) ($WORD, $Cont, sshQ_Channel, $action, $action, $action, $action, $action))((sshQ_Client)(self))->$class->channel_createG_local)(self, C_cont, channel, on_open, on_stdout, on_stderr, on_exit, on_close);
}
$R sshQ_L_13procD___exec__ (sshQ_L_13proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((sshQ_L_13proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void sshQ_L_13procD___serialize__ (sshQ_L_13proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->channel, state);
    $step_serialize(self->on_open, state);
    $step_serialize(self->on_stdout, state);
    $step_serialize(self->on_stderr, state);
    $step_serialize(self->on_exit, state);
    $step_serialize(self->on_close, state);
}
sshQ_L_13proc sshQ_L_13procD___deserialize__ (sshQ_L_13proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_13proc));
            self->$class = &sshQ_L_13procG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_13proc, state);
    }
    self->self = $step_deserialize(state);
    self->channel = $step_deserialize(state);
    self->on_open = $step_deserialize(state);
    self->on_stdout = $step_deserialize(state);
    self->on_stderr = $step_deserialize(state);
    self->on_exit = $step_deserialize(state);
    self->on_close = $step_deserialize(state);
    return self;
}
sshQ_L_13proc sshQ_L_13procG_new(sshQ_Client G_1, sshQ_Channel G_2, $action G_3, $action G_4, $action G_5, $action G_6, $action G_7) {
    sshQ_L_13proc $tmp = acton_malloc(sizeof(struct sshQ_L_13proc));
    $tmp->$class = &sshQ_L_13procG_methods;
    sshQ_L_13procG_methods.__init__($tmp, G_1, G_2, G_3, G_4, G_5, G_6, G_7);
    return $tmp;
}
struct sshQ_L_13procG_class sshQ_L_13procG_methods;
B_NoneType sshQ_L_14procD___init__ (sshQ_L_14proc L_self, sshQ_Client self, sshQ_Channel channel, B_str cmd) {
    ((sshQ_L_14proc)(L_self))->self = self;
    ((sshQ_L_14proc)(L_self))->channel = channel;
    ((sshQ_L_14proc)(L_self))->cmd = cmd;
    return B_None;
}
$R sshQ_L_14procD___call__ (sshQ_L_14proc L_self, $Cont C_cont) {
    sshQ_Client self = ((sshQ_L_14proc)(L_self))->self;
    sshQ_Channel channel = ((sshQ_L_14proc)(L_self))->channel;
    B_str cmd = ((sshQ_L_14proc)(L_self))->cmd;
    return (($R (*) ($WORD, $Cont, sshQ_Channel, B_str))((sshQ_Client)(self))->$class->channel_request_execG_local)(self, C_cont, channel, cmd);
}
$R sshQ_L_14procD___exec__ (sshQ_L_14proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((sshQ_L_14proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void sshQ_L_14procD___serialize__ (sshQ_L_14proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->channel, state);
    $step_serialize(self->cmd, state);
}
sshQ_L_14proc sshQ_L_14procD___deserialize__ (sshQ_L_14proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_14proc));
            self->$class = &sshQ_L_14procG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_14proc, state);
    }
    self->self = $step_deserialize(state);
    self->channel = $step_deserialize(state);
    self->cmd = $step_deserialize(state);
    return self;
}
sshQ_L_14proc sshQ_L_14procG_new(sshQ_Client G_1, sshQ_Channel G_2, B_str G_3) {
    sshQ_L_14proc $tmp = acton_malloc(sizeof(struct sshQ_L_14proc));
    $tmp->$class = &sshQ_L_14procG_methods;
    sshQ_L_14procG_methods.__init__($tmp, G_1, G_2, G_3);
    return $tmp;
}
struct sshQ_L_14procG_class sshQ_L_14procG_methods;
B_NoneType sshQ_L_15procD___init__ (sshQ_L_15proc L_self, sshQ_Client self, sshQ_Channel channel, B_str term, int64_t cols, int64_t rows, int64_t width_px, int64_t height_px, B_bool with_pty) {
    ((sshQ_L_15proc)(L_self))->self = self;
    ((sshQ_L_15proc)(L_self))->channel = channel;
    ((sshQ_L_15proc)(L_self))->term = term;
    ((sshQ_L_15proc)(L_self))->cols = cols;
    ((sshQ_L_15proc)(L_self))->rows = rows;
    ((sshQ_L_15proc)(L_self))->width_px = width_px;
    ((sshQ_L_15proc)(L_self))->height_px = height_px;
    ((sshQ_L_15proc)(L_self))->with_pty = with_pty;
    return B_None;
}
$R sshQ_L_15procD___call__ (sshQ_L_15proc L_self, $Cont C_cont) {
    sshQ_Client self = ((sshQ_L_15proc)(L_self))->self;
    sshQ_Channel channel = ((sshQ_L_15proc)(L_self))->channel;
    B_str term = ((sshQ_L_15proc)(L_self))->term;
    int64_t cols = ((int64_t)((sshQ_L_15proc)(L_self))->cols);
    int64_t rows = ((int64_t)((sshQ_L_15proc)(L_self))->rows);
    int64_t width_px = ((int64_t)((sshQ_L_15proc)(L_self))->width_px);
    int64_t height_px = ((int64_t)((sshQ_L_15proc)(L_self))->height_px);
    B_bool with_pty = ((sshQ_L_15proc)(L_self))->with_pty;
    return (($R (*) ($WORD, $Cont, sshQ_Channel, B_str, int64_t, int64_t, int64_t, int64_t, B_bool))((sshQ_Client)(self))->$class->channel_request_shellG_local)(self, C_cont, channel, term, cols, rows, width_px, height_px, with_pty);
}
$R sshQ_L_15procD___exec__ (sshQ_L_15proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((sshQ_L_15proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void sshQ_L_15procD___serialize__ (sshQ_L_15proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->channel, state);
    $step_serialize(self->term, state);
    $val_serialize(I64_ID, &self->cols, state);
    $val_serialize(I64_ID, &self->rows, state);
    $val_serialize(I64_ID, &self->width_px, state);
    $val_serialize(I64_ID, &self->height_px, state);
    $step_serialize(self->with_pty, state);
}
sshQ_L_15proc sshQ_L_15procD___deserialize__ (sshQ_L_15proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_15proc));
            self->$class = &sshQ_L_15procG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_15proc, state);
    }
    self->self = $step_deserialize(state);
    self->channel = $step_deserialize(state);
    self->term = $step_deserialize(state);
    $tmp = $val_deserialize(state);
    memcpy(&self->cols, &$tmp, sizeof(self->cols));
    $tmp = $val_deserialize(state);
    memcpy(&self->rows, &$tmp, sizeof(self->rows));
    $tmp = $val_deserialize(state);
    memcpy(&self->width_px, &$tmp, sizeof(self->width_px));
    $tmp = $val_deserialize(state);
    memcpy(&self->height_px, &$tmp, sizeof(self->height_px));
    self->with_pty = $step_deserialize(state);
    return self;
}
sshQ_L_15proc sshQ_L_15procG_new(sshQ_Client G_1, sshQ_Channel G_2, B_str G_3, int64_t G_4, int64_t G_5, int64_t G_6, int64_t G_7, B_bool G_8) {
    sshQ_L_15proc $tmp = acton_malloc(sizeof(struct sshQ_L_15proc));
    $tmp->$class = &sshQ_L_15procG_methods;
    sshQ_L_15procG_methods.__init__($tmp, G_1, G_2, G_3, G_4, G_5, G_6, G_7, G_8);
    return $tmp;
}
struct sshQ_L_15procG_class sshQ_L_15procG_methods;
B_NoneType sshQ_L_16procD___init__ (sshQ_L_16proc L_self, sshQ_Client self, sshQ_Channel channel, B_str name) {
    ((sshQ_L_16proc)(L_self))->self = self;
    ((sshQ_L_16proc)(L_self))->channel = channel;
    ((sshQ_L_16proc)(L_self))->name = name;
    return B_None;
}
$R sshQ_L_16procD___call__ (sshQ_L_16proc L_self, $Cont C_cont) {
    sshQ_Client self = ((sshQ_L_16proc)(L_self))->self;
    sshQ_Channel channel = ((sshQ_L_16proc)(L_self))->channel;
    B_str name = ((sshQ_L_16proc)(L_self))->name;
    return (($R (*) ($WORD, $Cont, sshQ_Channel, B_str))((sshQ_Client)(self))->$class->channel_request_subsystemG_local)(self, C_cont, channel, name);
}
$R sshQ_L_16procD___exec__ (sshQ_L_16proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((sshQ_L_16proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void sshQ_L_16procD___serialize__ (sshQ_L_16proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->channel, state);
    $step_serialize(self->name, state);
}
sshQ_L_16proc sshQ_L_16procD___deserialize__ (sshQ_L_16proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_16proc));
            self->$class = &sshQ_L_16procG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_16proc, state);
    }
    self->self = $step_deserialize(state);
    self->channel = $step_deserialize(state);
    self->name = $step_deserialize(state);
    return self;
}
sshQ_L_16proc sshQ_L_16procG_new(sshQ_Client G_1, sshQ_Channel G_2, B_str G_3) {
    sshQ_L_16proc $tmp = acton_malloc(sizeof(struct sshQ_L_16proc));
    $tmp->$class = &sshQ_L_16procG_methods;
    sshQ_L_16procG_methods.__init__($tmp, G_1, G_2, G_3);
    return $tmp;
}
struct sshQ_L_16procG_class sshQ_L_16procG_methods;
B_NoneType sshQ_L_17procD___init__ (sshQ_L_17proc L_self, sshQ_Client self, sshQ_Channel channel, B_bytes data) {
    ((sshQ_L_17proc)(L_self))->self = self;
    ((sshQ_L_17proc)(L_self))->channel = channel;
    ((sshQ_L_17proc)(L_self))->data = data;
    return B_None;
}
$R sshQ_L_17procD___call__ (sshQ_L_17proc L_self, $Cont C_cont) {
    sshQ_Client self = ((sshQ_L_17proc)(L_self))->self;
    sshQ_Channel channel = ((sshQ_L_17proc)(L_self))->channel;
    B_bytes data = ((sshQ_L_17proc)(L_self))->data;
    return (($R (*) ($WORD, $Cont, sshQ_Channel, B_bytes))((sshQ_Client)(self))->$class->channel_writeG_local)(self, C_cont, channel, data);
}
$R sshQ_L_17procD___exec__ (sshQ_L_17proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((sshQ_L_17proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void sshQ_L_17procD___serialize__ (sshQ_L_17proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->channel, state);
    $step_serialize(self->data, state);
}
sshQ_L_17proc sshQ_L_17procD___deserialize__ (sshQ_L_17proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_17proc));
            self->$class = &sshQ_L_17procG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_17proc, state);
    }
    self->self = $step_deserialize(state);
    self->channel = $step_deserialize(state);
    self->data = $step_deserialize(state);
    return self;
}
sshQ_L_17proc sshQ_L_17procG_new(sshQ_Client G_1, sshQ_Channel G_2, B_bytes G_3) {
    sshQ_L_17proc $tmp = acton_malloc(sizeof(struct sshQ_L_17proc));
    $tmp->$class = &sshQ_L_17procG_methods;
    sshQ_L_17procG_methods.__init__($tmp, G_1, G_2, G_3);
    return $tmp;
}
struct sshQ_L_17procG_class sshQ_L_17procG_methods;
B_NoneType sshQ_L_18procD___init__ (sshQ_L_18proc L_self, sshQ_Client self, sshQ_Channel channel) {
    ((sshQ_L_18proc)(L_self))->self = self;
    ((sshQ_L_18proc)(L_self))->channel = channel;
    return B_None;
}
$R sshQ_L_18procD___call__ (sshQ_L_18proc L_self, $Cont C_cont) {
    sshQ_Client self = ((sshQ_L_18proc)(L_self))->self;
    sshQ_Channel channel = ((sshQ_L_18proc)(L_self))->channel;
    return (($R (*) ($WORD, $Cont, sshQ_Channel))((sshQ_Client)(self))->$class->channel_send_eofG_local)(self, C_cont, channel);
}
$R sshQ_L_18procD___exec__ (sshQ_L_18proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((sshQ_L_18proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void sshQ_L_18procD___serialize__ (sshQ_L_18proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->channel, state);
}
sshQ_L_18proc sshQ_L_18procD___deserialize__ (sshQ_L_18proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_18proc));
            self->$class = &sshQ_L_18procG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_18proc, state);
    }
    self->self = $step_deserialize(state);
    self->channel = $step_deserialize(state);
    return self;
}
sshQ_L_18proc sshQ_L_18procG_new(sshQ_Client G_1, sshQ_Channel G_2) {
    sshQ_L_18proc $tmp = acton_malloc(sizeof(struct sshQ_L_18proc));
    $tmp->$class = &sshQ_L_18procG_methods;
    sshQ_L_18procG_methods.__init__($tmp, G_1, G_2);
    return $tmp;
}
struct sshQ_L_18procG_class sshQ_L_18procG_methods;
B_NoneType sshQ_L_19procD___init__ (sshQ_L_19proc L_self, sshQ_Client self, sshQ_Channel channel) {
    ((sshQ_L_19proc)(L_self))->self = self;
    ((sshQ_L_19proc)(L_self))->channel = channel;
    return B_None;
}
$R sshQ_L_19procD___call__ (sshQ_L_19proc L_self, $Cont C_cont) {
    sshQ_Client self = ((sshQ_L_19proc)(L_self))->self;
    sshQ_Channel channel = ((sshQ_L_19proc)(L_self))->channel;
    return (($R (*) ($WORD, $Cont, sshQ_Channel))((sshQ_Client)(self))->$class->channel_closeG_local)(self, C_cont, channel);
}
$R sshQ_L_19procD___exec__ (sshQ_L_19proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((sshQ_L_19proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void sshQ_L_19procD___serialize__ (sshQ_L_19proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->channel, state);
}
sshQ_L_19proc sshQ_L_19procD___deserialize__ (sshQ_L_19proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_19proc));
            self->$class = &sshQ_L_19procG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_19proc, state);
    }
    self->self = $step_deserialize(state);
    self->channel = $step_deserialize(state);
    return self;
}
sshQ_L_19proc sshQ_L_19procG_new(sshQ_Client G_1, sshQ_Channel G_2) {
    sshQ_L_19proc $tmp = acton_malloc(sizeof(struct sshQ_L_19proc));
    $tmp->$class = &sshQ_L_19procG_methods;
    sshQ_L_19procG_methods.__init__($tmp, G_1, G_2);
    return $tmp;
}
struct sshQ_L_19procG_class sshQ_L_19procG_methods;
$R sshQ_L_20C_5cont ($Cont C_cont, B_NoneType C_6res) {
    return $R_CONT(C_cont, B_None);
}
B_NoneType sshQ_L_21ContD___init__ (sshQ_L_21Cont L_self, $Cont C_cont) {
    ((sshQ_L_21Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R sshQ_L_21ContD___call__ (sshQ_L_21Cont L_self, B_NoneType G_1) {
    $Cont C_cont = ((sshQ_L_21Cont)(L_self))->C_cont;
    return sshQ_L_20C_5cont(C_cont, G_1);
}
void sshQ_L_21ContD___serialize__ (sshQ_L_21Cont self, $Serial$state state) {
    $step_serialize(self->C_cont, state);
}
sshQ_L_21Cont sshQ_L_21ContD___deserialize__ (sshQ_L_21Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_21Cont));
            self->$class = &sshQ_L_21ContG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_21Cont, state);
    }
    self->C_cont = $step_deserialize(state);
    return self;
}
sshQ_L_21Cont sshQ_L_21ContG_new($Cont G_1) {
    sshQ_L_21Cont $tmp = acton_malloc(sizeof(struct sshQ_L_21Cont));
    $tmp->$class = &sshQ_L_21ContG_methods;
    sshQ_L_21ContG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct sshQ_L_21ContG_class sshQ_L_21ContG_methods;
B_NoneType sshQ_L_22ContD___init__ (sshQ_L_22Cont L_self, $Cont C_cont) {
    ((sshQ_L_22Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R sshQ_L_22ContD___call__ (sshQ_L_22Cont L_self, B_NoneType G_1) {
    $Cont C_cont = ((sshQ_L_22Cont)(L_self))->C_cont;
    return sshQ_L_20C_5cont(C_cont, G_1);
}
void sshQ_L_22ContD___serialize__ (sshQ_L_22Cont self, $Serial$state state) {
    $step_serialize(self->C_cont, state);
}
sshQ_L_22Cont sshQ_L_22ContD___deserialize__ (sshQ_L_22Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_22Cont));
            self->$class = &sshQ_L_22ContG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_22Cont, state);
    }
    self->C_cont = $step_deserialize(state);
    return self;
}
sshQ_L_22Cont sshQ_L_22ContG_new($Cont G_1) {
    sshQ_L_22Cont $tmp = acton_malloc(sizeof(struct sshQ_L_22Cont));
    $tmp->$class = &sshQ_L_22ContG_methods;
    sshQ_L_22ContG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct sshQ_L_22ContG_class sshQ_L_22ContG_methods;
B_NoneType sshQ_L_23procD___init__ (sshQ_L_23proc L_self, sshQ_Channel self) {
    ((sshQ_L_23proc)(L_self))->self = self;
    return B_None;
}
$R sshQ_L_23procD___call__ (sshQ_L_23proc L_self, $Cont C_cont) {
    sshQ_Channel self = ((sshQ_L_23proc)(L_self))->self;
    return (($R (*) ($WORD, $Cont))((sshQ_Channel)(self))->$class->_initG_local)(self, C_cont);
}
$R sshQ_L_23procD___exec__ (sshQ_L_23proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((sshQ_L_23proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void sshQ_L_23procD___serialize__ (sshQ_L_23proc self, $Serial$state state) {
    $step_serialize(self->self, state);
}
sshQ_L_23proc sshQ_L_23procD___deserialize__ (sshQ_L_23proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_23proc));
            self->$class = &sshQ_L_23procG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_23proc, state);
    }
    self->self = $step_deserialize(state);
    return self;
}
sshQ_L_23proc sshQ_L_23procG_new(sshQ_Channel G_1) {
    sshQ_L_23proc $tmp = acton_malloc(sizeof(struct sshQ_L_23proc));
    $tmp->$class = &sshQ_L_23procG_methods;
    sshQ_L_23procG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct sshQ_L_23procG_class sshQ_L_23procG_methods;
B_NoneType sshQ_L_24procD___init__ (sshQ_L_24proc L_self, sshQ_Channel self, B_str cmd) {
    ((sshQ_L_24proc)(L_self))->self = self;
    ((sshQ_L_24proc)(L_self))->cmd = cmd;
    return B_None;
}
$R sshQ_L_24procD___call__ (sshQ_L_24proc L_self, $Cont C_cont) {
    sshQ_Channel self = ((sshQ_L_24proc)(L_self))->self;
    B_str cmd = ((sshQ_L_24proc)(L_self))->cmd;
    return (($R (*) ($WORD, $Cont, B_str))((sshQ_Channel)(self))->$class->request_execG_local)(self, C_cont, cmd);
}
$R sshQ_L_24procD___exec__ (sshQ_L_24proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((sshQ_L_24proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void sshQ_L_24procD___serialize__ (sshQ_L_24proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->cmd, state);
}
sshQ_L_24proc sshQ_L_24procD___deserialize__ (sshQ_L_24proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_24proc));
            self->$class = &sshQ_L_24procG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_24proc, state);
    }
    self->self = $step_deserialize(state);
    self->cmd = $step_deserialize(state);
    return self;
}
sshQ_L_24proc sshQ_L_24procG_new(sshQ_Channel G_1, B_str G_2) {
    sshQ_L_24proc $tmp = acton_malloc(sizeof(struct sshQ_L_24proc));
    $tmp->$class = &sshQ_L_24procG_methods;
    sshQ_L_24procG_methods.__init__($tmp, G_1, G_2);
    return $tmp;
}
struct sshQ_L_24procG_class sshQ_L_24procG_methods;
B_NoneType sshQ_L_25procD___init__ (sshQ_L_25proc L_self, sshQ_Channel self, B_str N_default_term, B_int N_default_cols, B_int N_default_rows, B_int N_default_width_px, B_int N_default_height_px, B_bool N_default_with_pty) {
    ((sshQ_L_25proc)(L_self))->self = self;
    ((sshQ_L_25proc)(L_self))->N_default_term = N_default_term;
    ((sshQ_L_25proc)(L_self))->N_default_cols = N_default_cols;
    ((sshQ_L_25proc)(L_self))->N_default_rows = N_default_rows;
    ((sshQ_L_25proc)(L_self))->N_default_width_px = N_default_width_px;
    ((sshQ_L_25proc)(L_self))->N_default_height_px = N_default_height_px;
    ((sshQ_L_25proc)(L_self))->N_default_with_pty = N_default_with_pty;
    return B_None;
}
$R sshQ_L_25procD___call__ (sshQ_L_25proc L_self, $Cont C_cont) {
    sshQ_Channel self = ((sshQ_L_25proc)(L_self))->self;
    B_str N_default_term = ((sshQ_L_25proc)(L_self))->N_default_term;
    B_int N_default_cols = ((sshQ_L_25proc)(L_self))->N_default_cols;
    B_int N_default_rows = ((sshQ_L_25proc)(L_self))->N_default_rows;
    B_int N_default_width_px = ((sshQ_L_25proc)(L_self))->N_default_width_px;
    B_int N_default_height_px = ((sshQ_L_25proc)(L_self))->N_default_height_px;
    B_bool N_default_with_pty = ((sshQ_L_25proc)(L_self))->N_default_with_pty;
    return (($R (*) ($WORD, $Cont, B_str, B_int, B_int, B_int, B_int, B_bool))((sshQ_Channel)(self))->$class->request_shellG_local)(self, C_cont, N_default_term, N_default_cols, N_default_rows, N_default_width_px, N_default_height_px, N_default_with_pty);
}
$R sshQ_L_25procD___exec__ (sshQ_L_25proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((sshQ_L_25proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void sshQ_L_25procD___serialize__ (sshQ_L_25proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->N_default_term, state);
    $step_serialize(self->N_default_cols, state);
    $step_serialize(self->N_default_rows, state);
    $step_serialize(self->N_default_width_px, state);
    $step_serialize(self->N_default_height_px, state);
    $step_serialize(self->N_default_with_pty, state);
}
sshQ_L_25proc sshQ_L_25procD___deserialize__ (sshQ_L_25proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_25proc));
            self->$class = &sshQ_L_25procG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_25proc, state);
    }
    self->self = $step_deserialize(state);
    self->N_default_term = $step_deserialize(state);
    self->N_default_cols = $step_deserialize(state);
    self->N_default_rows = $step_deserialize(state);
    self->N_default_width_px = $step_deserialize(state);
    self->N_default_height_px = $step_deserialize(state);
    self->N_default_with_pty = $step_deserialize(state);
    return self;
}
sshQ_L_25proc sshQ_L_25procG_new(sshQ_Channel G_1, B_str G_2, B_int G_3, B_int G_4, B_int G_5, B_int G_6, B_bool G_7) {
    sshQ_L_25proc $tmp = acton_malloc(sizeof(struct sshQ_L_25proc));
    $tmp->$class = &sshQ_L_25procG_methods;
    sshQ_L_25procG_methods.__init__($tmp, G_1, G_2, G_3, G_4, G_5, G_6, G_7);
    return $tmp;
}
struct sshQ_L_25procG_class sshQ_L_25procG_methods;
B_NoneType sshQ_L_26procD___init__ (sshQ_L_26proc L_self, sshQ_Channel self, B_str name) {
    ((sshQ_L_26proc)(L_self))->self = self;
    ((sshQ_L_26proc)(L_self))->name = name;
    return B_None;
}
$R sshQ_L_26procD___call__ (sshQ_L_26proc L_self, $Cont C_cont) {
    sshQ_Channel self = ((sshQ_L_26proc)(L_self))->self;
    B_str name = ((sshQ_L_26proc)(L_self))->name;
    return (($R (*) ($WORD, $Cont, B_str))((sshQ_Channel)(self))->$class->request_subsystemG_local)(self, C_cont, name);
}
$R sshQ_L_26procD___exec__ (sshQ_L_26proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((sshQ_L_26proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void sshQ_L_26procD___serialize__ (sshQ_L_26proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->name, state);
}
sshQ_L_26proc sshQ_L_26procD___deserialize__ (sshQ_L_26proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_26proc));
            self->$class = &sshQ_L_26procG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_26proc, state);
    }
    self->self = $step_deserialize(state);
    self->name = $step_deserialize(state);
    return self;
}
sshQ_L_26proc sshQ_L_26procG_new(sshQ_Channel G_1, B_str G_2) {
    sshQ_L_26proc $tmp = acton_malloc(sizeof(struct sshQ_L_26proc));
    $tmp->$class = &sshQ_L_26procG_methods;
    sshQ_L_26procG_methods.__init__($tmp, G_1, G_2);
    return $tmp;
}
struct sshQ_L_26procG_class sshQ_L_26procG_methods;
B_NoneType sshQ_L_27procD___init__ (sshQ_L_27proc L_self, sshQ_Channel self, B_bytes data) {
    ((sshQ_L_27proc)(L_self))->self = self;
    ((sshQ_L_27proc)(L_self))->data = data;
    return B_None;
}
$R sshQ_L_27procD___call__ (sshQ_L_27proc L_self, $Cont C_cont) {
    sshQ_Channel self = ((sshQ_L_27proc)(L_self))->self;
    B_bytes data = ((sshQ_L_27proc)(L_self))->data;
    return (($R (*) ($WORD, $Cont, B_bytes))((sshQ_Channel)(self))->$class->writeG_local)(self, C_cont, data);
}
$R sshQ_L_27procD___exec__ (sshQ_L_27proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((sshQ_L_27proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void sshQ_L_27procD___serialize__ (sshQ_L_27proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->data, state);
}
sshQ_L_27proc sshQ_L_27procD___deserialize__ (sshQ_L_27proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_27proc));
            self->$class = &sshQ_L_27procG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_27proc, state);
    }
    self->self = $step_deserialize(state);
    self->data = $step_deserialize(state);
    return self;
}
sshQ_L_27proc sshQ_L_27procG_new(sshQ_Channel G_1, B_bytes G_2) {
    sshQ_L_27proc $tmp = acton_malloc(sizeof(struct sshQ_L_27proc));
    $tmp->$class = &sshQ_L_27procG_methods;
    sshQ_L_27procG_methods.__init__($tmp, G_1, G_2);
    return $tmp;
}
struct sshQ_L_27procG_class sshQ_L_27procG_methods;
B_NoneType sshQ_L_28procD___init__ (sshQ_L_28proc L_self, sshQ_Channel self) {
    ((sshQ_L_28proc)(L_self))->self = self;
    return B_None;
}
$R sshQ_L_28procD___call__ (sshQ_L_28proc L_self, $Cont C_cont) {
    sshQ_Channel self = ((sshQ_L_28proc)(L_self))->self;
    return (($R (*) ($WORD, $Cont))((sshQ_Channel)(self))->$class->send_eofG_local)(self, C_cont);
}
$R sshQ_L_28procD___exec__ (sshQ_L_28proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((sshQ_L_28proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void sshQ_L_28procD___serialize__ (sshQ_L_28proc self, $Serial$state state) {
    $step_serialize(self->self, state);
}
sshQ_L_28proc sshQ_L_28procD___deserialize__ (sshQ_L_28proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_28proc));
            self->$class = &sshQ_L_28procG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_28proc, state);
    }
    self->self = $step_deserialize(state);
    return self;
}
sshQ_L_28proc sshQ_L_28procG_new(sshQ_Channel G_1) {
    sshQ_L_28proc $tmp = acton_malloc(sizeof(struct sshQ_L_28proc));
    $tmp->$class = &sshQ_L_28procG_methods;
    sshQ_L_28procG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct sshQ_L_28procG_class sshQ_L_28procG_methods;
B_NoneType sshQ_L_29procD___init__ (sshQ_L_29proc L_self, sshQ_Channel self) {
    ((sshQ_L_29proc)(L_self))->self = self;
    return B_None;
}
$R sshQ_L_29procD___call__ (sshQ_L_29proc L_self, $Cont C_cont) {
    sshQ_Channel self = ((sshQ_L_29proc)(L_self))->self;
    return (($R (*) ($WORD, $Cont))((sshQ_Channel)(self))->$class->closeG_local)(self, C_cont);
}
$R sshQ_L_29procD___exec__ (sshQ_L_29proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((sshQ_L_29proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void sshQ_L_29procD___serialize__ (sshQ_L_29proc self, $Serial$state state) {
    $step_serialize(self->self, state);
}
sshQ_L_29proc sshQ_L_29procD___deserialize__ (sshQ_L_29proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_29proc));
            self->$class = &sshQ_L_29procG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_29proc, state);
    }
    self->self = $step_deserialize(state);
    return self;
}
sshQ_L_29proc sshQ_L_29procG_new(sshQ_Channel G_1) {
    sshQ_L_29proc $tmp = acton_malloc(sizeof(struct sshQ_L_29proc));
    $tmp->$class = &sshQ_L_29procG_methods;
    sshQ_L_29procG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct sshQ_L_29procG_class sshQ_L_29procG_methods;
B_NoneType sshQ_L_30procD___init__ (sshQ_L_30proc L_self, sshQ_Channel self) {
    ((sshQ_L_30proc)(L_self))->self = self;
    return B_None;
}
$R sshQ_L_30procD___call__ (sshQ_L_30proc L_self, $Cont C_cont) {
    sshQ_Channel self = ((sshQ_L_30proc)(L_self))->self;
    return (($R (*) ($WORD, $Cont))((sshQ_Channel)(self))->$class->_cleanup_nativeG_local)(self, C_cont);
}
$R sshQ_L_30procD___exec__ (sshQ_L_30proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((sshQ_L_30proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void sshQ_L_30procD___serialize__ (sshQ_L_30proc self, $Serial$state state) {
    $step_serialize(self->self, state);
}
sshQ_L_30proc sshQ_L_30procD___deserialize__ (sshQ_L_30proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_30proc));
            self->$class = &sshQ_L_30procG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_30proc, state);
    }
    self->self = $step_deserialize(state);
    return self;
}
sshQ_L_30proc sshQ_L_30procG_new(sshQ_Channel G_1) {
    sshQ_L_30proc $tmp = acton_malloc(sizeof(struct sshQ_L_30proc));
    $tmp->$class = &sshQ_L_30procG_methods;
    sshQ_L_30procG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct sshQ_L_30procG_class sshQ_L_30procG_methods;
B_NoneType sshQ_L_31procD___init__ (sshQ_L_31proc L_self, sshQ_Channel self) {
    ((sshQ_L_31proc)(L_self))->self = self;
    return B_None;
}
$R sshQ_L_31procD___call__ (sshQ_L_31proc L_self, $Cont C_cont) {
    sshQ_Channel self = ((sshQ_L_31proc)(L_self))->self;
    return (($R (*) ($WORD, $Cont))((sshQ_Channel)(self))->$class->__cleanup__G_local)(self, C_cont);
}
$R sshQ_L_31procD___exec__ (sshQ_L_31proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((sshQ_L_31proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void sshQ_L_31procD___serialize__ (sshQ_L_31proc self, $Serial$state state) {
    $step_serialize(self->self, state);
}
sshQ_L_31proc sshQ_L_31procD___deserialize__ (sshQ_L_31proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_31proc));
            self->$class = &sshQ_L_31procG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_31proc, state);
    }
    self->self = $step_deserialize(state);
    return self;
}
sshQ_L_31proc sshQ_L_31procG_new(sshQ_Channel G_1) {
    sshQ_L_31proc $tmp = acton_malloc(sizeof(struct sshQ_L_31proc));
    $tmp->$class = &sshQ_L_31procG_methods;
    sshQ_L_31procG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct sshQ_L_31procG_class sshQ_L_31procG_methods;
$R sshQ_L_35C_11cont (sshQ_RunCommand self, $Cont C_cont, B_NoneType C_12res) {
    #line 381 "src/ssh.act"
    ((B_Msg (*) ($WORD))((sshQ_Channel)(((sshQ_RunCommand)(self))->_channel))->$class->close)(((sshQ_RunCommand)(self))->_channel);
    return $R_CONT(C_cont, B_None);
}
B_NoneType sshQ_L_36ContD___init__ (sshQ_L_36Cont L_self, sshQ_RunCommand self, $Cont C_cont) {
    ((sshQ_L_36Cont)(L_self))->self = self;
    ((sshQ_L_36Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R sshQ_L_36ContD___call__ (sshQ_L_36Cont L_self, B_NoneType G_1) {
    sshQ_RunCommand self = ((sshQ_L_36Cont)(L_self))->self;
    $Cont C_cont = ((sshQ_L_36Cont)(L_self))->C_cont;
    return sshQ_L_35C_11cont(self, C_cont, G_1);
}
void sshQ_L_36ContD___serialize__ (sshQ_L_36Cont self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->C_cont, state);
}
sshQ_L_36Cont sshQ_L_36ContD___deserialize__ (sshQ_L_36Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_36Cont));
            self->$class = &sshQ_L_36ContG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_36Cont, state);
    }
    self->self = $step_deserialize(state);
    self->C_cont = $step_deserialize(state);
    return self;
}
sshQ_L_36Cont sshQ_L_36ContG_new(sshQ_RunCommand G_1, $Cont G_2) {
    sshQ_L_36Cont $tmp = acton_malloc(sizeof(struct sshQ_L_36Cont));
    $tmp->$class = &sshQ_L_36ContG_methods;
    sshQ_L_36ContG_methods.__init__($tmp, G_1, G_2);
    return $tmp;
}
struct sshQ_L_36ContG_class sshQ_L_36ContG_methods;
$R sshQ_L_34C_9cont (sshQ_RunCommand self, $Cont C_cont, B_NoneType C_10res) {
    #line 379 "src/ssh.act"
    ((sshQ_RunCommand)(self))->_error = to$str("timeout");
    return (($R (*) ($WORD, $Cont, sshQ_Channel))((sshQ_RunCommand)(self))->$class->_finishG_local)(self, (($Cont)sshQ_L_36ContG_new(self, C_cont)), ((sshQ_RunCommand)(self))->_channel);
}
B_NoneType sshQ_L_37ContD___init__ (sshQ_L_37Cont L_self, sshQ_RunCommand self, $Cont C_cont) {
    ((sshQ_L_37Cont)(L_self))->self = self;
    ((sshQ_L_37Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R sshQ_L_37ContD___call__ (sshQ_L_37Cont L_self, B_NoneType G_1) {
    sshQ_RunCommand self = ((sshQ_L_37Cont)(L_self))->self;
    $Cont C_cont = ((sshQ_L_37Cont)(L_self))->C_cont;
    return sshQ_L_34C_9cont(self, C_cont, G_1);
}
void sshQ_L_37ContD___serialize__ (sshQ_L_37Cont self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->C_cont, state);
}
sshQ_L_37Cont sshQ_L_37ContD___deserialize__ (sshQ_L_37Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_37Cont));
            self->$class = &sshQ_L_37ContG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_37Cont, state);
    }
    self->self = $step_deserialize(state);
    self->C_cont = $step_deserialize(state);
    return self;
}
sshQ_L_37Cont sshQ_L_37ContG_new(sshQ_RunCommand G_1, $Cont G_2) {
    sshQ_L_37Cont $tmp = acton_malloc(sizeof(struct sshQ_L_37Cont));
    $tmp->$class = &sshQ_L_37ContG_methods;
    sshQ_L_37ContG_methods.__init__($tmp, G_1, G_2);
    return $tmp;
}
struct sshQ_L_37ContG_class sshQ_L_37ContG_methods;
#line 376 "src/ssh.act"
$R sshQ_L_33_on_timeout (sshQ_RunCommand self, $Cont C_cont) {
    if (((B_bool)((sshQ_RunCommand)(self))->_done)->val) {
        return $R_CONT(C_cont, B_None);
    }
    else {
        return $R_CONT((($Cont)sshQ_L_37ContG_new(self, C_cont)), B_None);
    }
}
B_NoneType sshQ_L_38procD___init__ (sshQ_L_38proc L_self, sshQ_RunCommand self) {
    ((sshQ_L_38proc)(L_self))->self = self;
    return B_None;
}
$R sshQ_L_38procD___call__ (sshQ_L_38proc L_self, $Cont C_cont) {
    sshQ_RunCommand self = ((sshQ_L_38proc)(L_self))->self;
    return sshQ_L_33_on_timeout(self, C_cont);
}
$R sshQ_L_38procD___exec__ (sshQ_L_38proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((sshQ_L_38proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void sshQ_L_38procD___serialize__ (sshQ_L_38proc self, $Serial$state state) {
    $step_serialize(self->self, state);
}
sshQ_L_38proc sshQ_L_38procD___deserialize__ (sshQ_L_38proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_38proc));
            self->$class = &sshQ_L_38procG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_38proc, state);
    }
    self->self = $step_deserialize(state);
    return self;
}
sshQ_L_38proc sshQ_L_38procG_new(sshQ_RunCommand G_1) {
    sshQ_L_38proc $tmp = acton_malloc(sizeof(struct sshQ_L_38proc));
    $tmp->$class = &sshQ_L_38procG_methods;
    sshQ_L_38procG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct sshQ_L_38procG_class sshQ_L_38procG_methods;
$R sshQ_L_32C_7cont (sshQ_RunCommand self, $Cont C_cont, sshQ_Channel C_8res) {
    #line 373 "src/ssh.act"
    ((sshQ_RunCommand)(self))->_channel = C_8res;
    if ($ISNOTNONE0(((sshQ_RunCommand)(self))->timeout)) {
        #line 382 "src/ssh.act"
        $AFTER(((B_float)((sshQ_RunCommand)(self))->timeout), (($Cont)sshQ_L_38procG_new(self)));
        return $R_CONT(C_cont, B_None);
    }
    else {
        return $R_CONT(C_cont, B_None);
    }
}
B_NoneType sshQ_L_39ContD___init__ (sshQ_L_39Cont L_self, sshQ_RunCommand self, $Cont C_cont) {
    ((sshQ_L_39Cont)(L_self))->self = self;
    ((sshQ_L_39Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R sshQ_L_39ContD___call__ (sshQ_L_39Cont L_self, sshQ_Channel G_1) {
    sshQ_RunCommand self = ((sshQ_L_39Cont)(L_self))->self;
    $Cont C_cont = ((sshQ_L_39Cont)(L_self))->C_cont;
    return sshQ_L_32C_7cont(self, C_cont, G_1);
}
void sshQ_L_39ContD___serialize__ (sshQ_L_39Cont self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->C_cont, state);
}
sshQ_L_39Cont sshQ_L_39ContD___deserialize__ (sshQ_L_39Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_39Cont));
            self->$class = &sshQ_L_39ContG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_39Cont, state);
    }
    self->self = $step_deserialize(state);
    self->C_cont = $step_deserialize(state);
    return self;
}
sshQ_L_39Cont sshQ_L_39ContG_new(sshQ_RunCommand G_1, $Cont G_2) {
    sshQ_L_39Cont $tmp = acton_malloc(sizeof(struct sshQ_L_39Cont));
    $tmp->$class = &sshQ_L_39ContG_methods;
    sshQ_L_39ContG_methods.__init__($tmp, G_1, G_2);
    return $tmp;
}
struct sshQ_L_39ContG_class sshQ_L_39ContG_methods;
B_NoneType sshQ_L_41actionD___init__ (sshQ_L_41action L_self, sshQ_RunCommand L_40obj) {
    ((sshQ_L_41action)(L_self))->L_40obj = L_40obj;
    return B_None;
}
$R sshQ_L_41actionD___call__ (sshQ_L_41action L_self, $Cont L_cont, sshQ_Channel G_1, B_str G_2) {
    return $AWAIT(L_cont, ((B_Msg (*) ($WORD, sshQ_Channel, B_str))((sshQ_L_41action)(L_self))->$class->__asyn__)(L_self, G_1, G_2));
}
$R sshQ_L_41actionD___exec__ (sshQ_L_41action L_self, $Cont L_cont, sshQ_Channel G_1, B_str G_2) {
    return $R_CONT(L_cont, ((B_Msg (*) ($WORD, sshQ_Channel, B_str))((sshQ_L_41action)(L_self))->$class->__asyn__)(L_self, G_1, G_2));
}
B_Msg sshQ_L_41actionD___asyn__ (sshQ_L_41action L_self, sshQ_Channel G_1, B_str G_2) {
    sshQ_RunCommand L_40obj = ((sshQ_L_41action)(L_self))->L_40obj;
    return ((B_Msg (*) ($WORD, sshQ_Channel, B_str))((sshQ_RunCommand)(L_40obj))->$class->_on_open)(L_40obj, G_1, G_2);
}
void sshQ_L_41actionD___serialize__ (sshQ_L_41action self, $Serial$state state) {
    $step_serialize(self->L_40obj, state);
}
sshQ_L_41action sshQ_L_41actionD___deserialize__ (sshQ_L_41action self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_41action));
            self->$class = &sshQ_L_41actionG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_41action, state);
    }
    self->L_40obj = $step_deserialize(state);
    return self;
}
sshQ_L_41action sshQ_L_41actionG_new(sshQ_RunCommand G_1) {
    sshQ_L_41action $tmp = acton_malloc(sizeof(struct sshQ_L_41action));
    $tmp->$class = &sshQ_L_41actionG_methods;
    sshQ_L_41actionG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct sshQ_L_41actionG_class sshQ_L_41actionG_methods;
B_NoneType sshQ_L_43actionD___init__ (sshQ_L_43action L_self, sshQ_RunCommand L_42obj) {
    ((sshQ_L_43action)(L_self))->L_42obj = L_42obj;
    return B_None;
}
$R sshQ_L_43actionD___call__ (sshQ_L_43action L_self, $Cont L_cont, sshQ_Channel G_1, B_bytes G_2) {
    return $AWAIT(L_cont, ((B_Msg (*) ($WORD, sshQ_Channel, B_bytes))((sshQ_L_43action)(L_self))->$class->__asyn__)(L_self, G_1, G_2));
}
$R sshQ_L_43actionD___exec__ (sshQ_L_43action L_self, $Cont L_cont, sshQ_Channel G_1, B_bytes G_2) {
    return $R_CONT(L_cont, ((B_Msg (*) ($WORD, sshQ_Channel, B_bytes))((sshQ_L_43action)(L_self))->$class->__asyn__)(L_self, G_1, G_2));
}
B_Msg sshQ_L_43actionD___asyn__ (sshQ_L_43action L_self, sshQ_Channel G_1, B_bytes G_2) {
    sshQ_RunCommand L_42obj = ((sshQ_L_43action)(L_self))->L_42obj;
    return ((B_Msg (*) ($WORD, sshQ_Channel, B_bytes))((sshQ_RunCommand)(L_42obj))->$class->_on_stdout)(L_42obj, G_1, G_2);
}
void sshQ_L_43actionD___serialize__ (sshQ_L_43action self, $Serial$state state) {
    $step_serialize(self->L_42obj, state);
}
sshQ_L_43action sshQ_L_43actionD___deserialize__ (sshQ_L_43action self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_43action));
            self->$class = &sshQ_L_43actionG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_43action, state);
    }
    self->L_42obj = $step_deserialize(state);
    return self;
}
sshQ_L_43action sshQ_L_43actionG_new(sshQ_RunCommand G_1) {
    sshQ_L_43action $tmp = acton_malloc(sizeof(struct sshQ_L_43action));
    $tmp->$class = &sshQ_L_43actionG_methods;
    sshQ_L_43actionG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct sshQ_L_43actionG_class sshQ_L_43actionG_methods;
B_NoneType sshQ_L_45actionD___init__ (sshQ_L_45action L_self, sshQ_RunCommand L_44obj) {
    ((sshQ_L_45action)(L_self))->L_44obj = L_44obj;
    return B_None;
}
$R sshQ_L_45actionD___call__ (sshQ_L_45action L_self, $Cont L_cont, sshQ_Channel G_1, B_bytes G_2) {
    return $AWAIT(L_cont, ((B_Msg (*) ($WORD, sshQ_Channel, B_bytes))((sshQ_L_45action)(L_self))->$class->__asyn__)(L_self, G_1, G_2));
}
$R sshQ_L_45actionD___exec__ (sshQ_L_45action L_self, $Cont L_cont, sshQ_Channel G_1, B_bytes G_2) {
    return $R_CONT(L_cont, ((B_Msg (*) ($WORD, sshQ_Channel, B_bytes))((sshQ_L_45action)(L_self))->$class->__asyn__)(L_self, G_1, G_2));
}
B_Msg sshQ_L_45actionD___asyn__ (sshQ_L_45action L_self, sshQ_Channel G_1, B_bytes G_2) {
    sshQ_RunCommand L_44obj = ((sshQ_L_45action)(L_self))->L_44obj;
    return ((B_Msg (*) ($WORD, sshQ_Channel, B_bytes))((sshQ_RunCommand)(L_44obj))->$class->_on_stderr)(L_44obj, G_1, G_2);
}
void sshQ_L_45actionD___serialize__ (sshQ_L_45action self, $Serial$state state) {
    $step_serialize(self->L_44obj, state);
}
sshQ_L_45action sshQ_L_45actionD___deserialize__ (sshQ_L_45action self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_45action));
            self->$class = &sshQ_L_45actionG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_45action, state);
    }
    self->L_44obj = $step_deserialize(state);
    return self;
}
sshQ_L_45action sshQ_L_45actionG_new(sshQ_RunCommand G_1) {
    sshQ_L_45action $tmp = acton_malloc(sizeof(struct sshQ_L_45action));
    $tmp->$class = &sshQ_L_45actionG_methods;
    sshQ_L_45actionG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct sshQ_L_45actionG_class sshQ_L_45actionG_methods;
B_NoneType sshQ_L_47actionD___init__ (sshQ_L_47action L_self, sshQ_RunCommand L_46obj) {
    ((sshQ_L_47action)(L_self))->L_46obj = L_46obj;
    return B_None;
}
$R sshQ_L_47actionD___call__ (sshQ_L_47action L_self, $Cont L_cont, sshQ_Channel G_1, B_int G_2, B_str G_3) {
    return $AWAIT(L_cont, ((B_Msg (*) ($WORD, sshQ_Channel, B_int, B_str))((sshQ_L_47action)(L_self))->$class->__asyn__)(L_self, G_1, G_2, G_3));
}
$R sshQ_L_47actionD___exec__ (sshQ_L_47action L_self, $Cont L_cont, sshQ_Channel G_1, B_int G_2, B_str G_3) {
    return $R_CONT(L_cont, ((B_Msg (*) ($WORD, sshQ_Channel, B_int, B_str))((sshQ_L_47action)(L_self))->$class->__asyn__)(L_self, G_1, G_2, G_3));
}
B_Msg sshQ_L_47actionD___asyn__ (sshQ_L_47action L_self, sshQ_Channel G_1, B_int G_2, B_str G_3) {
    sshQ_RunCommand L_46obj = ((sshQ_L_47action)(L_self))->L_46obj;
    return ((B_Msg (*) ($WORD, sshQ_Channel, int64_t, B_str))((sshQ_RunCommand)(L_46obj))->$class->_on_exit)(L_46obj, G_1, ((B_int)G_2)->val, G_3);
}
void sshQ_L_47actionD___serialize__ (sshQ_L_47action self, $Serial$state state) {
    $step_serialize(self->L_46obj, state);
}
sshQ_L_47action sshQ_L_47actionD___deserialize__ (sshQ_L_47action self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_47action));
            self->$class = &sshQ_L_47actionG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_47action, state);
    }
    self->L_46obj = $step_deserialize(state);
    return self;
}
sshQ_L_47action sshQ_L_47actionG_new(sshQ_RunCommand G_1) {
    sshQ_L_47action $tmp = acton_malloc(sizeof(struct sshQ_L_47action));
    $tmp->$class = &sshQ_L_47actionG_methods;
    sshQ_L_47actionG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct sshQ_L_47actionG_class sshQ_L_47actionG_methods;
B_NoneType sshQ_L_49actionD___init__ (sshQ_L_49action L_self, sshQ_RunCommand L_48obj) {
    ((sshQ_L_49action)(L_self))->L_48obj = L_48obj;
    return B_None;
}
$R sshQ_L_49actionD___call__ (sshQ_L_49action L_self, $Cont L_cont, sshQ_Channel G_1, B_str G_2) {
    return $AWAIT(L_cont, ((B_Msg (*) ($WORD, sshQ_Channel, B_str))((sshQ_L_49action)(L_self))->$class->__asyn__)(L_self, G_1, G_2));
}
$R sshQ_L_49actionD___exec__ (sshQ_L_49action L_self, $Cont L_cont, sshQ_Channel G_1, B_str G_2) {
    return $R_CONT(L_cont, ((B_Msg (*) ($WORD, sshQ_Channel, B_str))((sshQ_L_49action)(L_self))->$class->__asyn__)(L_self, G_1, G_2));
}
B_Msg sshQ_L_49actionD___asyn__ (sshQ_L_49action L_self, sshQ_Channel G_1, B_str G_2) {
    sshQ_RunCommand L_48obj = ((sshQ_L_49action)(L_self))->L_48obj;
    return ((B_Msg (*) ($WORD, sshQ_Channel, B_str))((sshQ_RunCommand)(L_48obj))->$class->_on_close)(L_48obj, G_1, G_2);
}
void sshQ_L_49actionD___serialize__ (sshQ_L_49action self, $Serial$state state) {
    $step_serialize(self->L_48obj, state);
}
sshQ_L_49action sshQ_L_49actionD___deserialize__ (sshQ_L_49action self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_49action));
            self->$class = &sshQ_L_49actionG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_49action, state);
    }
    self->L_48obj = $step_deserialize(state);
    return self;
}
sshQ_L_49action sshQ_L_49actionG_new(sshQ_RunCommand G_1) {
    sshQ_L_49action $tmp = acton_malloc(sizeof(struct sshQ_L_49action));
    $tmp->$class = &sshQ_L_49actionG_methods;
    sshQ_L_49actionG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct sshQ_L_49actionG_class sshQ_L_49actionG_methods;
$R sshQ_L_50C_13cont (sshQ_RunCommand self, sshQ_Channel ch, $Cont C_cont, B_NoneType C_14res) {
    #line 324 "src/ssh.act"
    ((sshQ_RunCommand)(self))->_done = B_True;
    #line 325 "src/ssh.act"
    ((B_Msg (*) ($WORD, sshQ_Channel, B_int, B_str, B_bytes, B_bytes, B_str))(($action)(((sshQ_RunCommand)(self))->on_exit))->$class->__asyn__)(((sshQ_RunCommand)(self))->on_exit, ch, toB_int(((int64_t)((sshQ_RunCommand)(self))->_exit_code)), ((sshQ_RunCommand)(self))->_exit_signal, ((sshQ_RunCommand)(self))->out_buf, ((sshQ_RunCommand)(self))->err_buf, ((sshQ_RunCommand)(self))->_error);
    return $R_CONT(C_cont, B_None);
}
B_NoneType sshQ_L_51ContD___init__ (sshQ_L_51Cont L_self, sshQ_RunCommand self, sshQ_Channel ch, $Cont C_cont) {
    ((sshQ_L_51Cont)(L_self))->self = self;
    ((sshQ_L_51Cont)(L_self))->ch = ch;
    ((sshQ_L_51Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R sshQ_L_51ContD___call__ (sshQ_L_51Cont L_self, B_NoneType G_1) {
    sshQ_RunCommand self = ((sshQ_L_51Cont)(L_self))->self;
    sshQ_Channel ch = ((sshQ_L_51Cont)(L_self))->ch;
    $Cont C_cont = ((sshQ_L_51Cont)(L_self))->C_cont;
    return sshQ_L_50C_13cont(self, ch, C_cont, G_1);
}
void sshQ_L_51ContD___serialize__ (sshQ_L_51Cont self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->ch, state);
    $step_serialize(self->C_cont, state);
}
sshQ_L_51Cont sshQ_L_51ContD___deserialize__ (sshQ_L_51Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_51Cont));
            self->$class = &sshQ_L_51ContG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_51Cont, state);
    }
    self->self = $step_deserialize(state);
    self->ch = $step_deserialize(state);
    self->C_cont = $step_deserialize(state);
    return self;
}
sshQ_L_51Cont sshQ_L_51ContG_new(sshQ_RunCommand G_1, sshQ_Channel G_2, $Cont G_3) {
    sshQ_L_51Cont $tmp = acton_malloc(sizeof(struct sshQ_L_51Cont));
    $tmp->$class = &sshQ_L_51ContG_methods;
    sshQ_L_51ContG_methods.__init__($tmp, G_1, G_2, G_3);
    return $tmp;
}
struct sshQ_L_51ContG_class sshQ_L_51ContG_methods;
$R sshQ_L_53C_17cont (sshQ_Channel ch, sshQ_RunCommand self, $Cont C_cont, B_NoneType C_18res) {
    #line 334 "src/ssh.act"
    ((B_Msg (*) ($WORD, B_str))((sshQ_Channel)(ch))->$class->request_exec)(ch, ((sshQ_RunCommand)(self))->cmd);
    return $R_CONT(C_cont, B_None);
}
$R sshQ_L_54C_19cont ($Cont C_cont, B_NoneType C_20res) {
    return $R_CONT(C_cont, B_None);
}
B_NoneType sshQ_L_55ContD___init__ (sshQ_L_55Cont L_self, $Cont C_cont) {
    ((sshQ_L_55Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R sshQ_L_55ContD___call__ (sshQ_L_55Cont L_self, B_NoneType G_1) {
    $Cont C_cont = ((sshQ_L_55Cont)(L_self))->C_cont;
    return sshQ_L_54C_19cont(C_cont, G_1);
}
void sshQ_L_55ContD___serialize__ (sshQ_L_55Cont self, $Serial$state state) {
    $step_serialize(self->C_cont, state);
}
sshQ_L_55Cont sshQ_L_55ContD___deserialize__ (sshQ_L_55Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_55Cont));
            self->$class = &sshQ_L_55ContG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_55Cont, state);
    }
    self->C_cont = $step_deserialize(state);
    return self;
}
sshQ_L_55Cont sshQ_L_55ContG_new($Cont G_1) {
    sshQ_L_55Cont $tmp = acton_malloc(sizeof(struct sshQ_L_55Cont));
    $tmp->$class = &sshQ_L_55ContG_methods;
    sshQ_L_55ContG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct sshQ_L_55ContG_class sshQ_L_55ContG_methods;
B_NoneType sshQ_L_56ContD___init__ (sshQ_L_56Cont L_self, sshQ_Channel ch, sshQ_RunCommand self, $Cont C_cont) {
    ((sshQ_L_56Cont)(L_self))->ch = ch;
    ((sshQ_L_56Cont)(L_self))->self = self;
    ((sshQ_L_56Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R sshQ_L_56ContD___call__ (sshQ_L_56Cont L_self, B_NoneType G_1) {
    sshQ_Channel ch = ((sshQ_L_56Cont)(L_self))->ch;
    sshQ_RunCommand self = ((sshQ_L_56Cont)(L_self))->self;
    $Cont C_cont = ((sshQ_L_56Cont)(L_self))->C_cont;
    return sshQ_L_53C_17cont(ch, self, C_cont, G_1);
}
void sshQ_L_56ContD___serialize__ (sshQ_L_56Cont self, $Serial$state state) {
    $step_serialize(self->ch, state);
    $step_serialize(self->self, state);
    $step_serialize(self->C_cont, state);
}
sshQ_L_56Cont sshQ_L_56ContD___deserialize__ (sshQ_L_56Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_56Cont));
            self->$class = &sshQ_L_56ContG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_56Cont, state);
    }
    self->ch = $step_deserialize(state);
    self->self = $step_deserialize(state);
    self->C_cont = $step_deserialize(state);
    return self;
}
sshQ_L_56Cont sshQ_L_56ContG_new(sshQ_Channel G_1, sshQ_RunCommand G_2, $Cont G_3) {
    sshQ_L_56Cont $tmp = acton_malloc(sizeof(struct sshQ_L_56Cont));
    $tmp->$class = &sshQ_L_56ContG_methods;
    sshQ_L_56ContG_methods.__init__($tmp, G_1, G_2, G_3);
    return $tmp;
}
struct sshQ_L_56ContG_class sshQ_L_56ContG_methods;
$R sshQ_L_52C_15cont (sshQ_Channel ch, sshQ_RunCommand self, $Cont C_cont, B_str err, B_NoneType C_16res) {
    if ($ISNOTNONE0(err)) {
        #line 331 "src/ssh.act"
        ((sshQ_RunCommand)(self))->_error = ((B_str)err);
        return (($R (*) ($WORD, $Cont, sshQ_Channel))((sshQ_RunCommand)(self))->$class->_finishG_local)(self, (($Cont)sshQ_L_55ContG_new(C_cont)), ch);
    }
    else {
        return $R_CONT((($Cont)sshQ_L_56ContG_new(ch, self, C_cont)), B_None);
    }
}
B_NoneType sshQ_L_57ContD___init__ (sshQ_L_57Cont L_self, sshQ_Channel ch, sshQ_RunCommand self, $Cont C_cont, B_str err) {
    ((sshQ_L_57Cont)(L_self))->ch = ch;
    ((sshQ_L_57Cont)(L_self))->self = self;
    ((sshQ_L_57Cont)(L_self))->C_cont = C_cont;
    ((sshQ_L_57Cont)(L_self))->err = err;
    return B_None;
}
$R sshQ_L_57ContD___call__ (sshQ_L_57Cont L_self, B_NoneType G_1) {
    sshQ_Channel ch = ((sshQ_L_57Cont)(L_self))->ch;
    sshQ_RunCommand self = ((sshQ_L_57Cont)(L_self))->self;
    $Cont C_cont = ((sshQ_L_57Cont)(L_self))->C_cont;
    B_str err = ((sshQ_L_57Cont)(L_self))->err;
    return sshQ_L_52C_15cont(ch, self, C_cont, err, G_1);
}
void sshQ_L_57ContD___serialize__ (sshQ_L_57Cont self, $Serial$state state) {
    $step_serialize(self->ch, state);
    $step_serialize(self->self, state);
    $step_serialize(self->C_cont, state);
    $step_serialize(self->err, state);
}
sshQ_L_57Cont sshQ_L_57ContD___deserialize__ (sshQ_L_57Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_57Cont));
            self->$class = &sshQ_L_57ContG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_57Cont, state);
    }
    self->ch = $step_deserialize(state);
    self->self = $step_deserialize(state);
    self->C_cont = $step_deserialize(state);
    self->err = $step_deserialize(state);
    return self;
}
sshQ_L_57Cont sshQ_L_57ContG_new(sshQ_Channel G_1, sshQ_RunCommand G_2, $Cont G_3, B_str G_4) {
    sshQ_L_57Cont $tmp = acton_malloc(sizeof(struct sshQ_L_57Cont));
    $tmp->$class = &sshQ_L_57ContG_methods;
    sshQ_L_57ContG_methods.__init__($tmp, G_1, G_2, G_3, G_4);
    return $tmp;
}
struct sshQ_L_57ContG_class sshQ_L_57ContG_methods;
$R sshQ_L_59C_23cont ($Cont C_cont, B_NoneType C_24res) {
    return $R_CONT(C_cont, B_None);
}
B_NoneType sshQ_L_60ContD___init__ (sshQ_L_60Cont L_self, $Cont C_cont) {
    ((sshQ_L_60Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R sshQ_L_60ContD___call__ (sshQ_L_60Cont L_self, B_NoneType G_1) {
    $Cont C_cont = ((sshQ_L_60Cont)(L_self))->C_cont;
    return sshQ_L_59C_23cont(C_cont, G_1);
}
void sshQ_L_60ContD___serialize__ (sshQ_L_60Cont self, $Serial$state state) {
    $step_serialize(self->C_cont, state);
}
sshQ_L_60Cont sshQ_L_60ContD___deserialize__ (sshQ_L_60Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_60Cont));
            self->$class = &sshQ_L_60ContG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_60Cont, state);
    }
    self->C_cont = $step_deserialize(state);
    return self;
}
sshQ_L_60Cont sshQ_L_60ContG_new($Cont G_1) {
    sshQ_L_60Cont $tmp = acton_malloc(sizeof(struct sshQ_L_60Cont));
    $tmp->$class = &sshQ_L_60ContG_methods;
    sshQ_L_60ContG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct sshQ_L_60ContG_class sshQ_L_60ContG_methods;
B_NoneType sshQ_L_61ContD___init__ (sshQ_L_61Cont L_self, $Cont C_cont) {
    ((sshQ_L_61Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R sshQ_L_61ContD___call__ (sshQ_L_61Cont L_self, B_NoneType G_1) {
    $Cont C_cont = ((sshQ_L_61Cont)(L_self))->C_cont;
    return sshQ_L_59C_23cont(C_cont, G_1);
}
void sshQ_L_61ContD___serialize__ (sshQ_L_61Cont self, $Serial$state state) {
    $step_serialize(self->C_cont, state);
}
sshQ_L_61Cont sshQ_L_61ContD___deserialize__ (sshQ_L_61Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_61Cont));
            self->$class = &sshQ_L_61ContG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_61Cont, state);
    }
    self->C_cont = $step_deserialize(state);
    return self;
}
sshQ_L_61Cont sshQ_L_61ContG_new($Cont G_1) {
    sshQ_L_61Cont $tmp = acton_malloc(sizeof(struct sshQ_L_61Cont));
    $tmp->$class = &sshQ_L_61ContG_methods;
    sshQ_L_61ContG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct sshQ_L_61ContG_class sshQ_L_61ContG_methods;
$R sshQ_L_58C_21cont ($Cont C_cont, B_bytes data, sshQ_RunCommand self, sshQ_Channel ch, B_NoneType C_22res) {
    if ($ISNOTNONE0(data)) {
        ((sshQ_RunCommand)(self))->out_buf = ((B_bytes (*) ($WORD, B_bytes, B_bytes))((B_Plus)(sshQ_W_HostKeyInfo_924))->$class->__iadd__)(sshQ_W_HostKeyInfo_924, ((sshQ_RunCommand)(self))->out_buf, ((B_bytes)data));
        return $R_CONT((($Cont)sshQ_L_60ContG_new(C_cont)), B_None);
    }
    else {
        #line 342 "src/ssh.act"
        ((sshQ_RunCommand)(self))->_out_done = B_True;
        return (($R (*) ($WORD, $Cont, sshQ_Channel))((sshQ_RunCommand)(self))->$class->_check_doneG_local)(self, (($Cont)sshQ_L_61ContG_new(C_cont)), ch);
    }
}
B_NoneType sshQ_L_62ContD___init__ (sshQ_L_62Cont L_self, $Cont C_cont, B_bytes data, sshQ_RunCommand self, sshQ_Channel ch) {
    ((sshQ_L_62Cont)(L_self))->C_cont = C_cont;
    ((sshQ_L_62Cont)(L_self))->data = data;
    ((sshQ_L_62Cont)(L_self))->self = self;
    ((sshQ_L_62Cont)(L_self))->ch = ch;
    return B_None;
}
$R sshQ_L_62ContD___call__ (sshQ_L_62Cont L_self, B_NoneType G_1) {
    $Cont C_cont = ((sshQ_L_62Cont)(L_self))->C_cont;
    B_bytes data = ((sshQ_L_62Cont)(L_self))->data;
    sshQ_RunCommand self = ((sshQ_L_62Cont)(L_self))->self;
    sshQ_Channel ch = ((sshQ_L_62Cont)(L_self))->ch;
    return sshQ_L_58C_21cont(C_cont, data, self, ch, G_1);
}
void sshQ_L_62ContD___serialize__ (sshQ_L_62Cont self, $Serial$state state) {
    $step_serialize(self->C_cont, state);
    $step_serialize(self->data, state);
    $step_serialize(self->self, state);
    $step_serialize(self->ch, state);
}
sshQ_L_62Cont sshQ_L_62ContD___deserialize__ (sshQ_L_62Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_62Cont));
            self->$class = &sshQ_L_62ContG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_62Cont, state);
    }
    self->C_cont = $step_deserialize(state);
    self->data = $step_deserialize(state);
    self->self = $step_deserialize(state);
    self->ch = $step_deserialize(state);
    return self;
}
sshQ_L_62Cont sshQ_L_62ContG_new($Cont G_1, B_bytes G_2, sshQ_RunCommand G_3, sshQ_Channel G_4) {
    sshQ_L_62Cont $tmp = acton_malloc(sizeof(struct sshQ_L_62Cont));
    $tmp->$class = &sshQ_L_62ContG_methods;
    sshQ_L_62ContG_methods.__init__($tmp, G_1, G_2, G_3, G_4);
    return $tmp;
}
struct sshQ_L_62ContG_class sshQ_L_62ContG_methods;
$R sshQ_L_64C_27cont ($Cont C_cont, B_NoneType C_28res) {
    return $R_CONT(C_cont, B_None);
}
B_NoneType sshQ_L_65ContD___init__ (sshQ_L_65Cont L_self, $Cont C_cont) {
    ((sshQ_L_65Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R sshQ_L_65ContD___call__ (sshQ_L_65Cont L_self, B_NoneType G_1) {
    $Cont C_cont = ((sshQ_L_65Cont)(L_self))->C_cont;
    return sshQ_L_64C_27cont(C_cont, G_1);
}
void sshQ_L_65ContD___serialize__ (sshQ_L_65Cont self, $Serial$state state) {
    $step_serialize(self->C_cont, state);
}
sshQ_L_65Cont sshQ_L_65ContD___deserialize__ (sshQ_L_65Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_65Cont));
            self->$class = &sshQ_L_65ContG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_65Cont, state);
    }
    self->C_cont = $step_deserialize(state);
    return self;
}
sshQ_L_65Cont sshQ_L_65ContG_new($Cont G_1) {
    sshQ_L_65Cont $tmp = acton_malloc(sizeof(struct sshQ_L_65Cont));
    $tmp->$class = &sshQ_L_65ContG_methods;
    sshQ_L_65ContG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct sshQ_L_65ContG_class sshQ_L_65ContG_methods;
B_NoneType sshQ_L_66ContD___init__ (sshQ_L_66Cont L_self, $Cont C_cont) {
    ((sshQ_L_66Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R sshQ_L_66ContD___call__ (sshQ_L_66Cont L_self, B_NoneType G_1) {
    $Cont C_cont = ((sshQ_L_66Cont)(L_self))->C_cont;
    return sshQ_L_64C_27cont(C_cont, G_1);
}
void sshQ_L_66ContD___serialize__ (sshQ_L_66Cont self, $Serial$state state) {
    $step_serialize(self->C_cont, state);
}
sshQ_L_66Cont sshQ_L_66ContD___deserialize__ (sshQ_L_66Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_66Cont));
            self->$class = &sshQ_L_66ContG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_66Cont, state);
    }
    self->C_cont = $step_deserialize(state);
    return self;
}
sshQ_L_66Cont sshQ_L_66ContG_new($Cont G_1) {
    sshQ_L_66Cont $tmp = acton_malloc(sizeof(struct sshQ_L_66Cont));
    $tmp->$class = &sshQ_L_66ContG_methods;
    sshQ_L_66ContG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct sshQ_L_66ContG_class sshQ_L_66ContG_methods;
$R sshQ_L_63C_25cont ($Cont C_cont, B_bytes data, sshQ_RunCommand self, sshQ_Channel ch, B_NoneType C_26res) {
    if ($ISNOTNONE0(data)) {
        ((sshQ_RunCommand)(self))->err_buf = ((B_bytes (*) ($WORD, B_bytes, B_bytes))((B_Plus)(sshQ_W_HostKeyInfo_924))->$class->__iadd__)(sshQ_W_HostKeyInfo_924, ((sshQ_RunCommand)(self))->err_buf, ((B_bytes)data));
        return $R_CONT((($Cont)sshQ_L_65ContG_new(C_cont)), B_None);
    }
    else {
        #line 351 "src/ssh.act"
        ((sshQ_RunCommand)(self))->_err_done = B_True;
        return (($R (*) ($WORD, $Cont, sshQ_Channel))((sshQ_RunCommand)(self))->$class->_check_doneG_local)(self, (($Cont)sshQ_L_66ContG_new(C_cont)), ch);
    }
}
B_NoneType sshQ_L_67ContD___init__ (sshQ_L_67Cont L_self, $Cont C_cont, B_bytes data, sshQ_RunCommand self, sshQ_Channel ch) {
    ((sshQ_L_67Cont)(L_self))->C_cont = C_cont;
    ((sshQ_L_67Cont)(L_self))->data = data;
    ((sshQ_L_67Cont)(L_self))->self = self;
    ((sshQ_L_67Cont)(L_self))->ch = ch;
    return B_None;
}
$R sshQ_L_67ContD___call__ (sshQ_L_67Cont L_self, B_NoneType G_1) {
    $Cont C_cont = ((sshQ_L_67Cont)(L_self))->C_cont;
    B_bytes data = ((sshQ_L_67Cont)(L_self))->data;
    sshQ_RunCommand self = ((sshQ_L_67Cont)(L_self))->self;
    sshQ_Channel ch = ((sshQ_L_67Cont)(L_self))->ch;
    return sshQ_L_63C_25cont(C_cont, data, self, ch, G_1);
}
void sshQ_L_67ContD___serialize__ (sshQ_L_67Cont self, $Serial$state state) {
    $step_serialize(self->C_cont, state);
    $step_serialize(self->data, state);
    $step_serialize(self->self, state);
    $step_serialize(self->ch, state);
}
sshQ_L_67Cont sshQ_L_67ContD___deserialize__ (sshQ_L_67Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_67Cont));
            self->$class = &sshQ_L_67ContG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_67Cont, state);
    }
    self->C_cont = $step_deserialize(state);
    self->data = $step_deserialize(state);
    self->self = $step_deserialize(state);
    self->ch = $step_deserialize(state);
    return self;
}
sshQ_L_67Cont sshQ_L_67ContG_new($Cont G_1, B_bytes G_2, sshQ_RunCommand G_3, sshQ_Channel G_4) {
    sshQ_L_67Cont $tmp = acton_malloc(sizeof(struct sshQ_L_67Cont));
    $tmp->$class = &sshQ_L_67ContG_methods;
    sshQ_L_67ContG_methods.__init__($tmp, G_1, G_2, G_3, G_4);
    return $tmp;
}
struct sshQ_L_67ContG_class sshQ_L_67ContG_methods;
$R sshQ_L_69C_31cont ($Cont C_cont, B_NoneType C_32res) {
    return $R_CONT(C_cont, B_None);
}
B_NoneType sshQ_L_70ContD___init__ (sshQ_L_70Cont L_self, $Cont C_cont) {
    ((sshQ_L_70Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R sshQ_L_70ContD___call__ (sshQ_L_70Cont L_self, B_NoneType G_1) {
    $Cont C_cont = ((sshQ_L_70Cont)(L_self))->C_cont;
    return sshQ_L_69C_31cont(C_cont, G_1);
}
void sshQ_L_70ContD___serialize__ (sshQ_L_70Cont self, $Serial$state state) {
    $step_serialize(self->C_cont, state);
}
sshQ_L_70Cont sshQ_L_70ContD___deserialize__ (sshQ_L_70Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_70Cont));
            self->$class = &sshQ_L_70ContG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_70Cont, state);
    }
    self->C_cont = $step_deserialize(state);
    return self;
}
sshQ_L_70Cont sshQ_L_70ContG_new($Cont G_1) {
    sshQ_L_70Cont $tmp = acton_malloc(sizeof(struct sshQ_L_70Cont));
    $tmp->$class = &sshQ_L_70ContG_methods;
    sshQ_L_70ContG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct sshQ_L_70ContG_class sshQ_L_70ContG_methods;
$R sshQ_L_68C_29cont (sshQ_RunCommand self, int64_t code, B_str sig, $Cont C_cont, sshQ_Channel ch, B_NoneType C_30res) {
    #line 357 "src/ssh.act"
    ((sshQ_RunCommand)(self))->_exited = B_True;
    #line 358 "src/ssh.act"
    ((sshQ_RunCommand)(self))->_exit_code = code;
    #line 359 "src/ssh.act"
    ((sshQ_RunCommand)(self))->_exit_signal = sig;
    return (($R (*) ($WORD, $Cont, sshQ_Channel))((sshQ_RunCommand)(self))->$class->_check_doneG_local)(self, (($Cont)sshQ_L_70ContG_new(C_cont)), ch);
}
B_NoneType sshQ_L_71ContD___init__ (sshQ_L_71Cont L_self, sshQ_RunCommand self, int64_t code, B_str sig, $Cont C_cont, sshQ_Channel ch) {
    ((sshQ_L_71Cont)(L_self))->self = self;
    ((sshQ_L_71Cont)(L_self))->code = code;
    ((sshQ_L_71Cont)(L_self))->sig = sig;
    ((sshQ_L_71Cont)(L_self))->C_cont = C_cont;
    ((sshQ_L_71Cont)(L_self))->ch = ch;
    return B_None;
}
$R sshQ_L_71ContD___call__ (sshQ_L_71Cont L_self, B_NoneType G_1) {
    sshQ_RunCommand self = ((sshQ_L_71Cont)(L_self))->self;
    int64_t code = ((int64_t)((sshQ_L_71Cont)(L_self))->code);
    B_str sig = ((sshQ_L_71Cont)(L_self))->sig;
    $Cont C_cont = ((sshQ_L_71Cont)(L_self))->C_cont;
    sshQ_Channel ch = ((sshQ_L_71Cont)(L_self))->ch;
    return sshQ_L_68C_29cont(self, code, sig, C_cont, ch, G_1);
}
void sshQ_L_71ContD___serialize__ (sshQ_L_71Cont self, $Serial$state state) {
    $step_serialize(self->self, state);
    $val_serialize(I64_ID, &self->code, state);
    $step_serialize(self->sig, state);
    $step_serialize(self->C_cont, state);
    $step_serialize(self->ch, state);
}
sshQ_L_71Cont sshQ_L_71ContD___deserialize__ (sshQ_L_71Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_71Cont));
            self->$class = &sshQ_L_71ContG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_71Cont, state);
    }
    self->self = $step_deserialize(state);
    $tmp = $val_deserialize(state);
    memcpy(&self->code, &$tmp, sizeof(self->code));
    self->sig = $step_deserialize(state);
    self->C_cont = $step_deserialize(state);
    self->ch = $step_deserialize(state);
    return self;
}
sshQ_L_71Cont sshQ_L_71ContG_new(sshQ_RunCommand G_1, int64_t G_2, B_str G_3, $Cont G_4, sshQ_Channel G_5) {
    sshQ_L_71Cont $tmp = acton_malloc(sizeof(struct sshQ_L_71Cont));
    $tmp->$class = &sshQ_L_71ContG_methods;
    sshQ_L_71ContG_methods.__init__($tmp, G_1, G_2, G_3, G_4, G_5);
    return $tmp;
}
struct sshQ_L_71ContG_class sshQ_L_71ContG_methods;
$R sshQ_L_73C_35cont ($Cont C_cont, B_NoneType C_36res) {
    return $R_CONT(C_cont, B_None);
}
B_NoneType sshQ_L_74ContD___init__ (sshQ_L_74Cont L_self, $Cont C_cont) {
    ((sshQ_L_74Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R sshQ_L_74ContD___call__ (sshQ_L_74Cont L_self, B_NoneType G_1) {
    $Cont C_cont = ((sshQ_L_74Cont)(L_self))->C_cont;
    return sshQ_L_73C_35cont(C_cont, G_1);
}
void sshQ_L_74ContD___serialize__ (sshQ_L_74Cont self, $Serial$state state) {
    $step_serialize(self->C_cont, state);
}
sshQ_L_74Cont sshQ_L_74ContD___deserialize__ (sshQ_L_74Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_74Cont));
            self->$class = &sshQ_L_74ContG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_74Cont, state);
    }
    self->C_cont = $step_deserialize(state);
    return self;
}
sshQ_L_74Cont sshQ_L_74ContG_new($Cont G_1) {
    sshQ_L_74Cont $tmp = acton_malloc(sizeof(struct sshQ_L_74Cont));
    $tmp->$class = &sshQ_L_74ContG_methods;
    sshQ_L_74ContG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct sshQ_L_74ContG_class sshQ_L_74ContG_methods;
$R sshQ_L_72C_33cont (sshQ_RunCommand self, B_Eq W_HostKeyInfo_980, B_str reason, $Cont C_cont, sshQ_Channel ch, B_NoneType C_34res) {
    #line 365 "src/ssh.act"
    if (((B_bool)$AND(B_bool, toB_bool($ISNONE0(((sshQ_RunCommand)(self))->_error)), ((B_bool (*) ($WORD, B_str, B_str))((B_Eq)(W_HostKeyInfo_980))->$class->__ne__)(W_HostKeyInfo_980, reason, to$str("closed"))))->val) {
        #line 366 "src/ssh.act"
        ((sshQ_RunCommand)(self))->_error = reason;
    }
    return (($R (*) ($WORD, $Cont, sshQ_Channel))((sshQ_RunCommand)(self))->$class->_finishG_local)(self, (($Cont)sshQ_L_74ContG_new(C_cont)), ch);
}
B_NoneType sshQ_L_75ContD___init__ (sshQ_L_75Cont L_self, sshQ_RunCommand self, B_Eq W_HostKeyInfo_980, B_str reason, $Cont C_cont, sshQ_Channel ch) {
    ((sshQ_L_75Cont)(L_self))->self = self;
    ((sshQ_L_75Cont)(L_self))->W_HostKeyInfo_980 = W_HostKeyInfo_980;
    ((sshQ_L_75Cont)(L_self))->reason = reason;
    ((sshQ_L_75Cont)(L_self))->C_cont = C_cont;
    ((sshQ_L_75Cont)(L_self))->ch = ch;
    return B_None;
}
$R sshQ_L_75ContD___call__ (sshQ_L_75Cont L_self, B_NoneType G_1) {
    sshQ_RunCommand self = ((sshQ_L_75Cont)(L_self))->self;
    B_Eq W_HostKeyInfo_980 = ((sshQ_L_75Cont)(L_self))->W_HostKeyInfo_980;
    B_str reason = ((sshQ_L_75Cont)(L_self))->reason;
    $Cont C_cont = ((sshQ_L_75Cont)(L_self))->C_cont;
    sshQ_Channel ch = ((sshQ_L_75Cont)(L_self))->ch;
    return sshQ_L_72C_33cont(self, W_HostKeyInfo_980, reason, C_cont, ch, G_1);
}
void sshQ_L_75ContD___serialize__ (sshQ_L_75Cont self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->W_HostKeyInfo_980, state);
    $step_serialize(self->reason, state);
    $step_serialize(self->C_cont, state);
    $step_serialize(self->ch, state);
}
sshQ_L_75Cont sshQ_L_75ContD___deserialize__ (sshQ_L_75Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_75Cont));
            self->$class = &sshQ_L_75ContG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_75Cont, state);
    }
    self->self = $step_deserialize(state);
    self->W_HostKeyInfo_980 = $step_deserialize(state);
    self->reason = $step_deserialize(state);
    self->C_cont = $step_deserialize(state);
    self->ch = $step_deserialize(state);
    return self;
}
sshQ_L_75Cont sshQ_L_75ContG_new(sshQ_RunCommand G_1, B_Eq G_2, B_str G_3, $Cont G_4, sshQ_Channel G_5) {
    sshQ_L_75Cont $tmp = acton_malloc(sizeof(struct sshQ_L_75Cont));
    $tmp->$class = &sshQ_L_75ContG_methods;
    sshQ_L_75ContG_methods.__init__($tmp, G_1, G_2, G_3, G_4, G_5);
    return $tmp;
}
struct sshQ_L_75ContG_class sshQ_L_75ContG_methods;
$R sshQ_L_76C_37cont ($Cont C_cont, B_NoneType C_38res) {
    return $R_CONT(C_cont, B_None);
}
B_NoneType sshQ_L_77ContD___init__ (sshQ_L_77Cont L_self, $Cont C_cont) {
    ((sshQ_L_77Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R sshQ_L_77ContD___call__ (sshQ_L_77Cont L_self, B_NoneType G_1) {
    $Cont C_cont = ((sshQ_L_77Cont)(L_self))->C_cont;
    return sshQ_L_76C_37cont(C_cont, G_1);
}
void sshQ_L_77ContD___serialize__ (sshQ_L_77Cont self, $Serial$state state) {
    $step_serialize(self->C_cont, state);
}
sshQ_L_77Cont sshQ_L_77ContD___deserialize__ (sshQ_L_77Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_77Cont));
            self->$class = &sshQ_L_77ContG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_77Cont, state);
    }
    self->C_cont = $step_deserialize(state);
    return self;
}
sshQ_L_77Cont sshQ_L_77ContG_new($Cont G_1) {
    sshQ_L_77Cont $tmp = acton_malloc(sizeof(struct sshQ_L_77Cont));
    $tmp->$class = &sshQ_L_77ContG_methods;
    sshQ_L_77ContG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct sshQ_L_77ContG_class sshQ_L_77ContG_methods;
B_NoneType sshQ_L_78ContD___init__ (sshQ_L_78Cont L_self, $Cont C_cont) {
    ((sshQ_L_78Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R sshQ_L_78ContD___call__ (sshQ_L_78Cont L_self, B_NoneType G_1) {
    $Cont C_cont = ((sshQ_L_78Cont)(L_self))->C_cont;
    return sshQ_L_76C_37cont(C_cont, G_1);
}
void sshQ_L_78ContD___serialize__ (sshQ_L_78Cont self, $Serial$state state) {
    $step_serialize(self->C_cont, state);
}
sshQ_L_78Cont sshQ_L_78ContD___deserialize__ (sshQ_L_78Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_78Cont));
            self->$class = &sshQ_L_78ContG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_78Cont, state);
    }
    self->C_cont = $step_deserialize(state);
    return self;
}
sshQ_L_78Cont sshQ_L_78ContG_new($Cont G_1) {
    sshQ_L_78Cont $tmp = acton_malloc(sizeof(struct sshQ_L_78Cont));
    $tmp->$class = &sshQ_L_78ContG_methods;
    sshQ_L_78ContG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct sshQ_L_78ContG_class sshQ_L_78ContG_methods;
B_NoneType sshQ_L_79procD___init__ (sshQ_L_79proc L_self, sshQ_RunCommand self, sshQ_Channel ch) {
    ((sshQ_L_79proc)(L_self))->self = self;
    ((sshQ_L_79proc)(L_self))->ch = ch;
    return B_None;
}
$R sshQ_L_79procD___call__ (sshQ_L_79proc L_self, $Cont C_cont) {
    sshQ_RunCommand self = ((sshQ_L_79proc)(L_self))->self;
    sshQ_Channel ch = ((sshQ_L_79proc)(L_self))->ch;
    return (($R (*) ($WORD, $Cont, sshQ_Channel))((sshQ_RunCommand)(self))->$class->_finishG_local)(self, C_cont, ch);
}
$R sshQ_L_79procD___exec__ (sshQ_L_79proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((sshQ_L_79proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void sshQ_L_79procD___serialize__ (sshQ_L_79proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->ch, state);
}
sshQ_L_79proc sshQ_L_79procD___deserialize__ (sshQ_L_79proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_79proc));
            self->$class = &sshQ_L_79procG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_79proc, state);
    }
    self->self = $step_deserialize(state);
    self->ch = $step_deserialize(state);
    return self;
}
sshQ_L_79proc sshQ_L_79procG_new(sshQ_RunCommand G_1, sshQ_Channel G_2) {
    sshQ_L_79proc $tmp = acton_malloc(sizeof(struct sshQ_L_79proc));
    $tmp->$class = &sshQ_L_79procG_methods;
    sshQ_L_79procG_methods.__init__($tmp, G_1, G_2);
    return $tmp;
}
struct sshQ_L_79procG_class sshQ_L_79procG_methods;
B_NoneType sshQ_L_80procD___init__ (sshQ_L_80proc L_self, sshQ_RunCommand self, sshQ_Channel ch, B_str err) {
    ((sshQ_L_80proc)(L_self))->self = self;
    ((sshQ_L_80proc)(L_self))->ch = ch;
    ((sshQ_L_80proc)(L_self))->err = err;
    return B_None;
}
$R sshQ_L_80procD___call__ (sshQ_L_80proc L_self, $Cont C_cont) {
    sshQ_RunCommand self = ((sshQ_L_80proc)(L_self))->self;
    sshQ_Channel ch = ((sshQ_L_80proc)(L_self))->ch;
    B_str err = ((sshQ_L_80proc)(L_self))->err;
    return (($R (*) ($WORD, $Cont, sshQ_Channel, B_str))((sshQ_RunCommand)(self))->$class->_on_openG_local)(self, C_cont, ch, err);
}
$R sshQ_L_80procD___exec__ (sshQ_L_80proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((sshQ_L_80proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void sshQ_L_80procD___serialize__ (sshQ_L_80proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->ch, state);
    $step_serialize(self->err, state);
}
sshQ_L_80proc sshQ_L_80procD___deserialize__ (sshQ_L_80proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_80proc));
            self->$class = &sshQ_L_80procG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_80proc, state);
    }
    self->self = $step_deserialize(state);
    self->ch = $step_deserialize(state);
    self->err = $step_deserialize(state);
    return self;
}
sshQ_L_80proc sshQ_L_80procG_new(sshQ_RunCommand G_1, sshQ_Channel G_2, B_str G_3) {
    sshQ_L_80proc $tmp = acton_malloc(sizeof(struct sshQ_L_80proc));
    $tmp->$class = &sshQ_L_80procG_methods;
    sshQ_L_80procG_methods.__init__($tmp, G_1, G_2, G_3);
    return $tmp;
}
struct sshQ_L_80procG_class sshQ_L_80procG_methods;
B_NoneType sshQ_L_81procD___init__ (sshQ_L_81proc L_self, sshQ_RunCommand self, sshQ_Channel ch, B_bytes data) {
    ((sshQ_L_81proc)(L_self))->self = self;
    ((sshQ_L_81proc)(L_self))->ch = ch;
    ((sshQ_L_81proc)(L_self))->data = data;
    return B_None;
}
$R sshQ_L_81procD___call__ (sshQ_L_81proc L_self, $Cont C_cont) {
    sshQ_RunCommand self = ((sshQ_L_81proc)(L_self))->self;
    sshQ_Channel ch = ((sshQ_L_81proc)(L_self))->ch;
    B_bytes data = ((sshQ_L_81proc)(L_self))->data;
    return (($R (*) ($WORD, $Cont, sshQ_Channel, B_bytes))((sshQ_RunCommand)(self))->$class->_on_stdoutG_local)(self, C_cont, ch, data);
}
$R sshQ_L_81procD___exec__ (sshQ_L_81proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((sshQ_L_81proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void sshQ_L_81procD___serialize__ (sshQ_L_81proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->ch, state);
    $step_serialize(self->data, state);
}
sshQ_L_81proc sshQ_L_81procD___deserialize__ (sshQ_L_81proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_81proc));
            self->$class = &sshQ_L_81procG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_81proc, state);
    }
    self->self = $step_deserialize(state);
    self->ch = $step_deserialize(state);
    self->data = $step_deserialize(state);
    return self;
}
sshQ_L_81proc sshQ_L_81procG_new(sshQ_RunCommand G_1, sshQ_Channel G_2, B_bytes G_3) {
    sshQ_L_81proc $tmp = acton_malloc(sizeof(struct sshQ_L_81proc));
    $tmp->$class = &sshQ_L_81procG_methods;
    sshQ_L_81procG_methods.__init__($tmp, G_1, G_2, G_3);
    return $tmp;
}
struct sshQ_L_81procG_class sshQ_L_81procG_methods;
B_NoneType sshQ_L_82procD___init__ (sshQ_L_82proc L_self, sshQ_RunCommand self, sshQ_Channel ch, B_bytes data) {
    ((sshQ_L_82proc)(L_self))->self = self;
    ((sshQ_L_82proc)(L_self))->ch = ch;
    ((sshQ_L_82proc)(L_self))->data = data;
    return B_None;
}
$R sshQ_L_82procD___call__ (sshQ_L_82proc L_self, $Cont C_cont) {
    sshQ_RunCommand self = ((sshQ_L_82proc)(L_self))->self;
    sshQ_Channel ch = ((sshQ_L_82proc)(L_self))->ch;
    B_bytes data = ((sshQ_L_82proc)(L_self))->data;
    return (($R (*) ($WORD, $Cont, sshQ_Channel, B_bytes))((sshQ_RunCommand)(self))->$class->_on_stderrG_local)(self, C_cont, ch, data);
}
$R sshQ_L_82procD___exec__ (sshQ_L_82proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((sshQ_L_82proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void sshQ_L_82procD___serialize__ (sshQ_L_82proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->ch, state);
    $step_serialize(self->data, state);
}
sshQ_L_82proc sshQ_L_82procD___deserialize__ (sshQ_L_82proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_82proc));
            self->$class = &sshQ_L_82procG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_82proc, state);
    }
    self->self = $step_deserialize(state);
    self->ch = $step_deserialize(state);
    self->data = $step_deserialize(state);
    return self;
}
sshQ_L_82proc sshQ_L_82procG_new(sshQ_RunCommand G_1, sshQ_Channel G_2, B_bytes G_3) {
    sshQ_L_82proc $tmp = acton_malloc(sizeof(struct sshQ_L_82proc));
    $tmp->$class = &sshQ_L_82procG_methods;
    sshQ_L_82procG_methods.__init__($tmp, G_1, G_2, G_3);
    return $tmp;
}
struct sshQ_L_82procG_class sshQ_L_82procG_methods;
B_NoneType sshQ_L_83procD___init__ (sshQ_L_83proc L_self, sshQ_RunCommand self, sshQ_Channel ch, int64_t code, B_str sig) {
    ((sshQ_L_83proc)(L_self))->self = self;
    ((sshQ_L_83proc)(L_self))->ch = ch;
    ((sshQ_L_83proc)(L_self))->code = code;
    ((sshQ_L_83proc)(L_self))->sig = sig;
    return B_None;
}
$R sshQ_L_83procD___call__ (sshQ_L_83proc L_self, $Cont C_cont) {
    sshQ_RunCommand self = ((sshQ_L_83proc)(L_self))->self;
    sshQ_Channel ch = ((sshQ_L_83proc)(L_self))->ch;
    int64_t code = ((int64_t)((sshQ_L_83proc)(L_self))->code);
    B_str sig = ((sshQ_L_83proc)(L_self))->sig;
    return (($R (*) ($WORD, $Cont, sshQ_Channel, int64_t, B_str))((sshQ_RunCommand)(self))->$class->_on_exitG_local)(self, C_cont, ch, code, sig);
}
$R sshQ_L_83procD___exec__ (sshQ_L_83proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((sshQ_L_83proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void sshQ_L_83procD___serialize__ (sshQ_L_83proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->ch, state);
    $val_serialize(I64_ID, &self->code, state);
    $step_serialize(self->sig, state);
}
sshQ_L_83proc sshQ_L_83procD___deserialize__ (sshQ_L_83proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_83proc));
            self->$class = &sshQ_L_83procG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_83proc, state);
    }
    self->self = $step_deserialize(state);
    self->ch = $step_deserialize(state);
    $tmp = $val_deserialize(state);
    memcpy(&self->code, &$tmp, sizeof(self->code));
    self->sig = $step_deserialize(state);
    return self;
}
sshQ_L_83proc sshQ_L_83procG_new(sshQ_RunCommand G_1, sshQ_Channel G_2, int64_t G_3, B_str G_4) {
    sshQ_L_83proc $tmp = acton_malloc(sizeof(struct sshQ_L_83proc));
    $tmp->$class = &sshQ_L_83procG_methods;
    sshQ_L_83procG_methods.__init__($tmp, G_1, G_2, G_3, G_4);
    return $tmp;
}
struct sshQ_L_83procG_class sshQ_L_83procG_methods;
B_NoneType sshQ_L_84procD___init__ (sshQ_L_84proc L_self, sshQ_RunCommand self, sshQ_Channel ch, B_str reason) {
    ((sshQ_L_84proc)(L_self))->self = self;
    ((sshQ_L_84proc)(L_self))->ch = ch;
    ((sshQ_L_84proc)(L_self))->reason = reason;
    return B_None;
}
$R sshQ_L_84procD___call__ (sshQ_L_84proc L_self, $Cont C_cont) {
    sshQ_RunCommand self = ((sshQ_L_84proc)(L_self))->self;
    sshQ_Channel ch = ((sshQ_L_84proc)(L_self))->ch;
    B_str reason = ((sshQ_L_84proc)(L_self))->reason;
    return (($R (*) ($WORD, $Cont, sshQ_Channel, B_str))((sshQ_RunCommand)(self))->$class->_on_closeG_local)(self, C_cont, ch, reason);
}
$R sshQ_L_84procD___exec__ (sshQ_L_84proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((sshQ_L_84proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void sshQ_L_84procD___serialize__ (sshQ_L_84proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->ch, state);
    $step_serialize(self->reason, state);
}
sshQ_L_84proc sshQ_L_84procD___deserialize__ (sshQ_L_84proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_84proc));
            self->$class = &sshQ_L_84procG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_84proc, state);
    }
    self->self = $step_deserialize(state);
    self->ch = $step_deserialize(state);
    self->reason = $step_deserialize(state);
    return self;
}
sshQ_L_84proc sshQ_L_84procG_new(sshQ_RunCommand G_1, sshQ_Channel G_2, B_str G_3) {
    sshQ_L_84proc $tmp = acton_malloc(sizeof(struct sshQ_L_84proc));
    $tmp->$class = &sshQ_L_84procG_methods;
    sshQ_L_84procG_methods.__init__($tmp, G_1, G_2, G_3);
    return $tmp;
}
struct sshQ_L_84procG_class sshQ_L_84procG_methods;
B_NoneType sshQ_L_85procD___init__ (sshQ_L_85proc L_self, sshQ_RunCommand self, sshQ_Channel ch) {
    ((sshQ_L_85proc)(L_self))->self = self;
    ((sshQ_L_85proc)(L_self))->ch = ch;
    return B_None;
}
$R sshQ_L_85procD___call__ (sshQ_L_85proc L_self, $Cont C_cont) {
    sshQ_RunCommand self = ((sshQ_L_85proc)(L_self))->self;
    sshQ_Channel ch = ((sshQ_L_85proc)(L_self))->ch;
    return (($R (*) ($WORD, $Cont, sshQ_Channel))((sshQ_RunCommand)(self))->$class->_check_doneG_local)(self, C_cont, ch);
}
$R sshQ_L_85procD___exec__ (sshQ_L_85proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((sshQ_L_85proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void sshQ_L_85procD___serialize__ (sshQ_L_85proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->ch, state);
}
sshQ_L_85proc sshQ_L_85procD___deserialize__ (sshQ_L_85proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_85proc));
            self->$class = &sshQ_L_85procG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_85proc, state);
    }
    self->self = $step_deserialize(state);
    self->ch = $step_deserialize(state);
    return self;
}
sshQ_L_85proc sshQ_L_85procG_new(sshQ_RunCommand G_1, sshQ_Channel G_2) {
    sshQ_L_85proc $tmp = acton_malloc(sizeof(struct sshQ_L_85proc));
    $tmp->$class = &sshQ_L_85procG_methods;
    sshQ_L_85procG_methods.__init__($tmp, G_1, G_2);
    return $tmp;
}
struct sshQ_L_85procG_class sshQ_L_85procG_methods;
$R sshQ_L_86C_39cont (sshQ_Server self, $Cont C_cont, B_NoneType C_40res) {
    return (($R (*) ($WORD, $Cont))((sshQ_Server)(self))->$class->_initG_local)(self, C_cont);
}
B_NoneType sshQ_L_87ContD___init__ (sshQ_L_87Cont L_self, sshQ_Server self, $Cont C_cont) {
    ((sshQ_L_87Cont)(L_self))->self = self;
    ((sshQ_L_87Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R sshQ_L_87ContD___call__ (sshQ_L_87Cont L_self, B_NoneType G_1) {
    sshQ_Server self = ((sshQ_L_87Cont)(L_self))->self;
    $Cont C_cont = ((sshQ_L_87Cont)(L_self))->C_cont;
    return sshQ_L_86C_39cont(self, C_cont, G_1);
}
void sshQ_L_87ContD___serialize__ (sshQ_L_87Cont self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->C_cont, state);
}
sshQ_L_87Cont sshQ_L_87ContD___deserialize__ (sshQ_L_87Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_87Cont));
            self->$class = &sshQ_L_87ContG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_87Cont, state);
    }
    self->self = $step_deserialize(state);
    self->C_cont = $step_deserialize(state);
    return self;
}
sshQ_L_87Cont sshQ_L_87ContG_new(sshQ_Server G_1, $Cont G_2) {
    sshQ_L_87Cont $tmp = acton_malloc(sizeof(struct sshQ_L_87Cont));
    $tmp->$class = &sshQ_L_87ContG_methods;
    sshQ_L_87ContG_methods.__init__($tmp, G_1, G_2);
    return $tmp;
}
struct sshQ_L_87ContG_class sshQ_L_87ContG_methods;
$R sshQ_L_88C_41cont ($Cont C_cont, B_NoneType C_42res) {
    return $R_CONT(C_cont, B_None);
}
B_NoneType sshQ_L_89ContD___init__ (sshQ_L_89Cont L_self, $Cont C_cont) {
    ((sshQ_L_89Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R sshQ_L_89ContD___call__ (sshQ_L_89Cont L_self, B_NoneType G_1) {
    $Cont C_cont = ((sshQ_L_89Cont)(L_self))->C_cont;
    return sshQ_L_88C_41cont(C_cont, G_1);
}
void sshQ_L_89ContD___serialize__ (sshQ_L_89Cont self, $Serial$state state) {
    $step_serialize(self->C_cont, state);
}
sshQ_L_89Cont sshQ_L_89ContD___deserialize__ (sshQ_L_89Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_89Cont));
            self->$class = &sshQ_L_89ContG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_89Cont, state);
    }
    self->C_cont = $step_deserialize(state);
    return self;
}
sshQ_L_89Cont sshQ_L_89ContG_new($Cont G_1) {
    sshQ_L_89Cont $tmp = acton_malloc(sizeof(struct sshQ_L_89Cont));
    $tmp->$class = &sshQ_L_89ContG_methods;
    sshQ_L_89ContG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct sshQ_L_89ContG_class sshQ_L_89ContG_methods;
B_NoneType sshQ_L_90ContD___init__ (sshQ_L_90Cont L_self, $Cont C_cont) {
    ((sshQ_L_90Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R sshQ_L_90ContD___call__ (sshQ_L_90Cont L_self, B_NoneType G_1) {
    $Cont C_cont = ((sshQ_L_90Cont)(L_self))->C_cont;
    return sshQ_L_88C_41cont(C_cont, G_1);
}
void sshQ_L_90ContD___serialize__ (sshQ_L_90Cont self, $Serial$state state) {
    $step_serialize(self->C_cont, state);
}
sshQ_L_90Cont sshQ_L_90ContD___deserialize__ (sshQ_L_90Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_90Cont));
            self->$class = &sshQ_L_90ContG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_90Cont, state);
    }
    self->C_cont = $step_deserialize(state);
    return self;
}
sshQ_L_90Cont sshQ_L_90ContG_new($Cont G_1) {
    sshQ_L_90Cont $tmp = acton_malloc(sizeof(struct sshQ_L_90Cont));
    $tmp->$class = &sshQ_L_90ContG_methods;
    sshQ_L_90ContG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct sshQ_L_90ContG_class sshQ_L_90ContG_methods;
$R sshQ_L_91C_43cont ($Cont C_cont, sshQ_ServerSession C_44res) {
    return $R_CONT(C_cont, B_None);
}
B_NoneType sshQ_L_92ContD___init__ (sshQ_L_92Cont L_self, $Cont C_cont) {
    ((sshQ_L_92Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R sshQ_L_92ContD___call__ (sshQ_L_92Cont L_self, sshQ_ServerSession G_1) {
    $Cont C_cont = ((sshQ_L_92Cont)(L_self))->C_cont;
    return sshQ_L_91C_43cont(C_cont, G_1);
}
void sshQ_L_92ContD___serialize__ (sshQ_L_92Cont self, $Serial$state state) {
    $step_serialize(self->C_cont, state);
}
sshQ_L_92Cont sshQ_L_92ContD___deserialize__ (sshQ_L_92Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_92Cont));
            self->$class = &sshQ_L_92ContG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_92Cont, state);
    }
    self->C_cont = $step_deserialize(state);
    return self;
}
sshQ_L_92Cont sshQ_L_92ContG_new($Cont G_1) {
    sshQ_L_92Cont $tmp = acton_malloc(sizeof(struct sshQ_L_92Cont));
    $tmp->$class = &sshQ_L_92ContG_methods;
    sshQ_L_92ContG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct sshQ_L_92ContG_class sshQ_L_92ContG_methods;
B_NoneType sshQ_L_93procD___init__ (sshQ_L_93proc L_self, sshQ_Server self) {
    ((sshQ_L_93proc)(L_self))->self = self;
    return B_None;
}
$R sshQ_L_93procD___call__ (sshQ_L_93proc L_self, $Cont C_cont) {
    sshQ_Server self = ((sshQ_L_93proc)(L_self))->self;
    return (($R (*) ($WORD, $Cont))((sshQ_Server)(self))->$class->_pin_affinityG_local)(self, C_cont);
}
$R sshQ_L_93procD___exec__ (sshQ_L_93proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((sshQ_L_93proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void sshQ_L_93procD___serialize__ (sshQ_L_93proc self, $Serial$state state) {
    $step_serialize(self->self, state);
}
sshQ_L_93proc sshQ_L_93procD___deserialize__ (sshQ_L_93proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_93proc));
            self->$class = &sshQ_L_93procG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_93proc, state);
    }
    self->self = $step_deserialize(state);
    return self;
}
sshQ_L_93proc sshQ_L_93procG_new(sshQ_Server G_1) {
    sshQ_L_93proc $tmp = acton_malloc(sizeof(struct sshQ_L_93proc));
    $tmp->$class = &sshQ_L_93procG_methods;
    sshQ_L_93procG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct sshQ_L_93procG_class sshQ_L_93procG_methods;
B_NoneType sshQ_L_94procD___init__ (sshQ_L_94proc L_self, sshQ_Server self) {
    ((sshQ_L_94proc)(L_self))->self = self;
    return B_None;
}
$R sshQ_L_94procD___call__ (sshQ_L_94proc L_self, $Cont C_cont) {
    sshQ_Server self = ((sshQ_L_94proc)(L_self))->self;
    return (($R (*) ($WORD, $Cont))((sshQ_Server)(self))->$class->_initG_local)(self, C_cont);
}
$R sshQ_L_94procD___exec__ (sshQ_L_94proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((sshQ_L_94proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void sshQ_L_94procD___serialize__ (sshQ_L_94proc self, $Serial$state state) {
    $step_serialize(self->self, state);
}
sshQ_L_94proc sshQ_L_94procD___deserialize__ (sshQ_L_94proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_94proc));
            self->$class = &sshQ_L_94procG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_94proc, state);
    }
    self->self = $step_deserialize(state);
    return self;
}
sshQ_L_94proc sshQ_L_94procG_new(sshQ_Server G_1) {
    sshQ_L_94proc $tmp = acton_malloc(sizeof(struct sshQ_L_94proc));
    $tmp->$class = &sshQ_L_94procG_methods;
    sshQ_L_94procG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct sshQ_L_94procG_class sshQ_L_94procG_methods;
B_NoneType sshQ_L_95procD___init__ (sshQ_L_95proc L_self, sshQ_Server self) {
    ((sshQ_L_95proc)(L_self))->self = self;
    return B_None;
}
$R sshQ_L_95procD___call__ (sshQ_L_95proc L_self, $Cont C_cont) {
    sshQ_Server self = ((sshQ_L_95proc)(L_self))->self;
    return (($R (*) ($WORD, $Cont))((sshQ_Server)(self))->$class->closeG_local)(self, C_cont);
}
$R sshQ_L_95procD___exec__ (sshQ_L_95proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((sshQ_L_95proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void sshQ_L_95procD___serialize__ (sshQ_L_95proc self, $Serial$state state) {
    $step_serialize(self->self, state);
}
sshQ_L_95proc sshQ_L_95procD___deserialize__ (sshQ_L_95proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_95proc));
            self->$class = &sshQ_L_95procG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_95proc, state);
    }
    self->self = $step_deserialize(state);
    return self;
}
sshQ_L_95proc sshQ_L_95procG_new(sshQ_Server G_1) {
    sshQ_L_95proc $tmp = acton_malloc(sizeof(struct sshQ_L_95proc));
    $tmp->$class = &sshQ_L_95procG_methods;
    sshQ_L_95procG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct sshQ_L_95procG_class sshQ_L_95procG_methods;
B_NoneType sshQ_L_96procD___init__ (sshQ_L_96proc L_self, sshQ_Server self) {
    ((sshQ_L_96proc)(L_self))->self = self;
    return B_None;
}
$R sshQ_L_96procD___call__ (sshQ_L_96proc L_self, $Cont C_cont) {
    sshQ_Server self = ((sshQ_L_96proc)(L_self))->self;
    return (($R (*) ($WORD, $Cont))((sshQ_Server)(self))->$class->bound_portG_local)(self, C_cont);
}
$R sshQ_L_96procD___exec__ (sshQ_L_96proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((sshQ_L_96proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void sshQ_L_96procD___serialize__ (sshQ_L_96proc self, $Serial$state state) {
    $step_serialize(self->self, state);
}
sshQ_L_96proc sshQ_L_96procD___deserialize__ (sshQ_L_96proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_96proc));
            self->$class = &sshQ_L_96procG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_96proc, state);
    }
    self->self = $step_deserialize(state);
    return self;
}
sshQ_L_96proc sshQ_L_96procG_new(sshQ_Server G_1) {
    sshQ_L_96proc $tmp = acton_malloc(sizeof(struct sshQ_L_96proc));
    $tmp->$class = &sshQ_L_96procG_methods;
    sshQ_L_96procG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct sshQ_L_96procG_class sshQ_L_96procG_methods;
B_NoneType sshQ_L_97procD___init__ (sshQ_L_97proc L_self, sshQ_Server self) {
    ((sshQ_L_97proc)(L_self))->self = self;
    return B_None;
}
$R sshQ_L_97procD___call__ (sshQ_L_97proc L_self, $Cont C_cont) {
    sshQ_Server self = ((sshQ_L_97proc)(L_self))->self;
    return (($R (*) ($WORD, $Cont))((sshQ_Server)(self))->$class->_cleanup_nativeG_local)(self, C_cont);
}
$R sshQ_L_97procD___exec__ (sshQ_L_97proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((sshQ_L_97proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void sshQ_L_97procD___serialize__ (sshQ_L_97proc self, $Serial$state state) {
    $step_serialize(self->self, state);
}
sshQ_L_97proc sshQ_L_97procD___deserialize__ (sshQ_L_97proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_97proc));
            self->$class = &sshQ_L_97procG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_97proc, state);
    }
    self->self = $step_deserialize(state);
    return self;
}
sshQ_L_97proc sshQ_L_97procG_new(sshQ_Server G_1) {
    sshQ_L_97proc $tmp = acton_malloc(sizeof(struct sshQ_L_97proc));
    $tmp->$class = &sshQ_L_97procG_methods;
    sshQ_L_97procG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct sshQ_L_97procG_class sshQ_L_97procG_methods;
B_NoneType sshQ_L_98procD___init__ (sshQ_L_98proc L_self, sshQ_Server self) {
    ((sshQ_L_98proc)(L_self))->self = self;
    return B_None;
}
$R sshQ_L_98procD___call__ (sshQ_L_98proc L_self, $Cont C_cont) {
    sshQ_Server self = ((sshQ_L_98proc)(L_self))->self;
    return (($R (*) ($WORD, $Cont))((sshQ_Server)(self))->$class->__cleanup__G_local)(self, C_cont);
}
$R sshQ_L_98procD___exec__ (sshQ_L_98proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((sshQ_L_98proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void sshQ_L_98procD___serialize__ (sshQ_L_98proc self, $Serial$state state) {
    $step_serialize(self->self, state);
}
sshQ_L_98proc sshQ_L_98procD___deserialize__ (sshQ_L_98proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_98proc));
            self->$class = &sshQ_L_98procG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_98proc, state);
    }
    self->self = $step_deserialize(state);
    return self;
}
sshQ_L_98proc sshQ_L_98procG_new(sshQ_Server G_1) {
    sshQ_L_98proc $tmp = acton_malloc(sizeof(struct sshQ_L_98proc));
    $tmp->$class = &sshQ_L_98procG_methods;
    sshQ_L_98procG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct sshQ_L_98procG_class sshQ_L_98procG_methods;
B_NoneType sshQ_L_99procD___init__ (sshQ_L_99proc L_self, sshQ_Server self, uint64_t session_id) {
    ((sshQ_L_99proc)(L_self))->self = self;
    ((sshQ_L_99proc)(L_self))->session_id = session_id;
    return B_None;
}
$R sshQ_L_99procD___call__ (sshQ_L_99proc L_self, $Cont C_cont) {
    sshQ_Server self = ((sshQ_L_99proc)(L_self))->self;
    uint64_t session_id = ((uint64_t)((sshQ_L_99proc)(L_self))->session_id);
    return (($R (*) ($WORD, $Cont, uint64_t))((sshQ_Server)(self))->$class->on_session_pendingG_local)(self, C_cont, session_id);
}
$R sshQ_L_99procD___exec__ (sshQ_L_99proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((sshQ_L_99proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void sshQ_L_99procD___serialize__ (sshQ_L_99proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $val_serialize(U64_ID, &self->session_id, state);
}
sshQ_L_99proc sshQ_L_99procD___deserialize__ (sshQ_L_99proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_99proc));
            self->$class = &sshQ_L_99procG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_99proc, state);
    }
    self->self = $step_deserialize(state);
    $tmp = $val_deserialize(state);
    memcpy(&self->session_id, &$tmp, sizeof(self->session_id));
    return self;
}
sshQ_L_99proc sshQ_L_99procG_new(sshQ_Server G_1, uint64_t G_2) {
    sshQ_L_99proc $tmp = acton_malloc(sizeof(struct sshQ_L_99proc));
    $tmp->$class = &sshQ_L_99procG_methods;
    sshQ_L_99procG_methods.__init__($tmp, G_1, G_2);
    return $tmp;
}
struct sshQ_L_99procG_class sshQ_L_99procG_methods;
B_NoneType sshQ_L_100procD___init__ (sshQ_L_100proc L_self, sshQ_Server self, sshQ_ServerSession session) {
    ((sshQ_L_100proc)(L_self))->self = self;
    ((sshQ_L_100proc)(L_self))->session = session;
    return B_None;
}
$R sshQ_L_100procD___call__ (sshQ_L_100proc L_self, $Cont C_cont) {
    sshQ_Server self = ((sshQ_L_100proc)(L_self))->self;
    sshQ_ServerSession session = ((sshQ_L_100proc)(L_self))->session;
    return (($R (*) ($WORD, $Cont, sshQ_ServerSession))((sshQ_Server)(self))->$class->on_session_readyG_local)(self, C_cont, session);
}
$R sshQ_L_100procD___exec__ (sshQ_L_100proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((sshQ_L_100proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void sshQ_L_100procD___serialize__ (sshQ_L_100proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->session, state);
}
sshQ_L_100proc sshQ_L_100procD___deserialize__ (sshQ_L_100proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_100proc));
            self->$class = &sshQ_L_100procG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_100proc, state);
    }
    self->self = $step_deserialize(state);
    self->session = $step_deserialize(state);
    return self;
}
sshQ_L_100proc sshQ_L_100procG_new(sshQ_Server G_1, sshQ_ServerSession G_2) {
    sshQ_L_100proc $tmp = acton_malloc(sizeof(struct sshQ_L_100proc));
    $tmp->$class = &sshQ_L_100procG_methods;
    sshQ_L_100procG_methods.__init__($tmp, G_1, G_2);
    return $tmp;
}
struct sshQ_L_100procG_class sshQ_L_100procG_methods;
B_NoneType sshQ_L_102procD___init__ (sshQ_L_102proc L_self, sshQ_ServerSession self) {
    ((sshQ_L_102proc)(L_self))->self = self;
    return B_None;
}
$R sshQ_L_102procD___call__ (sshQ_L_102proc L_self, $Cont C_cont) {
    sshQ_ServerSession self = ((sshQ_L_102proc)(L_self))->self;
    return (($R (*) ($WORD, $Cont))((sshQ_ServerSession)(self))->$class->_attach_readyG_local)(self, C_cont);
}
$R sshQ_L_102procD___exec__ (sshQ_L_102proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((sshQ_L_102proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void sshQ_L_102procD___serialize__ (sshQ_L_102proc self, $Serial$state state) {
    $step_serialize(self->self, state);
}
sshQ_L_102proc sshQ_L_102procD___deserialize__ (sshQ_L_102proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_102proc));
            self->$class = &sshQ_L_102procG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_102proc, state);
    }
    self->self = $step_deserialize(state);
    return self;
}
sshQ_L_102proc sshQ_L_102procG_new(sshQ_ServerSession G_1) {
    sshQ_L_102proc $tmp = acton_malloc(sizeof(struct sshQ_L_102proc));
    $tmp->$class = &sshQ_L_102procG_methods;
    sshQ_L_102procG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct sshQ_L_102procG_class sshQ_L_102procG_methods;
$R sshQ_L_101C_45cont (sshQ_ServerSession self, $Cont C_cont, B_NoneType C_46res) {
    #line 510 "src/ssh.act"
    $AFTER(toB_float(0), (($Cont)sshQ_L_102procG_new(self)));
    return $R_CONT(C_cont, B_None);
}
B_NoneType sshQ_L_103ContD___init__ (sshQ_L_103Cont L_self, sshQ_ServerSession self, $Cont C_cont) {
    ((sshQ_L_103Cont)(L_self))->self = self;
    ((sshQ_L_103Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R sshQ_L_103ContD___call__ (sshQ_L_103Cont L_self, B_NoneType G_1) {
    sshQ_ServerSession self = ((sshQ_L_103Cont)(L_self))->self;
    $Cont C_cont = ((sshQ_L_103Cont)(L_self))->C_cont;
    return sshQ_L_101C_45cont(self, C_cont, G_1);
}
void sshQ_L_103ContD___serialize__ (sshQ_L_103Cont self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->C_cont, state);
}
sshQ_L_103Cont sshQ_L_103ContD___deserialize__ (sshQ_L_103Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_103Cont));
            self->$class = &sshQ_L_103ContG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_103Cont, state);
    }
    self->self = $step_deserialize(state);
    self->C_cont = $step_deserialize(state);
    return self;
}
sshQ_L_103Cont sshQ_L_103ContG_new(sshQ_ServerSession G_1, $Cont G_2) {
    sshQ_L_103Cont $tmp = acton_malloc(sizeof(struct sshQ_L_103Cont));
    $tmp->$class = &sshQ_L_103ContG_methods;
    sshQ_L_103ContG_methods.__init__($tmp, G_1, G_2);
    return $tmp;
}
struct sshQ_L_103ContG_class sshQ_L_103ContG_methods;
$R sshQ_L_105C_49cont ($Cont C_cont, B_NoneType C_50res) {
    return $R_CONT(C_cont, B_None);
}
B_NoneType sshQ_L_106ContD___init__ (sshQ_L_106Cont L_self, $Cont C_cont) {
    ((sshQ_L_106Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R sshQ_L_106ContD___call__ (sshQ_L_106Cont L_self, B_NoneType G_1) {
    $Cont C_cont = ((sshQ_L_106Cont)(L_self))->C_cont;
    return sshQ_L_105C_49cont(C_cont, G_1);
}
void sshQ_L_106ContD___serialize__ (sshQ_L_106Cont self, $Serial$state state) {
    $step_serialize(self->C_cont, state);
}
sshQ_L_106Cont sshQ_L_106ContD___deserialize__ (sshQ_L_106Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_106Cont));
            self->$class = &sshQ_L_106ContG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_106Cont, state);
    }
    self->C_cont = $step_deserialize(state);
    return self;
}
sshQ_L_106Cont sshQ_L_106ContG_new($Cont G_1) {
    sshQ_L_106Cont $tmp = acton_malloc(sizeof(struct sshQ_L_106Cont));
    $tmp->$class = &sshQ_L_106ContG_methods;
    sshQ_L_106ContG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct sshQ_L_106ContG_class sshQ_L_106ContG_methods;
B_NoneType sshQ_L_107ContD___init__ (sshQ_L_107Cont L_self, $Cont C_cont) {
    ((sshQ_L_107Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R sshQ_L_107ContD___call__ (sshQ_L_107Cont L_self, B_NoneType G_1) {
    $Cont C_cont = ((sshQ_L_107Cont)(L_self))->C_cont;
    return sshQ_L_105C_49cont(C_cont, G_1);
}
void sshQ_L_107ContD___serialize__ (sshQ_L_107Cont self, $Serial$state state) {
    $step_serialize(self->C_cont, state);
}
sshQ_L_107Cont sshQ_L_107ContD___deserialize__ (sshQ_L_107Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_107Cont));
            self->$class = &sshQ_L_107ContG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_107Cont, state);
    }
    self->C_cont = $step_deserialize(state);
    return self;
}
sshQ_L_107Cont sshQ_L_107ContG_new($Cont G_1) {
    sshQ_L_107Cont $tmp = acton_malloc(sizeof(struct sshQ_L_107Cont));
    $tmp->$class = &sshQ_L_107ContG_methods;
    sshQ_L_107ContG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct sshQ_L_107ContG_class sshQ_L_107ContG_methods;
$R sshQ_L_104C_47cont ($Cont C_cont, sshQ_ServerSession self, B_NoneType C_48res) {
    if (((uint64_t)((sshQ_ServerSession)(self))->_session_id) != 0UL) {
        #line 507 "src/ssh.act"
        ((B_Msg (*) ($WORD, sshQ_ServerSession))((sshQ_Server)(((sshQ_ServerSession)(self))->server))->$class->on_session_ready)(((sshQ_ServerSession)(self))->server, self);
        return (($R (*) ($WORD, $Cont))((sshQ_ServerSession)(self))->$class->_drive_attachedG_local)(self, (($Cont)sshQ_L_106ContG_new(C_cont)));
    }
    else {
        return $R_CONT((($Cont)sshQ_L_107ContG_new(C_cont)), B_None);
    }
}
B_NoneType sshQ_L_108ContD___init__ (sshQ_L_108Cont L_self, $Cont C_cont, sshQ_ServerSession self) {
    ((sshQ_L_108Cont)(L_self))->C_cont = C_cont;
    ((sshQ_L_108Cont)(L_self))->self = self;
    return B_None;
}
$R sshQ_L_108ContD___call__ (sshQ_L_108Cont L_self, B_NoneType G_1) {
    $Cont C_cont = ((sshQ_L_108Cont)(L_self))->C_cont;
    sshQ_ServerSession self = ((sshQ_L_108Cont)(L_self))->self;
    return sshQ_L_104C_47cont(C_cont, self, G_1);
}
void sshQ_L_108ContD___serialize__ (sshQ_L_108Cont self, $Serial$state state) {
    $step_serialize(self->C_cont, state);
    $step_serialize(self->self, state);
}
sshQ_L_108Cont sshQ_L_108ContD___deserialize__ (sshQ_L_108Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_108Cont));
            self->$class = &sshQ_L_108ContG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_108Cont, state);
    }
    self->C_cont = $step_deserialize(state);
    self->self = $step_deserialize(state);
    return self;
}
sshQ_L_108Cont sshQ_L_108ContG_new($Cont G_1, sshQ_ServerSession G_2) {
    sshQ_L_108Cont $tmp = acton_malloc(sizeof(struct sshQ_L_108Cont));
    $tmp->$class = &sshQ_L_108ContG_methods;
    sshQ_L_108ContG_methods.__init__($tmp, G_1, G_2);
    return $tmp;
}
struct sshQ_L_108ContG_class sshQ_L_108ContG_methods;
$R sshQ_L_109C_51cont ($Cont C_cont, B_NoneType C_52res) {
    return $R_CONT(C_cont, B_None);
}
B_NoneType sshQ_L_110ContD___init__ (sshQ_L_110Cont L_self, $Cont C_cont) {
    ((sshQ_L_110Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R sshQ_L_110ContD___call__ (sshQ_L_110Cont L_self, B_NoneType G_1) {
    $Cont C_cont = ((sshQ_L_110Cont)(L_self))->C_cont;
    return sshQ_L_109C_51cont(C_cont, G_1);
}
void sshQ_L_110ContD___serialize__ (sshQ_L_110Cont self, $Serial$state state) {
    $step_serialize(self->C_cont, state);
}
sshQ_L_110Cont sshQ_L_110ContD___deserialize__ (sshQ_L_110Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_110Cont));
            self->$class = &sshQ_L_110ContG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_110Cont, state);
    }
    self->C_cont = $step_deserialize(state);
    return self;
}
sshQ_L_110Cont sshQ_L_110ContG_new($Cont G_1) {
    sshQ_L_110Cont $tmp = acton_malloc(sizeof(struct sshQ_L_110Cont));
    $tmp->$class = &sshQ_L_110ContG_methods;
    sshQ_L_110ContG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct sshQ_L_110ContG_class sshQ_L_110ContG_methods;
B_NoneType sshQ_L_111ContD___init__ (sshQ_L_111Cont L_self, $Cont C_cont) {
    ((sshQ_L_111Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R sshQ_L_111ContD___call__ (sshQ_L_111Cont L_self, B_NoneType G_1) {
    $Cont C_cont = ((sshQ_L_111Cont)(L_self))->C_cont;
    return sshQ_L_109C_51cont(C_cont, G_1);
}
void sshQ_L_111ContD___serialize__ (sshQ_L_111Cont self, $Serial$state state) {
    $step_serialize(self->C_cont, state);
}
sshQ_L_111Cont sshQ_L_111ContD___deserialize__ (sshQ_L_111Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_111Cont));
            self->$class = &sshQ_L_111ContG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_111Cont, state);
    }
    self->C_cont = $step_deserialize(state);
    return self;
}
sshQ_L_111Cont sshQ_L_111ContG_new($Cont G_1) {
    sshQ_L_111Cont $tmp = acton_malloc(sizeof(struct sshQ_L_111Cont));
    $tmp->$class = &sshQ_L_111ContG_methods;
    sshQ_L_111ContG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct sshQ_L_111ContG_class sshQ_L_111ContG_methods;
B_NoneType sshQ_L_112procD___init__ (sshQ_L_112proc L_self, sshQ_ServerSession self) {
    ((sshQ_L_112proc)(L_self))->self = self;
    return B_None;
}
$R sshQ_L_112procD___call__ (sshQ_L_112proc L_self, $Cont C_cont) {
    sshQ_ServerSession self = ((sshQ_L_112proc)(L_self))->self;
    return (($R (*) ($WORD, $Cont))((sshQ_ServerSession)(self))->$class->_pin_affinityG_local)(self, C_cont);
}
$R sshQ_L_112procD___exec__ (sshQ_L_112proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((sshQ_L_112proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void sshQ_L_112procD___serialize__ (sshQ_L_112proc self, $Serial$state state) {
    $step_serialize(self->self, state);
}
sshQ_L_112proc sshQ_L_112procD___deserialize__ (sshQ_L_112proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_112proc));
            self->$class = &sshQ_L_112procG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_112proc, state);
    }
    self->self = $step_deserialize(state);
    return self;
}
sshQ_L_112proc sshQ_L_112procG_new(sshQ_ServerSession G_1) {
    sshQ_L_112proc $tmp = acton_malloc(sizeof(struct sshQ_L_112proc));
    $tmp->$class = &sshQ_L_112procG_methods;
    sshQ_L_112procG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct sshQ_L_112procG_class sshQ_L_112procG_methods;
B_NoneType sshQ_L_113procD___init__ (sshQ_L_113proc L_self, sshQ_ServerSession self, uint64_t session_id) {
    ((sshQ_L_113proc)(L_self))->self = self;
    ((sshQ_L_113proc)(L_self))->session_id = session_id;
    return B_None;
}
$R sshQ_L_113procD___call__ (sshQ_L_113proc L_self, $Cont C_cont) {
    sshQ_ServerSession self = ((sshQ_L_113proc)(L_self))->self;
    uint64_t session_id = ((uint64_t)((sshQ_L_113proc)(L_self))->session_id);
    return (($R (*) ($WORD, $Cont, uint64_t))((sshQ_ServerSession)(self))->$class->_attachG_local)(self, C_cont, session_id);
}
$R sshQ_L_113procD___exec__ (sshQ_L_113proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((sshQ_L_113proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void sshQ_L_113procD___serialize__ (sshQ_L_113proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $val_serialize(U64_ID, &self->session_id, state);
}
sshQ_L_113proc sshQ_L_113procD___deserialize__ (sshQ_L_113proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_113proc));
            self->$class = &sshQ_L_113procG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_113proc, state);
    }
    self->self = $step_deserialize(state);
    $tmp = $val_deserialize(state);
    memcpy(&self->session_id, &$tmp, sizeof(self->session_id));
    return self;
}
sshQ_L_113proc sshQ_L_113procG_new(sshQ_ServerSession G_1, uint64_t G_2) {
    sshQ_L_113proc $tmp = acton_malloc(sizeof(struct sshQ_L_113proc));
    $tmp->$class = &sshQ_L_113procG_methods;
    sshQ_L_113procG_methods.__init__($tmp, G_1, G_2);
    return $tmp;
}
struct sshQ_L_113procG_class sshQ_L_113procG_methods;
B_NoneType sshQ_L_114procD___init__ (sshQ_L_114proc L_self, sshQ_ServerSession self) {
    ((sshQ_L_114proc)(L_self))->self = self;
    return B_None;
}
$R sshQ_L_114procD___call__ (sshQ_L_114proc L_self, $Cont C_cont) {
    sshQ_ServerSession self = ((sshQ_L_114proc)(L_self))->self;
    return (($R (*) ($WORD, $Cont))((sshQ_ServerSession)(self))->$class->_drive_attachedG_local)(self, C_cont);
}
$R sshQ_L_114procD___exec__ (sshQ_L_114proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((sshQ_L_114proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void sshQ_L_114procD___serialize__ (sshQ_L_114proc self, $Serial$state state) {
    $step_serialize(self->self, state);
}
sshQ_L_114proc sshQ_L_114procD___deserialize__ (sshQ_L_114proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_114proc));
            self->$class = &sshQ_L_114procG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_114proc, state);
    }
    self->self = $step_deserialize(state);
    return self;
}
sshQ_L_114proc sshQ_L_114procG_new(sshQ_ServerSession G_1) {
    sshQ_L_114proc $tmp = acton_malloc(sizeof(struct sshQ_L_114proc));
    $tmp->$class = &sshQ_L_114procG_methods;
    sshQ_L_114procG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct sshQ_L_114procG_class sshQ_L_114procG_methods;
B_NoneType sshQ_L_115procD___init__ (sshQ_L_115proc L_self, sshQ_ServerSession self) {
    ((sshQ_L_115proc)(L_self))->self = self;
    return B_None;
}
$R sshQ_L_115procD___call__ (sshQ_L_115proc L_self, $Cont C_cont) {
    sshQ_ServerSession self = ((sshQ_L_115proc)(L_self))->self;
    return (($R (*) ($WORD, $Cont))((sshQ_ServerSession)(self))->$class->_attach_readyG_local)(self, C_cont);
}
$R sshQ_L_115procD___exec__ (sshQ_L_115proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((sshQ_L_115proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void sshQ_L_115procD___serialize__ (sshQ_L_115proc self, $Serial$state state) {
    $step_serialize(self->self, state);
}
sshQ_L_115proc sshQ_L_115procD___deserialize__ (sshQ_L_115proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_115proc));
            self->$class = &sshQ_L_115procG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_115proc, state);
    }
    self->self = $step_deserialize(state);
    return self;
}
sshQ_L_115proc sshQ_L_115procG_new(sshQ_ServerSession G_1) {
    sshQ_L_115proc $tmp = acton_malloc(sizeof(struct sshQ_L_115proc));
    $tmp->$class = &sshQ_L_115procG_methods;
    sshQ_L_115procG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct sshQ_L_115procG_class sshQ_L_115procG_methods;
B_NoneType sshQ_L_116procD___init__ (sshQ_L_116proc L_self, sshQ_ServerSession self) {
    ((sshQ_L_116proc)(L_self))->self = self;
    return B_None;
}
$R sshQ_L_116procD___call__ (sshQ_L_116proc L_self, $Cont C_cont) {
    sshQ_ServerSession self = ((sshQ_L_116proc)(L_self))->self;
    return (($R (*) ($WORD, $Cont))((sshQ_ServerSession)(self))->$class->accept_authG_local)(self, C_cont);
}
$R sshQ_L_116procD___exec__ (sshQ_L_116proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((sshQ_L_116proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void sshQ_L_116procD___serialize__ (sshQ_L_116proc self, $Serial$state state) {
    $step_serialize(self->self, state);
}
sshQ_L_116proc sshQ_L_116procD___deserialize__ (sshQ_L_116proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_116proc));
            self->$class = &sshQ_L_116procG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_116proc, state);
    }
    self->self = $step_deserialize(state);
    return self;
}
sshQ_L_116proc sshQ_L_116procG_new(sshQ_ServerSession G_1) {
    sshQ_L_116proc $tmp = acton_malloc(sizeof(struct sshQ_L_116proc));
    $tmp->$class = &sshQ_L_116procG_methods;
    sshQ_L_116procG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct sshQ_L_116procG_class sshQ_L_116procG_methods;
B_NoneType sshQ_L_117procD___init__ (sshQ_L_117proc L_self, sshQ_ServerSession self, B_str reason) {
    ((sshQ_L_117proc)(L_self))->self = self;
    ((sshQ_L_117proc)(L_self))->reason = reason;
    return B_None;
}
$R sshQ_L_117procD___call__ (sshQ_L_117proc L_self, $Cont C_cont) {
    sshQ_ServerSession self = ((sshQ_L_117proc)(L_self))->self;
    B_str reason = ((sshQ_L_117proc)(L_self))->reason;
    return (($R (*) ($WORD, $Cont, B_str))((sshQ_ServerSession)(self))->$class->reject_authG_local)(self, C_cont, reason);
}
$R sshQ_L_117procD___exec__ (sshQ_L_117proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((sshQ_L_117proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void sshQ_L_117procD___serialize__ (sshQ_L_117proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->reason, state);
}
sshQ_L_117proc sshQ_L_117procD___deserialize__ (sshQ_L_117proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_117proc));
            self->$class = &sshQ_L_117procG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_117proc, state);
    }
    self->self = $step_deserialize(state);
    self->reason = $step_deserialize(state);
    return self;
}
sshQ_L_117proc sshQ_L_117procG_new(sshQ_ServerSession G_1, B_str G_2) {
    sshQ_L_117proc $tmp = acton_malloc(sizeof(struct sshQ_L_117proc));
    $tmp->$class = &sshQ_L_117procG_methods;
    sshQ_L_117procG_methods.__init__($tmp, G_1, G_2);
    return $tmp;
}
struct sshQ_L_117procG_class sshQ_L_117procG_methods;
B_NoneType sshQ_L_118procD___init__ (sshQ_L_118proc L_self, sshQ_ServerSession self, sshQ_ServerChannel channel) {
    ((sshQ_L_118proc)(L_self))->self = self;
    ((sshQ_L_118proc)(L_self))->channel = channel;
    return B_None;
}
$R sshQ_L_118procD___call__ (sshQ_L_118proc L_self, $Cont C_cont) {
    sshQ_ServerSession self = ((sshQ_L_118proc)(L_self))->self;
    sshQ_ServerChannel channel = ((sshQ_L_118proc)(L_self))->channel;
    return (($R (*) ($WORD, $Cont, sshQ_ServerChannel))((sshQ_ServerSession)(self))->$class->accept_channelG_local)(self, C_cont, channel);
}
$R sshQ_L_118procD___exec__ (sshQ_L_118proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((sshQ_L_118proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void sshQ_L_118procD___serialize__ (sshQ_L_118proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->channel, state);
}
sshQ_L_118proc sshQ_L_118procD___deserialize__ (sshQ_L_118proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_118proc));
            self->$class = &sshQ_L_118procG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_118proc, state);
    }
    self->self = $step_deserialize(state);
    self->channel = $step_deserialize(state);
    return self;
}
sshQ_L_118proc sshQ_L_118procG_new(sshQ_ServerSession G_1, sshQ_ServerChannel G_2) {
    sshQ_L_118proc $tmp = acton_malloc(sizeof(struct sshQ_L_118proc));
    $tmp->$class = &sshQ_L_118procG_methods;
    sshQ_L_118procG_methods.__init__($tmp, G_1, G_2);
    return $tmp;
}
struct sshQ_L_118procG_class sshQ_L_118procG_methods;
B_NoneType sshQ_L_119procD___init__ (sshQ_L_119proc L_self, sshQ_ServerSession self, sshQ_ServerChannel channel, $action on_data, $action on_stderr, $action on_close) {
    ((sshQ_L_119proc)(L_self))->self = self;
    ((sshQ_L_119proc)(L_self))->channel = channel;
    ((sshQ_L_119proc)(L_self))->on_data = on_data;
    ((sshQ_L_119proc)(L_self))->on_stderr = on_stderr;
    ((sshQ_L_119proc)(L_self))->on_close = on_close;
    return B_None;
}
$R sshQ_L_119procD___call__ (sshQ_L_119proc L_self, $Cont C_cont) {
    sshQ_ServerSession self = ((sshQ_L_119proc)(L_self))->self;
    sshQ_ServerChannel channel = ((sshQ_L_119proc)(L_self))->channel;
    $action on_data = ((sshQ_L_119proc)(L_self))->on_data;
    $action on_stderr = ((sshQ_L_119proc)(L_self))->on_stderr;
    $action on_close = ((sshQ_L_119proc)(L_self))->on_close;
    return (($R (*) ($WORD, $Cont, sshQ_ServerChannel, $action, $action, $action))((sshQ_ServerSession)(self))->$class->accept_channel_openG_local)(self, C_cont, channel, on_data, on_stderr, on_close);
}
$R sshQ_L_119procD___exec__ (sshQ_L_119proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((sshQ_L_119proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void sshQ_L_119procD___serialize__ (sshQ_L_119proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->channel, state);
    $step_serialize(self->on_data, state);
    $step_serialize(self->on_stderr, state);
    $step_serialize(self->on_close, state);
}
sshQ_L_119proc sshQ_L_119procD___deserialize__ (sshQ_L_119proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_119proc));
            self->$class = &sshQ_L_119procG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_119proc, state);
    }
    self->self = $step_deserialize(state);
    self->channel = $step_deserialize(state);
    self->on_data = $step_deserialize(state);
    self->on_stderr = $step_deserialize(state);
    self->on_close = $step_deserialize(state);
    return self;
}
sshQ_L_119proc sshQ_L_119procG_new(sshQ_ServerSession G_1, sshQ_ServerChannel G_2, $action G_3, $action G_4, $action G_5) {
    sshQ_L_119proc $tmp = acton_malloc(sizeof(struct sshQ_L_119proc));
    $tmp->$class = &sshQ_L_119procG_methods;
    sshQ_L_119procG_methods.__init__($tmp, G_1, G_2, G_3, G_4, G_5);
    return $tmp;
}
struct sshQ_L_119procG_class sshQ_L_119procG_methods;
B_NoneType sshQ_L_120procD___init__ (sshQ_L_120proc L_self, sshQ_ServerSession self, B_str reason) {
    ((sshQ_L_120proc)(L_self))->self = self;
    ((sshQ_L_120proc)(L_self))->reason = reason;
    return B_None;
}
$R sshQ_L_120procD___call__ (sshQ_L_120proc L_self, $Cont C_cont) {
    sshQ_ServerSession self = ((sshQ_L_120proc)(L_self))->self;
    B_str reason = ((sshQ_L_120proc)(L_self))->reason;
    return (($R (*) ($WORD, $Cont, B_str))((sshQ_ServerSession)(self))->$class->reject_channelG_local)(self, C_cont, reason);
}
$R sshQ_L_120procD___exec__ (sshQ_L_120proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((sshQ_L_120proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void sshQ_L_120procD___serialize__ (sshQ_L_120proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->reason, state);
}
sshQ_L_120proc sshQ_L_120procD___deserialize__ (sshQ_L_120proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_120proc));
            self->$class = &sshQ_L_120procG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_120proc, state);
    }
    self->self = $step_deserialize(state);
    self->reason = $step_deserialize(state);
    return self;
}
sshQ_L_120proc sshQ_L_120procG_new(sshQ_ServerSession G_1, B_str G_2) {
    sshQ_L_120proc $tmp = acton_malloc(sizeof(struct sshQ_L_120proc));
    $tmp->$class = &sshQ_L_120procG_methods;
    sshQ_L_120procG_methods.__init__($tmp, G_1, G_2);
    return $tmp;
}
struct sshQ_L_120procG_class sshQ_L_120procG_methods;
B_NoneType sshQ_L_121procD___init__ (sshQ_L_121proc L_self, sshQ_ServerSession self) {
    ((sshQ_L_121proc)(L_self))->self = self;
    return B_None;
}
$R sshQ_L_121procD___call__ (sshQ_L_121proc L_self, $Cont C_cont) {
    sshQ_ServerSession self = ((sshQ_L_121proc)(L_self))->self;
    return (($R (*) ($WORD, $Cont))((sshQ_ServerSession)(self))->$class->closeG_local)(self, C_cont);
}
$R sshQ_L_121procD___exec__ (sshQ_L_121proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((sshQ_L_121proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void sshQ_L_121procD___serialize__ (sshQ_L_121proc self, $Serial$state state) {
    $step_serialize(self->self, state);
}
sshQ_L_121proc sshQ_L_121procD___deserialize__ (sshQ_L_121proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_121proc));
            self->$class = &sshQ_L_121procG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_121proc, state);
    }
    self->self = $step_deserialize(state);
    return self;
}
sshQ_L_121proc sshQ_L_121procG_new(sshQ_ServerSession G_1) {
    sshQ_L_121proc $tmp = acton_malloc(sizeof(struct sshQ_L_121proc));
    $tmp->$class = &sshQ_L_121procG_methods;
    sshQ_L_121procG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct sshQ_L_121procG_class sshQ_L_121procG_methods;
B_NoneType sshQ_L_122procD___init__ (sshQ_L_122proc L_self, sshQ_ServerSession self) {
    ((sshQ_L_122proc)(L_self))->self = self;
    return B_None;
}
$R sshQ_L_122procD___call__ (sshQ_L_122proc L_self, $Cont C_cont) {
    sshQ_ServerSession self = ((sshQ_L_122proc)(L_self))->self;
    return (($R (*) ($WORD, $Cont))((sshQ_ServerSession)(self))->$class->_cleanup_nativeG_local)(self, C_cont);
}
$R sshQ_L_122procD___exec__ (sshQ_L_122proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((sshQ_L_122proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void sshQ_L_122procD___serialize__ (sshQ_L_122proc self, $Serial$state state) {
    $step_serialize(self->self, state);
}
sshQ_L_122proc sshQ_L_122procD___deserialize__ (sshQ_L_122proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_122proc));
            self->$class = &sshQ_L_122procG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_122proc, state);
    }
    self->self = $step_deserialize(state);
    return self;
}
sshQ_L_122proc sshQ_L_122procG_new(sshQ_ServerSession G_1) {
    sshQ_L_122proc $tmp = acton_malloc(sizeof(struct sshQ_L_122proc));
    $tmp->$class = &sshQ_L_122procG_methods;
    sshQ_L_122procG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct sshQ_L_122procG_class sshQ_L_122procG_methods;
B_NoneType sshQ_L_123procD___init__ (sshQ_L_123proc L_self, sshQ_ServerSession self) {
    ((sshQ_L_123proc)(L_self))->self = self;
    return B_None;
}
$R sshQ_L_123procD___call__ (sshQ_L_123proc L_self, $Cont C_cont) {
    sshQ_ServerSession self = ((sshQ_L_123proc)(L_self))->self;
    return (($R (*) ($WORD, $Cont))((sshQ_ServerSession)(self))->$class->__cleanup__G_local)(self, C_cont);
}
$R sshQ_L_123procD___exec__ (sshQ_L_123proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((sshQ_L_123proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void sshQ_L_123procD___serialize__ (sshQ_L_123proc self, $Serial$state state) {
    $step_serialize(self->self, state);
}
sshQ_L_123proc sshQ_L_123procD___deserialize__ (sshQ_L_123proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_123proc));
            self->$class = &sshQ_L_123procG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_123proc, state);
    }
    self->self = $step_deserialize(state);
    return self;
}
sshQ_L_123proc sshQ_L_123procG_new(sshQ_ServerSession G_1) {
    sshQ_L_123proc $tmp = acton_malloc(sizeof(struct sshQ_L_123proc));
    $tmp->$class = &sshQ_L_123procG_methods;
    sshQ_L_123procG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct sshQ_L_123procG_class sshQ_L_123procG_methods;
B_NoneType sshQ_L_124procD___init__ (sshQ_L_124proc L_self, sshQ_ServerSession self, sshQ_ServerChannel channel) {
    ((sshQ_L_124proc)(L_self))->self = self;
    ((sshQ_L_124proc)(L_self))->channel = channel;
    return B_None;
}
$R sshQ_L_124procD___call__ (sshQ_L_124proc L_self, $Cont C_cont) {
    sshQ_ServerSession self = ((sshQ_L_124proc)(L_self))->self;
    sshQ_ServerChannel channel = ((sshQ_L_124proc)(L_self))->channel;
    return (($R (*) ($WORD, $Cont, sshQ_ServerChannel))((sshQ_ServerSession)(self))->$class->channel_accept_requestG_local)(self, C_cont, channel);
}
$R sshQ_L_124procD___exec__ (sshQ_L_124proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((sshQ_L_124proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void sshQ_L_124procD___serialize__ (sshQ_L_124proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->channel, state);
}
sshQ_L_124proc sshQ_L_124procD___deserialize__ (sshQ_L_124proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_124proc));
            self->$class = &sshQ_L_124procG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_124proc, state);
    }
    self->self = $step_deserialize(state);
    self->channel = $step_deserialize(state);
    return self;
}
sshQ_L_124proc sshQ_L_124procG_new(sshQ_ServerSession G_1, sshQ_ServerChannel G_2) {
    sshQ_L_124proc $tmp = acton_malloc(sizeof(struct sshQ_L_124proc));
    $tmp->$class = &sshQ_L_124procG_methods;
    sshQ_L_124procG_methods.__init__($tmp, G_1, G_2);
    return $tmp;
}
struct sshQ_L_124procG_class sshQ_L_124procG_methods;
B_NoneType sshQ_L_125procD___init__ (sshQ_L_125proc L_self, sshQ_ServerSession self, sshQ_ServerChannel channel, B_str reason) {
    ((sshQ_L_125proc)(L_self))->self = self;
    ((sshQ_L_125proc)(L_self))->channel = channel;
    ((sshQ_L_125proc)(L_self))->reason = reason;
    return B_None;
}
$R sshQ_L_125procD___call__ (sshQ_L_125proc L_self, $Cont C_cont) {
    sshQ_ServerSession self = ((sshQ_L_125proc)(L_self))->self;
    sshQ_ServerChannel channel = ((sshQ_L_125proc)(L_self))->channel;
    B_str reason = ((sshQ_L_125proc)(L_self))->reason;
    return (($R (*) ($WORD, $Cont, sshQ_ServerChannel, B_str))((sshQ_ServerSession)(self))->$class->channel_reject_requestG_local)(self, C_cont, channel, reason);
}
$R sshQ_L_125procD___exec__ (sshQ_L_125proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((sshQ_L_125proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void sshQ_L_125procD___serialize__ (sshQ_L_125proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->channel, state);
    $step_serialize(self->reason, state);
}
sshQ_L_125proc sshQ_L_125procD___deserialize__ (sshQ_L_125proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_125proc));
            self->$class = &sshQ_L_125procG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_125proc, state);
    }
    self->self = $step_deserialize(state);
    self->channel = $step_deserialize(state);
    self->reason = $step_deserialize(state);
    return self;
}
sshQ_L_125proc sshQ_L_125procG_new(sshQ_ServerSession G_1, sshQ_ServerChannel G_2, B_str G_3) {
    sshQ_L_125proc $tmp = acton_malloc(sizeof(struct sshQ_L_125proc));
    $tmp->$class = &sshQ_L_125procG_methods;
    sshQ_L_125procG_methods.__init__($tmp, G_1, G_2, G_3);
    return $tmp;
}
struct sshQ_L_125procG_class sshQ_L_125procG_methods;
B_NoneType sshQ_L_126procD___init__ (sshQ_L_126proc L_self, sshQ_ServerSession self, sshQ_ServerChannel channel, B_bytes data) {
    ((sshQ_L_126proc)(L_self))->self = self;
    ((sshQ_L_126proc)(L_self))->channel = channel;
    ((sshQ_L_126proc)(L_self))->data = data;
    return B_None;
}
$R sshQ_L_126procD___call__ (sshQ_L_126proc L_self, $Cont C_cont) {
    sshQ_ServerSession self = ((sshQ_L_126proc)(L_self))->self;
    sshQ_ServerChannel channel = ((sshQ_L_126proc)(L_self))->channel;
    B_bytes data = ((sshQ_L_126proc)(L_self))->data;
    return (($R (*) ($WORD, $Cont, sshQ_ServerChannel, B_bytes))((sshQ_ServerSession)(self))->$class->channel_writeG_local)(self, C_cont, channel, data);
}
$R sshQ_L_126procD___exec__ (sshQ_L_126proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((sshQ_L_126proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void sshQ_L_126procD___serialize__ (sshQ_L_126proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->channel, state);
    $step_serialize(self->data, state);
}
sshQ_L_126proc sshQ_L_126procD___deserialize__ (sshQ_L_126proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_126proc));
            self->$class = &sshQ_L_126procG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_126proc, state);
    }
    self->self = $step_deserialize(state);
    self->channel = $step_deserialize(state);
    self->data = $step_deserialize(state);
    return self;
}
sshQ_L_126proc sshQ_L_126procG_new(sshQ_ServerSession G_1, sshQ_ServerChannel G_2, B_bytes G_3) {
    sshQ_L_126proc $tmp = acton_malloc(sizeof(struct sshQ_L_126proc));
    $tmp->$class = &sshQ_L_126procG_methods;
    sshQ_L_126procG_methods.__init__($tmp, G_1, G_2, G_3);
    return $tmp;
}
struct sshQ_L_126procG_class sshQ_L_126procG_methods;
B_NoneType sshQ_L_127procD___init__ (sshQ_L_127proc L_self, sshQ_ServerSession self, sshQ_ServerChannel channel, B_bytes data) {
    ((sshQ_L_127proc)(L_self))->self = self;
    ((sshQ_L_127proc)(L_self))->channel = channel;
    ((sshQ_L_127proc)(L_self))->data = data;
    return B_None;
}
$R sshQ_L_127procD___call__ (sshQ_L_127proc L_self, $Cont C_cont) {
    sshQ_ServerSession self = ((sshQ_L_127proc)(L_self))->self;
    sshQ_ServerChannel channel = ((sshQ_L_127proc)(L_self))->channel;
    B_bytes data = ((sshQ_L_127proc)(L_self))->data;
    return (($R (*) ($WORD, $Cont, sshQ_ServerChannel, B_bytes))((sshQ_ServerSession)(self))->$class->channel_write_stderrG_local)(self, C_cont, channel, data);
}
$R sshQ_L_127procD___exec__ (sshQ_L_127proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((sshQ_L_127proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void sshQ_L_127procD___serialize__ (sshQ_L_127proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->channel, state);
    $step_serialize(self->data, state);
}
sshQ_L_127proc sshQ_L_127procD___deserialize__ (sshQ_L_127proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_127proc));
            self->$class = &sshQ_L_127procG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_127proc, state);
    }
    self->self = $step_deserialize(state);
    self->channel = $step_deserialize(state);
    self->data = $step_deserialize(state);
    return self;
}
sshQ_L_127proc sshQ_L_127procG_new(sshQ_ServerSession G_1, sshQ_ServerChannel G_2, B_bytes G_3) {
    sshQ_L_127proc $tmp = acton_malloc(sizeof(struct sshQ_L_127proc));
    $tmp->$class = &sshQ_L_127procG_methods;
    sshQ_L_127procG_methods.__init__($tmp, G_1, G_2, G_3);
    return $tmp;
}
struct sshQ_L_127procG_class sshQ_L_127procG_methods;
B_NoneType sshQ_L_128procD___init__ (sshQ_L_128proc L_self, sshQ_ServerSession self, sshQ_ServerChannel channel) {
    ((sshQ_L_128proc)(L_self))->self = self;
    ((sshQ_L_128proc)(L_self))->channel = channel;
    return B_None;
}
$R sshQ_L_128procD___call__ (sshQ_L_128proc L_self, $Cont C_cont) {
    sshQ_ServerSession self = ((sshQ_L_128proc)(L_self))->self;
    sshQ_ServerChannel channel = ((sshQ_L_128proc)(L_self))->channel;
    return (($R (*) ($WORD, $Cont, sshQ_ServerChannel))((sshQ_ServerSession)(self))->$class->channel_send_eofG_local)(self, C_cont, channel);
}
$R sshQ_L_128procD___exec__ (sshQ_L_128proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((sshQ_L_128proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void sshQ_L_128procD___serialize__ (sshQ_L_128proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->channel, state);
}
sshQ_L_128proc sshQ_L_128procD___deserialize__ (sshQ_L_128proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_128proc));
            self->$class = &sshQ_L_128procG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_128proc, state);
    }
    self->self = $step_deserialize(state);
    self->channel = $step_deserialize(state);
    return self;
}
sshQ_L_128proc sshQ_L_128procG_new(sshQ_ServerSession G_1, sshQ_ServerChannel G_2) {
    sshQ_L_128proc $tmp = acton_malloc(sizeof(struct sshQ_L_128proc));
    $tmp->$class = &sshQ_L_128procG_methods;
    sshQ_L_128procG_methods.__init__($tmp, G_1, G_2);
    return $tmp;
}
struct sshQ_L_128procG_class sshQ_L_128procG_methods;
B_NoneType sshQ_L_129procD___init__ (sshQ_L_129proc L_self, sshQ_ServerSession self, sshQ_ServerChannel channel, int64_t status) {
    ((sshQ_L_129proc)(L_self))->self = self;
    ((sshQ_L_129proc)(L_self))->channel = channel;
    ((sshQ_L_129proc)(L_self))->status = status;
    return B_None;
}
$R sshQ_L_129procD___call__ (sshQ_L_129proc L_self, $Cont C_cont) {
    sshQ_ServerSession self = ((sshQ_L_129proc)(L_self))->self;
    sshQ_ServerChannel channel = ((sshQ_L_129proc)(L_self))->channel;
    int64_t status = ((int64_t)((sshQ_L_129proc)(L_self))->status);
    return (($R (*) ($WORD, $Cont, sshQ_ServerChannel, int64_t))((sshQ_ServerSession)(self))->$class->channel_send_exit_statusG_local)(self, C_cont, channel, status);
}
$R sshQ_L_129procD___exec__ (sshQ_L_129proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((sshQ_L_129proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void sshQ_L_129procD___serialize__ (sshQ_L_129proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->channel, state);
    $val_serialize(I64_ID, &self->status, state);
}
sshQ_L_129proc sshQ_L_129procD___deserialize__ (sshQ_L_129proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_129proc));
            self->$class = &sshQ_L_129procG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_129proc, state);
    }
    self->self = $step_deserialize(state);
    self->channel = $step_deserialize(state);
    $tmp = $val_deserialize(state);
    memcpy(&self->status, &$tmp, sizeof(self->status));
    return self;
}
sshQ_L_129proc sshQ_L_129procG_new(sshQ_ServerSession G_1, sshQ_ServerChannel G_2, int64_t G_3) {
    sshQ_L_129proc $tmp = acton_malloc(sizeof(struct sshQ_L_129proc));
    $tmp->$class = &sshQ_L_129procG_methods;
    sshQ_L_129procG_methods.__init__($tmp, G_1, G_2, G_3);
    return $tmp;
}
struct sshQ_L_129procG_class sshQ_L_129procG_methods;
B_NoneType sshQ_L_130procD___init__ (sshQ_L_130proc L_self, sshQ_ServerSession self, sshQ_ServerChannel channel) {
    ((sshQ_L_130proc)(L_self))->self = self;
    ((sshQ_L_130proc)(L_self))->channel = channel;
    return B_None;
}
$R sshQ_L_130procD___call__ (sshQ_L_130proc L_self, $Cont C_cont) {
    sshQ_ServerSession self = ((sshQ_L_130proc)(L_self))->self;
    sshQ_ServerChannel channel = ((sshQ_L_130proc)(L_self))->channel;
    return (($R (*) ($WORD, $Cont, sshQ_ServerChannel))((sshQ_ServerSession)(self))->$class->channel_closeG_local)(self, C_cont, channel);
}
$R sshQ_L_130procD___exec__ (sshQ_L_130proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((sshQ_L_130proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void sshQ_L_130procD___serialize__ (sshQ_L_130proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->channel, state);
}
sshQ_L_130proc sshQ_L_130procD___deserialize__ (sshQ_L_130proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_130proc));
            self->$class = &sshQ_L_130procG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_130proc, state);
    }
    self->self = $step_deserialize(state);
    self->channel = $step_deserialize(state);
    return self;
}
sshQ_L_130proc sshQ_L_130procG_new(sshQ_ServerSession G_1, sshQ_ServerChannel G_2) {
    sshQ_L_130proc $tmp = acton_malloc(sizeof(struct sshQ_L_130proc));
    $tmp->$class = &sshQ_L_130procG_methods;
    sshQ_L_130procG_methods.__init__($tmp, G_1, G_2);
    return $tmp;
}
struct sshQ_L_130procG_class sshQ_L_130procG_methods;
$R sshQ_L_131C_53cont ($Cont C_cont, B_NoneType C_54res) {
    return $R_CONT(C_cont, B_None);
}
B_NoneType sshQ_L_132ContD___init__ (sshQ_L_132Cont L_self, $Cont C_cont) {
    ((sshQ_L_132Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R sshQ_L_132ContD___call__ (sshQ_L_132Cont L_self, B_NoneType G_1) {
    $Cont C_cont = ((sshQ_L_132Cont)(L_self))->C_cont;
    return sshQ_L_131C_53cont(C_cont, G_1);
}
void sshQ_L_132ContD___serialize__ (sshQ_L_132Cont self, $Serial$state state) {
    $step_serialize(self->C_cont, state);
}
sshQ_L_132Cont sshQ_L_132ContD___deserialize__ (sshQ_L_132Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_132Cont));
            self->$class = &sshQ_L_132ContG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_132Cont, state);
    }
    self->C_cont = $step_deserialize(state);
    return self;
}
sshQ_L_132Cont sshQ_L_132ContG_new($Cont G_1) {
    sshQ_L_132Cont $tmp = acton_malloc(sizeof(struct sshQ_L_132Cont));
    $tmp->$class = &sshQ_L_132ContG_methods;
    sshQ_L_132ContG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct sshQ_L_132ContG_class sshQ_L_132ContG_methods;
B_NoneType sshQ_L_133ContD___init__ (sshQ_L_133Cont L_self, $Cont C_cont) {
    ((sshQ_L_133Cont)(L_self))->C_cont = C_cont;
    return B_None;
}
$R sshQ_L_133ContD___call__ (sshQ_L_133Cont L_self, B_NoneType G_1) {
    $Cont C_cont = ((sshQ_L_133Cont)(L_self))->C_cont;
    return sshQ_L_131C_53cont(C_cont, G_1);
}
void sshQ_L_133ContD___serialize__ (sshQ_L_133Cont self, $Serial$state state) {
    $step_serialize(self->C_cont, state);
}
sshQ_L_133Cont sshQ_L_133ContD___deserialize__ (sshQ_L_133Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_133Cont));
            self->$class = &sshQ_L_133ContG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_133Cont, state);
    }
    self->C_cont = $step_deserialize(state);
    return self;
}
sshQ_L_133Cont sshQ_L_133ContG_new($Cont G_1) {
    sshQ_L_133Cont $tmp = acton_malloc(sizeof(struct sshQ_L_133Cont));
    $tmp->$class = &sshQ_L_133ContG_methods;
    sshQ_L_133ContG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct sshQ_L_133ContG_class sshQ_L_133ContG_methods;
B_NoneType sshQ_L_134procD___init__ (sshQ_L_134proc L_self, sshQ_ServerChannel self) {
    ((sshQ_L_134proc)(L_self))->self = self;
    return B_None;
}
$R sshQ_L_134procD___call__ (sshQ_L_134proc L_self, $Cont C_cont) {
    sshQ_ServerChannel self = ((sshQ_L_134proc)(L_self))->self;
    return (($R (*) ($WORD, $Cont))((sshQ_ServerChannel)(self))->$class->accept_requestG_local)(self, C_cont);
}
$R sshQ_L_134procD___exec__ (sshQ_L_134proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((sshQ_L_134proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void sshQ_L_134procD___serialize__ (sshQ_L_134proc self, $Serial$state state) {
    $step_serialize(self->self, state);
}
sshQ_L_134proc sshQ_L_134procD___deserialize__ (sshQ_L_134proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_134proc));
            self->$class = &sshQ_L_134procG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_134proc, state);
    }
    self->self = $step_deserialize(state);
    return self;
}
sshQ_L_134proc sshQ_L_134procG_new(sshQ_ServerChannel G_1) {
    sshQ_L_134proc $tmp = acton_malloc(sizeof(struct sshQ_L_134proc));
    $tmp->$class = &sshQ_L_134procG_methods;
    sshQ_L_134procG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct sshQ_L_134procG_class sshQ_L_134procG_methods;
B_NoneType sshQ_L_135procD___init__ (sshQ_L_135proc L_self, sshQ_ServerChannel self) {
    ((sshQ_L_135proc)(L_self))->self = self;
    return B_None;
}
$R sshQ_L_135procD___call__ (sshQ_L_135proc L_self, $Cont C_cont) {
    sshQ_ServerChannel self = ((sshQ_L_135proc)(L_self))->self;
    return (($R (*) ($WORD, $Cont))((sshQ_ServerChannel)(self))->$class->accept_openG_local)(self, C_cont);
}
$R sshQ_L_135procD___exec__ (sshQ_L_135proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((sshQ_L_135proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void sshQ_L_135procD___serialize__ (sshQ_L_135proc self, $Serial$state state) {
    $step_serialize(self->self, state);
}
sshQ_L_135proc sshQ_L_135procD___deserialize__ (sshQ_L_135proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_135proc));
            self->$class = &sshQ_L_135procG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_135proc, state);
    }
    self->self = $step_deserialize(state);
    return self;
}
sshQ_L_135proc sshQ_L_135procG_new(sshQ_ServerChannel G_1) {
    sshQ_L_135proc $tmp = acton_malloc(sizeof(struct sshQ_L_135proc));
    $tmp->$class = &sshQ_L_135procG_methods;
    sshQ_L_135procG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct sshQ_L_135procG_class sshQ_L_135procG_methods;
B_NoneType sshQ_L_136procD___init__ (sshQ_L_136proc L_self, sshQ_ServerChannel self, B_str reason) {
    ((sshQ_L_136proc)(L_self))->self = self;
    ((sshQ_L_136proc)(L_self))->reason = reason;
    return B_None;
}
$R sshQ_L_136procD___call__ (sshQ_L_136proc L_self, $Cont C_cont) {
    sshQ_ServerChannel self = ((sshQ_L_136proc)(L_self))->self;
    B_str reason = ((sshQ_L_136proc)(L_self))->reason;
    return (($R (*) ($WORD, $Cont, B_str))((sshQ_ServerChannel)(self))->$class->reject_requestG_local)(self, C_cont, reason);
}
$R sshQ_L_136procD___exec__ (sshQ_L_136proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((sshQ_L_136proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void sshQ_L_136procD___serialize__ (sshQ_L_136proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->reason, state);
}
sshQ_L_136proc sshQ_L_136procD___deserialize__ (sshQ_L_136proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_136proc));
            self->$class = &sshQ_L_136procG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_136proc, state);
    }
    self->self = $step_deserialize(state);
    self->reason = $step_deserialize(state);
    return self;
}
sshQ_L_136proc sshQ_L_136procG_new(sshQ_ServerChannel G_1, B_str G_2) {
    sshQ_L_136proc $tmp = acton_malloc(sizeof(struct sshQ_L_136proc));
    $tmp->$class = &sshQ_L_136procG_methods;
    sshQ_L_136procG_methods.__init__($tmp, G_1, G_2);
    return $tmp;
}
struct sshQ_L_136procG_class sshQ_L_136procG_methods;
B_NoneType sshQ_L_137procD___init__ (sshQ_L_137proc L_self, sshQ_ServerChannel self, B_bytes data) {
    ((sshQ_L_137proc)(L_self))->self = self;
    ((sshQ_L_137proc)(L_self))->data = data;
    return B_None;
}
$R sshQ_L_137procD___call__ (sshQ_L_137proc L_self, $Cont C_cont) {
    sshQ_ServerChannel self = ((sshQ_L_137proc)(L_self))->self;
    B_bytes data = ((sshQ_L_137proc)(L_self))->data;
    return (($R (*) ($WORD, $Cont, B_bytes))((sshQ_ServerChannel)(self))->$class->writeG_local)(self, C_cont, data);
}
$R sshQ_L_137procD___exec__ (sshQ_L_137proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((sshQ_L_137proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void sshQ_L_137procD___serialize__ (sshQ_L_137proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->data, state);
}
sshQ_L_137proc sshQ_L_137procD___deserialize__ (sshQ_L_137proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_137proc));
            self->$class = &sshQ_L_137procG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_137proc, state);
    }
    self->self = $step_deserialize(state);
    self->data = $step_deserialize(state);
    return self;
}
sshQ_L_137proc sshQ_L_137procG_new(sshQ_ServerChannel G_1, B_bytes G_2) {
    sshQ_L_137proc $tmp = acton_malloc(sizeof(struct sshQ_L_137proc));
    $tmp->$class = &sshQ_L_137procG_methods;
    sshQ_L_137procG_methods.__init__($tmp, G_1, G_2);
    return $tmp;
}
struct sshQ_L_137procG_class sshQ_L_137procG_methods;
B_NoneType sshQ_L_138procD___init__ (sshQ_L_138proc L_self, sshQ_ServerChannel self, B_bytes data) {
    ((sshQ_L_138proc)(L_self))->self = self;
    ((sshQ_L_138proc)(L_self))->data = data;
    return B_None;
}
$R sshQ_L_138procD___call__ (sshQ_L_138proc L_self, $Cont C_cont) {
    sshQ_ServerChannel self = ((sshQ_L_138proc)(L_self))->self;
    B_bytes data = ((sshQ_L_138proc)(L_self))->data;
    return (($R (*) ($WORD, $Cont, B_bytes))((sshQ_ServerChannel)(self))->$class->write_stderrG_local)(self, C_cont, data);
}
$R sshQ_L_138procD___exec__ (sshQ_L_138proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((sshQ_L_138proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void sshQ_L_138procD___serialize__ (sshQ_L_138proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $step_serialize(self->data, state);
}
sshQ_L_138proc sshQ_L_138procD___deserialize__ (sshQ_L_138proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_138proc));
            self->$class = &sshQ_L_138procG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_138proc, state);
    }
    self->self = $step_deserialize(state);
    self->data = $step_deserialize(state);
    return self;
}
sshQ_L_138proc sshQ_L_138procG_new(sshQ_ServerChannel G_1, B_bytes G_2) {
    sshQ_L_138proc $tmp = acton_malloc(sizeof(struct sshQ_L_138proc));
    $tmp->$class = &sshQ_L_138procG_methods;
    sshQ_L_138procG_methods.__init__($tmp, G_1, G_2);
    return $tmp;
}
struct sshQ_L_138procG_class sshQ_L_138procG_methods;
B_NoneType sshQ_L_139procD___init__ (sshQ_L_139proc L_self, sshQ_ServerChannel self) {
    ((sshQ_L_139proc)(L_self))->self = self;
    return B_None;
}
$R sshQ_L_139procD___call__ (sshQ_L_139proc L_self, $Cont C_cont) {
    sshQ_ServerChannel self = ((sshQ_L_139proc)(L_self))->self;
    return (($R (*) ($WORD, $Cont))((sshQ_ServerChannel)(self))->$class->send_eofG_local)(self, C_cont);
}
$R sshQ_L_139procD___exec__ (sshQ_L_139proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((sshQ_L_139proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void sshQ_L_139procD___serialize__ (sshQ_L_139proc self, $Serial$state state) {
    $step_serialize(self->self, state);
}
sshQ_L_139proc sshQ_L_139procD___deserialize__ (sshQ_L_139proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_139proc));
            self->$class = &sshQ_L_139procG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_139proc, state);
    }
    self->self = $step_deserialize(state);
    return self;
}
sshQ_L_139proc sshQ_L_139procG_new(sshQ_ServerChannel G_1) {
    sshQ_L_139proc $tmp = acton_malloc(sizeof(struct sshQ_L_139proc));
    $tmp->$class = &sshQ_L_139procG_methods;
    sshQ_L_139procG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct sshQ_L_139procG_class sshQ_L_139procG_methods;
B_NoneType sshQ_L_140procD___init__ (sshQ_L_140proc L_self, sshQ_ServerChannel self, int64_t status) {
    ((sshQ_L_140proc)(L_self))->self = self;
    ((sshQ_L_140proc)(L_self))->status = status;
    return B_None;
}
$R sshQ_L_140procD___call__ (sshQ_L_140proc L_self, $Cont C_cont) {
    sshQ_ServerChannel self = ((sshQ_L_140proc)(L_self))->self;
    int64_t status = ((int64_t)((sshQ_L_140proc)(L_self))->status);
    return (($R (*) ($WORD, $Cont, int64_t))((sshQ_ServerChannel)(self))->$class->send_exit_statusG_local)(self, C_cont, status);
}
$R sshQ_L_140procD___exec__ (sshQ_L_140proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((sshQ_L_140proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void sshQ_L_140procD___serialize__ (sshQ_L_140proc self, $Serial$state state) {
    $step_serialize(self->self, state);
    $val_serialize(I64_ID, &self->status, state);
}
sshQ_L_140proc sshQ_L_140procD___deserialize__ (sshQ_L_140proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_140proc));
            self->$class = &sshQ_L_140procG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_140proc, state);
    }
    self->self = $step_deserialize(state);
    $tmp = $val_deserialize(state);
    memcpy(&self->status, &$tmp, sizeof(self->status));
    return self;
}
sshQ_L_140proc sshQ_L_140procG_new(sshQ_ServerChannel G_1, int64_t G_2) {
    sshQ_L_140proc $tmp = acton_malloc(sizeof(struct sshQ_L_140proc));
    $tmp->$class = &sshQ_L_140procG_methods;
    sshQ_L_140procG_methods.__init__($tmp, G_1, G_2);
    return $tmp;
}
struct sshQ_L_140procG_class sshQ_L_140procG_methods;
B_NoneType sshQ_L_141procD___init__ (sshQ_L_141proc L_self, sshQ_ServerChannel self) {
    ((sshQ_L_141proc)(L_self))->self = self;
    return B_None;
}
$R sshQ_L_141procD___call__ (sshQ_L_141proc L_self, $Cont C_cont) {
    sshQ_ServerChannel self = ((sshQ_L_141proc)(L_self))->self;
    return (($R (*) ($WORD, $Cont))((sshQ_ServerChannel)(self))->$class->closeG_local)(self, C_cont);
}
$R sshQ_L_141procD___exec__ (sshQ_L_141proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((sshQ_L_141proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void sshQ_L_141procD___serialize__ (sshQ_L_141proc self, $Serial$state state) {
    $step_serialize(self->self, state);
}
sshQ_L_141proc sshQ_L_141procD___deserialize__ (sshQ_L_141proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_141proc));
            self->$class = &sshQ_L_141procG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_141proc, state);
    }
    self->self = $step_deserialize(state);
    return self;
}
sshQ_L_141proc sshQ_L_141procG_new(sshQ_ServerChannel G_1) {
    sshQ_L_141proc $tmp = acton_malloc(sizeof(struct sshQ_L_141proc));
    $tmp->$class = &sshQ_L_141procG_methods;
    sshQ_L_141procG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct sshQ_L_141procG_class sshQ_L_141procG_methods;
B_NoneType sshQ_L_142procD___init__ (sshQ_L_142proc L_self, sshQ_ServerChannel self) {
    ((sshQ_L_142proc)(L_self))->self = self;
    return B_None;
}
$R sshQ_L_142procD___call__ (sshQ_L_142proc L_self, $Cont C_cont) {
    sshQ_ServerChannel self = ((sshQ_L_142proc)(L_self))->self;
    return (($R (*) ($WORD, $Cont))((sshQ_ServerChannel)(self))->$class->_cleanup_nativeG_local)(self, C_cont);
}
$R sshQ_L_142procD___exec__ (sshQ_L_142proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((sshQ_L_142proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void sshQ_L_142procD___serialize__ (sshQ_L_142proc self, $Serial$state state) {
    $step_serialize(self->self, state);
}
sshQ_L_142proc sshQ_L_142procD___deserialize__ (sshQ_L_142proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_142proc));
            self->$class = &sshQ_L_142procG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_142proc, state);
    }
    self->self = $step_deserialize(state);
    return self;
}
sshQ_L_142proc sshQ_L_142procG_new(sshQ_ServerChannel G_1) {
    sshQ_L_142proc $tmp = acton_malloc(sizeof(struct sshQ_L_142proc));
    $tmp->$class = &sshQ_L_142procG_methods;
    sshQ_L_142procG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct sshQ_L_142procG_class sshQ_L_142procG_methods;
B_NoneType sshQ_L_143procD___init__ (sshQ_L_143proc L_self, sshQ_ServerChannel self) {
    ((sshQ_L_143proc)(L_self))->self = self;
    return B_None;
}
$R sshQ_L_143procD___call__ (sshQ_L_143proc L_self, $Cont C_cont) {
    sshQ_ServerChannel self = ((sshQ_L_143proc)(L_self))->self;
    return (($R (*) ($WORD, $Cont))((sshQ_ServerChannel)(self))->$class->__cleanup__G_local)(self, C_cont);
}
$R sshQ_L_143procD___exec__ (sshQ_L_143proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((sshQ_L_143proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void sshQ_L_143procD___serialize__ (sshQ_L_143proc self, $Serial$state state) {
    $step_serialize(self->self, state);
}
sshQ_L_143proc sshQ_L_143procD___deserialize__ (sshQ_L_143proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_143proc));
            self->$class = &sshQ_L_143procG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_143proc, state);
    }
    self->self = $step_deserialize(state);
    return self;
}
sshQ_L_143proc sshQ_L_143procG_new(sshQ_ServerChannel G_1) {
    sshQ_L_143proc $tmp = acton_malloc(sizeof(struct sshQ_L_143proc));
    $tmp->$class = &sshQ_L_143procG_methods;
    sshQ_L_143procG_methods.__init__($tmp, G_1);
    return $tmp;
}
struct sshQ_L_143procG_class sshQ_L_143procG_methods;
$R sshQ_L_144C_55cont ($Cont C_cont, sshQ_Client G_act, B_NoneType C_56res) {
    return $R_CONT(C_cont, G_act);
}
B_NoneType sshQ_L_145ContD___init__ (sshQ_L_145Cont L_self, $Cont C_cont, sshQ_Client G_act) {
    ((sshQ_L_145Cont)(L_self))->C_cont = C_cont;
    ((sshQ_L_145Cont)(L_self))->G_act = G_act;
    return B_None;
}
$R sshQ_L_145ContD___call__ (sshQ_L_145Cont L_self, B_NoneType G_1) {
    $Cont C_cont = ((sshQ_L_145Cont)(L_self))->C_cont;
    sshQ_Client G_act = ((sshQ_L_145Cont)(L_self))->G_act;
    return sshQ_L_144C_55cont(C_cont, G_act, G_1);
}
void sshQ_L_145ContD___serialize__ (sshQ_L_145Cont self, $Serial$state state) {
    $step_serialize(self->C_cont, state);
    $step_serialize(self->G_act, state);
}
sshQ_L_145Cont sshQ_L_145ContD___deserialize__ (sshQ_L_145Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_145Cont));
            self->$class = &sshQ_L_145ContG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_145Cont, state);
    }
    self->C_cont = $step_deserialize(state);
    self->G_act = $step_deserialize(state);
    return self;
}
sshQ_L_145Cont sshQ_L_145ContG_new($Cont G_1, sshQ_Client G_2) {
    sshQ_L_145Cont $tmp = acton_malloc(sizeof(struct sshQ_L_145Cont));
    $tmp->$class = &sshQ_L_145ContG_methods;
    sshQ_L_145ContG_methods.__init__($tmp, G_1, G_2);
    return $tmp;
}
struct sshQ_L_145ContG_class sshQ_L_145ContG_methods;
B_NoneType sshQ_L_146procD___init__ (sshQ_L_146proc L_self, sshQ_Client G_act, netQ_TCPConnectCap cap, B_str host, B_str username, $action on_connect, $action on_close, $action N_default_on_hostkey, B_str N_default_password, B_str N_default_private_key_file, B_str N_default_private_key_passphrase, B_u16 N_default_port, B_str N_default_known_hosts, B_float N_default_connect_timeout, B_float N_default_auth_timeout, B_float N_default_keepalive_interval, B_bool N_default_keepalive_enabled, B_float N_default_close_timeout, B_int N_default_max_write_buffer) {
    ((sshQ_L_146proc)(L_self))->G_act = G_act;
    ((sshQ_L_146proc)(L_self))->cap = cap;
    ((sshQ_L_146proc)(L_self))->host = host;
    ((sshQ_L_146proc)(L_self))->username = username;
    ((sshQ_L_146proc)(L_self))->on_connect = on_connect;
    ((sshQ_L_146proc)(L_self))->on_close = on_close;
    ((sshQ_L_146proc)(L_self))->N_default_on_hostkey = N_default_on_hostkey;
    ((sshQ_L_146proc)(L_self))->N_default_password = N_default_password;
    ((sshQ_L_146proc)(L_self))->N_default_private_key_file = N_default_private_key_file;
    ((sshQ_L_146proc)(L_self))->N_default_private_key_passphrase = N_default_private_key_passphrase;
    ((sshQ_L_146proc)(L_self))->N_default_port = N_default_port;
    ((sshQ_L_146proc)(L_self))->N_default_known_hosts = N_default_known_hosts;
    ((sshQ_L_146proc)(L_self))->N_default_connect_timeout = N_default_connect_timeout;
    ((sshQ_L_146proc)(L_self))->N_default_auth_timeout = N_default_auth_timeout;
    ((sshQ_L_146proc)(L_self))->N_default_keepalive_interval = N_default_keepalive_interval;
    ((sshQ_L_146proc)(L_self))->N_default_keepalive_enabled = N_default_keepalive_enabled;
    ((sshQ_L_146proc)(L_self))->N_default_close_timeout = N_default_close_timeout;
    ((sshQ_L_146proc)(L_self))->N_default_max_write_buffer = N_default_max_write_buffer;
    return B_None;
}
$R sshQ_L_146procD___call__ (sshQ_L_146proc L_self, $Cont C_cont) {
    sshQ_Client G_act = ((sshQ_L_146proc)(L_self))->G_act;
    netQ_TCPConnectCap cap = ((sshQ_L_146proc)(L_self))->cap;
    B_str host = ((sshQ_L_146proc)(L_self))->host;
    B_str username = ((sshQ_L_146proc)(L_self))->username;
    $action on_connect = ((sshQ_L_146proc)(L_self))->on_connect;
    $action on_close = ((sshQ_L_146proc)(L_self))->on_close;
    $action N_default_on_hostkey = ((sshQ_L_146proc)(L_self))->N_default_on_hostkey;
    B_str N_default_password = ((sshQ_L_146proc)(L_self))->N_default_password;
    B_str N_default_private_key_file = ((sshQ_L_146proc)(L_self))->N_default_private_key_file;
    B_str N_default_private_key_passphrase = ((sshQ_L_146proc)(L_self))->N_default_private_key_passphrase;
    B_u16 N_default_port = ((sshQ_L_146proc)(L_self))->N_default_port;
    B_str N_default_known_hosts = ((sshQ_L_146proc)(L_self))->N_default_known_hosts;
    B_float N_default_connect_timeout = ((sshQ_L_146proc)(L_self))->N_default_connect_timeout;
    B_float N_default_auth_timeout = ((sshQ_L_146proc)(L_self))->N_default_auth_timeout;
    B_float N_default_keepalive_interval = ((sshQ_L_146proc)(L_self))->N_default_keepalive_interval;
    B_bool N_default_keepalive_enabled = ((sshQ_L_146proc)(L_self))->N_default_keepalive_enabled;
    B_float N_default_close_timeout = ((sshQ_L_146proc)(L_self))->N_default_close_timeout;
    B_int N_default_max_write_buffer = ((sshQ_L_146proc)(L_self))->N_default_max_write_buffer;
    return (($R (*) ($WORD, $Cont, netQ_TCPConnectCap, B_str, B_str, $action, $action, $action, B_str, B_str, B_str, B_u16, B_str, B_float, B_float, B_float, B_bool, B_float, B_int))((sshQ_Client)(G_act))->$class->__init__)(G_act, C_cont, cap, host, username, on_connect, on_close, N_default_on_hostkey, N_default_password, N_default_private_key_file, N_default_private_key_passphrase, N_default_port, N_default_known_hosts, N_default_connect_timeout, N_default_auth_timeout, N_default_keepalive_interval, N_default_keepalive_enabled, N_default_close_timeout, N_default_max_write_buffer);
}
$R sshQ_L_146procD___exec__ (sshQ_L_146proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((sshQ_L_146proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void sshQ_L_146procD___serialize__ (sshQ_L_146proc self, $Serial$state state) {
    $step_serialize(self->G_act, state);
    $step_serialize(self->cap, state);
    $step_serialize(self->host, state);
    $step_serialize(self->username, state);
    $step_serialize(self->on_connect, state);
    $step_serialize(self->on_close, state);
    $step_serialize(self->N_default_on_hostkey, state);
    $step_serialize(self->N_default_password, state);
    $step_serialize(self->N_default_private_key_file, state);
    $step_serialize(self->N_default_private_key_passphrase, state);
    $step_serialize(self->N_default_port, state);
    $step_serialize(self->N_default_known_hosts, state);
    $step_serialize(self->N_default_connect_timeout, state);
    $step_serialize(self->N_default_auth_timeout, state);
    $step_serialize(self->N_default_keepalive_interval, state);
    $step_serialize(self->N_default_keepalive_enabled, state);
    $step_serialize(self->N_default_close_timeout, state);
    $step_serialize(self->N_default_max_write_buffer, state);
}
sshQ_L_146proc sshQ_L_146procD___deserialize__ (sshQ_L_146proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_146proc));
            self->$class = &sshQ_L_146procG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_146proc, state);
    }
    self->G_act = $step_deserialize(state);
    self->cap = $step_deserialize(state);
    self->host = $step_deserialize(state);
    self->username = $step_deserialize(state);
    self->on_connect = $step_deserialize(state);
    self->on_close = $step_deserialize(state);
    self->N_default_on_hostkey = $step_deserialize(state);
    self->N_default_password = $step_deserialize(state);
    self->N_default_private_key_file = $step_deserialize(state);
    self->N_default_private_key_passphrase = $step_deserialize(state);
    self->N_default_port = $step_deserialize(state);
    self->N_default_known_hosts = $step_deserialize(state);
    self->N_default_connect_timeout = $step_deserialize(state);
    self->N_default_auth_timeout = $step_deserialize(state);
    self->N_default_keepalive_interval = $step_deserialize(state);
    self->N_default_keepalive_enabled = $step_deserialize(state);
    self->N_default_close_timeout = $step_deserialize(state);
    self->N_default_max_write_buffer = $step_deserialize(state);
    return self;
}
sshQ_L_146proc sshQ_L_146procG_new(sshQ_Client G_1, netQ_TCPConnectCap G_2, B_str G_3, B_str G_4, $action G_5, $action G_6, $action G_7, B_str G_8, B_str G_9, B_str G_10, B_u16 G_11, B_str G_12, B_float G_13, B_float G_14, B_float G_15, B_bool G_16, B_float G_17, B_int G_18) {
    sshQ_L_146proc $tmp = acton_malloc(sizeof(struct sshQ_L_146proc));
    $tmp->$class = &sshQ_L_146procG_methods;
    sshQ_L_146procG_methods.__init__($tmp, G_1, G_2, G_3, G_4, G_5, G_6, G_7, G_8, G_9, G_10, G_11, G_12, G_13, G_14, G_15, G_16, G_17, G_18);
    return $tmp;
}
struct sshQ_L_146procG_class sshQ_L_146procG_methods;
$R sshQ_L_147C_57cont ($Cont C_cont, sshQ_Channel G_act, B_NoneType C_58res) {
    return $R_CONT(C_cont, G_act);
}
B_NoneType sshQ_L_148ContD___init__ (sshQ_L_148Cont L_self, $Cont C_cont, sshQ_Channel G_act) {
    ((sshQ_L_148Cont)(L_self))->C_cont = C_cont;
    ((sshQ_L_148Cont)(L_self))->G_act = G_act;
    return B_None;
}
$R sshQ_L_148ContD___call__ (sshQ_L_148Cont L_self, B_NoneType G_1) {
    $Cont C_cont = ((sshQ_L_148Cont)(L_self))->C_cont;
    sshQ_Channel G_act = ((sshQ_L_148Cont)(L_self))->G_act;
    return sshQ_L_147C_57cont(C_cont, G_act, G_1);
}
void sshQ_L_148ContD___serialize__ (sshQ_L_148Cont self, $Serial$state state) {
    $step_serialize(self->C_cont, state);
    $step_serialize(self->G_act, state);
}
sshQ_L_148Cont sshQ_L_148ContD___deserialize__ (sshQ_L_148Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_148Cont));
            self->$class = &sshQ_L_148ContG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_148Cont, state);
    }
    self->C_cont = $step_deserialize(state);
    self->G_act = $step_deserialize(state);
    return self;
}
sshQ_L_148Cont sshQ_L_148ContG_new($Cont G_1, sshQ_Channel G_2) {
    sshQ_L_148Cont $tmp = acton_malloc(sizeof(struct sshQ_L_148Cont));
    $tmp->$class = &sshQ_L_148ContG_methods;
    sshQ_L_148ContG_methods.__init__($tmp, G_1, G_2);
    return $tmp;
}
struct sshQ_L_148ContG_class sshQ_L_148ContG_methods;
B_NoneType sshQ_L_149procD___init__ (sshQ_L_149proc L_self, sshQ_Channel G_act, sshQ_Client client, $action on_open, $action on_stdout, $action on_stderr, $action on_exit, $action on_close) {
    ((sshQ_L_149proc)(L_self))->G_act = G_act;
    ((sshQ_L_149proc)(L_self))->client = client;
    ((sshQ_L_149proc)(L_self))->on_open = on_open;
    ((sshQ_L_149proc)(L_self))->on_stdout = on_stdout;
    ((sshQ_L_149proc)(L_self))->on_stderr = on_stderr;
    ((sshQ_L_149proc)(L_self))->on_exit = on_exit;
    ((sshQ_L_149proc)(L_self))->on_close = on_close;
    return B_None;
}
$R sshQ_L_149procD___call__ (sshQ_L_149proc L_self, $Cont C_cont) {
    sshQ_Channel G_act = ((sshQ_L_149proc)(L_self))->G_act;
    sshQ_Client client = ((sshQ_L_149proc)(L_self))->client;
    $action on_open = ((sshQ_L_149proc)(L_self))->on_open;
    $action on_stdout = ((sshQ_L_149proc)(L_self))->on_stdout;
    $action on_stderr = ((sshQ_L_149proc)(L_self))->on_stderr;
    $action on_exit = ((sshQ_L_149proc)(L_self))->on_exit;
    $action on_close = ((sshQ_L_149proc)(L_self))->on_close;
    return (($R (*) ($WORD, $Cont, sshQ_Client, $action, $action, $action, $action, $action))((sshQ_Channel)(G_act))->$class->__init__)(G_act, C_cont, client, on_open, on_stdout, on_stderr, on_exit, on_close);
}
$R sshQ_L_149procD___exec__ (sshQ_L_149proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((sshQ_L_149proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void sshQ_L_149procD___serialize__ (sshQ_L_149proc self, $Serial$state state) {
    $step_serialize(self->G_act, state);
    $step_serialize(self->client, state);
    $step_serialize(self->on_open, state);
    $step_serialize(self->on_stdout, state);
    $step_serialize(self->on_stderr, state);
    $step_serialize(self->on_exit, state);
    $step_serialize(self->on_close, state);
}
sshQ_L_149proc sshQ_L_149procD___deserialize__ (sshQ_L_149proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_149proc));
            self->$class = &sshQ_L_149procG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_149proc, state);
    }
    self->G_act = $step_deserialize(state);
    self->client = $step_deserialize(state);
    self->on_open = $step_deserialize(state);
    self->on_stdout = $step_deserialize(state);
    self->on_stderr = $step_deserialize(state);
    self->on_exit = $step_deserialize(state);
    self->on_close = $step_deserialize(state);
    return self;
}
sshQ_L_149proc sshQ_L_149procG_new(sshQ_Channel G_1, sshQ_Client G_2, $action G_3, $action G_4, $action G_5, $action G_6, $action G_7) {
    sshQ_L_149proc $tmp = acton_malloc(sizeof(struct sshQ_L_149proc));
    $tmp->$class = &sshQ_L_149procG_methods;
    sshQ_L_149procG_methods.__init__($tmp, G_1, G_2, G_3, G_4, G_5, G_6, G_7);
    return $tmp;
}
struct sshQ_L_149procG_class sshQ_L_149procG_methods;
$R sshQ_L_150C_59cont ($Cont C_cont, sshQ_RunCommand G_act, B_NoneType C_60res) {
    return $R_CONT(C_cont, G_act);
}
B_NoneType sshQ_L_151ContD___init__ (sshQ_L_151Cont L_self, $Cont C_cont, sshQ_RunCommand G_act) {
    ((sshQ_L_151Cont)(L_self))->C_cont = C_cont;
    ((sshQ_L_151Cont)(L_self))->G_act = G_act;
    return B_None;
}
$R sshQ_L_151ContD___call__ (sshQ_L_151Cont L_self, B_NoneType G_1) {
    $Cont C_cont = ((sshQ_L_151Cont)(L_self))->C_cont;
    sshQ_RunCommand G_act = ((sshQ_L_151Cont)(L_self))->G_act;
    return sshQ_L_150C_59cont(C_cont, G_act, G_1);
}
void sshQ_L_151ContD___serialize__ (sshQ_L_151Cont self, $Serial$state state) {
    $step_serialize(self->C_cont, state);
    $step_serialize(self->G_act, state);
}
sshQ_L_151Cont sshQ_L_151ContD___deserialize__ (sshQ_L_151Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_151Cont));
            self->$class = &sshQ_L_151ContG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_151Cont, state);
    }
    self->C_cont = $step_deserialize(state);
    self->G_act = $step_deserialize(state);
    return self;
}
sshQ_L_151Cont sshQ_L_151ContG_new($Cont G_1, sshQ_RunCommand G_2) {
    sshQ_L_151Cont $tmp = acton_malloc(sizeof(struct sshQ_L_151Cont));
    $tmp->$class = &sshQ_L_151ContG_methods;
    sshQ_L_151ContG_methods.__init__($tmp, G_1, G_2);
    return $tmp;
}
struct sshQ_L_151ContG_class sshQ_L_151ContG_methods;
B_NoneType sshQ_L_152procD___init__ (sshQ_L_152proc L_self, sshQ_RunCommand G_act, sshQ_Client client, B_str cmd, $action on_exit, B_float N_default_timeout) {
    ((sshQ_L_152proc)(L_self))->G_act = G_act;
    ((sshQ_L_152proc)(L_self))->client = client;
    ((sshQ_L_152proc)(L_self))->cmd = cmd;
    ((sshQ_L_152proc)(L_self))->on_exit = on_exit;
    ((sshQ_L_152proc)(L_self))->N_default_timeout = N_default_timeout;
    return B_None;
}
$R sshQ_L_152procD___call__ (sshQ_L_152proc L_self, $Cont C_cont) {
    sshQ_RunCommand G_act = ((sshQ_L_152proc)(L_self))->G_act;
    sshQ_Client client = ((sshQ_L_152proc)(L_self))->client;
    B_str cmd = ((sshQ_L_152proc)(L_self))->cmd;
    $action on_exit = ((sshQ_L_152proc)(L_self))->on_exit;
    B_float N_default_timeout = ((sshQ_L_152proc)(L_self))->N_default_timeout;
    return (($R (*) ($WORD, $Cont, sshQ_Client, B_str, $action, B_float))((sshQ_RunCommand)(G_act))->$class->__init__)(G_act, C_cont, client, cmd, on_exit, N_default_timeout);
}
$R sshQ_L_152procD___exec__ (sshQ_L_152proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((sshQ_L_152proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void sshQ_L_152procD___serialize__ (sshQ_L_152proc self, $Serial$state state) {
    $step_serialize(self->G_act, state);
    $step_serialize(self->client, state);
    $step_serialize(self->cmd, state);
    $step_serialize(self->on_exit, state);
    $step_serialize(self->N_default_timeout, state);
}
sshQ_L_152proc sshQ_L_152procD___deserialize__ (sshQ_L_152proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_152proc));
            self->$class = &sshQ_L_152procG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_152proc, state);
    }
    self->G_act = $step_deserialize(state);
    self->client = $step_deserialize(state);
    self->cmd = $step_deserialize(state);
    self->on_exit = $step_deserialize(state);
    self->N_default_timeout = $step_deserialize(state);
    return self;
}
sshQ_L_152proc sshQ_L_152procG_new(sshQ_RunCommand G_1, sshQ_Client G_2, B_str G_3, $action G_4, B_float G_5) {
    sshQ_L_152proc $tmp = acton_malloc(sizeof(struct sshQ_L_152proc));
    $tmp->$class = &sshQ_L_152procG_methods;
    sshQ_L_152procG_methods.__init__($tmp, G_1, G_2, G_3, G_4, G_5);
    return $tmp;
}
struct sshQ_L_152procG_class sshQ_L_152procG_methods;
$R sshQ_L_153C_61cont ($Cont C_cont, sshQ_Server G_act, B_NoneType C_62res) {
    return $R_CONT(C_cont, G_act);
}
B_NoneType sshQ_L_154ContD___init__ (sshQ_L_154Cont L_self, $Cont C_cont, sshQ_Server G_act) {
    ((sshQ_L_154Cont)(L_self))->C_cont = C_cont;
    ((sshQ_L_154Cont)(L_self))->G_act = G_act;
    return B_None;
}
$R sshQ_L_154ContD___call__ (sshQ_L_154Cont L_self, B_NoneType G_1) {
    $Cont C_cont = ((sshQ_L_154Cont)(L_self))->C_cont;
    sshQ_Server G_act = ((sshQ_L_154Cont)(L_self))->G_act;
    return sshQ_L_153C_61cont(C_cont, G_act, G_1);
}
void sshQ_L_154ContD___serialize__ (sshQ_L_154Cont self, $Serial$state state) {
    $step_serialize(self->C_cont, state);
    $step_serialize(self->G_act, state);
}
sshQ_L_154Cont sshQ_L_154ContD___deserialize__ (sshQ_L_154Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_154Cont));
            self->$class = &sshQ_L_154ContG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_154Cont, state);
    }
    self->C_cont = $step_deserialize(state);
    self->G_act = $step_deserialize(state);
    return self;
}
sshQ_L_154Cont sshQ_L_154ContG_new($Cont G_1, sshQ_Server G_2) {
    sshQ_L_154Cont $tmp = acton_malloc(sizeof(struct sshQ_L_154Cont));
    $tmp->$class = &sshQ_L_154ContG_methods;
    sshQ_L_154ContG_methods.__init__($tmp, G_1, G_2);
    return $tmp;
}
struct sshQ_L_154ContG_class sshQ_L_154ContG_methods;
B_NoneType sshQ_L_155procD___init__ (sshQ_L_155proc L_self, sshQ_Server G_act, netQ_TCPListenCap cap, B_str host, uint16_t port, $action on_listen, $action on_close, $action on_session, $action on_auth, $action on_channel_open, $action N_default_on_exec, $action N_default_on_subsystem, $action N_default_on_session_close, B_str N_default_host_key_path, B_str N_default_host_key_type, B_int N_default_host_key_bits, B_float N_default_auth_timeout, B_float N_default_keepalive_interval, B_bool N_default_keepalive_enabled, B_float N_default_close_timeout, B_int N_default_max_sessions, B_int N_default_max_channels_per_session, B_int N_default_max_write_buffer) {
    ((sshQ_L_155proc)(L_self))->G_act = G_act;
    ((sshQ_L_155proc)(L_self))->cap = cap;
    ((sshQ_L_155proc)(L_self))->host = host;
    ((sshQ_L_155proc)(L_self))->port = port;
    ((sshQ_L_155proc)(L_self))->on_listen = on_listen;
    ((sshQ_L_155proc)(L_self))->on_close = on_close;
    ((sshQ_L_155proc)(L_self))->on_session = on_session;
    ((sshQ_L_155proc)(L_self))->on_auth = on_auth;
    ((sshQ_L_155proc)(L_self))->on_channel_open = on_channel_open;
    ((sshQ_L_155proc)(L_self))->N_default_on_exec = N_default_on_exec;
    ((sshQ_L_155proc)(L_self))->N_default_on_subsystem = N_default_on_subsystem;
    ((sshQ_L_155proc)(L_self))->N_default_on_session_close = N_default_on_session_close;
    ((sshQ_L_155proc)(L_self))->N_default_host_key_path = N_default_host_key_path;
    ((sshQ_L_155proc)(L_self))->N_default_host_key_type = N_default_host_key_type;
    ((sshQ_L_155proc)(L_self))->N_default_host_key_bits = N_default_host_key_bits;
    ((sshQ_L_155proc)(L_self))->N_default_auth_timeout = N_default_auth_timeout;
    ((sshQ_L_155proc)(L_self))->N_default_keepalive_interval = N_default_keepalive_interval;
    ((sshQ_L_155proc)(L_self))->N_default_keepalive_enabled = N_default_keepalive_enabled;
    ((sshQ_L_155proc)(L_self))->N_default_close_timeout = N_default_close_timeout;
    ((sshQ_L_155proc)(L_self))->N_default_max_sessions = N_default_max_sessions;
    ((sshQ_L_155proc)(L_self))->N_default_max_channels_per_session = N_default_max_channels_per_session;
    ((sshQ_L_155proc)(L_self))->N_default_max_write_buffer = N_default_max_write_buffer;
    return B_None;
}
$R sshQ_L_155procD___call__ (sshQ_L_155proc L_self, $Cont C_cont) {
    sshQ_Server G_act = ((sshQ_L_155proc)(L_self))->G_act;
    netQ_TCPListenCap cap = ((sshQ_L_155proc)(L_self))->cap;
    B_str host = ((sshQ_L_155proc)(L_self))->host;
    uint16_t port = ((uint16_t)((sshQ_L_155proc)(L_self))->port);
    $action on_listen = ((sshQ_L_155proc)(L_self))->on_listen;
    $action on_close = ((sshQ_L_155proc)(L_self))->on_close;
    $action on_session = ((sshQ_L_155proc)(L_self))->on_session;
    $action on_auth = ((sshQ_L_155proc)(L_self))->on_auth;
    $action on_channel_open = ((sshQ_L_155proc)(L_self))->on_channel_open;
    $action N_default_on_exec = ((sshQ_L_155proc)(L_self))->N_default_on_exec;
    $action N_default_on_subsystem = ((sshQ_L_155proc)(L_self))->N_default_on_subsystem;
    $action N_default_on_session_close = ((sshQ_L_155proc)(L_self))->N_default_on_session_close;
    B_str N_default_host_key_path = ((sshQ_L_155proc)(L_self))->N_default_host_key_path;
    B_str N_default_host_key_type = ((sshQ_L_155proc)(L_self))->N_default_host_key_type;
    B_int N_default_host_key_bits = ((sshQ_L_155proc)(L_self))->N_default_host_key_bits;
    B_float N_default_auth_timeout = ((sshQ_L_155proc)(L_self))->N_default_auth_timeout;
    B_float N_default_keepalive_interval = ((sshQ_L_155proc)(L_self))->N_default_keepalive_interval;
    B_bool N_default_keepalive_enabled = ((sshQ_L_155proc)(L_self))->N_default_keepalive_enabled;
    B_float N_default_close_timeout = ((sshQ_L_155proc)(L_self))->N_default_close_timeout;
    B_int N_default_max_sessions = ((sshQ_L_155proc)(L_self))->N_default_max_sessions;
    B_int N_default_max_channels_per_session = ((sshQ_L_155proc)(L_self))->N_default_max_channels_per_session;
    B_int N_default_max_write_buffer = ((sshQ_L_155proc)(L_self))->N_default_max_write_buffer;
    return (($R (*) ($WORD, $Cont, netQ_TCPListenCap, B_str, uint16_t, $action, $action, $action, $action, $action, $action, $action, $action, B_str, B_str, B_int, B_float, B_float, B_bool, B_float, B_int, B_int, B_int))((sshQ_Server)(G_act))->$class->__init__)(G_act, C_cont, cap, host, port, on_listen, on_close, on_session, on_auth, on_channel_open, N_default_on_exec, N_default_on_subsystem, N_default_on_session_close, N_default_host_key_path, N_default_host_key_type, N_default_host_key_bits, N_default_auth_timeout, N_default_keepalive_interval, N_default_keepalive_enabled, N_default_close_timeout, N_default_max_sessions, N_default_max_channels_per_session, N_default_max_write_buffer);
}
$R sshQ_L_155procD___exec__ (sshQ_L_155proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((sshQ_L_155proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void sshQ_L_155procD___serialize__ (sshQ_L_155proc self, $Serial$state state) {
    $step_serialize(self->G_act, state);
    $step_serialize(self->cap, state);
    $step_serialize(self->host, state);
    $val_serialize(U16_ID, &self->port, state);
    $step_serialize(self->on_listen, state);
    $step_serialize(self->on_close, state);
    $step_serialize(self->on_session, state);
    $step_serialize(self->on_auth, state);
    $step_serialize(self->on_channel_open, state);
    $step_serialize(self->N_default_on_exec, state);
    $step_serialize(self->N_default_on_subsystem, state);
    $step_serialize(self->N_default_on_session_close, state);
    $step_serialize(self->N_default_host_key_path, state);
    $step_serialize(self->N_default_host_key_type, state);
    $step_serialize(self->N_default_host_key_bits, state);
    $step_serialize(self->N_default_auth_timeout, state);
    $step_serialize(self->N_default_keepalive_interval, state);
    $step_serialize(self->N_default_keepalive_enabled, state);
    $step_serialize(self->N_default_close_timeout, state);
    $step_serialize(self->N_default_max_sessions, state);
    $step_serialize(self->N_default_max_channels_per_session, state);
    $step_serialize(self->N_default_max_write_buffer, state);
}
sshQ_L_155proc sshQ_L_155procD___deserialize__ (sshQ_L_155proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_155proc));
            self->$class = &sshQ_L_155procG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_155proc, state);
    }
    self->G_act = $step_deserialize(state);
    self->cap = $step_deserialize(state);
    self->host = $step_deserialize(state);
    $tmp = $val_deserialize(state);
    memcpy(&self->port, &$tmp, sizeof(self->port));
    self->on_listen = $step_deserialize(state);
    self->on_close = $step_deserialize(state);
    self->on_session = $step_deserialize(state);
    self->on_auth = $step_deserialize(state);
    self->on_channel_open = $step_deserialize(state);
    self->N_default_on_exec = $step_deserialize(state);
    self->N_default_on_subsystem = $step_deserialize(state);
    self->N_default_on_session_close = $step_deserialize(state);
    self->N_default_host_key_path = $step_deserialize(state);
    self->N_default_host_key_type = $step_deserialize(state);
    self->N_default_host_key_bits = $step_deserialize(state);
    self->N_default_auth_timeout = $step_deserialize(state);
    self->N_default_keepalive_interval = $step_deserialize(state);
    self->N_default_keepalive_enabled = $step_deserialize(state);
    self->N_default_close_timeout = $step_deserialize(state);
    self->N_default_max_sessions = $step_deserialize(state);
    self->N_default_max_channels_per_session = $step_deserialize(state);
    self->N_default_max_write_buffer = $step_deserialize(state);
    return self;
}
sshQ_L_155proc sshQ_L_155procG_new(sshQ_Server G_1, netQ_TCPListenCap G_2, B_str G_3, uint16_t G_4, $action G_5, $action G_6, $action G_7, $action G_8, $action G_9, $action G_10, $action G_11, $action G_12, B_str G_13, B_str G_14, B_int G_15, B_float G_16, B_float G_17, B_bool G_18, B_float G_19, B_int G_20, B_int G_21, B_int G_22) {
    sshQ_L_155proc $tmp = acton_malloc(sizeof(struct sshQ_L_155proc));
    $tmp->$class = &sshQ_L_155procG_methods;
    sshQ_L_155procG_methods.__init__($tmp, G_1, G_2, G_3, G_4, G_5, G_6, G_7, G_8, G_9, G_10, G_11, G_12, G_13, G_14, G_15, G_16, G_17, G_18, G_19, G_20, G_21, G_22);
    return $tmp;
}
struct sshQ_L_155procG_class sshQ_L_155procG_methods;
$R sshQ_L_156C_63cont ($Cont C_cont, sshQ_ServerSession G_act, B_NoneType C_64res) {
    return $R_CONT(C_cont, G_act);
}
B_NoneType sshQ_L_157ContD___init__ (sshQ_L_157Cont L_self, $Cont C_cont, sshQ_ServerSession G_act) {
    ((sshQ_L_157Cont)(L_self))->C_cont = C_cont;
    ((sshQ_L_157Cont)(L_self))->G_act = G_act;
    return B_None;
}
$R sshQ_L_157ContD___call__ (sshQ_L_157Cont L_self, B_NoneType G_1) {
    $Cont C_cont = ((sshQ_L_157Cont)(L_self))->C_cont;
    sshQ_ServerSession G_act = ((sshQ_L_157Cont)(L_self))->G_act;
    return sshQ_L_156C_63cont(C_cont, G_act, G_1);
}
void sshQ_L_157ContD___serialize__ (sshQ_L_157Cont self, $Serial$state state) {
    $step_serialize(self->C_cont, state);
    $step_serialize(self->G_act, state);
}
sshQ_L_157Cont sshQ_L_157ContD___deserialize__ (sshQ_L_157Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_157Cont));
            self->$class = &sshQ_L_157ContG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_157Cont, state);
    }
    self->C_cont = $step_deserialize(state);
    self->G_act = $step_deserialize(state);
    return self;
}
sshQ_L_157Cont sshQ_L_157ContG_new($Cont G_1, sshQ_ServerSession G_2) {
    sshQ_L_157Cont $tmp = acton_malloc(sizeof(struct sshQ_L_157Cont));
    $tmp->$class = &sshQ_L_157ContG_methods;
    sshQ_L_157ContG_methods.__init__($tmp, G_1, G_2);
    return $tmp;
}
struct sshQ_L_157ContG_class sshQ_L_157ContG_methods;
B_NoneType sshQ_L_158procD___init__ (sshQ_L_158proc L_self, sshQ_ServerSession G_act, sshQ_Server server, uint64_t session_id, $action on_auth, $action on_channel_open, $action N_default_on_exec, $action N_default_on_subsystem, $action N_default_on_close) {
    ((sshQ_L_158proc)(L_self))->G_act = G_act;
    ((sshQ_L_158proc)(L_self))->server = server;
    ((sshQ_L_158proc)(L_self))->session_id = session_id;
    ((sshQ_L_158proc)(L_self))->on_auth = on_auth;
    ((sshQ_L_158proc)(L_self))->on_channel_open = on_channel_open;
    ((sshQ_L_158proc)(L_self))->N_default_on_exec = N_default_on_exec;
    ((sshQ_L_158proc)(L_self))->N_default_on_subsystem = N_default_on_subsystem;
    ((sshQ_L_158proc)(L_self))->N_default_on_close = N_default_on_close;
    return B_None;
}
$R sshQ_L_158procD___call__ (sshQ_L_158proc L_self, $Cont C_cont) {
    sshQ_ServerSession G_act = ((sshQ_L_158proc)(L_self))->G_act;
    sshQ_Server server = ((sshQ_L_158proc)(L_self))->server;
    uint64_t session_id = ((uint64_t)((sshQ_L_158proc)(L_self))->session_id);
    $action on_auth = ((sshQ_L_158proc)(L_self))->on_auth;
    $action on_channel_open = ((sshQ_L_158proc)(L_self))->on_channel_open;
    $action N_default_on_exec = ((sshQ_L_158proc)(L_self))->N_default_on_exec;
    $action N_default_on_subsystem = ((sshQ_L_158proc)(L_self))->N_default_on_subsystem;
    $action N_default_on_close = ((sshQ_L_158proc)(L_self))->N_default_on_close;
    return (($R (*) ($WORD, $Cont, sshQ_Server, uint64_t, $action, $action, $action, $action, $action))((sshQ_ServerSession)(G_act))->$class->__init__)(G_act, C_cont, server, session_id, on_auth, on_channel_open, N_default_on_exec, N_default_on_subsystem, N_default_on_close);
}
$R sshQ_L_158procD___exec__ (sshQ_L_158proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((sshQ_L_158proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void sshQ_L_158procD___serialize__ (sshQ_L_158proc self, $Serial$state state) {
    $step_serialize(self->G_act, state);
    $step_serialize(self->server, state);
    $val_serialize(U64_ID, &self->session_id, state);
    $step_serialize(self->on_auth, state);
    $step_serialize(self->on_channel_open, state);
    $step_serialize(self->N_default_on_exec, state);
    $step_serialize(self->N_default_on_subsystem, state);
    $step_serialize(self->N_default_on_close, state);
}
sshQ_L_158proc sshQ_L_158procD___deserialize__ (sshQ_L_158proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_158proc));
            self->$class = &sshQ_L_158procG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_158proc, state);
    }
    self->G_act = $step_deserialize(state);
    self->server = $step_deserialize(state);
    $tmp = $val_deserialize(state);
    memcpy(&self->session_id, &$tmp, sizeof(self->session_id));
    self->on_auth = $step_deserialize(state);
    self->on_channel_open = $step_deserialize(state);
    self->N_default_on_exec = $step_deserialize(state);
    self->N_default_on_subsystem = $step_deserialize(state);
    self->N_default_on_close = $step_deserialize(state);
    return self;
}
sshQ_L_158proc sshQ_L_158procG_new(sshQ_ServerSession G_1, sshQ_Server G_2, uint64_t G_3, $action G_4, $action G_5, $action G_6, $action G_7, $action G_8) {
    sshQ_L_158proc $tmp = acton_malloc(sizeof(struct sshQ_L_158proc));
    $tmp->$class = &sshQ_L_158procG_methods;
    sshQ_L_158procG_methods.__init__($tmp, G_1, G_2, G_3, G_4, G_5, G_6, G_7, G_8);
    return $tmp;
}
struct sshQ_L_158procG_class sshQ_L_158procG_methods;
$R sshQ_L_159C_65cont ($Cont C_cont, sshQ_ServerChannel G_act, B_NoneType C_66res) {
    return $R_CONT(C_cont, G_act);
}
B_NoneType sshQ_L_160ContD___init__ (sshQ_L_160Cont L_self, $Cont C_cont, sshQ_ServerChannel G_act) {
    ((sshQ_L_160Cont)(L_self))->C_cont = C_cont;
    ((sshQ_L_160Cont)(L_self))->G_act = G_act;
    return B_None;
}
$R sshQ_L_160ContD___call__ (sshQ_L_160Cont L_self, B_NoneType G_1) {
    $Cont C_cont = ((sshQ_L_160Cont)(L_self))->C_cont;
    sshQ_ServerChannel G_act = ((sshQ_L_160Cont)(L_self))->G_act;
    return sshQ_L_159C_65cont(C_cont, G_act, G_1);
}
void sshQ_L_160ContD___serialize__ (sshQ_L_160Cont self, $Serial$state state) {
    $step_serialize(self->C_cont, state);
    $step_serialize(self->G_act, state);
}
sshQ_L_160Cont sshQ_L_160ContD___deserialize__ (sshQ_L_160Cont self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_160Cont));
            self->$class = &sshQ_L_160ContG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_160Cont, state);
    }
    self->C_cont = $step_deserialize(state);
    self->G_act = $step_deserialize(state);
    return self;
}
sshQ_L_160Cont sshQ_L_160ContG_new($Cont G_1, sshQ_ServerChannel G_2) {
    sshQ_L_160Cont $tmp = acton_malloc(sizeof(struct sshQ_L_160Cont));
    $tmp->$class = &sshQ_L_160ContG_methods;
    sshQ_L_160ContG_methods.__init__($tmp, G_1, G_2);
    return $tmp;
}
struct sshQ_L_160ContG_class sshQ_L_160ContG_methods;
B_NoneType sshQ_L_161procD___init__ (sshQ_L_161proc L_self, sshQ_ServerChannel G_act, sshQ_ServerSession session, $action on_data, $action on_stderr, $action on_close) {
    ((sshQ_L_161proc)(L_self))->G_act = G_act;
    ((sshQ_L_161proc)(L_self))->session = session;
    ((sshQ_L_161proc)(L_self))->on_data = on_data;
    ((sshQ_L_161proc)(L_self))->on_stderr = on_stderr;
    ((sshQ_L_161proc)(L_self))->on_close = on_close;
    return B_None;
}
$R sshQ_L_161procD___call__ (sshQ_L_161proc L_self, $Cont C_cont) {
    sshQ_ServerChannel G_act = ((sshQ_L_161proc)(L_self))->G_act;
    sshQ_ServerSession session = ((sshQ_L_161proc)(L_self))->session;
    $action on_data = ((sshQ_L_161proc)(L_self))->on_data;
    $action on_stderr = ((sshQ_L_161proc)(L_self))->on_stderr;
    $action on_close = ((sshQ_L_161proc)(L_self))->on_close;
    return (($R (*) ($WORD, $Cont, sshQ_ServerSession, $action, $action, $action))((sshQ_ServerChannel)(G_act))->$class->__init__)(G_act, C_cont, session, on_data, on_stderr, on_close);
}
$R sshQ_L_161procD___exec__ (sshQ_L_161proc L_self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont))((sshQ_L_161proc)(L_self))->$class->__call__)(L_self, C_cont);
}
void sshQ_L_161procD___serialize__ (sshQ_L_161proc self, $Serial$state state) {
    $step_serialize(self->G_act, state);
    $step_serialize(self->session, state);
    $step_serialize(self->on_data, state);
    $step_serialize(self->on_stderr, state);
    $step_serialize(self->on_close, state);
}
sshQ_L_161proc sshQ_L_161procD___deserialize__ (sshQ_L_161proc self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_L_161proc));
            self->$class = &sshQ_L_161procG_methods;
            return self;
        }
        self = $DNEW(sshQ_L_161proc, state);
    }
    self->G_act = $step_deserialize(state);
    self->session = $step_deserialize(state);
    self->on_data = $step_deserialize(state);
    self->on_stderr = $step_deserialize(state);
    self->on_close = $step_deserialize(state);
    return self;
}
sshQ_L_161proc sshQ_L_161procG_new(sshQ_ServerChannel G_1, sshQ_ServerSession G_2, $action G_3, $action G_4, $action G_5) {
    sshQ_L_161proc $tmp = acton_malloc(sizeof(struct sshQ_L_161proc));
    $tmp->$class = &sshQ_L_161procG_methods;
    sshQ_L_161procG_methods.__init__($tmp, G_1, G_2, G_3, G_4, G_5);
    return $tmp;
}
struct sshQ_L_161procG_class sshQ_L_161procG_methods;
B_NoneType sshQ_HostKeyInfoG_init (sshQ_HostKeyInfo self) {
    return B_None;
}
#line 95 "src/ssh.act"
B_NoneType sshQ_HostKeyInfoD___init__ (sshQ_HostKeyInfo self, B_str key_type, B_str fingerprint) {
    #line 96 "src/ssh.act"
    ((sshQ_HostKeyInfo)(self))->key_type = key_type;
    #line 97 "src/ssh.act"
    ((sshQ_HostKeyInfo)(self))->fingerprint = fingerprint;
    return B_None;
}
void sshQ_HostKeyInfoD___serialize__ (sshQ_HostKeyInfo self, $Serial$state state) {
    $step_serialize(self->key_type, state);
    $step_serialize(self->fingerprint, state);
}
sshQ_HostKeyInfo sshQ_HostKeyInfoD___deserialize__ (sshQ_HostKeyInfo self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_HostKeyInfo));
            self->$class = &sshQ_HostKeyInfoG_methods;
            return self;
        }
        self = $DNEW(sshQ_HostKeyInfo, state);
    }
    self->key_type = $step_deserialize(state);
    self->fingerprint = $step_deserialize(state);
    return self;
}
sshQ_HostKeyInfo sshQ_HostKeyInfoG_new(B_str G_1, B_str G_2) {
    sshQ_HostKeyInfo $tmp = acton_malloc(sizeof(struct sshQ_HostKeyInfo));
    $tmp->$class = &sshQ_HostKeyInfoG_methods;
    sshQ_HostKeyInfoG_methods.G_init($tmp);
    sshQ_HostKeyInfoG_methods.__init__($tmp, G_1, G_2);
    return $tmp;
}
struct sshQ_HostKeyInfoG_class sshQ_HostKeyInfoG_methods;
B_NoneType sshQ_AuthRequestG_init (sshQ_AuthRequest self) {
    return B_None;
}
#line 120 "src/ssh.act"
B_NoneType sshQ_AuthRequestD___init__ (sshQ_AuthRequest self, B_str method, B_str user, B_str N_default_password, B_bytes N_default_pubkey) {
    B_str password = (($ISNONE0(N_default_password)) ? B_None : N_default_password);
    B_bytes pubkey = (($ISNONE0(N_default_pubkey)) ? B_None : N_default_pubkey);
    #line 121 "src/ssh.act"
    ((sshQ_AuthRequest)(self))->method = method;
    #line 122 "src/ssh.act"
    ((sshQ_AuthRequest)(self))->user = user;
    #line 123 "src/ssh.act"
    ((sshQ_AuthRequest)(self))->password = password;
    #line 124 "src/ssh.act"
    ((sshQ_AuthRequest)(self))->pubkey = pubkey;
    return B_None;
}
void sshQ_AuthRequestD___serialize__ (sshQ_AuthRequest self, $Serial$state state) {
    $step_serialize(self->method, state);
    $step_serialize(self->user, state);
    $step_serialize(self->password, state);
    $step_serialize(self->pubkey, state);
}
sshQ_AuthRequest sshQ_AuthRequestD___deserialize__ (sshQ_AuthRequest self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_AuthRequest));
            self->$class = &sshQ_AuthRequestG_methods;
            return self;
        }
        self = $DNEW(sshQ_AuthRequest, state);
    }
    self->method = $step_deserialize(state);
    self->user = $step_deserialize(state);
    self->password = $step_deserialize(state);
    self->pubkey = $step_deserialize(state);
    return self;
}
sshQ_AuthRequest sshQ_AuthRequestG_new(B_str G_1, B_str G_2, B_str G_3, B_bytes G_4) {
    sshQ_AuthRequest $tmp = acton_malloc(sizeof(struct sshQ_AuthRequest));
    $tmp->$class = &sshQ_AuthRequestG_methods;
    sshQ_AuthRequestG_methods.G_init($tmp);
    sshQ_AuthRequestG_methods.__init__($tmp, G_1, G_2, G_3, G_4);
    return $tmp;
}
struct sshQ_AuthRequestG_class sshQ_AuthRequestG_methods;
$R sshQ_ClientD___init__ (sshQ_Client self, $Cont C_cont, netQ_TCPConnectCap cap, B_str host, B_str username, $action on_connect, $action on_close, $action N_default_on_hostkey, B_str N_default_password, B_str N_default_private_key_file, B_str N_default_private_key_passphrase, B_u16 N_default_port, B_str N_default_known_hosts, B_float N_default_connect_timeout, B_float N_default_auth_timeout, B_float N_default_keepalive_interval, B_bool N_default_keepalive_enabled, B_float N_default_close_timeout, B_int N_default_max_write_buffer) {
    ((sshQ_Client)(self))->cap = cap;
    ((sshQ_Client)(self))->host = host;
    ((sshQ_Client)(self))->username = username;
    ((sshQ_Client)(self))->on_connect = on_connect;
    ((sshQ_Client)(self))->on_close = on_close;
    ((sshQ_Client)(self))->N_default_on_hostkey = N_default_on_hostkey;
    ((sshQ_Client)(self))->N_default_password = N_default_password;
    ((sshQ_Client)(self))->N_default_private_key_file = N_default_private_key_file;
    ((sshQ_Client)(self))->N_default_private_key_passphrase = N_default_private_key_passphrase;
    ((sshQ_Client)(self))->N_default_port = N_default_port;
    ((sshQ_Client)(self))->N_default_known_hosts = N_default_known_hosts;
    ((sshQ_Client)(self))->N_default_connect_timeout = N_default_connect_timeout;
    ((sshQ_Client)(self))->N_default_auth_timeout = N_default_auth_timeout;
    ((sshQ_Client)(self))->N_default_keepalive_interval = N_default_keepalive_interval;
    ((sshQ_Client)(self))->N_default_keepalive_enabled = N_default_keepalive_enabled;
    ((sshQ_Client)(self))->N_default_close_timeout = N_default_close_timeout;
    ((sshQ_Client)(self))->N_default_max_write_buffer = N_default_max_write_buffer;
    ((sshQ_Client)(self))->on_hostkey = (($ISNONE0(((sshQ_Client)(self))->N_default_on_hostkey)) ? B_None : ((sshQ_Client)(self))->N_default_on_hostkey);
    ((sshQ_Client)(self))->password = (($ISNONE0(((sshQ_Client)(self))->N_default_password)) ? B_None : ((sshQ_Client)(self))->N_default_password);
    ((sshQ_Client)(self))->private_key_file = (($ISNONE0(((sshQ_Client)(self))->N_default_private_key_file)) ? B_None : ((sshQ_Client)(self))->N_default_private_key_file);
    ((sshQ_Client)(self))->private_key_passphrase = (($ISNONE0(((sshQ_Client)(self))->N_default_private_key_passphrase)) ? B_None : ((sshQ_Client)(self))->N_default_private_key_passphrase);
    ((sshQ_Client)(self))->port = (($ISNONE0(((sshQ_Client)(self))->N_default_port)) ? 22 : ((B_u16)((sshQ_Client)(self))->N_default_port)->val);
    ((sshQ_Client)(self))->known_hosts = (($ISNONE0(((sshQ_Client)(self))->N_default_known_hosts)) ? B_None : ((sshQ_Client)(self))->N_default_known_hosts);
    ((sshQ_Client)(self))->connect_timeout = (($ISNONE0(((sshQ_Client)(self))->N_default_connect_timeout)) ? 10.0 : ((B_float)((sshQ_Client)(self))->N_default_connect_timeout)->val);
    ((sshQ_Client)(self))->auth_timeout = (($ISNONE0(((sshQ_Client)(self))->N_default_auth_timeout)) ? 10.0 : ((B_float)((sshQ_Client)(self))->N_default_auth_timeout)->val);
    ((sshQ_Client)(self))->keepalive_interval = (($ISNONE0(((sshQ_Client)(self))->N_default_keepalive_interval)) ? 30.0 : ((B_float)((sshQ_Client)(self))->N_default_keepalive_interval)->val);
    ((sshQ_Client)(self))->keepalive_enabled = (($ISNONE0(((sshQ_Client)(self))->N_default_keepalive_enabled)) ? B_True : ((sshQ_Client)(self))->N_default_keepalive_enabled);
    ((sshQ_Client)(self))->close_timeout = (($ISNONE0(((sshQ_Client)(self))->N_default_close_timeout)) ? 5.0 : ((B_float)((sshQ_Client)(self))->N_default_close_timeout)->val);
    ((sshQ_Client)(self))->max_write_buffer = (($ISNONE0(((sshQ_Client)(self))->N_default_max_write_buffer)) ? 8388608LL : ((B_int)((sshQ_Client)(self))->N_default_max_write_buffer)->val);
    #line 156 "src/ssh.act"
    ((sshQ_Client)(self))->_client = 0UL;
    #line 157 "src/ssh.act"
    ((sshQ_Client)(self))->_host = ((sshQ_Client)(self))->host;
    #line 158 "src/ssh.act"
    ((sshQ_Client)(self))->_username = ((sshQ_Client)(self))->username;
    #line 159 "src/ssh.act"
    ((sshQ_Client)(self))->_password = ((sshQ_Client)(self))->password;
    #line 160 "src/ssh.act"
    ((sshQ_Client)(self))->_private_key_file = ((sshQ_Client)(self))->private_key_file;
    #line 161 "src/ssh.act"
    ((sshQ_Client)(self))->_private_key_passphrase = ((sshQ_Client)(self))->private_key_passphrase;
    #line 162 "src/ssh.act"
    ((sshQ_Client)(self))->_known_hosts = ((sshQ_Client)(self))->known_hosts;
    #line 163 "src/ssh.act"
    ((sshQ_Client)(self))->_connect_timeout = ((double)((sshQ_Client)(self))->connect_timeout);
    #line 164 "src/ssh.act"
    ((sshQ_Client)(self))->_auth_timeout = ((double)((sshQ_Client)(self))->auth_timeout);
    #line 165 "src/ssh.act"
    ((sshQ_Client)(self))->_keepalive_interval = ((double)((sshQ_Client)(self))->keepalive_interval);
    #line 166 "src/ssh.act"
    ((sshQ_Client)(self))->_keepalive_enabled = ((sshQ_Client)(self))->keepalive_enabled;
    #line 167 "src/ssh.act"
    ((sshQ_Client)(self))->_close_timeout = ((double)((sshQ_Client)(self))->close_timeout);
    #line 168 "src/ssh.act"
    ((sshQ_Client)(self))->_max_write_buffer = ((int64_t)((sshQ_Client)(self))->max_write_buffer);
    #line 169 "src/ssh.act"
    ((sshQ_Client)(self))->_on_connect = ((sshQ_Client)(self))->on_connect;
    #line 170 "src/ssh.act"
    ((sshQ_Client)(self))->_on_close = ((sshQ_Client)(self))->on_close;
    #line 171 "src/ssh.act"
    ((sshQ_Client)(self))->_on_hostkey = ((sshQ_Client)(self))->on_hostkey;
    return (($R (*) ($WORD, $Cont))((sshQ_Client)(self))->$class->_pin_affinityG_local)(self, (($Cont)sshQ_L_2ContG_new(self, C_cont)));
}
$R sshQ_ClientD__pin_affinityG_local (sshQ_Client self, $Cont C_cont);
/*
#line 173 "src/ssh.act"
$R sshQ_ClientD__pin_affinityG_local (sshQ_Client self, $Cont C_cont) {
    #line 174 "src/ssh.act"
    // NotImplemented
    return $R_CONT(C_cont, B_None);
}
*/
$R sshQ_ClientD__initG_local (sshQ_Client self, $Cont C_cont);
/*
#line 177 "src/ssh.act"
$R sshQ_ClientD__initG_local (sshQ_Client self, $Cont C_cont) {
    #line 179 "src/ssh.act"
    // NotImplemented
    return $R_CONT(C_cont, B_None);
}
*/
$R sshQ_ClientD_accept_hostkeyG_local (sshQ_Client self, $Cont C_cont);
/*
#line 182 "src/ssh.act"
$R sshQ_ClientD_accept_hostkeyG_local (sshQ_Client self, $Cont C_cont) {
    #line 184 "src/ssh.act"
    // NotImplemented
    return $R_CONT(C_cont, B_None);
}
*/
$R sshQ_ClientD_reject_hostkeyG_local (sshQ_Client self, $Cont C_cont, B_str reason);
/*
#line 186 "src/ssh.act"
$R sshQ_ClientD_reject_hostkeyG_local (sshQ_Client self, $Cont C_cont, B_str reason) {
    #line 188 "src/ssh.act"
    // NotImplemented
    return $R_CONT(C_cont, B_None);
}
*/
$R sshQ_ClientD_closeG_local (sshQ_Client self, $Cont C_cont);
/*
#line 190 "src/ssh.act"
$R sshQ_ClientD_closeG_local (sshQ_Client self, $Cont C_cont) {
    #line 192 "src/ssh.act"
    // NotImplemented
    return $R_CONT(C_cont, B_None);
}
*/
$R sshQ_ClientD__cleanup_nativeG_local (sshQ_Client self, $Cont C_cont);
/*
#line 194 "src/ssh.act"
$R sshQ_ClientD__cleanup_nativeG_local (sshQ_Client self, $Cont C_cont) {
    #line 195 "src/ssh.act"
    // NotImplemented
    return $R_CONT(C_cont, B_None);
}
*/
#line 197 "src/ssh.act"
$R sshQ_ClientD___cleanup__G_local (sshQ_Client self, $Cont C_cont) {
    if (((uint64_t)((sshQ_Client)(self))->_client) != 0UL) {
        return (($R (*) ($WORD, $Cont))((sshQ_Client)(self))->$class->_cleanup_nativeG_local)(self, (($Cont)sshQ_L_4ContG_new(C_cont)));
    }
    else {
        return $R_CONT((($Cont)sshQ_L_5ContG_new(C_cont)), B_None);
    }
}
$R sshQ_ClientD_channel_createG_local (sshQ_Client self, $Cont C_cont, sshQ_Channel channel, $action on_open, $action on_stdout, $action on_stderr, $action on_exit, $action on_close);
/*
#line 202 "src/ssh.act"
$R sshQ_ClientD_channel_createG_local (sshQ_Client self, $Cont C_cont, sshQ_Channel channel, $action on_open, $action on_stdout, $action on_stderr, $action on_exit, $action on_close) {
    #line 208 "src/ssh.act"
    // NotImplemented
    return $R_CONT(C_cont, B_None);
}
*/
$R sshQ_ClientD_channel_request_execG_local (sshQ_Client self, $Cont C_cont, sshQ_Channel channel, B_str cmd);
/*
#line 210 "src/ssh.act"
$R sshQ_ClientD_channel_request_execG_local (sshQ_Client self, $Cont C_cont, sshQ_Channel channel, B_str cmd) {
    #line 211 "src/ssh.act"
    // NotImplemented
    return $R_CONT(C_cont, B_None);
}
*/
$R sshQ_ClientD_channel_request_shellG_local (sshQ_Client self, $Cont C_cont, sshQ_Channel channel, B_str term, int64_t cols, int64_t rows, int64_t width_px, int64_t height_px, B_bool with_pty);
/*
#line 213 "src/ssh.act"
$R sshQ_ClientD_channel_request_shellG_local (sshQ_Client self, $Cont C_cont, sshQ_Channel channel, B_str term, int64_t cols, int64_t rows, int64_t width_px, int64_t height_px, B_bool with_pty) {
    #line 220 "src/ssh.act"
    // NotImplemented
    return $R_CONT(C_cont, B_None);
}
*/
$R sshQ_ClientD_channel_request_subsystemG_local (sshQ_Client self, $Cont C_cont, sshQ_Channel channel, B_str name);
/*
#line 222 "src/ssh.act"
$R sshQ_ClientD_channel_request_subsystemG_local (sshQ_Client self, $Cont C_cont, sshQ_Channel channel, B_str name) {
    #line 223 "src/ssh.act"
    // NotImplemented
    return $R_CONT(C_cont, B_None);
}
*/
$R sshQ_ClientD_channel_writeG_local (sshQ_Client self, $Cont C_cont, sshQ_Channel channel, B_bytes data);
/*
#line 225 "src/ssh.act"
$R sshQ_ClientD_channel_writeG_local (sshQ_Client self, $Cont C_cont, sshQ_Channel channel, B_bytes data) {
    #line 226 "src/ssh.act"
    // NotImplemented
    return $R_CONT(C_cont, B_None);
}
*/
$R sshQ_ClientD_channel_send_eofG_local (sshQ_Client self, $Cont C_cont, sshQ_Channel channel);
/*
#line 228 "src/ssh.act"
$R sshQ_ClientD_channel_send_eofG_local (sshQ_Client self, $Cont C_cont, sshQ_Channel channel) {
    #line 229 "src/ssh.act"
    // NotImplemented
    return $R_CONT(C_cont, B_None);
}
*/
$R sshQ_ClientD_channel_closeG_local (sshQ_Client self, $Cont C_cont, sshQ_Channel channel);
/*
#line 231 "src/ssh.act"
$R sshQ_ClientD_channel_closeG_local (sshQ_Client self, $Cont C_cont, sshQ_Channel channel) {
    #line 232 "src/ssh.act"
    // NotImplemented
    return $R_CONT(C_cont, B_None);
}
*/
B_Msg sshQ_ClientD__pin_affinity (sshQ_Client self) {
    return $ASYNC((($Actor)self), (($Cont)sshQ_L_6procG_new(self)));
}
B_Msg sshQ_ClientD__init (sshQ_Client self) {
    return $ASYNC((($Actor)self), (($Cont)sshQ_L_7procG_new(self)));
}
B_Msg sshQ_ClientD_accept_hostkey (sshQ_Client self) {
    return $ASYNC((($Actor)self), (($Cont)sshQ_L_8procG_new(self)));
}
B_Msg sshQ_ClientD_reject_hostkey (sshQ_Client self, B_str reason) {
    return $ASYNC((($Actor)self), (($Cont)sshQ_L_9procG_new(self, reason)));
}
B_Msg sshQ_ClientD_close (sshQ_Client self) {
    return $ASYNC((($Actor)self), (($Cont)sshQ_L_10procG_new(self)));
}
B_Msg sshQ_ClientD__cleanup_native (sshQ_Client self) {
    return $ASYNC((($Actor)self), (($Cont)sshQ_L_11procG_new(self)));
}
B_Msg sshQ_ClientD___cleanup__ (sshQ_Client self) {
    return $ASYNC((($Actor)self), (($Cont)sshQ_L_12procG_new(self)));
}
B_Msg sshQ_ClientD_channel_create (sshQ_Client self, sshQ_Channel channel, $action on_open, $action on_stdout, $action on_stderr, $action on_exit, $action on_close) {
    return $ASYNC((($Actor)self), (($Cont)sshQ_L_13procG_new(self, channel, on_open, on_stdout, on_stderr, on_exit, on_close)));
}
B_Msg sshQ_ClientD_channel_request_exec (sshQ_Client self, sshQ_Channel channel, B_str cmd) {
    return $ASYNC((($Actor)self), (($Cont)sshQ_L_14procG_new(self, channel, cmd)));
}
B_Msg sshQ_ClientD_channel_request_shell (sshQ_Client self, sshQ_Channel channel, B_str term, int64_t cols, int64_t rows, int64_t width_px, int64_t height_px, B_bool with_pty) {
    return $ASYNC((($Actor)self), (($Cont)sshQ_L_15procG_new(self, channel, term, cols, rows, width_px, height_px, with_pty)));
}
B_Msg sshQ_ClientD_channel_request_subsystem (sshQ_Client self, sshQ_Channel channel, B_str name) {
    return $ASYNC((($Actor)self), (($Cont)sshQ_L_16procG_new(self, channel, name)));
}
B_Msg sshQ_ClientD_channel_write (sshQ_Client self, sshQ_Channel channel, B_bytes data) {
    return $ASYNC((($Actor)self), (($Cont)sshQ_L_17procG_new(self, channel, data)));
}
B_Msg sshQ_ClientD_channel_send_eof (sshQ_Client self, sshQ_Channel channel) {
    return $ASYNC((($Actor)self), (($Cont)sshQ_L_18procG_new(self, channel)));
}
B_Msg sshQ_ClientD_channel_close (sshQ_Client self, sshQ_Channel channel) {
    return $ASYNC((($Actor)self), (($Cont)sshQ_L_19procG_new(self, channel)));
}
void sshQ_ClientD___serialize__ (sshQ_Client self, $Serial$state state) {
    $ActorG_methods.__serialize__(($Actor)self, state);
    $step_serialize(self->cap, state);
    $step_serialize(self->host, state);
    $step_serialize(self->username, state);
    $step_serialize(self->on_connect, state);
    $step_serialize(self->on_close, state);
    $step_serialize(self->N_default_on_hostkey, state);
    $step_serialize(self->N_default_password, state);
    $step_serialize(self->N_default_private_key_file, state);
    $step_serialize(self->N_default_private_key_passphrase, state);
    $step_serialize(self->N_default_port, state);
    $step_serialize(self->N_default_known_hosts, state);
    $step_serialize(self->N_default_connect_timeout, state);
    $step_serialize(self->N_default_auth_timeout, state);
    $step_serialize(self->N_default_keepalive_interval, state);
    $step_serialize(self->N_default_keepalive_enabled, state);
    $step_serialize(self->N_default_close_timeout, state);
    $step_serialize(self->N_default_max_write_buffer, state);
    $step_serialize(self->on_hostkey, state);
    $step_serialize(self->password, state);
    $step_serialize(self->private_key_file, state);
    $step_serialize(self->private_key_passphrase, state);
    $val_serialize(U16_ID, &self->port, state);
    $step_serialize(self->known_hosts, state);
    $val_serialize(FLOAT_ID, &self->connect_timeout, state);
    $val_serialize(FLOAT_ID, &self->auth_timeout, state);
    $val_serialize(FLOAT_ID, &self->keepalive_interval, state);
    $step_serialize(self->keepalive_enabled, state);
    $val_serialize(FLOAT_ID, &self->close_timeout, state);
    $val_serialize(I64_ID, &self->max_write_buffer, state);
    $val_serialize(U64_ID, &self->_client, state);
    $step_serialize(self->_host, state);
    $step_serialize(self->_username, state);
    $step_serialize(self->_password, state);
    $step_serialize(self->_private_key_file, state);
    $step_serialize(self->_private_key_passphrase, state);
    $step_serialize(self->_known_hosts, state);
    $val_serialize(FLOAT_ID, &self->_connect_timeout, state);
    $val_serialize(FLOAT_ID, &self->_auth_timeout, state);
    $val_serialize(FLOAT_ID, &self->_keepalive_interval, state);
    $step_serialize(self->_keepalive_enabled, state);
    $val_serialize(FLOAT_ID, &self->_close_timeout, state);
    $val_serialize(I64_ID, &self->_max_write_buffer, state);
    $step_serialize(self->_on_connect, state);
    $step_serialize(self->_on_close, state);
    $step_serialize(self->_on_hostkey, state);
}
sshQ_Client sshQ_ClientD___deserialize__ (sshQ_Client self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_Client));
            self->$class = &sshQ_ClientG_methods;
            return self;
        }
        self = $DNEW(sshQ_Client, state);
    }
    $ActorG_methods.__deserialize__(($Actor)self, state);
    self->cap = $step_deserialize(state);
    self->host = $step_deserialize(state);
    self->username = $step_deserialize(state);
    self->on_connect = $step_deserialize(state);
    self->on_close = $step_deserialize(state);
    self->N_default_on_hostkey = $step_deserialize(state);
    self->N_default_password = $step_deserialize(state);
    self->N_default_private_key_file = $step_deserialize(state);
    self->N_default_private_key_passphrase = $step_deserialize(state);
    self->N_default_port = $step_deserialize(state);
    self->N_default_known_hosts = $step_deserialize(state);
    self->N_default_connect_timeout = $step_deserialize(state);
    self->N_default_auth_timeout = $step_deserialize(state);
    self->N_default_keepalive_interval = $step_deserialize(state);
    self->N_default_keepalive_enabled = $step_deserialize(state);
    self->N_default_close_timeout = $step_deserialize(state);
    self->N_default_max_write_buffer = $step_deserialize(state);
    self->on_hostkey = $step_deserialize(state);
    self->password = $step_deserialize(state);
    self->private_key_file = $step_deserialize(state);
    self->private_key_passphrase = $step_deserialize(state);
    $tmp = $val_deserialize(state);
    memcpy(&self->port, &$tmp, sizeof(self->port));
    self->known_hosts = $step_deserialize(state);
    $tmp = $val_deserialize(state);
    memcpy(&self->connect_timeout, &$tmp, sizeof(self->connect_timeout));
    $tmp = $val_deserialize(state);
    memcpy(&self->auth_timeout, &$tmp, sizeof(self->auth_timeout));
    $tmp = $val_deserialize(state);
    memcpy(&self->keepalive_interval, &$tmp, sizeof(self->keepalive_interval));
    self->keepalive_enabled = $step_deserialize(state);
    $tmp = $val_deserialize(state);
    memcpy(&self->close_timeout, &$tmp, sizeof(self->close_timeout));
    $tmp = $val_deserialize(state);
    memcpy(&self->max_write_buffer, &$tmp, sizeof(self->max_write_buffer));
    $tmp = $val_deserialize(state);
    memcpy(&self->_client, &$tmp, sizeof(self->_client));
    self->_host = $step_deserialize(state);
    self->_username = $step_deserialize(state);
    self->_password = $step_deserialize(state);
    self->_private_key_file = $step_deserialize(state);
    self->_private_key_passphrase = $step_deserialize(state);
    self->_known_hosts = $step_deserialize(state);
    $tmp = $val_deserialize(state);
    memcpy(&self->_connect_timeout, &$tmp, sizeof(self->_connect_timeout));
    $tmp = $val_deserialize(state);
    memcpy(&self->_auth_timeout, &$tmp, sizeof(self->_auth_timeout));
    $tmp = $val_deserialize(state);
    memcpy(&self->_keepalive_interval, &$tmp, sizeof(self->_keepalive_interval));
    self->_keepalive_enabled = $step_deserialize(state);
    $tmp = $val_deserialize(state);
    memcpy(&self->_close_timeout, &$tmp, sizeof(self->_close_timeout));
    $tmp = $val_deserialize(state);
    memcpy(&self->_max_write_buffer, &$tmp, sizeof(self->_max_write_buffer));
    self->_on_connect = $step_deserialize(state);
    self->_on_close = $step_deserialize(state);
    self->_on_hostkey = $step_deserialize(state);
    return self;
}
void sshQ_ClientD_GCfinalizer (void *obj, void *cdata) {
    sshQ_Client self = (sshQ_Client)obj;
    self->$class->__cleanup__(self);
}
$R sshQ_ClientG_new($Cont G_1, netQ_TCPConnectCap G_2, B_str G_3, B_str G_4, $action G_5, $action G_6, $action G_7, B_str G_8, B_str G_9, B_str G_10, B_u16 G_11, B_str G_12, B_float G_13, B_float G_14, B_float G_15, B_bool G_16, B_float G_17, B_int G_18) {
    sshQ_Client $tmp = acton_malloc(sizeof(struct sshQ_Client));
    $tmp->$class = &sshQ_ClientG_methods;
    return sshQ_ClientG_methods.__init__($tmp, $CONSTCONT($tmp, G_1), G_2, G_3, G_4, G_5, G_6, G_7, G_8, G_9, G_10, G_11, G_12, G_13, G_14, G_15, G_16, G_17, G_18);
}
struct sshQ_ClientG_class sshQ_ClientG_methods;
$R sshQ_ChannelD___init__ (sshQ_Channel self, $Cont C_cont, sshQ_Client client, $action on_open, $action on_stdout, $action on_stderr, $action on_exit, $action on_close) {
    ((sshQ_Channel)(self))->client = client;
    ((sshQ_Channel)(self))->on_open = on_open;
    ((sshQ_Channel)(self))->on_stdout = on_stdout;
    ((sshQ_Channel)(self))->on_stderr = on_stderr;
    ((sshQ_Channel)(self))->on_exit = on_exit;
    ((sshQ_Channel)(self))->on_close = on_close;
    #line 251 "src/ssh.act"
    ((sshQ_Channel)(self))->_channel_id = 0UL;
    #line 252 "src/ssh.act"
    ((sshQ_Channel)(self))->_on_open = ((sshQ_Channel)(self))->on_open;
    #line 253 "src/ssh.act"
    ((sshQ_Channel)(self))->_on_stdout = ((sshQ_Channel)(self))->on_stdout;
    #line 254 "src/ssh.act"
    ((sshQ_Channel)(self))->_on_stderr = ((sshQ_Channel)(self))->on_stderr;
    #line 255 "src/ssh.act"
    ((sshQ_Channel)(self))->_on_exit = ((sshQ_Channel)(self))->on_exit;
    #line 256 "src/ssh.act"
    ((sshQ_Channel)(self))->_on_close = ((sshQ_Channel)(self))->on_close;
    return (($R (*) ($WORD, $Cont))((sshQ_Channel)(self))->$class->_initG_local)(self, C_cont);
}
#line 258 "src/ssh.act"
$R sshQ_ChannelD__initG_local (sshQ_Channel self, $Cont C_cont) {
    #line 259 "src/ssh.act"
    ((B_Msg (*) ($WORD, sshQ_Channel, $action, $action, $action, $action, $action))((sshQ_Client)(((sshQ_Channel)(self))->client))->$class->channel_create)(((sshQ_Channel)(self))->client, self, ((sshQ_Channel)(self))->_on_open, ((sshQ_Channel)(self))->_on_stdout, ((sshQ_Channel)(self))->_on_stderr, ((sshQ_Channel)(self))->_on_exit, ((sshQ_Channel)(self))->_on_close);
    return $R_CONT(C_cont, B_None);
}
#line 262 "src/ssh.act"
$R sshQ_ChannelD_request_execG_local (sshQ_Channel self, $Cont C_cont, B_str cmd) {
    #line 264 "src/ssh.act"
    ((B_Msg (*) ($WORD, sshQ_Channel, B_str))((sshQ_Client)(((sshQ_Channel)(self))->client))->$class->channel_request_exec)(((sshQ_Channel)(self))->client, self, cmd);
    return $R_CONT(C_cont, B_None);
}
#line 266 "src/ssh.act"
$R sshQ_ChannelD_request_shellG_local (sshQ_Channel self, $Cont C_cont, B_str N_default_term, B_int N_default_cols, B_int N_default_rows, B_int N_default_width_px, B_int N_default_height_px, B_bool N_default_with_pty) {
    B_str term = (($ISNONE0(N_default_term)) ? to$str("xterm-256color") : N_default_term);
    int64_t cols = (($ISNONE0(N_default_cols)) ? 80LL : ((B_int)N_default_cols)->val);
    int64_t rows = (($ISNONE0(N_default_rows)) ? 24LL : ((B_int)N_default_rows)->val);
    int64_t width_px = (($ISNONE0(N_default_width_px)) ? 0LL : ((B_int)N_default_width_px)->val);
    int64_t height_px = (($ISNONE0(N_default_height_px)) ? 0LL : ((B_int)N_default_height_px)->val);
    B_bool with_pty = (($ISNONE0(N_default_with_pty)) ? B_True : N_default_with_pty);
    #line 273 "src/ssh.act"
    ((B_Msg (*) ($WORD, sshQ_Channel, B_str, int64_t, int64_t, int64_t, int64_t, B_bool))((sshQ_Client)(((sshQ_Channel)(self))->client))->$class->channel_request_shell)(((sshQ_Channel)(self))->client, self, term, cols, rows, width_px, height_px, with_pty);
    return $R_CONT(C_cont, B_None);
}
#line 275 "src/ssh.act"
$R sshQ_ChannelD_request_subsystemG_local (sshQ_Channel self, $Cont C_cont, B_str name) {
    #line 277 "src/ssh.act"
    ((B_Msg (*) ($WORD, sshQ_Channel, B_str))((sshQ_Client)(((sshQ_Channel)(self))->client))->$class->channel_request_subsystem)(((sshQ_Channel)(self))->client, self, name);
    return $R_CONT(C_cont, B_None);
}
#line 279 "src/ssh.act"
$R sshQ_ChannelD_writeG_local (sshQ_Channel self, $Cont C_cont, B_bytes data) {
    #line 281 "src/ssh.act"
    ((B_Msg (*) ($WORD, sshQ_Channel, B_bytes))((sshQ_Client)(((sshQ_Channel)(self))->client))->$class->channel_write)(((sshQ_Channel)(self))->client, self, data);
    return $R_CONT(C_cont, B_None);
}
#line 283 "src/ssh.act"
$R sshQ_ChannelD_send_eofG_local (sshQ_Channel self, $Cont C_cont) {
    #line 285 "src/ssh.act"
    ((B_Msg (*) ($WORD, sshQ_Channel))((sshQ_Client)(((sshQ_Channel)(self))->client))->$class->channel_send_eof)(((sshQ_Channel)(self))->client, self);
    return $R_CONT(C_cont, B_None);
}
#line 287 "src/ssh.act"
$R sshQ_ChannelD_closeG_local (sshQ_Channel self, $Cont C_cont) {
    #line 289 "src/ssh.act"
    ((B_Msg (*) ($WORD, sshQ_Channel))((sshQ_Client)(((sshQ_Channel)(self))->client))->$class->channel_close)(((sshQ_Channel)(self))->client, self);
    return $R_CONT(C_cont, B_None);
}
$R sshQ_ChannelD__cleanup_nativeG_local (sshQ_Channel self, $Cont C_cont);
/*
#line 291 "src/ssh.act"
$R sshQ_ChannelD__cleanup_nativeG_local (sshQ_Channel self, $Cont C_cont) {
    #line 292 "src/ssh.act"
    // NotImplemented
    return $R_CONT(C_cont, B_None);
}
*/
#line 294 "src/ssh.act"
$R sshQ_ChannelD___cleanup__G_local (sshQ_Channel self, $Cont C_cont) {
    if (((uint64_t)((sshQ_Channel)(self))->_channel_id) != 0UL) {
        return (($R (*) ($WORD, $Cont))((sshQ_Channel)(self))->$class->_cleanup_nativeG_local)(self, (($Cont)sshQ_L_21ContG_new(C_cont)));
    }
    else {
        return $R_CONT((($Cont)sshQ_L_22ContG_new(C_cont)), B_None);
    }
}
B_Msg sshQ_ChannelD__init (sshQ_Channel self) {
    return $ASYNC((($Actor)self), (($Cont)sshQ_L_23procG_new(self)));
}
B_Msg sshQ_ChannelD_request_exec (sshQ_Channel self, B_str cmd) {
    return $ASYNC((($Actor)self), (($Cont)sshQ_L_24procG_new(self, cmd)));
}
B_Msg sshQ_ChannelD_request_shell (sshQ_Channel self, B_str N_default_term, B_int N_default_cols, B_int N_default_rows, B_int N_default_width_px, B_int N_default_height_px, B_bool N_default_with_pty) {
    return $ASYNC((($Actor)self), (($Cont)sshQ_L_25procG_new(self, N_default_term, N_default_cols, N_default_rows, N_default_width_px, N_default_height_px, N_default_with_pty)));
}
B_Msg sshQ_ChannelD_request_subsystem (sshQ_Channel self, B_str name) {
    return $ASYNC((($Actor)self), (($Cont)sshQ_L_26procG_new(self, name)));
}
B_Msg sshQ_ChannelD_write (sshQ_Channel self, B_bytes data) {
    return $ASYNC((($Actor)self), (($Cont)sshQ_L_27procG_new(self, data)));
}
B_Msg sshQ_ChannelD_send_eof (sshQ_Channel self) {
    return $ASYNC((($Actor)self), (($Cont)sshQ_L_28procG_new(self)));
}
B_Msg sshQ_ChannelD_close (sshQ_Channel self) {
    return $ASYNC((($Actor)self), (($Cont)sshQ_L_29procG_new(self)));
}
B_Msg sshQ_ChannelD__cleanup_native (sshQ_Channel self) {
    return $ASYNC((($Actor)self), (($Cont)sshQ_L_30procG_new(self)));
}
B_Msg sshQ_ChannelD___cleanup__ (sshQ_Channel self) {
    return $ASYNC((($Actor)self), (($Cont)sshQ_L_31procG_new(self)));
}
void sshQ_ChannelD___serialize__ (sshQ_Channel self, $Serial$state state) {
    $ActorG_methods.__serialize__(($Actor)self, state);
    $step_serialize(self->client, state);
    $step_serialize(self->on_open, state);
    $step_serialize(self->on_stdout, state);
    $step_serialize(self->on_stderr, state);
    $step_serialize(self->on_exit, state);
    $step_serialize(self->on_close, state);
    $val_serialize(U64_ID, &self->_channel_id, state);
    $step_serialize(self->_on_open, state);
    $step_serialize(self->_on_stdout, state);
    $step_serialize(self->_on_stderr, state);
    $step_serialize(self->_on_exit, state);
    $step_serialize(self->_on_close, state);
}
sshQ_Channel sshQ_ChannelD___deserialize__ (sshQ_Channel self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_Channel));
            self->$class = &sshQ_ChannelG_methods;
            return self;
        }
        self = $DNEW(sshQ_Channel, state);
    }
    $ActorG_methods.__deserialize__(($Actor)self, state);
    self->client = $step_deserialize(state);
    self->on_open = $step_deserialize(state);
    self->on_stdout = $step_deserialize(state);
    self->on_stderr = $step_deserialize(state);
    self->on_exit = $step_deserialize(state);
    self->on_close = $step_deserialize(state);
    $tmp = $val_deserialize(state);
    memcpy(&self->_channel_id, &$tmp, sizeof(self->_channel_id));
    self->_on_open = $step_deserialize(state);
    self->_on_stdout = $step_deserialize(state);
    self->_on_stderr = $step_deserialize(state);
    self->_on_exit = $step_deserialize(state);
    self->_on_close = $step_deserialize(state);
    return self;
}
void sshQ_ChannelD_GCfinalizer (void *obj, void *cdata) {
    sshQ_Channel self = (sshQ_Channel)obj;
    self->$class->__cleanup__(self);
}
$R sshQ_ChannelG_new($Cont G_1, sshQ_Client G_2, $action G_3, $action G_4, $action G_5, $action G_6, $action G_7) {
    sshQ_Channel $tmp = acton_malloc(sizeof(struct sshQ_Channel));
    $tmp->$class = &sshQ_ChannelG_methods;
    return sshQ_ChannelG_methods.__init__($tmp, $CONSTCONT($tmp, G_1), G_2, G_3, G_4, G_5, G_6, G_7);
}
struct sshQ_ChannelG_class sshQ_ChannelG_methods;
$R sshQ_RunCommandD___init__ (sshQ_RunCommand self, $Cont C_cont, sshQ_Client client, B_str cmd, $action on_exit, B_float N_default_timeout) {
    ((sshQ_RunCommand)(self))->cmd = cmd;
    ((sshQ_RunCommand)(self))->on_exit = on_exit;
    ((sshQ_RunCommand)(self))->timeout = (($ISNONE0(N_default_timeout)) ? B_None : N_default_timeout);
    #line 311 "src/ssh.act"
    ((sshQ_RunCommand)(self))->out_buf = to$bytesD_len("", 0);
    #line 312 "src/ssh.act"
    ((sshQ_RunCommand)(self))->err_buf = to$bytesD_len("", 0);
    #line 313 "src/ssh.act"
    ((sshQ_RunCommand)(self))->_out_done = B_False;
    #line 314 "src/ssh.act"
    ((sshQ_RunCommand)(self))->_err_done = B_False;
    #line 315 "src/ssh.act"
    ((sshQ_RunCommand)(self))->_exited = B_False;
    #line 316 "src/ssh.act"
    ((sshQ_RunCommand)(self))->_exit_code = 0LL;
    #line 317 "src/ssh.act"
    ((sshQ_RunCommand)(self))->_exit_signal = B_None;
    #line 318 "src/ssh.act"
    ((sshQ_RunCommand)(self))->_error = B_None;
    #line 319 "src/ssh.act"
    ((sshQ_RunCommand)(self))->_done = B_False;
    return sshQ_ChannelG_newact((($Cont)sshQ_L_39ContG_new(self, C_cont)), client, (($action)sshQ_L_41actionG_new(self)), (($action)sshQ_L_43actionG_new(self)), (($action)sshQ_L_45actionG_new(self)), (($action)sshQ_L_47actionG_new(self)), (($action)sshQ_L_49actionG_new(self)));
}
#line 321 "src/ssh.act"
$R sshQ_RunCommandD__finishG_local (sshQ_RunCommand self, $Cont C_cont, sshQ_Channel ch) {
    if (((B_bool)((sshQ_RunCommand)(self))->_done)->val) {
        return $R_CONT(C_cont, B_None);
    }
    else {
        return $R_CONT((($Cont)sshQ_L_51ContG_new(self, ch, C_cont)), B_None);
    }
}
#line 327 "src/ssh.act"
$R sshQ_RunCommandD__on_openG_local (sshQ_RunCommand self, $Cont C_cont, sshQ_Channel ch, B_str err) {
    if (((B_bool)((sshQ_RunCommand)(self))->_done)->val) {
        return $R_CONT(C_cont, B_None);
    }
    else {
        return $R_CONT((($Cont)sshQ_L_57ContG_new(ch, self, C_cont, err)), B_None);
    }
}
#line 336 "src/ssh.act"
$R sshQ_RunCommandD__on_stdoutG_local (sshQ_RunCommand self, $Cont C_cont, sshQ_Channel ch, B_bytes data) {
    if (((B_bool)((sshQ_RunCommand)(self))->_done)->val) {
        return $R_CONT(C_cont, B_None);
    }
    else {
        return $R_CONT((($Cont)sshQ_L_62ContG_new(C_cont, data, self, ch)), B_None);
    }
}
#line 345 "src/ssh.act"
$R sshQ_RunCommandD__on_stderrG_local (sshQ_RunCommand self, $Cont C_cont, sshQ_Channel ch, B_bytes data) {
    if (((B_bool)((sshQ_RunCommand)(self))->_done)->val) {
        return $R_CONT(C_cont, B_None);
    }
    else {
        return $R_CONT((($Cont)sshQ_L_67ContG_new(C_cont, data, self, ch)), B_None);
    }
}
#line 354 "src/ssh.act"
$R sshQ_RunCommandD__on_exitG_local (sshQ_RunCommand self, $Cont C_cont, sshQ_Channel ch, int64_t code, B_str sig) {
    if (((B_bool)((sshQ_RunCommand)(self))->_done)->val) {
        return $R_CONT(C_cont, B_None);
    }
    else {
        return $R_CONT((($Cont)sshQ_L_71ContG_new(self, code, sig, C_cont, ch)), B_None);
    }
}
#line 362 "src/ssh.act"
$R sshQ_RunCommandD__on_closeG_local (sshQ_RunCommand self, $Cont C_cont, sshQ_Channel ch, B_str reason) {
    B_Eq W_HostKeyInfo_980 = (B_Eq)B_OrdD_strG_witness;
    if (((B_bool)((sshQ_RunCommand)(self))->_done)->val) {
        return $R_CONT(C_cont, B_None);
    }
    else {
        return $R_CONT((($Cont)sshQ_L_75ContG_new(self, W_HostKeyInfo_980, reason, C_cont, ch)), B_None);
    }
}
#line 369 "src/ssh.act"
$R sshQ_RunCommandD__check_doneG_local (sshQ_RunCommand self, $Cont C_cont, sshQ_Channel ch) {
    if (((B_bool)$AND(B_bool, $AND(B_bool, $AND(B_bool, ((sshQ_RunCommand)(self))->_out_done, ((sshQ_RunCommand)(self))->_err_done), ((sshQ_RunCommand)(self))->_exited), toB_bool($ISNONE0(((sshQ_RunCommand)(self))->_error))))->val) {
        return (($R (*) ($WORD, $Cont, sshQ_Channel))((sshQ_RunCommand)(self))->$class->_finishG_local)(self, (($Cont)sshQ_L_77ContG_new(C_cont)), ch);
    }
    else {
        return $R_CONT((($Cont)sshQ_L_78ContG_new(C_cont)), B_None);
    }
}
B_Msg sshQ_RunCommandD__finish (sshQ_RunCommand self, sshQ_Channel ch) {
    return $ASYNC((($Actor)self), (($Cont)sshQ_L_79procG_new(self, ch)));
}
B_Msg sshQ_RunCommandD__on_open (sshQ_RunCommand self, sshQ_Channel ch, B_str err) {
    return $ASYNC((($Actor)self), (($Cont)sshQ_L_80procG_new(self, ch, err)));
}
B_Msg sshQ_RunCommandD__on_stdout (sshQ_RunCommand self, sshQ_Channel ch, B_bytes data) {
    return $ASYNC((($Actor)self), (($Cont)sshQ_L_81procG_new(self, ch, data)));
}
B_Msg sshQ_RunCommandD__on_stderr (sshQ_RunCommand self, sshQ_Channel ch, B_bytes data) {
    return $ASYNC((($Actor)self), (($Cont)sshQ_L_82procG_new(self, ch, data)));
}
B_Msg sshQ_RunCommandD__on_exit (sshQ_RunCommand self, sshQ_Channel ch, int64_t code, B_str sig) {
    return $ASYNC((($Actor)self), (($Cont)sshQ_L_83procG_new(self, ch, code, sig)));
}
B_Msg sshQ_RunCommandD__on_close (sshQ_RunCommand self, sshQ_Channel ch, B_str reason) {
    return $ASYNC((($Actor)self), (($Cont)sshQ_L_84procG_new(self, ch, reason)));
}
B_Msg sshQ_RunCommandD__check_done (sshQ_RunCommand self, sshQ_Channel ch) {
    return $ASYNC((($Actor)self), (($Cont)sshQ_L_85procG_new(self, ch)));
}
void sshQ_RunCommandD___serialize__ (sshQ_RunCommand self, $Serial$state state) {
    $ActorG_methods.__serialize__(($Actor)self, state);
    $step_serialize(self->cmd, state);
    $step_serialize(self->on_exit, state);
    $step_serialize(self->timeout, state);
    $step_serialize(self->out_buf, state);
    $step_serialize(self->err_buf, state);
    $step_serialize(self->_out_done, state);
    $step_serialize(self->_err_done, state);
    $step_serialize(self->_exited, state);
    $val_serialize(I64_ID, &self->_exit_code, state);
    $step_serialize(self->_exit_signal, state);
    $step_serialize(self->_error, state);
    $step_serialize(self->_done, state);
    $step_serialize(self->_channel, state);
}
sshQ_RunCommand sshQ_RunCommandD___deserialize__ (sshQ_RunCommand self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_RunCommand));
            self->$class = &sshQ_RunCommandG_methods;
            return self;
        }
        self = $DNEW(sshQ_RunCommand, state);
    }
    $ActorG_methods.__deserialize__(($Actor)self, state);
    self->cmd = $step_deserialize(state);
    self->on_exit = $step_deserialize(state);
    self->timeout = $step_deserialize(state);
    self->out_buf = $step_deserialize(state);
    self->err_buf = $step_deserialize(state);
    self->_out_done = $step_deserialize(state);
    self->_err_done = $step_deserialize(state);
    self->_exited = $step_deserialize(state);
    $tmp = $val_deserialize(state);
    memcpy(&self->_exit_code, &$tmp, sizeof(self->_exit_code));
    self->_exit_signal = $step_deserialize(state);
    self->_error = $step_deserialize(state);
    self->_done = $step_deserialize(state);
    self->_channel = $step_deserialize(state);
    return self;
}
void sshQ_RunCommandD_GCfinalizer (void *obj, void *cdata) {
    sshQ_RunCommand self = (sshQ_RunCommand)obj;
    self->$class->__cleanup__(self);
}
$R sshQ_RunCommandG_new($Cont G_1, sshQ_Client G_2, B_str G_3, $action G_4, B_float G_5) {
    sshQ_RunCommand $tmp = acton_malloc(sizeof(struct sshQ_RunCommand));
    $tmp->$class = &sshQ_RunCommandG_methods;
    return sshQ_RunCommandG_methods.__init__($tmp, $CONSTCONT($tmp, G_1), G_2, G_3, G_4, G_5);
}
struct sshQ_RunCommandG_class sshQ_RunCommandG_methods;
$R sshQ_ServerD___init__ (sshQ_Server self, $Cont C_cont, netQ_TCPListenCap cap, B_str host, uint16_t port, $action on_listen, $action on_close, $action on_session, $action on_auth, $action on_channel_open, $action N_default_on_exec, $action N_default_on_subsystem, $action N_default_on_session_close, B_str N_default_host_key_path, B_str N_default_host_key_type, B_int N_default_host_key_bits, B_float N_default_auth_timeout, B_float N_default_keepalive_interval, B_bool N_default_keepalive_enabled, B_float N_default_close_timeout, B_int N_default_max_sessions, B_int N_default_max_channels_per_session, B_int N_default_max_write_buffer) {
    ((sshQ_Server)(self))->cap = cap;
    ((sshQ_Server)(self))->host = host;
    ((sshQ_Server)(self))->port = port;
    ((sshQ_Server)(self))->on_listen = on_listen;
    ((sshQ_Server)(self))->on_close = on_close;
    ((sshQ_Server)(self))->on_session = on_session;
    ((sshQ_Server)(self))->on_auth = on_auth;
    ((sshQ_Server)(self))->on_channel_open = on_channel_open;
    ((sshQ_Server)(self))->N_default_on_exec = N_default_on_exec;
    ((sshQ_Server)(self))->N_default_on_subsystem = N_default_on_subsystem;
    ((sshQ_Server)(self))->N_default_on_session_close = N_default_on_session_close;
    ((sshQ_Server)(self))->N_default_host_key_path = N_default_host_key_path;
    ((sshQ_Server)(self))->N_default_host_key_type = N_default_host_key_type;
    ((sshQ_Server)(self))->N_default_host_key_bits = N_default_host_key_bits;
    ((sshQ_Server)(self))->N_default_auth_timeout = N_default_auth_timeout;
    ((sshQ_Server)(self))->N_default_keepalive_interval = N_default_keepalive_interval;
    ((sshQ_Server)(self))->N_default_keepalive_enabled = N_default_keepalive_enabled;
    ((sshQ_Server)(self))->N_default_close_timeout = N_default_close_timeout;
    ((sshQ_Server)(self))->N_default_max_sessions = N_default_max_sessions;
    ((sshQ_Server)(self))->N_default_max_channels_per_session = N_default_max_channels_per_session;
    ((sshQ_Server)(self))->N_default_max_write_buffer = N_default_max_write_buffer;
    ((sshQ_Server)(self))->on_exec = (($ISNONE0(((sshQ_Server)(self))->N_default_on_exec)) ? B_None : ((sshQ_Server)(self))->N_default_on_exec);
    ((sshQ_Server)(self))->on_subsystem = (($ISNONE0(((sshQ_Server)(self))->N_default_on_subsystem)) ? B_None : ((sshQ_Server)(self))->N_default_on_subsystem);
    ((sshQ_Server)(self))->on_session_close = (($ISNONE0(((sshQ_Server)(self))->N_default_on_session_close)) ? B_None : ((sshQ_Server)(self))->N_default_on_session_close);
    ((sshQ_Server)(self))->host_key_path = (($ISNONE0(((sshQ_Server)(self))->N_default_host_key_path)) ? B_None : ((sshQ_Server)(self))->N_default_host_key_path);
    ((sshQ_Server)(self))->host_key_type = (($ISNONE0(((sshQ_Server)(self))->N_default_host_key_type)) ? to$str("ed25519") : ((sshQ_Server)(self))->N_default_host_key_type);
    ((sshQ_Server)(self))->host_key_bits = (($ISNONE0(((sshQ_Server)(self))->N_default_host_key_bits)) ? 2048LL : ((B_int)((sshQ_Server)(self))->N_default_host_key_bits)->val);
    ((sshQ_Server)(self))->auth_timeout = (($ISNONE0(((sshQ_Server)(self))->N_default_auth_timeout)) ? 10.0 : ((B_float)((sshQ_Server)(self))->N_default_auth_timeout)->val);
    ((sshQ_Server)(self))->keepalive_interval = (($ISNONE0(((sshQ_Server)(self))->N_default_keepalive_interval)) ? 30.0 : ((B_float)((sshQ_Server)(self))->N_default_keepalive_interval)->val);
    ((sshQ_Server)(self))->keepalive_enabled = (($ISNONE0(((sshQ_Server)(self))->N_default_keepalive_enabled)) ? B_True : ((sshQ_Server)(self))->N_default_keepalive_enabled);
    ((sshQ_Server)(self))->close_timeout = (($ISNONE0(((sshQ_Server)(self))->N_default_close_timeout)) ? 5.0 : ((B_float)((sshQ_Server)(self))->N_default_close_timeout)->val);
    ((sshQ_Server)(self))->max_sessions = (($ISNONE0(((sshQ_Server)(self))->N_default_max_sessions)) ? 128LL : ((B_int)((sshQ_Server)(self))->N_default_max_sessions)->val);
    ((sshQ_Server)(self))->max_channels_per_session = (($ISNONE0(((sshQ_Server)(self))->N_default_max_channels_per_session)) ? 32LL : ((B_int)((sshQ_Server)(self))->N_default_max_channels_per_session)->val);
    ((sshQ_Server)(self))->max_write_buffer = (($ISNONE0(((sshQ_Server)(self))->N_default_max_write_buffer)) ? 8388608LL : ((B_int)((sshQ_Server)(self))->N_default_max_write_buffer)->val);
    #line 419 "src/ssh.act"
    ((sshQ_Server)(self))->_server = 0UL;
    #line 420 "src/ssh.act"
    ((sshQ_Server)(self))->_bound_port = 0;
    #line 421 "src/ssh.act"
    ((sshQ_Server)(self))->_host = ((sshQ_Server)(self))->host;
    #line 422 "src/ssh.act"
    ((sshQ_Server)(self))->_port = ((uint16_t)((sshQ_Server)(self))->port);
    #line 423 "src/ssh.act"
    ((sshQ_Server)(self))->_host_key_path = ((sshQ_Server)(self))->host_key_path;
    #line 424 "src/ssh.act"
    ((sshQ_Server)(self))->_host_key_type = ((sshQ_Server)(self))->host_key_type;
    #line 425 "src/ssh.act"
    ((sshQ_Server)(self))->_host_key_bits = ((int64_t)((sshQ_Server)(self))->host_key_bits);
    #line 426 "src/ssh.act"
    ((sshQ_Server)(self))->_auth_timeout = ((double)((sshQ_Server)(self))->auth_timeout);
    #line 427 "src/ssh.act"
    ((sshQ_Server)(self))->_keepalive_interval = ((double)((sshQ_Server)(self))->keepalive_interval);
    #line 428 "src/ssh.act"
    ((sshQ_Server)(self))->_keepalive_enabled = ((sshQ_Server)(self))->keepalive_enabled;
    #line 429 "src/ssh.act"
    ((sshQ_Server)(self))->_close_timeout = ((double)((sshQ_Server)(self))->close_timeout);
    #line 430 "src/ssh.act"
    ((sshQ_Server)(self))->_max_sessions = ((int64_t)((sshQ_Server)(self))->max_sessions);
    #line 431 "src/ssh.act"
    ((sshQ_Server)(self))->_max_channels_per_session = ((int64_t)((sshQ_Server)(self))->max_channels_per_session);
    #line 432 "src/ssh.act"
    ((sshQ_Server)(self))->_max_write_buffer = ((int64_t)((sshQ_Server)(self))->max_write_buffer);
    #line 433 "src/ssh.act"
    ((sshQ_Server)(self))->_on_listen = ((sshQ_Server)(self))->on_listen;
    #line 434 "src/ssh.act"
    ((sshQ_Server)(self))->_on_close = ((sshQ_Server)(self))->on_close;
    return (($R (*) ($WORD, $Cont))((sshQ_Server)(self))->$class->_pin_affinityG_local)(self, (($Cont)sshQ_L_87ContG_new(self, C_cont)));
}
$R sshQ_ServerD__pin_affinityG_local (sshQ_Server self, $Cont C_cont);
/*
#line 436 "src/ssh.act"
$R sshQ_ServerD__pin_affinityG_local (sshQ_Server self, $Cont C_cont) {
    #line 437 "src/ssh.act"
    // NotImplemented
    return $R_CONT(C_cont, B_None);
}
*/
$R sshQ_ServerD__initG_local (sshQ_Server self, $Cont C_cont);
/*
#line 440 "src/ssh.act"
$R sshQ_ServerD__initG_local (sshQ_Server self, $Cont C_cont) {
    #line 442 "src/ssh.act"
    // NotImplemented
    return $R_CONT(C_cont, B_None);
}
*/
$R sshQ_ServerD_closeG_local (sshQ_Server self, $Cont C_cont);
/*
#line 445 "src/ssh.act"
$R sshQ_ServerD_closeG_local (sshQ_Server self, $Cont C_cont) {
    #line 447 "src/ssh.act"
    // NotImplemented
    return $R_CONT(C_cont, B_None);
}
*/
#line 449 "src/ssh.act"
$R sshQ_ServerD_bound_portG_local (sshQ_Server self, $Cont C_cont) {
    return $R_CONT(C_cont, toB_u16(((uint16_t)((sshQ_Server)(self))->_bound_port)));
}
$R sshQ_ServerD__cleanup_nativeG_local (sshQ_Server self, $Cont C_cont);
/*
#line 453 "src/ssh.act"
$R sshQ_ServerD__cleanup_nativeG_local (sshQ_Server self, $Cont C_cont) {
    #line 454 "src/ssh.act"
    // NotImplemented
    return $R_CONT(C_cont, B_None);
}
*/
#line 456 "src/ssh.act"
$R sshQ_ServerD___cleanup__G_local (sshQ_Server self, $Cont C_cont) {
    if (((uint64_t)((sshQ_Server)(self))->_server) != 0UL) {
        return (($R (*) ($WORD, $Cont))((sshQ_Server)(self))->$class->_cleanup_nativeG_local)(self, (($Cont)sshQ_L_89ContG_new(C_cont)));
    }
    else {
        return $R_CONT((($Cont)sshQ_L_90ContG_new(C_cont)), B_None);
    }
}
#line 460 "src/ssh.act"
$R sshQ_ServerD_on_session_pendingG_local (sshQ_Server self, $Cont C_cont, uint64_t session_id) {
    return sshQ_ServerSessionG_newact((($Cont)sshQ_L_92ContG_new(C_cont)), self, session_id, ((sshQ_Server)(self))->on_auth, ((sshQ_Server)(self))->on_channel_open, ((sshQ_Server)(self))->on_exec, ((sshQ_Server)(self))->on_subsystem, ((sshQ_Server)(self))->on_session_close);
}
#line 469 "src/ssh.act"
$R sshQ_ServerD_on_session_readyG_local (sshQ_Server self, $Cont C_cont, sshQ_ServerSession session) {
    #line 470 "src/ssh.act"
    ((B_Msg (*) ($WORD, sshQ_ServerSession))(($action)(((sshQ_Server)(self))->on_session))->$class->__asyn__)(((sshQ_Server)(self))->on_session, session);
    return $R_CONT(C_cont, B_None);
}
B_Msg sshQ_ServerD__pin_affinity (sshQ_Server self) {
    return $ASYNC((($Actor)self), (($Cont)sshQ_L_93procG_new(self)));
}
B_Msg sshQ_ServerD__init (sshQ_Server self) {
    return $ASYNC((($Actor)self), (($Cont)sshQ_L_94procG_new(self)));
}
B_Msg sshQ_ServerD_close (sshQ_Server self) {
    return $ASYNC((($Actor)self), (($Cont)sshQ_L_95procG_new(self)));
}
B_Msg sshQ_ServerD_bound_port (sshQ_Server self) {
    return ((B_Msg)$ASYNC((($Actor)self), (($Cont)sshQ_L_96procG_new(self))));
}
B_Msg sshQ_ServerD__cleanup_native (sshQ_Server self) {
    return $ASYNC((($Actor)self), (($Cont)sshQ_L_97procG_new(self)));
}
B_Msg sshQ_ServerD___cleanup__ (sshQ_Server self) {
    return $ASYNC((($Actor)self), (($Cont)sshQ_L_98procG_new(self)));
}
B_Msg sshQ_ServerD_on_session_pending (sshQ_Server self, uint64_t session_id) {
    return $ASYNC((($Actor)self), (($Cont)sshQ_L_99procG_new(self, session_id)));
}
B_Msg sshQ_ServerD_on_session_ready (sshQ_Server self, sshQ_ServerSession session) {
    return $ASYNC((($Actor)self), (($Cont)sshQ_L_100procG_new(self, session)));
}
void sshQ_ServerD___serialize__ (sshQ_Server self, $Serial$state state) {
    $ActorG_methods.__serialize__(($Actor)self, state);
    $step_serialize(self->cap, state);
    $step_serialize(self->host, state);
    $val_serialize(U16_ID, &self->port, state);
    $step_serialize(self->on_listen, state);
    $step_serialize(self->on_close, state);
    $step_serialize(self->on_session, state);
    $step_serialize(self->on_auth, state);
    $step_serialize(self->on_channel_open, state);
    $step_serialize(self->N_default_on_exec, state);
    $step_serialize(self->N_default_on_subsystem, state);
    $step_serialize(self->N_default_on_session_close, state);
    $step_serialize(self->N_default_host_key_path, state);
    $step_serialize(self->N_default_host_key_type, state);
    $step_serialize(self->N_default_host_key_bits, state);
    $step_serialize(self->N_default_auth_timeout, state);
    $step_serialize(self->N_default_keepalive_interval, state);
    $step_serialize(self->N_default_keepalive_enabled, state);
    $step_serialize(self->N_default_close_timeout, state);
    $step_serialize(self->N_default_max_sessions, state);
    $step_serialize(self->N_default_max_channels_per_session, state);
    $step_serialize(self->N_default_max_write_buffer, state);
    $step_serialize(self->on_exec, state);
    $step_serialize(self->on_subsystem, state);
    $step_serialize(self->on_session_close, state);
    $step_serialize(self->host_key_path, state);
    $step_serialize(self->host_key_type, state);
    $val_serialize(I64_ID, &self->host_key_bits, state);
    $val_serialize(FLOAT_ID, &self->auth_timeout, state);
    $val_serialize(FLOAT_ID, &self->keepalive_interval, state);
    $step_serialize(self->keepalive_enabled, state);
    $val_serialize(FLOAT_ID, &self->close_timeout, state);
    $val_serialize(I64_ID, &self->max_sessions, state);
    $val_serialize(I64_ID, &self->max_channels_per_session, state);
    $val_serialize(I64_ID, &self->max_write_buffer, state);
    $val_serialize(U64_ID, &self->_server, state);
    $val_serialize(U16_ID, &self->_bound_port, state);
    $step_serialize(self->_host, state);
    $val_serialize(U16_ID, &self->_port, state);
    $step_serialize(self->_host_key_path, state);
    $step_serialize(self->_host_key_type, state);
    $val_serialize(I64_ID, &self->_host_key_bits, state);
    $val_serialize(FLOAT_ID, &self->_auth_timeout, state);
    $val_serialize(FLOAT_ID, &self->_keepalive_interval, state);
    $step_serialize(self->_keepalive_enabled, state);
    $val_serialize(FLOAT_ID, &self->_close_timeout, state);
    $val_serialize(I64_ID, &self->_max_sessions, state);
    $val_serialize(I64_ID, &self->_max_channels_per_session, state);
    $val_serialize(I64_ID, &self->_max_write_buffer, state);
    $step_serialize(self->_on_listen, state);
    $step_serialize(self->_on_close, state);
}
sshQ_Server sshQ_ServerD___deserialize__ (sshQ_Server self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_Server));
            self->$class = &sshQ_ServerG_methods;
            return self;
        }
        self = $DNEW(sshQ_Server, state);
    }
    $ActorG_methods.__deserialize__(($Actor)self, state);
    self->cap = $step_deserialize(state);
    self->host = $step_deserialize(state);
    $tmp = $val_deserialize(state);
    memcpy(&self->port, &$tmp, sizeof(self->port));
    self->on_listen = $step_deserialize(state);
    self->on_close = $step_deserialize(state);
    self->on_session = $step_deserialize(state);
    self->on_auth = $step_deserialize(state);
    self->on_channel_open = $step_deserialize(state);
    self->N_default_on_exec = $step_deserialize(state);
    self->N_default_on_subsystem = $step_deserialize(state);
    self->N_default_on_session_close = $step_deserialize(state);
    self->N_default_host_key_path = $step_deserialize(state);
    self->N_default_host_key_type = $step_deserialize(state);
    self->N_default_host_key_bits = $step_deserialize(state);
    self->N_default_auth_timeout = $step_deserialize(state);
    self->N_default_keepalive_interval = $step_deserialize(state);
    self->N_default_keepalive_enabled = $step_deserialize(state);
    self->N_default_close_timeout = $step_deserialize(state);
    self->N_default_max_sessions = $step_deserialize(state);
    self->N_default_max_channels_per_session = $step_deserialize(state);
    self->N_default_max_write_buffer = $step_deserialize(state);
    self->on_exec = $step_deserialize(state);
    self->on_subsystem = $step_deserialize(state);
    self->on_session_close = $step_deserialize(state);
    self->host_key_path = $step_deserialize(state);
    self->host_key_type = $step_deserialize(state);
    $tmp = $val_deserialize(state);
    memcpy(&self->host_key_bits, &$tmp, sizeof(self->host_key_bits));
    $tmp = $val_deserialize(state);
    memcpy(&self->auth_timeout, &$tmp, sizeof(self->auth_timeout));
    $tmp = $val_deserialize(state);
    memcpy(&self->keepalive_interval, &$tmp, sizeof(self->keepalive_interval));
    self->keepalive_enabled = $step_deserialize(state);
    $tmp = $val_deserialize(state);
    memcpy(&self->close_timeout, &$tmp, sizeof(self->close_timeout));
    $tmp = $val_deserialize(state);
    memcpy(&self->max_sessions, &$tmp, sizeof(self->max_sessions));
    $tmp = $val_deserialize(state);
    memcpy(&self->max_channels_per_session, &$tmp, sizeof(self->max_channels_per_session));
    $tmp = $val_deserialize(state);
    memcpy(&self->max_write_buffer, &$tmp, sizeof(self->max_write_buffer));
    $tmp = $val_deserialize(state);
    memcpy(&self->_server, &$tmp, sizeof(self->_server));
    $tmp = $val_deserialize(state);
    memcpy(&self->_bound_port, &$tmp, sizeof(self->_bound_port));
    self->_host = $step_deserialize(state);
    $tmp = $val_deserialize(state);
    memcpy(&self->_port, &$tmp, sizeof(self->_port));
    self->_host_key_path = $step_deserialize(state);
    self->_host_key_type = $step_deserialize(state);
    $tmp = $val_deserialize(state);
    memcpy(&self->_host_key_bits, &$tmp, sizeof(self->_host_key_bits));
    $tmp = $val_deserialize(state);
    memcpy(&self->_auth_timeout, &$tmp, sizeof(self->_auth_timeout));
    $tmp = $val_deserialize(state);
    memcpy(&self->_keepalive_interval, &$tmp, sizeof(self->_keepalive_interval));
    self->_keepalive_enabled = $step_deserialize(state);
    $tmp = $val_deserialize(state);
    memcpy(&self->_close_timeout, &$tmp, sizeof(self->_close_timeout));
    $tmp = $val_deserialize(state);
    memcpy(&self->_max_sessions, &$tmp, sizeof(self->_max_sessions));
    $tmp = $val_deserialize(state);
    memcpy(&self->_max_channels_per_session, &$tmp, sizeof(self->_max_channels_per_session));
    $tmp = $val_deserialize(state);
    memcpy(&self->_max_write_buffer, &$tmp, sizeof(self->_max_write_buffer));
    self->_on_listen = $step_deserialize(state);
    self->_on_close = $step_deserialize(state);
    return self;
}
void sshQ_ServerD_GCfinalizer (void *obj, void *cdata) {
    sshQ_Server self = (sshQ_Server)obj;
    self->$class->__cleanup__(self);
}
$R sshQ_ServerG_new($Cont G_1, netQ_TCPListenCap G_2, B_str G_3, uint16_t G_4, $action G_5, $action G_6, $action G_7, $action G_8, $action G_9, $action G_10, $action G_11, $action G_12, B_str G_13, B_str G_14, B_int G_15, B_float G_16, B_float G_17, B_bool G_18, B_float G_19, B_int G_20, B_int G_21, B_int G_22) {
    sshQ_Server $tmp = acton_malloc(sizeof(struct sshQ_Server));
    $tmp->$class = &sshQ_ServerG_methods;
    return sshQ_ServerG_methods.__init__($tmp, $CONSTCONT($tmp, G_1), G_2, G_3, G_4, G_5, G_6, G_7, G_8, G_9, G_10, G_11, G_12, G_13, G_14, G_15, G_16, G_17, G_18, G_19, G_20, G_21, G_22);
}
struct sshQ_ServerG_class sshQ_ServerG_methods;
$R sshQ_ServerSessionD___init__ (sshQ_ServerSession self, $Cont C_cont, sshQ_Server server, uint64_t session_id, $action on_auth, $action on_channel_open, $action N_default_on_exec, $action N_default_on_subsystem, $action N_default_on_close) {
    ((sshQ_ServerSession)(self))->server = server;
    ((sshQ_ServerSession)(self))->session_id = session_id;
    ((sshQ_ServerSession)(self))->on_auth = on_auth;
    ((sshQ_ServerSession)(self))->on_channel_open = on_channel_open;
    ((sshQ_ServerSession)(self))->N_default_on_exec = N_default_on_exec;
    ((sshQ_ServerSession)(self))->N_default_on_subsystem = N_default_on_subsystem;
    ((sshQ_ServerSession)(self))->N_default_on_close = N_default_on_close;
    ((sshQ_ServerSession)(self))->on_exec = (($ISNONE0(((sshQ_ServerSession)(self))->N_default_on_exec)) ? B_None : ((sshQ_ServerSession)(self))->N_default_on_exec);
    ((sshQ_ServerSession)(self))->on_subsystem = (($ISNONE0(((sshQ_ServerSession)(self))->N_default_on_subsystem)) ? B_None : ((sshQ_ServerSession)(self))->N_default_on_subsystem);
    ((sshQ_ServerSession)(self))->on_close = (($ISNONE0(((sshQ_ServerSession)(self))->N_default_on_close)) ? B_None : ((sshQ_ServerSession)(self))->N_default_on_close);
    #line 487 "src/ssh.act"
    ((sshQ_ServerSession)(self))->_session_id = 0UL;
    #line 488 "src/ssh.act"
    ((sshQ_ServerSession)(self))->_on_auth = ((sshQ_ServerSession)(self))->on_auth;
    #line 489 "src/ssh.act"
    ((sshQ_ServerSession)(self))->_on_channel_open = ((sshQ_ServerSession)(self))->on_channel_open;
    #line 490 "src/ssh.act"
    ((sshQ_ServerSession)(self))->_on_exec = ((sshQ_ServerSession)(self))->on_exec;
    #line 491 "src/ssh.act"
    ((sshQ_ServerSession)(self))->_on_subsystem = ((sshQ_ServerSession)(self))->on_subsystem;
    #line 492 "src/ssh.act"
    ((sshQ_ServerSession)(self))->_on_close = ((sshQ_ServerSession)(self))->on_close;
    return (($R (*) ($WORD, $Cont))((sshQ_ServerSession)(self))->$class->_pin_affinityG_local)(self, (($Cont)sshQ_L_103ContG_new(self, C_cont)));
}
$R sshQ_ServerSessionD__pin_affinityG_local (sshQ_ServerSession self, $Cont C_cont);
/*
#line 494 "src/ssh.act"
$R sshQ_ServerSessionD__pin_affinityG_local (sshQ_ServerSession self, $Cont C_cont) {
    #line 495 "src/ssh.act"
    // NotImplemented
    return $R_CONT(C_cont, B_None);
}
*/
$R sshQ_ServerSessionD__attachG_local (sshQ_ServerSession self, $Cont C_cont, uint64_t session_id);
/*
#line 498 "src/ssh.act"
$R sshQ_ServerSessionD__attachG_local (sshQ_ServerSession self, $Cont C_cont, uint64_t session_id) {
    #line 499 "src/ssh.act"
    // NotImplemented
    return $R_CONT(C_cont, B_None);
}
*/
$R sshQ_ServerSessionD__drive_attachedG_local (sshQ_ServerSession self, $Cont C_cont);
/*
#line 501 "src/ssh.act"
$R sshQ_ServerSessionD__drive_attachedG_local (sshQ_ServerSession self, $Cont C_cont) {
    #line 502 "src/ssh.act"
    // NotImplemented
    return $R_CONT(C_cont, B_None);
}
*/
#line 504 "src/ssh.act"
$R sshQ_ServerSessionD__attach_readyG_local (sshQ_ServerSession self, $Cont C_cont) {
    return (($R (*) ($WORD, $Cont, uint64_t))((sshQ_ServerSession)(self))->$class->_attachG_local)(self, (($Cont)sshQ_L_108ContG_new(C_cont, self)), ((uint64_t)((sshQ_ServerSession)(self))->session_id));
}
$R sshQ_ServerSessionD_accept_authG_local (sshQ_ServerSession self, $Cont C_cont);
/*
#line 512 "src/ssh.act"
$R sshQ_ServerSessionD_accept_authG_local (sshQ_ServerSession self, $Cont C_cont) {
    #line 514 "src/ssh.act"
    // NotImplemented
    return $R_CONT(C_cont, B_None);
}
*/
$R sshQ_ServerSessionD_reject_authG_local (sshQ_ServerSession self, $Cont C_cont, B_str reason);
/*
#line 516 "src/ssh.act"
$R sshQ_ServerSessionD_reject_authG_local (sshQ_ServerSession self, $Cont C_cont, B_str reason) {
    #line 518 "src/ssh.act"
    // NotImplemented
    return $R_CONT(C_cont, B_None);
}
*/
#line 520 "src/ssh.act"
$R sshQ_ServerSessionD_accept_channelG_local (sshQ_ServerSession self, $Cont C_cont, sshQ_ServerChannel channel) {
    #line 522 "src/ssh.act"
    ((B_Msg (*) ($WORD))((sshQ_ServerChannel)(channel))->$class->accept_open)(channel);
    return $R_CONT(C_cont, B_None);
}
$R sshQ_ServerSessionD_accept_channel_openG_local (sshQ_ServerSession self, $Cont C_cont, sshQ_ServerChannel channel, $action on_data, $action on_stderr, $action on_close);
/*
#line 524 "src/ssh.act"
$R sshQ_ServerSessionD_accept_channel_openG_local (sshQ_ServerSession self, $Cont C_cont, sshQ_ServerChannel channel, $action on_data, $action on_stderr, $action on_close) {
    #line 528 "src/ssh.act"
    // NotImplemented
    return $R_CONT(C_cont, B_None);
}
*/
$R sshQ_ServerSessionD_reject_channelG_local (sshQ_ServerSession self, $Cont C_cont, B_str reason);
/*
#line 530 "src/ssh.act"
$R sshQ_ServerSessionD_reject_channelG_local (sshQ_ServerSession self, $Cont C_cont, B_str reason) {
    #line 532 "src/ssh.act"
    // NotImplemented
    return $R_CONT(C_cont, B_None);
}
*/
$R sshQ_ServerSessionD_closeG_local (sshQ_ServerSession self, $Cont C_cont);
/*
#line 534 "src/ssh.act"
$R sshQ_ServerSessionD_closeG_local (sshQ_ServerSession self, $Cont C_cont) {
    #line 536 "src/ssh.act"
    // NotImplemented
    return $R_CONT(C_cont, B_None);
}
*/
$R sshQ_ServerSessionD__cleanup_nativeG_local (sshQ_ServerSession self, $Cont C_cont);
/*
#line 538 "src/ssh.act"
$R sshQ_ServerSessionD__cleanup_nativeG_local (sshQ_ServerSession self, $Cont C_cont) {
    #line 539 "src/ssh.act"
    // NotImplemented
    return $R_CONT(C_cont, B_None);
}
*/
#line 541 "src/ssh.act"
$R sshQ_ServerSessionD___cleanup__G_local (sshQ_ServerSession self, $Cont C_cont) {
    if (((uint64_t)((sshQ_ServerSession)(self))->_session_id) != 0UL) {
        return (($R (*) ($WORD, $Cont))((sshQ_ServerSession)(self))->$class->_cleanup_nativeG_local)(self, (($Cont)sshQ_L_110ContG_new(C_cont)));
    }
    else {
        return $R_CONT((($Cont)sshQ_L_111ContG_new(C_cont)), B_None);
    }
}
$R sshQ_ServerSessionD_channel_accept_requestG_local (sshQ_ServerSession self, $Cont C_cont, sshQ_ServerChannel channel);
/*
#line 546 "src/ssh.act"
$R sshQ_ServerSessionD_channel_accept_requestG_local (sshQ_ServerSession self, $Cont C_cont, sshQ_ServerChannel channel) {
    #line 547 "src/ssh.act"
    // NotImplemented
    return $R_CONT(C_cont, B_None);
}
*/
$R sshQ_ServerSessionD_channel_reject_requestG_local (sshQ_ServerSession self, $Cont C_cont, sshQ_ServerChannel channel, B_str reason);
/*
#line 549 "src/ssh.act"
$R sshQ_ServerSessionD_channel_reject_requestG_local (sshQ_ServerSession self, $Cont C_cont, sshQ_ServerChannel channel, B_str reason) {
    #line 550 "src/ssh.act"
    // NotImplemented
    return $R_CONT(C_cont, B_None);
}
*/
$R sshQ_ServerSessionD_channel_writeG_local (sshQ_ServerSession self, $Cont C_cont, sshQ_ServerChannel channel, B_bytes data);
/*
#line 552 "src/ssh.act"
$R sshQ_ServerSessionD_channel_writeG_local (sshQ_ServerSession self, $Cont C_cont, sshQ_ServerChannel channel, B_bytes data) {
    #line 553 "src/ssh.act"
    // NotImplemented
    return $R_CONT(C_cont, B_None);
}
*/
$R sshQ_ServerSessionD_channel_write_stderrG_local (sshQ_ServerSession self, $Cont C_cont, sshQ_ServerChannel channel, B_bytes data);
/*
#line 555 "src/ssh.act"
$R sshQ_ServerSessionD_channel_write_stderrG_local (sshQ_ServerSession self, $Cont C_cont, sshQ_ServerChannel channel, B_bytes data) {
    #line 556 "src/ssh.act"
    // NotImplemented
    return $R_CONT(C_cont, B_None);
}
*/
$R sshQ_ServerSessionD_channel_send_eofG_local (sshQ_ServerSession self, $Cont C_cont, sshQ_ServerChannel channel);
/*
#line 558 "src/ssh.act"
$R sshQ_ServerSessionD_channel_send_eofG_local (sshQ_ServerSession self, $Cont C_cont, sshQ_ServerChannel channel) {
    #line 559 "src/ssh.act"
    // NotImplemented
    return $R_CONT(C_cont, B_None);
}
*/
$R sshQ_ServerSessionD_channel_send_exit_statusG_local (sshQ_ServerSession self, $Cont C_cont, sshQ_ServerChannel channel, int64_t status);
/*
#line 561 "src/ssh.act"
$R sshQ_ServerSessionD_channel_send_exit_statusG_local (sshQ_ServerSession self, $Cont C_cont, sshQ_ServerChannel channel, int64_t status) {
    #line 562 "src/ssh.act"
    // NotImplemented
    return $R_CONT(C_cont, B_None);
}
*/
$R sshQ_ServerSessionD_channel_closeG_local (sshQ_ServerSession self, $Cont C_cont, sshQ_ServerChannel channel);
/*
#line 564 "src/ssh.act"
$R sshQ_ServerSessionD_channel_closeG_local (sshQ_ServerSession self, $Cont C_cont, sshQ_ServerChannel channel) {
    #line 565 "src/ssh.act"
    // NotImplemented
    return $R_CONT(C_cont, B_None);
}
*/
B_Msg sshQ_ServerSessionD__pin_affinity (sshQ_ServerSession self) {
    return $ASYNC((($Actor)self), (($Cont)sshQ_L_112procG_new(self)));
}
B_Msg sshQ_ServerSessionD__attach (sshQ_ServerSession self, uint64_t session_id) {
    return $ASYNC((($Actor)self), (($Cont)sshQ_L_113procG_new(self, session_id)));
}
B_Msg sshQ_ServerSessionD__drive_attached (sshQ_ServerSession self) {
    return $ASYNC((($Actor)self), (($Cont)sshQ_L_114procG_new(self)));
}
B_Msg sshQ_ServerSessionD__attach_ready (sshQ_ServerSession self) {
    return $ASYNC((($Actor)self), (($Cont)sshQ_L_115procG_new(self)));
}
B_Msg sshQ_ServerSessionD_accept_auth (sshQ_ServerSession self) {
    return $ASYNC((($Actor)self), (($Cont)sshQ_L_116procG_new(self)));
}
B_Msg sshQ_ServerSessionD_reject_auth (sshQ_ServerSession self, B_str reason) {
    return $ASYNC((($Actor)self), (($Cont)sshQ_L_117procG_new(self, reason)));
}
B_Msg sshQ_ServerSessionD_accept_channel (sshQ_ServerSession self, sshQ_ServerChannel channel) {
    return $ASYNC((($Actor)self), (($Cont)sshQ_L_118procG_new(self, channel)));
}
B_Msg sshQ_ServerSessionD_accept_channel_open (sshQ_ServerSession self, sshQ_ServerChannel channel, $action on_data, $action on_stderr, $action on_close) {
    return $ASYNC((($Actor)self), (($Cont)sshQ_L_119procG_new(self, channel, on_data, on_stderr, on_close)));
}
B_Msg sshQ_ServerSessionD_reject_channel (sshQ_ServerSession self, B_str reason) {
    return $ASYNC((($Actor)self), (($Cont)sshQ_L_120procG_new(self, reason)));
}
B_Msg sshQ_ServerSessionD_close (sshQ_ServerSession self) {
    return $ASYNC((($Actor)self), (($Cont)sshQ_L_121procG_new(self)));
}
B_Msg sshQ_ServerSessionD__cleanup_native (sshQ_ServerSession self) {
    return $ASYNC((($Actor)self), (($Cont)sshQ_L_122procG_new(self)));
}
B_Msg sshQ_ServerSessionD___cleanup__ (sshQ_ServerSession self) {
    return $ASYNC((($Actor)self), (($Cont)sshQ_L_123procG_new(self)));
}
B_Msg sshQ_ServerSessionD_channel_accept_request (sshQ_ServerSession self, sshQ_ServerChannel channel) {
    return $ASYNC((($Actor)self), (($Cont)sshQ_L_124procG_new(self, channel)));
}
B_Msg sshQ_ServerSessionD_channel_reject_request (sshQ_ServerSession self, sshQ_ServerChannel channel, B_str reason) {
    return $ASYNC((($Actor)self), (($Cont)sshQ_L_125procG_new(self, channel, reason)));
}
B_Msg sshQ_ServerSessionD_channel_write (sshQ_ServerSession self, sshQ_ServerChannel channel, B_bytes data) {
    return $ASYNC((($Actor)self), (($Cont)sshQ_L_126procG_new(self, channel, data)));
}
B_Msg sshQ_ServerSessionD_channel_write_stderr (sshQ_ServerSession self, sshQ_ServerChannel channel, B_bytes data) {
    return $ASYNC((($Actor)self), (($Cont)sshQ_L_127procG_new(self, channel, data)));
}
B_Msg sshQ_ServerSessionD_channel_send_eof (sshQ_ServerSession self, sshQ_ServerChannel channel) {
    return $ASYNC((($Actor)self), (($Cont)sshQ_L_128procG_new(self, channel)));
}
B_Msg sshQ_ServerSessionD_channel_send_exit_status (sshQ_ServerSession self, sshQ_ServerChannel channel, int64_t status) {
    return $ASYNC((($Actor)self), (($Cont)sshQ_L_129procG_new(self, channel, status)));
}
B_Msg sshQ_ServerSessionD_channel_close (sshQ_ServerSession self, sshQ_ServerChannel channel) {
    return $ASYNC((($Actor)self), (($Cont)sshQ_L_130procG_new(self, channel)));
}
void sshQ_ServerSessionD___serialize__ (sshQ_ServerSession self, $Serial$state state) {
    $ActorG_methods.__serialize__(($Actor)self, state);
    $step_serialize(self->server, state);
    $val_serialize(U64_ID, &self->session_id, state);
    $step_serialize(self->on_auth, state);
    $step_serialize(self->on_channel_open, state);
    $step_serialize(self->N_default_on_exec, state);
    $step_serialize(self->N_default_on_subsystem, state);
    $step_serialize(self->N_default_on_close, state);
    $step_serialize(self->on_exec, state);
    $step_serialize(self->on_subsystem, state);
    $step_serialize(self->on_close, state);
    $val_serialize(U64_ID, &self->_session_id, state);
    $step_serialize(self->_on_auth, state);
    $step_serialize(self->_on_channel_open, state);
    $step_serialize(self->_on_exec, state);
    $step_serialize(self->_on_subsystem, state);
    $step_serialize(self->_on_close, state);
}
sshQ_ServerSession sshQ_ServerSessionD___deserialize__ (sshQ_ServerSession self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_ServerSession));
            self->$class = &sshQ_ServerSessionG_methods;
            return self;
        }
        self = $DNEW(sshQ_ServerSession, state);
    }
    $ActorG_methods.__deserialize__(($Actor)self, state);
    self->server = $step_deserialize(state);
    $tmp = $val_deserialize(state);
    memcpy(&self->session_id, &$tmp, sizeof(self->session_id));
    self->on_auth = $step_deserialize(state);
    self->on_channel_open = $step_deserialize(state);
    self->N_default_on_exec = $step_deserialize(state);
    self->N_default_on_subsystem = $step_deserialize(state);
    self->N_default_on_close = $step_deserialize(state);
    self->on_exec = $step_deserialize(state);
    self->on_subsystem = $step_deserialize(state);
    self->on_close = $step_deserialize(state);
    $tmp = $val_deserialize(state);
    memcpy(&self->_session_id, &$tmp, sizeof(self->_session_id));
    self->_on_auth = $step_deserialize(state);
    self->_on_channel_open = $step_deserialize(state);
    self->_on_exec = $step_deserialize(state);
    self->_on_subsystem = $step_deserialize(state);
    self->_on_close = $step_deserialize(state);
    return self;
}
void sshQ_ServerSessionD_GCfinalizer (void *obj, void *cdata) {
    sshQ_ServerSession self = (sshQ_ServerSession)obj;
    self->$class->__cleanup__(self);
}
$R sshQ_ServerSessionG_new($Cont G_1, sshQ_Server G_2, uint64_t G_3, $action G_4, $action G_5, $action G_6, $action G_7, $action G_8) {
    sshQ_ServerSession $tmp = acton_malloc(sizeof(struct sshQ_ServerSession));
    $tmp->$class = &sshQ_ServerSessionG_methods;
    return sshQ_ServerSessionG_methods.__init__($tmp, $CONSTCONT($tmp, G_1), G_2, G_3, G_4, G_5, G_6, G_7, G_8);
}
struct sshQ_ServerSessionG_class sshQ_ServerSessionG_methods;
$R sshQ_ServerChannelD___init__ (sshQ_ServerChannel self, $Cont C_cont, sshQ_ServerSession session, $action on_data, $action on_stderr, $action on_close) {
    ((sshQ_ServerChannel)(self))->session = session;
    ((sshQ_ServerChannel)(self))->on_data = on_data;
    ((sshQ_ServerChannel)(self))->on_stderr = on_stderr;
    ((sshQ_ServerChannel)(self))->on_close = on_close;
    #line 579 "src/ssh.act"
    ((sshQ_ServerChannel)(self))->_channel_id = 0UL;
    #line 580 "src/ssh.act"
    ((sshQ_ServerChannel)(self))->_on_data = ((sshQ_ServerChannel)(self))->on_data;
    #line 581 "src/ssh.act"
    ((sshQ_ServerChannel)(self))->_on_stderr = ((sshQ_ServerChannel)(self))->on_stderr;
    #line 582 "src/ssh.act"
    ((sshQ_ServerChannel)(self))->_on_close = ((sshQ_ServerChannel)(self))->on_close;
    return $R_CONT(C_cont, B_None);
}
#line 584 "src/ssh.act"
$R sshQ_ServerChannelD_accept_requestG_local (sshQ_ServerChannel self, $Cont C_cont) {
    #line 586 "src/ssh.act"
    ((B_Msg (*) ($WORD, sshQ_ServerChannel))((sshQ_ServerSession)(((sshQ_ServerChannel)(self))->session))->$class->channel_accept_request)(((sshQ_ServerChannel)(self))->session, self);
    return $R_CONT(C_cont, B_None);
}
#line 588 "src/ssh.act"
$R sshQ_ServerChannelD_accept_openG_local (sshQ_ServerChannel self, $Cont C_cont) {
    #line 590 "src/ssh.act"
    ((B_Msg (*) ($WORD, sshQ_ServerChannel, $action, $action, $action))((sshQ_ServerSession)(((sshQ_ServerChannel)(self))->session))->$class->accept_channel_open)(((sshQ_ServerChannel)(self))->session, self, ((sshQ_ServerChannel)(self))->_on_data, ((sshQ_ServerChannel)(self))->_on_stderr, ((sshQ_ServerChannel)(self))->_on_close);
    return $R_CONT(C_cont, B_None);
}
#line 592 "src/ssh.act"
$R sshQ_ServerChannelD_reject_requestG_local (sshQ_ServerChannel self, $Cont C_cont, B_str reason) {
    #line 594 "src/ssh.act"
    ((B_Msg (*) ($WORD, sshQ_ServerChannel, B_str))((sshQ_ServerSession)(((sshQ_ServerChannel)(self))->session))->$class->channel_reject_request)(((sshQ_ServerChannel)(self))->session, self, reason);
    return $R_CONT(C_cont, B_None);
}
#line 596 "src/ssh.act"
$R sshQ_ServerChannelD_writeG_local (sshQ_ServerChannel self, $Cont C_cont, B_bytes data) {
    #line 598 "src/ssh.act"
    ((B_Msg (*) ($WORD, sshQ_ServerChannel, B_bytes))((sshQ_ServerSession)(((sshQ_ServerChannel)(self))->session))->$class->channel_write)(((sshQ_ServerChannel)(self))->session, self, data);
    return $R_CONT(C_cont, B_None);
}
#line 600 "src/ssh.act"
$R sshQ_ServerChannelD_write_stderrG_local (sshQ_ServerChannel self, $Cont C_cont, B_bytes data) {
    #line 602 "src/ssh.act"
    ((B_Msg (*) ($WORD, sshQ_ServerChannel, B_bytes))((sshQ_ServerSession)(((sshQ_ServerChannel)(self))->session))->$class->channel_write_stderr)(((sshQ_ServerChannel)(self))->session, self, data);
    return $R_CONT(C_cont, B_None);
}
#line 604 "src/ssh.act"
$R sshQ_ServerChannelD_send_eofG_local (sshQ_ServerChannel self, $Cont C_cont) {
    #line 606 "src/ssh.act"
    ((B_Msg (*) ($WORD, sshQ_ServerChannel))((sshQ_ServerSession)(((sshQ_ServerChannel)(self))->session))->$class->channel_send_eof)(((sshQ_ServerChannel)(self))->session, self);
    return $R_CONT(C_cont, B_None);
}
#line 608 "src/ssh.act"
$R sshQ_ServerChannelD_send_exit_statusG_local (sshQ_ServerChannel self, $Cont C_cont, int64_t status) {
    #line 610 "src/ssh.act"
    ((B_Msg (*) ($WORD, sshQ_ServerChannel, int64_t))((sshQ_ServerSession)(((sshQ_ServerChannel)(self))->session))->$class->channel_send_exit_status)(((sshQ_ServerChannel)(self))->session, self, status);
    return $R_CONT(C_cont, B_None);
}
#line 612 "src/ssh.act"
$R sshQ_ServerChannelD_closeG_local (sshQ_ServerChannel self, $Cont C_cont) {
    #line 614 "src/ssh.act"
    ((B_Msg (*) ($WORD, sshQ_ServerChannel))((sshQ_ServerSession)(((sshQ_ServerChannel)(self))->session))->$class->channel_close)(((sshQ_ServerChannel)(self))->session, self);
    return $R_CONT(C_cont, B_None);
}
$R sshQ_ServerChannelD__cleanup_nativeG_local (sshQ_ServerChannel self, $Cont C_cont);
/*
#line 616 "src/ssh.act"
$R sshQ_ServerChannelD__cleanup_nativeG_local (sshQ_ServerChannel self, $Cont C_cont) {
    #line 617 "src/ssh.act"
    // NotImplemented
    return $R_CONT(C_cont, B_None);
}
*/
#line 619 "src/ssh.act"
$R sshQ_ServerChannelD___cleanup__G_local (sshQ_ServerChannel self, $Cont C_cont) {
    if (((uint64_t)((sshQ_ServerChannel)(self))->_channel_id) != 0UL) {
        return (($R (*) ($WORD, $Cont))((sshQ_ServerChannel)(self))->$class->_cleanup_nativeG_local)(self, (($Cont)sshQ_L_132ContG_new(C_cont)));
    }
    else {
        return $R_CONT((($Cont)sshQ_L_133ContG_new(C_cont)), B_None);
    }
}
B_Msg sshQ_ServerChannelD_accept_request (sshQ_ServerChannel self) {
    return $ASYNC((($Actor)self), (($Cont)sshQ_L_134procG_new(self)));
}
B_Msg sshQ_ServerChannelD_accept_open (sshQ_ServerChannel self) {
    return $ASYNC((($Actor)self), (($Cont)sshQ_L_135procG_new(self)));
}
B_Msg sshQ_ServerChannelD_reject_request (sshQ_ServerChannel self, B_str reason) {
    return $ASYNC((($Actor)self), (($Cont)sshQ_L_136procG_new(self, reason)));
}
B_Msg sshQ_ServerChannelD_write (sshQ_ServerChannel self, B_bytes data) {
    return $ASYNC((($Actor)self), (($Cont)sshQ_L_137procG_new(self, data)));
}
B_Msg sshQ_ServerChannelD_write_stderr (sshQ_ServerChannel self, B_bytes data) {
    return $ASYNC((($Actor)self), (($Cont)sshQ_L_138procG_new(self, data)));
}
B_Msg sshQ_ServerChannelD_send_eof (sshQ_ServerChannel self) {
    return $ASYNC((($Actor)self), (($Cont)sshQ_L_139procG_new(self)));
}
B_Msg sshQ_ServerChannelD_send_exit_status (sshQ_ServerChannel self, int64_t status) {
    return $ASYNC((($Actor)self), (($Cont)sshQ_L_140procG_new(self, status)));
}
B_Msg sshQ_ServerChannelD_close (sshQ_ServerChannel self) {
    return $ASYNC((($Actor)self), (($Cont)sshQ_L_141procG_new(self)));
}
B_Msg sshQ_ServerChannelD__cleanup_native (sshQ_ServerChannel self) {
    return $ASYNC((($Actor)self), (($Cont)sshQ_L_142procG_new(self)));
}
B_Msg sshQ_ServerChannelD___cleanup__ (sshQ_ServerChannel self) {
    return $ASYNC((($Actor)self), (($Cont)sshQ_L_143procG_new(self)));
}
void sshQ_ServerChannelD___serialize__ (sshQ_ServerChannel self, $Serial$state state) {
    $ActorG_methods.__serialize__(($Actor)self, state);
    $step_serialize(self->session, state);
    $step_serialize(self->on_data, state);
    $step_serialize(self->on_stderr, state);
    $step_serialize(self->on_close, state);
    $val_serialize(U64_ID, &self->_channel_id, state);
    $step_serialize(self->_on_data, state);
    $step_serialize(self->_on_stderr, state);
    $step_serialize(self->_on_close, state);
}
sshQ_ServerChannel sshQ_ServerChannelD___deserialize__ (sshQ_ServerChannel self, $Serial$state state) {
    $WORD $tmp;
    if (!self) {
        if (!state) {
            self = acton_malloc(sizeof(struct sshQ_ServerChannel));
            self->$class = &sshQ_ServerChannelG_methods;
            return self;
        }
        self = $DNEW(sshQ_ServerChannel, state);
    }
    $ActorG_methods.__deserialize__(($Actor)self, state);
    self->session = $step_deserialize(state);
    self->on_data = $step_deserialize(state);
    self->on_stderr = $step_deserialize(state);
    self->on_close = $step_deserialize(state);
    $tmp = $val_deserialize(state);
    memcpy(&self->_channel_id, &$tmp, sizeof(self->_channel_id));
    self->_on_data = $step_deserialize(state);
    self->_on_stderr = $step_deserialize(state);
    self->_on_close = $step_deserialize(state);
    return self;
}
void sshQ_ServerChannelD_GCfinalizer (void *obj, void *cdata) {
    sshQ_ServerChannel self = (sshQ_ServerChannel)obj;
    self->$class->__cleanup__(self);
}
$R sshQ_ServerChannelG_new($Cont G_1, sshQ_ServerSession G_2, $action G_3, $action G_4, $action G_5) {
    sshQ_ServerChannel $tmp = acton_malloc(sizeof(struct sshQ_ServerChannel));
    $tmp->$class = &sshQ_ServerChannelG_methods;
    return sshQ_ServerChannelG_methods.__init__($tmp, $CONSTCONT($tmp, G_1), G_2, G_3, G_4, G_5);
}
struct sshQ_ServerChannelG_class sshQ_ServerChannelG_methods;
$R sshQ_ClientG_newact ($Cont C_cont, netQ_TCPConnectCap cap, B_str host, B_str username, $action on_connect, $action on_close, $action N_default_on_hostkey, B_str N_default_password, B_str N_default_private_key_file, B_str N_default_private_key_passphrase, B_u16 N_default_port, B_str N_default_known_hosts, B_float N_default_connect_timeout, B_float N_default_auth_timeout, B_float N_default_keepalive_interval, B_bool N_default_keepalive_enabled, B_float N_default_close_timeout, B_int N_default_max_write_buffer) {
    sshQ_Client G_act = $NEWACTOR(sshQ_Client);
    if ((void*)G_act->$class->__cleanup__ != (void*)$ActorD___cleanup__) $InstallFinalizer(G_act, sshQ_ClientD_GCfinalizer);
    return $AWAIT((($Cont)sshQ_L_145ContG_new(C_cont, G_act)), $ASYNC((($Actor)G_act), (($Cont)sshQ_L_146procG_new(G_act, cap, host, username, on_connect, on_close, N_default_on_hostkey, N_default_password, N_default_private_key_file, N_default_private_key_passphrase, N_default_port, N_default_known_hosts, N_default_connect_timeout, N_default_auth_timeout, N_default_keepalive_interval, N_default_keepalive_enabled, N_default_close_timeout, N_default_max_write_buffer))));
}
$R sshQ_ChannelG_newact ($Cont C_cont, sshQ_Client client, $action on_open, $action on_stdout, $action on_stderr, $action on_exit, $action on_close) {
    sshQ_Channel G_act = $NEWACTOR(sshQ_Channel);
    if ((void*)G_act->$class->__cleanup__ != (void*)$ActorD___cleanup__) $InstallFinalizer(G_act, sshQ_ChannelD_GCfinalizer);
    return $AWAIT((($Cont)sshQ_L_148ContG_new(C_cont, G_act)), $ASYNC((($Actor)G_act), (($Cont)sshQ_L_149procG_new(G_act, client, on_open, on_stdout, on_stderr, on_exit, on_close))));
}
$R sshQ_RunCommandG_newact ($Cont C_cont, sshQ_Client client, B_str cmd, $action on_exit, B_float N_default_timeout) {
    sshQ_RunCommand G_act = $NEWACTOR(sshQ_RunCommand);
    if ((void*)G_act->$class->__cleanup__ != (void*)$ActorD___cleanup__) $InstallFinalizer(G_act, sshQ_RunCommandD_GCfinalizer);
    return $AWAIT((($Cont)sshQ_L_151ContG_new(C_cont, G_act)), $ASYNC((($Actor)G_act), (($Cont)sshQ_L_152procG_new(G_act, client, cmd, on_exit, N_default_timeout))));
}
$R sshQ_ServerG_newact ($Cont C_cont, netQ_TCPListenCap cap, B_str host, uint16_t port, $action on_listen, $action on_close, $action on_session, $action on_auth, $action on_channel_open, $action N_default_on_exec, $action N_default_on_subsystem, $action N_default_on_session_close, B_str N_default_host_key_path, B_str N_default_host_key_type, B_int N_default_host_key_bits, B_float N_default_auth_timeout, B_float N_default_keepalive_interval, B_bool N_default_keepalive_enabled, B_float N_default_close_timeout, B_int N_default_max_sessions, B_int N_default_max_channels_per_session, B_int N_default_max_write_buffer) {
    sshQ_Server G_act = $NEWACTOR(sshQ_Server);
    if ((void*)G_act->$class->__cleanup__ != (void*)$ActorD___cleanup__) $InstallFinalizer(G_act, sshQ_ServerD_GCfinalizer);
    return $AWAIT((($Cont)sshQ_L_154ContG_new(C_cont, G_act)), $ASYNC((($Actor)G_act), (($Cont)sshQ_L_155procG_new(G_act, cap, host, port, on_listen, on_close, on_session, on_auth, on_channel_open, N_default_on_exec, N_default_on_subsystem, N_default_on_session_close, N_default_host_key_path, N_default_host_key_type, N_default_host_key_bits, N_default_auth_timeout, N_default_keepalive_interval, N_default_keepalive_enabled, N_default_close_timeout, N_default_max_sessions, N_default_max_channels_per_session, N_default_max_write_buffer))));
}
$R sshQ_ServerSessionG_newact ($Cont C_cont, sshQ_Server server, uint64_t session_id, $action on_auth, $action on_channel_open, $action N_default_on_exec, $action N_default_on_subsystem, $action N_default_on_close) {
    sshQ_ServerSession G_act = $NEWACTOR(sshQ_ServerSession);
    if ((void*)G_act->$class->__cleanup__ != (void*)$ActorD___cleanup__) $InstallFinalizer(G_act, sshQ_ServerSessionD_GCfinalizer);
    return $AWAIT((($Cont)sshQ_L_157ContG_new(C_cont, G_act)), $ASYNC((($Actor)G_act), (($Cont)sshQ_L_158procG_new(G_act, server, session_id, on_auth, on_channel_open, N_default_on_exec, N_default_on_subsystem, N_default_on_close))));
}
$R sshQ_ServerChannelG_newact ($Cont C_cont, sshQ_ServerSession session, $action on_data, $action on_stderr, $action on_close) {
    sshQ_ServerChannel G_act = $NEWACTOR(sshQ_ServerChannel);
    if ((void*)G_act->$class->__cleanup__ != (void*)$ActorD___cleanup__) $InstallFinalizer(G_act, sshQ_ServerChannelD_GCfinalizer);
    return $AWAIT((($Cont)sshQ_L_160ContG_new(C_cont, G_act)), $ASYNC((($Actor)G_act), (($Cont)sshQ_L_161procG_new(G_act, session, on_data, on_stderr, on_close))));
}
int sshQ_done$ = 0;
void sshQ___init__ () {
    if (sshQ_done$) return;
    sshQ_done$ = 1;
    sshQ___ext_init__ ();
    netQ___init__();
    {
        sshQ_L_2ContG_methods.$GCINFO = "sshQ_L_2Cont";
        sshQ_L_2ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        sshQ_L_2ContG_methods.__bool__ = (B_bool (*) (sshQ_L_2Cont))B_valueG_methods.__bool__;
        sshQ_L_2ContG_methods.__str__ = (B_str (*) (sshQ_L_2Cont))B_valueG_methods.__str__;
        sshQ_L_2ContG_methods.__repr__ = (B_str (*) (sshQ_L_2Cont))B_valueG_methods.__repr__;
        sshQ_L_2ContG_methods.__init__ = (B_NoneType (*) (sshQ_L_2Cont, sshQ_Client, $Cont))sshQ_L_2ContD___init__;
        sshQ_L_2ContG_methods.__call__ = ($R (*) (sshQ_L_2Cont, B_NoneType))sshQ_L_2ContD___call__;
        sshQ_L_2ContG_methods.__serialize__ = sshQ_L_2ContD___serialize__;
        sshQ_L_2ContG_methods.__deserialize__ = sshQ_L_2ContD___deserialize__;
        $register(&sshQ_L_2ContG_methods);
    }
    {
        sshQ_L_4ContG_methods.$GCINFO = "sshQ_L_4Cont";
        sshQ_L_4ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        sshQ_L_4ContG_methods.__bool__ = (B_bool (*) (sshQ_L_4Cont))B_valueG_methods.__bool__;
        sshQ_L_4ContG_methods.__str__ = (B_str (*) (sshQ_L_4Cont))B_valueG_methods.__str__;
        sshQ_L_4ContG_methods.__repr__ = (B_str (*) (sshQ_L_4Cont))B_valueG_methods.__repr__;
        sshQ_L_4ContG_methods.__init__ = (B_NoneType (*) (sshQ_L_4Cont, $Cont))sshQ_L_4ContD___init__;
        sshQ_L_4ContG_methods.__call__ = ($R (*) (sshQ_L_4Cont, B_NoneType))sshQ_L_4ContD___call__;
        sshQ_L_4ContG_methods.__serialize__ = sshQ_L_4ContD___serialize__;
        sshQ_L_4ContG_methods.__deserialize__ = sshQ_L_4ContD___deserialize__;
        $register(&sshQ_L_4ContG_methods);
    }
    {
        sshQ_L_5ContG_methods.$GCINFO = "sshQ_L_5Cont";
        sshQ_L_5ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        sshQ_L_5ContG_methods.__bool__ = (B_bool (*) (sshQ_L_5Cont))B_valueG_methods.__bool__;
        sshQ_L_5ContG_methods.__str__ = (B_str (*) (sshQ_L_5Cont))B_valueG_methods.__str__;
        sshQ_L_5ContG_methods.__repr__ = (B_str (*) (sshQ_L_5Cont))B_valueG_methods.__repr__;
        sshQ_L_5ContG_methods.__init__ = (B_NoneType (*) (sshQ_L_5Cont, $Cont))sshQ_L_5ContD___init__;
        sshQ_L_5ContG_methods.__call__ = ($R (*) (sshQ_L_5Cont, B_NoneType))sshQ_L_5ContD___call__;
        sshQ_L_5ContG_methods.__serialize__ = sshQ_L_5ContD___serialize__;
        sshQ_L_5ContG_methods.__deserialize__ = sshQ_L_5ContD___deserialize__;
        $register(&sshQ_L_5ContG_methods);
    }
    {
        sshQ_L_6procG_methods.$GCINFO = "sshQ_L_6proc";
        sshQ_L_6procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        sshQ_L_6procG_methods.__bool__ = (B_bool (*) (sshQ_L_6proc))B_valueG_methods.__bool__;
        sshQ_L_6procG_methods.__str__ = (B_str (*) (sshQ_L_6proc))B_valueG_methods.__str__;
        sshQ_L_6procG_methods.__repr__ = (B_str (*) (sshQ_L_6proc))B_valueG_methods.__repr__;
        sshQ_L_6procG_methods.__init__ = (B_NoneType (*) (sshQ_L_6proc, sshQ_Client))sshQ_L_6procD___init__;
        sshQ_L_6procG_methods.__call__ = ($R (*) (sshQ_L_6proc, $Cont))sshQ_L_6procD___call__;
        sshQ_L_6procG_methods.__exec__ = ($R (*) (sshQ_L_6proc, $Cont))sshQ_L_6procD___exec__;
        sshQ_L_6procG_methods.__serialize__ = sshQ_L_6procD___serialize__;
        sshQ_L_6procG_methods.__deserialize__ = sshQ_L_6procD___deserialize__;
        $register(&sshQ_L_6procG_methods);
    }
    {
        sshQ_L_7procG_methods.$GCINFO = "sshQ_L_7proc";
        sshQ_L_7procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        sshQ_L_7procG_methods.__bool__ = (B_bool (*) (sshQ_L_7proc))B_valueG_methods.__bool__;
        sshQ_L_7procG_methods.__str__ = (B_str (*) (sshQ_L_7proc))B_valueG_methods.__str__;
        sshQ_L_7procG_methods.__repr__ = (B_str (*) (sshQ_L_7proc))B_valueG_methods.__repr__;
        sshQ_L_7procG_methods.__init__ = (B_NoneType (*) (sshQ_L_7proc, sshQ_Client))sshQ_L_7procD___init__;
        sshQ_L_7procG_methods.__call__ = ($R (*) (sshQ_L_7proc, $Cont))sshQ_L_7procD___call__;
        sshQ_L_7procG_methods.__exec__ = ($R (*) (sshQ_L_7proc, $Cont))sshQ_L_7procD___exec__;
        sshQ_L_7procG_methods.__serialize__ = sshQ_L_7procD___serialize__;
        sshQ_L_7procG_methods.__deserialize__ = sshQ_L_7procD___deserialize__;
        $register(&sshQ_L_7procG_methods);
    }
    {
        sshQ_L_8procG_methods.$GCINFO = "sshQ_L_8proc";
        sshQ_L_8procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        sshQ_L_8procG_methods.__bool__ = (B_bool (*) (sshQ_L_8proc))B_valueG_methods.__bool__;
        sshQ_L_8procG_methods.__str__ = (B_str (*) (sshQ_L_8proc))B_valueG_methods.__str__;
        sshQ_L_8procG_methods.__repr__ = (B_str (*) (sshQ_L_8proc))B_valueG_methods.__repr__;
        sshQ_L_8procG_methods.__init__ = (B_NoneType (*) (sshQ_L_8proc, sshQ_Client))sshQ_L_8procD___init__;
        sshQ_L_8procG_methods.__call__ = ($R (*) (sshQ_L_8proc, $Cont))sshQ_L_8procD___call__;
        sshQ_L_8procG_methods.__exec__ = ($R (*) (sshQ_L_8proc, $Cont))sshQ_L_8procD___exec__;
        sshQ_L_8procG_methods.__serialize__ = sshQ_L_8procD___serialize__;
        sshQ_L_8procG_methods.__deserialize__ = sshQ_L_8procD___deserialize__;
        $register(&sshQ_L_8procG_methods);
    }
    {
        sshQ_L_9procG_methods.$GCINFO = "sshQ_L_9proc";
        sshQ_L_9procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        sshQ_L_9procG_methods.__bool__ = (B_bool (*) (sshQ_L_9proc))B_valueG_methods.__bool__;
        sshQ_L_9procG_methods.__str__ = (B_str (*) (sshQ_L_9proc))B_valueG_methods.__str__;
        sshQ_L_9procG_methods.__repr__ = (B_str (*) (sshQ_L_9proc))B_valueG_methods.__repr__;
        sshQ_L_9procG_methods.__init__ = (B_NoneType (*) (sshQ_L_9proc, sshQ_Client, B_str))sshQ_L_9procD___init__;
        sshQ_L_9procG_methods.__call__ = ($R (*) (sshQ_L_9proc, $Cont))sshQ_L_9procD___call__;
        sshQ_L_9procG_methods.__exec__ = ($R (*) (sshQ_L_9proc, $Cont))sshQ_L_9procD___exec__;
        sshQ_L_9procG_methods.__serialize__ = sshQ_L_9procD___serialize__;
        sshQ_L_9procG_methods.__deserialize__ = sshQ_L_9procD___deserialize__;
        $register(&sshQ_L_9procG_methods);
    }
    {
        sshQ_L_10procG_methods.$GCINFO = "sshQ_L_10proc";
        sshQ_L_10procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        sshQ_L_10procG_methods.__bool__ = (B_bool (*) (sshQ_L_10proc))B_valueG_methods.__bool__;
        sshQ_L_10procG_methods.__str__ = (B_str (*) (sshQ_L_10proc))B_valueG_methods.__str__;
        sshQ_L_10procG_methods.__repr__ = (B_str (*) (sshQ_L_10proc))B_valueG_methods.__repr__;
        sshQ_L_10procG_methods.__init__ = (B_NoneType (*) (sshQ_L_10proc, sshQ_Client))sshQ_L_10procD___init__;
        sshQ_L_10procG_methods.__call__ = ($R (*) (sshQ_L_10proc, $Cont))sshQ_L_10procD___call__;
        sshQ_L_10procG_methods.__exec__ = ($R (*) (sshQ_L_10proc, $Cont))sshQ_L_10procD___exec__;
        sshQ_L_10procG_methods.__serialize__ = sshQ_L_10procD___serialize__;
        sshQ_L_10procG_methods.__deserialize__ = sshQ_L_10procD___deserialize__;
        $register(&sshQ_L_10procG_methods);
    }
    {
        sshQ_L_11procG_methods.$GCINFO = "sshQ_L_11proc";
        sshQ_L_11procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        sshQ_L_11procG_methods.__bool__ = (B_bool (*) (sshQ_L_11proc))B_valueG_methods.__bool__;
        sshQ_L_11procG_methods.__str__ = (B_str (*) (sshQ_L_11proc))B_valueG_methods.__str__;
        sshQ_L_11procG_methods.__repr__ = (B_str (*) (sshQ_L_11proc))B_valueG_methods.__repr__;
        sshQ_L_11procG_methods.__init__ = (B_NoneType (*) (sshQ_L_11proc, sshQ_Client))sshQ_L_11procD___init__;
        sshQ_L_11procG_methods.__call__ = ($R (*) (sshQ_L_11proc, $Cont))sshQ_L_11procD___call__;
        sshQ_L_11procG_methods.__exec__ = ($R (*) (sshQ_L_11proc, $Cont))sshQ_L_11procD___exec__;
        sshQ_L_11procG_methods.__serialize__ = sshQ_L_11procD___serialize__;
        sshQ_L_11procG_methods.__deserialize__ = sshQ_L_11procD___deserialize__;
        $register(&sshQ_L_11procG_methods);
    }
    {
        sshQ_L_12procG_methods.$GCINFO = "sshQ_L_12proc";
        sshQ_L_12procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        sshQ_L_12procG_methods.__bool__ = (B_bool (*) (sshQ_L_12proc))B_valueG_methods.__bool__;
        sshQ_L_12procG_methods.__str__ = (B_str (*) (sshQ_L_12proc))B_valueG_methods.__str__;
        sshQ_L_12procG_methods.__repr__ = (B_str (*) (sshQ_L_12proc))B_valueG_methods.__repr__;
        sshQ_L_12procG_methods.__init__ = (B_NoneType (*) (sshQ_L_12proc, sshQ_Client))sshQ_L_12procD___init__;
        sshQ_L_12procG_methods.__call__ = ($R (*) (sshQ_L_12proc, $Cont))sshQ_L_12procD___call__;
        sshQ_L_12procG_methods.__exec__ = ($R (*) (sshQ_L_12proc, $Cont))sshQ_L_12procD___exec__;
        sshQ_L_12procG_methods.__serialize__ = sshQ_L_12procD___serialize__;
        sshQ_L_12procG_methods.__deserialize__ = sshQ_L_12procD___deserialize__;
        $register(&sshQ_L_12procG_methods);
    }
    {
        sshQ_L_13procG_methods.$GCINFO = "sshQ_L_13proc";
        sshQ_L_13procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        sshQ_L_13procG_methods.__bool__ = (B_bool (*) (sshQ_L_13proc))B_valueG_methods.__bool__;
        sshQ_L_13procG_methods.__str__ = (B_str (*) (sshQ_L_13proc))B_valueG_methods.__str__;
        sshQ_L_13procG_methods.__repr__ = (B_str (*) (sshQ_L_13proc))B_valueG_methods.__repr__;
        sshQ_L_13procG_methods.__init__ = (B_NoneType (*) (sshQ_L_13proc, sshQ_Client, sshQ_Channel, $action, $action, $action, $action, $action))sshQ_L_13procD___init__;
        sshQ_L_13procG_methods.__call__ = ($R (*) (sshQ_L_13proc, $Cont))sshQ_L_13procD___call__;
        sshQ_L_13procG_methods.__exec__ = ($R (*) (sshQ_L_13proc, $Cont))sshQ_L_13procD___exec__;
        sshQ_L_13procG_methods.__serialize__ = sshQ_L_13procD___serialize__;
        sshQ_L_13procG_methods.__deserialize__ = sshQ_L_13procD___deserialize__;
        $register(&sshQ_L_13procG_methods);
    }
    {
        sshQ_L_14procG_methods.$GCINFO = "sshQ_L_14proc";
        sshQ_L_14procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        sshQ_L_14procG_methods.__bool__ = (B_bool (*) (sshQ_L_14proc))B_valueG_methods.__bool__;
        sshQ_L_14procG_methods.__str__ = (B_str (*) (sshQ_L_14proc))B_valueG_methods.__str__;
        sshQ_L_14procG_methods.__repr__ = (B_str (*) (sshQ_L_14proc))B_valueG_methods.__repr__;
        sshQ_L_14procG_methods.__init__ = (B_NoneType (*) (sshQ_L_14proc, sshQ_Client, sshQ_Channel, B_str))sshQ_L_14procD___init__;
        sshQ_L_14procG_methods.__call__ = ($R (*) (sshQ_L_14proc, $Cont))sshQ_L_14procD___call__;
        sshQ_L_14procG_methods.__exec__ = ($R (*) (sshQ_L_14proc, $Cont))sshQ_L_14procD___exec__;
        sshQ_L_14procG_methods.__serialize__ = sshQ_L_14procD___serialize__;
        sshQ_L_14procG_methods.__deserialize__ = sshQ_L_14procD___deserialize__;
        $register(&sshQ_L_14procG_methods);
    }
    {
        sshQ_L_15procG_methods.$GCINFO = "sshQ_L_15proc";
        sshQ_L_15procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        sshQ_L_15procG_methods.__bool__ = (B_bool (*) (sshQ_L_15proc))B_valueG_methods.__bool__;
        sshQ_L_15procG_methods.__str__ = (B_str (*) (sshQ_L_15proc))B_valueG_methods.__str__;
        sshQ_L_15procG_methods.__repr__ = (B_str (*) (sshQ_L_15proc))B_valueG_methods.__repr__;
        sshQ_L_15procG_methods.__init__ = (B_NoneType (*) (sshQ_L_15proc, sshQ_Client, sshQ_Channel, B_str, int64_t, int64_t, int64_t, int64_t, B_bool))sshQ_L_15procD___init__;
        sshQ_L_15procG_methods.__call__ = ($R (*) (sshQ_L_15proc, $Cont))sshQ_L_15procD___call__;
        sshQ_L_15procG_methods.__exec__ = ($R (*) (sshQ_L_15proc, $Cont))sshQ_L_15procD___exec__;
        sshQ_L_15procG_methods.__serialize__ = sshQ_L_15procD___serialize__;
        sshQ_L_15procG_methods.__deserialize__ = sshQ_L_15procD___deserialize__;
        $register(&sshQ_L_15procG_methods);
    }
    {
        sshQ_L_16procG_methods.$GCINFO = "sshQ_L_16proc";
        sshQ_L_16procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        sshQ_L_16procG_methods.__bool__ = (B_bool (*) (sshQ_L_16proc))B_valueG_methods.__bool__;
        sshQ_L_16procG_methods.__str__ = (B_str (*) (sshQ_L_16proc))B_valueG_methods.__str__;
        sshQ_L_16procG_methods.__repr__ = (B_str (*) (sshQ_L_16proc))B_valueG_methods.__repr__;
        sshQ_L_16procG_methods.__init__ = (B_NoneType (*) (sshQ_L_16proc, sshQ_Client, sshQ_Channel, B_str))sshQ_L_16procD___init__;
        sshQ_L_16procG_methods.__call__ = ($R (*) (sshQ_L_16proc, $Cont))sshQ_L_16procD___call__;
        sshQ_L_16procG_methods.__exec__ = ($R (*) (sshQ_L_16proc, $Cont))sshQ_L_16procD___exec__;
        sshQ_L_16procG_methods.__serialize__ = sshQ_L_16procD___serialize__;
        sshQ_L_16procG_methods.__deserialize__ = sshQ_L_16procD___deserialize__;
        $register(&sshQ_L_16procG_methods);
    }
    {
        sshQ_L_17procG_methods.$GCINFO = "sshQ_L_17proc";
        sshQ_L_17procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        sshQ_L_17procG_methods.__bool__ = (B_bool (*) (sshQ_L_17proc))B_valueG_methods.__bool__;
        sshQ_L_17procG_methods.__str__ = (B_str (*) (sshQ_L_17proc))B_valueG_methods.__str__;
        sshQ_L_17procG_methods.__repr__ = (B_str (*) (sshQ_L_17proc))B_valueG_methods.__repr__;
        sshQ_L_17procG_methods.__init__ = (B_NoneType (*) (sshQ_L_17proc, sshQ_Client, sshQ_Channel, B_bytes))sshQ_L_17procD___init__;
        sshQ_L_17procG_methods.__call__ = ($R (*) (sshQ_L_17proc, $Cont))sshQ_L_17procD___call__;
        sshQ_L_17procG_methods.__exec__ = ($R (*) (sshQ_L_17proc, $Cont))sshQ_L_17procD___exec__;
        sshQ_L_17procG_methods.__serialize__ = sshQ_L_17procD___serialize__;
        sshQ_L_17procG_methods.__deserialize__ = sshQ_L_17procD___deserialize__;
        $register(&sshQ_L_17procG_methods);
    }
    {
        sshQ_L_18procG_methods.$GCINFO = "sshQ_L_18proc";
        sshQ_L_18procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        sshQ_L_18procG_methods.__bool__ = (B_bool (*) (sshQ_L_18proc))B_valueG_methods.__bool__;
        sshQ_L_18procG_methods.__str__ = (B_str (*) (sshQ_L_18proc))B_valueG_methods.__str__;
        sshQ_L_18procG_methods.__repr__ = (B_str (*) (sshQ_L_18proc))B_valueG_methods.__repr__;
        sshQ_L_18procG_methods.__init__ = (B_NoneType (*) (sshQ_L_18proc, sshQ_Client, sshQ_Channel))sshQ_L_18procD___init__;
        sshQ_L_18procG_methods.__call__ = ($R (*) (sshQ_L_18proc, $Cont))sshQ_L_18procD___call__;
        sshQ_L_18procG_methods.__exec__ = ($R (*) (sshQ_L_18proc, $Cont))sshQ_L_18procD___exec__;
        sshQ_L_18procG_methods.__serialize__ = sshQ_L_18procD___serialize__;
        sshQ_L_18procG_methods.__deserialize__ = sshQ_L_18procD___deserialize__;
        $register(&sshQ_L_18procG_methods);
    }
    {
        sshQ_L_19procG_methods.$GCINFO = "sshQ_L_19proc";
        sshQ_L_19procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        sshQ_L_19procG_methods.__bool__ = (B_bool (*) (sshQ_L_19proc))B_valueG_methods.__bool__;
        sshQ_L_19procG_methods.__str__ = (B_str (*) (sshQ_L_19proc))B_valueG_methods.__str__;
        sshQ_L_19procG_methods.__repr__ = (B_str (*) (sshQ_L_19proc))B_valueG_methods.__repr__;
        sshQ_L_19procG_methods.__init__ = (B_NoneType (*) (sshQ_L_19proc, sshQ_Client, sshQ_Channel))sshQ_L_19procD___init__;
        sshQ_L_19procG_methods.__call__ = ($R (*) (sshQ_L_19proc, $Cont))sshQ_L_19procD___call__;
        sshQ_L_19procG_methods.__exec__ = ($R (*) (sshQ_L_19proc, $Cont))sshQ_L_19procD___exec__;
        sshQ_L_19procG_methods.__serialize__ = sshQ_L_19procD___serialize__;
        sshQ_L_19procG_methods.__deserialize__ = sshQ_L_19procD___deserialize__;
        $register(&sshQ_L_19procG_methods);
    }
    {
        sshQ_L_21ContG_methods.$GCINFO = "sshQ_L_21Cont";
        sshQ_L_21ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        sshQ_L_21ContG_methods.__bool__ = (B_bool (*) (sshQ_L_21Cont))B_valueG_methods.__bool__;
        sshQ_L_21ContG_methods.__str__ = (B_str (*) (sshQ_L_21Cont))B_valueG_methods.__str__;
        sshQ_L_21ContG_methods.__repr__ = (B_str (*) (sshQ_L_21Cont))B_valueG_methods.__repr__;
        sshQ_L_21ContG_methods.__init__ = (B_NoneType (*) (sshQ_L_21Cont, $Cont))sshQ_L_21ContD___init__;
        sshQ_L_21ContG_methods.__call__ = ($R (*) (sshQ_L_21Cont, B_NoneType))sshQ_L_21ContD___call__;
        sshQ_L_21ContG_methods.__serialize__ = sshQ_L_21ContD___serialize__;
        sshQ_L_21ContG_methods.__deserialize__ = sshQ_L_21ContD___deserialize__;
        $register(&sshQ_L_21ContG_methods);
    }
    {
        sshQ_L_22ContG_methods.$GCINFO = "sshQ_L_22Cont";
        sshQ_L_22ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        sshQ_L_22ContG_methods.__bool__ = (B_bool (*) (sshQ_L_22Cont))B_valueG_methods.__bool__;
        sshQ_L_22ContG_methods.__str__ = (B_str (*) (sshQ_L_22Cont))B_valueG_methods.__str__;
        sshQ_L_22ContG_methods.__repr__ = (B_str (*) (sshQ_L_22Cont))B_valueG_methods.__repr__;
        sshQ_L_22ContG_methods.__init__ = (B_NoneType (*) (sshQ_L_22Cont, $Cont))sshQ_L_22ContD___init__;
        sshQ_L_22ContG_methods.__call__ = ($R (*) (sshQ_L_22Cont, B_NoneType))sshQ_L_22ContD___call__;
        sshQ_L_22ContG_methods.__serialize__ = sshQ_L_22ContD___serialize__;
        sshQ_L_22ContG_methods.__deserialize__ = sshQ_L_22ContD___deserialize__;
        $register(&sshQ_L_22ContG_methods);
    }
    {
        sshQ_L_23procG_methods.$GCINFO = "sshQ_L_23proc";
        sshQ_L_23procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        sshQ_L_23procG_methods.__bool__ = (B_bool (*) (sshQ_L_23proc))B_valueG_methods.__bool__;
        sshQ_L_23procG_methods.__str__ = (B_str (*) (sshQ_L_23proc))B_valueG_methods.__str__;
        sshQ_L_23procG_methods.__repr__ = (B_str (*) (sshQ_L_23proc))B_valueG_methods.__repr__;
        sshQ_L_23procG_methods.__init__ = (B_NoneType (*) (sshQ_L_23proc, sshQ_Channel))sshQ_L_23procD___init__;
        sshQ_L_23procG_methods.__call__ = ($R (*) (sshQ_L_23proc, $Cont))sshQ_L_23procD___call__;
        sshQ_L_23procG_methods.__exec__ = ($R (*) (sshQ_L_23proc, $Cont))sshQ_L_23procD___exec__;
        sshQ_L_23procG_methods.__serialize__ = sshQ_L_23procD___serialize__;
        sshQ_L_23procG_methods.__deserialize__ = sshQ_L_23procD___deserialize__;
        $register(&sshQ_L_23procG_methods);
    }
    {
        sshQ_L_24procG_methods.$GCINFO = "sshQ_L_24proc";
        sshQ_L_24procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        sshQ_L_24procG_methods.__bool__ = (B_bool (*) (sshQ_L_24proc))B_valueG_methods.__bool__;
        sshQ_L_24procG_methods.__str__ = (B_str (*) (sshQ_L_24proc))B_valueG_methods.__str__;
        sshQ_L_24procG_methods.__repr__ = (B_str (*) (sshQ_L_24proc))B_valueG_methods.__repr__;
        sshQ_L_24procG_methods.__init__ = (B_NoneType (*) (sshQ_L_24proc, sshQ_Channel, B_str))sshQ_L_24procD___init__;
        sshQ_L_24procG_methods.__call__ = ($R (*) (sshQ_L_24proc, $Cont))sshQ_L_24procD___call__;
        sshQ_L_24procG_methods.__exec__ = ($R (*) (sshQ_L_24proc, $Cont))sshQ_L_24procD___exec__;
        sshQ_L_24procG_methods.__serialize__ = sshQ_L_24procD___serialize__;
        sshQ_L_24procG_methods.__deserialize__ = sshQ_L_24procD___deserialize__;
        $register(&sshQ_L_24procG_methods);
    }
    {
        sshQ_L_25procG_methods.$GCINFO = "sshQ_L_25proc";
        sshQ_L_25procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        sshQ_L_25procG_methods.__bool__ = (B_bool (*) (sshQ_L_25proc))B_valueG_methods.__bool__;
        sshQ_L_25procG_methods.__str__ = (B_str (*) (sshQ_L_25proc))B_valueG_methods.__str__;
        sshQ_L_25procG_methods.__repr__ = (B_str (*) (sshQ_L_25proc))B_valueG_methods.__repr__;
        sshQ_L_25procG_methods.__init__ = (B_NoneType (*) (sshQ_L_25proc, sshQ_Channel, B_str, B_int, B_int, B_int, B_int, B_bool))sshQ_L_25procD___init__;
        sshQ_L_25procG_methods.__call__ = ($R (*) (sshQ_L_25proc, $Cont))sshQ_L_25procD___call__;
        sshQ_L_25procG_methods.__exec__ = ($R (*) (sshQ_L_25proc, $Cont))sshQ_L_25procD___exec__;
        sshQ_L_25procG_methods.__serialize__ = sshQ_L_25procD___serialize__;
        sshQ_L_25procG_methods.__deserialize__ = sshQ_L_25procD___deserialize__;
        $register(&sshQ_L_25procG_methods);
    }
    {
        sshQ_L_26procG_methods.$GCINFO = "sshQ_L_26proc";
        sshQ_L_26procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        sshQ_L_26procG_methods.__bool__ = (B_bool (*) (sshQ_L_26proc))B_valueG_methods.__bool__;
        sshQ_L_26procG_methods.__str__ = (B_str (*) (sshQ_L_26proc))B_valueG_methods.__str__;
        sshQ_L_26procG_methods.__repr__ = (B_str (*) (sshQ_L_26proc))B_valueG_methods.__repr__;
        sshQ_L_26procG_methods.__init__ = (B_NoneType (*) (sshQ_L_26proc, sshQ_Channel, B_str))sshQ_L_26procD___init__;
        sshQ_L_26procG_methods.__call__ = ($R (*) (sshQ_L_26proc, $Cont))sshQ_L_26procD___call__;
        sshQ_L_26procG_methods.__exec__ = ($R (*) (sshQ_L_26proc, $Cont))sshQ_L_26procD___exec__;
        sshQ_L_26procG_methods.__serialize__ = sshQ_L_26procD___serialize__;
        sshQ_L_26procG_methods.__deserialize__ = sshQ_L_26procD___deserialize__;
        $register(&sshQ_L_26procG_methods);
    }
    {
        sshQ_L_27procG_methods.$GCINFO = "sshQ_L_27proc";
        sshQ_L_27procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        sshQ_L_27procG_methods.__bool__ = (B_bool (*) (sshQ_L_27proc))B_valueG_methods.__bool__;
        sshQ_L_27procG_methods.__str__ = (B_str (*) (sshQ_L_27proc))B_valueG_methods.__str__;
        sshQ_L_27procG_methods.__repr__ = (B_str (*) (sshQ_L_27proc))B_valueG_methods.__repr__;
        sshQ_L_27procG_methods.__init__ = (B_NoneType (*) (sshQ_L_27proc, sshQ_Channel, B_bytes))sshQ_L_27procD___init__;
        sshQ_L_27procG_methods.__call__ = ($R (*) (sshQ_L_27proc, $Cont))sshQ_L_27procD___call__;
        sshQ_L_27procG_methods.__exec__ = ($R (*) (sshQ_L_27proc, $Cont))sshQ_L_27procD___exec__;
        sshQ_L_27procG_methods.__serialize__ = sshQ_L_27procD___serialize__;
        sshQ_L_27procG_methods.__deserialize__ = sshQ_L_27procD___deserialize__;
        $register(&sshQ_L_27procG_methods);
    }
    {
        sshQ_L_28procG_methods.$GCINFO = "sshQ_L_28proc";
        sshQ_L_28procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        sshQ_L_28procG_methods.__bool__ = (B_bool (*) (sshQ_L_28proc))B_valueG_methods.__bool__;
        sshQ_L_28procG_methods.__str__ = (B_str (*) (sshQ_L_28proc))B_valueG_methods.__str__;
        sshQ_L_28procG_methods.__repr__ = (B_str (*) (sshQ_L_28proc))B_valueG_methods.__repr__;
        sshQ_L_28procG_methods.__init__ = (B_NoneType (*) (sshQ_L_28proc, sshQ_Channel))sshQ_L_28procD___init__;
        sshQ_L_28procG_methods.__call__ = ($R (*) (sshQ_L_28proc, $Cont))sshQ_L_28procD___call__;
        sshQ_L_28procG_methods.__exec__ = ($R (*) (sshQ_L_28proc, $Cont))sshQ_L_28procD___exec__;
        sshQ_L_28procG_methods.__serialize__ = sshQ_L_28procD___serialize__;
        sshQ_L_28procG_methods.__deserialize__ = sshQ_L_28procD___deserialize__;
        $register(&sshQ_L_28procG_methods);
    }
    {
        sshQ_L_29procG_methods.$GCINFO = "sshQ_L_29proc";
        sshQ_L_29procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        sshQ_L_29procG_methods.__bool__ = (B_bool (*) (sshQ_L_29proc))B_valueG_methods.__bool__;
        sshQ_L_29procG_methods.__str__ = (B_str (*) (sshQ_L_29proc))B_valueG_methods.__str__;
        sshQ_L_29procG_methods.__repr__ = (B_str (*) (sshQ_L_29proc))B_valueG_methods.__repr__;
        sshQ_L_29procG_methods.__init__ = (B_NoneType (*) (sshQ_L_29proc, sshQ_Channel))sshQ_L_29procD___init__;
        sshQ_L_29procG_methods.__call__ = ($R (*) (sshQ_L_29proc, $Cont))sshQ_L_29procD___call__;
        sshQ_L_29procG_methods.__exec__ = ($R (*) (sshQ_L_29proc, $Cont))sshQ_L_29procD___exec__;
        sshQ_L_29procG_methods.__serialize__ = sshQ_L_29procD___serialize__;
        sshQ_L_29procG_methods.__deserialize__ = sshQ_L_29procD___deserialize__;
        $register(&sshQ_L_29procG_methods);
    }
    {
        sshQ_L_30procG_methods.$GCINFO = "sshQ_L_30proc";
        sshQ_L_30procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        sshQ_L_30procG_methods.__bool__ = (B_bool (*) (sshQ_L_30proc))B_valueG_methods.__bool__;
        sshQ_L_30procG_methods.__str__ = (B_str (*) (sshQ_L_30proc))B_valueG_methods.__str__;
        sshQ_L_30procG_methods.__repr__ = (B_str (*) (sshQ_L_30proc))B_valueG_methods.__repr__;
        sshQ_L_30procG_methods.__init__ = (B_NoneType (*) (sshQ_L_30proc, sshQ_Channel))sshQ_L_30procD___init__;
        sshQ_L_30procG_methods.__call__ = ($R (*) (sshQ_L_30proc, $Cont))sshQ_L_30procD___call__;
        sshQ_L_30procG_methods.__exec__ = ($R (*) (sshQ_L_30proc, $Cont))sshQ_L_30procD___exec__;
        sshQ_L_30procG_methods.__serialize__ = sshQ_L_30procD___serialize__;
        sshQ_L_30procG_methods.__deserialize__ = sshQ_L_30procD___deserialize__;
        $register(&sshQ_L_30procG_methods);
    }
    {
        sshQ_L_31procG_methods.$GCINFO = "sshQ_L_31proc";
        sshQ_L_31procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        sshQ_L_31procG_methods.__bool__ = (B_bool (*) (sshQ_L_31proc))B_valueG_methods.__bool__;
        sshQ_L_31procG_methods.__str__ = (B_str (*) (sshQ_L_31proc))B_valueG_methods.__str__;
        sshQ_L_31procG_methods.__repr__ = (B_str (*) (sshQ_L_31proc))B_valueG_methods.__repr__;
        sshQ_L_31procG_methods.__init__ = (B_NoneType (*) (sshQ_L_31proc, sshQ_Channel))sshQ_L_31procD___init__;
        sshQ_L_31procG_methods.__call__ = ($R (*) (sshQ_L_31proc, $Cont))sshQ_L_31procD___call__;
        sshQ_L_31procG_methods.__exec__ = ($R (*) (sshQ_L_31proc, $Cont))sshQ_L_31procD___exec__;
        sshQ_L_31procG_methods.__serialize__ = sshQ_L_31procD___serialize__;
        sshQ_L_31procG_methods.__deserialize__ = sshQ_L_31procD___deserialize__;
        $register(&sshQ_L_31procG_methods);
    }
    {
        sshQ_L_36ContG_methods.$GCINFO = "sshQ_L_36Cont";
        sshQ_L_36ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        sshQ_L_36ContG_methods.__bool__ = (B_bool (*) (sshQ_L_36Cont))B_valueG_methods.__bool__;
        sshQ_L_36ContG_methods.__str__ = (B_str (*) (sshQ_L_36Cont))B_valueG_methods.__str__;
        sshQ_L_36ContG_methods.__repr__ = (B_str (*) (sshQ_L_36Cont))B_valueG_methods.__repr__;
        sshQ_L_36ContG_methods.__init__ = (B_NoneType (*) (sshQ_L_36Cont, sshQ_RunCommand, $Cont))sshQ_L_36ContD___init__;
        sshQ_L_36ContG_methods.__call__ = ($R (*) (sshQ_L_36Cont, B_NoneType))sshQ_L_36ContD___call__;
        sshQ_L_36ContG_methods.__serialize__ = sshQ_L_36ContD___serialize__;
        sshQ_L_36ContG_methods.__deserialize__ = sshQ_L_36ContD___deserialize__;
        $register(&sshQ_L_36ContG_methods);
    }
    {
        sshQ_L_37ContG_methods.$GCINFO = "sshQ_L_37Cont";
        sshQ_L_37ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        sshQ_L_37ContG_methods.__bool__ = (B_bool (*) (sshQ_L_37Cont))B_valueG_methods.__bool__;
        sshQ_L_37ContG_methods.__str__ = (B_str (*) (sshQ_L_37Cont))B_valueG_methods.__str__;
        sshQ_L_37ContG_methods.__repr__ = (B_str (*) (sshQ_L_37Cont))B_valueG_methods.__repr__;
        sshQ_L_37ContG_methods.__init__ = (B_NoneType (*) (sshQ_L_37Cont, sshQ_RunCommand, $Cont))sshQ_L_37ContD___init__;
        sshQ_L_37ContG_methods.__call__ = ($R (*) (sshQ_L_37Cont, B_NoneType))sshQ_L_37ContD___call__;
        sshQ_L_37ContG_methods.__serialize__ = sshQ_L_37ContD___serialize__;
        sshQ_L_37ContG_methods.__deserialize__ = sshQ_L_37ContD___deserialize__;
        $register(&sshQ_L_37ContG_methods);
    }
    {
        sshQ_L_38procG_methods.$GCINFO = "sshQ_L_38proc";
        sshQ_L_38procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        sshQ_L_38procG_methods.__bool__ = (B_bool (*) (sshQ_L_38proc))B_valueG_methods.__bool__;
        sshQ_L_38procG_methods.__str__ = (B_str (*) (sshQ_L_38proc))B_valueG_methods.__str__;
        sshQ_L_38procG_methods.__repr__ = (B_str (*) (sshQ_L_38proc))B_valueG_methods.__repr__;
        sshQ_L_38procG_methods.__init__ = (B_NoneType (*) (sshQ_L_38proc, sshQ_RunCommand))sshQ_L_38procD___init__;
        sshQ_L_38procG_methods.__call__ = ($R (*) (sshQ_L_38proc, $Cont))sshQ_L_38procD___call__;
        sshQ_L_38procG_methods.__exec__ = ($R (*) (sshQ_L_38proc, $Cont))sshQ_L_38procD___exec__;
        sshQ_L_38procG_methods.__serialize__ = sshQ_L_38procD___serialize__;
        sshQ_L_38procG_methods.__deserialize__ = sshQ_L_38procD___deserialize__;
        $register(&sshQ_L_38procG_methods);
    }
    {
        sshQ_L_39ContG_methods.$GCINFO = "sshQ_L_39Cont";
        sshQ_L_39ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        sshQ_L_39ContG_methods.__bool__ = (B_bool (*) (sshQ_L_39Cont))B_valueG_methods.__bool__;
        sshQ_L_39ContG_methods.__str__ = (B_str (*) (sshQ_L_39Cont))B_valueG_methods.__str__;
        sshQ_L_39ContG_methods.__repr__ = (B_str (*) (sshQ_L_39Cont))B_valueG_methods.__repr__;
        sshQ_L_39ContG_methods.__init__ = (B_NoneType (*) (sshQ_L_39Cont, sshQ_RunCommand, $Cont))sshQ_L_39ContD___init__;
        sshQ_L_39ContG_methods.__call__ = ($R (*) (sshQ_L_39Cont, sshQ_Channel))sshQ_L_39ContD___call__;
        sshQ_L_39ContG_methods.__serialize__ = sshQ_L_39ContD___serialize__;
        sshQ_L_39ContG_methods.__deserialize__ = sshQ_L_39ContD___deserialize__;
        $register(&sshQ_L_39ContG_methods);
    }
    {
        sshQ_L_41actionG_methods.$GCINFO = "sshQ_L_41action";
        sshQ_L_41actionG_methods.$superclass = ($SuperG_class)&$actionG_methods;
        sshQ_L_41actionG_methods.__bool__ = (B_bool (*) (sshQ_L_41action))B_valueG_methods.__bool__;
        sshQ_L_41actionG_methods.__str__ = (B_str (*) (sshQ_L_41action))B_valueG_methods.__str__;
        sshQ_L_41actionG_methods.__repr__ = (B_str (*) (sshQ_L_41action))B_valueG_methods.__repr__;
        sshQ_L_41actionG_methods.__init__ = (B_NoneType (*) (sshQ_L_41action, sshQ_RunCommand))sshQ_L_41actionD___init__;
        sshQ_L_41actionG_methods.__call__ = ($R (*) (sshQ_L_41action, $Cont, sshQ_Channel, B_str))sshQ_L_41actionD___call__;
        sshQ_L_41actionG_methods.__exec__ = ($R (*) (sshQ_L_41action, $Cont, sshQ_Channel, B_str))sshQ_L_41actionD___exec__;
        sshQ_L_41actionG_methods.__asyn__ = (B_Msg (*) (sshQ_L_41action, sshQ_Channel, B_str))sshQ_L_41actionD___asyn__;
        sshQ_L_41actionG_methods.__serialize__ = sshQ_L_41actionD___serialize__;
        sshQ_L_41actionG_methods.__deserialize__ = sshQ_L_41actionD___deserialize__;
        $register(&sshQ_L_41actionG_methods);
    }
    {
        sshQ_L_43actionG_methods.$GCINFO = "sshQ_L_43action";
        sshQ_L_43actionG_methods.$superclass = ($SuperG_class)&$actionG_methods;
        sshQ_L_43actionG_methods.__bool__ = (B_bool (*) (sshQ_L_43action))B_valueG_methods.__bool__;
        sshQ_L_43actionG_methods.__str__ = (B_str (*) (sshQ_L_43action))B_valueG_methods.__str__;
        sshQ_L_43actionG_methods.__repr__ = (B_str (*) (sshQ_L_43action))B_valueG_methods.__repr__;
        sshQ_L_43actionG_methods.__init__ = (B_NoneType (*) (sshQ_L_43action, sshQ_RunCommand))sshQ_L_43actionD___init__;
        sshQ_L_43actionG_methods.__call__ = ($R (*) (sshQ_L_43action, $Cont, sshQ_Channel, B_bytes))sshQ_L_43actionD___call__;
        sshQ_L_43actionG_methods.__exec__ = ($R (*) (sshQ_L_43action, $Cont, sshQ_Channel, B_bytes))sshQ_L_43actionD___exec__;
        sshQ_L_43actionG_methods.__asyn__ = (B_Msg (*) (sshQ_L_43action, sshQ_Channel, B_bytes))sshQ_L_43actionD___asyn__;
        sshQ_L_43actionG_methods.__serialize__ = sshQ_L_43actionD___serialize__;
        sshQ_L_43actionG_methods.__deserialize__ = sshQ_L_43actionD___deserialize__;
        $register(&sshQ_L_43actionG_methods);
    }
    {
        sshQ_L_45actionG_methods.$GCINFO = "sshQ_L_45action";
        sshQ_L_45actionG_methods.$superclass = ($SuperG_class)&$actionG_methods;
        sshQ_L_45actionG_methods.__bool__ = (B_bool (*) (sshQ_L_45action))B_valueG_methods.__bool__;
        sshQ_L_45actionG_methods.__str__ = (B_str (*) (sshQ_L_45action))B_valueG_methods.__str__;
        sshQ_L_45actionG_methods.__repr__ = (B_str (*) (sshQ_L_45action))B_valueG_methods.__repr__;
        sshQ_L_45actionG_methods.__init__ = (B_NoneType (*) (sshQ_L_45action, sshQ_RunCommand))sshQ_L_45actionD___init__;
        sshQ_L_45actionG_methods.__call__ = ($R (*) (sshQ_L_45action, $Cont, sshQ_Channel, B_bytes))sshQ_L_45actionD___call__;
        sshQ_L_45actionG_methods.__exec__ = ($R (*) (sshQ_L_45action, $Cont, sshQ_Channel, B_bytes))sshQ_L_45actionD___exec__;
        sshQ_L_45actionG_methods.__asyn__ = (B_Msg (*) (sshQ_L_45action, sshQ_Channel, B_bytes))sshQ_L_45actionD___asyn__;
        sshQ_L_45actionG_methods.__serialize__ = sshQ_L_45actionD___serialize__;
        sshQ_L_45actionG_methods.__deserialize__ = sshQ_L_45actionD___deserialize__;
        $register(&sshQ_L_45actionG_methods);
    }
    {
        sshQ_L_47actionG_methods.$GCINFO = "sshQ_L_47action";
        sshQ_L_47actionG_methods.$superclass = ($SuperG_class)&$actionG_methods;
        sshQ_L_47actionG_methods.__bool__ = (B_bool (*) (sshQ_L_47action))B_valueG_methods.__bool__;
        sshQ_L_47actionG_methods.__str__ = (B_str (*) (sshQ_L_47action))B_valueG_methods.__str__;
        sshQ_L_47actionG_methods.__repr__ = (B_str (*) (sshQ_L_47action))B_valueG_methods.__repr__;
        sshQ_L_47actionG_methods.__init__ = (B_NoneType (*) (sshQ_L_47action, sshQ_RunCommand))sshQ_L_47actionD___init__;
        sshQ_L_47actionG_methods.__call__ = ($R (*) (sshQ_L_47action, $Cont, sshQ_Channel, B_int, B_str))sshQ_L_47actionD___call__;
        sshQ_L_47actionG_methods.__exec__ = ($R (*) (sshQ_L_47action, $Cont, sshQ_Channel, B_int, B_str))sshQ_L_47actionD___exec__;
        sshQ_L_47actionG_methods.__asyn__ = (B_Msg (*) (sshQ_L_47action, sshQ_Channel, B_int, B_str))sshQ_L_47actionD___asyn__;
        sshQ_L_47actionG_methods.__serialize__ = sshQ_L_47actionD___serialize__;
        sshQ_L_47actionG_methods.__deserialize__ = sshQ_L_47actionD___deserialize__;
        $register(&sshQ_L_47actionG_methods);
    }
    {
        sshQ_L_49actionG_methods.$GCINFO = "sshQ_L_49action";
        sshQ_L_49actionG_methods.$superclass = ($SuperG_class)&$actionG_methods;
        sshQ_L_49actionG_methods.__bool__ = (B_bool (*) (sshQ_L_49action))B_valueG_methods.__bool__;
        sshQ_L_49actionG_methods.__str__ = (B_str (*) (sshQ_L_49action))B_valueG_methods.__str__;
        sshQ_L_49actionG_methods.__repr__ = (B_str (*) (sshQ_L_49action))B_valueG_methods.__repr__;
        sshQ_L_49actionG_methods.__init__ = (B_NoneType (*) (sshQ_L_49action, sshQ_RunCommand))sshQ_L_49actionD___init__;
        sshQ_L_49actionG_methods.__call__ = ($R (*) (sshQ_L_49action, $Cont, sshQ_Channel, B_str))sshQ_L_49actionD___call__;
        sshQ_L_49actionG_methods.__exec__ = ($R (*) (sshQ_L_49action, $Cont, sshQ_Channel, B_str))sshQ_L_49actionD___exec__;
        sshQ_L_49actionG_methods.__asyn__ = (B_Msg (*) (sshQ_L_49action, sshQ_Channel, B_str))sshQ_L_49actionD___asyn__;
        sshQ_L_49actionG_methods.__serialize__ = sshQ_L_49actionD___serialize__;
        sshQ_L_49actionG_methods.__deserialize__ = sshQ_L_49actionD___deserialize__;
        $register(&sshQ_L_49actionG_methods);
    }
    {
        sshQ_L_51ContG_methods.$GCINFO = "sshQ_L_51Cont";
        sshQ_L_51ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        sshQ_L_51ContG_methods.__bool__ = (B_bool (*) (sshQ_L_51Cont))B_valueG_methods.__bool__;
        sshQ_L_51ContG_methods.__str__ = (B_str (*) (sshQ_L_51Cont))B_valueG_methods.__str__;
        sshQ_L_51ContG_methods.__repr__ = (B_str (*) (sshQ_L_51Cont))B_valueG_methods.__repr__;
        sshQ_L_51ContG_methods.__init__ = (B_NoneType (*) (sshQ_L_51Cont, sshQ_RunCommand, sshQ_Channel, $Cont))sshQ_L_51ContD___init__;
        sshQ_L_51ContG_methods.__call__ = ($R (*) (sshQ_L_51Cont, B_NoneType))sshQ_L_51ContD___call__;
        sshQ_L_51ContG_methods.__serialize__ = sshQ_L_51ContD___serialize__;
        sshQ_L_51ContG_methods.__deserialize__ = sshQ_L_51ContD___deserialize__;
        $register(&sshQ_L_51ContG_methods);
    }
    {
        sshQ_L_55ContG_methods.$GCINFO = "sshQ_L_55Cont";
        sshQ_L_55ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        sshQ_L_55ContG_methods.__bool__ = (B_bool (*) (sshQ_L_55Cont))B_valueG_methods.__bool__;
        sshQ_L_55ContG_methods.__str__ = (B_str (*) (sshQ_L_55Cont))B_valueG_methods.__str__;
        sshQ_L_55ContG_methods.__repr__ = (B_str (*) (sshQ_L_55Cont))B_valueG_methods.__repr__;
        sshQ_L_55ContG_methods.__init__ = (B_NoneType (*) (sshQ_L_55Cont, $Cont))sshQ_L_55ContD___init__;
        sshQ_L_55ContG_methods.__call__ = ($R (*) (sshQ_L_55Cont, B_NoneType))sshQ_L_55ContD___call__;
        sshQ_L_55ContG_methods.__serialize__ = sshQ_L_55ContD___serialize__;
        sshQ_L_55ContG_methods.__deserialize__ = sshQ_L_55ContD___deserialize__;
        $register(&sshQ_L_55ContG_methods);
    }
    {
        sshQ_L_56ContG_methods.$GCINFO = "sshQ_L_56Cont";
        sshQ_L_56ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        sshQ_L_56ContG_methods.__bool__ = (B_bool (*) (sshQ_L_56Cont))B_valueG_methods.__bool__;
        sshQ_L_56ContG_methods.__str__ = (B_str (*) (sshQ_L_56Cont))B_valueG_methods.__str__;
        sshQ_L_56ContG_methods.__repr__ = (B_str (*) (sshQ_L_56Cont))B_valueG_methods.__repr__;
        sshQ_L_56ContG_methods.__init__ = (B_NoneType (*) (sshQ_L_56Cont, sshQ_Channel, sshQ_RunCommand, $Cont))sshQ_L_56ContD___init__;
        sshQ_L_56ContG_methods.__call__ = ($R (*) (sshQ_L_56Cont, B_NoneType))sshQ_L_56ContD___call__;
        sshQ_L_56ContG_methods.__serialize__ = sshQ_L_56ContD___serialize__;
        sshQ_L_56ContG_methods.__deserialize__ = sshQ_L_56ContD___deserialize__;
        $register(&sshQ_L_56ContG_methods);
    }
    {
        sshQ_L_57ContG_methods.$GCINFO = "sshQ_L_57Cont";
        sshQ_L_57ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        sshQ_L_57ContG_methods.__bool__ = (B_bool (*) (sshQ_L_57Cont))B_valueG_methods.__bool__;
        sshQ_L_57ContG_methods.__str__ = (B_str (*) (sshQ_L_57Cont))B_valueG_methods.__str__;
        sshQ_L_57ContG_methods.__repr__ = (B_str (*) (sshQ_L_57Cont))B_valueG_methods.__repr__;
        sshQ_L_57ContG_methods.__init__ = (B_NoneType (*) (sshQ_L_57Cont, sshQ_Channel, sshQ_RunCommand, $Cont, B_str))sshQ_L_57ContD___init__;
        sshQ_L_57ContG_methods.__call__ = ($R (*) (sshQ_L_57Cont, B_NoneType))sshQ_L_57ContD___call__;
        sshQ_L_57ContG_methods.__serialize__ = sshQ_L_57ContD___serialize__;
        sshQ_L_57ContG_methods.__deserialize__ = sshQ_L_57ContD___deserialize__;
        $register(&sshQ_L_57ContG_methods);
    }
    {
        sshQ_L_60ContG_methods.$GCINFO = "sshQ_L_60Cont";
        sshQ_L_60ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        sshQ_L_60ContG_methods.__bool__ = (B_bool (*) (sshQ_L_60Cont))B_valueG_methods.__bool__;
        sshQ_L_60ContG_methods.__str__ = (B_str (*) (sshQ_L_60Cont))B_valueG_methods.__str__;
        sshQ_L_60ContG_methods.__repr__ = (B_str (*) (sshQ_L_60Cont))B_valueG_methods.__repr__;
        sshQ_L_60ContG_methods.__init__ = (B_NoneType (*) (sshQ_L_60Cont, $Cont))sshQ_L_60ContD___init__;
        sshQ_L_60ContG_methods.__call__ = ($R (*) (sshQ_L_60Cont, B_NoneType))sshQ_L_60ContD___call__;
        sshQ_L_60ContG_methods.__serialize__ = sshQ_L_60ContD___serialize__;
        sshQ_L_60ContG_methods.__deserialize__ = sshQ_L_60ContD___deserialize__;
        $register(&sshQ_L_60ContG_methods);
    }
    {
        sshQ_L_61ContG_methods.$GCINFO = "sshQ_L_61Cont";
        sshQ_L_61ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        sshQ_L_61ContG_methods.__bool__ = (B_bool (*) (sshQ_L_61Cont))B_valueG_methods.__bool__;
        sshQ_L_61ContG_methods.__str__ = (B_str (*) (sshQ_L_61Cont))B_valueG_methods.__str__;
        sshQ_L_61ContG_methods.__repr__ = (B_str (*) (sshQ_L_61Cont))B_valueG_methods.__repr__;
        sshQ_L_61ContG_methods.__init__ = (B_NoneType (*) (sshQ_L_61Cont, $Cont))sshQ_L_61ContD___init__;
        sshQ_L_61ContG_methods.__call__ = ($R (*) (sshQ_L_61Cont, B_NoneType))sshQ_L_61ContD___call__;
        sshQ_L_61ContG_methods.__serialize__ = sshQ_L_61ContD___serialize__;
        sshQ_L_61ContG_methods.__deserialize__ = sshQ_L_61ContD___deserialize__;
        $register(&sshQ_L_61ContG_methods);
    }
    {
        sshQ_L_62ContG_methods.$GCINFO = "sshQ_L_62Cont";
        sshQ_L_62ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        sshQ_L_62ContG_methods.__bool__ = (B_bool (*) (sshQ_L_62Cont))B_valueG_methods.__bool__;
        sshQ_L_62ContG_methods.__str__ = (B_str (*) (sshQ_L_62Cont))B_valueG_methods.__str__;
        sshQ_L_62ContG_methods.__repr__ = (B_str (*) (sshQ_L_62Cont))B_valueG_methods.__repr__;
        sshQ_L_62ContG_methods.__init__ = (B_NoneType (*) (sshQ_L_62Cont, $Cont, B_bytes, sshQ_RunCommand, sshQ_Channel))sshQ_L_62ContD___init__;
        sshQ_L_62ContG_methods.__call__ = ($R (*) (sshQ_L_62Cont, B_NoneType))sshQ_L_62ContD___call__;
        sshQ_L_62ContG_methods.__serialize__ = sshQ_L_62ContD___serialize__;
        sshQ_L_62ContG_methods.__deserialize__ = sshQ_L_62ContD___deserialize__;
        $register(&sshQ_L_62ContG_methods);
    }
    {
        sshQ_L_65ContG_methods.$GCINFO = "sshQ_L_65Cont";
        sshQ_L_65ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        sshQ_L_65ContG_methods.__bool__ = (B_bool (*) (sshQ_L_65Cont))B_valueG_methods.__bool__;
        sshQ_L_65ContG_methods.__str__ = (B_str (*) (sshQ_L_65Cont))B_valueG_methods.__str__;
        sshQ_L_65ContG_methods.__repr__ = (B_str (*) (sshQ_L_65Cont))B_valueG_methods.__repr__;
        sshQ_L_65ContG_methods.__init__ = (B_NoneType (*) (sshQ_L_65Cont, $Cont))sshQ_L_65ContD___init__;
        sshQ_L_65ContG_methods.__call__ = ($R (*) (sshQ_L_65Cont, B_NoneType))sshQ_L_65ContD___call__;
        sshQ_L_65ContG_methods.__serialize__ = sshQ_L_65ContD___serialize__;
        sshQ_L_65ContG_methods.__deserialize__ = sshQ_L_65ContD___deserialize__;
        $register(&sshQ_L_65ContG_methods);
    }
    {
        sshQ_L_66ContG_methods.$GCINFO = "sshQ_L_66Cont";
        sshQ_L_66ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        sshQ_L_66ContG_methods.__bool__ = (B_bool (*) (sshQ_L_66Cont))B_valueG_methods.__bool__;
        sshQ_L_66ContG_methods.__str__ = (B_str (*) (sshQ_L_66Cont))B_valueG_methods.__str__;
        sshQ_L_66ContG_methods.__repr__ = (B_str (*) (sshQ_L_66Cont))B_valueG_methods.__repr__;
        sshQ_L_66ContG_methods.__init__ = (B_NoneType (*) (sshQ_L_66Cont, $Cont))sshQ_L_66ContD___init__;
        sshQ_L_66ContG_methods.__call__ = ($R (*) (sshQ_L_66Cont, B_NoneType))sshQ_L_66ContD___call__;
        sshQ_L_66ContG_methods.__serialize__ = sshQ_L_66ContD___serialize__;
        sshQ_L_66ContG_methods.__deserialize__ = sshQ_L_66ContD___deserialize__;
        $register(&sshQ_L_66ContG_methods);
    }
    {
        sshQ_L_67ContG_methods.$GCINFO = "sshQ_L_67Cont";
        sshQ_L_67ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        sshQ_L_67ContG_methods.__bool__ = (B_bool (*) (sshQ_L_67Cont))B_valueG_methods.__bool__;
        sshQ_L_67ContG_methods.__str__ = (B_str (*) (sshQ_L_67Cont))B_valueG_methods.__str__;
        sshQ_L_67ContG_methods.__repr__ = (B_str (*) (sshQ_L_67Cont))B_valueG_methods.__repr__;
        sshQ_L_67ContG_methods.__init__ = (B_NoneType (*) (sshQ_L_67Cont, $Cont, B_bytes, sshQ_RunCommand, sshQ_Channel))sshQ_L_67ContD___init__;
        sshQ_L_67ContG_methods.__call__ = ($R (*) (sshQ_L_67Cont, B_NoneType))sshQ_L_67ContD___call__;
        sshQ_L_67ContG_methods.__serialize__ = sshQ_L_67ContD___serialize__;
        sshQ_L_67ContG_methods.__deserialize__ = sshQ_L_67ContD___deserialize__;
        $register(&sshQ_L_67ContG_methods);
    }
    {
        sshQ_L_70ContG_methods.$GCINFO = "sshQ_L_70Cont";
        sshQ_L_70ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        sshQ_L_70ContG_methods.__bool__ = (B_bool (*) (sshQ_L_70Cont))B_valueG_methods.__bool__;
        sshQ_L_70ContG_methods.__str__ = (B_str (*) (sshQ_L_70Cont))B_valueG_methods.__str__;
        sshQ_L_70ContG_methods.__repr__ = (B_str (*) (sshQ_L_70Cont))B_valueG_methods.__repr__;
        sshQ_L_70ContG_methods.__init__ = (B_NoneType (*) (sshQ_L_70Cont, $Cont))sshQ_L_70ContD___init__;
        sshQ_L_70ContG_methods.__call__ = ($R (*) (sshQ_L_70Cont, B_NoneType))sshQ_L_70ContD___call__;
        sshQ_L_70ContG_methods.__serialize__ = sshQ_L_70ContD___serialize__;
        sshQ_L_70ContG_methods.__deserialize__ = sshQ_L_70ContD___deserialize__;
        $register(&sshQ_L_70ContG_methods);
    }
    {
        sshQ_L_71ContG_methods.$GCINFO = "sshQ_L_71Cont";
        sshQ_L_71ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        sshQ_L_71ContG_methods.__bool__ = (B_bool (*) (sshQ_L_71Cont))B_valueG_methods.__bool__;
        sshQ_L_71ContG_methods.__str__ = (B_str (*) (sshQ_L_71Cont))B_valueG_methods.__str__;
        sshQ_L_71ContG_methods.__repr__ = (B_str (*) (sshQ_L_71Cont))B_valueG_methods.__repr__;
        sshQ_L_71ContG_methods.__init__ = (B_NoneType (*) (sshQ_L_71Cont, sshQ_RunCommand, int64_t, B_str, $Cont, sshQ_Channel))sshQ_L_71ContD___init__;
        sshQ_L_71ContG_methods.__call__ = ($R (*) (sshQ_L_71Cont, B_NoneType))sshQ_L_71ContD___call__;
        sshQ_L_71ContG_methods.__serialize__ = sshQ_L_71ContD___serialize__;
        sshQ_L_71ContG_methods.__deserialize__ = sshQ_L_71ContD___deserialize__;
        $register(&sshQ_L_71ContG_methods);
    }
    {
        sshQ_L_74ContG_methods.$GCINFO = "sshQ_L_74Cont";
        sshQ_L_74ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        sshQ_L_74ContG_methods.__bool__ = (B_bool (*) (sshQ_L_74Cont))B_valueG_methods.__bool__;
        sshQ_L_74ContG_methods.__str__ = (B_str (*) (sshQ_L_74Cont))B_valueG_methods.__str__;
        sshQ_L_74ContG_methods.__repr__ = (B_str (*) (sshQ_L_74Cont))B_valueG_methods.__repr__;
        sshQ_L_74ContG_methods.__init__ = (B_NoneType (*) (sshQ_L_74Cont, $Cont))sshQ_L_74ContD___init__;
        sshQ_L_74ContG_methods.__call__ = ($R (*) (sshQ_L_74Cont, B_NoneType))sshQ_L_74ContD___call__;
        sshQ_L_74ContG_methods.__serialize__ = sshQ_L_74ContD___serialize__;
        sshQ_L_74ContG_methods.__deserialize__ = sshQ_L_74ContD___deserialize__;
        $register(&sshQ_L_74ContG_methods);
    }
    {
        sshQ_L_75ContG_methods.$GCINFO = "sshQ_L_75Cont";
        sshQ_L_75ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        sshQ_L_75ContG_methods.__bool__ = (B_bool (*) (sshQ_L_75Cont))B_valueG_methods.__bool__;
        sshQ_L_75ContG_methods.__str__ = (B_str (*) (sshQ_L_75Cont))B_valueG_methods.__str__;
        sshQ_L_75ContG_methods.__repr__ = (B_str (*) (sshQ_L_75Cont))B_valueG_methods.__repr__;
        sshQ_L_75ContG_methods.__init__ = (B_NoneType (*) (sshQ_L_75Cont, sshQ_RunCommand, B_Eq, B_str, $Cont, sshQ_Channel))sshQ_L_75ContD___init__;
        sshQ_L_75ContG_methods.__call__ = ($R (*) (sshQ_L_75Cont, B_NoneType))sshQ_L_75ContD___call__;
        sshQ_L_75ContG_methods.__serialize__ = sshQ_L_75ContD___serialize__;
        sshQ_L_75ContG_methods.__deserialize__ = sshQ_L_75ContD___deserialize__;
        $register(&sshQ_L_75ContG_methods);
    }
    {
        sshQ_L_77ContG_methods.$GCINFO = "sshQ_L_77Cont";
        sshQ_L_77ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        sshQ_L_77ContG_methods.__bool__ = (B_bool (*) (sshQ_L_77Cont))B_valueG_methods.__bool__;
        sshQ_L_77ContG_methods.__str__ = (B_str (*) (sshQ_L_77Cont))B_valueG_methods.__str__;
        sshQ_L_77ContG_methods.__repr__ = (B_str (*) (sshQ_L_77Cont))B_valueG_methods.__repr__;
        sshQ_L_77ContG_methods.__init__ = (B_NoneType (*) (sshQ_L_77Cont, $Cont))sshQ_L_77ContD___init__;
        sshQ_L_77ContG_methods.__call__ = ($R (*) (sshQ_L_77Cont, B_NoneType))sshQ_L_77ContD___call__;
        sshQ_L_77ContG_methods.__serialize__ = sshQ_L_77ContD___serialize__;
        sshQ_L_77ContG_methods.__deserialize__ = sshQ_L_77ContD___deserialize__;
        $register(&sshQ_L_77ContG_methods);
    }
    {
        sshQ_L_78ContG_methods.$GCINFO = "sshQ_L_78Cont";
        sshQ_L_78ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        sshQ_L_78ContG_methods.__bool__ = (B_bool (*) (sshQ_L_78Cont))B_valueG_methods.__bool__;
        sshQ_L_78ContG_methods.__str__ = (B_str (*) (sshQ_L_78Cont))B_valueG_methods.__str__;
        sshQ_L_78ContG_methods.__repr__ = (B_str (*) (sshQ_L_78Cont))B_valueG_methods.__repr__;
        sshQ_L_78ContG_methods.__init__ = (B_NoneType (*) (sshQ_L_78Cont, $Cont))sshQ_L_78ContD___init__;
        sshQ_L_78ContG_methods.__call__ = ($R (*) (sshQ_L_78Cont, B_NoneType))sshQ_L_78ContD___call__;
        sshQ_L_78ContG_methods.__serialize__ = sshQ_L_78ContD___serialize__;
        sshQ_L_78ContG_methods.__deserialize__ = sshQ_L_78ContD___deserialize__;
        $register(&sshQ_L_78ContG_methods);
    }
    {
        sshQ_L_79procG_methods.$GCINFO = "sshQ_L_79proc";
        sshQ_L_79procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        sshQ_L_79procG_methods.__bool__ = (B_bool (*) (sshQ_L_79proc))B_valueG_methods.__bool__;
        sshQ_L_79procG_methods.__str__ = (B_str (*) (sshQ_L_79proc))B_valueG_methods.__str__;
        sshQ_L_79procG_methods.__repr__ = (B_str (*) (sshQ_L_79proc))B_valueG_methods.__repr__;
        sshQ_L_79procG_methods.__init__ = (B_NoneType (*) (sshQ_L_79proc, sshQ_RunCommand, sshQ_Channel))sshQ_L_79procD___init__;
        sshQ_L_79procG_methods.__call__ = ($R (*) (sshQ_L_79proc, $Cont))sshQ_L_79procD___call__;
        sshQ_L_79procG_methods.__exec__ = ($R (*) (sshQ_L_79proc, $Cont))sshQ_L_79procD___exec__;
        sshQ_L_79procG_methods.__serialize__ = sshQ_L_79procD___serialize__;
        sshQ_L_79procG_methods.__deserialize__ = sshQ_L_79procD___deserialize__;
        $register(&sshQ_L_79procG_methods);
    }
    {
        sshQ_L_80procG_methods.$GCINFO = "sshQ_L_80proc";
        sshQ_L_80procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        sshQ_L_80procG_methods.__bool__ = (B_bool (*) (sshQ_L_80proc))B_valueG_methods.__bool__;
        sshQ_L_80procG_methods.__str__ = (B_str (*) (sshQ_L_80proc))B_valueG_methods.__str__;
        sshQ_L_80procG_methods.__repr__ = (B_str (*) (sshQ_L_80proc))B_valueG_methods.__repr__;
        sshQ_L_80procG_methods.__init__ = (B_NoneType (*) (sshQ_L_80proc, sshQ_RunCommand, sshQ_Channel, B_str))sshQ_L_80procD___init__;
        sshQ_L_80procG_methods.__call__ = ($R (*) (sshQ_L_80proc, $Cont))sshQ_L_80procD___call__;
        sshQ_L_80procG_methods.__exec__ = ($R (*) (sshQ_L_80proc, $Cont))sshQ_L_80procD___exec__;
        sshQ_L_80procG_methods.__serialize__ = sshQ_L_80procD___serialize__;
        sshQ_L_80procG_methods.__deserialize__ = sshQ_L_80procD___deserialize__;
        $register(&sshQ_L_80procG_methods);
    }
    {
        sshQ_L_81procG_methods.$GCINFO = "sshQ_L_81proc";
        sshQ_L_81procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        sshQ_L_81procG_methods.__bool__ = (B_bool (*) (sshQ_L_81proc))B_valueG_methods.__bool__;
        sshQ_L_81procG_methods.__str__ = (B_str (*) (sshQ_L_81proc))B_valueG_methods.__str__;
        sshQ_L_81procG_methods.__repr__ = (B_str (*) (sshQ_L_81proc))B_valueG_methods.__repr__;
        sshQ_L_81procG_methods.__init__ = (B_NoneType (*) (sshQ_L_81proc, sshQ_RunCommand, sshQ_Channel, B_bytes))sshQ_L_81procD___init__;
        sshQ_L_81procG_methods.__call__ = ($R (*) (sshQ_L_81proc, $Cont))sshQ_L_81procD___call__;
        sshQ_L_81procG_methods.__exec__ = ($R (*) (sshQ_L_81proc, $Cont))sshQ_L_81procD___exec__;
        sshQ_L_81procG_methods.__serialize__ = sshQ_L_81procD___serialize__;
        sshQ_L_81procG_methods.__deserialize__ = sshQ_L_81procD___deserialize__;
        $register(&sshQ_L_81procG_methods);
    }
    {
        sshQ_L_82procG_methods.$GCINFO = "sshQ_L_82proc";
        sshQ_L_82procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        sshQ_L_82procG_methods.__bool__ = (B_bool (*) (sshQ_L_82proc))B_valueG_methods.__bool__;
        sshQ_L_82procG_methods.__str__ = (B_str (*) (sshQ_L_82proc))B_valueG_methods.__str__;
        sshQ_L_82procG_methods.__repr__ = (B_str (*) (sshQ_L_82proc))B_valueG_methods.__repr__;
        sshQ_L_82procG_methods.__init__ = (B_NoneType (*) (sshQ_L_82proc, sshQ_RunCommand, sshQ_Channel, B_bytes))sshQ_L_82procD___init__;
        sshQ_L_82procG_methods.__call__ = ($R (*) (sshQ_L_82proc, $Cont))sshQ_L_82procD___call__;
        sshQ_L_82procG_methods.__exec__ = ($R (*) (sshQ_L_82proc, $Cont))sshQ_L_82procD___exec__;
        sshQ_L_82procG_methods.__serialize__ = sshQ_L_82procD___serialize__;
        sshQ_L_82procG_methods.__deserialize__ = sshQ_L_82procD___deserialize__;
        $register(&sshQ_L_82procG_methods);
    }
    {
        sshQ_L_83procG_methods.$GCINFO = "sshQ_L_83proc";
        sshQ_L_83procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        sshQ_L_83procG_methods.__bool__ = (B_bool (*) (sshQ_L_83proc))B_valueG_methods.__bool__;
        sshQ_L_83procG_methods.__str__ = (B_str (*) (sshQ_L_83proc))B_valueG_methods.__str__;
        sshQ_L_83procG_methods.__repr__ = (B_str (*) (sshQ_L_83proc))B_valueG_methods.__repr__;
        sshQ_L_83procG_methods.__init__ = (B_NoneType (*) (sshQ_L_83proc, sshQ_RunCommand, sshQ_Channel, int64_t, B_str))sshQ_L_83procD___init__;
        sshQ_L_83procG_methods.__call__ = ($R (*) (sshQ_L_83proc, $Cont))sshQ_L_83procD___call__;
        sshQ_L_83procG_methods.__exec__ = ($R (*) (sshQ_L_83proc, $Cont))sshQ_L_83procD___exec__;
        sshQ_L_83procG_methods.__serialize__ = sshQ_L_83procD___serialize__;
        sshQ_L_83procG_methods.__deserialize__ = sshQ_L_83procD___deserialize__;
        $register(&sshQ_L_83procG_methods);
    }
    {
        sshQ_L_84procG_methods.$GCINFO = "sshQ_L_84proc";
        sshQ_L_84procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        sshQ_L_84procG_methods.__bool__ = (B_bool (*) (sshQ_L_84proc))B_valueG_methods.__bool__;
        sshQ_L_84procG_methods.__str__ = (B_str (*) (sshQ_L_84proc))B_valueG_methods.__str__;
        sshQ_L_84procG_methods.__repr__ = (B_str (*) (sshQ_L_84proc))B_valueG_methods.__repr__;
        sshQ_L_84procG_methods.__init__ = (B_NoneType (*) (sshQ_L_84proc, sshQ_RunCommand, sshQ_Channel, B_str))sshQ_L_84procD___init__;
        sshQ_L_84procG_methods.__call__ = ($R (*) (sshQ_L_84proc, $Cont))sshQ_L_84procD___call__;
        sshQ_L_84procG_methods.__exec__ = ($R (*) (sshQ_L_84proc, $Cont))sshQ_L_84procD___exec__;
        sshQ_L_84procG_methods.__serialize__ = sshQ_L_84procD___serialize__;
        sshQ_L_84procG_methods.__deserialize__ = sshQ_L_84procD___deserialize__;
        $register(&sshQ_L_84procG_methods);
    }
    {
        sshQ_L_85procG_methods.$GCINFO = "sshQ_L_85proc";
        sshQ_L_85procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        sshQ_L_85procG_methods.__bool__ = (B_bool (*) (sshQ_L_85proc))B_valueG_methods.__bool__;
        sshQ_L_85procG_methods.__str__ = (B_str (*) (sshQ_L_85proc))B_valueG_methods.__str__;
        sshQ_L_85procG_methods.__repr__ = (B_str (*) (sshQ_L_85proc))B_valueG_methods.__repr__;
        sshQ_L_85procG_methods.__init__ = (B_NoneType (*) (sshQ_L_85proc, sshQ_RunCommand, sshQ_Channel))sshQ_L_85procD___init__;
        sshQ_L_85procG_methods.__call__ = ($R (*) (sshQ_L_85proc, $Cont))sshQ_L_85procD___call__;
        sshQ_L_85procG_methods.__exec__ = ($R (*) (sshQ_L_85proc, $Cont))sshQ_L_85procD___exec__;
        sshQ_L_85procG_methods.__serialize__ = sshQ_L_85procD___serialize__;
        sshQ_L_85procG_methods.__deserialize__ = sshQ_L_85procD___deserialize__;
        $register(&sshQ_L_85procG_methods);
    }
    {
        sshQ_L_87ContG_methods.$GCINFO = "sshQ_L_87Cont";
        sshQ_L_87ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        sshQ_L_87ContG_methods.__bool__ = (B_bool (*) (sshQ_L_87Cont))B_valueG_methods.__bool__;
        sshQ_L_87ContG_methods.__str__ = (B_str (*) (sshQ_L_87Cont))B_valueG_methods.__str__;
        sshQ_L_87ContG_methods.__repr__ = (B_str (*) (sshQ_L_87Cont))B_valueG_methods.__repr__;
        sshQ_L_87ContG_methods.__init__ = (B_NoneType (*) (sshQ_L_87Cont, sshQ_Server, $Cont))sshQ_L_87ContD___init__;
        sshQ_L_87ContG_methods.__call__ = ($R (*) (sshQ_L_87Cont, B_NoneType))sshQ_L_87ContD___call__;
        sshQ_L_87ContG_methods.__serialize__ = sshQ_L_87ContD___serialize__;
        sshQ_L_87ContG_methods.__deserialize__ = sshQ_L_87ContD___deserialize__;
        $register(&sshQ_L_87ContG_methods);
    }
    {
        sshQ_L_89ContG_methods.$GCINFO = "sshQ_L_89Cont";
        sshQ_L_89ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        sshQ_L_89ContG_methods.__bool__ = (B_bool (*) (sshQ_L_89Cont))B_valueG_methods.__bool__;
        sshQ_L_89ContG_methods.__str__ = (B_str (*) (sshQ_L_89Cont))B_valueG_methods.__str__;
        sshQ_L_89ContG_methods.__repr__ = (B_str (*) (sshQ_L_89Cont))B_valueG_methods.__repr__;
        sshQ_L_89ContG_methods.__init__ = (B_NoneType (*) (sshQ_L_89Cont, $Cont))sshQ_L_89ContD___init__;
        sshQ_L_89ContG_methods.__call__ = ($R (*) (sshQ_L_89Cont, B_NoneType))sshQ_L_89ContD___call__;
        sshQ_L_89ContG_methods.__serialize__ = sshQ_L_89ContD___serialize__;
        sshQ_L_89ContG_methods.__deserialize__ = sshQ_L_89ContD___deserialize__;
        $register(&sshQ_L_89ContG_methods);
    }
    {
        sshQ_L_90ContG_methods.$GCINFO = "sshQ_L_90Cont";
        sshQ_L_90ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        sshQ_L_90ContG_methods.__bool__ = (B_bool (*) (sshQ_L_90Cont))B_valueG_methods.__bool__;
        sshQ_L_90ContG_methods.__str__ = (B_str (*) (sshQ_L_90Cont))B_valueG_methods.__str__;
        sshQ_L_90ContG_methods.__repr__ = (B_str (*) (sshQ_L_90Cont))B_valueG_methods.__repr__;
        sshQ_L_90ContG_methods.__init__ = (B_NoneType (*) (sshQ_L_90Cont, $Cont))sshQ_L_90ContD___init__;
        sshQ_L_90ContG_methods.__call__ = ($R (*) (sshQ_L_90Cont, B_NoneType))sshQ_L_90ContD___call__;
        sshQ_L_90ContG_methods.__serialize__ = sshQ_L_90ContD___serialize__;
        sshQ_L_90ContG_methods.__deserialize__ = sshQ_L_90ContD___deserialize__;
        $register(&sshQ_L_90ContG_methods);
    }
    {
        sshQ_L_92ContG_methods.$GCINFO = "sshQ_L_92Cont";
        sshQ_L_92ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        sshQ_L_92ContG_methods.__bool__ = (B_bool (*) (sshQ_L_92Cont))B_valueG_methods.__bool__;
        sshQ_L_92ContG_methods.__str__ = (B_str (*) (sshQ_L_92Cont))B_valueG_methods.__str__;
        sshQ_L_92ContG_methods.__repr__ = (B_str (*) (sshQ_L_92Cont))B_valueG_methods.__repr__;
        sshQ_L_92ContG_methods.__init__ = (B_NoneType (*) (sshQ_L_92Cont, $Cont))sshQ_L_92ContD___init__;
        sshQ_L_92ContG_methods.__call__ = ($R (*) (sshQ_L_92Cont, sshQ_ServerSession))sshQ_L_92ContD___call__;
        sshQ_L_92ContG_methods.__serialize__ = sshQ_L_92ContD___serialize__;
        sshQ_L_92ContG_methods.__deserialize__ = sshQ_L_92ContD___deserialize__;
        $register(&sshQ_L_92ContG_methods);
    }
    {
        sshQ_L_93procG_methods.$GCINFO = "sshQ_L_93proc";
        sshQ_L_93procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        sshQ_L_93procG_methods.__bool__ = (B_bool (*) (sshQ_L_93proc))B_valueG_methods.__bool__;
        sshQ_L_93procG_methods.__str__ = (B_str (*) (sshQ_L_93proc))B_valueG_methods.__str__;
        sshQ_L_93procG_methods.__repr__ = (B_str (*) (sshQ_L_93proc))B_valueG_methods.__repr__;
        sshQ_L_93procG_methods.__init__ = (B_NoneType (*) (sshQ_L_93proc, sshQ_Server))sshQ_L_93procD___init__;
        sshQ_L_93procG_methods.__call__ = ($R (*) (sshQ_L_93proc, $Cont))sshQ_L_93procD___call__;
        sshQ_L_93procG_methods.__exec__ = ($R (*) (sshQ_L_93proc, $Cont))sshQ_L_93procD___exec__;
        sshQ_L_93procG_methods.__serialize__ = sshQ_L_93procD___serialize__;
        sshQ_L_93procG_methods.__deserialize__ = sshQ_L_93procD___deserialize__;
        $register(&sshQ_L_93procG_methods);
    }
    {
        sshQ_L_94procG_methods.$GCINFO = "sshQ_L_94proc";
        sshQ_L_94procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        sshQ_L_94procG_methods.__bool__ = (B_bool (*) (sshQ_L_94proc))B_valueG_methods.__bool__;
        sshQ_L_94procG_methods.__str__ = (B_str (*) (sshQ_L_94proc))B_valueG_methods.__str__;
        sshQ_L_94procG_methods.__repr__ = (B_str (*) (sshQ_L_94proc))B_valueG_methods.__repr__;
        sshQ_L_94procG_methods.__init__ = (B_NoneType (*) (sshQ_L_94proc, sshQ_Server))sshQ_L_94procD___init__;
        sshQ_L_94procG_methods.__call__ = ($R (*) (sshQ_L_94proc, $Cont))sshQ_L_94procD___call__;
        sshQ_L_94procG_methods.__exec__ = ($R (*) (sshQ_L_94proc, $Cont))sshQ_L_94procD___exec__;
        sshQ_L_94procG_methods.__serialize__ = sshQ_L_94procD___serialize__;
        sshQ_L_94procG_methods.__deserialize__ = sshQ_L_94procD___deserialize__;
        $register(&sshQ_L_94procG_methods);
    }
    {
        sshQ_L_95procG_methods.$GCINFO = "sshQ_L_95proc";
        sshQ_L_95procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        sshQ_L_95procG_methods.__bool__ = (B_bool (*) (sshQ_L_95proc))B_valueG_methods.__bool__;
        sshQ_L_95procG_methods.__str__ = (B_str (*) (sshQ_L_95proc))B_valueG_methods.__str__;
        sshQ_L_95procG_methods.__repr__ = (B_str (*) (sshQ_L_95proc))B_valueG_methods.__repr__;
        sshQ_L_95procG_methods.__init__ = (B_NoneType (*) (sshQ_L_95proc, sshQ_Server))sshQ_L_95procD___init__;
        sshQ_L_95procG_methods.__call__ = ($R (*) (sshQ_L_95proc, $Cont))sshQ_L_95procD___call__;
        sshQ_L_95procG_methods.__exec__ = ($R (*) (sshQ_L_95proc, $Cont))sshQ_L_95procD___exec__;
        sshQ_L_95procG_methods.__serialize__ = sshQ_L_95procD___serialize__;
        sshQ_L_95procG_methods.__deserialize__ = sshQ_L_95procD___deserialize__;
        $register(&sshQ_L_95procG_methods);
    }
    {
        sshQ_L_96procG_methods.$GCINFO = "sshQ_L_96proc";
        sshQ_L_96procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        sshQ_L_96procG_methods.__bool__ = (B_bool (*) (sshQ_L_96proc))B_valueG_methods.__bool__;
        sshQ_L_96procG_methods.__str__ = (B_str (*) (sshQ_L_96proc))B_valueG_methods.__str__;
        sshQ_L_96procG_methods.__repr__ = (B_str (*) (sshQ_L_96proc))B_valueG_methods.__repr__;
        sshQ_L_96procG_methods.__init__ = (B_NoneType (*) (sshQ_L_96proc, sshQ_Server))sshQ_L_96procD___init__;
        sshQ_L_96procG_methods.__call__ = ($R (*) (sshQ_L_96proc, $Cont))sshQ_L_96procD___call__;
        sshQ_L_96procG_methods.__exec__ = ($R (*) (sshQ_L_96proc, $Cont))sshQ_L_96procD___exec__;
        sshQ_L_96procG_methods.__serialize__ = sshQ_L_96procD___serialize__;
        sshQ_L_96procG_methods.__deserialize__ = sshQ_L_96procD___deserialize__;
        $register(&sshQ_L_96procG_methods);
    }
    {
        sshQ_L_97procG_methods.$GCINFO = "sshQ_L_97proc";
        sshQ_L_97procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        sshQ_L_97procG_methods.__bool__ = (B_bool (*) (sshQ_L_97proc))B_valueG_methods.__bool__;
        sshQ_L_97procG_methods.__str__ = (B_str (*) (sshQ_L_97proc))B_valueG_methods.__str__;
        sshQ_L_97procG_methods.__repr__ = (B_str (*) (sshQ_L_97proc))B_valueG_methods.__repr__;
        sshQ_L_97procG_methods.__init__ = (B_NoneType (*) (sshQ_L_97proc, sshQ_Server))sshQ_L_97procD___init__;
        sshQ_L_97procG_methods.__call__ = ($R (*) (sshQ_L_97proc, $Cont))sshQ_L_97procD___call__;
        sshQ_L_97procG_methods.__exec__ = ($R (*) (sshQ_L_97proc, $Cont))sshQ_L_97procD___exec__;
        sshQ_L_97procG_methods.__serialize__ = sshQ_L_97procD___serialize__;
        sshQ_L_97procG_methods.__deserialize__ = sshQ_L_97procD___deserialize__;
        $register(&sshQ_L_97procG_methods);
    }
    {
        sshQ_L_98procG_methods.$GCINFO = "sshQ_L_98proc";
        sshQ_L_98procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        sshQ_L_98procG_methods.__bool__ = (B_bool (*) (sshQ_L_98proc))B_valueG_methods.__bool__;
        sshQ_L_98procG_methods.__str__ = (B_str (*) (sshQ_L_98proc))B_valueG_methods.__str__;
        sshQ_L_98procG_methods.__repr__ = (B_str (*) (sshQ_L_98proc))B_valueG_methods.__repr__;
        sshQ_L_98procG_methods.__init__ = (B_NoneType (*) (sshQ_L_98proc, sshQ_Server))sshQ_L_98procD___init__;
        sshQ_L_98procG_methods.__call__ = ($R (*) (sshQ_L_98proc, $Cont))sshQ_L_98procD___call__;
        sshQ_L_98procG_methods.__exec__ = ($R (*) (sshQ_L_98proc, $Cont))sshQ_L_98procD___exec__;
        sshQ_L_98procG_methods.__serialize__ = sshQ_L_98procD___serialize__;
        sshQ_L_98procG_methods.__deserialize__ = sshQ_L_98procD___deserialize__;
        $register(&sshQ_L_98procG_methods);
    }
    {
        sshQ_L_99procG_methods.$GCINFO = "sshQ_L_99proc";
        sshQ_L_99procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        sshQ_L_99procG_methods.__bool__ = (B_bool (*) (sshQ_L_99proc))B_valueG_methods.__bool__;
        sshQ_L_99procG_methods.__str__ = (B_str (*) (sshQ_L_99proc))B_valueG_methods.__str__;
        sshQ_L_99procG_methods.__repr__ = (B_str (*) (sshQ_L_99proc))B_valueG_methods.__repr__;
        sshQ_L_99procG_methods.__init__ = (B_NoneType (*) (sshQ_L_99proc, sshQ_Server, uint64_t))sshQ_L_99procD___init__;
        sshQ_L_99procG_methods.__call__ = ($R (*) (sshQ_L_99proc, $Cont))sshQ_L_99procD___call__;
        sshQ_L_99procG_methods.__exec__ = ($R (*) (sshQ_L_99proc, $Cont))sshQ_L_99procD___exec__;
        sshQ_L_99procG_methods.__serialize__ = sshQ_L_99procD___serialize__;
        sshQ_L_99procG_methods.__deserialize__ = sshQ_L_99procD___deserialize__;
        $register(&sshQ_L_99procG_methods);
    }
    {
        sshQ_L_100procG_methods.$GCINFO = "sshQ_L_100proc";
        sshQ_L_100procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        sshQ_L_100procG_methods.__bool__ = (B_bool (*) (sshQ_L_100proc))B_valueG_methods.__bool__;
        sshQ_L_100procG_methods.__str__ = (B_str (*) (sshQ_L_100proc))B_valueG_methods.__str__;
        sshQ_L_100procG_methods.__repr__ = (B_str (*) (sshQ_L_100proc))B_valueG_methods.__repr__;
        sshQ_L_100procG_methods.__init__ = (B_NoneType (*) (sshQ_L_100proc, sshQ_Server, sshQ_ServerSession))sshQ_L_100procD___init__;
        sshQ_L_100procG_methods.__call__ = ($R (*) (sshQ_L_100proc, $Cont))sshQ_L_100procD___call__;
        sshQ_L_100procG_methods.__exec__ = ($R (*) (sshQ_L_100proc, $Cont))sshQ_L_100procD___exec__;
        sshQ_L_100procG_methods.__serialize__ = sshQ_L_100procD___serialize__;
        sshQ_L_100procG_methods.__deserialize__ = sshQ_L_100procD___deserialize__;
        $register(&sshQ_L_100procG_methods);
    }
    {
        sshQ_L_102procG_methods.$GCINFO = "sshQ_L_102proc";
        sshQ_L_102procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        sshQ_L_102procG_methods.__bool__ = (B_bool (*) (sshQ_L_102proc))B_valueG_methods.__bool__;
        sshQ_L_102procG_methods.__str__ = (B_str (*) (sshQ_L_102proc))B_valueG_methods.__str__;
        sshQ_L_102procG_methods.__repr__ = (B_str (*) (sshQ_L_102proc))B_valueG_methods.__repr__;
        sshQ_L_102procG_methods.__init__ = (B_NoneType (*) (sshQ_L_102proc, sshQ_ServerSession))sshQ_L_102procD___init__;
        sshQ_L_102procG_methods.__call__ = ($R (*) (sshQ_L_102proc, $Cont))sshQ_L_102procD___call__;
        sshQ_L_102procG_methods.__exec__ = ($R (*) (sshQ_L_102proc, $Cont))sshQ_L_102procD___exec__;
        sshQ_L_102procG_methods.__serialize__ = sshQ_L_102procD___serialize__;
        sshQ_L_102procG_methods.__deserialize__ = sshQ_L_102procD___deserialize__;
        $register(&sshQ_L_102procG_methods);
    }
    {
        sshQ_L_103ContG_methods.$GCINFO = "sshQ_L_103Cont";
        sshQ_L_103ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        sshQ_L_103ContG_methods.__bool__ = (B_bool (*) (sshQ_L_103Cont))B_valueG_methods.__bool__;
        sshQ_L_103ContG_methods.__str__ = (B_str (*) (sshQ_L_103Cont))B_valueG_methods.__str__;
        sshQ_L_103ContG_methods.__repr__ = (B_str (*) (sshQ_L_103Cont))B_valueG_methods.__repr__;
        sshQ_L_103ContG_methods.__init__ = (B_NoneType (*) (sshQ_L_103Cont, sshQ_ServerSession, $Cont))sshQ_L_103ContD___init__;
        sshQ_L_103ContG_methods.__call__ = ($R (*) (sshQ_L_103Cont, B_NoneType))sshQ_L_103ContD___call__;
        sshQ_L_103ContG_methods.__serialize__ = sshQ_L_103ContD___serialize__;
        sshQ_L_103ContG_methods.__deserialize__ = sshQ_L_103ContD___deserialize__;
        $register(&sshQ_L_103ContG_methods);
    }
    {
        sshQ_L_106ContG_methods.$GCINFO = "sshQ_L_106Cont";
        sshQ_L_106ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        sshQ_L_106ContG_methods.__bool__ = (B_bool (*) (sshQ_L_106Cont))B_valueG_methods.__bool__;
        sshQ_L_106ContG_methods.__str__ = (B_str (*) (sshQ_L_106Cont))B_valueG_methods.__str__;
        sshQ_L_106ContG_methods.__repr__ = (B_str (*) (sshQ_L_106Cont))B_valueG_methods.__repr__;
        sshQ_L_106ContG_methods.__init__ = (B_NoneType (*) (sshQ_L_106Cont, $Cont))sshQ_L_106ContD___init__;
        sshQ_L_106ContG_methods.__call__ = ($R (*) (sshQ_L_106Cont, B_NoneType))sshQ_L_106ContD___call__;
        sshQ_L_106ContG_methods.__serialize__ = sshQ_L_106ContD___serialize__;
        sshQ_L_106ContG_methods.__deserialize__ = sshQ_L_106ContD___deserialize__;
        $register(&sshQ_L_106ContG_methods);
    }
    {
        sshQ_L_107ContG_methods.$GCINFO = "sshQ_L_107Cont";
        sshQ_L_107ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        sshQ_L_107ContG_methods.__bool__ = (B_bool (*) (sshQ_L_107Cont))B_valueG_methods.__bool__;
        sshQ_L_107ContG_methods.__str__ = (B_str (*) (sshQ_L_107Cont))B_valueG_methods.__str__;
        sshQ_L_107ContG_methods.__repr__ = (B_str (*) (sshQ_L_107Cont))B_valueG_methods.__repr__;
        sshQ_L_107ContG_methods.__init__ = (B_NoneType (*) (sshQ_L_107Cont, $Cont))sshQ_L_107ContD___init__;
        sshQ_L_107ContG_methods.__call__ = ($R (*) (sshQ_L_107Cont, B_NoneType))sshQ_L_107ContD___call__;
        sshQ_L_107ContG_methods.__serialize__ = sshQ_L_107ContD___serialize__;
        sshQ_L_107ContG_methods.__deserialize__ = sshQ_L_107ContD___deserialize__;
        $register(&sshQ_L_107ContG_methods);
    }
    {
        sshQ_L_108ContG_methods.$GCINFO = "sshQ_L_108Cont";
        sshQ_L_108ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        sshQ_L_108ContG_methods.__bool__ = (B_bool (*) (sshQ_L_108Cont))B_valueG_methods.__bool__;
        sshQ_L_108ContG_methods.__str__ = (B_str (*) (sshQ_L_108Cont))B_valueG_methods.__str__;
        sshQ_L_108ContG_methods.__repr__ = (B_str (*) (sshQ_L_108Cont))B_valueG_methods.__repr__;
        sshQ_L_108ContG_methods.__init__ = (B_NoneType (*) (sshQ_L_108Cont, $Cont, sshQ_ServerSession))sshQ_L_108ContD___init__;
        sshQ_L_108ContG_methods.__call__ = ($R (*) (sshQ_L_108Cont, B_NoneType))sshQ_L_108ContD___call__;
        sshQ_L_108ContG_methods.__serialize__ = sshQ_L_108ContD___serialize__;
        sshQ_L_108ContG_methods.__deserialize__ = sshQ_L_108ContD___deserialize__;
        $register(&sshQ_L_108ContG_methods);
    }
    {
        sshQ_L_110ContG_methods.$GCINFO = "sshQ_L_110Cont";
        sshQ_L_110ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        sshQ_L_110ContG_methods.__bool__ = (B_bool (*) (sshQ_L_110Cont))B_valueG_methods.__bool__;
        sshQ_L_110ContG_methods.__str__ = (B_str (*) (sshQ_L_110Cont))B_valueG_methods.__str__;
        sshQ_L_110ContG_methods.__repr__ = (B_str (*) (sshQ_L_110Cont))B_valueG_methods.__repr__;
        sshQ_L_110ContG_methods.__init__ = (B_NoneType (*) (sshQ_L_110Cont, $Cont))sshQ_L_110ContD___init__;
        sshQ_L_110ContG_methods.__call__ = ($R (*) (sshQ_L_110Cont, B_NoneType))sshQ_L_110ContD___call__;
        sshQ_L_110ContG_methods.__serialize__ = sshQ_L_110ContD___serialize__;
        sshQ_L_110ContG_methods.__deserialize__ = sshQ_L_110ContD___deserialize__;
        $register(&sshQ_L_110ContG_methods);
    }
    {
        sshQ_L_111ContG_methods.$GCINFO = "sshQ_L_111Cont";
        sshQ_L_111ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        sshQ_L_111ContG_methods.__bool__ = (B_bool (*) (sshQ_L_111Cont))B_valueG_methods.__bool__;
        sshQ_L_111ContG_methods.__str__ = (B_str (*) (sshQ_L_111Cont))B_valueG_methods.__str__;
        sshQ_L_111ContG_methods.__repr__ = (B_str (*) (sshQ_L_111Cont))B_valueG_methods.__repr__;
        sshQ_L_111ContG_methods.__init__ = (B_NoneType (*) (sshQ_L_111Cont, $Cont))sshQ_L_111ContD___init__;
        sshQ_L_111ContG_methods.__call__ = ($R (*) (sshQ_L_111Cont, B_NoneType))sshQ_L_111ContD___call__;
        sshQ_L_111ContG_methods.__serialize__ = sshQ_L_111ContD___serialize__;
        sshQ_L_111ContG_methods.__deserialize__ = sshQ_L_111ContD___deserialize__;
        $register(&sshQ_L_111ContG_methods);
    }
    {
        sshQ_L_112procG_methods.$GCINFO = "sshQ_L_112proc";
        sshQ_L_112procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        sshQ_L_112procG_methods.__bool__ = (B_bool (*) (sshQ_L_112proc))B_valueG_methods.__bool__;
        sshQ_L_112procG_methods.__str__ = (B_str (*) (sshQ_L_112proc))B_valueG_methods.__str__;
        sshQ_L_112procG_methods.__repr__ = (B_str (*) (sshQ_L_112proc))B_valueG_methods.__repr__;
        sshQ_L_112procG_methods.__init__ = (B_NoneType (*) (sshQ_L_112proc, sshQ_ServerSession))sshQ_L_112procD___init__;
        sshQ_L_112procG_methods.__call__ = ($R (*) (sshQ_L_112proc, $Cont))sshQ_L_112procD___call__;
        sshQ_L_112procG_methods.__exec__ = ($R (*) (sshQ_L_112proc, $Cont))sshQ_L_112procD___exec__;
        sshQ_L_112procG_methods.__serialize__ = sshQ_L_112procD___serialize__;
        sshQ_L_112procG_methods.__deserialize__ = sshQ_L_112procD___deserialize__;
        $register(&sshQ_L_112procG_methods);
    }
    {
        sshQ_L_113procG_methods.$GCINFO = "sshQ_L_113proc";
        sshQ_L_113procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        sshQ_L_113procG_methods.__bool__ = (B_bool (*) (sshQ_L_113proc))B_valueG_methods.__bool__;
        sshQ_L_113procG_methods.__str__ = (B_str (*) (sshQ_L_113proc))B_valueG_methods.__str__;
        sshQ_L_113procG_methods.__repr__ = (B_str (*) (sshQ_L_113proc))B_valueG_methods.__repr__;
        sshQ_L_113procG_methods.__init__ = (B_NoneType (*) (sshQ_L_113proc, sshQ_ServerSession, uint64_t))sshQ_L_113procD___init__;
        sshQ_L_113procG_methods.__call__ = ($R (*) (sshQ_L_113proc, $Cont))sshQ_L_113procD___call__;
        sshQ_L_113procG_methods.__exec__ = ($R (*) (sshQ_L_113proc, $Cont))sshQ_L_113procD___exec__;
        sshQ_L_113procG_methods.__serialize__ = sshQ_L_113procD___serialize__;
        sshQ_L_113procG_methods.__deserialize__ = sshQ_L_113procD___deserialize__;
        $register(&sshQ_L_113procG_methods);
    }
    {
        sshQ_L_114procG_methods.$GCINFO = "sshQ_L_114proc";
        sshQ_L_114procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        sshQ_L_114procG_methods.__bool__ = (B_bool (*) (sshQ_L_114proc))B_valueG_methods.__bool__;
        sshQ_L_114procG_methods.__str__ = (B_str (*) (sshQ_L_114proc))B_valueG_methods.__str__;
        sshQ_L_114procG_methods.__repr__ = (B_str (*) (sshQ_L_114proc))B_valueG_methods.__repr__;
        sshQ_L_114procG_methods.__init__ = (B_NoneType (*) (sshQ_L_114proc, sshQ_ServerSession))sshQ_L_114procD___init__;
        sshQ_L_114procG_methods.__call__ = ($R (*) (sshQ_L_114proc, $Cont))sshQ_L_114procD___call__;
        sshQ_L_114procG_methods.__exec__ = ($R (*) (sshQ_L_114proc, $Cont))sshQ_L_114procD___exec__;
        sshQ_L_114procG_methods.__serialize__ = sshQ_L_114procD___serialize__;
        sshQ_L_114procG_methods.__deserialize__ = sshQ_L_114procD___deserialize__;
        $register(&sshQ_L_114procG_methods);
    }
    {
        sshQ_L_115procG_methods.$GCINFO = "sshQ_L_115proc";
        sshQ_L_115procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        sshQ_L_115procG_methods.__bool__ = (B_bool (*) (sshQ_L_115proc))B_valueG_methods.__bool__;
        sshQ_L_115procG_methods.__str__ = (B_str (*) (sshQ_L_115proc))B_valueG_methods.__str__;
        sshQ_L_115procG_methods.__repr__ = (B_str (*) (sshQ_L_115proc))B_valueG_methods.__repr__;
        sshQ_L_115procG_methods.__init__ = (B_NoneType (*) (sshQ_L_115proc, sshQ_ServerSession))sshQ_L_115procD___init__;
        sshQ_L_115procG_methods.__call__ = ($R (*) (sshQ_L_115proc, $Cont))sshQ_L_115procD___call__;
        sshQ_L_115procG_methods.__exec__ = ($R (*) (sshQ_L_115proc, $Cont))sshQ_L_115procD___exec__;
        sshQ_L_115procG_methods.__serialize__ = sshQ_L_115procD___serialize__;
        sshQ_L_115procG_methods.__deserialize__ = sshQ_L_115procD___deserialize__;
        $register(&sshQ_L_115procG_methods);
    }
    {
        sshQ_L_116procG_methods.$GCINFO = "sshQ_L_116proc";
        sshQ_L_116procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        sshQ_L_116procG_methods.__bool__ = (B_bool (*) (sshQ_L_116proc))B_valueG_methods.__bool__;
        sshQ_L_116procG_methods.__str__ = (B_str (*) (sshQ_L_116proc))B_valueG_methods.__str__;
        sshQ_L_116procG_methods.__repr__ = (B_str (*) (sshQ_L_116proc))B_valueG_methods.__repr__;
        sshQ_L_116procG_methods.__init__ = (B_NoneType (*) (sshQ_L_116proc, sshQ_ServerSession))sshQ_L_116procD___init__;
        sshQ_L_116procG_methods.__call__ = ($R (*) (sshQ_L_116proc, $Cont))sshQ_L_116procD___call__;
        sshQ_L_116procG_methods.__exec__ = ($R (*) (sshQ_L_116proc, $Cont))sshQ_L_116procD___exec__;
        sshQ_L_116procG_methods.__serialize__ = sshQ_L_116procD___serialize__;
        sshQ_L_116procG_methods.__deserialize__ = sshQ_L_116procD___deserialize__;
        $register(&sshQ_L_116procG_methods);
    }
    {
        sshQ_L_117procG_methods.$GCINFO = "sshQ_L_117proc";
        sshQ_L_117procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        sshQ_L_117procG_methods.__bool__ = (B_bool (*) (sshQ_L_117proc))B_valueG_methods.__bool__;
        sshQ_L_117procG_methods.__str__ = (B_str (*) (sshQ_L_117proc))B_valueG_methods.__str__;
        sshQ_L_117procG_methods.__repr__ = (B_str (*) (sshQ_L_117proc))B_valueG_methods.__repr__;
        sshQ_L_117procG_methods.__init__ = (B_NoneType (*) (sshQ_L_117proc, sshQ_ServerSession, B_str))sshQ_L_117procD___init__;
        sshQ_L_117procG_methods.__call__ = ($R (*) (sshQ_L_117proc, $Cont))sshQ_L_117procD___call__;
        sshQ_L_117procG_methods.__exec__ = ($R (*) (sshQ_L_117proc, $Cont))sshQ_L_117procD___exec__;
        sshQ_L_117procG_methods.__serialize__ = sshQ_L_117procD___serialize__;
        sshQ_L_117procG_methods.__deserialize__ = sshQ_L_117procD___deserialize__;
        $register(&sshQ_L_117procG_methods);
    }
    {
        sshQ_L_118procG_methods.$GCINFO = "sshQ_L_118proc";
        sshQ_L_118procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        sshQ_L_118procG_methods.__bool__ = (B_bool (*) (sshQ_L_118proc))B_valueG_methods.__bool__;
        sshQ_L_118procG_methods.__str__ = (B_str (*) (sshQ_L_118proc))B_valueG_methods.__str__;
        sshQ_L_118procG_methods.__repr__ = (B_str (*) (sshQ_L_118proc))B_valueG_methods.__repr__;
        sshQ_L_118procG_methods.__init__ = (B_NoneType (*) (sshQ_L_118proc, sshQ_ServerSession, sshQ_ServerChannel))sshQ_L_118procD___init__;
        sshQ_L_118procG_methods.__call__ = ($R (*) (sshQ_L_118proc, $Cont))sshQ_L_118procD___call__;
        sshQ_L_118procG_methods.__exec__ = ($R (*) (sshQ_L_118proc, $Cont))sshQ_L_118procD___exec__;
        sshQ_L_118procG_methods.__serialize__ = sshQ_L_118procD___serialize__;
        sshQ_L_118procG_methods.__deserialize__ = sshQ_L_118procD___deserialize__;
        $register(&sshQ_L_118procG_methods);
    }
    {
        sshQ_L_119procG_methods.$GCINFO = "sshQ_L_119proc";
        sshQ_L_119procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        sshQ_L_119procG_methods.__bool__ = (B_bool (*) (sshQ_L_119proc))B_valueG_methods.__bool__;
        sshQ_L_119procG_methods.__str__ = (B_str (*) (sshQ_L_119proc))B_valueG_methods.__str__;
        sshQ_L_119procG_methods.__repr__ = (B_str (*) (sshQ_L_119proc))B_valueG_methods.__repr__;
        sshQ_L_119procG_methods.__init__ = (B_NoneType (*) (sshQ_L_119proc, sshQ_ServerSession, sshQ_ServerChannel, $action, $action, $action))sshQ_L_119procD___init__;
        sshQ_L_119procG_methods.__call__ = ($R (*) (sshQ_L_119proc, $Cont))sshQ_L_119procD___call__;
        sshQ_L_119procG_methods.__exec__ = ($R (*) (sshQ_L_119proc, $Cont))sshQ_L_119procD___exec__;
        sshQ_L_119procG_methods.__serialize__ = sshQ_L_119procD___serialize__;
        sshQ_L_119procG_methods.__deserialize__ = sshQ_L_119procD___deserialize__;
        $register(&sshQ_L_119procG_methods);
    }
    {
        sshQ_L_120procG_methods.$GCINFO = "sshQ_L_120proc";
        sshQ_L_120procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        sshQ_L_120procG_methods.__bool__ = (B_bool (*) (sshQ_L_120proc))B_valueG_methods.__bool__;
        sshQ_L_120procG_methods.__str__ = (B_str (*) (sshQ_L_120proc))B_valueG_methods.__str__;
        sshQ_L_120procG_methods.__repr__ = (B_str (*) (sshQ_L_120proc))B_valueG_methods.__repr__;
        sshQ_L_120procG_methods.__init__ = (B_NoneType (*) (sshQ_L_120proc, sshQ_ServerSession, B_str))sshQ_L_120procD___init__;
        sshQ_L_120procG_methods.__call__ = ($R (*) (sshQ_L_120proc, $Cont))sshQ_L_120procD___call__;
        sshQ_L_120procG_methods.__exec__ = ($R (*) (sshQ_L_120proc, $Cont))sshQ_L_120procD___exec__;
        sshQ_L_120procG_methods.__serialize__ = sshQ_L_120procD___serialize__;
        sshQ_L_120procG_methods.__deserialize__ = sshQ_L_120procD___deserialize__;
        $register(&sshQ_L_120procG_methods);
    }
    {
        sshQ_L_121procG_methods.$GCINFO = "sshQ_L_121proc";
        sshQ_L_121procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        sshQ_L_121procG_methods.__bool__ = (B_bool (*) (sshQ_L_121proc))B_valueG_methods.__bool__;
        sshQ_L_121procG_methods.__str__ = (B_str (*) (sshQ_L_121proc))B_valueG_methods.__str__;
        sshQ_L_121procG_methods.__repr__ = (B_str (*) (sshQ_L_121proc))B_valueG_methods.__repr__;
        sshQ_L_121procG_methods.__init__ = (B_NoneType (*) (sshQ_L_121proc, sshQ_ServerSession))sshQ_L_121procD___init__;
        sshQ_L_121procG_methods.__call__ = ($R (*) (sshQ_L_121proc, $Cont))sshQ_L_121procD___call__;
        sshQ_L_121procG_methods.__exec__ = ($R (*) (sshQ_L_121proc, $Cont))sshQ_L_121procD___exec__;
        sshQ_L_121procG_methods.__serialize__ = sshQ_L_121procD___serialize__;
        sshQ_L_121procG_methods.__deserialize__ = sshQ_L_121procD___deserialize__;
        $register(&sshQ_L_121procG_methods);
    }
    {
        sshQ_L_122procG_methods.$GCINFO = "sshQ_L_122proc";
        sshQ_L_122procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        sshQ_L_122procG_methods.__bool__ = (B_bool (*) (sshQ_L_122proc))B_valueG_methods.__bool__;
        sshQ_L_122procG_methods.__str__ = (B_str (*) (sshQ_L_122proc))B_valueG_methods.__str__;
        sshQ_L_122procG_methods.__repr__ = (B_str (*) (sshQ_L_122proc))B_valueG_methods.__repr__;
        sshQ_L_122procG_methods.__init__ = (B_NoneType (*) (sshQ_L_122proc, sshQ_ServerSession))sshQ_L_122procD___init__;
        sshQ_L_122procG_methods.__call__ = ($R (*) (sshQ_L_122proc, $Cont))sshQ_L_122procD___call__;
        sshQ_L_122procG_methods.__exec__ = ($R (*) (sshQ_L_122proc, $Cont))sshQ_L_122procD___exec__;
        sshQ_L_122procG_methods.__serialize__ = sshQ_L_122procD___serialize__;
        sshQ_L_122procG_methods.__deserialize__ = sshQ_L_122procD___deserialize__;
        $register(&sshQ_L_122procG_methods);
    }
    {
        sshQ_L_123procG_methods.$GCINFO = "sshQ_L_123proc";
        sshQ_L_123procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        sshQ_L_123procG_methods.__bool__ = (B_bool (*) (sshQ_L_123proc))B_valueG_methods.__bool__;
        sshQ_L_123procG_methods.__str__ = (B_str (*) (sshQ_L_123proc))B_valueG_methods.__str__;
        sshQ_L_123procG_methods.__repr__ = (B_str (*) (sshQ_L_123proc))B_valueG_methods.__repr__;
        sshQ_L_123procG_methods.__init__ = (B_NoneType (*) (sshQ_L_123proc, sshQ_ServerSession))sshQ_L_123procD___init__;
        sshQ_L_123procG_methods.__call__ = ($R (*) (sshQ_L_123proc, $Cont))sshQ_L_123procD___call__;
        sshQ_L_123procG_methods.__exec__ = ($R (*) (sshQ_L_123proc, $Cont))sshQ_L_123procD___exec__;
        sshQ_L_123procG_methods.__serialize__ = sshQ_L_123procD___serialize__;
        sshQ_L_123procG_methods.__deserialize__ = sshQ_L_123procD___deserialize__;
        $register(&sshQ_L_123procG_methods);
    }
    {
        sshQ_L_124procG_methods.$GCINFO = "sshQ_L_124proc";
        sshQ_L_124procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        sshQ_L_124procG_methods.__bool__ = (B_bool (*) (sshQ_L_124proc))B_valueG_methods.__bool__;
        sshQ_L_124procG_methods.__str__ = (B_str (*) (sshQ_L_124proc))B_valueG_methods.__str__;
        sshQ_L_124procG_methods.__repr__ = (B_str (*) (sshQ_L_124proc))B_valueG_methods.__repr__;
        sshQ_L_124procG_methods.__init__ = (B_NoneType (*) (sshQ_L_124proc, sshQ_ServerSession, sshQ_ServerChannel))sshQ_L_124procD___init__;
        sshQ_L_124procG_methods.__call__ = ($R (*) (sshQ_L_124proc, $Cont))sshQ_L_124procD___call__;
        sshQ_L_124procG_methods.__exec__ = ($R (*) (sshQ_L_124proc, $Cont))sshQ_L_124procD___exec__;
        sshQ_L_124procG_methods.__serialize__ = sshQ_L_124procD___serialize__;
        sshQ_L_124procG_methods.__deserialize__ = sshQ_L_124procD___deserialize__;
        $register(&sshQ_L_124procG_methods);
    }
    {
        sshQ_L_125procG_methods.$GCINFO = "sshQ_L_125proc";
        sshQ_L_125procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        sshQ_L_125procG_methods.__bool__ = (B_bool (*) (sshQ_L_125proc))B_valueG_methods.__bool__;
        sshQ_L_125procG_methods.__str__ = (B_str (*) (sshQ_L_125proc))B_valueG_methods.__str__;
        sshQ_L_125procG_methods.__repr__ = (B_str (*) (sshQ_L_125proc))B_valueG_methods.__repr__;
        sshQ_L_125procG_methods.__init__ = (B_NoneType (*) (sshQ_L_125proc, sshQ_ServerSession, sshQ_ServerChannel, B_str))sshQ_L_125procD___init__;
        sshQ_L_125procG_methods.__call__ = ($R (*) (sshQ_L_125proc, $Cont))sshQ_L_125procD___call__;
        sshQ_L_125procG_methods.__exec__ = ($R (*) (sshQ_L_125proc, $Cont))sshQ_L_125procD___exec__;
        sshQ_L_125procG_methods.__serialize__ = sshQ_L_125procD___serialize__;
        sshQ_L_125procG_methods.__deserialize__ = sshQ_L_125procD___deserialize__;
        $register(&sshQ_L_125procG_methods);
    }
    {
        sshQ_L_126procG_methods.$GCINFO = "sshQ_L_126proc";
        sshQ_L_126procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        sshQ_L_126procG_methods.__bool__ = (B_bool (*) (sshQ_L_126proc))B_valueG_methods.__bool__;
        sshQ_L_126procG_methods.__str__ = (B_str (*) (sshQ_L_126proc))B_valueG_methods.__str__;
        sshQ_L_126procG_methods.__repr__ = (B_str (*) (sshQ_L_126proc))B_valueG_methods.__repr__;
        sshQ_L_126procG_methods.__init__ = (B_NoneType (*) (sshQ_L_126proc, sshQ_ServerSession, sshQ_ServerChannel, B_bytes))sshQ_L_126procD___init__;
        sshQ_L_126procG_methods.__call__ = ($R (*) (sshQ_L_126proc, $Cont))sshQ_L_126procD___call__;
        sshQ_L_126procG_methods.__exec__ = ($R (*) (sshQ_L_126proc, $Cont))sshQ_L_126procD___exec__;
        sshQ_L_126procG_methods.__serialize__ = sshQ_L_126procD___serialize__;
        sshQ_L_126procG_methods.__deserialize__ = sshQ_L_126procD___deserialize__;
        $register(&sshQ_L_126procG_methods);
    }
    {
        sshQ_L_127procG_methods.$GCINFO = "sshQ_L_127proc";
        sshQ_L_127procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        sshQ_L_127procG_methods.__bool__ = (B_bool (*) (sshQ_L_127proc))B_valueG_methods.__bool__;
        sshQ_L_127procG_methods.__str__ = (B_str (*) (sshQ_L_127proc))B_valueG_methods.__str__;
        sshQ_L_127procG_methods.__repr__ = (B_str (*) (sshQ_L_127proc))B_valueG_methods.__repr__;
        sshQ_L_127procG_methods.__init__ = (B_NoneType (*) (sshQ_L_127proc, sshQ_ServerSession, sshQ_ServerChannel, B_bytes))sshQ_L_127procD___init__;
        sshQ_L_127procG_methods.__call__ = ($R (*) (sshQ_L_127proc, $Cont))sshQ_L_127procD___call__;
        sshQ_L_127procG_methods.__exec__ = ($R (*) (sshQ_L_127proc, $Cont))sshQ_L_127procD___exec__;
        sshQ_L_127procG_methods.__serialize__ = sshQ_L_127procD___serialize__;
        sshQ_L_127procG_methods.__deserialize__ = sshQ_L_127procD___deserialize__;
        $register(&sshQ_L_127procG_methods);
    }
    {
        sshQ_L_128procG_methods.$GCINFO = "sshQ_L_128proc";
        sshQ_L_128procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        sshQ_L_128procG_methods.__bool__ = (B_bool (*) (sshQ_L_128proc))B_valueG_methods.__bool__;
        sshQ_L_128procG_methods.__str__ = (B_str (*) (sshQ_L_128proc))B_valueG_methods.__str__;
        sshQ_L_128procG_methods.__repr__ = (B_str (*) (sshQ_L_128proc))B_valueG_methods.__repr__;
        sshQ_L_128procG_methods.__init__ = (B_NoneType (*) (sshQ_L_128proc, sshQ_ServerSession, sshQ_ServerChannel))sshQ_L_128procD___init__;
        sshQ_L_128procG_methods.__call__ = ($R (*) (sshQ_L_128proc, $Cont))sshQ_L_128procD___call__;
        sshQ_L_128procG_methods.__exec__ = ($R (*) (sshQ_L_128proc, $Cont))sshQ_L_128procD___exec__;
        sshQ_L_128procG_methods.__serialize__ = sshQ_L_128procD___serialize__;
        sshQ_L_128procG_methods.__deserialize__ = sshQ_L_128procD___deserialize__;
        $register(&sshQ_L_128procG_methods);
    }
    {
        sshQ_L_129procG_methods.$GCINFO = "sshQ_L_129proc";
        sshQ_L_129procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        sshQ_L_129procG_methods.__bool__ = (B_bool (*) (sshQ_L_129proc))B_valueG_methods.__bool__;
        sshQ_L_129procG_methods.__str__ = (B_str (*) (sshQ_L_129proc))B_valueG_methods.__str__;
        sshQ_L_129procG_methods.__repr__ = (B_str (*) (sshQ_L_129proc))B_valueG_methods.__repr__;
        sshQ_L_129procG_methods.__init__ = (B_NoneType (*) (sshQ_L_129proc, sshQ_ServerSession, sshQ_ServerChannel, int64_t))sshQ_L_129procD___init__;
        sshQ_L_129procG_methods.__call__ = ($R (*) (sshQ_L_129proc, $Cont))sshQ_L_129procD___call__;
        sshQ_L_129procG_methods.__exec__ = ($R (*) (sshQ_L_129proc, $Cont))sshQ_L_129procD___exec__;
        sshQ_L_129procG_methods.__serialize__ = sshQ_L_129procD___serialize__;
        sshQ_L_129procG_methods.__deserialize__ = sshQ_L_129procD___deserialize__;
        $register(&sshQ_L_129procG_methods);
    }
    {
        sshQ_L_130procG_methods.$GCINFO = "sshQ_L_130proc";
        sshQ_L_130procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        sshQ_L_130procG_methods.__bool__ = (B_bool (*) (sshQ_L_130proc))B_valueG_methods.__bool__;
        sshQ_L_130procG_methods.__str__ = (B_str (*) (sshQ_L_130proc))B_valueG_methods.__str__;
        sshQ_L_130procG_methods.__repr__ = (B_str (*) (sshQ_L_130proc))B_valueG_methods.__repr__;
        sshQ_L_130procG_methods.__init__ = (B_NoneType (*) (sshQ_L_130proc, sshQ_ServerSession, sshQ_ServerChannel))sshQ_L_130procD___init__;
        sshQ_L_130procG_methods.__call__ = ($R (*) (sshQ_L_130proc, $Cont))sshQ_L_130procD___call__;
        sshQ_L_130procG_methods.__exec__ = ($R (*) (sshQ_L_130proc, $Cont))sshQ_L_130procD___exec__;
        sshQ_L_130procG_methods.__serialize__ = sshQ_L_130procD___serialize__;
        sshQ_L_130procG_methods.__deserialize__ = sshQ_L_130procD___deserialize__;
        $register(&sshQ_L_130procG_methods);
    }
    {
        sshQ_L_132ContG_methods.$GCINFO = "sshQ_L_132Cont";
        sshQ_L_132ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        sshQ_L_132ContG_methods.__bool__ = (B_bool (*) (sshQ_L_132Cont))B_valueG_methods.__bool__;
        sshQ_L_132ContG_methods.__str__ = (B_str (*) (sshQ_L_132Cont))B_valueG_methods.__str__;
        sshQ_L_132ContG_methods.__repr__ = (B_str (*) (sshQ_L_132Cont))B_valueG_methods.__repr__;
        sshQ_L_132ContG_methods.__init__ = (B_NoneType (*) (sshQ_L_132Cont, $Cont))sshQ_L_132ContD___init__;
        sshQ_L_132ContG_methods.__call__ = ($R (*) (sshQ_L_132Cont, B_NoneType))sshQ_L_132ContD___call__;
        sshQ_L_132ContG_methods.__serialize__ = sshQ_L_132ContD___serialize__;
        sshQ_L_132ContG_methods.__deserialize__ = sshQ_L_132ContD___deserialize__;
        $register(&sshQ_L_132ContG_methods);
    }
    {
        sshQ_L_133ContG_methods.$GCINFO = "sshQ_L_133Cont";
        sshQ_L_133ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        sshQ_L_133ContG_methods.__bool__ = (B_bool (*) (sshQ_L_133Cont))B_valueG_methods.__bool__;
        sshQ_L_133ContG_methods.__str__ = (B_str (*) (sshQ_L_133Cont))B_valueG_methods.__str__;
        sshQ_L_133ContG_methods.__repr__ = (B_str (*) (sshQ_L_133Cont))B_valueG_methods.__repr__;
        sshQ_L_133ContG_methods.__init__ = (B_NoneType (*) (sshQ_L_133Cont, $Cont))sshQ_L_133ContD___init__;
        sshQ_L_133ContG_methods.__call__ = ($R (*) (sshQ_L_133Cont, B_NoneType))sshQ_L_133ContD___call__;
        sshQ_L_133ContG_methods.__serialize__ = sshQ_L_133ContD___serialize__;
        sshQ_L_133ContG_methods.__deserialize__ = sshQ_L_133ContD___deserialize__;
        $register(&sshQ_L_133ContG_methods);
    }
    {
        sshQ_L_134procG_methods.$GCINFO = "sshQ_L_134proc";
        sshQ_L_134procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        sshQ_L_134procG_methods.__bool__ = (B_bool (*) (sshQ_L_134proc))B_valueG_methods.__bool__;
        sshQ_L_134procG_methods.__str__ = (B_str (*) (sshQ_L_134proc))B_valueG_methods.__str__;
        sshQ_L_134procG_methods.__repr__ = (B_str (*) (sshQ_L_134proc))B_valueG_methods.__repr__;
        sshQ_L_134procG_methods.__init__ = (B_NoneType (*) (sshQ_L_134proc, sshQ_ServerChannel))sshQ_L_134procD___init__;
        sshQ_L_134procG_methods.__call__ = ($R (*) (sshQ_L_134proc, $Cont))sshQ_L_134procD___call__;
        sshQ_L_134procG_methods.__exec__ = ($R (*) (sshQ_L_134proc, $Cont))sshQ_L_134procD___exec__;
        sshQ_L_134procG_methods.__serialize__ = sshQ_L_134procD___serialize__;
        sshQ_L_134procG_methods.__deserialize__ = sshQ_L_134procD___deserialize__;
        $register(&sshQ_L_134procG_methods);
    }
    {
        sshQ_L_135procG_methods.$GCINFO = "sshQ_L_135proc";
        sshQ_L_135procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        sshQ_L_135procG_methods.__bool__ = (B_bool (*) (sshQ_L_135proc))B_valueG_methods.__bool__;
        sshQ_L_135procG_methods.__str__ = (B_str (*) (sshQ_L_135proc))B_valueG_methods.__str__;
        sshQ_L_135procG_methods.__repr__ = (B_str (*) (sshQ_L_135proc))B_valueG_methods.__repr__;
        sshQ_L_135procG_methods.__init__ = (B_NoneType (*) (sshQ_L_135proc, sshQ_ServerChannel))sshQ_L_135procD___init__;
        sshQ_L_135procG_methods.__call__ = ($R (*) (sshQ_L_135proc, $Cont))sshQ_L_135procD___call__;
        sshQ_L_135procG_methods.__exec__ = ($R (*) (sshQ_L_135proc, $Cont))sshQ_L_135procD___exec__;
        sshQ_L_135procG_methods.__serialize__ = sshQ_L_135procD___serialize__;
        sshQ_L_135procG_methods.__deserialize__ = sshQ_L_135procD___deserialize__;
        $register(&sshQ_L_135procG_methods);
    }
    {
        sshQ_L_136procG_methods.$GCINFO = "sshQ_L_136proc";
        sshQ_L_136procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        sshQ_L_136procG_methods.__bool__ = (B_bool (*) (sshQ_L_136proc))B_valueG_methods.__bool__;
        sshQ_L_136procG_methods.__str__ = (B_str (*) (sshQ_L_136proc))B_valueG_methods.__str__;
        sshQ_L_136procG_methods.__repr__ = (B_str (*) (sshQ_L_136proc))B_valueG_methods.__repr__;
        sshQ_L_136procG_methods.__init__ = (B_NoneType (*) (sshQ_L_136proc, sshQ_ServerChannel, B_str))sshQ_L_136procD___init__;
        sshQ_L_136procG_methods.__call__ = ($R (*) (sshQ_L_136proc, $Cont))sshQ_L_136procD___call__;
        sshQ_L_136procG_methods.__exec__ = ($R (*) (sshQ_L_136proc, $Cont))sshQ_L_136procD___exec__;
        sshQ_L_136procG_methods.__serialize__ = sshQ_L_136procD___serialize__;
        sshQ_L_136procG_methods.__deserialize__ = sshQ_L_136procD___deserialize__;
        $register(&sshQ_L_136procG_methods);
    }
    {
        sshQ_L_137procG_methods.$GCINFO = "sshQ_L_137proc";
        sshQ_L_137procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        sshQ_L_137procG_methods.__bool__ = (B_bool (*) (sshQ_L_137proc))B_valueG_methods.__bool__;
        sshQ_L_137procG_methods.__str__ = (B_str (*) (sshQ_L_137proc))B_valueG_methods.__str__;
        sshQ_L_137procG_methods.__repr__ = (B_str (*) (sshQ_L_137proc))B_valueG_methods.__repr__;
        sshQ_L_137procG_methods.__init__ = (B_NoneType (*) (sshQ_L_137proc, sshQ_ServerChannel, B_bytes))sshQ_L_137procD___init__;
        sshQ_L_137procG_methods.__call__ = ($R (*) (sshQ_L_137proc, $Cont))sshQ_L_137procD___call__;
        sshQ_L_137procG_methods.__exec__ = ($R (*) (sshQ_L_137proc, $Cont))sshQ_L_137procD___exec__;
        sshQ_L_137procG_methods.__serialize__ = sshQ_L_137procD___serialize__;
        sshQ_L_137procG_methods.__deserialize__ = sshQ_L_137procD___deserialize__;
        $register(&sshQ_L_137procG_methods);
    }
    {
        sshQ_L_138procG_methods.$GCINFO = "sshQ_L_138proc";
        sshQ_L_138procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        sshQ_L_138procG_methods.__bool__ = (B_bool (*) (sshQ_L_138proc))B_valueG_methods.__bool__;
        sshQ_L_138procG_methods.__str__ = (B_str (*) (sshQ_L_138proc))B_valueG_methods.__str__;
        sshQ_L_138procG_methods.__repr__ = (B_str (*) (sshQ_L_138proc))B_valueG_methods.__repr__;
        sshQ_L_138procG_methods.__init__ = (B_NoneType (*) (sshQ_L_138proc, sshQ_ServerChannel, B_bytes))sshQ_L_138procD___init__;
        sshQ_L_138procG_methods.__call__ = ($R (*) (sshQ_L_138proc, $Cont))sshQ_L_138procD___call__;
        sshQ_L_138procG_methods.__exec__ = ($R (*) (sshQ_L_138proc, $Cont))sshQ_L_138procD___exec__;
        sshQ_L_138procG_methods.__serialize__ = sshQ_L_138procD___serialize__;
        sshQ_L_138procG_methods.__deserialize__ = sshQ_L_138procD___deserialize__;
        $register(&sshQ_L_138procG_methods);
    }
    {
        sshQ_L_139procG_methods.$GCINFO = "sshQ_L_139proc";
        sshQ_L_139procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        sshQ_L_139procG_methods.__bool__ = (B_bool (*) (sshQ_L_139proc))B_valueG_methods.__bool__;
        sshQ_L_139procG_methods.__str__ = (B_str (*) (sshQ_L_139proc))B_valueG_methods.__str__;
        sshQ_L_139procG_methods.__repr__ = (B_str (*) (sshQ_L_139proc))B_valueG_methods.__repr__;
        sshQ_L_139procG_methods.__init__ = (B_NoneType (*) (sshQ_L_139proc, sshQ_ServerChannel))sshQ_L_139procD___init__;
        sshQ_L_139procG_methods.__call__ = ($R (*) (sshQ_L_139proc, $Cont))sshQ_L_139procD___call__;
        sshQ_L_139procG_methods.__exec__ = ($R (*) (sshQ_L_139proc, $Cont))sshQ_L_139procD___exec__;
        sshQ_L_139procG_methods.__serialize__ = sshQ_L_139procD___serialize__;
        sshQ_L_139procG_methods.__deserialize__ = sshQ_L_139procD___deserialize__;
        $register(&sshQ_L_139procG_methods);
    }
    {
        sshQ_L_140procG_methods.$GCINFO = "sshQ_L_140proc";
        sshQ_L_140procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        sshQ_L_140procG_methods.__bool__ = (B_bool (*) (sshQ_L_140proc))B_valueG_methods.__bool__;
        sshQ_L_140procG_methods.__str__ = (B_str (*) (sshQ_L_140proc))B_valueG_methods.__str__;
        sshQ_L_140procG_methods.__repr__ = (B_str (*) (sshQ_L_140proc))B_valueG_methods.__repr__;
        sshQ_L_140procG_methods.__init__ = (B_NoneType (*) (sshQ_L_140proc, sshQ_ServerChannel, int64_t))sshQ_L_140procD___init__;
        sshQ_L_140procG_methods.__call__ = ($R (*) (sshQ_L_140proc, $Cont))sshQ_L_140procD___call__;
        sshQ_L_140procG_methods.__exec__ = ($R (*) (sshQ_L_140proc, $Cont))sshQ_L_140procD___exec__;
        sshQ_L_140procG_methods.__serialize__ = sshQ_L_140procD___serialize__;
        sshQ_L_140procG_methods.__deserialize__ = sshQ_L_140procD___deserialize__;
        $register(&sshQ_L_140procG_methods);
    }
    {
        sshQ_L_141procG_methods.$GCINFO = "sshQ_L_141proc";
        sshQ_L_141procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        sshQ_L_141procG_methods.__bool__ = (B_bool (*) (sshQ_L_141proc))B_valueG_methods.__bool__;
        sshQ_L_141procG_methods.__str__ = (B_str (*) (sshQ_L_141proc))B_valueG_methods.__str__;
        sshQ_L_141procG_methods.__repr__ = (B_str (*) (sshQ_L_141proc))B_valueG_methods.__repr__;
        sshQ_L_141procG_methods.__init__ = (B_NoneType (*) (sshQ_L_141proc, sshQ_ServerChannel))sshQ_L_141procD___init__;
        sshQ_L_141procG_methods.__call__ = ($R (*) (sshQ_L_141proc, $Cont))sshQ_L_141procD___call__;
        sshQ_L_141procG_methods.__exec__ = ($R (*) (sshQ_L_141proc, $Cont))sshQ_L_141procD___exec__;
        sshQ_L_141procG_methods.__serialize__ = sshQ_L_141procD___serialize__;
        sshQ_L_141procG_methods.__deserialize__ = sshQ_L_141procD___deserialize__;
        $register(&sshQ_L_141procG_methods);
    }
    {
        sshQ_L_142procG_methods.$GCINFO = "sshQ_L_142proc";
        sshQ_L_142procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        sshQ_L_142procG_methods.__bool__ = (B_bool (*) (sshQ_L_142proc))B_valueG_methods.__bool__;
        sshQ_L_142procG_methods.__str__ = (B_str (*) (sshQ_L_142proc))B_valueG_methods.__str__;
        sshQ_L_142procG_methods.__repr__ = (B_str (*) (sshQ_L_142proc))B_valueG_methods.__repr__;
        sshQ_L_142procG_methods.__init__ = (B_NoneType (*) (sshQ_L_142proc, sshQ_ServerChannel))sshQ_L_142procD___init__;
        sshQ_L_142procG_methods.__call__ = ($R (*) (sshQ_L_142proc, $Cont))sshQ_L_142procD___call__;
        sshQ_L_142procG_methods.__exec__ = ($R (*) (sshQ_L_142proc, $Cont))sshQ_L_142procD___exec__;
        sshQ_L_142procG_methods.__serialize__ = sshQ_L_142procD___serialize__;
        sshQ_L_142procG_methods.__deserialize__ = sshQ_L_142procD___deserialize__;
        $register(&sshQ_L_142procG_methods);
    }
    {
        sshQ_L_143procG_methods.$GCINFO = "sshQ_L_143proc";
        sshQ_L_143procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        sshQ_L_143procG_methods.__bool__ = (B_bool (*) (sshQ_L_143proc))B_valueG_methods.__bool__;
        sshQ_L_143procG_methods.__str__ = (B_str (*) (sshQ_L_143proc))B_valueG_methods.__str__;
        sshQ_L_143procG_methods.__repr__ = (B_str (*) (sshQ_L_143proc))B_valueG_methods.__repr__;
        sshQ_L_143procG_methods.__init__ = (B_NoneType (*) (sshQ_L_143proc, sshQ_ServerChannel))sshQ_L_143procD___init__;
        sshQ_L_143procG_methods.__call__ = ($R (*) (sshQ_L_143proc, $Cont))sshQ_L_143procD___call__;
        sshQ_L_143procG_methods.__exec__ = ($R (*) (sshQ_L_143proc, $Cont))sshQ_L_143procD___exec__;
        sshQ_L_143procG_methods.__serialize__ = sshQ_L_143procD___serialize__;
        sshQ_L_143procG_methods.__deserialize__ = sshQ_L_143procD___deserialize__;
        $register(&sshQ_L_143procG_methods);
    }
    {
        sshQ_L_145ContG_methods.$GCINFO = "sshQ_L_145Cont";
        sshQ_L_145ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        sshQ_L_145ContG_methods.__bool__ = (B_bool (*) (sshQ_L_145Cont))B_valueG_methods.__bool__;
        sshQ_L_145ContG_methods.__str__ = (B_str (*) (sshQ_L_145Cont))B_valueG_methods.__str__;
        sshQ_L_145ContG_methods.__repr__ = (B_str (*) (sshQ_L_145Cont))B_valueG_methods.__repr__;
        sshQ_L_145ContG_methods.__init__ = (B_NoneType (*) (sshQ_L_145Cont, $Cont, sshQ_Client))sshQ_L_145ContD___init__;
        sshQ_L_145ContG_methods.__call__ = ($R (*) (sshQ_L_145Cont, B_NoneType))sshQ_L_145ContD___call__;
        sshQ_L_145ContG_methods.__serialize__ = sshQ_L_145ContD___serialize__;
        sshQ_L_145ContG_methods.__deserialize__ = sshQ_L_145ContD___deserialize__;
        $register(&sshQ_L_145ContG_methods);
    }
    {
        sshQ_L_146procG_methods.$GCINFO = "sshQ_L_146proc";
        sshQ_L_146procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        sshQ_L_146procG_methods.__bool__ = (B_bool (*) (sshQ_L_146proc))B_valueG_methods.__bool__;
        sshQ_L_146procG_methods.__str__ = (B_str (*) (sshQ_L_146proc))B_valueG_methods.__str__;
        sshQ_L_146procG_methods.__repr__ = (B_str (*) (sshQ_L_146proc))B_valueG_methods.__repr__;
        sshQ_L_146procG_methods.__init__ = (B_NoneType (*) (sshQ_L_146proc, sshQ_Client, netQ_TCPConnectCap, B_str, B_str, $action, $action, $action, B_str, B_str, B_str, B_u16, B_str, B_float, B_float, B_float, B_bool, B_float, B_int))sshQ_L_146procD___init__;
        sshQ_L_146procG_methods.__call__ = ($R (*) (sshQ_L_146proc, $Cont))sshQ_L_146procD___call__;
        sshQ_L_146procG_methods.__exec__ = ($R (*) (sshQ_L_146proc, $Cont))sshQ_L_146procD___exec__;
        sshQ_L_146procG_methods.__serialize__ = sshQ_L_146procD___serialize__;
        sshQ_L_146procG_methods.__deserialize__ = sshQ_L_146procD___deserialize__;
        $register(&sshQ_L_146procG_methods);
    }
    {
        sshQ_L_148ContG_methods.$GCINFO = "sshQ_L_148Cont";
        sshQ_L_148ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        sshQ_L_148ContG_methods.__bool__ = (B_bool (*) (sshQ_L_148Cont))B_valueG_methods.__bool__;
        sshQ_L_148ContG_methods.__str__ = (B_str (*) (sshQ_L_148Cont))B_valueG_methods.__str__;
        sshQ_L_148ContG_methods.__repr__ = (B_str (*) (sshQ_L_148Cont))B_valueG_methods.__repr__;
        sshQ_L_148ContG_methods.__init__ = (B_NoneType (*) (sshQ_L_148Cont, $Cont, sshQ_Channel))sshQ_L_148ContD___init__;
        sshQ_L_148ContG_methods.__call__ = ($R (*) (sshQ_L_148Cont, B_NoneType))sshQ_L_148ContD___call__;
        sshQ_L_148ContG_methods.__serialize__ = sshQ_L_148ContD___serialize__;
        sshQ_L_148ContG_methods.__deserialize__ = sshQ_L_148ContD___deserialize__;
        $register(&sshQ_L_148ContG_methods);
    }
    {
        sshQ_L_149procG_methods.$GCINFO = "sshQ_L_149proc";
        sshQ_L_149procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        sshQ_L_149procG_methods.__bool__ = (B_bool (*) (sshQ_L_149proc))B_valueG_methods.__bool__;
        sshQ_L_149procG_methods.__str__ = (B_str (*) (sshQ_L_149proc))B_valueG_methods.__str__;
        sshQ_L_149procG_methods.__repr__ = (B_str (*) (sshQ_L_149proc))B_valueG_methods.__repr__;
        sshQ_L_149procG_methods.__init__ = (B_NoneType (*) (sshQ_L_149proc, sshQ_Channel, sshQ_Client, $action, $action, $action, $action, $action))sshQ_L_149procD___init__;
        sshQ_L_149procG_methods.__call__ = ($R (*) (sshQ_L_149proc, $Cont))sshQ_L_149procD___call__;
        sshQ_L_149procG_methods.__exec__ = ($R (*) (sshQ_L_149proc, $Cont))sshQ_L_149procD___exec__;
        sshQ_L_149procG_methods.__serialize__ = sshQ_L_149procD___serialize__;
        sshQ_L_149procG_methods.__deserialize__ = sshQ_L_149procD___deserialize__;
        $register(&sshQ_L_149procG_methods);
    }
    {
        sshQ_L_151ContG_methods.$GCINFO = "sshQ_L_151Cont";
        sshQ_L_151ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        sshQ_L_151ContG_methods.__bool__ = (B_bool (*) (sshQ_L_151Cont))B_valueG_methods.__bool__;
        sshQ_L_151ContG_methods.__str__ = (B_str (*) (sshQ_L_151Cont))B_valueG_methods.__str__;
        sshQ_L_151ContG_methods.__repr__ = (B_str (*) (sshQ_L_151Cont))B_valueG_methods.__repr__;
        sshQ_L_151ContG_methods.__init__ = (B_NoneType (*) (sshQ_L_151Cont, $Cont, sshQ_RunCommand))sshQ_L_151ContD___init__;
        sshQ_L_151ContG_methods.__call__ = ($R (*) (sshQ_L_151Cont, B_NoneType))sshQ_L_151ContD___call__;
        sshQ_L_151ContG_methods.__serialize__ = sshQ_L_151ContD___serialize__;
        sshQ_L_151ContG_methods.__deserialize__ = sshQ_L_151ContD___deserialize__;
        $register(&sshQ_L_151ContG_methods);
    }
    {
        sshQ_L_152procG_methods.$GCINFO = "sshQ_L_152proc";
        sshQ_L_152procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        sshQ_L_152procG_methods.__bool__ = (B_bool (*) (sshQ_L_152proc))B_valueG_methods.__bool__;
        sshQ_L_152procG_methods.__str__ = (B_str (*) (sshQ_L_152proc))B_valueG_methods.__str__;
        sshQ_L_152procG_methods.__repr__ = (B_str (*) (sshQ_L_152proc))B_valueG_methods.__repr__;
        sshQ_L_152procG_methods.__init__ = (B_NoneType (*) (sshQ_L_152proc, sshQ_RunCommand, sshQ_Client, B_str, $action, B_float))sshQ_L_152procD___init__;
        sshQ_L_152procG_methods.__call__ = ($R (*) (sshQ_L_152proc, $Cont))sshQ_L_152procD___call__;
        sshQ_L_152procG_methods.__exec__ = ($R (*) (sshQ_L_152proc, $Cont))sshQ_L_152procD___exec__;
        sshQ_L_152procG_methods.__serialize__ = sshQ_L_152procD___serialize__;
        sshQ_L_152procG_methods.__deserialize__ = sshQ_L_152procD___deserialize__;
        $register(&sshQ_L_152procG_methods);
    }
    {
        sshQ_L_154ContG_methods.$GCINFO = "sshQ_L_154Cont";
        sshQ_L_154ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        sshQ_L_154ContG_methods.__bool__ = (B_bool (*) (sshQ_L_154Cont))B_valueG_methods.__bool__;
        sshQ_L_154ContG_methods.__str__ = (B_str (*) (sshQ_L_154Cont))B_valueG_methods.__str__;
        sshQ_L_154ContG_methods.__repr__ = (B_str (*) (sshQ_L_154Cont))B_valueG_methods.__repr__;
        sshQ_L_154ContG_methods.__init__ = (B_NoneType (*) (sshQ_L_154Cont, $Cont, sshQ_Server))sshQ_L_154ContD___init__;
        sshQ_L_154ContG_methods.__call__ = ($R (*) (sshQ_L_154Cont, B_NoneType))sshQ_L_154ContD___call__;
        sshQ_L_154ContG_methods.__serialize__ = sshQ_L_154ContD___serialize__;
        sshQ_L_154ContG_methods.__deserialize__ = sshQ_L_154ContD___deserialize__;
        $register(&sshQ_L_154ContG_methods);
    }
    {
        sshQ_L_155procG_methods.$GCINFO = "sshQ_L_155proc";
        sshQ_L_155procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        sshQ_L_155procG_methods.__bool__ = (B_bool (*) (sshQ_L_155proc))B_valueG_methods.__bool__;
        sshQ_L_155procG_methods.__str__ = (B_str (*) (sshQ_L_155proc))B_valueG_methods.__str__;
        sshQ_L_155procG_methods.__repr__ = (B_str (*) (sshQ_L_155proc))B_valueG_methods.__repr__;
        sshQ_L_155procG_methods.__init__ = (B_NoneType (*) (sshQ_L_155proc, sshQ_Server, netQ_TCPListenCap, B_str, uint16_t, $action, $action, $action, $action, $action, $action, $action, $action, B_str, B_str, B_int, B_float, B_float, B_bool, B_float, B_int, B_int, B_int))sshQ_L_155procD___init__;
        sshQ_L_155procG_methods.__call__ = ($R (*) (sshQ_L_155proc, $Cont))sshQ_L_155procD___call__;
        sshQ_L_155procG_methods.__exec__ = ($R (*) (sshQ_L_155proc, $Cont))sshQ_L_155procD___exec__;
        sshQ_L_155procG_methods.__serialize__ = sshQ_L_155procD___serialize__;
        sshQ_L_155procG_methods.__deserialize__ = sshQ_L_155procD___deserialize__;
        $register(&sshQ_L_155procG_methods);
    }
    {
        sshQ_L_157ContG_methods.$GCINFO = "sshQ_L_157Cont";
        sshQ_L_157ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        sshQ_L_157ContG_methods.__bool__ = (B_bool (*) (sshQ_L_157Cont))B_valueG_methods.__bool__;
        sshQ_L_157ContG_methods.__str__ = (B_str (*) (sshQ_L_157Cont))B_valueG_methods.__str__;
        sshQ_L_157ContG_methods.__repr__ = (B_str (*) (sshQ_L_157Cont))B_valueG_methods.__repr__;
        sshQ_L_157ContG_methods.__init__ = (B_NoneType (*) (sshQ_L_157Cont, $Cont, sshQ_ServerSession))sshQ_L_157ContD___init__;
        sshQ_L_157ContG_methods.__call__ = ($R (*) (sshQ_L_157Cont, B_NoneType))sshQ_L_157ContD___call__;
        sshQ_L_157ContG_methods.__serialize__ = sshQ_L_157ContD___serialize__;
        sshQ_L_157ContG_methods.__deserialize__ = sshQ_L_157ContD___deserialize__;
        $register(&sshQ_L_157ContG_methods);
    }
    {
        sshQ_L_158procG_methods.$GCINFO = "sshQ_L_158proc";
        sshQ_L_158procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        sshQ_L_158procG_methods.__bool__ = (B_bool (*) (sshQ_L_158proc))B_valueG_methods.__bool__;
        sshQ_L_158procG_methods.__str__ = (B_str (*) (sshQ_L_158proc))B_valueG_methods.__str__;
        sshQ_L_158procG_methods.__repr__ = (B_str (*) (sshQ_L_158proc))B_valueG_methods.__repr__;
        sshQ_L_158procG_methods.__init__ = (B_NoneType (*) (sshQ_L_158proc, sshQ_ServerSession, sshQ_Server, uint64_t, $action, $action, $action, $action, $action))sshQ_L_158procD___init__;
        sshQ_L_158procG_methods.__call__ = ($R (*) (sshQ_L_158proc, $Cont))sshQ_L_158procD___call__;
        sshQ_L_158procG_methods.__exec__ = ($R (*) (sshQ_L_158proc, $Cont))sshQ_L_158procD___exec__;
        sshQ_L_158procG_methods.__serialize__ = sshQ_L_158procD___serialize__;
        sshQ_L_158procG_methods.__deserialize__ = sshQ_L_158procD___deserialize__;
        $register(&sshQ_L_158procG_methods);
    }
    {
        sshQ_L_160ContG_methods.$GCINFO = "sshQ_L_160Cont";
        sshQ_L_160ContG_methods.$superclass = ($SuperG_class)&$ContG_methods;
        sshQ_L_160ContG_methods.__bool__ = (B_bool (*) (sshQ_L_160Cont))B_valueG_methods.__bool__;
        sshQ_L_160ContG_methods.__str__ = (B_str (*) (sshQ_L_160Cont))B_valueG_methods.__str__;
        sshQ_L_160ContG_methods.__repr__ = (B_str (*) (sshQ_L_160Cont))B_valueG_methods.__repr__;
        sshQ_L_160ContG_methods.__init__ = (B_NoneType (*) (sshQ_L_160Cont, $Cont, sshQ_ServerChannel))sshQ_L_160ContD___init__;
        sshQ_L_160ContG_methods.__call__ = ($R (*) (sshQ_L_160Cont, B_NoneType))sshQ_L_160ContD___call__;
        sshQ_L_160ContG_methods.__serialize__ = sshQ_L_160ContD___serialize__;
        sshQ_L_160ContG_methods.__deserialize__ = sshQ_L_160ContD___deserialize__;
        $register(&sshQ_L_160ContG_methods);
    }
    {
        sshQ_L_161procG_methods.$GCINFO = "sshQ_L_161proc";
        sshQ_L_161procG_methods.$superclass = ($SuperG_class)&$procG_methods;
        sshQ_L_161procG_methods.__bool__ = (B_bool (*) (sshQ_L_161proc))B_valueG_methods.__bool__;
        sshQ_L_161procG_methods.__str__ = (B_str (*) (sshQ_L_161proc))B_valueG_methods.__str__;
        sshQ_L_161procG_methods.__repr__ = (B_str (*) (sshQ_L_161proc))B_valueG_methods.__repr__;
        sshQ_L_161procG_methods.__init__ = (B_NoneType (*) (sshQ_L_161proc, sshQ_ServerChannel, sshQ_ServerSession, $action, $action, $action))sshQ_L_161procD___init__;
        sshQ_L_161procG_methods.__call__ = ($R (*) (sshQ_L_161proc, $Cont))sshQ_L_161procD___call__;
        sshQ_L_161procG_methods.__exec__ = ($R (*) (sshQ_L_161proc, $Cont))sshQ_L_161procD___exec__;
        sshQ_L_161procG_methods.__serialize__ = sshQ_L_161procD___serialize__;
        sshQ_L_161procG_methods.__deserialize__ = sshQ_L_161procD___deserialize__;
        $register(&sshQ_L_161procG_methods);
    }
    {
        sshQ_HostKeyInfoG_methods.$GCINFO = "sshQ_HostKeyInfo";
        sshQ_HostKeyInfoG_methods.$superclass = ($SuperG_class)&B_valueG_methods;
        sshQ_HostKeyInfoG_methods.__bool__ = (B_bool (*) (sshQ_HostKeyInfo))B_valueG_methods.__bool__;
        sshQ_HostKeyInfoG_methods.__str__ = (B_str (*) (sshQ_HostKeyInfo))B_valueG_methods.__str__;
        sshQ_HostKeyInfoG_methods.__repr__ = (B_str (*) (sshQ_HostKeyInfo))B_valueG_methods.__repr__;
        sshQ_HostKeyInfoG_methods.G_init = (B_NoneType (*) (sshQ_HostKeyInfo))sshQ_HostKeyInfoG_init;
        sshQ_HostKeyInfoG_methods.__init__ = (B_NoneType (*) (sshQ_HostKeyInfo, B_str, B_str))sshQ_HostKeyInfoD___init__;
        sshQ_HostKeyInfoG_methods.__serialize__ = sshQ_HostKeyInfoD___serialize__;
        sshQ_HostKeyInfoG_methods.__deserialize__ = sshQ_HostKeyInfoD___deserialize__;
        $register(&sshQ_HostKeyInfoG_methods);
    }
    {
        sshQ_AuthRequestG_methods.$GCINFO = "sshQ_AuthRequest";
        sshQ_AuthRequestG_methods.$superclass = ($SuperG_class)&B_valueG_methods;
        sshQ_AuthRequestG_methods.__bool__ = (B_bool (*) (sshQ_AuthRequest))B_valueG_methods.__bool__;
        sshQ_AuthRequestG_methods.__str__ = (B_str (*) (sshQ_AuthRequest))B_valueG_methods.__str__;
        sshQ_AuthRequestG_methods.__repr__ = (B_str (*) (sshQ_AuthRequest))B_valueG_methods.__repr__;
        sshQ_AuthRequestG_methods.G_init = (B_NoneType (*) (sshQ_AuthRequest))sshQ_AuthRequestG_init;
        sshQ_AuthRequestG_methods.__init__ = (B_NoneType (*) (sshQ_AuthRequest, B_str, B_str, B_str, B_bytes))sshQ_AuthRequestD___init__;
        sshQ_AuthRequestG_methods.__serialize__ = sshQ_AuthRequestD___serialize__;
        sshQ_AuthRequestG_methods.__deserialize__ = sshQ_AuthRequestD___deserialize__;
        $register(&sshQ_AuthRequestG_methods);
    }
    {
        sshQ_ClientG_methods.$GCINFO = "sshQ_Client";
        sshQ_ClientG_methods.$superclass = ($SuperG_class)&$ActorG_methods;
        sshQ_ClientG_methods.__bool__ = (B_bool (*) (sshQ_Client))$ActorG_methods.__bool__;
        sshQ_ClientG_methods.__str__ = (B_str (*) (sshQ_Client))$ActorG_methods.__str__;
        sshQ_ClientG_methods.__repr__ = (B_str (*) (sshQ_Client))$ActorG_methods.__repr__;
        sshQ_ClientG_methods.__resume__ = (B_NoneType (*) (sshQ_Client))$ActorG_methods.__resume__;
        sshQ_ClientG_methods.__init__ = ($R (*) (sshQ_Client, $Cont, netQ_TCPConnectCap, B_str, B_str, $action, $action, $action, B_str, B_str, B_str, B_u16, B_str, B_float, B_float, B_float, B_bool, B_float, B_int))sshQ_ClientD___init__;
        sshQ_ClientG_methods._pin_affinityG_local = ($R (*) (sshQ_Client, $Cont))sshQ_ClientD__pin_affinityG_local;
        sshQ_ClientG_methods._initG_local = ($R (*) (sshQ_Client, $Cont))sshQ_ClientD__initG_local;
        sshQ_ClientG_methods.accept_hostkeyG_local = ($R (*) (sshQ_Client, $Cont))sshQ_ClientD_accept_hostkeyG_local;
        sshQ_ClientG_methods.reject_hostkeyG_local = ($R (*) (sshQ_Client, $Cont, B_str))sshQ_ClientD_reject_hostkeyG_local;
        sshQ_ClientG_methods.closeG_local = ($R (*) (sshQ_Client, $Cont))sshQ_ClientD_closeG_local;
        sshQ_ClientG_methods._cleanup_nativeG_local = ($R (*) (sshQ_Client, $Cont))sshQ_ClientD__cleanup_nativeG_local;
        sshQ_ClientG_methods.__cleanup__G_local = ($R (*) (sshQ_Client, $Cont))sshQ_ClientD___cleanup__G_local;
        sshQ_ClientG_methods.channel_createG_local = ($R (*) (sshQ_Client, $Cont, sshQ_Channel, $action, $action, $action, $action, $action))sshQ_ClientD_channel_createG_local;
        sshQ_ClientG_methods.channel_request_execG_local = ($R (*) (sshQ_Client, $Cont, sshQ_Channel, B_str))sshQ_ClientD_channel_request_execG_local;
        sshQ_ClientG_methods.channel_request_shellG_local = ($R (*) (sshQ_Client, $Cont, sshQ_Channel, B_str, int64_t, int64_t, int64_t, int64_t, B_bool))sshQ_ClientD_channel_request_shellG_local;
        sshQ_ClientG_methods.channel_request_subsystemG_local = ($R (*) (sshQ_Client, $Cont, sshQ_Channel, B_str))sshQ_ClientD_channel_request_subsystemG_local;
        sshQ_ClientG_methods.channel_writeG_local = ($R (*) (sshQ_Client, $Cont, sshQ_Channel, B_bytes))sshQ_ClientD_channel_writeG_local;
        sshQ_ClientG_methods.channel_send_eofG_local = ($R (*) (sshQ_Client, $Cont, sshQ_Channel))sshQ_ClientD_channel_send_eofG_local;
        sshQ_ClientG_methods.channel_closeG_local = ($R (*) (sshQ_Client, $Cont, sshQ_Channel))sshQ_ClientD_channel_closeG_local;
        sshQ_ClientG_methods._pin_affinity = (B_Msg (*) (sshQ_Client))sshQ_ClientD__pin_affinity;
        sshQ_ClientG_methods._init = (B_Msg (*) (sshQ_Client))sshQ_ClientD__init;
        sshQ_ClientG_methods.accept_hostkey = (B_Msg (*) (sshQ_Client))sshQ_ClientD_accept_hostkey;
        sshQ_ClientG_methods.reject_hostkey = (B_Msg (*) (sshQ_Client, B_str))sshQ_ClientD_reject_hostkey;
        sshQ_ClientG_methods.close = (B_Msg (*) (sshQ_Client))sshQ_ClientD_close;
        sshQ_ClientG_methods._cleanup_native = (B_Msg (*) (sshQ_Client))sshQ_ClientD__cleanup_native;
        sshQ_ClientG_methods.__cleanup__ = (B_Msg (*) (sshQ_Client))sshQ_ClientD___cleanup__;
        sshQ_ClientG_methods.channel_create = (B_Msg (*) (sshQ_Client, sshQ_Channel, $action, $action, $action, $action, $action))sshQ_ClientD_channel_create;
        sshQ_ClientG_methods.channel_request_exec = (B_Msg (*) (sshQ_Client, sshQ_Channel, B_str))sshQ_ClientD_channel_request_exec;
        sshQ_ClientG_methods.channel_request_shell = (B_Msg (*) (sshQ_Client, sshQ_Channel, B_str, int64_t, int64_t, int64_t, int64_t, B_bool))sshQ_ClientD_channel_request_shell;
        sshQ_ClientG_methods.channel_request_subsystem = (B_Msg (*) (sshQ_Client, sshQ_Channel, B_str))sshQ_ClientD_channel_request_subsystem;
        sshQ_ClientG_methods.channel_write = (B_Msg (*) (sshQ_Client, sshQ_Channel, B_bytes))sshQ_ClientD_channel_write;
        sshQ_ClientG_methods.channel_send_eof = (B_Msg (*) (sshQ_Client, sshQ_Channel))sshQ_ClientD_channel_send_eof;
        sshQ_ClientG_methods.channel_close = (B_Msg (*) (sshQ_Client, sshQ_Channel))sshQ_ClientD_channel_close;
        sshQ_ClientG_methods.__serialize__ = sshQ_ClientD___serialize__;
        sshQ_ClientG_methods.__deserialize__ = sshQ_ClientD___deserialize__;
        $register(&sshQ_ClientG_methods);
    }
    {
        sshQ_ChannelG_methods.$GCINFO = "sshQ_Channel";
        sshQ_ChannelG_methods.$superclass = ($SuperG_class)&$ActorG_methods;
        sshQ_ChannelG_methods.__bool__ = (B_bool (*) (sshQ_Channel))$ActorG_methods.__bool__;
        sshQ_ChannelG_methods.__str__ = (B_str (*) (sshQ_Channel))$ActorG_methods.__str__;
        sshQ_ChannelG_methods.__repr__ = (B_str (*) (sshQ_Channel))$ActorG_methods.__repr__;
        sshQ_ChannelG_methods.__resume__ = (B_NoneType (*) (sshQ_Channel))$ActorG_methods.__resume__;
        sshQ_ChannelG_methods.__init__ = ($R (*) (sshQ_Channel, $Cont, sshQ_Client, $action, $action, $action, $action, $action))sshQ_ChannelD___init__;
        sshQ_ChannelG_methods._initG_local = ($R (*) (sshQ_Channel, $Cont))sshQ_ChannelD__initG_local;
        sshQ_ChannelG_methods.request_execG_local = ($R (*) (sshQ_Channel, $Cont, B_str))sshQ_ChannelD_request_execG_local;
        sshQ_ChannelG_methods.request_shellG_local = ($R (*) (sshQ_Channel, $Cont, B_str, B_int, B_int, B_int, B_int, B_bool))sshQ_ChannelD_request_shellG_local;
        sshQ_ChannelG_methods.request_subsystemG_local = ($R (*) (sshQ_Channel, $Cont, B_str))sshQ_ChannelD_request_subsystemG_local;
        sshQ_ChannelG_methods.writeG_local = ($R (*) (sshQ_Channel, $Cont, B_bytes))sshQ_ChannelD_writeG_local;
        sshQ_ChannelG_methods.send_eofG_local = ($R (*) (sshQ_Channel, $Cont))sshQ_ChannelD_send_eofG_local;
        sshQ_ChannelG_methods.closeG_local = ($R (*) (sshQ_Channel, $Cont))sshQ_ChannelD_closeG_local;
        sshQ_ChannelG_methods._cleanup_nativeG_local = ($R (*) (sshQ_Channel, $Cont))sshQ_ChannelD__cleanup_nativeG_local;
        sshQ_ChannelG_methods.__cleanup__G_local = ($R (*) (sshQ_Channel, $Cont))sshQ_ChannelD___cleanup__G_local;
        sshQ_ChannelG_methods._init = (B_Msg (*) (sshQ_Channel))sshQ_ChannelD__init;
        sshQ_ChannelG_methods.request_exec = (B_Msg (*) (sshQ_Channel, B_str))sshQ_ChannelD_request_exec;
        sshQ_ChannelG_methods.request_shell = (B_Msg (*) (sshQ_Channel, B_str, B_int, B_int, B_int, B_int, B_bool))sshQ_ChannelD_request_shell;
        sshQ_ChannelG_methods.request_subsystem = (B_Msg (*) (sshQ_Channel, B_str))sshQ_ChannelD_request_subsystem;
        sshQ_ChannelG_methods.write = (B_Msg (*) (sshQ_Channel, B_bytes))sshQ_ChannelD_write;
        sshQ_ChannelG_methods.send_eof = (B_Msg (*) (sshQ_Channel))sshQ_ChannelD_send_eof;
        sshQ_ChannelG_methods.close = (B_Msg (*) (sshQ_Channel))sshQ_ChannelD_close;
        sshQ_ChannelG_methods._cleanup_native = (B_Msg (*) (sshQ_Channel))sshQ_ChannelD__cleanup_native;
        sshQ_ChannelG_methods.__cleanup__ = (B_Msg (*) (sshQ_Channel))sshQ_ChannelD___cleanup__;
        sshQ_ChannelG_methods.__serialize__ = sshQ_ChannelD___serialize__;
        sshQ_ChannelG_methods.__deserialize__ = sshQ_ChannelD___deserialize__;
        $register(&sshQ_ChannelG_methods);
    }
    {
        sshQ_RunCommandG_methods.$GCINFO = "sshQ_RunCommand";
        sshQ_RunCommandG_methods.$superclass = ($SuperG_class)&$ActorG_methods;
        sshQ_RunCommandG_methods.__bool__ = (B_bool (*) (sshQ_RunCommand))$ActorG_methods.__bool__;
        sshQ_RunCommandG_methods.__str__ = (B_str (*) (sshQ_RunCommand))$ActorG_methods.__str__;
        sshQ_RunCommandG_methods.__repr__ = (B_str (*) (sshQ_RunCommand))$ActorG_methods.__repr__;
        sshQ_RunCommandG_methods.__resume__ = (B_NoneType (*) (sshQ_RunCommand))$ActorG_methods.__resume__;
        sshQ_RunCommandG_methods.__cleanup__ = (B_NoneType (*) (sshQ_RunCommand))$ActorG_methods.__cleanup__;
        sshQ_RunCommandG_methods.__init__ = ($R (*) (sshQ_RunCommand, $Cont, sshQ_Client, B_str, $action, B_float))sshQ_RunCommandD___init__;
        sshQ_RunCommandG_methods._finishG_local = ($R (*) (sshQ_RunCommand, $Cont, sshQ_Channel))sshQ_RunCommandD__finishG_local;
        sshQ_RunCommandG_methods._on_openG_local = ($R (*) (sshQ_RunCommand, $Cont, sshQ_Channel, B_str))sshQ_RunCommandD__on_openG_local;
        sshQ_RunCommandG_methods._on_stdoutG_local = ($R (*) (sshQ_RunCommand, $Cont, sshQ_Channel, B_bytes))sshQ_RunCommandD__on_stdoutG_local;
        sshQ_RunCommandG_methods._on_stderrG_local = ($R (*) (sshQ_RunCommand, $Cont, sshQ_Channel, B_bytes))sshQ_RunCommandD__on_stderrG_local;
        sshQ_RunCommandG_methods._on_exitG_local = ($R (*) (sshQ_RunCommand, $Cont, sshQ_Channel, int64_t, B_str))sshQ_RunCommandD__on_exitG_local;
        sshQ_RunCommandG_methods._on_closeG_local = ($R (*) (sshQ_RunCommand, $Cont, sshQ_Channel, B_str))sshQ_RunCommandD__on_closeG_local;
        sshQ_RunCommandG_methods._check_doneG_local = ($R (*) (sshQ_RunCommand, $Cont, sshQ_Channel))sshQ_RunCommandD__check_doneG_local;
        sshQ_RunCommandG_methods._finish = (B_Msg (*) (sshQ_RunCommand, sshQ_Channel))sshQ_RunCommandD__finish;
        sshQ_RunCommandG_methods._on_open = (B_Msg (*) (sshQ_RunCommand, sshQ_Channel, B_str))sshQ_RunCommandD__on_open;
        sshQ_RunCommandG_methods._on_stdout = (B_Msg (*) (sshQ_RunCommand, sshQ_Channel, B_bytes))sshQ_RunCommandD__on_stdout;
        sshQ_RunCommandG_methods._on_stderr = (B_Msg (*) (sshQ_RunCommand, sshQ_Channel, B_bytes))sshQ_RunCommandD__on_stderr;
        sshQ_RunCommandG_methods._on_exit = (B_Msg (*) (sshQ_RunCommand, sshQ_Channel, int64_t, B_str))sshQ_RunCommandD__on_exit;
        sshQ_RunCommandG_methods._on_close = (B_Msg (*) (sshQ_RunCommand, sshQ_Channel, B_str))sshQ_RunCommandD__on_close;
        sshQ_RunCommandG_methods._check_done = (B_Msg (*) (sshQ_RunCommand, sshQ_Channel))sshQ_RunCommandD__check_done;
        sshQ_RunCommandG_methods.__serialize__ = sshQ_RunCommandD___serialize__;
        sshQ_RunCommandG_methods.__deserialize__ = sshQ_RunCommandD___deserialize__;
        $register(&sshQ_RunCommandG_methods);
    }
    {
        sshQ_ServerG_methods.$GCINFO = "sshQ_Server";
        sshQ_ServerG_methods.$superclass = ($SuperG_class)&$ActorG_methods;
        sshQ_ServerG_methods.__bool__ = (B_bool (*) (sshQ_Server))$ActorG_methods.__bool__;
        sshQ_ServerG_methods.__str__ = (B_str (*) (sshQ_Server))$ActorG_methods.__str__;
        sshQ_ServerG_methods.__repr__ = (B_str (*) (sshQ_Server))$ActorG_methods.__repr__;
        sshQ_ServerG_methods.__resume__ = (B_NoneType (*) (sshQ_Server))$ActorG_methods.__resume__;
        sshQ_ServerG_methods.__init__ = ($R (*) (sshQ_Server, $Cont, netQ_TCPListenCap, B_str, uint16_t, $action, $action, $action, $action, $action, $action, $action, $action, B_str, B_str, B_int, B_float, B_float, B_bool, B_float, B_int, B_int, B_int))sshQ_ServerD___init__;
        sshQ_ServerG_methods._pin_affinityG_local = ($R (*) (sshQ_Server, $Cont))sshQ_ServerD__pin_affinityG_local;
        sshQ_ServerG_methods._initG_local = ($R (*) (sshQ_Server, $Cont))sshQ_ServerD__initG_local;
        sshQ_ServerG_methods.closeG_local = ($R (*) (sshQ_Server, $Cont))sshQ_ServerD_closeG_local;
        sshQ_ServerG_methods.bound_portG_local = ($R (*) (sshQ_Server, $Cont))sshQ_ServerD_bound_portG_local;
        sshQ_ServerG_methods._cleanup_nativeG_local = ($R (*) (sshQ_Server, $Cont))sshQ_ServerD__cleanup_nativeG_local;
        sshQ_ServerG_methods.__cleanup__G_local = ($R (*) (sshQ_Server, $Cont))sshQ_ServerD___cleanup__G_local;
        sshQ_ServerG_methods.on_session_pendingG_local = ($R (*) (sshQ_Server, $Cont, uint64_t))sshQ_ServerD_on_session_pendingG_local;
        sshQ_ServerG_methods.on_session_readyG_local = ($R (*) (sshQ_Server, $Cont, sshQ_ServerSession))sshQ_ServerD_on_session_readyG_local;
        sshQ_ServerG_methods._pin_affinity = (B_Msg (*) (sshQ_Server))sshQ_ServerD__pin_affinity;
        sshQ_ServerG_methods._init = (B_Msg (*) (sshQ_Server))sshQ_ServerD__init;
        sshQ_ServerG_methods.close = (B_Msg (*) (sshQ_Server))sshQ_ServerD_close;
        sshQ_ServerG_methods.bound_port = (B_Msg (*) (sshQ_Server))sshQ_ServerD_bound_port;
        sshQ_ServerG_methods._cleanup_native = (B_Msg (*) (sshQ_Server))sshQ_ServerD__cleanup_native;
        sshQ_ServerG_methods.__cleanup__ = (B_Msg (*) (sshQ_Server))sshQ_ServerD___cleanup__;
        sshQ_ServerG_methods.on_session_pending = (B_Msg (*) (sshQ_Server, uint64_t))sshQ_ServerD_on_session_pending;
        sshQ_ServerG_methods.on_session_ready = (B_Msg (*) (sshQ_Server, sshQ_ServerSession))sshQ_ServerD_on_session_ready;
        sshQ_ServerG_methods.__serialize__ = sshQ_ServerD___serialize__;
        sshQ_ServerG_methods.__deserialize__ = sshQ_ServerD___deserialize__;
        $register(&sshQ_ServerG_methods);
    }
    {
        sshQ_ServerSessionG_methods.$GCINFO = "sshQ_ServerSession";
        sshQ_ServerSessionG_methods.$superclass = ($SuperG_class)&$ActorG_methods;
        sshQ_ServerSessionG_methods.__bool__ = (B_bool (*) (sshQ_ServerSession))$ActorG_methods.__bool__;
        sshQ_ServerSessionG_methods.__str__ = (B_str (*) (sshQ_ServerSession))$ActorG_methods.__str__;
        sshQ_ServerSessionG_methods.__repr__ = (B_str (*) (sshQ_ServerSession))$ActorG_methods.__repr__;
        sshQ_ServerSessionG_methods.__resume__ = (B_NoneType (*) (sshQ_ServerSession))$ActorG_methods.__resume__;
        sshQ_ServerSessionG_methods.__init__ = ($R (*) (sshQ_ServerSession, $Cont, sshQ_Server, uint64_t, $action, $action, $action, $action, $action))sshQ_ServerSessionD___init__;
        sshQ_ServerSessionG_methods._pin_affinityG_local = ($R (*) (sshQ_ServerSession, $Cont))sshQ_ServerSessionD__pin_affinityG_local;
        sshQ_ServerSessionG_methods._attachG_local = ($R (*) (sshQ_ServerSession, $Cont, uint64_t))sshQ_ServerSessionD__attachG_local;
        sshQ_ServerSessionG_methods._drive_attachedG_local = ($R (*) (sshQ_ServerSession, $Cont))sshQ_ServerSessionD__drive_attachedG_local;
        sshQ_ServerSessionG_methods._attach_readyG_local = ($R (*) (sshQ_ServerSession, $Cont))sshQ_ServerSessionD__attach_readyG_local;
        sshQ_ServerSessionG_methods.accept_authG_local = ($R (*) (sshQ_ServerSession, $Cont))sshQ_ServerSessionD_accept_authG_local;
        sshQ_ServerSessionG_methods.reject_authG_local = ($R (*) (sshQ_ServerSession, $Cont, B_str))sshQ_ServerSessionD_reject_authG_local;
        sshQ_ServerSessionG_methods.accept_channelG_local = ($R (*) (sshQ_ServerSession, $Cont, sshQ_ServerChannel))sshQ_ServerSessionD_accept_channelG_local;
        sshQ_ServerSessionG_methods.accept_channel_openG_local = ($R (*) (sshQ_ServerSession, $Cont, sshQ_ServerChannel, $action, $action, $action))sshQ_ServerSessionD_accept_channel_openG_local;
        sshQ_ServerSessionG_methods.reject_channelG_local = ($R (*) (sshQ_ServerSession, $Cont, B_str))sshQ_ServerSessionD_reject_channelG_local;
        sshQ_ServerSessionG_methods.closeG_local = ($R (*) (sshQ_ServerSession, $Cont))sshQ_ServerSessionD_closeG_local;
        sshQ_ServerSessionG_methods._cleanup_nativeG_local = ($R (*) (sshQ_ServerSession, $Cont))sshQ_ServerSessionD__cleanup_nativeG_local;
        sshQ_ServerSessionG_methods.__cleanup__G_local = ($R (*) (sshQ_ServerSession, $Cont))sshQ_ServerSessionD___cleanup__G_local;
        sshQ_ServerSessionG_methods.channel_accept_requestG_local = ($R (*) (sshQ_ServerSession, $Cont, sshQ_ServerChannel))sshQ_ServerSessionD_channel_accept_requestG_local;
        sshQ_ServerSessionG_methods.channel_reject_requestG_local = ($R (*) (sshQ_ServerSession, $Cont, sshQ_ServerChannel, B_str))sshQ_ServerSessionD_channel_reject_requestG_local;
        sshQ_ServerSessionG_methods.channel_writeG_local = ($R (*) (sshQ_ServerSession, $Cont, sshQ_ServerChannel, B_bytes))sshQ_ServerSessionD_channel_writeG_local;
        sshQ_ServerSessionG_methods.channel_write_stderrG_local = ($R (*) (sshQ_ServerSession, $Cont, sshQ_ServerChannel, B_bytes))sshQ_ServerSessionD_channel_write_stderrG_local;
        sshQ_ServerSessionG_methods.channel_send_eofG_local = ($R (*) (sshQ_ServerSession, $Cont, sshQ_ServerChannel))sshQ_ServerSessionD_channel_send_eofG_local;
        sshQ_ServerSessionG_methods.channel_send_exit_statusG_local = ($R (*) (sshQ_ServerSession, $Cont, sshQ_ServerChannel, int64_t))sshQ_ServerSessionD_channel_send_exit_statusG_local;
        sshQ_ServerSessionG_methods.channel_closeG_local = ($R (*) (sshQ_ServerSession, $Cont, sshQ_ServerChannel))sshQ_ServerSessionD_channel_closeG_local;
        sshQ_ServerSessionG_methods._pin_affinity = (B_Msg (*) (sshQ_ServerSession))sshQ_ServerSessionD__pin_affinity;
        sshQ_ServerSessionG_methods._attach = (B_Msg (*) (sshQ_ServerSession, uint64_t))sshQ_ServerSessionD__attach;
        sshQ_ServerSessionG_methods._drive_attached = (B_Msg (*) (sshQ_ServerSession))sshQ_ServerSessionD__drive_attached;
        sshQ_ServerSessionG_methods._attach_ready = (B_Msg (*) (sshQ_ServerSession))sshQ_ServerSessionD__attach_ready;
        sshQ_ServerSessionG_methods.accept_auth = (B_Msg (*) (sshQ_ServerSession))sshQ_ServerSessionD_accept_auth;
        sshQ_ServerSessionG_methods.reject_auth = (B_Msg (*) (sshQ_ServerSession, B_str))sshQ_ServerSessionD_reject_auth;
        sshQ_ServerSessionG_methods.accept_channel = (B_Msg (*) (sshQ_ServerSession, sshQ_ServerChannel))sshQ_ServerSessionD_accept_channel;
        sshQ_ServerSessionG_methods.accept_channel_open = (B_Msg (*) (sshQ_ServerSession, sshQ_ServerChannel, $action, $action, $action))sshQ_ServerSessionD_accept_channel_open;
        sshQ_ServerSessionG_methods.reject_channel = (B_Msg (*) (sshQ_ServerSession, B_str))sshQ_ServerSessionD_reject_channel;
        sshQ_ServerSessionG_methods.close = (B_Msg (*) (sshQ_ServerSession))sshQ_ServerSessionD_close;
        sshQ_ServerSessionG_methods._cleanup_native = (B_Msg (*) (sshQ_ServerSession))sshQ_ServerSessionD__cleanup_native;
        sshQ_ServerSessionG_methods.__cleanup__ = (B_Msg (*) (sshQ_ServerSession))sshQ_ServerSessionD___cleanup__;
        sshQ_ServerSessionG_methods.channel_accept_request = (B_Msg (*) (sshQ_ServerSession, sshQ_ServerChannel))sshQ_ServerSessionD_channel_accept_request;
        sshQ_ServerSessionG_methods.channel_reject_request = (B_Msg (*) (sshQ_ServerSession, sshQ_ServerChannel, B_str))sshQ_ServerSessionD_channel_reject_request;
        sshQ_ServerSessionG_methods.channel_write = (B_Msg (*) (sshQ_ServerSession, sshQ_ServerChannel, B_bytes))sshQ_ServerSessionD_channel_write;
        sshQ_ServerSessionG_methods.channel_write_stderr = (B_Msg (*) (sshQ_ServerSession, sshQ_ServerChannel, B_bytes))sshQ_ServerSessionD_channel_write_stderr;
        sshQ_ServerSessionG_methods.channel_send_eof = (B_Msg (*) (sshQ_ServerSession, sshQ_ServerChannel))sshQ_ServerSessionD_channel_send_eof;
        sshQ_ServerSessionG_methods.channel_send_exit_status = (B_Msg (*) (sshQ_ServerSession, sshQ_ServerChannel, int64_t))sshQ_ServerSessionD_channel_send_exit_status;
        sshQ_ServerSessionG_methods.channel_close = (B_Msg (*) (sshQ_ServerSession, sshQ_ServerChannel))sshQ_ServerSessionD_channel_close;
        sshQ_ServerSessionG_methods.__serialize__ = sshQ_ServerSessionD___serialize__;
        sshQ_ServerSessionG_methods.__deserialize__ = sshQ_ServerSessionD___deserialize__;
        $register(&sshQ_ServerSessionG_methods);
    }
    {
        sshQ_ServerChannelG_methods.$GCINFO = "sshQ_ServerChannel";
        sshQ_ServerChannelG_methods.$superclass = ($SuperG_class)&$ActorG_methods;
        sshQ_ServerChannelG_methods.__bool__ = (B_bool (*) (sshQ_ServerChannel))$ActorG_methods.__bool__;
        sshQ_ServerChannelG_methods.__str__ = (B_str (*) (sshQ_ServerChannel))$ActorG_methods.__str__;
        sshQ_ServerChannelG_methods.__repr__ = (B_str (*) (sshQ_ServerChannel))$ActorG_methods.__repr__;
        sshQ_ServerChannelG_methods.__resume__ = (B_NoneType (*) (sshQ_ServerChannel))$ActorG_methods.__resume__;
        sshQ_ServerChannelG_methods.__init__ = ($R (*) (sshQ_ServerChannel, $Cont, sshQ_ServerSession, $action, $action, $action))sshQ_ServerChannelD___init__;
        sshQ_ServerChannelG_methods.accept_requestG_local = ($R (*) (sshQ_ServerChannel, $Cont))sshQ_ServerChannelD_accept_requestG_local;
        sshQ_ServerChannelG_methods.accept_openG_local = ($R (*) (sshQ_ServerChannel, $Cont))sshQ_ServerChannelD_accept_openG_local;
        sshQ_ServerChannelG_methods.reject_requestG_local = ($R (*) (sshQ_ServerChannel, $Cont, B_str))sshQ_ServerChannelD_reject_requestG_local;
        sshQ_ServerChannelG_methods.writeG_local = ($R (*) (sshQ_ServerChannel, $Cont, B_bytes))sshQ_ServerChannelD_writeG_local;
        sshQ_ServerChannelG_methods.write_stderrG_local = ($R (*) (sshQ_ServerChannel, $Cont, B_bytes))sshQ_ServerChannelD_write_stderrG_local;
        sshQ_ServerChannelG_methods.send_eofG_local = ($R (*) (sshQ_ServerChannel, $Cont))sshQ_ServerChannelD_send_eofG_local;
        sshQ_ServerChannelG_methods.send_exit_statusG_local = ($R (*) (sshQ_ServerChannel, $Cont, int64_t))sshQ_ServerChannelD_send_exit_statusG_local;
        sshQ_ServerChannelG_methods.closeG_local = ($R (*) (sshQ_ServerChannel, $Cont))sshQ_ServerChannelD_closeG_local;
        sshQ_ServerChannelG_methods._cleanup_nativeG_local = ($R (*) (sshQ_ServerChannel, $Cont))sshQ_ServerChannelD__cleanup_nativeG_local;
        sshQ_ServerChannelG_methods.__cleanup__G_local = ($R (*) (sshQ_ServerChannel, $Cont))sshQ_ServerChannelD___cleanup__G_local;
        sshQ_ServerChannelG_methods.accept_request = (B_Msg (*) (sshQ_ServerChannel))sshQ_ServerChannelD_accept_request;
        sshQ_ServerChannelG_methods.accept_open = (B_Msg (*) (sshQ_ServerChannel))sshQ_ServerChannelD_accept_open;
        sshQ_ServerChannelG_methods.reject_request = (B_Msg (*) (sshQ_ServerChannel, B_str))sshQ_ServerChannelD_reject_request;
        sshQ_ServerChannelG_methods.write = (B_Msg (*) (sshQ_ServerChannel, B_bytes))sshQ_ServerChannelD_write;
        sshQ_ServerChannelG_methods.write_stderr = (B_Msg (*) (sshQ_ServerChannel, B_bytes))sshQ_ServerChannelD_write_stderr;
        sshQ_ServerChannelG_methods.send_eof = (B_Msg (*) (sshQ_ServerChannel))sshQ_ServerChannelD_send_eof;
        sshQ_ServerChannelG_methods.send_exit_status = (B_Msg (*) (sshQ_ServerChannel, int64_t))sshQ_ServerChannelD_send_exit_status;
        sshQ_ServerChannelG_methods.close = (B_Msg (*) (sshQ_ServerChannel))sshQ_ServerChannelD_close;
        sshQ_ServerChannelG_methods._cleanup_native = (B_Msg (*) (sshQ_ServerChannel))sshQ_ServerChannelD__cleanup_native;
        sshQ_ServerChannelG_methods.__cleanup__ = (B_Msg (*) (sshQ_ServerChannel))sshQ_ServerChannelD___cleanup__;
        sshQ_ServerChannelG_methods.__serialize__ = sshQ_ServerChannelD___serialize__;
        sshQ_ServerChannelG_methods.__deserialize__ = sshQ_ServerChannelD___deserialize__;
        $register(&sshQ_ServerChannelG_methods);
    }
    B_str HOSTKEY_OK = to$str("ok");
    sshQ_HOSTKEY_OK = HOSTKEY_OK;
    B_str HOSTKEY_UNKNOWN = to$str("unknown");
    sshQ_HOSTKEY_UNKNOWN = HOSTKEY_UNKNOWN;
    B_str HOSTKEY_NOT_FOUND = to$str("not_found");
    sshQ_HOSTKEY_NOT_FOUND = HOSTKEY_NOT_FOUND;
    B_str HOSTKEY_CHANGED = to$str("changed");
    sshQ_HOSTKEY_CHANGED = HOSTKEY_CHANGED;
    B_str HOSTKEY_OTHER = to$str("other");
    sshQ_HOSTKEY_OTHER = HOSTKEY_OTHER;
    B_str HOSTKEY_ERROR = to$str("error");
    sshQ_HOSTKEY_ERROR = HOSTKEY_ERROR;
    B_Plus W_HostKeyInfo_924 = (B_Plus)B_TimesD_bytesG_witness;
    sshQ_W_HostKeyInfo_924 = W_HostKeyInfo_924;
}