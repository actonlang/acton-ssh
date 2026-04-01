#include <errno.h>
#include <libssh/libssh.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
// acton includes
#include <rts/rts.h>

/* Declared in rts/io.h but not always in the include path */
uv_loop_t *get_uv_loop();

enum client_state {
    S_AUTH,
    S_AUTH_KBDINT,
    S_CHANNEL_OPEN,
    S_REQUEST_TYPE,
    S_READY,
    S_ERROR
};

typedef struct {
    ssh_session session;
    ssh_channel channel;
    uv_poll_t *poll;
    int fd;
    enum client_state state;

    /* pending write buffer */
    char *write_buf;
    size_t write_len;
    size_t write_sent;

    /* actor reference for callbacks */
    sshQ_Client actor;
} client_t;

/* Forward declarations */
static void poll_cb(uv_poll_t *handle, int status, int events);

/* Helper: set up SSH session, connect, and start polling on the RTS loop */
static int client_setup(client_t *c, sshQ_Client self) {
    int err = 0;

    c->actor = self;
    c->channel = NULL;
    c->write_buf = NULL;
    c->write_len = 0;
    c->write_sent = 0;

    c->session = ssh_new();
    if (!c->session)
        return -1;

    const char *host = (const char *)fromB_str(self->host);
    int port = (int)fromB_int(self->port);
    const char *user = (const char *)fromB_str(self->username);

    ssh_options_set(c->session, SSH_OPTIONS_HOST, host);
    ssh_options_set(c->session, SSH_OPTIONS_PORT, &port);
    ssh_options_set(c->session, SSH_OPTIONS_USER, user);
    ssh_session_set_disconnect_message(c->session, "Disconnecting SSH, powered by Acton");

    /* Blocking TCP connect (fast) */
    err = ssh_connect(c->session);
    if (err != SSH_OK) {
        ssh_free(c->session);
        c->session = NULL;
        return -1;
    }

    c->state = S_AUTH;
    ssh_set_blocking(c->session, 0);

    c->fd = ssh_get_fd(c->session);
    if (c->fd < 0) {
        ssh_disconnect(c->session);
        ssh_free(c->session);
        c->session = NULL;
        return -1;
    }

    /* Use the RTS event loop instead of a private loop */
    c->poll = (uv_poll_t *)acton_malloc(sizeof(uv_poll_t));
    err = uv_poll_init(get_uv_loop(), c->poll, c->fd);
    if (err < 0) {
        ssh_disconnect(c->session);
        ssh_free(c->session);
        c->session = NULL;
        return -1;
    }

    c->poll->data = c;
    err = uv_poll_start(c->poll, UV_READABLE | UV_WRITABLE, poll_cb);
    if (err < 0) {
        uv_close((uv_handle_t *)c->poll, NULL);
        ssh_disconnect(c->session);
        ssh_free(c->session);
        c->session = NULL;
        return -1;
    }

    return 0;
}

/* Called whenever the polled fd has activity — drives connection state machine
 * and delivers data to Acton via callbacks */
static void poll_cb(uv_poll_t *handle, int status, int events) {
    if (!handle || !handle->data)
        return;

    client_t *c = (client_t *)handle->data;
    sshQ_Client self = c->actor;
    int rc;

    if (status < 0) {
        $action2 f = ($action2)self->on_error;
        f->$class->__asyn__(f, self, to$str((char *)uv_strerror(status)));
        uv_poll_stop(c->poll);
        return;
    }

    switch (c->state) {
    case S_AUTH: {
        if ((void *)self->password == (void *)B_None || self->password == NULL) {
            $action2 f = ($action2)self->on_error;
            f->$class->__asyn__(f, self, to$str("No authentication method available"));
            uv_poll_stop(c->poll);
            return;
        }
        rc = ssh_userauth_password(c->session, NULL, (const char *)fromB_str(self->password));
        if (rc == SSH_AUTH_SUCCESS) {
            c->state = S_CHANNEL_OPEN;
        } else if (rc == SSH_AUTH_AGAIN) {
            return;
        } else {
            /* Password auth failed/denied — try keyboard-interactive */
            c->state = S_AUTH_KBDINT;
        }
        break;
    }
    case S_AUTH_KBDINT: {
        rc = ssh_userauth_kbdint(c->session, NULL, NULL);
        if (rc == SSH_AUTH_INFO) {
            int nprompts = ssh_userauth_kbdint_getnprompts(c->session);
            for (int i = 0; i < nprompts; i++) {
                ssh_userauth_kbdint_setanswer(c->session, i,
                    (const char *)fromB_str(self->password));
            }
            /* Need another round — stay in S_AUTH_KBDINT */
            return;
        } else if (rc == SSH_AUTH_SUCCESS) {
            c->state = S_CHANNEL_OPEN;
        } else if (rc == SSH_AUTH_AGAIN) {
            return;
        } else {
            char errmsg[512];
            snprintf(errmsg, sizeof(errmsg), "Authentication failed: %s", ssh_get_error(c->session));
            $action2 f = ($action2)self->on_error;
            f->$class->__asyn__(f, self, to$str(errmsg));
            uv_poll_stop(c->poll);
            return;
        }
        break;
    }
    case S_CHANNEL_OPEN:
        if (!c->channel) {
            c->channel = ssh_channel_new(c->session);
            if (!c->channel) {
                $action2 f = ($action2)self->on_error;
                f->$class->__asyn__(f, self, to$str("Failed to create SSH channel"));
                uv_poll_stop(c->poll);
                return;
            }
        }
        rc = ssh_channel_open_session(c->channel);
        if (rc == SSH_OK) {
            c->state = S_REQUEST_TYPE;
        } else if (rc == SSH_AGAIN) {
            return;
        } else {
            char errmsg[512];
            snprintf(errmsg, sizeof(errmsg), "Failed to open channel: %s", ssh_get_error(c->session));
            $action2 f = ($action2)self->on_error;
            f->$class->__asyn__(f, self, to$str(errmsg));
            uv_poll_stop(c->poll);
            return;
        }
        break;
    case S_REQUEST_TYPE:
        if ((void *)self->subsystem == (void *)B_None || self->subsystem == NULL) {
            /* No subsystem — request a shell */
            rc = ssh_channel_request_shell(c->channel);
        } else {
            rc = ssh_channel_request_subsystem(c->channel, (const char *)fromB_str(self->subsystem));
        }
        if (rc == SSH_OK) {
            c->state = S_READY;
            /* Connection fully established — notify Acton */
            $action f = ($action)self->on_connect;
            f->$class->__asyn__(f, self);
        } else if (rc == SSH_AGAIN) {
            return;
        } else {
            char errmsg[512];
            snprintf(errmsg, sizeof(errmsg), "Failed to request shell/subsystem: %s", ssh_get_error(c->session));
            $action2 f = ($action2)self->on_error;
            f->$class->__asyn__(f, self, to$str(errmsg));
            uv_poll_stop(c->poll);
            return;
        }
        break;

    case S_READY:
        /* Flush any pending write data */
        if (c->write_buf && c->write_sent < c->write_len && (events & UV_WRITABLE)) {
            int wrote = ssh_channel_write(c->channel,
                                          c->write_buf + c->write_sent,
                                          (uint32_t)(c->write_len - c->write_sent));
            if (wrote > 0) {
                c->write_sent += (size_t)wrote;
                if (c->write_sent >= c->write_len) {
                    free(c->write_buf);
                    c->write_buf = NULL;
                    c->write_len = 0;
                    c->write_sent = 0;
                }
            } else if (wrote == SSH_ERROR) {
                $action2 f = ($action2)self->on_error;
                f->$class->__asyn__(f, self, to$str("SSH channel write failed"));
                uv_poll_stop(c->poll);
                return;
            }
            /* SSH_AGAIN / 0: try again on next poll */
        }

        /* Read all available data from the channel */
        {
            char buf[8192];
            int n;
            while ((n = ssh_channel_read_nonblocking(c->channel, buf, sizeof(buf), 0)) > 0) {
                $action2 f = ($action2)self->on_receive;
                f->$class->__asyn__(f, self, to$bytesD_len(buf, n));
            }
            if (ssh_channel_is_eof(c->channel)) {
                uv_poll_stop(c->poll);
                if (self->on_remote_close) {
                    $action f = ($action)self->on_remote_close;
                    f->$class->__asyn__(f, self);
                }
            } else if (n < 0) {
                $action2 f = ($action2)self->on_error;
                f->$class->__asyn__(f, self, to$str((char *)ssh_get_error(c->session)));
                uv_poll_stop(c->poll);
            }
        }
        break;

    case S_ERROR:
        uv_poll_stop(c->poll);
        break;
    }
}

/* ---- Module-level functions ---- */

void sshQ___ext_init__() {
    int r = ssh_init();
    if (r != SSH_OK)
        printf("SSH init failed (%d)\n", r);
}

B_str sshQ_version() {
    return to$str("0.2.0");
}

/* ---- Client actor methods ---- */

$R sshQ_ClientD__pin_affinityG_local(sshQ_Client self, $Cont c$cont) {
    pin_actor_affinity();
    return $R_CONT(c$cont, B_None);
}

$R sshQ_ClientD__initG_local(sshQ_Client self, $Cont c$cont) {
    pin_actor_affinity();

    client_t *client = (client_t *)acton_malloc(sizeof(client_t));
    memset(client, 0, sizeof(client_t));

    if (client_setup(client, self) != 0) {
        char errmsg[512];
        if (client->session) {
            snprintf(errmsg, sizeof(errmsg), "SSH connect failed: %s", ssh_get_error(client->session));
        } else {
            snprintf(errmsg, sizeof(errmsg), "SSH initialization failed");
        }
        $action2 f = ($action2)self->on_error;
        f->$class->__asyn__(f, self, to$str(errmsg));
        return $R_CONT(c$cont, B_None);
    }

    self->_client = toB_u64((unsigned long)client);
    return $R_CONT(c$cont, B_None);
}

$R sshQ_ClientD_writeG_local(sshQ_Client self, $Cont c$cont, B_bytes data) {
    client_t *client = (client_t *)fromB_u64(self->_client);
    if (!client || !client->channel || client->state != S_READY) {
        $action2 f = ($action2)self->on_error;
        f->$class->__asyn__(f, self, to$str("Cannot write: not connected"));
        return $R_CONT(c$cont, B_None);
    }

    /* If there is already pending data, append to the write buffer */
    if (client->write_buf) {
        size_t remaining = client->write_len - client->write_sent;
        size_t new_len = remaining + data->nbytes;
        char *new_buf = malloc(new_len);
        if (!new_buf) {
            $action2 f = ($action2)self->on_error;
            f->$class->__asyn__(f, self, to$str("Write buffer allocation failed"));
            return $R_CONT(c$cont, B_None);
        }
        memcpy(new_buf, client->write_buf + client->write_sent, remaining);
        memcpy(new_buf + remaining, data->str, data->nbytes);
        free(client->write_buf);
        client->write_buf = new_buf;
        client->write_len = new_len;
        client->write_sent = 0;
        return $R_CONT(c$cont, B_None);
    }

    /* Try to write directly */
    int wrote = ssh_channel_write(client->channel, (const char *)data->str, (uint32_t)data->nbytes);
    if (wrote == (int)data->nbytes) {
        return $R_CONT(c$cont, B_None);
    }

    /* Partial or failed write — buffer the remainder for poll_cb to flush */
    size_t sent = (wrote > 0) ? (size_t)wrote : 0;
    size_t remaining = data->nbytes - sent;
    client->write_buf = malloc(remaining);
    if (!client->write_buf) {
        $action2 f = ($action2)self->on_error;
        f->$class->__asyn__(f, self, to$str("Write buffer allocation failed"));
        return $R_CONT(c$cont, B_None);
    }
    memcpy(client->write_buf, (const char *)data->str + sent, remaining);
    client->write_len = remaining;
    client->write_sent = 0;

    return $R_CONT(c$cont, B_None);
}

$R sshQ_ClientD_closeG_local(sshQ_Client self, $Cont c$cont, $action on_close) {
    client_t *client = (client_t *)fromB_u64(self->_client);
    if (!client) {
        on_close->$class->__asyn__(on_close, self);
        return $R_CONT(c$cont, B_None);
    }

    /* Stop polling */
    if (client->poll) {
        uv_poll_stop(client->poll);
        uv_close((uv_handle_t *)client->poll, NULL);
        client->poll = NULL;
    }

    /* Close SSH channel */
    if (client->channel) {
        ssh_channel_send_eof(client->channel);
        ssh_channel_close(client->channel);
        ssh_channel_free(client->channel);
        client->channel = NULL;
    }

    /* Disconnect SSH session */
    if (client->session) {
        ssh_disconnect(client->session);
        ssh_free(client->session);
        client->session = NULL;
    }

    /* Free write buffer */
    if (client->write_buf) {
        free(client->write_buf);
        client->write_buf = NULL;
    }

    self->_client = toB_u64(0);

    /* Invoke on_close callback */
    on_close->$class->__asyn__(on_close, self);

    return $R_CONT(c$cont, B_None);
}

$R sshQ_ClientD__connectG_local(sshQ_Client self, $Cont c$cont, sshQ_Client c) {
    pin_actor_affinity();

    client_t *client = (client_t *)acton_malloc(sizeof(client_t));
    memset(client, 0, sizeof(client_t));

    if (client_setup(client, self) != 0) {
        char errmsg[512];
        if (client->session) {
            snprintf(errmsg, sizeof(errmsg), "SSH reconnect failed: %s", ssh_get_error(client->session));
        } else {
            snprintf(errmsg, sizeof(errmsg), "SSH reconnect initialization failed");
        }
        $action2 f = ($action2)self->on_error;
        f->$class->__asyn__(f, self, to$str(errmsg));
        return $R_CONT(c$cont, B_None);
    }

    self->_client = toB_u64((unsigned long)client);
    return $R_CONT(c$cont, B_None);
}
