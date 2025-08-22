#include <errno.h>
#include <libssh/libssh.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
// acton includes
#include <rts/rts.h>

#include "netconf.h"

#ifndef DEBUG_MODE
// #define DEBUG_MODE    /* uncomment for pretty prints */
#endif

#define BUF_SIZE 512

enum client_state {
    S_CONNECT,
    S_AUTH,
    S_CHANNEL_OPEN,
    S_SUBSYSTEM,
    S_SEND_HELLO,
    S_RECV_HELLO,
    S_SEND_GET,
    S_SEND_GET_WRITING,
    S_RECV_GET,
    S_CLOSE,
    S_CLOSE_WRITING,
    S_RECV_CLOSE_REPLY,
    S_CLEANUP,
    S_DONE,
    S_ERROR
};

enum client_operation {
    OP_HELLO,
    OP_HELLO_REPLY,
    OP_GET,
    OP_GET_REPLY,
    OP_CLOSE,
    OP_CLOSE_REPLY
};

typedef struct {
    const char *data;
    size_t len;
    size_t sent;
} write_buffer_t;

typedef struct {
    uv_loop_t *loop;

    ssh_session session;
    ssh_channel channel;
    uv_poll_t *poll;
    const char *subsystem;

    int fd;
    enum client_state state;
    const char *host;
    int port;
    const char *user;
    const char *password;

    /* current write buffer */
    write_buffer_t write_buf;

    char *payload;
    char *response;

    /* read buffer */
    char *reply;
    size_t reply_len;
    size_t reply_cap;
} client_t;

static char *client_operation_to_str(enum client_operation op) {
    switch (op) {
    case OP_HELLO:
        return "OP_HELLO";
    case OP_HELLO_REPLY:
        return "OP_HELLO_REPLY";
    case OP_GET:
        return "OP_GET";
    case OP_GET_REPLY:
        return "OP_GET_REPLY";
    case OP_CLOSE:
        return "OP_CLOSE";
    case OP_CLOSE_REPLY:
        return "OP_CLOSE_REPLY";
    default:
        return "";
    }
    return "";
}

/* Simple helper to append to reply buffer */
static int append_reply(client_t *c, const char *buf, size_t n) {
    if (n == 0) return 0;
    if (c->reply_len + n + 1 > c->reply_cap) {
        size_t newcap = (c->reply_cap == 0) ? BUF_SIZE : c->reply_cap * 2;
        while (newcap < c->reply_len + n + 1)
            newcap *= 2;
        char *p = realloc(c->reply, newcap);
        if (!p) {
            printf("ERROR: realloc failed\n");
            return -1;
        }
        c->reply = p;
        c->reply_cap = newcap;
    }
    memcpy(c->reply + c->reply_len, buf, n);
    c->reply_len += n;
    c->reply[c->reply_len] = '\0';
    return 0;
}

/* Print libssh error and transition to error */
static void set_error(client_t *c, const char *msg) {
    printf("ERROR: %s: %s\n", msg, ssh_get_error(c->session));
    c->state = S_ERROR;
}

/* Initialize write buffer for sending data */
static void init_write_buffer(client_t *c, const char *data) {
    c->write_buf.data = data;
    c->write_buf.len = strlen(data);
    c->write_buf.sent = 0;
}

/* Generic write operation - returns 1 if complete, 0 if more needed, -1 if error */
static int do_write(client_t *c, enum client_operation operation) {
    if (c->write_buf.sent >= c->write_buf.len) {
        return 1; /* complete */
    }

    int wrote = ssh_channel_write(c->channel, c->write_buf.data + c->write_buf.sent,
                                 (uint32_t)(c->write_buf.len - c->write_buf.sent));

    if (wrote > 0) {
        c->write_buf.sent += (size_t)wrote;
        if (c->write_buf.sent >= c->write_buf.len) {
            printf("%s fully sent\n", client_operation_to_str(operation));
            return 1; /* complete */
        }
        return 0; /* more data to send */
    } else if (wrote == SSH_ERROR) {
        char error_msg[256];
        snprintf(error_msg, sizeof(error_msg), "ssh_channel_write failed for %s", client_operation_to_str(operation));
        set_error(c, error_msg);
        return -1; /* error */
    } else if (wrote == SSH_AGAIN || wrote == 0) {
        return 0; /* not writable now */
    } else {
        char error_msg[256];
        snprintf(error_msg, sizeof(error_msg), "ssh_channel_write returned unexpected value for %s", client_operation_to_str(operation));
        set_error(c, error_msg);
        return -1; /* error */
    }
}

/* Generic read operation - returns 1 if complete, 0 if more needed, -1 if error */
static int do_read(client_t *c, enum client_operation operation, enum client_state next_state) {
    char buf[BUF_SIZE];
    int n = ssh_channel_read_nonblocking(c->channel, buf, sizeof(buf)-1, 0);

    if (n > 0) {
        if (append_reply(c, buf, (size_t)n) != 0) {
            set_error(c, "realloc failed");
            return -1;
        }
        printf("Read %s %d bytes (total %zu)\n", client_operation_to_str(operation), n, c->reply_len);

        /* Check for RFC6242 end-of-message token */
        if (strstr(c->reply, "]]>]]>") != NULL) {
            printf("=== NETCONF %s ===\n%s\n=== end ===\n", client_operation_to_str(operation), c->reply);
            // save response so it can be returned
            if (operation == OP_GET_REPLY) {
                c->response = strdup(c->reply);
            }
            /* Reset reply buffer for next message */
            c->reply_len = 0;
            c->reply[0] = '\0';
            c->state = next_state;
            return 1; /* complete */
        }
        return 0; /* more data expected */
    } else if (n == 0) {
        if (ssh_channel_is_eof(c->channel)) {
            printf("Channel EOF during %s\n", client_operation_to_str(operation));
            if (c->reply_len > 0) {
                printf("=== NETCONF %s (partial) ===\n%s\n=== end ===\n", client_operation_to_str(operation), c->reply);
            }
            c->state = S_CLEANUP;
            return 1; /* complete via EOF */
        }
        return 0; /* no data now, wait */
    } else {
        char error_msg[256];
        snprintf(error_msg, sizeof(error_msg), "ssh_channel_read_nonblocking failed during %s", client_operation_to_str(operation));
        set_error(c, error_msg);
        return -1; /* error */
    }
}

/* Called whenever the polled fd has activity (readable/writable) */
static void poll_cb(uv_poll_t *handle, int status, int events) {
    (void)status;
    int rc = 0;
    client_t *c = (client_t*)handle->data;

    if (c->state == S_DONE || c->state == S_ERROR) {
        if (c->state == S_DONE)
            printf("uv loop is done. stopping it\n");
        else if (c->state == S_ERROR)
            printf("uv loop encountered and error. stopping it\n");
        uv_poll_stop(c->poll);
        return;
    }

    /* Drive a simple state machine */
    switch (c->state) {
    case S_CONNECT:
        rc = ssh_connect(c->session);
        if (rc == SSH_OK) {
            printf("Connected (SSH_OK)\n");
            c->state = S_AUTH;
        } else if (rc == SSH_AGAIN) {
            return;
        } else {
            set_error(c, "ssh_connect failed");
            return;
        }
        /* fallthrough */
    case S_AUTH:
        rc = ssh_userauth_password(c->session, NULL, c->password);
        if (rc == SSH_AUTH_SUCCESS) {
            printf("Authenticated (password)\n");
            c->state = S_CHANNEL_OPEN;
        } else if (rc == SSH_AUTH_AGAIN) {
            return;
        } else {
            set_error(c, "ssh_userauth_password failed");
            return;
        }
        /* fallthrough */
    case S_CHANNEL_OPEN:
        if (!c->channel) {
            c->channel = ssh_channel_new(c->session);
            if (!c->channel) {
                set_error(c, "ssh_channel_new failed");
                return;
            }
        }
        rc = ssh_channel_open_session(c->channel);
        if (rc == SSH_OK) {
            printf("Channel opened\n");
            c->state = S_SUBSYSTEM;
        } else if (rc == SSH_AGAIN) {
            return;
        } else {
            set_error(c, "ssh_channel_open_session failed");
            return;
        }
        /* fallthrough */
    case S_SUBSYSTEM:
        rc = ssh_channel_request_subsystem(c->channel, c->subsystem);
        if (rc == SSH_OK) {
            printf("Requested subsystem: '%s'\n", c->subsystem);
            init_write_buffer(c, NETCONF_HELLO_MSG);
            c->state = S_SEND_HELLO;
        } else if (rc == SSH_AGAIN) {
            return;
        } else {
            set_error(c, "ssh_channel_request_subsystem failed");
            return;
        }
        /* fallthrough */
    case S_SEND_HELLO:
        rc = do_write(c, OP_HELLO);
        if (rc == 1) {
            c->state = S_RECV_HELLO;
        } else if (rc == -1) {
            return;
        }
        break;
    case S_RECV_HELLO:
        rc = do_read(c, OP_HELLO_REPLY, S_SEND_GET);
        if (rc == -1)
            return;
        break;
    case S_SEND_GET:
        init_write_buffer(c, c->payload);
        c->state = S_SEND_GET_WRITING;
        /* fallthrough */
    case S_SEND_GET_WRITING:
        rc = do_write(c, OP_GET);
        if (rc == 1) {
            c->state = S_RECV_GET;
        } else if (rc == -1) {
            return;
        }
        break;
    case S_RECV_GET:
        rc = do_read(c, OP_GET_REPLY, S_CLOSE);
        if (rc == -1)
            return;
        break;
    case S_CLOSE:
        init_write_buffer(c, NETCONF_CLOSE_SESSION_MSG);
        c->state = S_CLOSE_WRITING;
        /* fallthrough */
    case S_CLOSE_WRITING:
        rc = do_write(c, OP_CLOSE);
        if (rc == 1) {
            printf("Close message fully sent, waiting for reply\n");
            c->state = S_RECV_CLOSE_REPLY;
        } else if (rc == -1) {
            return;
        }
        break;
    case S_RECV_CLOSE_REPLY:
        rc = do_read(c, OP_CLOSE_REPLY, S_CLEANUP);
        if (rc == -1)
            return;
        break;
    case S_CLEANUP:
        c->state = S_DONE;
        printf("Disconnected and cleaned up\n");
        uv_poll_stop(c->poll);
        uv_stop(c->loop);
        return;
    default:
        return;
    }
}

// Walk callback to close remaining handles
static void close_walk_cb(uv_handle_t* handle, void* arg) {
    if (!uv_is_closing(handle)) {
        uv_close(handle, NULL);
    }
}

void noop_free(void *ptr) {
}

void sshQ___ext_init__() {
    // TODO: can we avoid custom malloc in libssh? like let libssh use stock
    // malloc and instead we would explicitly call free() from a finalizer()
    // All things related to buffers for receiving data and similarly would have
    // to be allocated on the GC-heap though since that data is passed outside
    // of the SSH actor
    // libssh_replace_allocator(
    //     acton_gc_malloc,
    //     acton_gc_realloc,
    //     acton_gc_calloc,
    //     noop_free,
    //     acton_gc_strdup,
    //     acton_gc_strndup);
    int r = ssh_init();
    if (r != SSH_OK)
        printf("SSH init failed (%d)\n", r);
#ifdef DEBUG_MODE
    else
        printf("SSH extension successfully initialized\n");
#endif
}

B_str sshQ_version() {
    return to$str("0.1.0");
}

// Client

$R sshQ_ClientD__pin_affinityG_local (sshQ_Client self, $Cont c$cont) {
    pin_actor_affinity();
    return $R_CONT(c$cont, B_None);
}

$R sshQ_ClientD__initG_local (sshQ_Client self, $Cont c$cont) {
    pin_actor_affinity();

    int err = 0;

    client_t *client = calloc(1, sizeof(client_t));
    if (client == NULL) {
        printf("error allocating client_t\n");
        return $R_CONT(c$cont, B_None);
    }

    client->loop = uv_default_loop();

    client->session = ssh_new();
    if (client->session == NULL) {
        printf("%s: ssh_new() Failed to create SSH session\n", __FUNCTION__);
        return $R_CONT(c$cont, B_None);
    }

    client->poll = NULL;
    client->channel = NULL;
    client->reply = NULL;
    client->reply_len = 0;
    client->reply_cap = 0;
    client->state = S_CONNECT;

    /* Initialize write buffer to empty */
    client->write_buf.data = NULL;
    client->write_buf.len = 0;
    client->write_buf.sent = 0;

    client->host = (const char *)fromB_str(self->host);
    client->port = self->port->val;
    client->user = (const char *)fromB_str(self->username);
    client->password = (const char *)fromB_str(self->password);
    client->subsystem = (const char *)fromB_str(self->subsystem);

#ifdef DEBUG_MODE
    // available: SSH_LOG_NOLOG, SSH_LOG_WARNING, SSH_LOG_PROTOCOL, SSH_LOG_PACKET, SSH_LOG_FUNCTIONS
    err = ssh_set_log_level(SSH_LOG_FUNCTIONS);
    if (err != SSH_OK)
    {
        printf("%s: ssh_set_log_level() Error setting log level: %d\n", __FUNCTION__, err);
        return $R_CONT(c$cont, B_None);
    }
#endif

    err = ssh_session_set_disconnect_message(client->session, "Disconnecting SSH, powered by Acton");
    if (err != SSH_OK) {
        printf("%s: ssh_session_set_disconnect_message() Error setting disconnect message: %d\n", __FUNCTION__, err);
        return $R_CONT(c$cont, B_None);
    }

    err = ssh_options_set(client->session, SSH_OPTIONS_HOST, client->host);
    if (err != SSH_OK) {
        printf("%s: ssh_options_set() Error setting SSH option 'SSH_OPTIONS_HOST': %d\n", __FUNCTION__, err);
        return $R_CONT(c$cont, B_None);
    }

    err = ssh_options_set(client->session, SSH_OPTIONS_PORT, &client->port);
    if (err != SSH_OK) {
        printf("%s: ssh_options_set() Error setting SSH option 'SSH_OPTIONS_PORT': %d\n", __FUNCTION__, err);
        return $R_CONT(c$cont, B_None);
    }

    err = ssh_options_set(client->session, SSH_OPTIONS_USER, client->user);
    if (err != SSH_OK) {
        printf("%s: ssh_options_set() Error setting SSH option 'SSH_OPTIONS_USER': %d\n", __FUNCTION__, err);
        return $R_CONT(c$cont, B_None);
    }

    ssh_set_blocking(client->session, 0);

    // should it auto-parse user config? for example from /home/user/.ssh/
    // err = ssh_options_set(session, SSH_OPTIONS_PROCESS_CONFIG, "0");
	// if (err != SSH_OK) {
	// 	printf("%s: ssh_options_set() Error setting SSH option 'SSH_OPTIONS_PROCESS_CONFIG': %d\n", __FUNCTION__, err);
	// 	return  $R_CONT(c$cont, B_None);
	// }

    err = ssh_connect(client->session);
    if (err == SSH_ERROR) {
        printf("%s: ssh_connect() Error connecting to SSH server: '%s' (%d)\n", __FUNCTION__, ssh_get_error(client->session), err);
        return $R_CONT(c$cont, B_None);
    }

    // At this point ssh_get_fd should return a valid fd for uv_poll
    client->fd = ssh_get_fd(client->session);
    if (client->fd < 0) {
        printf("Could not get SSH session fd\n");
        ssh_disconnect(client->session);
        ssh_free(client->session);
        return $R_CONT(c$cont, B_None);
    }

    client->poll = calloc(1, sizeof(uv_poll_t));
    if (!client->poll) {
        printf("Failed to allocate poll handle\n");
        ssh_disconnect(client->session);
        ssh_free(client->session);
        return $R_CONT(c$cont, B_None);
    }

    err = uv_poll_init(client->loop, client->poll, client->fd);
    if (err < 0) {
        printf("uv_poll_init failed: %s\n", uv_strerror(err));
        free(client->poll);
        client->poll = NULL;
        ssh_disconnect(client->session);
        ssh_free(client->session);
        return $R_CONT(c$cont, B_None);
    }
    client->poll->data = client;

    /* Watch for read/write events; libssh manages what it needs depending on state */
    err = uv_poll_start(client->poll, UV_READABLE | UV_WRITABLE, poll_cb);
    if (err < 0) {
        printf("uv_poll_start failed: %s\n", uv_strerror(err));
        uv_close((uv_handle_t*)client->poll, NULL);
        free(client->poll);
        client->poll = NULL;
        ssh_disconnect(client->session);
        ssh_free(client->session);
        return $R_CONT(c$cont, B_None);
    }

    self->_client = toB_u64((unsigned long)client);

    $action f = ($action) self->on_connect;
    f->$class->__asyn__(f, self);

    return $R_CONT(c$cont, B_None);
}

$R sshQ_ClientD_get_affinityG_local (sshQ_Client self, $Cont c$cont) {
    printf("sshQ_ClientD_get_affinityG_local, affinity=%ld\n", self->$affinity);
    return $R_CONT(c$cont, B_None);
}

$R sshQ_ClientD_send_nc_payloadG_local (sshQ_Client self, $Cont c$cont) {
    int err = 0;

    client_t *client = (client_t*)fromB_u64(self->_client);
    if (client == NULL) {
        printf("ERROR: client == NULL\n");
        goto err_out;
    }

    client->payload = (const char *)fromB_str(self->_payload);

#ifdef DEBUG_MODE
    printf("Starting libuv loop client\n");
#endif
    uv_run(client->loop, UV_RUN_DEFAULT);
#ifdef DEBUG_MODE
    printf("Stopped libuv loop client\n");
#endif

    return $R_CONT(c$cont, client->response ? to$str(client->response) : B_None);
err_out:
    return $R_CONT(c$cont, B_None);
}

$R sshQ_ClientD_disconnectG_local (sshQ_Client self, $Cont c$cont) {
    int err = 0;

    if (self == NULL || self->_client == NULL) {
        printf("self->_client == NULL\n");
        goto out;
    }
    client_t *client = (client_t*)fromB_u64(self->_client);
    if (client == NULL) {
        printf("client == NULL, nothing to cleanup\n");
        goto out;
    }

    /* cleanup */
    /* graceful close of ssh channel & session */
    if (client->channel) {
        ssh_channel_send_eof(client->channel);
        ssh_channel_close(client->channel);
        ssh_channel_free(client->channel);
        client->channel = NULL;
    }
    if (client->session) {
        ssh_disconnect(client->session);
        ssh_free(client->session);
    }

    if (client->loop) {
        // see MAKE_VALGRIND_HAPPY in libuv/test/task.h
        // walk the loop to close any remaining handles
        uv_walk(client->loop, close_walk_cb, NULL);
        // run the loop one more time to let close callbacks execute
        uv_run(client->loop, UV_RUN_DEFAULT);

        // now it's safe to close the loop
        err = uv_loop_close(client->loop);
        if (err != 0) {
            printf("WARNING: Loop close failed: %s\n", uv_strerror(err));

            // If we still have handles, print debug info
            if (err == UV_EBUSY) {
                printf("There are still active handles in the loop. This is a leak.\n");
            }
        }
        uv_library_shutdown();
    }

    if (client->reply) {
        free(client->reply);
        client->reply = NULL;
    }
    if (client->response) {
        free(client->response);
        client->response = NULL;
    }
    if (client->poll) {
        free(client->poll);
        client->poll = NULL;
    }
    if (client) {
        free(client);
        client = NULL;
    }

    if (ssh_finalize()) {
        printf("%s: ssh_finalize error", __FUNCTION__);
    }
out:
    return $R_CONT(c$cont, B_None);
}
