/*
 * async_netconf_client_2.c
 *
 * Non-blocking NETCONF hello exchange using libssh (non-blocking) + libuv (uv_poll)
 *
 * Build:
 *   gcc -o ancc2 async_netconf_client_2.c -lssh -luv
 *
 * Usage:
 *   ./ancc2 <host> <port> <username> <password>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <libssh/libssh.h>

#include <uv.h>

#define BUF_SIZE 512

const char *NETCONF_HELLO = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                           "<hello xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
                           "  <capabilities>\n"
                           "    <capability>urn:ietf:params:netconf:base:1.0</capability>\n"
                           "  </capabilities>\n"
                           "</hello>\n"
                           "]]>]]>";

const char *NETCONF_GET_CONFIG = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                                "<rpc xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\" message-id=\"10\">\n"
                                "  <get-config>\n"
                                "    <source>\n"
                                "      <running/>\n"
                                "    </source>\n"
                                "  </get-config>\n"
                                "</rpc>\n"
                                "]]>]]>";

const char *NETCONF_CLOSE_SESSION = "<rpc message-id=\"101\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
                                    "  <close-session/>\n"
                                    "</rpc>\n"
                                    "]]>]]>";

enum client_state {
    S_CONNECT,
    S_AUTH,
    S_CHANNEL_OPEN,
    S_SUBSYSTEM,
    S_SEND_HELLO,
    S_RECV_HELLO,
    S_SEND_GET_CONFIG,
    S_SEND_GET_CONFIG_WRITING,
    S_RECV_GET_CONFIG,
    S_CLOSE,
    S_CLOSE_WRITING,
    S_RECV_CLOSE_REPLY,
    S_CLEANUP,
    S_DONE,
    S_ERROR
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
    int fd;
    enum client_state state;
    const char *host;
    int port;
    const char *user;
    const char *password;

    /* current write buffer */
    write_buffer_t write_buf;

    /* read buffer */
    char *reply;
    size_t reply_len;
    size_t reply_cap;
} client_t;

/* Simple helper to append to reply buffer */
static int append_reply(client_t *c, const char *buf, size_t n) {
    if (n == 0) return 0;
    if (c->reply_len + n + 1 > c->reply_cap) {
        size_t newcap = (c->reply_cap == 0) ? BUF_SIZE : c->reply_cap * 2;
        while (newcap < c->reply_len + n + 1)
            newcap *= 2;
        char *p = realloc(c->reply, newcap);
        if (!p) {
            fprintf(stderr, "ERROR: realloc failed\n");
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
    fprintf(stderr, "ERROR: %s: %s\n", msg, ssh_get_error(c->session));
    c->state = S_ERROR;
}

/* Initialize write buffer for sending data */
static void init_write_buffer(client_t *c, const char *data) {
    c->write_buf.data = data;
    c->write_buf.len = strlen(data);
    c->write_buf.sent = 0;
}

/* Generic write operation - returns 1 if complete, 0 if more needed, -1 if error */
static int do_write(client_t *c, const char *operation) {
    if (c->write_buf.sent >= c->write_buf.len) {
        return 1; /* complete */
    }

    int wrote = ssh_channel_write(c->channel,
                                 c->write_buf.data + c->write_buf.sent,
                                 (uint32_t)(c->write_buf.len - c->write_buf.sent));
    
    if (wrote > 0) {
        c->write_buf.sent += (size_t)wrote;
        if (c->write_buf.sent >= c->write_buf.len) {
            fprintf(stderr, "%s fully sent\n", operation);
            return 1; /* complete */
        }
        return 0; /* more data to send */
    } else if (wrote == SSH_ERROR) {
        char error_msg[256];
        snprintf(error_msg, sizeof(error_msg), "ssh_channel_write failed for %s", operation);
        set_error(c, error_msg);
        return -1; /* error */
    } else if (wrote == SSH_AGAIN || wrote == 0) {
        return 0; /* not writable now */
    } else {
        char error_msg[256];
        snprintf(error_msg, sizeof(error_msg), "ssh_channel_write returned unexpected value for %s", operation);
        set_error(c, error_msg);
        return -1; /* error */
    }
}

/* Generic read operation - returns 1 if complete, 0 if more needed, -1 if error */
static int do_read(client_t *c, const char *operation, enum client_state next_state) {
    char buf[BUF_SIZE];
    int n = ssh_channel_read_nonblocking(c->channel, buf, sizeof(buf)-1, 0);
    
    if (n > 0) {
        if (append_reply(c, buf, (size_t)n) != 0) {
            set_error(c, "realloc failed");
            return -1;
        }
        fprintf(stderr, "Read %s %d bytes (total %zu)\n", operation, n, c->reply_len);
        
        /* Check for RFC6242 end-of-message token */
        if (strstr(c->reply, "]]>]]>") != NULL) {
            fprintf(stdout, "=== NETCONF %s ===\n%s\n=== end ===\n", operation, c->reply);
            /* Reset reply buffer for next message */
            c->reply_len = 0;
            c->reply[0] = '\0';
            c->state = next_state;
            return 1; /* complete */
        }
        return 0; /* more data expected */
    } else if (n == 0) {
        if (ssh_channel_is_eof(c->channel)) {
            fprintf(stderr, "Channel EOF during %s\n", operation);
            if (c->reply_len > 0) {
                fprintf(stdout, "=== NETCONF %s (partial) ===\n%s\n=== end ===\n", operation, c->reply);
            }
            c->state = S_CLEANUP;
            return 1; /* complete via EOF */
        }
        return 0; /* no data now, wait */
    } else {
        char error_msg[256];
        snprintf(error_msg, sizeof(error_msg), "ssh_channel_read_nonblocking failed during %s", operation);
        set_error(c, error_msg);
        return -1; /* error */
    }
}

/* Called whenever the polled fd has activity (readable/writable) */
static void poll_cb(uv_poll_t *handle, int status, int events) {
    (void)status;
    client_t *c = (client_t*)handle->data;
    int rc = 0;

    if (c->state == S_DONE || c->state == S_ERROR) {
        printf("uv_poll_stop\n");
        uv_poll_stop(c->poll);
        return;
    }

    /* Drive a simple state machine */
    switch (c->state) {
    case S_CONNECT:
        rc = ssh_connect(c->session);
        if (rc == SSH_OK) {
            fprintf(stderr, "Connected (SSH_OK)\n");
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
            fprintf(stderr, "Authenticated (password)\n");
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
            fprintf(stderr, "Channel opened\n");
            c->state = S_SUBSYSTEM;
        } else if (rc == SSH_AGAIN) {
            return;
        } else {
            set_error(c, "ssh_channel_open_session failed");
            return;
        }
        /* fallthrough */
    case S_SUBSYSTEM:
        rc = ssh_channel_request_subsystem(c->channel, "netconf");
        if (rc == SSH_OK) {
            fprintf(stderr, "Requested subsystem: netconf\n");
            init_write_buffer(c, NETCONF_HELLO);
            c->state = S_SEND_HELLO;
        } else if (rc == SSH_AGAIN) {
            return;
        } else {
            set_error(c, "ssh_channel_request_subsystem failed");
            return;
        }
        /* fallthrough */
    case S_SEND_HELLO:
        rc = do_write(c, "Hello");
        if (rc == 1) {
            c->state = S_RECV_HELLO;
        } else if (rc == -1) {
            return;
        }
        break;
    case S_RECV_HELLO:
        rc = do_read(c, "hello reply", S_SEND_GET_CONFIG);
        if (rc == -1)
            return;
        break;
    case S_SEND_GET_CONFIG:
        init_write_buffer(c, NETCONF_GET_CONFIG);
        c->state = S_SEND_GET_CONFIG_WRITING;
        /* fallthrough */
    case S_SEND_GET_CONFIG_WRITING:
        rc = do_write(c, "GET_CONFIG");
        if (rc == 1) {
            c->state = S_RECV_GET_CONFIG;
        } else if (rc == -1) {
            return;
        }
        break;
    case S_RECV_GET_CONFIG:
        rc = do_read(c, "GET_CONFIG reply", S_CLOSE);
        if (rc == -1)
            return;
        break;
    case S_CLOSE:
        init_write_buffer(c, NETCONF_CLOSE_SESSION);
        c->state = S_CLOSE_WRITING;
        /* fallthrough */
    case S_CLOSE_WRITING:
        rc = do_write(c, "Close message");
        if (rc == 1) {
            fprintf(stderr, "Close message fully sent, waiting for reply\n");
            c->state = S_RECV_CLOSE_REPLY;
        } else if (rc == -1) {
            return;
        }
        break;
    case S_RECV_CLOSE_REPLY:
        rc = do_read(c, "close reply", S_CLEANUP);
        if (rc == -1)
            return;
        break;
    case S_CLEANUP:
        c->state = S_DONE;
        fprintf(stderr, "Disconnected and cleaned up\n");
        uv_poll_stop(c->poll);
        uv_stop(c->loop);
        return;
    default:
        return;
    }
}

/* Helper: initialize session and uv poll */
static int client_init(client_t *c) {
    c->session = ssh_new();
    if (!c->session) {
        fprintf(stderr, "ERROR: ssh_new error");
        return -1;
    }
    ssh_options_set(c->session, SSH_OPTIONS_HOST, c->host);
    ssh_options_set(c->session, SSH_OPTIONS_PORT, &c->port);
    ssh_options_set(c->session, SSH_OPTIONS_USER, c->user);

    /* Non-blocking mode */
    ssh_set_blocking(c->session, 0);

    c->channel = NULL;
    c->poll = NULL;
    c->reply = NULL;
    c->reply_len = 0;
    c->reply_cap = 0;
    c->state = S_CONNECT;
    
    /* Initialize write buffer to empty */
    c->write_buf.data = NULL;
    c->write_buf.len = 0;
    c->write_buf.sent = 0;

    return 0;
}

// Walk callback to close remaining handles
static void close_walk_cb(uv_handle_t* handle, void* arg) {
    if (!uv_is_closing(handle)) {
        uv_close(handle, NULL);
    }
}

int main(int argc, char **argv) {
    if (argc < 5) {
        fprintf(stderr, "Usage: %s <host> <port> <username> <password>\n", argv[0]);
        return 1;
    }
    client_t client = { 0 };

    client.host = argv[1];
    client.port = atoi(argv[2]);
    client.user = argv[3];
    client.password = argv[4];

    if (client_init(&client) != 0) {
        fprintf(stderr, "Failed to init client\n");
        return 2;
    }

    /* create the uv loop and poll handle*/
    client.loop = uv_default_loop();

    /* We need to ensure we have a valid fd to initialize uv_poll */
    int err = ssh_connect(client.session);
    if (err == SSH_ERROR) {
        fprintf(stderr, "Initial ssh_connect failed: %s\n", ssh_get_error(client.session));
        ssh_free(client.session);
        return 3;
    }
    /* At this point ssh_get_fd should return a valid fd for uv_poll */
    client.fd = ssh_get_fd(client.session);
    if (client.fd < 0) {
        fprintf(stderr, "Could not get SSH session fd\n");
        ssh_disconnect(client.session);
        ssh_free(client.session);
        return 4;
    }

    client.poll = malloc(sizeof(uv_poll_t));
    if (!client.poll) {
        fprintf(stderr, "Failed to allocate poll handle\n");
        ssh_disconnect(client.session);
        ssh_free(client.session);
        return 5;
    }

    err = uv_poll_init(client.loop, client.poll, client.fd);
    if (err < 0) {
        fprintf(stderr, "uv_poll_init failed: %s\n", uv_strerror(err));
        free(client.poll);
        client.poll = NULL;
        ssh_disconnect(client.session);
        ssh_free(client.session);
        return 6;
    }
    client.poll->data = &client;

    /* Watch for read/write events; libssh manages what it needs depending on state */
    err = uv_poll_start(client.poll, UV_READABLE | UV_WRITABLE, poll_cb);
    if (err < 0) {
        fprintf(stderr, "uv_poll_start failed: %s\n", uv_strerror(err));
        uv_close((uv_handle_t*)client.poll, NULL);
        free(client.poll);
        client.poll = NULL;
        ssh_disconnect(client.session);
        ssh_free(client.session);
        return 7;
    }

    /* If the preliminary ssh_connect returned SSH_AGAIN, the state should still be CONNECT.
       Otherwise, poll_cb will drive the next steps. */
    fprintf(stderr, "Starting libuv loop\n");
    uv_run(client.loop, UV_RUN_DEFAULT);
    fprintf(stderr, "Stopped libuv loop\n");

    /* cleanup */
    /* graceful close of ssh channel & session */
    if (client.channel) {
        ssh_channel_send_eof(client.channel);
        ssh_channel_close(client.channel);
        ssh_channel_free(client.channel);
        client.channel = NULL;
    }
    if (client.session) {
        ssh_disconnect(client.session);
        ssh_free(client.session);
    }

    // see MAKE_VALGRIND_HAPPY in libuv/test/task.h
    // walk the loop to close any remaining handles
    uv_walk(client.loop, close_walk_cb, NULL);
    // run the loop one more time to let close callbacks execute
    uv_run(client.loop, UV_RUN_DEFAULT);

    // now it's safe to close the loop
    err = uv_loop_close(client.loop);
    if (err != 0) {
        fprintf(stderr, "WARNING: Loop close failed: %s\n", uv_strerror(err));

        // If we still have handles, print debug info
        if (err == UV_EBUSY) {
            fprintf(stderr, "There are still active handles in the loop. This is a leak.\n");
        }
    }
    uv_library_shutdown();

    if (client.reply)
        free(client.reply);

    if (client.poll)
        free(client.poll);

    fprintf(stderr, "Exited\n");
    return (client.state == S_DONE) ? 0 : 7;
}
