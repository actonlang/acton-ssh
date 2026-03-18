/*
 * Acton <-> libssh integration overview
 *
 * This file is the external-C glue that drives libssh from Acton's libuv loop
 * and exposes it to Acton actors. The core goals are:
 *   - Nonblocking SSH I/O integrated with libuv (no blocking syscalls).
 *   - Actor-safe, async callback-driven API in Acton.
 *   - GC-safe memory: libssh allocations use Acton's allocator.
 *
 * Event loop integration
 *   - Each libssh session is created nonblocking.
 *   - We attach a uv_poll watcher to the libssh socket fd.
 *   - On poll events we call ssh_session_handle_poll() (via
 *     session_apply_poll_events), then drive a small state machine
 *     (connect/auth/ready for client, keyex/auth/ready for server).
 *   - ssh_get_poll_flags()/ssh_get_status() decide which poll events to arm.
 *
 * Buffered data + SSH_AGAIN (why we keep driving without fd readability)
 *   - libssh maintains its own internal buffers. After a poll callback, libssh
 *     may have already read bytes into those buffers even though the socket is
 *     no longer readable at the OS level.
 *   - When a nonblocking API returns SSH_AGAIN and ssh_get_status() includes
 *     SSH_READ_PENDING, it means "call again, there is buffered data to
 *     process" even if the fd will not trigger another readable event.
 *   - If we only wait for uv_poll readability, we can deadlock:
 *       1) uv_poll READABLE fires; ssh_session_handle_poll() drains the fd.
 *       2) ssh_connect()/ssh_handle_key_exchange()/ssh_userauth_password()
 *          returns SSH_AGAIN.
 *       3) No more kernel readability events happen, but libssh still has
 *          buffered protocol bytes (SSH_READ_PENDING).
 *       4) We wait for an event that never comes and eventually time out.
 *   - The fix is to keep driving the state machine in a bounded loop while
 *     SSH_READ_PENDING is set, even without fd readability.
 *     We cap iterations with SSH_IO_PUMP_LIMIT to avoid CPU spin.
 *
 * Channel I/O
 *   - SSH channels carry two streams: "data" and "extended data". We expose
 *     these as stdout/stderr callbacks (client on_stdout/on_stderr, server
 *     on_data/on_stderr). This is protocol-level stdout/stderr, not host OS
 *     process stdio.
 *   - Channels install libssh callbacks for data/extended-data/EOF/close.
 *   - Inbound data always flows through these callbacks. As we drive libssh
 *     (via ssh_session_handle_poll), libssh invokes the registered C callback
 *     functions, and those callbacks call the corresponding Acton action
 *     methods (foo->$class->on_stdout/on_stderr/on_close, etc.). We do not run
 *     manual read loops; libssh owns buffering and read state.
 *   - Channel writes are queued and flushed when libssh reports write pending.
 *
 * Actor/GC/threading model
 *   - Client and ServerSession actors own libssh state and are pinned to a
 *     worker thread. Channel actors invoke action methods on their owning
 *     Client/ServerSession actor for all operations; there is no hidden
 *     cross-actor C magic.
 *   - We replace libssh allocators with Acton's GC allocator so libuv/GC
 *     roots remain visible (libssh structures can reference GC memory).
 *
 * Config & filesystem
 *   - libssh config processing is disabled by default; known_hosts is only
 *     read if explicitly configured by the Acton API.
 *   - Server host keys are generated in-memory unless a path is provided.
 */
#include <errno.h>
#include <fcntl.h>
#include <libssh/libssh.h>
#include <libssh/callbacks.h>
#include <libssh/server.h>
#include <poll.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <uv.h>

#include "rts/log.h"

uv_loop_t *get_uv_loop(void);
extern struct $Cont $Done$instance;

#define SSH_READ_BUFSIZE 4096
#define SSH_IO_PUMP_LIMIT 128
static int ssh_debug_enabled = 0;
static int ssh_libssh_log_level = SSH_LOG_NOLOG;

typedef enum {
    CLIENT_STATE_INIT = 0,
    CLIENT_STATE_CONNECTING,
    CLIENT_STATE_HOSTKEY,
    CLIENT_STATE_HOSTKEY_WAIT,
    CLIENT_STATE_AUTH,
    CLIENT_STATE_READY,
    CLIENT_STATE_ERROR,
    CLIENT_STATE_CLOSING,
    CLIENT_STATE_CLOSED,
} client_state_t;

typedef enum {
    CHAN_STATE_INIT = 0,
    CHAN_STATE_OPENING,
    CHAN_STATE_OPEN,
    CHAN_STATE_RUNNING,
    CHAN_STATE_CLOSING,
    CHAN_STATE_CLOSED,
    CHAN_STATE_ERROR,
} channel_state_t;

typedef enum {
    CHAN_REQ_NONE = 0,
    CHAN_REQ_SHELL,
    CHAN_REQ_EXEC,
    CHAN_REQ_SUBSYSTEM,
} channel_request_t;

typedef struct write_chunk {
    B_bytes data;
    size_t offset;
    struct write_chunk *next;
} write_chunk_t;

typedef struct ssh_channel_ctx {
    struct ssh_channel_ctx *next;
    ssh_channel channel;
    struct ssh_channel_callbacks_struct *callbacks;
    sshQ_Channel actor;
    channel_state_t state;
    channel_request_t pending_req;
    int pty_pending;
    int pty_done;
    B_str exec_cmd;
    B_str subsystem;
    B_str term;
    int cols;
    int rows;
    int width_px;
    int height_px;
    int send_eof;
    int eof_sent;
    int close_requested;
    int close_sent;
    int remote_close_seen;
    int write_wontblock;
    int stdout_eof;
    int stderr_eof;
    int exit_sent;
    int open_notified;
    int open_succeeded;
    int close_notified;
    $action2 on_open;
    $action2 on_close;
    $action2 on_stdout;
    $action2 on_stderr;
    $action3 on_exit;
    write_chunk_t *write_head;
    write_chunk_t *write_tail;
} ssh_channel_ctx;

typedef struct ssh_client_ctx {
    sshQ_Client actor;
    ssh_session session;
    uv_poll_t *poll;
    int poll_events;
    uv_timer_t *connect_timer;
    uv_timer_t *auth_timer;
    uv_timer_t *keepalive_timer;
    double connect_timeout;
    double auth_timeout;
    double keepalive_interval;
    int keepalive_enabled;
    client_state_t state;
    int fd;
    int connect_notified;
    int connected_ok;
    int close_notified;
    int close_finalized;
    int write_ready;
    char *close_reason;
    enum ssh_known_hosts_e hostkey_state;
    ssh_channel_ctx *channels;
    $action2 on_connect;
    $action2 on_close;
    $action3 on_hostkey;
} ssh_client_ctx;

typedef enum {
    SERVER_STATE_INIT = 0,
    SERVER_STATE_LISTENING,
    SERVER_STATE_ERROR,
    SERVER_STATE_CLOSING,
    SERVER_STATE_CLOSED,
} server_state_t;

typedef enum {
    SESSION_STATE_PENDING = 0,
    SESSION_STATE_KEYEX,
    SESSION_STATE_AUTH,
    SESSION_STATE_READY,
    SESSION_STATE_ERROR,
    SESSION_STATE_CLOSING,
    SESSION_STATE_CLOSED,
} session_state_t;

typedef enum {
    SCHAN_STATE_OPEN = 0,
    SCHAN_STATE_CLOSING,
    SCHAN_STATE_CLOSED,
    SCHAN_STATE_ERROR,
} schan_state_t;

typedef enum {
    SCHAN_REQ_NONE = 0,
    SCHAN_REQ_EXEC,
    SCHAN_REQ_SUBSYSTEM,
} schan_req_t;

typedef struct server_write_chunk {
    B_bytes data;
    size_t offset;
    int is_stderr;
    struct server_write_chunk *next;
} server_write_chunk_t;

typedef struct ssh_server_channel_ctx {
    struct ssh_server_channel_ctx *next;
    ssh_channel channel;
    struct ssh_channel_callbacks_struct *callbacks;
    struct ssh_server_session_ctx *session;
    sshQ_ServerChannel actor;
    schan_state_t state;
    int send_eof;
    int close_requested;
    int close_sent;
    int remote_close_seen;
    int write_wontblock;
    int eof_sent;
    int stdout_eof;
    int stderr_eof;
    int close_notified;
    ssh_message pending_req;
    schan_req_t pending_req_type;
    $action2 on_data;
    $action2 on_stderr;
    $action2 on_close;
    server_write_chunk_t *write_head;
    server_write_chunk_t *write_tail;
} ssh_server_channel_ctx;

typedef struct ssh_server_session_ctx {
    struct ssh_server_session_ctx *next;
    sshQ_ServerSession actor;
    struct ssh_server_ctx *server;
    ssh_session session;
    uv_poll_t *poll;
    int poll_events;
    uv_timer_t *auth_timer;
    uv_timer_t *keepalive_timer;
    double auth_timeout;
    double keepalive_interval;
    int keepalive_enabled;
    session_state_t state;
    int attached;
    int fd;
    int owner_wt;
    int write_ready;
    int close_notified;
    int close_finalized;
    char *close_reason;
    ssh_message pending_auth;
    ssh_message pending_channel_open;
    ssh_server_channel_ctx *channels;
    $action2 on_auth;
    $action on_channel_open;
    $action3 on_exec;
    $action3 on_subsystem;
    $action2 on_close;
} ssh_server_session_ctx;

typedef struct ssh_server_ctx {
    sshQ_Server actor;
    ssh_bind bind;
    ssh_key hostkey;
    uv_poll_t *poll;
    int fd;
    server_state_t state;
    int listen_notified;
    int listen_ok;
    int close_notified;
    int close_finalized;
    char *close_reason;
    ssh_server_session_ctx *sessions;
    $action2 on_listen;
    $action2 on_close;
} ssh_server_ctx;

static void client_drive(ssh_client_ctx *c);
static void client_update_poll(ssh_client_ctx *c);
static void client_close_internal(ssh_client_ctx *c, const char *reason);
static void client_finalize(ssh_client_ctx *c);
static void channel_drive(ssh_client_ctx *c, ssh_channel_ctx *ch);
static int client_needs_write(ssh_client_ctx *c);
static void client_pump_io(ssh_client_ctx *c);

static void server_accept(ssh_server_ctx *s);
static void server_close_internal(ssh_server_ctx *s, const char *reason);
static void server_finalize(ssh_server_ctx *s);
static void server_remove_session(ssh_server_ctx *s, ssh_server_session_ctx *sess);
static void session_drive(ssh_server_session_ctx *s);
static void session_update_poll(ssh_server_session_ctx *s);
static void session_pump_io(ssh_server_session_ctx *s);
static void session_close_internal(ssh_server_session_ctx *s, const char *reason);
static void session_finalize(ssh_server_session_ctx *s);
static void server_channel_drive(ssh_server_session_ctx *s, ssh_server_channel_ctx *ch);
static int session_needs_write(ssh_server_session_ctx *s);
static void session_poll_cb(uv_poll_t *handle, int status, int events);
static void server_poll_cb(uv_poll_t *handle, int status, int events);
static void session_auth_timeout_cb(uv_timer_t *timer);
static void session_keepalive_cb(uv_timer_t *timer);
static void client_poll_close_cb(uv_handle_t *handle);
static void client_timer_close_cb(uv_handle_t *handle);
static void server_poll_close_cb(uv_handle_t *handle);
static void session_poll_close_cb(uv_handle_t *handle);
static void session_timer_close_cb(uv_handle_t *handle);

static void ssh_debug_log(const char *fmt, ...) {
    if (!ssh_debug_enabled)
        return;
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, "\n");
    fflush(stderr);
}

static int parse_libssh_log_level(const char *value) {
    if (value == NULL || value[0] == '\0')
        return SSH_LOG_NOLOG;
    char *endptr = NULL;
    long lvl = strtol(value, &endptr, 10);
    if (endptr != value && endptr && *endptr == '\0') {
        if (lvl < 0)
            return SSH_LOG_NOLOG;
        if (lvl > SSH_LOG_TRACE)
            lvl = SSH_LOG_TRACE;
        return (int)lvl;
    }
    if (strcasecmp(value, "warn") == 0 || strcasecmp(value, "warning") == 0)
        return SSH_LOG_WARN;
    if (strcasecmp(value, "info") == 0 || strcasecmp(value, "protocol") == 0)
        return SSH_LOG_INFO;
    if (strcasecmp(value, "debug") == 0 || strcasecmp(value, "packet") == 0)
        return SSH_LOG_DEBUG;
    if (strcasecmp(value, "trace") == 0 || strcasecmp(value, "functions") == 0)
        return SSH_LOG_TRACE;
    if (strcasecmp(value, "none") == 0 || strcasecmp(value, "off") == 0)
        return SSH_LOG_NOLOG;
    return SSH_LOG_NOLOG;
}

static void ssh_log_cb(int priority, const char *function, const char *buffer, void *userdata) {
    (void)userdata;
    if (buffer == NULL)
        return;
    fprintf(stderr, "libssh[%d] %s: %s\n", priority, function ? function : "", buffer);
    fflush(stderr);
}

static void ssh_configure_libssh_logging(void) {
    if (ssh_libssh_log_level <= SSH_LOG_NOLOG)
        return;
    ssh_set_log_callback(ssh_log_cb);
    ssh_set_log_level(ssh_libssh_log_level);
}

static int session_apply_poll_events(ssh_session session, int events) {
    if (session == NULL)
        return -1;
    int revents = 0;
    if (events & UV_READABLE)
        revents |= POLLIN;
    if (events & UV_WRITABLE)
        revents |= POLLOUT;
#ifdef UV_DISCONNECT
    if (events & UV_DISCONNECT)
        revents |= POLLHUP;
#endif
#ifdef UV_PRIORITIZED
    if (events & UV_PRIORITIZED)
        revents |= POLLPRI;
#endif
    if (revents == 0)
        return 0;
    if (ssh_session_handle_poll(session, revents) != SSH_OK)
        return -1;
    return 0;
}

static const char *hostkey_state_str(enum ssh_known_hosts_e state) {
    switch (state) {
        case SSH_KNOWN_HOSTS_OK:
            return "ok";
        case SSH_KNOWN_HOSTS_UNKNOWN:
            return "unknown";
        case SSH_KNOWN_HOSTS_NOT_FOUND:
            return "not_found";
        case SSH_KNOWN_HOSTS_CHANGED:
            return "changed";
        case SSH_KNOWN_HOSTS_OTHER:
            return "other";
        case SSH_KNOWN_HOSTS_ERROR:
        default:
            return "error";
    }
}

static ssh_client_ctx *client_from_actor(sshQ_Client self) {
    if (self == NULL)
        return NULL;
    unsigned long ptr = fromB_u64(self->_client);
    if (ptr == 0)
        return NULL;
    return (ssh_client_ctx *)ptr;
}

static ssh_channel_ctx *channel_from_actor(sshQ_Channel channel) {
    if (channel == NULL)
        return NULL;
    unsigned long ptr = fromB_u64(channel->_channel_id);
    if (ptr == 0)
        return NULL;
    return (ssh_channel_ctx *)ptr;
}

static ssh_server_ctx *server_from_actor(sshQ_Server self) {
    if (self == NULL)
        return NULL;
    unsigned long ptr = fromB_u64(self->_server);
    if (ptr == 0)
        return NULL;
    return (ssh_server_ctx *)ptr;
}

static ssh_server_session_ctx *session_from_actor(sshQ_ServerSession self) {
    if (self == NULL)
        return NULL;
    unsigned long ptr = fromB_u64(self->_session_id);
    if (ptr == 0)
        return NULL;
    return (ssh_server_session_ctx *)ptr;
}

static ssh_server_channel_ctx *server_channel_from_actor(sshQ_ServerChannel channel) {
    if (channel == NULL)
        return NULL;
    unsigned long ptr = fromB_u64(channel->_channel_id);
    if (ptr == 0)
        return NULL;
    return (ssh_server_channel_ctx *)ptr;
}

static ssh_server_channel_ctx *server_channel_from_ssh(ssh_server_session_ctx *s, ssh_channel chan) {
    if (s == NULL || chan == NULL)
        return NULL;
    ssh_server_channel_ctx *cur = s->channels;
    while (cur != NULL) {
        if (cur->channel == chan)
            return cur;
        cur = cur->next;
    }
    return NULL;
}

static void close_poll(uv_poll_t **poll, uv_close_cb close_cb) {
    if (*poll != NULL) {
        if (uv_is_closing((uv_handle_t *)*poll))
            return;
        uv_poll_stop(*poll);
        uv_close((uv_handle_t *)*poll, close_cb);
    }
}

static void stop_timer(uv_timer_t **timer, uv_close_cb close_cb) {
    if (*timer != NULL) {
        if (uv_is_closing((uv_handle_t *)*timer))
            return;
        uv_timer_stop(*timer);
        uv_close((uv_handle_t *)*timer, close_cb);
    }
}

static int fd_has_data(int fd) {
    if (fd < 0)
        return 0;
    struct pollfd pfd;
    pfd.fd = fd;
    pfd.events = POLLIN;
    pfd.revents = 0;
    int rc;
    do {
        rc = poll(&pfd, 1, 0);
    } while (rc < 0 && errno == EINTR);
    if (rc <= 0)
        return 0;
    if (pfd.revents & POLLIN)
        return 1;
    if (pfd.revents & POLLNVAL)
        return 0;
    return 0;
}

static int fd_set_nonblocking(int fd) {
    if (fd < 0)
        return -1;
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0)
        return -1;
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
        return -1;
    return 0;
}

static void format_session_error(ssh_session session, const char *prefix,
                                 char *buf, size_t buflen) {
    const char *err = NULL;
    if (session != NULL)
        err = ssh_get_error(session);
    if (err != NULL && err[0] != '\0')
        snprintf(buf, buflen, "%s: %s", prefix, err);
    else
        snprintf(buf, buflen, "%s", prefix);
}

static int session_has_pending_write(ssh_session session) {
    if (session == NULL)
        return 0;
    int pending = ssh_get_status(session) | ssh_get_poll_flags(session);
    return (pending & SSH_WRITE_PENDING) != 0;
}

static void client_poll_close_cb(uv_handle_t *handle) {
    ssh_client_ctx *c = (ssh_client_ctx *)handle->data;
    if (c == NULL)
        return;
    if (c->poll == (uv_poll_t *)handle) {
        c->poll = NULL;
        c->poll_events = 0;
    }
    if (c->state == CLIENT_STATE_CLOSING) {
        client_finalize(c);
    }
}

static void client_timer_close_cb(uv_handle_t *handle) {
    ssh_client_ctx *c = (ssh_client_ctx *)handle->data;
    if (c == NULL)
        return;
    if ((uv_timer_t *)handle == c->connect_timer)
        c->connect_timer = NULL;
    if ((uv_timer_t *)handle == c->auth_timer)
        c->auth_timer = NULL;
    if ((uv_timer_t *)handle == c->keepalive_timer)
        c->keepalive_timer = NULL;
}

static void server_poll_close_cb(uv_handle_t *handle) {
    ssh_server_ctx *s = (ssh_server_ctx *)handle->data;
    if (s == NULL)
        return;
    if (s->poll == (uv_poll_t *)handle)
        s->poll = NULL;
    if (s->state == SERVER_STATE_CLOSING) {
        server_finalize(s);
    }
}

static void session_poll_close_cb(uv_handle_t *handle) {
    ssh_server_session_ctx *s = (ssh_server_session_ctx *)handle->data;
    if (s == NULL)
        return;
    if (s->poll == (uv_poll_t *)handle) {
        s->poll = NULL;
        s->poll_events = 0;
    }
    if (s->state == SESSION_STATE_CLOSING) {
        session_finalize(s);
    }
}

static void session_timer_close_cb(uv_handle_t *handle) {
    ssh_server_session_ctx *s = (ssh_server_session_ctx *)handle->data;
    if (s == NULL)
        return;
    if ((uv_timer_t *)handle == s->auth_timer)
        s->auth_timer = NULL;
    if ((uv_timer_t *)handle == s->keepalive_timer)
        s->keepalive_timer = NULL;
}

static void client_notify_connect(ssh_client_ctx *c, const char *err) {
    if (c == NULL)
        return;
    if (c->connect_notified)
        return;
    if (c->on_connect) {
        $action2 f = ($action2)c->on_connect;
        f->$class->__asyn__(f, c->actor, err ? to$str((char *)err) : B_None);
    }
    c->connect_notified = 1;
    if (err == NULL)
        c->connected_ok = 1;
}

static void client_notify_close(ssh_client_ctx *c, const char *reason) {
    if (c->close_notified)
        return;
    if (!c->connected_ok)
        return;
    if (c->on_close) {
        $action2 f = ($action2)c->on_close;
        f->$class->__asyn__(f, c->actor, to$str((char *)reason));
    }
    c->close_notified = 1;
}

static void client_fail(ssh_client_ctx *c, const char *msg) {
    if (c == NULL || c->state == CLIENT_STATE_CLOSED || c->state == CLIENT_STATE_ERROR)
        return;
    c->state = CLIENT_STATE_ERROR;
    if (!c->connected_ok)
        client_notify_connect(c, msg);
    client_close_internal(c, msg);
}

static void channel_notify_open(ssh_channel_ctx *ch, const char *err) {
    if (ch->open_notified)
        return;
    if (ch->on_open) {
        $action2 f = ($action2)ch->on_open;
        f->$class->__asyn__(f, ch->actor, err ? to$str((char *)err) : B_None);
    }
    ch->open_notified = 1;
    if (err == NULL)
        ch->open_succeeded = 1;
}

static void channel_notify_close(ssh_channel_ctx *ch, const char *reason) {
    if (ch->close_notified)
        return;
    if (!ch->open_succeeded) {
        ch->close_notified = 1;
        return;
    }
    if (ch->on_close) {
        $action2 f = ($action2)ch->on_close;
        f->$class->__asyn__(f, ch->actor, to$str((char *)reason));
    }
    ch->close_notified = 1;
}

static void channel_notify_error(ssh_channel_ctx *ch, const char *msg) {
    if (ch->open_succeeded)
        channel_notify_close(ch, msg);
    else
        channel_notify_open(ch, msg);
}

static void channel_notify_exit(ssh_channel_ctx *ch, int exit_status, B_str signal) {
    if (ch->exit_sent)
        return;
    if (ch->on_exit) {
        $action3 f = ($action3)ch->on_exit;
        f->$class->__asyn__(f, ch->actor, toB_int(exit_status), signal);
    }
    ch->exit_sent = 1;
}

static int client_channel_data_cb(ssh_session session, ssh_channel channel, void *data,
                                  uint32_t len, int is_stderr, void *userdata) {
    ssh_channel_ctx *ch = (ssh_channel_ctx *)userdata;
    (void)session;
    (void)channel;
    if (ch == NULL || ch->state == CHAN_STATE_CLOSED || ch->state == CHAN_STATE_ERROR)
        return 0;
    if (len == 0)
        return 0;
    B_bytes out = to$bytesD_len((const char *)data, (size_t)len);
    if (is_stderr) {
        if (ch->on_stderr) {
            $action2 f = ($action2)ch->on_stderr;
            f->$class->__asyn__(f, ch->actor, out);
        }
    } else {
        if (ch->on_stdout) {
            $action2 f = ($action2)ch->on_stdout;
            f->$class->__asyn__(f, ch->actor, out);
        }
    }
    return (int)len;
}

static void client_channel_eof_cb(ssh_session session, ssh_channel channel, void *userdata) {
    ssh_channel_ctx *ch = (ssh_channel_ctx *)userdata;
    (void)session;
    (void)channel;
    if (ch == NULL)
        return;
    if (!ch->stdout_eof && ch->on_stdout) {
        $action2 f = ($action2)ch->on_stdout;
        f->$class->__asyn__(f, ch->actor, B_None);
        ch->stdout_eof = 1;
    }
    if (!ch->stderr_eof && ch->on_stderr) {
        $action2 f = ($action2)ch->on_stderr;
        f->$class->__asyn__(f, ch->actor, B_None);
        ch->stderr_eof = 1;
    }
}

static void client_channel_close_cb(ssh_session session, ssh_channel channel, void *userdata) {
    ssh_channel_ctx *ch = (ssh_channel_ctx *)userdata;
    (void)session;
    (void)channel;
    if (ch == NULL)
        return;
    ch->remote_close_seen = 1;
    channel_notify_close(ch, "closed");
}

static int client_channel_write_wontblock_cb(ssh_session session, ssh_channel channel,
                                             uint32_t bytes, void *userdata) {
    ssh_channel_ctx *ch = (ssh_channel_ctx *)userdata;
    (void)session;
    (void)channel;
    if (ch == NULL || ch->state == CHAN_STATE_CLOSED || ch->state == CHAN_STATE_ERROR)
        return 0;
    ch->write_wontblock = bytes > 0 ? 1 : 0;
    if (ssh_debug_enabled) {
        ssh_debug_log("client channel write_wontblock: bytes=%u ch=%p", bytes, (void *)ch);
    }
    return 0;
}

static void client_channel_setup_callbacks(ssh_channel_ctx *ch) {
    if (ch == NULL || ch->channel == NULL || ch->callbacks != NULL)
        return;
    struct ssh_channel_callbacks_struct *cb = acton_calloc(1, sizeof(*cb));
    ssh_callbacks_init(cb);
    cb->userdata = ch;
    cb->channel_data_function = client_channel_data_cb;
    cb->channel_eof_function = client_channel_eof_cb;
    cb->channel_close_function = client_channel_close_cb;
    cb->channel_write_wontblock_function = client_channel_write_wontblock_cb;
    ch->callbacks = cb;
    ssh_add_channel_callbacks(ch->channel, cb);
    if (ssh_debug_enabled) {
        ssh_debug_log("client channel callbacks set ch=%p", (void *)ch);
    }
}

static void channel_notify_eof(ssh_channel_ctx *ch) {
    if (ch->channel == NULL)
        return;
    if (ssh_channel_is_eof(ch->channel)) {
        if (!ch->stdout_eof && ch->on_stdout) {
            $action2 f = ($action2)ch->on_stdout;
            f->$class->__asyn__(f, ch->actor, B_None);
            ch->stdout_eof = 1;
        }
        if (!ch->stderr_eof && ch->on_stderr) {
            $action2 f = ($action2)ch->on_stderr;
            f->$class->__asyn__(f, ch->actor, B_None);
            ch->stderr_eof = 1;
        }
    }
}

static void channel_finalize(ssh_client_ctx *c, ssh_channel_ctx *ch) {
    if (ch->channel != NULL) {
        int exit_status = -1;
        B_str exit_signal = B_None;
        if (ssh_channel_is_closed(ch->channel)) {
            uint32_t exit_code = 0;
            char *signal = NULL;
            int core_dumped = 0;
            int rc = ssh_channel_get_exit_state(ch->channel, &exit_code, &signal, &core_dumped);
            if (rc == SSH_OK) {
                exit_status = (int)exit_code;
                if (signal != NULL)
                    exit_signal = to$str(signal);
            }
            if (signal)
                ssh_string_free_char(signal);
            (void)core_dumped;
        }
        channel_notify_exit(ch, exit_status, exit_signal);
        if (ch->callbacks) {
            ssh_remove_channel_callbacks(ch->channel, ch->callbacks);
            ch->callbacks = NULL;
        }
        ssh_channel_free(ch->channel);
        ch->channel = NULL;
    } else {
        channel_notify_exit(ch, -1, B_None);
    }
    if (!ch->stdout_eof && ch->on_stdout) {
        $action2 f = ($action2)ch->on_stdout;
        f->$class->__asyn__(f, ch->actor, B_None);
        ch->stdout_eof = 1;
    }
    if (!ch->stderr_eof && ch->on_stderr) {
        $action2 f = ($action2)ch->on_stderr;
        f->$class->__asyn__(f, ch->actor, B_None);
        ch->stderr_eof = 1;
    }
    channel_notify_close(ch, "closed");
    if (ch->actor)
        ch->actor->_channel_id = toB_u64(0);
    ch->state = CHAN_STATE_CLOSED;
    (void)c;
}

static void channel_fail(ssh_client_ctx *c, ssh_channel_ctx *ch, const char *msg) {
    if (ch->state == CHAN_STATE_ERROR || ch->state == CHAN_STATE_CLOSED)
        return;
    ch->state = CHAN_STATE_ERROR;
    channel_notify_error(ch, msg);
    if (ch->channel) {
        ssh_channel_close(ch->channel);
    }
    channel_finalize(c, ch);
}

static void channel_queue_write(ssh_channel_ctx *ch, B_bytes data) {
    write_chunk_t *chunk = acton_calloc(1, sizeof(write_chunk_t));
    chunk->data = data;
    chunk->offset = 0;
    chunk->next = NULL;
    if (ch->write_tail) {
        ch->write_tail->next = chunk;
    } else {
        ch->write_head = chunk;
    }
    ch->write_tail = chunk;
}

static void channel_try_write(ssh_client_ctx *c, ssh_channel_ctx *ch) {
    while (ch->write_head != NULL && ch->write_head->data->nbytes == ch->write_head->offset) {
        write_chunk_t *chunk = ch->write_head;
        ch->write_head = chunk->next;
        if (ch->write_head == NULL)
            ch->write_tail = NULL;
    }

    if (ch->write_head == NULL || !ch->write_wontblock || session_has_pending_write(c->session))
        return;

    write_chunk_t *chunk = ch->write_head;
    size_t remaining = chunk->data->nbytes - chunk->offset;
    ch->write_wontblock = 0;
    int rc = ssh_channel_write(ch->channel, chunk->data->str + chunk->offset, (uint32_t)remaining);
    if (rc > 0) {
        chunk->offset += (size_t)rc;
        if (chunk->offset >= chunk->data->nbytes) {
            ch->write_head = chunk->next;
            if (ch->write_head == NULL)
                ch->write_tail = NULL;
        }
    } else if (rc == 0 || rc == SSH_AGAIN) {
        c->write_ready = 0;
        return;
    } else {
        char errmsg[256] = {0};
        snprintf(errmsg, sizeof(errmsg), "SSH channel write error: %s", ssh_get_error(c->session));
        channel_fail(c, ch, errmsg);
        return;
    }
}

static int channel_read_stream(ssh_client_ctx *c, ssh_channel_ctx *ch, int is_stderr) {
    char buf[SSH_READ_BUFSIZE];
    int read_any = 0;
    for (;;) {
        int n = ssh_channel_read_buffered(ch->channel, buf, sizeof(buf), is_stderr);
        if (ssh_debug_enabled) {
            ssh_debug_log("client channel read: rc=%d stderr=%d", n, is_stderr);
        }
        if (n > 0) {
            read_any = 1;
            B_bytes out = to$bytesD_len(buf, n);
            if (is_stderr) {
                if (ch->on_stderr) {
                    $action2 f = ($action2)ch->on_stderr;
                    f->$class->__asyn__(f, ch->actor, out);
                }
            } else {
                if (ch->on_stdout) {
                    $action2 f = ($action2)ch->on_stdout;
                    f->$class->__asyn__(f, ch->actor, out);
                }
            }
            continue;
        }
        if (n == 0 || n == SSH_AGAIN) {
            break;
        }
        if (n == SSH_EOF) {
            break;
        }
        if (n == SSH_ERROR) {
            char errmsg[256] = {0};
            snprintf(errmsg, sizeof(errmsg), "SSH channel read error: %s", ssh_get_error(c->session));
            channel_fail(c, ch, errmsg);
            break;
        }
    }
    return read_any;
}

static void channel_drive(ssh_client_ctx *c, ssh_channel_ctx *ch) {
    if (ch->state == CHAN_STATE_CLOSED || ch->state == CHAN_STATE_ERROR)
        return;

    if (ch->state == CHAN_STATE_INIT) {
        ch->channel = ssh_channel_new(c->session);
        if (ch->channel == NULL) {
            channel_fail(c, ch, "Failed to create SSH channel");
            return;
        }
        client_channel_setup_callbacks(ch);
        if (ssh_debug_enabled) {
            ssh_debug_log("client channel new ch=%p callbacks=%p", (void *)ch, (void *)ch->callbacks);
        }
        ch->state = CHAN_STATE_OPENING;
    }

    if (ch->state == CHAN_STATE_OPENING) {
        int rc = ssh_channel_open_session(ch->channel);
        if (rc == SSH_OK) {
            ch->state = CHAN_STATE_OPEN;
            channel_notify_open(ch, NULL);
        } else if (rc == SSH_AGAIN) {
            c->write_ready = 0;
            return;
        } else {
            char errmsg[256] = {0};
            snprintf(errmsg, sizeof(errmsg), "Failed to open SSH channel: %s", ssh_get_error(c->session));
            channel_fail(c, ch, errmsg);
            return;
        }
    }

    if (ch->state == CHAN_STATE_OPEN || ch->state == CHAN_STATE_RUNNING) {
        if (ch->pty_pending && !ch->pty_done) {
            const char *term = ch->term ? (const char *)fromB_str(ch->term) : "xterm-256color";
            int rc = ssh_channel_request_pty_size(ch->channel, term, ch->cols, ch->rows);
            if (rc == SSH_OK) {
                ch->pty_done = 1;
            } else if (rc == SSH_AGAIN) {
                c->write_ready = 0;
                return;
            } else {
                char errmsg[256] = {0};
                snprintf(errmsg, sizeof(errmsg), "Failed to request PTY: %s", ssh_get_error(c->session));
                channel_fail(c, ch, errmsg);
                return;
            }
        }

        if (ch->pending_req != CHAN_REQ_NONE) {
            int rc = SSH_ERROR;
            if (ch->pending_req == CHAN_REQ_SHELL) {
                rc = ssh_channel_request_shell(ch->channel);
            } else if (ch->pending_req == CHAN_REQ_EXEC) {
                rc = ssh_channel_request_exec(ch->channel, (const char *)fromB_str(ch->exec_cmd));
            } else if (ch->pending_req == CHAN_REQ_SUBSYSTEM) {
                rc = ssh_channel_request_subsystem(ch->channel, (const char *)fromB_str(ch->subsystem));
            }

            if (rc == SSH_OK) {
                if (ssh_debug_enabled) {
                    ssh_debug_log("client channel request ok");
                }
                ch->pending_req = CHAN_REQ_NONE;
                ch->state = CHAN_STATE_RUNNING;
            } else if (rc == SSH_AGAIN) {
                c->write_ready = 0;
                if (ssh_debug_enabled) {
                    ssh_debug_log("client channel request again");
                }
                return;
            } else {
                char errmsg[256] = {0};
                snprintf(errmsg, sizeof(errmsg), "SSH channel request failed: %s", ssh_get_error(c->session));
                channel_fail(c, ch, errmsg);
                return;
            }
        }
    }

    if (ch->state == CHAN_STATE_OPEN || ch->state == CHAN_STATE_RUNNING) {
        if (ch->write_head != NULL) {
            channel_try_write(c, ch);
            if (ch->state == CHAN_STATE_ERROR)
                return;
        }

        if (ch->send_eof && !ch->eof_sent && ch->write_head == NULL &&
            !session_has_pending_write(c->session)) {
            int rc = ssh_channel_send_eof(ch->channel);
            if (rc == SSH_OK) {
                ch->eof_sent = 1;
            } else if (rc == SSH_AGAIN) {
                c->write_ready = 0;
                return;
            } else {
                char errmsg[256] = {0};
                snprintf(errmsg, sizeof(errmsg), "Failed to send EOF: %s", ssh_get_error(c->session));
                channel_fail(c, ch, errmsg);
                return;
            }
        }

        if (ch->close_requested && !ch->close_sent && ch->write_head == NULL &&
            (!ch->send_eof || ch->eof_sent) &&
            !session_has_pending_write(c->session)) {
            int rc = ssh_channel_close(ch->channel);
            if (rc == SSH_OK) {
                ch->close_sent = 1;
                ch->state = CHAN_STATE_CLOSING;
            } else if (rc == SSH_AGAIN) {
                c->write_ready = 0;
                return;
            } else {
                char errmsg[256] = {0};
                snprintf(errmsg, sizeof(errmsg), "Failed to close channel: %s", ssh_get_error(c->session));
                channel_fail(c, ch, errmsg);
                return;
            }
        }

        if (ch->callbacks == NULL) {
            for (int i = 0; i < SSH_IO_PUMP_LIMIT; i++) {
                int did = 0;
                did |= channel_read_stream(c, ch, 0);
                did |= channel_read_stream(c, ch, 1);
                if (!did)
                    break;
            }
        }
        channel_notify_eof(ch);
    }

    if (ch->channel != NULL && ch->remote_close_seen &&
        ssh_channel_is_closed(ch->channel)) {
        channel_finalize(c, ch);
    }
}

static void client_drive_channels(ssh_client_ctx *c) {
    ssh_channel_ctx *prev = NULL;
    ssh_channel_ctx *ch = c->channels;
    while (ch != NULL) {
        ssh_channel_ctx *next = ch->next;
        channel_drive(c, ch);
        if (ch->state == CHAN_STATE_CLOSED || ch->state == CHAN_STATE_ERROR) {
            if (prev != NULL) {
                prev->next = next;
            } else {
                c->channels = next;
            }
            ch->next = NULL;
        } else {
            prev = ch;
        }
        ch = next;
    }
}

static int client_get_hostkey_info(ssh_client_ctx *c, B_str *key_type_out, B_str *fingerprint_out) {
    ssh_key key = NULL;
    unsigned char *hash = NULL;
    size_t hash_len = 0;
    char *fingerprint = NULL;

    int rc = ssh_get_server_publickey(c->session, &key);
    if (rc != SSH_OK || key == NULL)
        return -1;

    enum ssh_keytypes_e key_type = ssh_key_type(key);
    const char *key_type_str = ssh_key_type_to_char(key_type);

    rc = ssh_get_publickey_hash(key, SSH_PUBLICKEY_HASH_SHA256, &hash, &hash_len);
    if (rc != SSH_OK) {
        ssh_key_free(key);
        return -1;
    }

    fingerprint = ssh_get_fingerprint_hash(SSH_PUBLICKEY_HASH_SHA256, hash, hash_len);

    if (key_type_out)
        *key_type_out = to$str((char *)(key_type_str ? key_type_str : ""));
    if (fingerprint_out)
        *fingerprint_out = to$str((char *)(fingerprint ? fingerprint : ""));

    ssh_clean_pubkey_hash(&hash);
    ssh_key_free(key);
    if (fingerprint)
        ssh_string_free_char(fingerprint);

    return 0;
}

static int client_check_hostkey(ssh_client_ctx *c) {
    enum ssh_known_hosts_e state = SSH_KNOWN_HOSTS_UNKNOWN;
    int use_known_hosts = 0;

    if (c->actor != NULL && c->actor->known_hosts != B_None)
        use_known_hosts = 1;

    if (use_known_hosts) {
        state = ssh_session_is_known_server(c->session);
        if (state == SSH_KNOWN_HOSTS_OK)
            return 0;

        if (state == SSH_KNOWN_HOSTS_ERROR) {
            char errmsg[256] = {0};
            snprintf(errmsg, sizeof(errmsg), "Host key check error: %s", ssh_get_error(c->session));
            client_fail(c, errmsg);
            return -1;
        }
    }

    c->hostkey_state = state;

    if (!c->on_hostkey) {
        char errmsg[256] = {0};
        snprintf(errmsg, sizeof(errmsg), "Host key not accepted (%s)", hostkey_state_str(state));
        client_fail(c, errmsg);
        return -1;
    }

    B_str key_type = to$str((char *)"");
    B_str fingerprint = to$str((char *)"");
    if (client_get_hostkey_info(c, &key_type, &fingerprint) != 0) {
        key_type = to$str((char *)"");
        fingerprint = to$str((char *)"");
    }

    sshQ_HostKeyInfo info = sshQ_HostKeyInfoG_new(key_type, fingerprint);
    $action3 f = ($action3)c->on_hostkey;
    f->$class->__asyn__(f, c->actor, to$str((char *)hostkey_state_str(state)), info);
    return 1;
}

static void connect_timeout_cb(uv_timer_t *timer) {
    ssh_client_ctx *c = (ssh_client_ctx *)timer->data;
    if (c == NULL)
        return;
    if (c->state == CLIENT_STATE_CONNECTING || c->state == CLIENT_STATE_HOSTKEY || c->state == CLIENT_STATE_HOSTKEY_WAIT) {
        client_fail(c, "SSH connect timeout");
    }
}

static void auth_timeout_cb(uv_timer_t *timer) {
    ssh_client_ctx *c = (ssh_client_ctx *)timer->data;
    if (c == NULL)
        return;
    if (c->state == CLIENT_STATE_AUTH) {
        client_fail(c, "SSH authentication timeout");
    }
}

static void keepalive_cb(uv_timer_t *timer) {
    ssh_client_ctx *c = (ssh_client_ctx *)timer->data;
    if (c == NULL)
        return;
    if (c->state != CLIENT_STATE_READY || c->session == NULL)
        return;
    int rc = ssh_send_ignore(c->session, "keepalive");
    if (rc == SSH_AGAIN) {
        client_update_poll(c);
        return;
    }
    if (rc != SSH_OK) {
        char errmsg[256] = {0};
        snprintf(errmsg, sizeof(errmsg), "SSH keepalive failed: %s", ssh_get_error(c->session));
        client_fail(c, errmsg);
        return;
    }
    client_update_poll(c);
}

static void client_start_connect_timer(ssh_client_ctx *c) {
    if (c->connect_timeout <= 0.0 || c->connect_timer != NULL)
        return;
    c->connect_timer = acton_calloc(1, sizeof(uv_timer_t));
    c->connect_timer->data = c;
    uv_timer_init(get_uv_loop(), c->connect_timer);
    uv_timer_start(c->connect_timer, connect_timeout_cb, (uint64_t)(c->connect_timeout * 1000), 0);
}

static void client_start_auth_timer(ssh_client_ctx *c) {
    if (c->auth_timeout <= 0.0 || c->auth_timer != NULL)
        return;
    c->auth_timer = acton_calloc(1, sizeof(uv_timer_t));
    c->auth_timer->data = c;
    uv_timer_init(get_uv_loop(), c->auth_timer);
    uv_timer_start(c->auth_timer, auth_timeout_cb, (uint64_t)(c->auth_timeout * 1000), 0);
}

static void client_start_keepalive(ssh_client_ctx *c) {
    if (!c->keepalive_enabled || c->keepalive_interval <= 0.0 || c->keepalive_timer != NULL)
        return;
    c->keepalive_timer = acton_calloc(1, sizeof(uv_timer_t));
    c->keepalive_timer->data = c;
    uv_timer_init(get_uv_loop(), c->keepalive_timer);
    uint64_t interval_ms = (uint64_t)(c->keepalive_interval * 1000);
    uv_timer_start(c->keepalive_timer, keepalive_cb, interval_ms, interval_ms);
}

static void poll_cb(uv_poll_t *handle, int status, int events) {
    ssh_client_ctx *c = (ssh_client_ctx *)handle->data;
    if (c == NULL)
        return;
    if (ssh_debug_enabled) {
        ssh_debug_log("client poll: status=%d events=0x%x state=%d", status, events, c->state);
    }
    if (status < 0) {
        char errmsg[256] = {0};
        uv_strerror_r(status, errmsg + strlen(errmsg), sizeof(errmsg) - strlen(errmsg));
        client_fail(c, errmsg);
        return;
    }
    int libssh_events = 0;
    if ((events & UV_READABLE) && fd_has_data(c->fd)) {
        ssh_set_fd_toread(c->session);
        libssh_events |= UV_READABLE;
    }
    if (events & UV_WRITABLE) {
        c->write_ready = 1;
        ssh_set_fd_towrite(c->session);
        libssh_events |= UV_WRITABLE;
    }
    if (session_apply_poll_events(c->session, libssh_events) != 0) {
        char errmsg[256] = {0};
        format_session_error(c->session, "SSH poll callback error", errmsg, sizeof(errmsg));
        client_fail(c, errmsg);
        return;
    }
    client_drive(c);
    client_pump_io(c);
    c->write_ready = 0;
}

static void client_update_poll(ssh_client_ctx *c) {
    if (c->poll == NULL || c->session == NULL)
        return;
    if (c->state == CLIENT_STATE_CLOSING || c->state == CLIENT_STATE_CLOSED)
        return;
    if (uv_is_closing((uv_handle_t *)c->poll))
        return;
    int status = ssh_get_status(c->session);
    if (status & SSH_CLOSED_ERROR) {
        client_fail(c, "SSH session closed with error");
        return;
    }
    if (status & SSH_CLOSED) {
        client_close_internal(c, "SSH session closed");
        return;
    }
    int flags = ssh_get_poll_flags(c->session);
    int pending = flags | status;
    int events = UV_READABLE;
    if (pending & SSH_WRITE_PENDING)
        events |= UV_WRITABLE;
    if ((events & UV_WRITABLE) == 0 && client_needs_write(c))
        events |= UV_WRITABLE;
    if (ssh_debug_enabled && (events != c->poll_events || (pending & SSH_WRITE_PENDING))) {
        ssh_debug_log("client update poll: status=0x%x flags=0x%x pending=0x%x events=0x%x state=%d",
                      status, flags, pending, events, c->state);
    }
    if (events != c->poll_events) {
        int uv_rc = uv_poll_start(c->poll, events, poll_cb);
        if (uv_rc != 0) {
            char errmsg[256] = {0};
            uv_strerror_r(uv_rc, errmsg + strlen(errmsg), sizeof(errmsg) - strlen(errmsg));
            client_fail(c, errmsg);
            return;
        }
        c->poll_events = events;
    }
}

static void client_pump_io(ssh_client_ctx *c) {
    if (c == NULL || c->session == NULL)
        return;
    int i;
    for (i = 0; i < SSH_IO_PUMP_LIMIT; i++) {
        int did = 0;
        if (c->session == NULL)
            return;
        int has_data = fd_has_data(c->fd);
        if (has_data) {
            if (ssh_debug_enabled) {
                ssh_debug_log("client pump: readable");
            }
            ssh_set_fd_toread(c->session);
            if (session_apply_poll_events(c->session, UV_READABLE) != 0) {
                char errmsg[256] = {0};
                format_session_error(c->session, "SSH poll callback error", errmsg, sizeof(errmsg));
                client_fail(c, errmsg);
                return;
            }
            client_drive(c);
            did = 1;
        }
        if (c->session == NULL)
            return;
        if (!did) {
            int status = ssh_get_status(c->session);
            if (status & SSH_READ_PENDING) {
                if (ssh_debug_enabled) {
                    ssh_debug_log("client pump: buffered read pending=0x%x", status);
                }
                client_drive(c);
                /* Avoid spinning when only buffered data remains. */
                break;
            }
        }
        if (!did)
            break;
    }
    if (ssh_debug_enabled && i >= SSH_IO_PUMP_LIMIT) {
        int status = ssh_get_status(c->session);
        int flags = ssh_get_poll_flags(c->session);
        ssh_debug_log("client pump: hit limit status=0x%x flags=0x%x", status, flags);
    }
}

static int client_needs_write(ssh_client_ctx *c) {
    if (c == NULL)
        return 0;
    ssh_channel_ctx *ch = c->channels;
    while (ch != NULL) {
        if (ch->pending_req != CHAN_REQ_NONE || ch->write_head != NULL)
            return 1;
        if (ch->send_eof && !ch->eof_sent)
            return 1;
        if (ch->close_requested && !ch->close_sent)
            return 1;
        ch = ch->next;
    }
    return 0;
}

static void client_on_ready(ssh_client_ctx *c) {
    c->state = CLIENT_STATE_READY;
    stop_timer(&c->connect_timer, client_timer_close_cb);
    stop_timer(&c->auth_timer, client_timer_close_cb);
    client_notify_connect(c, NULL);
    client_start_keepalive(c);
    client_drive_channels(c);
    client_update_poll(c);
}

static void client_drive(ssh_client_ctx *c) {
    if (c == NULL)
        return;
    if (c->state == CLIENT_STATE_ERROR || c->state == CLIENT_STATE_CLOSED || c->state == CLIENT_STATE_CLOSING)
        return;

    int spin = 0;
    while (1) {
        if (c->state == CLIENT_STATE_CONNECTING) {
            int rc = ssh_connect(c->session);
            if (ssh_debug_enabled) {
                log_debug("ssh_connect rc=%d state=%d", rc, c->state);
            }
            if (rc == SSH_OK) {
                stop_timer(&c->connect_timer, client_timer_close_cb);
                if (fd_set_nonblocking(c->fd) != 0) {
                    client_fail(c, "Failed to restore SSH session fd nonblocking");
                    return;
                }
                c->state = CLIENT_STATE_HOSTKEY;
                continue;
            } else if (rc == SSH_AGAIN) {
                int status = ssh_get_status(c->session);
                if (status & SSH_WRITE_PENDING)
                    c->write_ready = 0;
                if ((status & SSH_READ_PENDING) && spin++ < SSH_IO_PUMP_LIMIT) {
                    if (ssh_debug_enabled) {
                        ssh_debug_log("client drive: buffered read pending during connect");
                    }
                    continue;
                }
                client_update_poll(c);
                return;
            } else {
                char errmsg[256] = {0};
                snprintf(errmsg, sizeof(errmsg), "SSH connect failed: %s", ssh_get_error(c->session));
                client_fail(c, errmsg);
                return;
            }
        }

        if (c->state == CLIENT_STATE_HOSTKEY) {
            int rc = client_check_hostkey(c);
            if (rc == 0) {
                c->state = CLIENT_STATE_AUTH;
                client_start_auth_timer(c);
                continue;
            } else if (rc == 1) {
                c->state = CLIENT_STATE_HOSTKEY_WAIT;
                return;
            } else {
                return;
            }
        }

        if (c->state == CLIENT_STATE_HOSTKEY_WAIT) {
            client_update_poll(c);
            return;
        }

        if (c->state == CLIENT_STATE_AUTH) {
            if (c->actor->password == B_None) {
                client_fail(c, "Password auth requested but no password provided");
                return;
            }
            int rc = ssh_userauth_password(c->session, NULL, (const char *)fromB_str(c->actor->password));
            if (rc == SSH_AUTH_SUCCESS) {
                client_on_ready(c);
                return;
            } else if (rc == SSH_AUTH_AGAIN) {
                int status = ssh_get_status(c->session);
                if (status & SSH_WRITE_PENDING)
                    c->write_ready = 0;
                if ((status & SSH_READ_PENDING) && spin++ < SSH_IO_PUMP_LIMIT) {
                    if (ssh_debug_enabled) {
                        ssh_debug_log("client drive: buffered read pending during auth");
                    }
                    continue;
                }
                client_update_poll(c);
                return;
            } else {
                char errmsg[256] = {0};
                snprintf(errmsg, sizeof(errmsg), "SSH auth failed: %s", ssh_get_error(c->session));
                client_fail(c, errmsg);
                return;
            }
        }

        if (c->state == CLIENT_STATE_READY) {
            client_drive_channels(c);
            client_update_poll(c);
            return;
        }

        return;
    }
}

static void client_finalize(ssh_client_ctx *c) {
    if (c == NULL || c->close_finalized)
        return;
    c->close_finalized = 1;

    if (c->session != NULL) {
        ssh_disconnect(c->session);
        ssh_free(c->session);
        c->session = NULL;
    }

    client_notify_close(c, c->close_reason ? c->close_reason : "closed");
    c->state = CLIENT_STATE_CLOSED;
    if (c->actor)
        c->actor->_client = toB_u64(0);
}

static void client_close_internal(ssh_client_ctx *c, const char *reason) {
    if (c == NULL || c->state == CLIENT_STATE_CLOSED || c->state == CLIENT_STATE_CLOSING)
        return;

    if (!c->connected_ok && !c->connect_notified) {
        client_notify_connect(c, reason ? reason : "closed");
    }

    int notify_channel_error = (c->state == CLIENT_STATE_ERROR);
    c->state = CLIENT_STATE_CLOSING;
    if (reason != NULL && c->close_reason == NULL)
        c->close_reason = acton_strdup(reason);

    stop_timer(&c->connect_timer, client_timer_close_cb);
    stop_timer(&c->auth_timer, client_timer_close_cb);
    stop_timer(&c->keepalive_timer, client_timer_close_cb);

    if (c->poll != NULL) {
        close_poll(&c->poll, client_poll_close_cb);
        c->poll_events = 0;
    }

    ssh_channel_ctx *ch = c->channels;
    while (ch != NULL) {
        ssh_channel_ctx *next = ch->next;
        if (notify_channel_error)
            channel_notify_error(ch, "Session closed");
        channel_notify_eof(ch);
        channel_finalize(c, ch);
        ch->next = NULL;
        ch = next;
    }
    c->channels = NULL;

    if (c->poll != NULL)
        return;

    client_finalize(c);
}

void sshQ___ext_init__() {
    const char *dbg_env = getenv("ACTON_SSH_DEBUG");
    const char *log_env = getenv("ACTON_SSH_LIBSSH_LOG");
    if (dbg_env != NULL && dbg_env[0] != '\0')
        ssh_debug_enabled = 1;
    if (log_env != NULL && log_env[0] != '\0') {
        ssh_libssh_log_level = parse_libssh_log_level(log_env);
    }
    int r = libssh_replace_allocator(acton_malloc,
                                     acton_realloc,
                                     acton_calloc,
                                     acton_free,
                                     acton_strdup,
                                     acton_strndup);
    if (r != SSH_OK) {
        log_warn("SSH allocator replacement failed");
    }
    r = ssh_threads_set_callbacks(ssh_threads_get_default());
    if (r != SSH_OK) {
        log_warn("SSH thread callbacks setup failed");
    }
    r = ssh_init();
    if (r != SSH_OK) {
        log_warn("SSH init failed");
    }
}

B_str sshQ_version() {
    return to$str((char *)ssh_version(0));
}

B_NoneType sshQ__debug(B_str msg) {
    if (ssh_debug_enabled) {
        log_info("%s", fromB_str(msg));
    }
    return B_None;
}

$R sshQ_ClientD__pin_affinityG_local(sshQ_Client self, $Cont c$cont) {
    pin_actor_affinity();
    return $R_CONT(c$cont, B_None);
}

$R sshQ_ClientD__initG_local(sshQ_Client self, $Cont c$cont) {
    ssh_configure_libssh_logging();
    ssh_client_ctx *c = acton_calloc(1, sizeof(ssh_client_ctx));
    c->actor = self;
    c->on_connect = ($action2)self->on_connect;
    c->on_close = ($action2)self->on_close;
    c->on_hostkey = ($action3)self->on_hostkey;
    c->connect_timeout = fromB_float(self->connect_timeout);
    c->auth_timeout = fromB_float(self->auth_timeout);
    c->keepalive_interval = fromB_float(self->keepalive_interval);
    c->keepalive_enabled = fromB_bool(self->keepalive_enabled) ? 1 : 0;

    self->_client = toB_u64((unsigned long)c);

    c->session = ssh_new();
    if (c->session == NULL) {
        client_fail(c, "Failed to create SSH session");
        return $R_CONT(c$cont, B_None);
    }

    int rc;
    int strict = 1;
    int port = (int)fromB_u16(self->port);
    bool process_config = false;

    rc = ssh_options_set(c->session, SSH_OPTIONS_PROCESS_CONFIG, &process_config);
    if (rc != SSH_OK) {
        client_fail(c, "Failed to disable SSH config processing");
        return $R_CONT(c$cont, B_None);
    }

    rc = ssh_options_set(c->session, SSH_OPTIONS_HOST, fromB_str(self->host));
    if (rc != SSH_OK) {
        client_fail(c, "Failed to set SSH host");
        return $R_CONT(c$cont, B_None);
    }
    rc = ssh_options_set(c->session, SSH_OPTIONS_PORT, &port);
    if (rc != SSH_OK) {
        client_fail(c, "Failed to set SSH port");
        return $R_CONT(c$cont, B_None);
    }
    rc = ssh_options_set(c->session, SSH_OPTIONS_USER, fromB_str(self->username));
    if (rc != SSH_OK) {
        client_fail(c, "Failed to set SSH username");
        return $R_CONT(c$cont, B_None);
    }
    if (self->known_hosts != B_None) {
        const char *known_hosts = (const char *)fromB_str(self->known_hosts);
        rc = ssh_options_set(c->session, SSH_OPTIONS_KNOWNHOSTS, known_hosts);
        if (rc != SSH_OK) {
            client_fail(c, "Failed to set SSH known_hosts path");
            return $R_CONT(c$cont, B_None);
        }
        rc = ssh_options_set(c->session, SSH_OPTIONS_GLOBAL_KNOWNHOSTS, known_hosts);
        if (rc != SSH_OK) {
            client_fail(c, "Failed to set SSH global known_hosts path");
            return $R_CONT(c$cont, B_None);
        }
    }
    rc = ssh_options_set(c->session, SSH_OPTIONS_STRICTHOSTKEYCHECK, &strict);
    if (rc != SSH_OK) {
        client_fail(c, "Failed to set SSH strict host key checking");
        return $R_CONT(c$cont, B_None);
    }

    ssh_set_blocking(c->session, 0);

    c->state = CLIENT_STATE_CONNECTING;
    rc = ssh_connect(c->session);
    if (rc == SSH_OK) {
        c->state = CLIENT_STATE_HOSTKEY;
    } else if (rc == SSH_AGAIN) {
        c->state = CLIENT_STATE_CONNECTING;
    } else {
        char errmsg[256] = {0};
        snprintf(errmsg, sizeof(errmsg), "SSH connect failed: %s", ssh_get_error(c->session));
        client_fail(c, errmsg);
        return $R_CONT(c$cont, B_None);
    }

    c->fd = ssh_get_fd(c->session);
    if (c->fd < 0) {
        client_fail(c, "Failed to get SSH session fd");
        return $R_CONT(c$cont, B_None);
    }
    if (c->state != CLIENT_STATE_CONNECTING && fd_set_nonblocking(c->fd) != 0) {
        client_fail(c, "Failed to set SSH session fd nonblocking");
        return $R_CONT(c$cont, B_None);
    }

    c->poll = acton_calloc(1, sizeof(uv_poll_t));
    c->poll->data = c;
    int uv_rc = uv_poll_init(get_uv_loop(), c->poll, c->fd);
    if (uv_rc != 0) {
        char errmsg[256] = {0};
        uv_strerror_r(uv_rc, errmsg + strlen(errmsg), sizeof(errmsg) - strlen(errmsg));
        client_fail(c, errmsg);
        return $R_CONT(c$cont, B_None);
    }
    c->poll_events = UV_READABLE | UV_WRITABLE;
    uv_rc = uv_poll_start(c->poll, c->poll_events, poll_cb);
    if (uv_rc != 0) {
        char errmsg[256] = {0};
        uv_strerror_r(uv_rc, errmsg + strlen(errmsg), sizeof(errmsg) - strlen(errmsg));
        client_fail(c, errmsg);
        return $R_CONT(c$cont, B_None);
    }

    client_start_connect_timer(c);
    client_drive(c);

    return $R_CONT(c$cont, B_None);
}

$R sshQ_ClientD_accept_hostkeyG_local(sshQ_Client self, $Cont c$cont) {
    ssh_client_ctx *c = client_from_actor(self);
    if (c == NULL)
        return $R_CONT(c$cont, B_None);
    if (c->state != CLIENT_STATE_HOSTKEY_WAIT)
        return $R_CONT(c$cont, B_None);

    c->state = CLIENT_STATE_AUTH;
    client_start_auth_timer(c);
    client_drive(c);

    return $R_CONT(c$cont, B_None);
}

$R sshQ_ClientD_reject_hostkeyG_local(sshQ_Client self, $Cont c$cont, B_str reason) {
    ssh_client_ctx *c = client_from_actor(self);
    if (c == NULL)
        return $R_CONT(c$cont, B_None);
    if (c->state != CLIENT_STATE_HOSTKEY_WAIT)
        return $R_CONT(c$cont, B_None);

    char errmsg[256] = {0};
    snprintf(errmsg, sizeof(errmsg), "Host key rejected: %s", fromB_str(reason));
    client_fail(c, errmsg);

    return $R_CONT(c$cont, B_None);
}

$R sshQ_ClientD_closeG_local(sshQ_Client self, $Cont c$cont) {
    ssh_client_ctx *c = client_from_actor(self);
    if (c == NULL)
        return $R_CONT(c$cont, B_None);
    client_close_internal(c, "closed");
    return $R_CONT(c$cont, B_None);
}

$R sshQ_ClientD_channel_createG_local(sshQ_Client self, $Cont c$cont, sshQ_Channel channel,
                                      $action on_open,
                                      $action on_stdout,
                                      $action on_stderr,
                                      $action on_exit,
                                      $action on_close) {
    ssh_client_ctx *c = client_from_actor(self);
    if (c == NULL) {
        if (on_open) {
            $action2 f = ($action2)on_open;
            f->$class->__asyn__(f, channel, to$str((char *)"Client not initialized"));
        }
        return $R_CONT(c$cont, B_None);
    }

    ssh_channel_ctx *ch = acton_calloc(1, sizeof(ssh_channel_ctx));
    ch->actor = channel;
    ch->callbacks = NULL;
    ch->state = CHAN_STATE_INIT;
    ch->pending_req = CHAN_REQ_NONE;
    ch->pty_pending = 0;
    ch->pty_done = 0;
    ch->term = to$str((char *)"xterm-256color");
    ch->cols = 80;
    ch->rows = 24;
    ch->width_px = 0;
    ch->height_px = 0;
    ch->on_open = ($action2)on_open;
    ch->on_close = ($action2)on_close;
    ch->on_stdout = ($action2)on_stdout;
    ch->on_stderr = ($action2)on_stderr;
    ch->on_exit = ($action3)on_exit;

    ch->next = c->channels;
    c->channels = ch;

    channel->_channel_id = toB_u64((unsigned long)ch);

    if (c->state == CLIENT_STATE_READY)
        client_drive(c);

    return $R_CONT(c$cont, B_None);
}

static int channel_validate(ssh_client_ctx *c, ssh_channel_ctx *ch) {
    if (c == NULL || ch == NULL) {
        return -1;
    }
    if (ch->state == CHAN_STATE_ERROR || ch->state == CHAN_STATE_CLOSED) {
        return -1;
    }
    return 0;
}

$R sshQ_ClientD_channel_request_execG_local(sshQ_Client self, $Cont c$cont, sshQ_Channel channel, B_str cmd) {
    ssh_client_ctx *c = client_from_actor(self);
    ssh_channel_ctx *ch = channel_from_actor(channel);
    if (channel_validate(c, ch) != 0) {
        if (ch != NULL)
            channel_notify_error(ch, "Channel not ready");
        return $R_CONT(c$cont, B_None);
    }

    if (ch->pending_req != CHAN_REQ_NONE) {
        channel_notify_error(ch, "Channel already has a pending request");
        return $R_CONT(c$cont, B_None);
    }
    if (ch->state == CHAN_STATE_RUNNING || ch->state == CHAN_STATE_CLOSING) {
        channel_notify_error(ch, "Channel already running");
        return $R_CONT(c$cont, B_None);
    }

    ch->exec_cmd = cmd;
    ch->pending_req = CHAN_REQ_EXEC;
    client_drive(c);

    return $R_CONT(c$cont, B_None);
}

$R sshQ_ClientD_channel_request_shellG_local(sshQ_Client self, $Cont c$cont, sshQ_Channel channel, B_str term, B_int cols, B_int rows, B_int width_px, B_int height_px, B_bool with_pty) {
    ssh_client_ctx *c = client_from_actor(self);
    ssh_channel_ctx *ch = channel_from_actor(channel);
    if (channel_validate(c, ch) != 0) {
        if (ch != NULL)
            channel_notify_error(ch, "Channel not ready");
        return $R_CONT(c$cont, B_None);
    }

    if (ch->pending_req != CHAN_REQ_NONE) {
        channel_notify_error(ch, "Channel already has a pending request");
        return $R_CONT(c$cont, B_None);
    }
    if (ch->state == CHAN_STATE_RUNNING || ch->state == CHAN_STATE_CLOSING) {
        channel_notify_error(ch, "Channel already running");
        return $R_CONT(c$cont, B_None);
    }

    ch->term = term;
    ch->cols = fromB_int(cols);
    ch->rows = fromB_int(rows);
    ch->width_px = fromB_int(width_px);
    ch->height_px = fromB_int(height_px);
    ch->pty_pending = fromB_bool(with_pty) ? 1 : 0;

    ch->pending_req = CHAN_REQ_SHELL;
    client_drive(c);

    return $R_CONT(c$cont, B_None);
}

$R sshQ_ClientD_channel_request_subsystemG_local(sshQ_Client self, $Cont c$cont, sshQ_Channel channel, B_str name) {
    ssh_client_ctx *c = client_from_actor(self);
    ssh_channel_ctx *ch = channel_from_actor(channel);
    if (channel_validate(c, ch) != 0) {
        if (ch != NULL)
            channel_notify_error(ch, "Channel not ready");
        return $R_CONT(c$cont, B_None);
    }

    if (ch->pending_req != CHAN_REQ_NONE) {
        channel_notify_error(ch, "Channel already has a pending request");
        return $R_CONT(c$cont, B_None);
    }
    if (ch->state == CHAN_STATE_RUNNING || ch->state == CHAN_STATE_CLOSING) {
        channel_notify_error(ch, "Channel already running");
        return $R_CONT(c$cont, B_None);
    }

    ch->subsystem = name;
    ch->pending_req = CHAN_REQ_SUBSYSTEM;
    client_drive(c);

    return $R_CONT(c$cont, B_None);
}

$R sshQ_ClientD_channel_writeG_local(sshQ_Client self, $Cont c$cont, sshQ_Channel channel, B_bytes data) {
    ssh_client_ctx *c = client_from_actor(self);
    ssh_channel_ctx *ch = channel_from_actor(channel);
    if (channel_validate(c, ch) != 0) {
        if (ch != NULL)
            channel_notify_error(ch, "Channel not ready");
        return $R_CONT(c$cont, B_None);
    }

    channel_queue_write(ch, data);
    client_drive(c);

    return $R_CONT(c$cont, B_None);
}

$R sshQ_ClientD_channel_send_eofG_local(sshQ_Client self, $Cont c$cont, sshQ_Channel channel) {
    ssh_client_ctx *c = client_from_actor(self);
    ssh_channel_ctx *ch = channel_from_actor(channel);
    if (channel_validate(c, ch) != 0)
        return $R_CONT(c$cont, B_None);

    ch->send_eof = 1;
    client_drive(c);

    return $R_CONT(c$cont, B_None);
}

$R sshQ_ClientD_channel_closeG_local(sshQ_Client self, $Cont c$cont, sshQ_Channel channel) {
    ssh_client_ctx *c = client_from_actor(self);
    ssh_channel_ctx *ch = channel_from_actor(channel);
    if (channel_validate(c, ch) != 0)
        return $R_CONT(c$cont, B_None);

    ch->send_eof = 1;
    ch->close_requested = 1;
    client_drive(c);

    return $R_CONT(c$cont, B_None);
}

// --- Server implementation

static void server_notify_listen(ssh_server_ctx *s, const char *err) {
    if (s == NULL)
        return;
    if (s->listen_notified)
        return;
    if (s->on_listen) {
        $action2 f = ($action2)s->on_listen;
        f->$class->__asyn__(f, s->actor, err ? to$str((char *)err) : B_None);
    }
    s->listen_notified = 1;
    if (err == NULL)
        s->listen_ok = 1;
}

static void server_notify_close(ssh_server_ctx *s, const char *reason) {
    if (s->close_notified)
        return;
    if (!s->listen_ok)
        return;
    if (s->on_close) {
        $action2 f = ($action2)s->on_close;
        f->$class->__asyn__(f, s->actor, to$str((char *)reason));
    }
    s->close_notified = 1;
}

static void session_notify_close(ssh_server_session_ctx *s, const char *reason) {
    if (s->close_notified)
        return;
    if (s->on_close) {
        $action2 f = ($action2)s->on_close;
        f->$class->__asyn__(f, s->actor, to$str((char *)reason));
    }
    s->close_notified = 1;
}

static void server_channel_notify_close(ssh_server_channel_ctx *ch, const char *reason) {
    if (ch->close_notified)
        return;
    if (ch->on_close) {
        $action2 f = ($action2)ch->on_close;
        f->$class->__asyn__(f, ch->actor, to$str((char *)reason));
    }
    ch->close_notified = 1;
}

static int server_channel_data_cb(ssh_session session, ssh_channel channel, void *data,
                                  uint32_t len, int is_stderr, void *userdata) {
    ssh_server_channel_ctx *ch = (ssh_server_channel_ctx *)userdata;
    (void)session;
    (void)channel;
    if (ch == NULL || ch->state == SCHAN_STATE_CLOSED || ch->state == SCHAN_STATE_ERROR)
        return 0;
    if (len == 0)
        return 0;
    B_bytes out = to$bytesD_len((const char *)data, (size_t)len);
    if (is_stderr) {
        if (ch->on_stderr) {
            $action2 f = ($action2)ch->on_stderr;
            f->$class->__asyn__(f, ch->actor, out);
        }
    } else {
        if (ch->on_data) {
            $action2 f = ($action2)ch->on_data;
            f->$class->__asyn__(f, ch->actor, out);
        }
    }
    return (int)len;
}

static void server_channel_eof_cb(ssh_session session, ssh_channel channel, void *userdata) {
    ssh_server_channel_ctx *ch = (ssh_server_channel_ctx *)userdata;
    (void)session;
    (void)channel;
    if (ch == NULL)
        return;
    if (!ch->stdout_eof && ch->on_data) {
        $action2 f = ($action2)ch->on_data;
        f->$class->__asyn__(f, ch->actor, B_None);
        ch->stdout_eof = 1;
    }
    if (!ch->stderr_eof && ch->on_stderr) {
        $action2 f = ($action2)ch->on_stderr;
        f->$class->__asyn__(f, ch->actor, B_None);
        ch->stderr_eof = 1;
    }
}

static void server_channel_close_cb(ssh_session session, ssh_channel channel, void *userdata) {
    ssh_server_channel_ctx *ch = (ssh_server_channel_ctx *)userdata;
    (void)session;
    (void)channel;
    if (ch == NULL)
        return;
    ch->remote_close_seen = 1;
    server_channel_notify_close(ch, "closed");
}

static int server_channel_write_wontblock_cb(ssh_session session, ssh_channel channel,
                                             uint32_t bytes, void *userdata) {
    ssh_server_channel_ctx *ch = (ssh_server_channel_ctx *)userdata;
    (void)session;
    (void)channel;
    if (ch == NULL || ch->state == SCHAN_STATE_CLOSED || ch->state == SCHAN_STATE_ERROR)
        return 0;
    ch->write_wontblock = bytes > 0 ? 1 : 0;
    if (ssh_debug_enabled) {
        ssh_debug_log("server channel write_wontblock: bytes=%u ch=%p", bytes, (void *)ch);
    }
    return 0;
}

static void server_channel_setup_callbacks(ssh_server_channel_ctx *ch) {
    if (ch == NULL || ch->channel == NULL || ch->callbacks != NULL)
        return;
    struct ssh_channel_callbacks_struct *cb = acton_calloc(1, sizeof(*cb));
    ssh_callbacks_init(cb);
    cb->userdata = ch;
    cb->channel_data_function = server_channel_data_cb;
    cb->channel_eof_function = server_channel_eof_cb;
    cb->channel_close_function = server_channel_close_cb;
    cb->channel_write_wontblock_function = server_channel_write_wontblock_cb;
    ch->callbacks = cb;
    ssh_add_channel_callbacks(ch->channel, cb);
    if (ssh_debug_enabled) {
        ssh_debug_log("server channel callbacks set ch=%p", (void *)ch);
    }
}

static void server_channel_notify_eof(ssh_server_channel_ctx *ch) {
    if (ch->channel == NULL)
        return;
    if (ssh_channel_is_eof(ch->channel)) {
        if (!ch->stdout_eof && ch->on_data) {
            $action2 f = ($action2)ch->on_data;
            f->$class->__asyn__(f, ch->actor, B_None);
            ch->stdout_eof = 1;
        }
        if (!ch->stderr_eof && ch->on_stderr) {
            $action2 f = ($action2)ch->on_stderr;
            f->$class->__asyn__(f, ch->actor, B_None);
            ch->stderr_eof = 1;
        }
    }
}

static void server_channel_finalize(ssh_server_channel_ctx *ch) {
    if (ch->pending_req) {
        ssh_message_reply_default(ch->pending_req);
        ssh_message_free(ch->pending_req);
        ch->pending_req = NULL;
        ch->pending_req_type = SCHAN_REQ_NONE;
    }
    if (ch->channel != NULL) {
        if (ch->callbacks) {
            ssh_remove_channel_callbacks(ch->channel, ch->callbacks);
            ch->callbacks = NULL;
        }
        ssh_channel_free(ch->channel);
        ch->channel = NULL;
    }
    if (!ch->stdout_eof && ch->on_data) {
        $action2 f = ($action2)ch->on_data;
        f->$class->__asyn__(f, ch->actor, B_None);
        ch->stdout_eof = 1;
    }
    if (!ch->stderr_eof && ch->on_stderr) {
        $action2 f = ($action2)ch->on_stderr;
        f->$class->__asyn__(f, ch->actor, B_None);
        ch->stderr_eof = 1;
    }
    server_channel_notify_close(ch, "closed");
    if (ch->actor)
        ch->actor->_channel_id = toB_u64(0);
    ch->state = SCHAN_STATE_CLOSED;
}

static void server_channel_queue_write(ssh_server_channel_ctx *ch, B_bytes data, int is_stderr) {
    server_write_chunk_t *chunk = acton_calloc(1, sizeof(server_write_chunk_t));
    chunk->data = data;
    chunk->offset = 0;
    chunk->is_stderr = is_stderr;
    chunk->next = NULL;
    if (ch->write_tail) {
        ch->write_tail->next = chunk;
    } else {
        ch->write_head = chunk;
    }
    ch->write_tail = chunk;
    if (ssh_debug_enabled) {
        ssh_debug_log("server channel queue write: %zu bytes", data ? data->nbytes : 0);
    }
}

static void server_channel_try_write(ssh_server_session_ctx *s, ssh_server_channel_ctx *ch) {
    while (ch->write_head != NULL && ch->write_head->data->nbytes == ch->write_head->offset) {
        server_write_chunk_t *chunk = ch->write_head;
        ch->write_head = chunk->next;
        if (ch->write_head == NULL)
            ch->write_tail = NULL;
    }

    if (ch->write_head == NULL || !ch->write_wontblock || session_has_pending_write(s->session))
        return;

    server_write_chunk_t *chunk = ch->write_head;
    size_t remaining = chunk->data->nbytes - chunk->offset;
    ch->write_wontblock = 0;
    int rc;
    if (chunk->is_stderr) {
        rc = ssh_channel_write_stderr(ch->channel, chunk->data->str + chunk->offset, (uint32_t)remaining);
    } else {
        rc = ssh_channel_write(ch->channel, chunk->data->str + chunk->offset, (uint32_t)remaining);
    }
    if (rc > 0) {
        chunk->offset += (size_t)rc;
        if (ssh_debug_enabled) {
            ssh_debug_log("server channel wrote %d bytes", rc);
        }
        if (chunk->offset >= chunk->data->nbytes) {
            ch->write_head = chunk->next;
            if (ch->write_head == NULL)
                ch->write_tail = NULL;
        }
    } else if (rc == 0 || rc == SSH_AGAIN) {
        s->write_ready = 0;
        if (ssh_debug_enabled) {
            unsigned int window = ssh_channel_window_size(ch->channel);
            ssh_debug_log("server channel write pending rc=%d remaining=%zu window=%u",
                          rc, remaining, window);
        }
        return;
    } else {
        char errmsg[256] = {0};
        snprintf(errmsg, sizeof(errmsg), "SSH server channel write error: %s", ssh_get_error(s->session));
        server_channel_notify_close(ch, errmsg);
        ch->state = SCHAN_STATE_ERROR;
        return;
    }
}

static int server_channel_read_stream(ssh_server_session_ctx *s, ssh_server_channel_ctx *ch, int is_stderr) {
    char buf[SSH_READ_BUFSIZE];
    int read_any = 0;
    for (;;) {
        int n = ssh_channel_read_buffered(ch->channel, buf, sizeof(buf), is_stderr);
        if (ssh_debug_enabled) {
            ssh_debug_log("server channel read: rc=%d stderr=%d", n, is_stderr);
        }
        if (n > 0) {
            read_any = 1;
            B_bytes out = to$bytesD_len(buf, n);
            if (is_stderr) {
                if (ch->on_stderr) {
                    $action2 f = ($action2)ch->on_stderr;
                    f->$class->__asyn__(f, ch->actor, out);
                }
            } else {
                if (ch->on_data) {
                    $action2 f = ($action2)ch->on_data;
                    f->$class->__asyn__(f, ch->actor, out);
                }
            }
            continue;
        }
        if (n == 0 || n == SSH_AGAIN) {
            break;
        }
        if (n == SSH_EOF) {
            break;
        }
        if (n == SSH_ERROR) {
            char errmsg[256] = {0};
            snprintf(errmsg, sizeof(errmsg), "SSH server channel read error: %s", ssh_get_error(s->session));
            server_channel_notify_close(ch, errmsg);
            ch->state = SCHAN_STATE_ERROR;
            break;
        }
    }
    return read_any;
}

static void server_channel_drive(ssh_server_session_ctx *s, ssh_server_channel_ctx *ch) {
    if (ch->state == SCHAN_STATE_CLOSED || ch->state == SCHAN_STATE_ERROR)
        return;

    if (ch->write_head != NULL) {
        server_channel_try_write(s, ch);
        if (ch->state == SCHAN_STATE_ERROR)
            return;
    }

    if (ch->send_eof && !ch->eof_sent && ch->write_head == NULL &&
        !session_has_pending_write(s->session)) {
        int rc = ssh_channel_send_eof(ch->channel);
        if (rc == SSH_OK) {
            ch->eof_sent = 1;
        } else if (rc == SSH_AGAIN) {
            s->write_ready = 0;
            return;
        } else {
            char errmsg[256] = {0};
            snprintf(errmsg, sizeof(errmsg), "SSH server send EOF failed: %s", ssh_get_error(s->session));
            server_channel_notify_close(ch, errmsg);
            ch->state = SCHAN_STATE_ERROR;
            return;
        }
    }

    if (ch->close_requested && !ch->close_sent && ch->write_head == NULL &&
        (!ch->send_eof || ch->eof_sent) &&
        !session_has_pending_write(s->session)) {
        int rc = ssh_channel_close(ch->channel);
        if (rc == SSH_OK) {
            ch->close_sent = 1;
            ch->state = SCHAN_STATE_CLOSING;
        } else if (rc == SSH_AGAIN) {
            s->write_ready = 0;
            return;
        } else {
            char errmsg[256] = {0};
            snprintf(errmsg, sizeof(errmsg), "SSH server channel close failed: %s", ssh_get_error(s->session));
            server_channel_notify_close(ch, errmsg);
            ch->state = SCHAN_STATE_ERROR;
            return;
        }
    }

    if (ch->callbacks == NULL) {
        for (int i = 0; i < SSH_IO_PUMP_LIMIT; i++) {
            int did = 0;
            did |= server_channel_read_stream(s, ch, 0);
            did |= server_channel_read_stream(s, ch, 1);
            if (!did)
                break;
        }
    }
    server_channel_notify_eof(ch);

    if (ch->channel != NULL && ch->remote_close_seen &&
        ssh_channel_is_closed(ch->channel)) {
        server_channel_finalize(ch);
    }
}

static void session_drive_channels(ssh_server_session_ctx *s) {
    ssh_server_channel_ctx *prev = NULL;
    ssh_server_channel_ctx *ch = s->channels;
    while (ch != NULL) {
        ssh_server_channel_ctx *next = ch->next;
        server_channel_drive(s, ch);
        if (ch->state == SCHAN_STATE_CLOSED || ch->state == SCHAN_STATE_ERROR) {
            if (prev != NULL) {
                prev->next = next;
            } else {
                s->channels = next;
            }
            ch->next = NULL;
        } else {
            prev = ch;
        }
        ch = next;
    }
}

static void session_fail(ssh_server_session_ctx *s, const char *msg) {
    if (s == NULL || s->state == SESSION_STATE_CLOSED || s->state == SESSION_STATE_ERROR)
        return;
    s->state = SESSION_STATE_ERROR;
    session_close_internal(s, msg);
}

static void session_start_auth_timer(ssh_server_session_ctx *s) {
    if (s == NULL || s->auth_timeout <= 0.0 || s->auth_timer != NULL)
        return;
    s->auth_timer = acton_calloc(1, sizeof(uv_timer_t));
    s->auth_timer->data = s;
    uv_timer_init(get_uv_loop(), s->auth_timer);
    uv_timer_start(s->auth_timer, session_auth_timeout_cb, (uint64_t)(s->auth_timeout * 1000.0), 0);
}

static void session_start_keepalive(ssh_server_session_ctx *s) {
    if (s == NULL || !s->keepalive_enabled || s->keepalive_interval <= 0.0 || s->keepalive_timer != NULL)
        return;
    s->keepalive_timer = acton_calloc(1, sizeof(uv_timer_t));
    s->keepalive_timer->data = s;
    uv_timer_init(get_uv_loop(), s->keepalive_timer);
    uv_timer_start(s->keepalive_timer, session_keepalive_cb, (uint64_t)(s->keepalive_interval * 1000.0), (uint64_t)(s->keepalive_interval * 1000.0));
}

static void server_fail(ssh_server_ctx *s, const char *msg) {
    if (s == NULL || s->state == SERVER_STATE_CLOSED || s->state == SERVER_STATE_ERROR)
        return;
    s->state = SERVER_STATE_ERROR;
    if (!s->listen_ok)
        server_notify_listen(s, msg);
    server_close_internal(s, msg);
}

static void session_auth_timeout_cb(uv_timer_t *timer) {
    ssh_server_session_ctx *s = (ssh_server_session_ctx *)timer->data;
    if (s == NULL)
        return;
    if (s->state == SESSION_STATE_AUTH) {
        session_fail(s, "SSH authentication timeout");
    }
}

static void session_keepalive_cb(uv_timer_t *timer) {
    ssh_server_session_ctx *s = (ssh_server_session_ctx *)timer->data;
    if (s == NULL || s->session == NULL)
        return;
    if (s->state != SESSION_STATE_READY)
        return;
    int rc = ssh_send_ignore(s->session, "keepalive");
    if (rc == SSH_AGAIN) {
        session_update_poll(s);
        return;
    }
    if (rc != SSH_OK) {
        char errmsg[256] = {0};
        snprintf(errmsg, sizeof(errmsg), "SSH server keepalive failed: %s", ssh_get_error(s->session));
        session_fail(s, errmsg);
        return;
    }
    session_update_poll(s);
}

static void session_update_poll(ssh_server_session_ctx *s) {
    if (s->poll == NULL || s->session == NULL)
        return;
    if (s->state == SESSION_STATE_CLOSING || s->state == SESSION_STATE_CLOSED)
        return;
    if (uv_is_closing((uv_handle_t *)s->poll))
        return;
    int status = ssh_get_status(s->session);
    if (status & SSH_CLOSED_ERROR) {
        session_fail(s, "SSH session closed with error");
        return;
    }
    if (status & SSH_CLOSED) {
        session_close_internal(s, "SSH session closed");
        return;
    }
    int flags = ssh_get_poll_flags(s->session);
    int pending = flags | status;
    int events = UV_READABLE;
    if (pending & SSH_WRITE_PENDING)
        events |= UV_WRITABLE;
    if ((events & UV_WRITABLE) == 0 && session_needs_write(s))
        events |= UV_WRITABLE;
    if (ssh_debug_enabled && (events != s->poll_events || (pending & SSH_WRITE_PENDING))) {
        ssh_debug_log("server update poll: status=0x%x flags=0x%x pending=0x%x events=0x%x state=%d",
                      status, flags, pending, events, s->state);
    }
    if (events != s->poll_events) {
        int uv_rc = uv_poll_start(s->poll, events, session_poll_cb);
        if (uv_rc != 0) {
            char errmsg[256] = {0};
            uv_strerror_r(uv_rc, errmsg + strlen(errmsg), sizeof(errmsg) - strlen(errmsg));
            session_fail(s, errmsg);
            return;
        }
        s->poll_events = events;
    }
}

static void session_pump_io(ssh_server_session_ctx *s) {
    if (s == NULL || s->session == NULL)
        return;
    int i;
    for (i = 0; i < SSH_IO_PUMP_LIMIT; i++) {
        int did = 0;
        if (s->session == NULL)
            return;
        int has_data = fd_has_data(s->fd);
        if (has_data) {
            if (ssh_debug_enabled) {
                ssh_debug_log("server pump: readable");
            }
            ssh_set_fd_toread(s->session);
            if (session_apply_poll_events(s->session, UV_READABLE) != 0) {
                char errmsg[256] = {0};
                format_session_error(s->session, "SSH poll callback error", errmsg, sizeof(errmsg));
                session_fail(s, errmsg);
                return;
            }
            session_drive(s);
            did = 1;
        }
        if (s->session == NULL)
            return;
        if (!did) {
            int status = ssh_get_status(s->session);
            if (status & SSH_READ_PENDING) {
                if (ssh_debug_enabled) {
                    ssh_debug_log("server pump: buffered read pending=0x%x", status);
                }
                session_drive(s);
                /* Avoid spinning when only buffered data remains. */
                break;
            }
        }
        if (!did)
            break;
    }
    if (ssh_debug_enabled && i >= SSH_IO_PUMP_LIMIT) {
        int status = ssh_get_status(s->session);
        int flags = ssh_get_poll_flags(s->session);
        ssh_debug_log("server pump: hit limit status=0x%x flags=0x%x", status, flags);
    }
}

static int session_needs_write(ssh_server_session_ctx *s) {
    if (s == NULL)
        return 0;
    ssh_server_channel_ctx *ch = s->channels;
    while (ch != NULL) {
        if (ch->pending_req != NULL || ch->write_head != NULL)
            return 1;
        if (ch->send_eof && !ch->eof_sent)
            return 1;
        if (ch->close_requested && !ch->close_sent)
            return 1;
        ch = ch->next;
    }
    return 0;
}

static void session_drive(ssh_server_session_ctx *s) {
    if (s == NULL)
        return;
    if (s->state == SESSION_STATE_ERROR || s->state == SESSION_STATE_CLOSED || s->state == SESSION_STATE_CLOSING)
        return;
    if (!s->attached)
        return;

    int spin = 0;
    while (1) {
        if (s->state == SESSION_STATE_KEYEX) {
            int rc = ssh_handle_key_exchange(s->session);
            if (rc == SSH_OK) {
                s->state = SESSION_STATE_AUTH;
                session_start_auth_timer(s);
                ssh_set_auth_methods(s->session, SSH_AUTH_METHOD_PASSWORD);
                continue;
            } else if (rc == SSH_AGAIN) {
                int status = ssh_get_status(s->session);
                if (status & SSH_WRITE_PENDING)
                    s->write_ready = 0;
                if ((status & SSH_READ_PENDING) && spin++ < SSH_IO_PUMP_LIMIT) {
                    if (ssh_debug_enabled) {
                        ssh_debug_log("server drive: buffered read pending during key exchange");
                    }
                    continue;
                }
                session_update_poll(s);
                return;
            } else {
                char errmsg[256] = {0};
                snprintf(errmsg, sizeof(errmsg), "SSH key exchange failed: %s", ssh_get_error(s->session));
                session_fail(s, errmsg);
                return;
            }
        }

        if (s->state == SESSION_STATE_AUTH) {
            if (s->pending_auth != NULL) {
                session_update_poll(s);
                return;
            }
            ssh_message msg = ssh_message_get(s->session);
            if (msg == NULL) {
                session_update_poll(s);
                return;
            }
            int type = ssh_message_type(msg);
            if (type == SSH_REQUEST_SERVICE) {
                const char *service = ssh_message_service_service(msg);
                if (service && strcmp(service, "ssh-userauth") == 0) {
                    ssh_message_service_reply_success(msg);
                } else {
                    ssh_message_reply_default(msg);
                }
                ssh_message_free(msg);
                continue;
            }
            if (type == SSH_REQUEST_AUTH && ssh_message_subtype(msg) == SSH_AUTH_METHOD_PASSWORD) {
                if (s->on_auth == NULL) {
                    ssh_message_auth_set_methods(msg, SSH_AUTH_METHOD_PASSWORD);
                    ssh_message_reply_default(msg);
                    ssh_message_free(msg);
                    continue;
                }
                const char *user = ssh_message_auth_user(msg);
#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#endif
                const char *pass = ssh_message_auth_password(msg);
#ifdef __clang__
#pragma clang diagnostic pop
#endif
                s->pending_auth = msg;
                sshQ_AuthRequest req = sshQ_AuthRequestG_new(
                    to$str((char *)"password"),
                    to$str((char *)(user ? user : "")),
                    pass ? to$str((char *)(pass)) : B_None,
                    B_None);
                $action2 f = ($action2)s->on_auth;
                f->$class->__asyn__(f, s->actor, req);
                session_update_poll(s);
                return;
            }
            ssh_message_reply_default(msg);
            ssh_message_free(msg);
            continue;
        }

        if (s->state == SESSION_STATE_READY) {
            if (s->pending_channel_open != NULL) {
                session_drive_channels(s);
                session_update_poll(s);
                return;
            }
            while (1) {
                ssh_message msg = ssh_message_get(s->session);
                if (msg == NULL)
                    break;
                int type = ssh_message_type(msg);
                if (type == SSH_REQUEST_CHANNEL_OPEN) {
                    if (s->pending_channel_open != NULL) {
                        ssh_message_reply_default(msg);
                        ssh_message_free(msg);
                    } else if (ssh_message_subtype(msg) != SSH_CHANNEL_SESSION) {
                        ssh_message_reply_default(msg);
                        ssh_message_free(msg);
                    } else if (s->on_channel_open == NULL) {
                        ssh_message_reply_default(msg);
                        ssh_message_free(msg);
                    } else {
                        s->pending_channel_open = msg;
                        $action f = ($action)s->on_channel_open;
                        f->$class->__asyn__(f, s->actor);
                        break;
                    }
                } else if (type == SSH_REQUEST_CHANNEL) {
                    ssh_channel chan = ssh_message_channel_request_channel(msg);
                    ssh_server_channel_ctx *ch = server_channel_from_ssh(s, chan);
                    if (ch == NULL || ch->pending_req != NULL) {
                        ssh_message_reply_default(msg);
                        ssh_message_free(msg);
                    } else if (ssh_message_subtype(msg) == SSH_CHANNEL_REQUEST_EXEC) {
                        if (s->on_exec == NULL) {
                            ssh_message_reply_default(msg);
                            ssh_message_free(msg);
                        } else {
                            const char *cmd = ssh_message_channel_request_command(msg);
                            ch->pending_req = msg;
                            ch->pending_req_type = SCHAN_REQ_EXEC;
                            $action3 f = ($action3)s->on_exec;
                            f->$class->__asyn__(f, s->actor, ch->actor,
                                               to$str((char *)(cmd ? cmd : "")));
                            break;
                        }
                    } else if (ssh_message_subtype(msg) == SSH_CHANNEL_REQUEST_SUBSYSTEM) {
                        if (s->on_subsystem == NULL) {
                            ssh_message_reply_default(msg);
                            ssh_message_free(msg);
                        } else {
                            const char *name = ssh_message_channel_request_subsystem(msg);
                            ch->pending_req = msg;
                            ch->pending_req_type = SCHAN_REQ_SUBSYSTEM;
                            $action3 f = ($action3)s->on_subsystem;
                            f->$class->__asyn__(f, s->actor, ch->actor,
                                               to$str((char *)(name ? name : "")));
                            break;
                        }
                    } else {
                        ssh_message_reply_default(msg);
                        ssh_message_free(msg);
                    }
                } else if (type == SSH_REQUEST_SERVICE) {
                    const char *service = ssh_message_service_service(msg);
                    if (service && strcmp(service, "ssh-connection") == 0) {
                        ssh_message_service_reply_success(msg);
                    } else {
                        ssh_message_reply_default(msg);
                    }
                    ssh_message_free(msg);
                } else {
                    ssh_message_reply_default(msg);
                    ssh_message_free(msg);
                }
            }
            session_drive_channels(s);
            session_update_poll(s);
            return;
        }
        return;
    }
}

static void session_poll_cb(uv_poll_t *handle, int status, int events) {
    ssh_server_session_ctx *s = (ssh_server_session_ctx *)handle->data;
    if (s == NULL)
        return;
    if (ssh_debug_enabled) {
        ssh_debug_log("server poll: status=%d events=0x%x state=%d", status, events, s->state);
    }
    if (status < 0) {
        char errmsg[256] = {0};
        snprintf(errmsg, sizeof(errmsg), "SSH session poll error: %s", uv_strerror(status));
        session_fail(s, errmsg);
        return;
    }
    int libssh_events = 0;
    if ((events & UV_READABLE) && fd_has_data(s->fd)) {
        ssh_set_fd_toread(s->session);
        libssh_events |= UV_READABLE;
    }
    if (events & UV_WRITABLE) {
        s->write_ready = 1;
        ssh_set_fd_towrite(s->session);
        libssh_events |= UV_WRITABLE;
    }
    if (session_apply_poll_events(s->session, libssh_events) != 0) {
        char errmsg[256] = {0};
        format_session_error(s->session, "SSH poll callback error", errmsg, sizeof(errmsg));
        session_fail(s, errmsg);
        return;
    }
    session_drive(s);
    session_pump_io(s);
    s->write_ready = 0;
}

static void server_poll_cb(uv_poll_t *handle, int status, int events) {
    ssh_server_ctx *s = (ssh_server_ctx *)handle->data;
    if (s == NULL)
        return;
    if (ssh_debug_enabled) {
        ssh_debug_log("server listen poll: status=%d events=0x%x", status, events);
    }
    if (status < 0) {
        char errmsg[256] = {0};
        snprintf(errmsg, sizeof(errmsg), "SSH server poll error: %s", uv_strerror(status));
        server_fail(s, errmsg);
        return;
    }
    if (events & UV_READABLE)
        server_accept(s);
}

static void server_accept(ssh_server_ctx *s) {
    if (s == NULL || s->state != SERVER_STATE_LISTENING)
        return;

    while (1) {
        socket_t fd = accept(s->fd, NULL, NULL);
        if (fd == SSH_INVALID_SOCKET) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return;
            }
            char errmsg[256] = {0};
            snprintf(errmsg, sizeof(errmsg), "SSH accept failed: %s", strerror(errno));
            server_fail(s, errmsg);
            return;
        }

        if (fd_set_nonblocking(fd) != 0) {
            close(fd);
            server_fail(s, "Failed to set accepted fd nonblocking");
            return;
        }

        ssh_session session = ssh_new();
        if (session == NULL) {
            close(fd);
            server_fail(s, "Failed to create SSH session");
            return;
        }

        if (ssh_debug_enabled) {
            ssh_debug_log("server accept: actor=%p", (void *)s->actor);
        }

        int rc = ssh_bind_accept_fd(s->bind, session, fd);
        if (rc != SSH_OK) {
            char errmsg[256] = {0};
            snprintf(errmsg, sizeof(errmsg), "SSH accept failed: %s", ssh_get_error(s->bind));
            close(fd);
            ssh_free(session);
            server_fail(s, errmsg);
            return;
        }

        ssh_set_blocking(session, 0);
        ssh_server_session_ctx *sess = acton_calloc(1, sizeof(ssh_server_session_ctx));
        sess->server = s;
        sess->session = session;
        sess->state = SESSION_STATE_KEYEX;
        sess->fd = ssh_get_fd(session);
        sess->owner_wt = s->actor ? (int)s->actor->$affinity : 0;
        if (sess->fd < 0) {
            ssh_free(session);
            server_fail(s, "Failed to get SSH session fd");
            return;
        }
        sess->poll = acton_calloc(1, sizeof(uv_poll_t));
        sess->poll->data = sess;
        int uv_rc = uv_poll_init(get_uv_loop(), sess->poll, sess->fd);
        if (uv_rc != 0) {
            char errmsg[256] = {0};
            uv_strerror_r(uv_rc, errmsg + strlen(errmsg), sizeof(errmsg) - strlen(errmsg));
            ssh_free(session);
            server_fail(s, errmsg);
            return;
        }
        sess->poll_events = UV_READABLE | UV_WRITABLE;
        uv_rc = uv_poll_start(sess->poll, sess->poll_events, session_poll_cb);
        if (uv_rc != 0) {
            char errmsg[256] = {0};
            uv_strerror_r(uv_rc, errmsg + strlen(errmsg), sizeof(errmsg) - strlen(errmsg));
            ssh_free(session);
            server_fail(s, errmsg);
            return;
        }

        sess->next = s->sessions;
        s->sessions = sess;

        if (ssh_debug_enabled) {
            ssh_debug_log("server accept: session fd=%d", sess->fd);
        }

        if (s->actor) {
            sshQ_Server act = (sshQ_Server)s->actor;
            if (ssh_debug_enabled) {
                ssh_debug_log("server accept: scheduling session pending act=%p session=%p", (void *)act, (void *)sess);
            }
            act->$class->on_session_pending(act, toB_u64((unsigned long)sess));
            if (ssh_debug_enabled) {
                ssh_debug_log("server accept: on_session_pending call returned session=%p", (void *)sess);
            }
        }
    }
}

static void server_remove_session(ssh_server_ctx *s, ssh_server_session_ctx *sess) {
    if (s == NULL || sess == NULL)
        return;
    ssh_server_session_ctx *prev = NULL;
    ssh_server_session_ctx *cur = s->sessions;
    while (cur != NULL) {
        if (cur == sess) {
            if (prev != NULL)
                prev->next = cur->next;
            else
                s->sessions = cur->next;
            break;
        }
        prev = cur;
        cur = cur->next;
    }
}

static void server_finalize(ssh_server_ctx *s) {
    if (s == NULL || s->close_finalized)
        return;
    s->close_finalized = 1;

    if (s->bind != NULL) {
        ssh_bind_free(s->bind);
        s->bind = NULL;
    }
    if (s->hostkey != NULL) {
        ssh_key_free(s->hostkey);
        s->hostkey = NULL;
    }

    server_notify_close(s, s->close_reason ? s->close_reason : "closed");
    s->state = SERVER_STATE_CLOSED;
    if (s->actor)
        s->actor->_server = toB_u64(0);
}

static void session_finalize(ssh_server_session_ctx *s) {
    if (s == NULL || s->close_finalized)
        return;
    s->close_finalized = 1;

    if (s->session != NULL) {
        ssh_disconnect(s->session);
        ssh_free(s->session);
        s->session = NULL;
    }

    server_remove_session(s->server, s);
    session_notify_close(s, s->close_reason ? s->close_reason : "closed");
    s->state = SESSION_STATE_CLOSED;
    if (s->actor)
        s->actor->_session_id = toB_u64(0);
}

static void server_close_internal(ssh_server_ctx *s, const char *reason) {
    if (s == NULL || s->state == SERVER_STATE_CLOSED || s->state == SERVER_STATE_CLOSING)
        return;

    if (!s->listen_ok && !s->listen_notified) {
        server_notify_listen(s, reason ? reason : "closed");
    }

    s->state = SERVER_STATE_CLOSING;
    if (reason != NULL && s->close_reason == NULL)
        s->close_reason = acton_strdup(reason);

    if (s->poll != NULL) {
        close_poll(&s->poll, server_poll_close_cb);
    }

    ssh_server_session_ctx *sess = s->sessions;
    while (sess != NULL) {
        ssh_server_session_ctx *next = sess->next;
        session_close_internal(sess, "Server closed");
        sess = next;
    }
    s->sessions = NULL;

    if (s->poll != NULL)
        return;

    server_finalize(s);
}

static void session_close_internal(ssh_server_session_ctx *s, const char *reason) {
    if (s == NULL || s->state == SESSION_STATE_CLOSED || s->state == SESSION_STATE_CLOSING)
        return;

    s->state = SESSION_STATE_CLOSING;
    if (reason != NULL && s->close_reason == NULL)
        s->close_reason = acton_strdup(reason);

    stop_timer(&s->auth_timer, session_timer_close_cb);
    stop_timer(&s->keepalive_timer, session_timer_close_cb);

    if (s->poll != NULL) {
        close_poll(&s->poll, session_poll_close_cb);
        s->poll_events = 0;
    }

    ssh_server_channel_ctx *ch = s->channels;
    while (ch != NULL) {
        ssh_server_channel_ctx *next = ch->next;
        server_channel_notify_close(ch, "Session closed");
        server_channel_finalize(ch);
        ch->next = NULL;
        ch = next;
    }
    s->channels = NULL;

    if (s->pending_auth) {
        ssh_message_reply_default(s->pending_auth);
        ssh_message_free(s->pending_auth);
        s->pending_auth = NULL;
    }
    if (s->pending_channel_open) {
        ssh_message_reply_default(s->pending_channel_open);
        ssh_message_free(s->pending_channel_open);
        s->pending_channel_open = NULL;
    }

    if (s->poll != NULL)
        return;

    session_finalize(s);
}

static enum ssh_keytypes_e parse_hostkey_type(const char *type_str, int *param_out) {
    if (type_str == NULL)
        return SSH_KEYTYPE_UNKNOWN;
    if (strcmp(type_str, "ed25519") == 0) {
        if (param_out)
            *param_out = 0;
        return SSH_KEYTYPE_ED25519;
    }
    if (strcmp(type_str, "rsa") == 0) {
        if (param_out)
            *param_out = 2048;
        return SSH_KEYTYPE_RSA;
    }
    if (strcmp(type_str, "ecdsa") == 0) {
        if (param_out)
            *param_out = 256;
        return SSH_KEYTYPE_ECDSA;
    }
    return SSH_KEYTYPE_UNKNOWN;
}

$R sshQ_ServerD__pin_affinityG_local(sshQ_Server self, $Cont c$cont) {
    pin_actor_affinity();
    return $R_CONT(c$cont, B_None);
}

$R sshQ_ServerD__initG_local(sshQ_Server self, $Cont c$cont) {
    ssh_configure_libssh_logging();
    if (ssh_debug_enabled) {
        log_info("ssh server init: self=%p", (void *)self);
    }
    ssh_server_ctx *s = acton_calloc(1, sizeof(ssh_server_ctx));
    s->actor = self;
    s->on_listen = ($action2)self->_on_listen;
    s->on_close = ($action2)self->_on_close;
    s->state = SERVER_STATE_INIT;

    self->_server = toB_u64((unsigned long)s);

    s->bind = ssh_bind_new();
    if (s->bind == NULL) {
        server_fail(s, "Failed to create SSH bind");
        return $R_CONT(c$cont, B_None);
    }

    int rc;
    bool process_config = false;

    rc = ssh_bind_options_set(s->bind, SSH_BIND_OPTIONS_PROCESS_CONFIG, &process_config);
    if (rc != SSH_OK) {
        server_fail(s, "Failed to disable SSH bind config processing");
        return $R_CONT(c$cont, B_None);
    }

    const char *host = (const char *)fromB_str(self->_host);
    int port = (int)fromB_u16(self->_port);
    rc = ssh_bind_options_set(s->bind, SSH_BIND_OPTIONS_BINDADDR, host);
    if (rc != SSH_OK) {
        server_fail(s, "Failed to set bind address");
        return $R_CONT(c$cont, B_None);
    }
    rc = ssh_bind_options_set(s->bind, SSH_BIND_OPTIONS_BINDPORT, &port);
    if (rc != SSH_OK) {
        server_fail(s, "Failed to set bind port");
        return $R_CONT(c$cont, B_None);
    }

    if (self->_host_key_path != B_None) {
        const char *path = (const char *)fromB_str(self->_host_key_path);
        rc = ssh_pki_import_privkey_file(path, NULL, NULL, NULL, &s->hostkey);
        if (rc != SSH_OK) {
            char errmsg[256] = {0};
            snprintf(errmsg, sizeof(errmsg), "Failed to load host key: %s", ssh_get_error(s->bind));
            server_fail(s, errmsg);
            return $R_CONT(c$cont, B_None);
        }
    } else {
        const char *type_str = (const char *)fromB_str(self->_host_key_type);
        int param = fromB_int(self->_host_key_bits);
        int default_param = 0;
        enum ssh_keytypes_e type = parse_hostkey_type(type_str, &default_param);
        if (type == SSH_KEYTYPE_UNKNOWN) {
            server_fail(s, "Unsupported host key type");
            return $R_CONT(c$cont, B_None);
        }
        if (type == SSH_KEYTYPE_ED25519) {
            param = 0;
        } else if (param <= 0) {
            param = default_param;
        }
        rc = ssh_pki_generate(type, param, &s->hostkey);
        if (rc != SSH_OK) {
            server_fail(s, "Failed to generate host key");
            return $R_CONT(c$cont, B_None);
        }
    }

    rc = ssh_bind_options_set(s->bind, SSH_BIND_OPTIONS_IMPORT_KEY, s->hostkey);
    if (rc != SSH_OK) {
        server_fail(s, "Failed to set host key");
        return $R_CONT(c$cont, B_None);
    }

    ssh_bind_set_blocking(s->bind, 0);

    rc = ssh_bind_listen(s->bind);
    if (rc != SSH_OK) {
        char errmsg[256] = {0};
        snprintf(errmsg, sizeof(errmsg), "SSH listen failed: %s", ssh_get_error(s->bind));
        server_fail(s, errmsg);
        return $R_CONT(c$cont, B_None);
    }

    s->fd = ssh_bind_get_fd(s->bind);
    if (s->fd < 0) {
        server_fail(s, "Failed to get bind fd");
        return $R_CONT(c$cont, B_None);
    }
    if (fd_set_nonblocking(s->fd) != 0) {
        server_fail(s, "Failed to set bind fd nonblocking");
        return $R_CONT(c$cont, B_None);
    }

    s->poll = acton_calloc(1, sizeof(uv_poll_t));
    s->poll->data = s;
    int uv_rc = uv_poll_init(get_uv_loop(), s->poll, s->fd);
    if (uv_rc != 0) {
        char errmsg[256] = {0};
        uv_strerror_r(uv_rc, errmsg + strlen(errmsg), sizeof(errmsg) - strlen(errmsg));
        server_fail(s, errmsg);
        return $R_CONT(c$cont, B_None);
    }
    uv_rc = uv_poll_start(s->poll, UV_READABLE, server_poll_cb);
    if (uv_rc != 0) {
        char errmsg[256] = {0};
        uv_strerror_r(uv_rc, errmsg + strlen(errmsg), sizeof(errmsg) - strlen(errmsg));
        server_fail(s, errmsg);
        return $R_CONT(c$cont, B_None);
    }

    s->state = SERVER_STATE_LISTENING;
    server_notify_listen(s, NULL);

    return $R_CONT(c$cont, B_None);
}

$R sshQ_ServerD_closeG_local(sshQ_Server self, $Cont c$cont) {
    ssh_server_ctx *s = server_from_actor(self);
    if (s == NULL)
        return $R_CONT(c$cont, B_None);
    server_close_internal(s, "closed");
    return $R_CONT(c$cont, B_None);
}

$R sshQ_ServerSessionD__pin_affinityG_local(sshQ_ServerSession self, $Cont c$cont) {
    ssh_server_session_ctx *s = (ssh_server_session_ctx *)(unsigned long)fromB_u64(self->session_id);
    if (s != NULL && s->owner_wt >= 0) {
        set_actor_affinity(s->owner_wt);
    } else {
        pin_actor_affinity();
    }
    return $R_CONT(c$cont, B_None);
}

$R sshQ_ServerSessionD__attachG_local(sshQ_ServerSession self, $Cont c$cont, B_u64 session_id) {
    ssh_server_session_ctx *s = (ssh_server_session_ctx *)(unsigned long)fromB_u64(session_id);
    if (s == NULL)
        return $R_CONT(c$cont, B_None);
    if (ssh_debug_enabled) {
        ssh_debug_log("server session attach: id=%llu", (unsigned long long)fromB_u64(session_id));
    }
    s->actor = self;
    self->_session_id = session_id;
    s->attached = 1;
    s->on_auth = ($action2)self->_on_auth;
    s->on_channel_open = ($action)self->_on_channel_open;
    s->on_exec = (self->_on_exec == B_None) ? NULL : ($action3)self->_on_exec;
    s->on_subsystem = (self->_on_subsystem == B_None) ? NULL : ($action3)self->_on_subsystem;
    s->on_close = (self->_on_close == B_None) ? NULL : ($action2)self->_on_close;
    s->auth_timeout = fromB_float(self->server->_auth_timeout);
    s->keepalive_interval = fromB_float(self->server->_keepalive_interval);
    s->keepalive_enabled = fromB_bool(self->server->_keepalive_enabled) ? 1 : 0;
    if (ssh_debug_enabled) {
        ssh_debug_log("server session attach: callbacks set, driving session");
    }
    session_drive(s);
    if (ssh_debug_enabled) {
        ssh_debug_log("server session attach: session_drive returned");
    }
    return $R_CONT(c$cont, B_None);
}

$R sshQ_ServerSessionD_accept_authG_local(sshQ_ServerSession self, $Cont c$cont) {
    ssh_server_session_ctx *s = session_from_actor(self);
    if (s == NULL || s->pending_auth == NULL)
        return $R_CONT(c$cont, B_None);

    ssh_message_auth_reply_success(s->pending_auth, 0);
    ssh_message_free(s->pending_auth);
    s->pending_auth = NULL;
    s->state = SESSION_STATE_READY;
    stop_timer(&s->auth_timer, session_timer_close_cb);
    session_start_keepalive(s);
    session_drive(s);

    return $R_CONT(c$cont, B_None);
}

$R sshQ_ServerSessionD_reject_authG_local(sshQ_ServerSession self, $Cont c$cont, B_str reason) {
    ssh_server_session_ctx *s = session_from_actor(self);
    if (s == NULL || s->pending_auth == NULL)
        return $R_CONT(c$cont, B_None);

    ssh_message_auth_set_methods(s->pending_auth, SSH_AUTH_METHOD_PASSWORD);
    ssh_message_reply_default(s->pending_auth);
    ssh_message_free(s->pending_auth);
    s->pending_auth = NULL;
    (void)reason;
    session_drive(s);

    return $R_CONT(c$cont, B_None);
}

$R sshQ_ServerSessionD_accept_channel_openG_local(sshQ_ServerSession self, $Cont c$cont, sshQ_ServerChannel channel,
                                                  $action on_data,
                                                  $action on_stderr,
                                                  $action on_close) {
    ssh_server_session_ctx *s = session_from_actor(self);
    if (s == NULL || s->pending_channel_open == NULL)
        return $R_CONT(c$cont, B_None);

    ssh_channel chan = ssh_message_channel_request_open_reply_accept(s->pending_channel_open);
    if (chan == NULL) {
        ssh_message_reply_default(s->pending_channel_open);
        ssh_message_free(s->pending_channel_open);
        s->pending_channel_open = NULL;
        if (on_close) {
            $action2 f = ($action2)on_close;
            f->$class->__asyn__(f, channel, to$str((char *)"Failed to accept channel open"));
        }
        session_drive(s);
        return $R_CONT(c$cont, B_None);
    }
    ssh_channel_set_blocking(chan, 0);
    ssh_message_free(s->pending_channel_open);
    s->pending_channel_open = NULL;

    ssh_server_channel_ctx *ch = acton_calloc(1, sizeof(ssh_server_channel_ctx));
    ch->channel = chan;
    ch->session = s;
    ch->actor = channel;
    ch->callbacks = NULL;
    ch->state = SCHAN_STATE_OPEN;
    ch->send_eof = 0;
    ch->close_requested = 0;
    ch->close_sent = 0;
    ch->eof_sent = 0;
    ch->stdout_eof = 0;
    ch->stderr_eof = 0;
    ch->pending_req = NULL;
    ch->pending_req_type = SCHAN_REQ_NONE;
    ch->on_data = ($action2)on_data;
    ch->on_stderr = ($action2)on_stderr;
    ch->on_close = ($action2)on_close;
    server_channel_setup_callbacks(ch);
    if (ssh_debug_enabled) {
        ssh_debug_log("server channel new ch=%p callbacks=%p", (void *)ch, (void *)ch->callbacks);
    }

    ch->next = s->channels;
    s->channels = ch;
    channel->_channel_id = toB_u64((unsigned long)ch);

    session_drive(s);
    return $R_CONT(c$cont, B_None);
}

$R sshQ_ServerSessionD_reject_channelG_local(sshQ_ServerSession self, $Cont c$cont, B_str reason) {
    ssh_server_session_ctx *s = session_from_actor(self);
    if (s == NULL || s->pending_channel_open == NULL)
        return $R_CONT(c$cont, B_None);

    ssh_message_reply_default(s->pending_channel_open);
    ssh_message_free(s->pending_channel_open);
    s->pending_channel_open = NULL;
    (void)reason;
    session_drive(s);
    return $R_CONT(c$cont, B_None);
}

$R sshQ_ServerSessionD_closeG_local(sshQ_ServerSession self, $Cont c$cont) {
    ssh_server_session_ctx *s = session_from_actor(self);
    if (s == NULL)
        return $R_CONT(c$cont, B_None);
    session_close_internal(s, "closed");
    return $R_CONT(c$cont, B_None);
}

$R sshQ_ServerSessionD_channel_accept_requestG_local(sshQ_ServerSession self, $Cont c$cont, sshQ_ServerChannel channel) {
    ssh_server_session_ctx *s = session_from_actor(self);
    ssh_server_channel_ctx *ch = server_channel_from_actor(channel);
    if (s == NULL || ch == NULL || ch->pending_req == NULL)
        return $R_CONT(c$cont, B_None);

    ssh_message_channel_request_reply_success(ch->pending_req);
    ssh_message_free(ch->pending_req);
    ch->pending_req = NULL;
    ch->pending_req_type = SCHAN_REQ_NONE;
    session_drive(s);
    return $R_CONT(c$cont, B_None);
}

$R sshQ_ServerSessionD_channel_reject_requestG_local(sshQ_ServerSession self, $Cont c$cont, sshQ_ServerChannel channel, B_str reason) {
    ssh_server_session_ctx *s = session_from_actor(self);
    ssh_server_channel_ctx *ch = server_channel_from_actor(channel);
    if (s == NULL || ch == NULL || ch->pending_req == NULL)
        return $R_CONT(c$cont, B_None);

    ssh_message_reply_default(ch->pending_req);
    ssh_message_free(ch->pending_req);
    ch->pending_req = NULL;
    ch->pending_req_type = SCHAN_REQ_NONE;
    (void)reason;
    session_drive(s);
    return $R_CONT(c$cont, B_None);
}

$R sshQ_ServerSessionD_channel_writeG_local(sshQ_ServerSession self, $Cont c$cont, sshQ_ServerChannel channel, B_bytes data) {
    ssh_server_session_ctx *s = session_from_actor(self);
    ssh_server_channel_ctx *ch = server_channel_from_actor(channel);
    if (s == NULL || ch == NULL)
        return $R_CONT(c$cont, B_None);
    server_channel_queue_write(ch, data, 0);
    session_drive(s);
    return $R_CONT(c$cont, B_None);
}

$R sshQ_ServerSessionD_channel_write_stderrG_local(sshQ_ServerSession self, $Cont c$cont, sshQ_ServerChannel channel, B_bytes data) {
    ssh_server_session_ctx *s = session_from_actor(self);
    ssh_server_channel_ctx *ch = server_channel_from_actor(channel);
    if (s == NULL || ch == NULL)
        return $R_CONT(c$cont, B_None);
    server_channel_queue_write(ch, data, 1);
    session_drive(s);
    return $R_CONT(c$cont, B_None);
}

$R sshQ_ServerSessionD_channel_send_eofG_local(sshQ_ServerSession self, $Cont c$cont, sshQ_ServerChannel channel) {
    ssh_server_session_ctx *s = session_from_actor(self);
    ssh_server_channel_ctx *ch = server_channel_from_actor(channel);
    if (s == NULL || ch == NULL)
        return $R_CONT(c$cont, B_None);
    ch->send_eof = 1;
    session_drive(s);
    return $R_CONT(c$cont, B_None);
}

$R sshQ_ServerSessionD_channel_send_exit_statusG_local(sshQ_ServerSession self, $Cont c$cont, sshQ_ServerChannel channel, B_int status) {
    ssh_server_session_ctx *s = session_from_actor(self);
    ssh_server_channel_ctx *ch = server_channel_from_actor(channel);
    if (s == NULL || ch == NULL || ch->channel == NULL)
        return $R_CONT(c$cont, B_None);
    int rc = ssh_channel_request_send_exit_status(ch->channel, fromB_int(status));
    if (rc != SSH_OK) {
        char errmsg[256] = {0};
        snprintf(errmsg, sizeof(errmsg), "SSH server send exit status failed: %s", ssh_get_error(s->session));
        server_channel_notify_close(ch, errmsg);
    }
    session_drive(s);
    return $R_CONT(c$cont, B_None);
}

$R sshQ_ServerSessionD_channel_closeG_local(sshQ_ServerSession self, $Cont c$cont, sshQ_ServerChannel channel) {
    ssh_server_session_ctx *s = session_from_actor(self);
    ssh_server_channel_ctx *ch = server_channel_from_actor(channel);
    if (s == NULL || ch == NULL)
        return $R_CONT(c$cont, B_None);
    ch->send_eof = 1;
    ch->close_requested = 1;
    session_drive(s);
    return $R_CONT(c$cont, B_None);
}
