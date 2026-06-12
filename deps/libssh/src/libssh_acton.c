/* Acton additions to libssh — see include/libssh/libssh_acton.h.
 *
 * This file is compiled together with the unmodified upstream libssh source
 * tarball (pinned in build.zig.zon); it only uses internals exposed through
 * libssh's private headers. The two functions are taken verbatim from the
 * actonlang/libssh fork (commits "Expose session poll handler" and "Expose
 * ssh_channel_read_buffered for callback-driven reads").
 *
 * grow_window() and ssh_channel_has_unread_data() are static helpers inside
 * src/channels.c upstream, so they cannot be called from another translation
 * unit; the copies below must be kept in sync with the pinned tarball
 * (libssh 0.11.0).
 */
#include "config.h"

#include <stdbool.h>
#include <string.h>

#include "libssh/priv.h"
#include "libssh/libssh.h"
#include "libssh/buffer.h"
#include "libssh/channels.h"
#include "libssh/packet.h"
#include "libssh/poll.h"
#include "libssh/session.h"
#include "libssh/socket.h"
#include "libssh/ssh2.h"

#include "libssh/libssh_acton.h"

/* Copies of #defines and static helpers from src/channels.c @ 0.11.0. */
#define CHANNEL_MAX_PACKET 32768
#define WINDOW_DEFAULT (64 * CHANNEL_MAX_PACKET)

static int grow_window(ssh_session session, ssh_channel channel)
{
    uint32_t used;
    uint32_t increment;
    int rc;

    /* Calculate the increment taking into account what the peer may still
     * send (local_window) and what we've already buffered (stdout_buffer and
     * stderr_buffer).
     */
    used = channel->local_window;
    if (channel->stdout_buffer != NULL) {
        used += ssh_buffer_get_len(channel->stdout_buffer);
    }
    if (channel->stderr_buffer != NULL) {
        used += ssh_buffer_get_len(channel->stderr_buffer);
    }
    /* Avoid a negative increment in case the peer sent more than the window
     * allowed */
    increment = WINDOW_DEFAULT > used ? WINDOW_DEFAULT - used : 0;
    /* Don't grow until we can request at least half a window */
    if (increment < (WINDOW_DEFAULT / 2)) {
        SSH_LOG(SSH_LOG_DEBUG,
                "growing window (channel %" PRIu32 ":%" PRIu32 ") to %" PRIu32
                " bytes : not needed (%" PRIu32 " bytes)",
                channel->local_channel, channel->remote_channel,
                WINDOW_DEFAULT, channel->local_window);

        return SSH_OK;
    }

    rc = ssh_buffer_pack(session->out_buffer,
                         "bdd",
                         SSH2_MSG_CHANNEL_WINDOW_ADJUST,
                         channel->remote_channel,
                         increment);
    if (rc != SSH_OK) {
        ssh_set_error_oom(session);
        goto error;
    }

    if (ssh_packet_send(session) == SSH_ERROR) {
        goto error;
    }

    SSH_LOG(SSH_LOG_DEBUG,
            "growing window (channel %" PRIu32 ":%" PRIu32 ") by %" PRIu32
            " bytes",
            channel->local_channel,
            channel->remote_channel,
            increment);

    channel->local_window += increment;

    return SSH_OK;
error:
    ssh_buffer_reinit(session->out_buffer);

    return SSH_ERROR;
}

static bool ssh_channel_has_unread_data(ssh_channel channel)
{
    if (channel == NULL) {
        return false;
    }

    if ((channel->stdout_buffer &&
         ssh_buffer_get_len(channel->stdout_buffer) > 0) ||
        (channel->stderr_buffer &&
         ssh_buffer_get_len(channel->stderr_buffer) > 0))
    {
        return true;
    }

    return false;
}

int ssh_session_handle_poll(ssh_session session, int revents)
{
    ssh_poll_handle ph;
    int rc;

    if (session == NULL || session->socket == NULL) {
        return SSH_ERROR;
    }

    ph = ssh_socket_get_poll_handle(session->socket);
    if (ph == NULL) {
        return SSH_ERROR;
    }

    rc = ssh_socket_pollcallback(ph,
                                 ssh_socket_get_fd(session->socket),
                                 revents,
                                 session->socket);
    if (rc < 0) {
        return SSH_ERROR;
    }

    return SSH_OK;
}

/**
 * @brief Reads buffered data from a channel without polling the socket.
 *
 * @param[in]  channel   The channel to read from.
 *
 * @param[out] dest      The destination buffer which will get the data.
 *
 * @param[in]  count     The count of bytes to be read.
 *
 * @param[in]  is_stderr A boolean value to mark reading from the stderr flow.
 *
 * @return               The number of bytes read, SSH_AGAIN if nothing is
 *                       available, SSH_ERROR on error, and SSH_EOF if the
 *                       channel is EOF.
 */
int ssh_channel_read_buffered(ssh_channel channel,
                              void *dest,
                              uint32_t count,
                              int is_stderr)
{
    ssh_session session;
    ssh_buffer stdbuf;
    uint32_t len;

    if (channel == NULL) {
        return SSH_ERROR;
    }
    if (dest == NULL) {
        ssh_set_error_invalid(channel->session);
        return SSH_ERROR;
    }

    session = channel->session;
    if (count == 0) {
        return 0;
    }

    stdbuf = channel->stdout_buffer;
    if (is_stderr) {
        stdbuf = channel->stderr_buffer;
    }

    if (session->session_state == SSH_SESSION_STATE_ERROR) {
        return SSH_ERROR;
    }

    if (channel->state == SSH_CHANNEL_STATE_CLOSED) {
        ssh_set_error(session,
                      SSH_FATAL,
                      "Remote channel is closed.");
        return SSH_ERROR;
    }

    len = ssh_buffer_get_len(stdbuf);
    if (len == 0) {
        if (channel->remote_eof) {
            return SSH_EOF;
        }
        return SSH_AGAIN;
    }

    if (len > count) {
        len = count;
    }

    memcpy(dest, ssh_buffer_get(stdbuf), len);
    ssh_buffer_pass_bytes(stdbuf, len);
    if (channel->counter != NULL) {
        channel->counter->in_bytes += len;
    }

    /* Try completing the delayed_close */
    if (channel->delayed_close && !ssh_channel_has_unread_data(channel)) {
        channel->state = SSH_CHANNEL_STATE_CLOSED;
    }

    if (grow_window(session, channel) == SSH_ERROR) {
        return SSH_ERROR;
    }

    return len;
}
