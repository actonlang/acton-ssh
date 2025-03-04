#include <errno.h>
#include <libssh/libssh.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
// acton includes
#include <rts/rts.h>

#ifndef DEBUG_MODE
// #define DEBUG_MODE    /* uncomment for pretty prints */
#endif

#define BUF_SIZE 65536          // this will definitely not be enough, find a better way. maybe chunks like libyang does?
#define TIMEOUT 1500000         // microseconds: 1.5 seconds
#define USLEEP_INTERVAL 5000    // microseconds: 0.005 seconds

void ssh_channel_close_free(ssh_channel channel) {
    int err = ssh_channel_close(channel);
    if (err != SSH_OK)
    {
        printf("%s: ssh_channel_close() error (%d)\n", __FUNCTION__, err);
    }
    ssh_channel_free(channel);
}

void ssh_channel_close_free_eof(ssh_channel channel) {
    int err = ssh_channel_send_eof(channel);
    if (err != SSH_OK)
    {
        printf("%s: ssh_channel_send_eof() error (%d)\n", __FUNCTION__, err);
    }
    ssh_channel_close_free(channel);
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

$R sshQ_ClientD__pin_affinityG_local (sshQ_Client self, $Cont c$cont) {
    pin_actor_affinity();
    return $R_CONT(c$cont, B_None);
}

$R sshQ_ChannelD__pin_affinityG_local (sshQ_Channel self, $Cont c$cont) {
    pin_actor_affinity();
    return $R_CONT(c$cont, B_None);
}

/**
 * @brief Send netconf payload
 *
 * @param[in] channel ssh_channel
 * @param[in] payload The Netconf Payload, for example the hello message
 */
int send_nc_payload(ssh_channel channel, const char *payload, char *buf)
{
    int err = 0;
    int nbytes = 0;
    int len = 0;
    size_t buflen = 0;
    char tmp[1024] = {0};

    err = ssh_channel_write(channel, payload, (uint32_t)strlen(payload));
    if (err == SSH_ERROR)
    {
        printf("%s: ssh_channel_write() error (%d)\n", __FUNCTION__, err);
        goto error;
    }

    nbytes = ssh_channel_read(channel, tmp, sizeof(tmp)-1, 0);
    while (nbytes > 0)
    {
        // sometimes the string tmp has invalid characters from the 1024th element
        // and the strlen reports more than what the sizeof() is
        if (strlen(tmp) > sizeof(tmp)) {
            tmp[sizeof(tmp)-1] = '\0';
        }

        // append string
        len = snprintf(buf + buflen, BUF_SIZE - buflen, "%s", tmp);
        buflen = strlen(buf);

        if (len > BUF_SIZE)
        {
            printf("%s: snprintf() error %lu\n", __FUNCTION__, buflen);
            goto error;
        }
#ifdef DEBUG_MODE
        if (write(STDOUT_FILENO, tmp, (size_t)nbytes) != (ssize_t) nbytes)
        {
            printf("%s: write() error (bytes written not matching expectation)\n", __FUNCTION__);
            goto error;
        }
        fflush(stdout);
#endif
        // find end of netconf reply
        if (strstr(tmp, "]]>]]>")) {
            return SSH_OK;
        }
        memset(tmp, 0, sizeof(tmp));
        nbytes = ssh_channel_read(channel, tmp, sizeof(tmp), 0);
    }

    if (nbytes < 0)
    {
        printf("%s: ssh_channel_read() error (%d)\n", __FUNCTION__, errno);
        goto error;
    }

    return SSH_OK;
error:
    ssh_channel_close_free(channel);
    return SSH_ERROR;
}

/**
 * @brief Set subsystem
 *
 * @param[in] channel ssh_channel
 * @param[in] subsystem The subsystem, for example "netconf"
 */
 int set_subsystem (ssh_channel channel, const char *subsystem) {
    int err = 0;
    int timeout = TIMEOUT;

    if (channel == NULL) {
        printf("%s: channel is NULL\n", __FUNCTION__);
        return SSH_ERROR;
    }

    if (subsystem && !strcmp(subsystem, "netconf")) {
        while ((err = ssh_channel_request_subsystem(channel, "netconf")) == SSH_AGAIN && timeout > 0)
        {
            err = usleep(USLEEP_INTERVAL);
            if (err) {
                printf("%s: usleep() error '%s' (%d)\n", __FUNCTION__, strerror(errno), errno);
                return SSH_ERROR;
            }
            timeout -= USLEEP_INTERVAL;
        }
        if (err != SSH_OK)
        {
            printf("%s: ssh_channel_request_subsystem() Error setting SSH subsystem 'netconf': %d\n", __FUNCTION__, err);
            return SSH_ERROR;
        }
    }

    return SSH_OK;
}

// Client

$R sshQ_ClientD__initG_local (sshQ_Client self, $Cont c$cont) {
    pin_actor_affinity();

    int err = 0;
    ssh_session session = ssh_new();
    if (session == NULL)
    {
        printf("%s: ssh_new() Failed to create SSH session\n", __FUNCTION__);
        return $R_CONT(c$cont, B_None);
    }

    self->_ssh_session = toB_u64((unsigned long)session);

#ifdef DEBUG_MODE
    // available: SSH_LOG_NOLOG, SSH_LOG_WARNING, SSH_LOG_PROTOCOL, SSH_LOG_PACKET, SSH_LOG_FUNCTIONS
    err = ssh_set_log_level(SSH_LOG_FUNCTIONS);
    if (err != SSH_OK)
    {
        printf("%s: ssh_set_log_level() Error setting log level: %d\n", __FUNCTION__, err);
        return $R_CONT(c$cont, B_None);
    }
#endif

    err = ssh_session_set_disconnect_message(session, "Disconnecting SSH, powered by Acton");
    if (err != SSH_OK)
    {
        printf("%s: ssh_session_set_disconnect_message() Error setting disconnect message: %d\n", __FUNCTION__, err);
        return $R_CONT(c$cont, B_None);
    }

    err = ssh_options_set(session, SSH_OPTIONS_HOST, fromB_str(self->host));
    if (err != SSH_OK)
    {
        printf("%s: ssh_options_set() Error setting SSH option 'SSH_OPTIONS_HOST': %d\n", __FUNCTION__, err);
        return $R_CONT(c$cont, B_None);
    }

    err = ssh_options_set(session, SSH_OPTIONS_PORT, &self->port->val);
    if (err != SSH_OK)
    {
        printf("%s: ssh_options_set() Error setting SSH option 'SSH_OPTIONS_PORT': %d\n", __FUNCTION__, err);
        return $R_CONT(c$cont, B_None);
    }

    err = ssh_options_set(session, SSH_OPTIONS_USER, fromB_str(self->username));
    if (err != SSH_OK)
    {
        printf("%s: ssh_options_set() Error setting SSH option 'SSH_OPTIONS_USER': %d\n", __FUNCTION__, err);
        return $R_CONT(c$cont, B_None);
    }

    // should it auto-parse user config? for example from /home/user/.ssh/
    // err = ssh_options_set(session, SSH_OPTIONS_PROCESS_CONFIG, "0");
	// if (err != SSH_OK)
	// {
	// 	printf("%s: ssh_options_set() Error setting SSH option 'SSH_OPTIONS_PROCESS_CONFIG': %d\n", __FUNCTION__, err);
	// 	return  $R_CONT(c$cont, B_None);
	// }

    err = ssh_connect(session);
    if (err != SSH_OK)
    {
        printf("%s: ssh_connect() Error connecting to SSH server: %s\n", __FUNCTION__, ssh_get_error(session));
        return $R_CONT(c$cont, B_None);
    }

    err = ssh_userauth_password(session, NULL, (const char *)fromB_str(self->password));
    if (err != SSH_OK)
    {
        printf("%s: ssh_userauth_password() error: %s\n", __FUNCTION__, ssh_get_error(session));
        return $R_CONT(c$cont, B_None);
    }

    $action f = ($action) self->on_connect;
    f->$class->__asyn__(f, self);

    return $R_CONT(c$cont, B_None);
}

$R sshQ_ClientD_disconnectG_local (sshQ_Client self, $Cont c$cont) {
    ssh_disconnect((ssh_session)fromB_u64(self->_ssh_session));
    ssh_free((ssh_session)fromB_u64(self->_ssh_session));
    if (ssh_finalize()) {
        printf("%s: ssh_finalize error", __FUNCTION__);
    }

    return $R_CONT(c$cont, B_None);
}

// Channel

$R sshQ_ChannelD__initG_local (sshQ_Channel self, $Cont c$cont) {
    pin_actor_affinity();

    int err = 0;
    ssh_session session = (struct ssh_session_struct *)fromB_u64(self->_ssh_session);
    ssh_channel channel = { 0 };

#ifdef DEBUG_MODE
    printf("Connecting to SSH server\n");
#endif

    channel = ssh_channel_new(session);
    if (channel == NULL)
    {
        printf("%s: ssh_channel_new() Failed to create SSH channel\n", __FUNCTION__);
        return $R_CONT(c$cont, B_None);
    }

    self->_ssh_channel = toB_u64((unsigned long)channel);

    err = ssh_channel_open_session(channel);
    if (err != SSH_OK)
    {
        printf("%s: ssh_channel_open_session() error (%d)\n", __FUNCTION__, err);
        return $R_CONT(c$cont, B_None);
    }

    if (self->_subsystem) {
        err = set_subsystem(channel, (const char *)fromB_str(self->_subsystem));
        if (err != SSH_OK) {
            printf("%s: set_subsystem() setting subsystem failed error (%d)\n", __FUNCTION__, err);
            return $R_CONT(c$cont, B_None);
        }
    }

    return $R_CONT(c$cont, B_None);
}

$R sshQ_ChannelD_sendNCPayloadG_local (sshQ_Channel self, $Cont c$cont) {
    int err = 0;
    char buffer[BUF_SIZE] = {0};
    ssh_channel channel = (ssh_channel)fromB_u64(self->_ssh_channel);

    err = send_nc_payload(channel, (const char *)fromB_str(self->payload), buffer);
    if (err != SSH_OK)
    {
        printf("%s: send_nc_payload() error: %d\n", __FUNCTION__, err);
        return $R_CONT(c$cont, B_None);
    }

    return $R_CONT(c$cont, to$str(buffer));
}
