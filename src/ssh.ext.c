#include <libssh/libssh.h>
#include <libssh/libssh_version.h>
// TODO: figure out how to include rts/log so we get access to log_error etc

#define LOG_ERR(msg) printf("ERR\t%s\n", (msg))

void noop_free(void *ptr) {
}

void sshQ___ext_init__() {
    // TODO: can we avoid custom malloc in libssh? like let libssh use stock
    // malloc and instead we would explicitly call free() from a finalizer()
    // All things related to buffers for receiving data and similarly would have
    // to be allocated on the GC-heap though since that data is passed outside
    // of the SSH actor
    libssh_replace_allocator(
        acton_gc_malloc,
        acton_gc_realloc,
        acton_gc_calloc,
        noop_free,
        acton_gc_strdup,
        acton_gc_strndup);
    int r = ssh_init();
    if (r != SSH_OK)
      printf("SSH init failed (%d)\n", r);
    else
      printf("SSH extension successfully initialized (retval: %d)\n", r);
}

B_str sshQ_version () {
    if (LIBSSH_VERSION_MAJOR != 0 || LIBSSH_VERSION_MINOR != 11 || LIBSSH_VERSION_MICRO != 0)
        return to$str("unsupported version");
    return to$str("libssh 0.11.0 supported\n");
}

// TODO: crap function for test, to be replaced with something
int show_remote_processes(ssh_session session)
{
  ssh_channel channel;
  int rc;
  char buffer[256];
  int nbytes;

  channel = ssh_channel_new(session);
  if (channel == NULL)
    return SSH_ERROR;

  rc = ssh_channel_open_session(channel);
  if (rc != SSH_OK)
  {
    ssh_channel_free(channel);
    return rc;
  }

  rc = ssh_channel_request_exec(channel, "uptime");
  if (rc != SSH_OK)
  {
    ssh_channel_close(channel);
    ssh_channel_free(channel);
    return rc;
  }

  nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
  while (nbytes > 0)
  {
    if (write(1, buffer, nbytes) != (unsigned int) nbytes)
    {
      ssh_channel_close(channel);
      ssh_channel_free(channel);
      return SSH_ERROR;
    }
    nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
  }

  if (nbytes < 0)
  {
    ssh_channel_close(channel);
    ssh_channel_free(channel);
    return SSH_ERROR;
  }

  ssh_channel_send_eof(channel);
  ssh_channel_close(channel);
  ssh_channel_free(channel);

  return SSH_OK;
}

$R sshQ_ChannelD__initG_local (sshQ_Channel self, $Cont c$cont) {
    int err = 0;
    ssh_channel channel = ssh_channel_new(self->_ssh_session);
    if (channel == NULL) {
        LOG_ERR("Failed to create SSH channel");
        printf("ssh_get_error: %s\n\n" , ssh_get_error(self->_ssh_session));
        return $R_CONT(c$cont, B_None);
    }

    printf("\t%s channel: %p\n", __FUNCTION__, channel);
    self->_ssh_channel = channel;
    printf("\t%s self->_ssh_channel:\t%p\n", __FUNCTION__, self->_ssh_channel);

    err = ssh_channel_open_session(channel);
    if (err != SSH_OK) {
        printf("\t%s ssh_channel_open_session() error (%d)\n", __FUNCTION__, err);
        return $R_CONT(c$cont, B_None);
    }
    if (ssh_channel_request_exec(channel, "touch /tmp/bla")) {
        printf("\t%s Error executing '%s' : %s\n", __FUNCTION__, "touch /tmp/bla", ssh_get_error(self->_ssh_session));
        // ssh_channel_free(channel);
        return $R_CONT(c$cont, B_None);
    }
    ssh_channel_send_eof(channel);
    ssh_channel_close(channel);
    ssh_channel_free(channel);

    return $R_CONT(c$cont, B_None);
}

$R sshQ_ClientD__initG_local (sshQ_Client self, $Cont c$cont) {
    ssh_session session = ssh_new();
    if (session == NULL) {
        LOG_ERR("Failed to create SSH session");
        return $R_CONT(c$cont, B_None);
    }
    // casting via toB_u64((unsigned long)..) leads to an invalid value in self->_ssh_session
    // self->_ssh_session = toB_u64((unsigned long)session);
    // instead do direct assignment
    self->_ssh_session = session;

    printf("\t%s session:\t\t%p\n", __FUNCTION__, session);
    printf("\t%s self->session:\t%p\n", __FUNCTION__, self->_ssh_session);

    ssh_options_set(session, SSH_OPTIONS_HOST, fromB_str(self->host));
    ssh_options_set(session, SSH_OPTIONS_PORT, &self->port->val);
    ssh_options_set(session, SSH_OPTIONS_USER, fromB_str(self->username));

    ssh_set_blocking(session, 1);
    printf("Connecting to SSH server '%s'\n", fromB_str(self->host));
    int rc = ssh_connect(session);
    if (rc != SSH_OK) {
        //log_error("Error connecting to SSH server: %s", ssh_get_error(session));
        $action2 f = ($action2) self->on_close;
        f->$class->__asyn__(f, self, to$str(ssh_get_error(session)));
        return $R_CONT(c$cont, B_None);
    }

    rc = ssh_userauth_password(session, NULL, fromB_str(self->password));
    if (rc == SSH_OK) {
        ($action) self->on_connect;
        show_remote_processes(session);
    } else {
        printf("Error: %s\n", ssh_get_error(session));
    }

//    self->_connected = true;
//    $action f = ($action) self->on_connect;
//    f->$class->__asyn__(f, self);
    return $R_CONT(c$cont, B_None);
}
