#include <libssh/libssh.h>
#include <libssh/libssh_version.h>

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

B_str sshQ_version() {
    return to$str("libssh 0.11.0\n");
}

// TODO: crap function for test, to be replaced with something
int show_remote_processes(ssh_session session)
{
  ssh_channel channel = { 0 };
  char buffer[256] = { 0 };
  int rc = 0;
  int nbytes = 0;

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
    ssh_channel channel = ssh_channel_new((struct ssh_session_struct *)fromB_u64(self->_ssh_session));
    if (channel == NULL) {
        printf("Failed to create SSH channel. ssh_get_error: %s\n\n" , ssh_get_error((struct ssh_session_struct *)fromB_u64(self->_ssh_session)));
        return $R_CONT(c$cont, B_None);
    }

    self->_ssh_channel = channel;

    err = ssh_channel_open_session(channel);
    if (err != SSH_OK) {
        printf("\t%s ssh_channel_open_session() error (%d)\n", __FUNCTION__, err);
        return $R_CONT(c$cont, B_None);
    }
    if (ssh_channel_request_exec(channel, "touch /tmp/bla")) {
        printf("\t%s Error executing '%s' : %s\n", __FUNCTION__, "touch /tmp/bla", ssh_get_error((struct ssh_session_struct *)fromB_u64(self->_ssh_session)));
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
        printf("Failed to create SSH session\n");
        return $R_CONT(c$cont, B_None);
    }

    self->_ssh_session = toB_u64((unsigned long)session);

    int err = 0;
    err = ssh_options_set(session, SSH_OPTIONS_HOST, fromB_str(self->host));
    if (err < 0)
        printf("Error setting SSH option 'SSH_OPTIONS_HOST': %d\n", err);
    err = ssh_options_set(session, SSH_OPTIONS_PORT, &self->port->val);
    if (err < 0)
        printf("Error setting SSH option 'SSH_OPTIONS_PORT': %d\n", err);
    err = ssh_options_set(session, SSH_OPTIONS_USER, fromB_str(self->username));
    if (err < 0)
        printf("Error setting SSH option 'SSH_OPTIONS_USER': %d\n", err);

    ssh_set_blocking(session, 1);
    printf("Connecting to SSH server '%s'\n", fromB_str(self->host));
    int rc = ssh_connect(session);
    if (rc != SSH_OK) {
        printf("Error connecting to SSH server: %s\n", ssh_get_error(session));
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
