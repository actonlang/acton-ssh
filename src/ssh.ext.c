#include <libssh/libssh.h>
#include <libssh/libssh_version.h>
// TODO: figure out how to include rts/log so we get access to log_error etc

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
    printf("SSH extension initialized %d\n", r);
}

B_str sshQ_version () {
    if (LIBSSH_VERSION_MINOR != 11)
        return to$str("invalid");
    return to$str("0.11.0");
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

  rc = ssh_channel_request_exec(channel, "ps aux");
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

$R sshQ_ClientD__initG_local (sshQ_Client self, $Cont c$cont) {
    ssh_session session = ssh_new();
    if (session == NULL) {
        //log_error("Failed to create SSH session");
        return $R_CONT(c$cont, B_None);
    }
    printf("session: %p\n", session);
    self->_ssh_session = toB_u64((unsigned long)session);
    printf("init self->session: %p\n", self->_ssh_session);

    ssh_options_set(session, SSH_OPTIONS_HOST, fromB_str(self->host));
    ssh_options_set(session, SSH_OPTIONS_PORT, &self->port->val);
    ssh_options_set(session, SSH_OPTIONS_USER, fromB_str(self->username));

    ssh_set_blocking(session, 1);
    printf("Connecting to \n");
    int rc = ssh_connect(session);
    if (rc != SSH_OK) {
        //log_error("Error connecting to SSH server: %s", ssh_get_error(session));
        $action2 f = ($action2) self->on_close;
        f->$class->__asyn__(f, self, to$str(ssh_get_error(session)));
        return $R_CONT(c$cont, B_None);
    }

    rc = ssh_userauth_password(session, NULL, fromB_str(self->password));
    if (rc == SSH_OK) {
        printf("Connected\n");
        show_remote_processes(session);
    } else {
        printf("Error: %s\n", ssh_get_error(session));
    }

//    self->_connected = true;
//    $action f = ($action) self->on_connect;
//    f->$class->__asyn__(f, self);
    return $R_CONT(c$cont, B_None);
}
