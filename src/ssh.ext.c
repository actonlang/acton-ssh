#include <errno.h>
#include <libssh/libssh.h>
#include <libssh/libssh_version.h>
#include <stdio.h>

void ssh_close_free(ssh_channel channel) {
    int err = ssh_channel_close(channel);
    if (err != SSH_OK)
    {
        printf("%s ssh_channel_close() error (%d)\n", __FUNCTION__, err);
    }
    ssh_channel_free(channel);
}

void ssh_close_free_eof(ssh_channel channel) {
    int err = ssh_channel_send_eof(channel);
    if (err != SSH_OK)
    {
        printf("%s ssh_channel_send_eof() error (%d)\n", __FUNCTION__, err);
    }
    ssh_close_free(channel);
}

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
        printf("SSH extension successfully initialized\n");
}

B_str sshQ_version() {
    return to$str("0.1.0");
}

// TODO: crap function for test, to be replaced with something
int show_remote_load(ssh_session session)
{
  ssh_channel channel = { 0 };
  char buffer[256] = { 0 };
  int rc = 0;
  int nbytes = 0;

  channel = ssh_channel_new(session);
  if (channel == NULL) {
      printf("%s ssh_channel_new error (NULL)", __FUNCTION__);
      return SSH_ERROR;
  }

  rc = ssh_channel_open_session(channel);
  if (rc != SSH_OK)
  {
      printf("%s ssh_channel_open_session error (%d)", __FUNCTION__, rc);
      ssh_channel_free(channel);
      return rc;
  }

  rc = ssh_channel_request_exec(channel, "uptime");
  if (rc != SSH_OK)
  {
      printf("%s ssh_channel_request_exec error (%d)", __FUNCTION__, rc);
      ssh_close_free(channel);
      return rc;
  }

  nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
  while (nbytes > 0)
  {
      if (write(STDOUT_FILENO, buffer, nbytes) != (unsigned int) nbytes)
      {
          printf("%s write() error (bytes written not matching expectation)", __FUNCTION__);
          ssh_close_free(channel);
          return SSH_ERROR;
      }
      nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
  }

  if (nbytes < 0)
  {
      printf("%s write() error (%d)", __FUNCTION__, errno);
      ssh_close_free(channel);
      return SSH_ERROR;
  }

  ssh_close_free_eof(channel);
  return SSH_OK;
}

$R sshQ_ChannelD__initG_local (sshQ_Channel self, $Cont c$cont) {
    int err = 0;
    ssh_channel channel = ssh_channel_new((struct ssh_session_struct *)fromB_u64(self->_ssh_session));
    if (channel == NULL)
    {
        printf("%s Failed to create SSH channel. ssh_get_error: %s\n\n", __FUNCTION__, ssh_get_error((struct ssh_session_struct *)fromB_u64(self->_ssh_session)));
        return $R_CONT(c$cont, B_None);
    }

    self->_ssh_channel = channel;

    err = ssh_channel_open_session(channel);
    if (err != SSH_OK)
    {
        printf("%s ssh_channel_open_session() error (%d)\n", __FUNCTION__, err);
        return $R_CONT(c$cont, B_None);
    }

    if (ssh_channel_request_exec(channel, "touch /tmp/bla"))
    {
        printf("%s Error executing '%s' : %s\n", __FUNCTION__, "touch /tmp/bla", ssh_get_error((struct ssh_session_struct *)fromB_u64(self->_ssh_session)));
        ssh_channel_free(channel);
        return $R_CONT(c$cont, B_None);
    }

    ssh_close_free_eof(channel);
    return $R_CONT(c$cont, B_None);
}

$R sshQ_ClientD__initG_local (sshQ_Client self, $Cont c$cont) {
    int err = 0;
    ssh_session session = ssh_new();
    if (session == NULL)
    {
        printf("%s Failed to create SSH session\n", __FUNCTION__);
        return $R_CONT(c$cont, B_None);
    }

    self->_ssh_session = toB_u64((unsigned long)session);

    err = ssh_options_set(session, SSH_OPTIONS_HOST, fromB_str(self->host));
    if (err < 0)
    {
        printf("%s Error setting SSH option 'SSH_OPTIONS_HOST': %d\n", __FUNCTION__, err);
        return $R_CONT(c$cont, B_None);
    }

    err = ssh_options_set(session, SSH_OPTIONS_PORT, &self->port->val);
    if (err < 0)
    {
        printf("%s Error setting SSH option 'SSH_OPTIONS_PORT': %d\n", __FUNCTION__, err);
        return $R_CONT(c$cont, B_None);
    }

    err = ssh_options_set(session, SSH_OPTIONS_USER, fromB_str(self->username));
    if (err < 0)
    {
        printf("%s Error setting SSH option 'SSH_OPTIONS_USER': %d\n", __FUNCTION__, err);
        return $R_CONT(c$cont, B_None);
    }

    ssh_set_blocking(session, 1);
    printf("Connecting to SSH server '%s'\n", fromB_str(self->host));

    err = ssh_connect(session);
    if (err != SSH_OK)
    {
        printf("%s Error connecting to SSH server: %s\n", __FUNCTION__, ssh_get_error(session));
        $action2 f = ($action2) self->on_close;
        f->$class->__asyn__(f, self, to$str(ssh_get_error(session)));
        return $R_CONT(c$cont, B_None);
    }

    err = ssh_userauth_password(session, NULL, fromB_str(self->password));
    if (err != SSH_OK)
    {
        printf("%s ssh_userauth_password error: %s\n", __FUNCTION__, ssh_get_error(session));
        return $R_CONT(c$cont, B_None);
    }

    $action f = ($action) self->on_connect;
    f->$class->__asyn__(f, self);

    err = show_remote_load(session);
    if (err != SSH_OK)
    {
        printf("%s show_remote_load error: %d\n", __FUNCTION__, err);
        return $R_CONT(c$cont, B_None);
    }

    return $R_CONT(c$cont, B_None);
}
