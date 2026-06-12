/* Acton additions to the libssh API.
 *
 * These functions are NOT part of upstream libssh. They are compiled into
 * the library by this wrapper's build.zig (src/libssh_acton.c) on top of the
 * unmodified upstream source tarball pinned in build.zig.zon. They provide
 * the hooks Acton's external (libuv) event loop needs:
 *
 *   - ssh_session_handle_poll: feed poll(2)-style revents for the session's
 *     fd into libssh's internal poll machinery, so libssh makes progress
 *     without owning the event loop.
 *   - ssh_channel_read_buffered: drain data libssh has already buffered for
 *     a channel without touching the socket, for callback-driven reads.
 */
#ifndef LIBSSH_ACTON_H
#define LIBSSH_ACTON_H

#include <libssh/libssh.h>

#ifdef __cplusplus
extern "C" {
#endif

LIBSSH_API int ssh_session_handle_poll(ssh_session session, int revents);
LIBSSH_API int ssh_channel_read_buffered(ssh_channel channel, void *dest,
                                         uint32_t count, int is_stderr);

#ifdef __cplusplus
}
#endif

#endif /* LIBSSH_ACTON_H */
