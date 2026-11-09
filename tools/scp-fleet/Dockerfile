# One SSH "device" for scp-fleet: OpenSSH sshd and scp, plus tc for
# shaping the container's network. Build it with `./fleet.sh build`.
FROM debian:bookworm-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-server openssh-client iproute2 procps \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /run/sshd /root/.ssh \
 && chmod 700 /root/.ssh \
 && echo 'root:scp-fleet' | chpasswd \
 && printf '%s\n' \
      'PermitRootLogin yes' \
      'PasswordAuthentication yes' \
      'KbdInteractiveAuthentication no' \
      'UseDNS no' \
      'MaxStartups 200' \
      'MaxSessions 64' \
      > /etc/ssh/sshd_config.d/scp-fleet.conf

COPY entrypoint.sh /entrypoint.sh

# The public key that may log in as root. fleet.sh passes it.
ARG PUBKEY
RUN test -n "$PUBKEY" \
 && echo "$PUBKEY" > /root/.ssh/authorized_keys \
 && chmod 600 /root/.ssh/authorized_keys \
 && chmod 755 /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
