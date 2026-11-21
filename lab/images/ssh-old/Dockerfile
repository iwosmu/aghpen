# An old OpenSSH (7.9, from Alpine 3.9) for the "outdated remote access" case.
FROM alpine:3.9
RUN apk add --no-cache openssh-server && ssh-keygen -A
CMD ["/usr/sbin/sshd", "-D", "-e"]
