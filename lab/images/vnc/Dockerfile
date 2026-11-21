# TigerVNC server (Xvnc) with password authentication.
FROM alpine:3.24.4
RUN apk add --no-cache tigervnc \
 && printf 'labvnc26\n' | vncpasswd -f > /etc/lab-vncpasswd && chmod 600 /etc/lab-vncpasswd
CMD ["Xvnc", ":0", "-geometry", "800x600", "-depth", "16", "-rfbport", "5900", "-SecurityTypes", "VncAuth", "-PasswordFile", "/etc/lab-vncpasswd"]
