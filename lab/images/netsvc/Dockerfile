# One small image for the classic network services of the lab. Each container
# starts one of them: sshd, vsftpd, postfix, dnsmasq, snmpd, chronyd.
FROM alpine:3.24.4
RUN apk add --no-cache openssh-server vsftpd postfix dnsmasq net-snmp net-snmp-tools chrony \
 && mkdir -p /var/ftp/pub /var/run/vsftpd/empty \
 && echo "Pliki publiczne laboratorium Czujka" > /var/ftp/pub/README.txt \
 && postconf -e "inet_interfaces = all" "inet_protocols = ipv4" "myhostname = mail.lab.czujka.test" "mydomain = lab.czujka.test" "maillog_file = /dev/stdout" "mynetworks = 127.0.0.0/8" \
 && newaliases
COPY vsftpd.conf /etc/vsftpd/lab.conf
COPY snmpd.conf /etc/snmp/lab-snmpd.conf
COPY chrony.conf /etc/chrony/lab-chrony.conf
