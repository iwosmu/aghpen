# Zoo, zbiór strojenia, po zmianach (obraz zoo-after; nmap -sV z fazy przed)

# Zoo: after

| batch | port | expected | Czujka | ok | nmap -sV | ok |
| --- | --- | --- | --- | --- | --- | --- |
| 01-cms | 2368/tcp | ^Ghost$ 6.78 | http Node.js Express framework [Express, Ghost 6.78, Node.js] | NPVT | http Node.js Express framework | N··· |
| 01-cms | 33080/tcp | ^MediaWiki$ 1.46.2 {install-page} | http Apache httpd 2.4.71 [Apache HTTP Server 2.4.71, MediaWiki 1.46.2, PHP 8.3.37] {install-page} | NPVTC | http Apache httpd 2.4.71 | N···· |
| 01-cms | 80/tcp | ^Nextcloud$ 35.0.3 {install-page} | http Apache httpd 2.4.71 [Apache HTTP Server 2.4.71, Nextcloud 35.0.3, PHP 8.5.13] {admin-panel,install-page} | NPVTC | http Apache httpd 2.4.71 | N···· |
| 01-cms | 41080/tcp | ^Matomo$ 5.14.3 {install-page} | http Apache httpd 2.4.71 [Apache HTTP Server 2.4.71, Matomo 5.14.3, PHP 8.4.28, Vue.js] {admin-panel,install-page} | NPVTC | http Apache httpd 2.4.71 | N···· |
| 01-cms | 27080/tcp | ^Roundcube 1.7.6 {login} | http Apache httpd 2.4.71 [Apache HTTP Server 2.4.71, Bootstrap, PHP 8.4.28, Roundcube Webmail, jQuery] {login} | NP·TC | http Apache httpd 2.4.71 | N···· |
| 01-cms | 8082/tcp | ^Joomla 3.10 {install-page} | http Apache httpd 2.4.56 [Apache HTTP Server 2.4.56, Bootstrap, Joomla 3.10.12, PHP 8.0.30, jQuery] {admin-panel,install-page} | NPVTC | http Apache httpd 2.4.56 | N···· |
| 01-cms | 19080/tcp | ^Drupal$ 7 {install-page} | http Apache httpd 2.4.62 [Apache HTTP Server 2.4.62, Drupal 7, PHP 8.1.31, jQuery] {admin-panel,install-page} | NPVTC | http Apache httpd 2.4.62 | N···· |
| 01-cms | 8083/tcp | ^Joomla 6 {install-page} | http Apache httpd 2.4.71 [Apache HTTP Server 2.4.71, Joomla 6.2.0, PHP] {admin-panel,install-page} | NPVTC | http Apache httpd 2.4.71 | N···· |
| 02-observability | 3000/tcp | ^Grafana$ 11.6.16 {login} | http Grafana http [Grafana 11.6.16] {login} | NPVC | http Grafana http | N··· |
| 02-observability | 9200/tcp | ^Elasticsearch$ 8.19.25 {database} | http Elasticsearch REST API 8.19.25 [Elasticsearch 8.19.25, Elasticsearch REST API 8.19.25] {api,database} | NPVC | http Elasticsearch REST API 8.19.25 | N··· |
| 02-observability | 45601/tcp | ^Kibana$ 8.19.25 | http Elasticsearch Kibana [Elasticsearch Kibana, Kibana 8.19.25] | NPV | http Elasticsearch Kibana | N·· |
| 02-observability | 9093/tcp | ^Alertmanager$ 0.35.0 | http Golang net/http server [Alertmanager 0.35.0, Go] {dev-tool} | NPV | http Golang net/http server | N·· |
| 02-observability | 39100/tcp | [Nn]ode.?[Ee]xporter\|Prometheus exporter 1.13.1 | http Prometheus exporter node_exporter 1.13.1 [Eksporter Prometheus, Prometheus exporter node_exporter 1.13.1] {dev-tool} | NPV | http Prometheus exporter node_exporter 1.13.1 | NPV |
| 02-observability | 9091/tcp | Pushgateway 1.11.5 | http Golang net/http server [Bootstrap 4.3.1, Go, Prometheus Pushgateway 1.11.5, jQuery 3.7.1] {dev-tool} | NPV | http Golang net/http server | N·· |
| 02-observability | 29999/tcp | ^Netdata$ 2.13 | http [Netdata 2.13.0] {dev-tool} | NPV | bingbang | ··· |
| 02-observability | 3001/tcp | ^Uptime Kuma$ {install-page} | http Node.js Express framework [Express, Node.js, Uptime Kuma] {admin-panel,install-page} | NPC | http Node.js Express framework | N·· |
| 02-observability | 30080/tcp | ^Nagios {login} | http Apache httpd 2.4.58 [Apache HTTP Server 2.4.58, Nagios] {admin-panel,login} | NPTC | http Apache httpd 2.4.58 | N··· |
| 03-devtools | 8080/tcp | ^Keycloak$ {admin-panel} | rtsp [Java, Keycloak, React] {admin-panel,login} | ·PC | rtsp | ··· |
| 03-devtools | 8200/tcp | Vault 2.2.2 | http Golang net/http server [Go, HashiCorp Vault 2.2.2] {login} | NPV | http Golang net/http server | N·· |
| 03-devtools | 18500/tcp | Consul 2.1.0 {unauth-control-api} | http Golang net/http server [Go, HashiCorp Consul 2.1.0] {dev-tool,unauth-control-api} | NPVC | http Golang net/http server | N··· |
| 03-devtools | 5000/tcp | Docker Registry {unauth-control-api} | http Docker Registry [Docker Registry] {api,dev-tool,unauth-control-api} | NPC | http Docker Registry | NP· |
| 03-devtools | 38025/tcp | ^Mailpit$ 1.34.0 {dev-tool} | http Golang net/http server [Go, Mailpit 1.34.0] {dev-tool,staging} | NPVC | http Golang net/http server | N··· |
| 03-devtools | 1025/tcp | Mailpit | smtp | N· | smtp | N· |
| 03-devtools | 47080/tcp | ^Swagger UI$ {api} | http nginx [Swagger UI, nginx] {api,dev-tool} | NPC | http nginx | N·· |
| 03-devtools | 14080/tcp | ^code-server$ {login} | http [code-server] {dev-tool,login} | NPC | unknown | ··· |
| 03-devtools | 8888/tcp | ^Jupyter 2.21.1 {login} | http Tornado httpd 6.6.1 [Bootstrap, Jupyter Notebook / JupyterLab 2.21.1, Python, Tornado 6.6.1] {dev-tool,login} | NPVC | http Tornado httpd 6.6.1 | N··· |
| 03-devtools | 1880/tcp | ^Node-RED$ {dev-tool} | http [Bootstrap, Node-RED] {admin-panel,dev-tool} | NPC | vsat-control | ··· |
| 03-devtools | 3300/tcp | ^Gogs$ {install-page} | http Golang net/http server [Go, Gogs, jQuery 3.6.0] {admin-panel,dev-tool,install-page} | NPC | http Golang net/http server | N·· |
| 03-devtools | 8081/tcp | ^Redis Commander$ {admin-panel} | http [Bootstrap, Redis Commander, jQuery 2.2.4] {admin-panel,database,login} | NPC | blackice-icecap | ··· |
| 03-devtools | 28081/tcp | ^Mongo Express$ {login} | http Node.js Express framework [Express, Node.js] {login} | N·C | http Node.js Express framework | N·· |
| 04-java | 8080/tcp | Tomcat 10.1.62 {default-page} | http Apache Tomcat 10.1.62 [Apache Tomcat 10.1.62, Java] {default-page} | NPVC | http Apache Tomcat 10.1.62 | NPV· |
| 04-java | 18081/tcp | ^Jetty$ 12.1.15 | http Jetty 12.1.15 [Java, Jetty 12.1.15] {error-page} | NPV | http Jetty 12.1.15 | NPV |
| 04-java | 28080/tcp | WildFly {default-page} | http [Java, WildFly / JBoss] {default-page} | NPC | thor-engine | ··· |
| 04-java | 9990/tcp | WildFly {admin-panel} | http [Java, WildFly / JBoss] {admin-panel} | NPC | osm-appsrvr | ··· |
| 04-java | 8983/tcp | Solr 9.11.0 {admin-panel} | http Jetty [AngularJS, Apache Solr 9.11.0, Java, Jetty, jQuery 3.5.1] {admin-panel,database} | NPVTC | http Jetty | N···· |
| 04-java | 13000/tcp | ^Metabase$ 0.65.6.3 {install-page} | http [Java, Metabase 0.65.6.3] {admin-panel,install-page} | NPVC | unknown | ···· |
| 05-vuln | 3000/tcp | Juice Shop 20.4.0 {staging} | http [Angular, Node.js, OWASP Juice Shop 20.4.0] {staging} | NPVC | ppp | ···· |
| 05-vuln | 8080/tcp | WebGoat {staging} | http Apache Tomcat [Apache Tomcat 11.0.24, Java, OWASP WebGoat] {error-page,login,staging} | NPC | http Apache Tomcat | N·· |
| 05-vuln | 9090/tcp | WebWolf {staging} | http Apache Tomcat [Apache Tomcat, Java] {error-page} | N·· | http Apache Tomcat | N·· |
| 05-vuln | 36080/tcp | ^bWAPP {staging} | http Apache httpd 2.4.7 [Apache HTTP Server 2.4.7, PHP 5.5.9, bWAPP] {install-page,staging} | NPC | http Apache httpd 2.4.7 | N·· |
| 05-vuln | 8000/tcp | ^PHP$ 8.3.37 {staging} | http PHP cli server 5.5 or later [PHP 8.3.37, PHP cli server 5.5] {staging} | NPVCF | http PHP cli server 5.5 or later | N··· |
| 05-vuln | 48000/tcp | Python\|SimpleHTTP 3.14.10 {directory-listing} | http SimpleHTTPServer 0.6 [Python 3.14.10, Python http.server 0.6] {directory-listing} | NPVC | http SimpleHTTPServer 0.6 | NP·· |
| 06-db | 3306/tcp | ^MySQL$ 8.4.13 {database} | mysql MySQL 8.4.13 [MySQL 8.4.13] {database} | NPVC | mysql MySQL 8.4.13 | NPV· |
| 06-db | 37017/tcp | ^MongoDB$ 8.0.38 {database} | mongodb MongoDB 3.6 after 3.6.3, or 3.7.3 or later [MongoDB 3.6] {database} | NP·C | mongodb MongoDB 3.6 after 3.6.3, or 3.7.3 or later | NP·· |
| 06-db | 5984/tcp | CouchDB 3.5.3 {database} | http CouchDB httpd 3.5.3 [Apache CouchDB 3.5.3] {api,database} | NPVC | http CouchDB httpd 3.5.3 | NPV· |
| 06-db | 18086/tcp | ^InfluxDB$ 2.10.1 {database} | http InfluxDB http admin 2.10.1 [InfluxDB 2.10.1, InfluxDB http admin 2.10.1] {database} | NPVC | http InfluxDB http admin 2.10.1 | N··· |
| 06-db | 9042/tcp | ^Cassandra$ 5.0.9 {database} | tcpwrapped | ···· | unknown | N··· |
| 06-db | 39092/tcp | Kafka {database} | unknown | N·· |  | ··· |
| 06-db | 4222/tcp | ^NATS 2.15.3 {database} | vrml-multi-use | ···· | vrml-multi-use | ···· |
| 06-db | 48222/tcp | ^NATS 2.15.3 | http Golang net/http server [Go] | N·· | http Golang net/http server | N·· |
| 06-db | 2379/tcp | ^etcd$ 3.6.17 {database} | http [Etcd] {error-page} | NP·· | etcd-client | ···· |
| 06-db | 8123/tcp | ^ClickHouse$ 26.9 {database} | rtsp [Clickhouse] | ·P·· | rtsp | ···· |
| 06-db | 19000/tcp | ^ClickHouse$ {database} | http {error-page} | ··· | igrid | ··· |
| 06-db | 7474/tcp | ^Neo4j$ 5.26.33 {database} | http | N··· | neo4j | ···· |
| 06-db | 47687/tcp | ^Neo4j$ {database} | http | ··· | unknown | N·· |
| 07-remote | 42222/tcp | ^OpenSSH$ 10.3 {remote-access} | ssh OpenSSH 10.3 [OpenSSH 10.3] {remote-access} | NPVC | ssh OpenSSH 10.3 | NPV· |
| 07-remote | 23022/tcp | ^Dropbear 2025 {remote-access} | ssh Dropbear sshd 2025.88 [Dropbear SSH 2025.88] {iot,remote-access} | NPVC | ssh Dropbear sshd 2025.88 | NPV· |
| 07-remote | 2121/tcp | ^ProFTPD$ | ftp ProFTPD [ProFTPD] | NP | ftp ProFTPD | NP |
| 07-remote | 21/tcp | ^Pure-FTPd$ | tcpwrapped | ·· | tcpwrapped | ·· |
| 07-remote | 445/tcp | ^Samba 4 | netbios-ssn Samba smbd 4 [Samba / SMB 4] | NPV | netbios-ssn Samba smbd 4 | NPV |
| 07-remote | 873/tcp | rsync | rsync [rsync] | NP | rsync | N· |
| 07-remote | 23/tcp | telnet\|BusyBox {remote-access} | telnet BusyBox telnetd [BusyBox telnetd] {remote-access} | NPC | telnet BusyBox telnetd | NP· |
| 07-remote | 25/tcp | ^Postfix | smtp Postfix smtpd [Postfix] | NP | smtp Postfix smtpd | NP |
| 07-remote | 143/tcp | ^Dovecot | imap Dovecot imapd [Dovecot] | NP | imap Dovecot imapd | NP |
| 07-remote | 40993/tcp | ^Dovecot | imap Dovecot imapd [Dovecot] | NP | imap Dovecot imapd | NP |
| 07-remote | 389/tcp | OpenLDAP | ldap OpenLDAP 2.2.X - 2.3.X [OpenLDAP 2.2.X] {database} | NP | ldap OpenLDAP 2.2.X - 2.3.X | NP |
| 07-remote | 53/tcp | CoreDNS 1.15.0 | domain NLnet Labs NSD [NLnet Labs NSD] | N·· | domain NLnet Labs NSD | N·· |
| 07-remote | 53/udp | CoreDNS 1.15.0 | domain | N·· | domain NLnet Labs NSD | N·· |
| 08-proxies | 8404/tcp | ^HAProxy$ 3.0.31 {admin-panel} | http-proxy HAProxy http proxy [HAProxy] {error-page} | ·P·· | http-proxy HAProxy http proxy | ···· |
| 08-proxies | 18888/tcp | ^Apache 2.4.71 {default-page} | http-proxy HAProxy http proxy 2.0.0 or later [Apache HTTP Server 2.4.71, HAProxy 2.0.0] {default-page} | ·PVC | http-proxy HAProxy http proxy 2.0.0 or later | ···· |
| 08-proxies | 9901/tcp | ^Envoy$ 1.39.6 {unauth-control-api} | http [Envoy] {admin-panel,unauth-control-api} | NP·C | unknown | ···· |
| 08-proxies | 10000/tcp | ^Envoy$ {default-page} | http [Apache HTTP Server, Envoy] {default-page} | NPTC | snet-sensor-mgmt | ···· |
| 08-proxies | 3128/tcp | ^Squid$ 6.6 | http-proxy Squid http proxy 6.13 [Squid 6.13] | NP· | http-proxy Squid http proxy 6.13 | N·· |
| 08-proxies | 36081/tcp | ^Varnish$ 9.1 {default-page} |  | – |  | – |
| 09-heavy | 48081/tcp | Nexus 3.98.3 | http Jetty 12.1.13 [Bootstrap, Java, Jetty 12.1.13, Sonatype Nexus Repository 3.98.3-01] {dev-tool} | NPV | http Jetty 12.1.13 | N·· |
| 10-sonarqube | 9000/tcp | ^SonarQube$ 26.11 {login} | http Apache Tomcat [Apache Tomcat, Java, SonarQube 26.11.0.134175, Sonarqubes] {dev-tool} | NPV· | http Apache Tomcat | N··· |

## Per category

| category | ports | tool | found | named | product | version | technologies | classes | wrong |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| appserver | 6 | Czujka | 6 | 6 | 6 | 4/4 | 1/1 | 5/5 | 0 |
| appserver | 6 | nmap -sV | 6 | 3 | 2 | 2/4 | 0/1 | 0/5 | 0 |
| cms | 8 | Czujka | 8 | 8 | 8 | 7/8 | 8/8 | 7/7 | 0 |
| cms | 8 | nmap -sV | 8 | 8 | 0 | 0/8 | 0/8 | 0/7 | 0 |
| database | 14 | Czujka | 14 | 9 | 7 | 4/11 | 0/0 | 5/13 | 0 |
| database | 14 | nmap -sV | 14 | 8 | 3 | 2/11 | 0/0 | 0/13 | 0 |
| monitoring | 8 | Czujka | 8 | 8 | 8 | 6/6 | 1/1 | 3/3 | 0 |
| monitoring | 8 | nmap -sV | 8 | 7 | 1 | 1/6 | 0/1 | 0/3 | 0 |
| panel | 15 | Czujka | 15 | 14 | 13 | 6/6 | 0/0 | 11/12 | 2 |
| panel | 15 | nmap -sV | 15 | 11 | 1 | 0/6 | 0/0 | 0/12 | 0 |
| proxy | 6 | Czujka | 5 | 3 | 5 | 1/5 | 1/2 | 3/5 | 0 |
| proxy | 6 | nmap -sV | 5 | 1 | 0 | 0/5 | 0/2 | 0/5 | 0 |
| remote | 13 | Czujka | 13 | 12 | 10 | 3/5 | 0/0 | 3/3 | 0 |
| remote | 13 | nmap -sV | 13 | 12 | 9 | 3/5 | 0/0 | 0/3 | 0 |
| vuln | 6 | Czujka | 6 | 6 | 5 | 3/3 | 0/0 | 5/6 | 0 |
| vuln | 6 | nmap -sV | 6 | 5 | 1 | 0/3 | 0/0 | 0/6 | 0 |
| **all** | 76 | **Czujka** | 75 | 66 | 62 | 34/48 | 11/12 | 42/54 | 2 |
| **all** | 76 | **nmap -sV** | 75 | 55 | 17 | 8/48 | 0/12 | 0/54 | 0 |

## Missing and wrong (Czujka)

| batch | port | missing | wrong (false positive) |
| --- | --- | --- | --- |
| 03-devtools | 8081/tcp |  | class:login |
| 05-vuln | 9090/tcp | class:staging |  |
| 06-db | 9042/tcp | class:database |  |
| 06-db | 39092/tcp | class:database |  |
| 06-db | 4222/tcp | class:database |  |
| 06-db | 2379/tcp | class:database |  |
| 06-db | 8123/tcp | class:database |  |
| 06-db | 19000/tcp | class:database |  |
| 06-db | 7474/tcp | class:database |  |
| 06-db | 47687/tcp | class:database |  |
| 08-proxies | 8404/tcp | class:admin-panel |  |
| 10-sonarqube | 9000/tcp | class:login | Sonarqubes |