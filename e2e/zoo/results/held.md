# Zoo, zbiór odłożony, jedyny skan (obraz zoo-after)

# Zoo: held

| batch | port | expected | Czujka | ok | nmap -sV | ok |
| --- | --- | --- | --- | --- | --- | --- |
| held-1 | 23000/tcp | Wiki\.js {install-page} |  | – |  | – |
| held-1 | 8443/tcp | Vaultwarden\|Bitwarden {login} |  | – |  | – |
| held-1 | 18800/tcp | Gotify {login} | http Golang net/http server [Go, Gotify] | NP· | http Golang net/http server | N·· |
| held-1 | 8090/tcp | File ?Browser {login} | http Golang net/http server [File Browser, Go] | NP· | http Golang net/http server | N·· |
| held-1 | 8384/tcp | Syncthing {admin-panel} | http Syncthing 2.1.7 [AngularJS, Bootstrap, Syncthing 2.1.7] {admin-panel,login} | NPC | http Syncthing 2.1.7 | NP· |
| held-1 | 43000/tcp | AdGuard {install-page} | http Golang net/http server [AdGuard Home, Go] {admin-panel,login} | NP· | http Golang net/http server | N·· |
| held-1 | 18180/tcp | Kanboard {login} | http nginx [Kanboard, nginx] {login} | NP·C | http nginx | N··· |
| held-1 | 80/tcp | FreshRSS {install-page} | http Apache httpd 2.4.69 [Apache HTTP Server 2.4.69, Freshrss, PHP 8.5.12] | NPT· | http Apache httpd 2.4.69 | N··· |
| held-1 | 9001/tcp | Etherpad | http Node.js Express framework [Etherpad, Express, Node.js] | NP | http Node.js Express framework | N· |
| held-1 | 48080/tcp | Heimdall | http nginx [PHP 8.5.13, jQuery, nginx] | N·T | http nginx | N·· |
| held-2 | 8161/tcp | ActiveMQ {login} | http Jetty [Java, Jetty] {login} | N·C | http Jetty | N·· |
| held-2 | 41616/tcp | ActiveMQ 6.2.0 | apachemq ActiveMQ OpenWire transport 6.2.0 [ActiveMQ OpenWire transport 6.2.0] | NPV | apachemq ActiveMQ OpenWire transport 6.2.0 | NPV |
| held-2 | 6380/tcp | Valkey\|Redis 9.2.0 {database} | redis Redis key-value store 7.2.4 [Redis 7.2.4] {database} | NP·C | redis Redis key-value store 7.2.4 | NP·· |
| held-2 | 18083/tcp | EMQX {login} | http Cowboy httpd [Cowboy] | N·· | http Cowboy httpd | N·· |
| held-2 | 11883/tcp | EMQX\|MQTT | unknown | ·· |  | ·· |
| held-2 | 8880/tcp | Graphite | http nginx 1.20.2 [Graphite Browser, nginx 1.20.2] | NP | http nginx 1.20.2 | N· |
| held-2 | 33000/tcp | Redmine | http [Redmine, Ruby, Ruby on Rails] | NPT | wg-endpt-comms | ··· |
| held-2 | 8070/tcp | Docker Registry UI\|Joxit | http nginx 1.29.4 [Docker Registry, nginx 1.29.4] {api,dev-tool,unauth-control-api} | N· | http nginx 1.29.4 | N· |
| held-2 | 13300/tcp | VS ?Code\|OpenVSCode {dev-tool} | http [Code] | N·· | unknown | ··· |
| held-2 | 8055/tcp | Directus {login} | http [Directus] {admin-panel} | NP· | senomix04 | ··· |
| held-2 | 2181/tcp | ZooKeeper 3.9.7 | eforward | ··· | eforward | ··· |
| held-2 | 28180/tcp | ZooKeeper\|Jetty | http Jetty 9.4.58.v20250814 [Java, Jetty 9.4.58.v20250814] {error-page} | NP | http Jetty 9.4.58.v20250814 | NP |
| held-2 | 38080/tcp | YOURLS {install-page} | tcpwrapped | ···· | tcpwrapped | ···· |

## Per category

| category | ports | tool | found | named | product | version | technologies | classes | wrong |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| cms | 6 | Czujka | 5 | 4 | 4 | 0/0 | 2/4 | 1/4 | 0 |
| cms | 6 | nmap -sV | 5 | 3 | 0 | 0/0 | 0/4 | 0/4 | 0 |
| database | 5 | Czujka | 5 | 3 | 3 | 1/3 | 0/0 | 1/1 | 1 |
| database | 5 | nmap -sV | 5 | 3 | 3 | 1/3 | 0/0 | 0/1 | 0 |
| monitoring | 1 | Czujka | 1 | 1 | 1 | 0/0 | 0/0 | 0/0 | 0 |
| monitoring | 1 | nmap -sV | 1 | 1 | 0 | 0/0 | 0/0 | 0/0 | 0 |
| panel | 11 | Czujka | 10 | 10 | 5 | 0/0 | 1/1 | 2/9 | 10 |
| panel | 11 | nmap -sV | 10 | 8 | 1 | 0/0 | 0/1 | 0/9 | 0 |
| **all** | 23 | **Czujka** | 21 | 18 | 13 | 1/3 | 3/5 | 4/14 | 11 |
| **all** | 23 | **nmap -sV** | 21 | 15 | 4 | 1/3 | 0/5 | 0/14 | 0 |

## Missing and wrong (Czujka)

| batch | port | missing | wrong (false positive) |
| --- | --- | --- | --- |
| held-1 | 18800/tcp | class:login |  |
| held-1 | 8090/tcp | class:login |  |
| held-1 | 8384/tcp |  | class:login |
| held-1 | 43000/tcp | class:install-page | class:admin-panel, class:login |
| held-1 | 18180/tcp | PHP |  |
| held-1 | 80/tcp | class:install-page |  |
| held-2 | 18083/tcp | class:login | Cowboy |
| held-2 | 8070/tcp |  | Docker Registry, class:api, class:dev-tool, class:unauth-control-api |
| held-2 | 13300/tcp | class:dev-tool | Code |
| held-2 | 8055/tcp | class:login | class:admin-panel |
| held-2 | 28180/tcp |  | class:error-page |
| held-2 | 38080/tcp | PHP, class:install-page |  |