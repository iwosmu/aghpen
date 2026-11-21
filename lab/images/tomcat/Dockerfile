# Tomcat with the default applications restored and the manager reachable
# from the network, so /manager/html answers 401 (the login prompt).
FROM tomcat:10.1.62-jre21-temurin
RUN cp -a /usr/local/tomcat/webapps.dist/. /usr/local/tomcat/webapps/ \
 && sed -i '/Remote[A-Za-z]*Valve/,/\/>/d' /usr/local/tomcat/webapps/manager/META-INF/context.xml /usr/local/tomcat/webapps/host-manager/META-INF/context.xml
ENV CATALINA_OPTS="-Xms64m -Xmx192m -XX:+UseSerialGC"
