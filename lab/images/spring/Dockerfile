# Small Spring Boot application with every Actuator endpoint exposed.
FROM maven:3.9.16-eclipse-temurin-21-alpine AS build
WORKDIR /src
COPY pom.xml .
COPY src src
RUN mvn -q -B package -DskipTests

FROM eclipse-temurin:21-jre-alpine
COPY --from=build /src/target/oceny-api-0.9.3.jar /app.jar
ENV JAVA_TOOL_OPTIONS="-Xmx192m -Xss512k -XX:+UseSerialGC"
CMD ["java", "-jar", "/app.jar"]
