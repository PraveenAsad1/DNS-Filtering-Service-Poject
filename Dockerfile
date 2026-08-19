# Stage 1: build the application — uses the official Gradle image with Gradle
# pre-installed, avoiding a fresh wrapper download (and its network fragility) on every build
FROM gradle:8.10.2-jdk17 AS build
WORKDIR /workspace

COPY gradle.properties .
COPY settings.gradle .
COPY app app

RUN gradle :app:bootJar --no-daemon

# Stage 2: run it with just a JRE, not the full JDK/Gradle toolchain
FROM eclipse-temurin:17-jre
WORKDIR /app

COPY --from=build /workspace/app/build/libs/*.jar app.jar

EXPOSE 1053/udp
EXPOSE 8080

ENTRYPOINT ["java", "-jar", "app.jar"]
