# Stage 1: build the application
FROM eclipse-temurin:17-jdk AS build
WORKDIR /workspace

# Copy the whole multi-project structure — settings.gradle ties the root to the app subproject
COPY gradlew .
COPY gradle gradle
COPY gradle.properties .
COPY settings.gradle .
COPY app app

RUN chmod +x gradlew
RUN ./gradlew :app:bootJar --no-daemon

# Stage 2: run it with just a JRE, not the full JDK/Gradle toolchain
FROM eclipse-temurin:17-jre
WORKDIR /app

COPY --from=build /workspace/app/build/libs/*.jar app.jar

EXPOSE 1053/udp
EXPOSE 8080

ENTRYPOINT ["java", "-jar", "app.jar"]
