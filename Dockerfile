# Stage 1: build
FROM maven:3.9.9-eclipse-temurin-21 AS builder
WORKDIR /app

# Копируем весь репозиторий (включая parent POM и все модули)
COPY .. .

# Собираем только AuthService
RUN mvn -pl AuthService -am clean package -DskipTests

# Stage 2: runtime
FROM eclipse-temurin:21-jdk-alpine
WORKDIR /app

COPY --from=builder /app/AuthService/target/AuthService-0.0.1-SNAPSHOT.jar app.jar

EXPOSE 8081
ENTRYPOINT ["java", "-jar", "app.jar"]

# docker build -t auth-service:latest -f AuthService/Dockerfile