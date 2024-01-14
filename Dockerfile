# Fase de construção
FROM maven:3.8.3-openjdk-17-slim AS build
WORKDIR /usr/src/app
COPY . .
RUN mvn clean package -DskipTests

# Fase de execução
FROM eclipse-temurin:17-jdk-alpine
WORKDIR /usr/src/app
COPY --from=build /usr/src/app/target/AuthUserManagementAPI-0.0.1-SNAPSHOT.jar app.jar
CMD ["java", "-jar", "-Dspring.profiles.active=prod", "app.jar"]
