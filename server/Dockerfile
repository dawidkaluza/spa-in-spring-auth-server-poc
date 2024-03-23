FROM eclipse-temurin:17-jdk-alpine

WORKDIR /app

COPY gradle ./gradle
COPY src ./src
COPY settings.gradle build.gradle gradlew ./

CMD ./gradlew bootRun