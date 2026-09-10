# =========================
# Build stage
# =========================
FROM maven:3.9.6-eclipse-temurin-17 AS build
WORKDIR /app

# Cache dependency
COPY pom.xml .
RUN mvn -B dependency:go-offline

# Copy source sau
COPY src ./src
RUN mvn -B package -DskipTests

# =========================
# Runtime stage
# =========================
FROM eclipse-temurin:26.0.1_8-jre-jammy
WORKDIR /app

COPY --from=build /app/target/*.jar app.jar

EXPOSE 8080
ENTRYPOINT ["java","-jar","app.jar"]
