# Multi-stage build for VISTA
FROM maven:3.9-eclipse-temurin-17 AS builder

WORKDIR /app

# Copy POM and download dependencies (cached layer)
COPY pom.xml .
RUN mvn dependency:go-offline -B

# Copy source and build
COPY src ./src
RUN mvn clean package -DskipTests -B

# Runtime stage
FROM eclipse-temurin:17-jre-alpine

LABEL org.opencontainers.image.source=https://github.com/Adw0rm-sec/VISTA
LABEL org.opencontainers.image.description="VISTA - AI-Powered Security Testing Assistant"
LABEL org.opencontainers.image.licenses=MIT

WORKDIR /vista

# Copy built JAR
COPY --from=builder /app/target/vista-*.jar /vista/vista.jar

# Create volume for configuration
VOLUME ["/vista/config"]

# Metadata
ENV VISTA_VERSION=1.0.0-MVP
ENV JAVA_OPTS="-Xmx512m"

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD java -version || exit 1

CMD ["sh", "-c", "java $JAVA_OPTS -jar vista.jar"]
