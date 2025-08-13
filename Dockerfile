# Use Debian-based Java 21 image
FROM eclipse-temurin:21-jdk

# Install netcat
RUN apt-get update && apt-get install -y netcat-openbsd && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy the JAR
COPY target/*.jar app.jar

# Copy the wait-for script
COPY wait-for.sh .

# Make it executable
RUN chmod +x wait-for.sh

# Expose app port
EXPOSE 8080

# Run the wait script and then the app
ENTRYPOINT ["./wait-for.sh", "redis:6379", "--", "java", "-jar", "app.jar"]