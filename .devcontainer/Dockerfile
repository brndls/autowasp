# Autowasp Development Container
# Java 21 LTS + Gradle for Burp Suite extension development

FROM eclipse-temurin:21-jdk

LABEL maintainer="Autowasp Contributors"
LABEL description="Development environment for Autowasp Burp Suite extension"

# Install development dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    fish \
    git \
    curl \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Set environment variables
ENV JAVA_HOME=/opt/java/openjdk
ENV PATH="${JAVA_HOME}/bin:${PATH}"

# Set working directory
WORKDIR /workspace

# Default command
CMD ["fish"]
