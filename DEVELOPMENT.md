# Development Guide

This document provides instructions for setting up a development environment for Autowasp using DevContainers.

## Prerequisites

- [Docker](https://docs.docker.com/get-docker/) - Required for DevContainer
- [VS Code](https://code.visualstudio.com/) or compatible IDE (Cursor, Antigravity)
- [Dev Containers extension](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers)
- [Burp Suite Professional](https://portswigger.net/burp/pro) - For testing the extension

## Getting Started with DevContainer

### 1. Open in DevContainer

1. Clone this repository:

   ```bash
   git clone https://github.com/brndls/autowasp.git
   cd autowasp
   ```

2. Open the folder in VS Code/Antigravity

3. When prompted "Reopen in Container", click **Reopen in Container**
   - Or use Command Palette: `Dev Containers: Reopen in Container`

4. Wait for the container to build (first time may take a few minutes)

### 2. Build the Extension

Inside the DevContainer, run:

```bash
./gradlew clean build
```

The JAR file will be created at:

```shell
build/libs/autowasp-<version>-jar-with-dependencies.jar
```

### 3. Install in Burp Suite

1. Open Burp Suite Professional
2. Go to **Extensions** tab
3. Click **Add**
4. Select the JAR file from `build/libs/` directory
5. Verify the "Autowasp" tab appears

## Project Structure

```shell
autowasp/
├── .devcontainer/          # DevContainer configuration
│   ├── Dockerfile          # Java 21 image
│   └── devcontainer.json   # VS Code settings & extensions
├── src/main/java/
│   ├── autowasp/           # Core extension logic
│   │   ├── checklist/      # OWASP WSTG checklist
│   │   ├── http/           # HTTP handling wrappers
│   │   └── logger/         # Traffic & scan logging
│   └── burp/               # Burp Suite entry point
├── src/main/resources/     # WSTG local cache
├── build.gradle.kts        # Gradle configuration
└── README.md               # Project overview
```

## Development Workflow

1. Make changes to Java source files in `src/main/java/`
2. Rebuild: `./gradlew clean build`
3. Reload extension in Burp Suite (Extensions > Remove > Add)
4. Test your changes

## Gradle Commands

| Command                     | Description                     |
| --------------------------- | ------------------------------- |
| `./gradlew clean`           | Remove build artifacts          |
| `./gradlew build`           | Compile and build JAR           |
| `./gradlew clean build`     | Clean build from scratch        |
| `./gradlew dependencies`    | Show dependency tree            |
| `./gradlew shadowJar`       | Build fat JAR only              |

## Troubleshooting

### Extension fails to load in Burp Suite

- Ensure you're using **Burp Suite Professional** (not Community Edition)
- Verify the JAR was built successfully
- Check Burp's Extensions > Errors tab for details

### DevContainer build fails

- Ensure Docker is running
- Try rebuilding: `Dev Containers: Rebuild Container`
- Check Docker logs for errors

### Java version mismatch

This extension requires Java 21. Ensure:

- DevContainer uses `eclipse-temurin:21-jdk` image
- `build.gradle.kts` uses `JavaVersion.VERSION_21`

## Contributing

See [README.md](README.md#contributing) for contribution guidelines.
