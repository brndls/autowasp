# Development Guide

This document provides instructions for setting up a development environment for Autowasp.

## Prerequisites

- **Java 21** - Required for building
- **Burp Suite Professional** - For testing the extension

## Quick Start

Choose one of the following methods based on your platform and preference:

| Method                                                         | Best For                | Requirements    |
| -------------------------------------------------------------- | ----------------------- | --------------- |
| [DevContainer](#option-1-devcontainer-recommended-for-windows) | Windows, cross-platform | Docker, VS Code |
| [direnv](#option-2-using-direnv)                               | macOS, Linux            | direnv, Java 21 |
| [Nix Shell](#option-3-using-nix-shell)                         | NixOS, Nix users        | Nix             |
| [Manual](#option-4-manual-setup)                               | Any platform            | Java 21         |

---

## Option 1: DevContainer (Recommended for Windows)

DevContainer provides a consistent, pre-configured development environment using Docker. This is the recommended approach for Windows users.

### Prerequisites

- [Docker](https://docs.docker.com/get-docker/)
- [VS Code](https://code.visualstudio.com/) or compatible IDE (Cursor, Antigravity)
- [Dev Containers extension](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers)

### Steps

1. Clone the repository:

   ```bash
   git clone https://github.com/brndls/autowasp.git
   cd autowasp
   ```

2. Open the folder in VS Code

3. When prompted "Reopen in Container", click **Reopen in Container**
   - Or use Command Palette: `Dev Containers: Reopen in Container`

4. Wait for the container to build (first time may take a few minutes)

5. Build the extension:

   ```bash
   ./gradlew build
   ```

---

## Option 2: Using direnv

[direnv](https://direnv.net/) automatically loads environment variables when entering the project directory.

### Prerequisites

- direnv installed (`brew install direnv` on macOS)
- Java 21 installed via Homebrew, Nix, or package manager
- Shell hook configured

### Steps

1. Clone and enter the repository:

   ```bash
   git clone https://github.com/brndls/autowasp.git
   cd autowasp
   ```

2. Copy and configure environment:

   ```bash
   cp .envrc.example .envrc
   ```

3. Edit `.envrc` and set `JAVA_HOME` for your system:

   ```bash
   # macOS (Homebrew)
   export JAVA_HOME="/opt/homebrew/opt/openjdk@21"
   
   # macOS/Linux (Nix)
   export JAVA_HOME="/nix/store/xxx-zulu-ca-jdk-21.x.x/..."
   
   # Linux (apt)
   export JAVA_HOME="/usr/lib/jvm/java-21-openjdk-amd64"
   ```

4. Allow direnv:

   ```bash
   direnv allow
   ```

5. Build:

   ```bash
   ./gradlew build
   ```

### Shell Hook Setup

If not already configured, add to your `~/.zshrc` or `~/.bashrc`:

```bash
eval "$(direnv hook zsh)"  # or bash
```

---

## Option 3: Using Nix Shell

A `shell.nix` is provided for Nix users with all dependencies pre-configured.

### Steps

1. Clone and enter the repository:

   ```bash
   git clone https://github.com/brndls/autowasp.git
   cd autowasp
   ```

2. Enter Nix shell:

   ```bash
   nix-shell
   ```

   Or with direnv (if `use nix` is configured):

   ```bash
   direnv allow
   ```

3. Build:

   ```bash
   ./gradlew build
   ```

---

## Option 4: Manual Setup

For any platform without the above tools.

### Steps

1. Clone the repository:

   ```bash
   git clone https://github.com/brndls/autowasp.git
   cd autowasp
   ```

2. Set JAVA_HOME manually:

   ```bash
   export JAVA_HOME="/path/to/java-21"
   export PATH="$JAVA_HOME/bin:$PATH"
   ```

3. Build:

   ```bash
   ./gradlew build
   ```

---

## Build Output

The JAR file will be created at:

```text
build/libs/autowasp-jar-with-dependencies.jar
```

## Install in Burp Suite

1. Open Burp Suite Professional
2. Go to **Extensions** tab
3. Click **Add**
4. Select the JAR file from `build/libs/` directory
5. Verify the "Autowasp" tab appears

---

## Project Structure

```text
autowasp/
├── .devcontainer/          # DevContainer configuration
├── .envrc.example          # direnv template
├── shell.nix               # Nix shell environment
├── src/main/java/
│   └── autowasp/           # Core extension logic
│       ├── checklist/      # OWASP WSTG checklist
│       ├── http/           # HTTP handling wrappers
│       └── logger/         # Traffic & scan logging
├── src/main/resources/     # WSTG local cache
├── build.gradle.kts        # Gradle configuration
└── README.md               # Project overview
```

## Gradle Commands

| Command                  | Description              |
| ------------------------ | ------------------------ |
| `./gradlew build`        | Compile and build JAR    |
| `./gradlew clean build`  | Clean build from scratch |
| `./gradlew shadowJar`    | Build fat JAR only       |
| `./gradlew spotlessApply`| Auto-format code         |
| `./gradlew dependencies` | Show dependency tree     |

## Development Workflow

1. Make changes to Java source files in `src/main/java/`
2. Rebuild: `./gradlew build`
3. Reload extension in Burp Suite (Extensions > Remove > Add)
4. Test your changes

---

## Troubleshooting

### Extension fails to load in Burp Suite

- Ensure you're using **Burp Suite Professional** (not Community Edition)
- Verify the JAR was built successfully
- Check Burp's Extensions > Errors tab for details

### Java version mismatch

This extension requires Java 21. Verify with:

```bash
java -version
# Should show: openjdk version "21.x.x"
```

### DevContainer build fails

- Ensure Docker is running
- Try rebuilding: `Dev Containers: Rebuild Container`
- Check Docker logs for errors

### direnv not loading

- Ensure direnv hook is in your shell config
- Run `direnv allow` in the project directory
- Check `.envrc` has correct `JAVA_HOME` path

---

## Contributing

See [README.md](README.md#contributing) for contribution guidelines.
