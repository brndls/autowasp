# Autowasp Development Environment
# Uses Java 21 LTS for Burp Suite Extension compatibility
#
# Usage:
# 1. Install direnv: already included in packages.nix
# 2. Run: direnv allow
# 3. Environment will automatically activate when entering this directory
#
# For manual entry without direnv: nix-shell

{
  pkgs ? import <nixpkgs> { },
}:

pkgs.mkShell {
  name = "autowasp-dev";

  buildInputs = with pkgs; [
    # Java 21 LTS - Required for Burp Suite Extension development
    openjdk21

    # Build tools
    gradle
  ];

  shellHook = ''
    # Set JAVA_HOME to Java 21 from Nix
    export JAVA_HOME="${pkgs.openjdk21}/lib/openjdk"
    export GRADLE_USER_HOME="''${XDG_DATA_HOME:-$HOME/.local/share}/gradle"

    # Project-specific settings
    export AUTOWASP_DEV=1

    # Display environment info
    echo "🔧 Autowasp dev environment loaded"
    echo "   JAVA_HOME: $JAVA_HOME"
    echo "   Java: $(java -version 2>&1 | head -1)"
    echo "   Gradle: $(gradle --version 2>&1 | grep 'Gradle' | head -1)"
  '';
}
