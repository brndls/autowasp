# SonarQube Cloud Setup Guide

Comprehensive guide to integrate Autowasp with SonarQube Cloud for test coverage reporting and code quality analysis.

## Prerequisites

- GitHub account with access to the Autowasp repository
- Access to add GitHub Secrets
- (Optional) Gradle installed for local testing

## Configuration Approach

> [!IMPORTANT]
> **How Configuration Works**
> - All SonarQube settings are defined in `build.gradle.kts` (single source of truth)
> - Credentials (SONAR_TOKEN) are provided via **environment variables**, never hardcoded
> - For local testing, set `SONAR_TOKEN` via `.envrc` (gitignored)

This approach provides:
- ✅ **Transparency**: Everyone can see the project configuration
- ✅ **Security**: No credentials in the repository
- ✅ **DRY**: Single source of truth in `build.gradle.kts`

---

## Step 1: Setup SonarQube Cloud Account

### 1.1 Create Account

1. Visit [SonarQube Cloud](https://sonarcloud.io/)
2. Click **"Log in"** or **"Sign up"**
3. Log in using your GitHub account
4. Authorize SonarQube Cloud to access GitHub

### 1.2 Create Organization

1. After logging in, click **"+"** in the top right corner
2. Select **"Create new organization"**
3. Select **"Choose an organization on GitHub"**
4. Choose your organization or user account (e.g., `brndls`)
5. Choose the **"Free"** plan for open-source projects
6. Click **"Create Organization"**
7. **Note the organization key** that is created (e.g., `honk-buzz`)

### 1.3 Create Project

1. In the organization dashboard, click **"Analyze new project"**
2. Select the **"autowasp"** repository
3. Click **"Set Up"**
4. Select **"With GitHub Actions"**
5. **Note the project key** that is created (e.g., `brndls_autowasp`)

---

## Step 2: Generate SonarQube Token

1. In SonarQube Cloud, click your avatar in the top right corner
2. Select **"My Account"** → **"Security"**
3. In the **"Generate Tokens"** section:
   - Name: `GitHub Actions - Autowasp`
   - Type: **"Global Analysis Token"**
   - Expires in: **"No expiration"** (or according to your policy)
4. Click **"Generate"**
5. **IMPORTANT: Copy this token immediately** (it is only displayed once)
   - Format: `sqp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`

---

## Step 3: Setup GitHub Secrets

1. Open the Autowasp repository on GitHub
2. Click **"Settings"** → **"Secrets and variables"** → **"Actions"**
3. Click **"New repository secret"**
4. Add the secret:
   - Name: `SONAR_TOKEN`
   - Value: [paste the token from Step 2]
5. Click **"Add secret"**

> [!NOTE]
> The GitHub Actions workflow will automatically use this secret. The token is never stored in the repository.

---

## Step 4: Verify Configuration

All SonarQube configuration is defined in [build.gradle.kts](../build.gradle.kts) in the `sonarqube` block:

```kotlin
sonarqube {
    properties {
        property("sonar.organization", "honk-buzz")
        property("sonar.projectKey", "brndls_autowasp")
        // ... other properties
    }
}
```

**No separate properties file needed!** The configuration is centralized in `build.gradle.kts`.

---

## Step 5: Trigger GitHub Actions

The SonarQube analysis will run automatically when you:
- Push to the `main` branch
- Create or update a pull request

To trigger it manually:

```bash
# Make a small change (if needed)
git commit --allow-empty -m "chore: Trigger SonarQube analysis"
git push origin main
```

---

## Step 6: Verify Integration

### 6.1 Check GitHub Actions

1. Open the repository on GitHub
2. Click the **"Actions"** tab
3. See that the **"Build and Analyze"** workflow is running
4. Click the workflow to see the logs
5. Ensure all steps completed successfully (✅)

### 6.2 Check SonarQube Cloud Dashboard

1. Return to [SonarQube Cloud](https://sonarcloud.io/)
2. Select the **"autowasp"** project
3. Verify that metrics appear:
   - **Quality Gate**: Status (Passed/Failed)
   - **Coverage**: Code coverage percentage
   - **Code Smells**: Number of code smells
   - **Bugs**: Number of bugs
   - **Vulnerabilities**: Number of security vulnerabilities

---

## Running Analysis Locally (Optional)

To run SonarQube analysis on your local machine, you need to provide the `SONAR_TOKEN` via environment variable.

### Using .envrc (Recommended)

If you're using `direnv` (already configured in this project):

```bash
# 1. Add SONAR_TOKEN to your .envrc file
echo 'export SONAR_TOKEN="sqp_your_token_here"' >> .envrc

# 2. Allow direnv to load the updated .envrc
direnv allow

# 3. Run analysis (token is automatically available)
./gradlew clean test jacocoTestReport sonarqube
```

> [!TIP]
> The `.envrc` file is gitignored, so your token won't be committed. The `.envrc.example` file includes a commented template for `SONAR_TOKEN`.

### Manual Export

For one-time use or if not using direnv:

```bash
# Set environment variable with your token
export SONAR_TOKEN=your_token_here

# Run tests, generate coverage, and analyze
./gradlew clean test jacocoTestReport sonarqube
```

---

## Troubleshooting

### Error: "SONAR_TOKEN not found"

**Cause:** GitHub Secret has not been set up or the name does not match.

**Solution:**
1. Verify the secret name in GitHub Settings → Secrets is `SONAR_TOKEN`
2. Re-run the workflow after adding the secret

### Error: "sonar.organization not defined"

**Cause:** The `sonarqube` block in `build.gradle.kts` is missing or incomplete.

**Solution:**
1. Verify that `build.gradle.kts` contains the `sonarqube { ... }` block
2. Check that `sonar.organization` property is defined

### Error: "Coverage report not found"

**Cause:** JaCoCo report has not been generated or the path is incorrect.

**Solution:**
1. Verify that the workflow runs `./gradlew jacocoTestReport`
2. Check if the file exists: `build/reports/jacoco/test/jacocoTestReport.xml`

### Workflow not running

**Cause:** Workflow file has not been committed or there is a syntax error.

**Solution:**
1. Verify the file exists: `.github/workflows/sonarqube.yml`
2. Check YAML syntax with an online validator
3. Check workflow logs in GitHub Actions for error details

---

## Maintenance

### Update SonarQube Plugin Version

Edit `build.gradle.kts`:

```kotlin
id("org.sonarqube") version "X.X.X.XXXX"
```

Check the latest version at: https://plugins.gradle.org/plugin/org.sonarqube

### Rotate Token

If the token needs to be rotated:

1. Generate a new token in SonarQube Cloud (Step 2)
2. Update GitHub Secret `SONAR_TOKEN` with the new token
3. Re-run the workflow to verify

### Update Project Configuration

If you need to change organization or project key, edit the `sonarqube` block in `build.gradle.kts`.

---

## Resources

- [SonarQube Cloud Documentation](https://docs.sonarsource.com/sonarqube-cloud/)
- [Java Test Coverage Guide](https://docs.sonarsource.com/sonarqube-cloud/enriching/test-coverage/java-test-coverage/)
- [SonarQube Gradle Plugin](https://docs.sonarsource.com/sonarqube-server/latest/analyzing-source-code/scanners/sonarscanner-for-gradle/)
- [JaCoCo Documentation](https://www.jacoco.org/jacoco/trunk/doc/)

---

## Support

If you encounter issues:

1. Check the [SonarQube Community Forum](https://community.sonarsource.com/)
2. Check GitHub Actions logs for error details
3. Review SonarQube Cloud project settings
4. Open an issue in the Autowasp repository
