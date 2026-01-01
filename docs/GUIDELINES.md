# Burp Suite Extension Development Guidelines

This document provides official guidelines from PortSwigger for developing Burp Suite extensions, compiled for quick reference.

> **Source**: [PortSwigger Official Documentation](https://portswigger.net/burp/documentation/desktop/extend-burp/extensions/creating)

---

## Language Choice

**Strongly recommended**: Java using the **Montoya API**

- Modern API with full access to Burp's extensibility features
- Actively maintained and well-documented
- All official documentation and examples use Java + Montoya API

**Alternative**: Kotlin (compiles to .jar, loaded like Java extensions)

> ⚠️ **Legacy Warning**: Python (Jython) and Ruby (JRuby) using the legacy Extender API are no longer actively maintained.

---

## Montoya API Quick Reference

### Maven Dependency

```xml
<dependency>
    <groupId>net.portswigger.burp.extensions</groupId>
    <artifactId>montoya-api</artifactId>
    <version>2025.12</version>
</dependency>
```

### Gradle Dependency

```kotlin
implementation("net.portswigger.burp.extensions:montoya-api:2025.12")
```

### Entry Point

```java
import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

public class MyExtension implements BurpExtension {
    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("My Extension");
        // Register handlers, tabs, etc.
    }
}
```

---

## BApp Store Acceptance Criteria

To submit extensions to the BApp Store, ensure compliance with these requirements:

### 1. Unique Function

- Don't duplicate existing BApp Store extensions
- Consider contributing to existing BApps instead

### 2. Clear, Descriptive Name

- Name should clearly describe functionality
- Include a one-line summary

### 3. Secure Operation

- Treat HTTP message content as **untrusted**
- Extensions must not expose users to attack
- Auto-fill from untrusted sources should be verified

### 4. Include All Dependencies

- Fat JAR with all dependencies for one-click installation
- Avoids version mismatch issues

### 5. Use Background Threads

- **Never** perform slow operations in Swing Event Dispatch Thread
- Avoid slow operations in `ProxyHttpRequestHandler`, `ProxyHttpResponseHandler`, `HttpHandler`
- Protect shared data structures with locks
- Handle exceptions in background threads:

  ```java
  try {
      // thread logic
  } catch (Exception e) {
      api.logging().logToError(e);
  }
  ```

### 6. Clean Unload

```java
api.extension().registerUnloadingHandler(() -> {
    // Terminate background threads
    // Release resources
});
```

### 7. Use Burp Networking

```java
// Preferred
api.http().sendRequest(httpRequest);

// Avoid
new URL(...).openConnection(); // java.net.URL
```

This ensures proxy settings and session handling rules are respected.

### 8. Support Offline Working

- Include copy of vulnerability definitions
- Don't require internet for core functionality

### 9. Handle Large Projects

- Avoid long-term references to objects from handlers
- Use `Persistence.temporaryFileContext()` for persistent storage
- Be careful with `SiteMap.requestResponses()` and `Proxy.history()`

### 10. Parent GUI Elements

```java
Frame parentFrame = api.userInterface().swingUtils().suiteFrame();
JOptionPane.showMessageDialog(parentFrame, "Message");
```

### 11. Use Montoya API Artifact

- Use Gradle or Maven (Gradle recommended for new projects)

### 12. Use Montoya API for AI Features

- Use dedicated Montoya API methods for AI functionality
- Follow [AI extension best practices](https://portswigger.net/burp/documentation/desktop/extend-burp/extensions/creating/creating-ai-extensions/best-practices)

---

## Common Interface Mappings

| Legacy Extender API      | Montoya API                                              |
|--------------------------|----------------------------------------------------------|
| `IBurpExtender`          | `BurpExtension`                                          |
| `IBurpExtenderCallbacks` | `MontoyaApi`                                             |
| `IExtensionHelpers`      | `MontoyaApi.*` (distributed across interfaces)           |
| `ITab`                   | `api.userInterface().registerSuiteTab()`                 |
| `IProxyListener`         | `api.proxy().registerRequestHandler()`                   |
| `IScannerListener`       | `api.scanner().registerAuditIssueHandler()`              |
| `IContextMenuFactory`    | `api.userInterface().registerContextMenuItemsProvider()` |
| `IHttpService`           | `HttpService`                                            |
| `IHttpRequestResponse`   | `HttpRequestResponse`                                    |
| `IScanIssue`             | `AuditIssue`                                             |

---

## Resources

- [Montoya API GitHub](https://github.com/PortSwigger/burp-extensions-montoya-api)
- [Montoya API Javadoc](https://portswigger.github.io/burp-extensions-montoya-api/javadoc/burp/api/montoya/MontoyaApi.html)
- [Montoya API Examples](https://github.com/PortSwigger/burp-extensions-montoya-api-examples)
- [PortSwigger Discord #extensions](https://discord.com/invite/portswigger)
- [BApp Store](https://portswigger.net/bappstore)

---

## AI-Powered Development

PortSwigger provides support for AI-assisted extension development:

- **CLAUDE.md**: Extension starter projects include context files for LLMs
- **Vibe Coding**: Use LLMs to accelerate Burp extension development

For setup instructions, see:

- [Setting up using starter project](https://portswigger.net/burp/documentation/desktop/extend-burp/extensions/creating/set-up/starter-project)
- [Manual setup](https://portswigger.net/burp/documentation/desktop/extend-burp/extensions/creating/set-up/manual-setup)
