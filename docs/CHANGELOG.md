# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.1.0] - 2026-01-03

### Added

- **Security Audit & Fixes**: Resolved critical deserialization vulnerability, path traversal, and URL injection (BApp Criteria #3).
- **Memory Management Audit**: Implemented Logger table pagination and hard limits to handle large projects (BApp Criteria #9).
- **Memory Monitor**: Real-time memory usage indicator with visual warnings.
- **Submission Assets**: New extension icon, refined BApp description, and screenshots.
- **Project Reliability**: Replaced insecure Java serialization with safe JSON-based persistence.

### Changed

- **UI Refinement**: Optimized Logger UI for better responsiveness.
- **Documentation**: Updated README with installation guide and fixed copyright headers.
- **Code Quality**: Reduced cognitive complexity in UI components and fixed SonarQube issues.

## [2.0.1] - 2026-01-02

### Added

- **Burp Networking**: HTTP connections now use `api.http().sendRequest()` for proxy and session handling (BApp Criteria #7).

### Changed

- **Model & Helper Tests**: Improved test coverage for `ChecklistEntry`, `LoggerEntry`, `InstanceEntry`, and wrappers.

---

## [2.0.0] - 2026-01-01

### Added

- **Montoya API Support**: Full migration from Legacy Extender API to modern Montoya API (2025.12).
- **Java 21 Support**: Project updated to use Java 21 LTS.
- **Gradle Build System**: Replaced Maven with Gradle for faster and more flexible builds.
- **Clean Unload**: Added proper unload handlers to release resources when extension is unloaded.
- **Enhanced Logging**: Improved error logging with full stack traces.
- **Development Tools**: Added `DevContainer`, `direnv`, and `Nix` support for easy development setup.
- **Offline Mode**: Bundled WSTG v4.2 checklist for offline operation (BApp Criteria #8).
- **Progress Indicator**: Added progress bar during checklist fetch operations.
- **Background Threading**: Fetch operations now use SwingWorker for proper EDT handling (BApp Criteria #5).
- **Unit Test Framework**: Added JUnit 5, Mockito, and JaCoCo for test coverage reporting.
- **LocalChecklistLoader Tests**: Added comprehensive unit tests with 98% code coverage.
- **ChecklistLogic Tests**: Added unit tests for fetch logic, scraping, File I/O, and error handling (>70% coverage).
- **ChecklistFetchWorker Tests**: Added unit tests for background fetch execution and progress updates.

### Changed

- **Breaking Change**: Minimum Burp Suite requirement increased to 2022.1+.
- **Breaking Change**: Java runtime requirement increased to Java 21+.
- Updated all dependencies (Apache POI, Jsoup, GSON) to latest versions.
- Refactored project structure to follow best practices.

### Removed

- Legacy Burp Extender API dependencies.
- Maven `pom.xml` configuration.

## [1.0.1] - 2021-04-06

### Fixed

- Fixed an issue where online WSTG mapping failed to map findings to the excel file correctly.
- Security fix for HTML rendering on Swing components (PortSwigger Support).

### Changed

- UI/UX updates for better usability.
- Code cleanup and removal of redundant code.

## [1.0.0] - 2021-02-04

### Added

- Initial BApp Store release.
- **Testing Checklist**: Integration with OWASP WSTG Checklist.
- **Logger Tool**: Automation for logging vulnerable network traffic issues.
- **Report Generation**: Feature to generate Excel reports from findings.
