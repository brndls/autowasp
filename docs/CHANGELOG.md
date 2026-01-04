# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.2.2] - 2026-01-04

### Changed

- **Full Data Encapsulation**: Completed Phase 4 refactoring. Removed all public data fields (`checklistLog`, `loggerList`, etc.) from `Autowasp.java` and enforced access via Managers.
- **API Cleanup**: Removed 17+ legacy delegation methods from `Autowasp`, reducing API surface area significantly.
- **Code Quality**: `Autowasp.java` is now purely an entry point and coordinator, with zero business logic or data storage.
- **Maintainability**: All components now access data through strict Manager interfaces (`getChecklistManager()`, `getLoggerManager()`), preventing spaghetti code dependencies.
- **Clean Architecture**: Achieved strict separation of concerns; Logic components no longer depend on the main Extender class for data.

### Technical Details

- Updated 20+ files to use Manager accessors.
- Removed unused imports globally.
- Verified zero public fields in main class.
- All unit tests updated to mock Managers instead of Extender fields.

## [2.2.1] - 2026-01-04

### Changed

- **Internal Refactoring**: Extracted component management into domain-specific managers (ChecklistManager, LoggerManager, UIManager, PersistenceManager).
- **Code Quality**: Resolved SonarQube "Monster Class" warning by reducing `Autowasp.java` dependencies from 21 to 6 (-71%).
- **Maintainability**: Improved code organization and separation of concerns for better long-term maintenance.
- **Architecture**: Implemented manager pattern with proper delegation for backward compatibility.

### Technical Details

- Reduced `Autowasp.java` from 390 to 337 lines (-13.6%)
- Created 4 manager classes totaling 552 lines
- Maintained 100% backward compatibility - no breaking changes
- All existing functionality preserved

## [2.2.0] - 2026-01-03

### Added

- **Project Persistence**: Auto-save and load of checklist state and logger traffic to Burp Suite project files (`.burp`).
- **Data Compression**: GZIP compression for HTTP traffic in memory, significantly reducing memory footprint for large projects (~70% reduction).
- **Advanced Search**: Search and filter functionality for both the OWASP WSTG Checklist and the Logger table.
- **Improved UI Scalability**: Fixed table index mapping to support sorting and filtering without data corruption.
- **Enhanced Memory Monitor**: Added visual progress bar and "Update Memory Usage" button for better resource tracking.
- **Traffic Interning**: Memory optimization using shared constants for common vulnerability types and severities.

### Fixed

- Resolved row index mismatch issue when selecting items in sorted/filtered tables.
- Standardized utility classes with private constructors for better maintainability.

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
