# Autowasp Development Roadmap

This document tracks the ongoing development phases for Autowasp.

## Phase Overview

| Phase | Name                          | Status     | Effort    |
| ----- | ----------------------------- | ---------- | --------- |
| 4.1   | Modernization (Java 21)       | ✅ Complete | -         |
| 4.2   | Reliability (Fetch Logic)     | ✅ Complete | Medium    |
| 4.3   | Report Enhancements           | ⏳ Pending  | Medium    |
| 4.4   | UI Improvements               | ⏳ Pending  | Medium    |
| 5.1   | Unit Tests                    | ✅ Complete | Medium    |
| 5.2   | Integration Tests             | ⏳ Pending  | High      |
| 6.1   | Local Checklist Import        | ✅ Complete | Medium    |
| 6.2   | GitHub Release & CI/CD        | ✅ Complete | Medium    |
| 6.3   | BApp Store Submission         | ⏳ Pending  | Low       |
| 7.0   | Future Maintenance            | ⏳ Pending  | Low       |
| 7.1   | Handle Large Projects         | ⏳ Pending  | Medium    |
| 8.1   | Auto-Mapping WSTG             | 🔮 Future   | Medium    |
| 8.2   | Evidence Collector            | 🔮 Future   | Medium    |
| 9.1   | Smart Severity Calculator     | 🔮 Future   | Medium    |
| 9.2   | Retest Tracking               | 🔮 Future   | High      |
| 10.1  | Burp Collaborator Integration | 🔮 Future   | High      |
| 10.2  | External Tool Integration     | 🔮 Future   | High      |
| 11.1  | AI-Powered Analysis           | 🔮 Future   | Very High |
| 11.2  | Scope-Aware Testing Tracker   | 🔮 Future   | High      |
| 12.1  | Session Notes                 | ⏳ Pending  | Low       |
| 12.2  | Payload Manager               | ⏳ Pending  | Medium    |
| 12.3  | Target Scope Manager          | ⏳ Pending  | High      |

---

## Phase 4.2 - Reliability (Fetch Logic)

**Goal:** Improve reliability, error handling, and maintainability of `ChecklistLogic.java`.

### 4.2.1 Quick Wins ✅

- [x] Remove 120-line dead code (anonymous List class)
- [x] Fix assignment bug `if (entry.exclusion = true)` → `if (entry.exclusion)`
- [x] Remove blocking `TimeUnit.sleep(1000)`

### 4.2.2 Reliability Improvements ✅

- [x] Add retry logic (3 attempts, exponential backoff)
- [x] Skip-and-continue on failed URLs
- [x] User-friendly error dialogs using `suiteFrame()` *(BApp #10)*
- [x] Improve logging verbosity options

### 4.2.3 UX Improvements ✅

- [x] Add progress indicators for long-running tasks
- [x] Move fetch to background thread (SwingWorker) *(BApp #5)*

> [!NOTE]
> **TODO:** Web fetch currently fails due to OWASP URL connectivity issues.
> Consider deprecating web fetch in favor of bundled offline mode (Phase 6.1).

### 4.2.4 Burp Networking Compliance ✅ *(BApp #7)*

**Goal:** Replace direct HTTP connections with Burp's networking API.

**Problem:** `ChecklistLogic.java` uses `Jsoup.connect()` which bypasses Burp's proxy settings, session handling, and SSL configuration.

**Affected Methods:**

- `fetchWithRetry()` (line 77) - Uses `Jsoup.connect(url).timeout(10000).get()`

**Solution:** Refactor to use Montoya API:

```java
// BEFORE (Jsoup direct connection - VIOLATES BApp #7)
private Document fetchWithRetry(String url) {
    return Jsoup.connect(url).timeout(10000).get();
}

// AFTER (Burp Networking - COMPLIANT)
private Document fetchWithRetry(String url) {
    HttpRequest request = HttpRequest.httpRequestFromUrl(url);
    HttpRequestResponse response = extender.getApi().http().sendRequest(request);
    
    if (response.response().statusCode() == 200) {
        String html = response.response().bodyToString();
        return Jsoup.parse(html);  // Parse only, no connection
    }
    return null;
}
```

**Tasks:**

- [x] Refactor `fetchWithRetry()` to use `api.http().sendRequest()`
- [x] Update retry logic to handle `HttpRequestResponse`
- [x] Test with Burp proxy interception enabled
- [x] Verify SSL certificate handling

**Note on `java.net.URL` usage:**
> `java.net.URL` used in `InstanceEntry.java`, `TrafficEntry.java`, etc. is **compliant** because it's used only as a data container (storing URL strings), not for making HTTP connections. Montoya API does not provide a replacement class for URL representation.

---

## Phase 4.3 - Report Enhancements

**Goal:** Improve Excel report quality and add new export formats with persistent project state.

> [!NOTE]
> Phase 4.3 tightly integrates with Phase 7.1 (Project Persistence) to enable:
>
> - Resume report generation from saved project state
> - Include data from previous testing sessions
> - Generate consolidated reports across multiple Burp project files

### Report Features

- [ ] Add summary sheet with statistics
- [ ] Include severity/confidence charts
- [ ] Add HTML report option
- [ ] Add JSON export for automation
- [ ] Custom report templates

### Template System *(Absorbed from old roadmap Phase 7.1)*

| Template                  | Purpose                           |
| ------------------------- | --------------------------------- |
| `executive_summary.ftl`   | High-level summary for management |
| `methodology.ftl`         | WSTG methodology description      |
| `finding_detail.ftl`      | Individual finding template       |
| `risk_dashboard.ftl`      | Visual risk summary               |
| `remediation_roadmap.ftl` | Prioritized fix recommendations   |

### Multi-Format Export *(Absorbed from old roadmap Phase 7.2)*

| Format             | Library               | Use Case                       |
| ------------------ | --------------------- | ------------------------------ |
| **Excel (.xlsx)**  | Apache POI (existing) | Data analysis, client delivery |
| **HTML**           | Built-in              | Web viewing, email embedding   |
| **Markdown (.md)** | Built-in              | Documentation systems, Git     |
| **JSON**           | GSON (existing)       | API integration, automation    |
| **PDF**            | OpenPDF / iText       | Formal reports, print          |

### Persistence Integration (requires Phase 7.1)

- [ ] Load saved checklist progress when generating report
- [ ] Include historical traffic instances from project file
- [ ] Export report with embedded session metadata

---

## Phase 4.4 - UI Improvements

**Goal:** Modernize user interface.

### Core UI Enhancements

- [ ] Add dark mode support
- [ ] Improve table filtering and sorting
- [ ] Add keyboard shortcuts
- [ ] Improve request/response viewer

### Enhanced Context Menu *(Absorbed from old roadmap Phase 5.3)*

Rich context menu options for streamlined workflow using `api.userInterface().registerContextMenuItemsProvider()`.

**Menu Structure:**

| Menu Item             | Shortcut     | Action                                   |
| --------------------- | ------------ | ---------------------------------------- |
| Add to WSTG Checklist | Ctrl+Shift+W | Open dialog to select WSTG test case     |
| Mark as Finding       | Ctrl+Shift+F | Create new finding from selected request |
| Generate Evidence     | Ctrl+Shift+E | Capture and save evidence snapshot       |
| Quick Note            | Ctrl+Shift+N | Add annotation to request                |
| Link to Existing      | Ctrl+Shift+L | Associate with existing finding          |

---

## Phase 5.1 - Unit Tests ✅

**Goal:** Establish test coverage for quality assurance.

**Framework:** JUnit 5 + Mockito + JaCoCo

**Run tests:** `./gradlew test jacocoTestReport`

### Tasks Checklist

#### 5.1.1 Setup Test Framework ✅

- [x] Add JUnit 5 dependency to `build.gradle`
- [x] Add Mockito dependency
- [x] Configure JaCoCo plugin
- [x] Create `src/test/java/autowasp/` folder

#### 5.1.2 LocalChecklistLoader Tests (High Priority) ✅

- [x] `loadFromResources()` - successful JSON load
- [x] `loadFromResources()` - handle file not found
- [x] `parseCategory()` - parse valid JSON structure
- [x] `parseCategory()` - handle malformed JSON

#### 5.1.3 ChecklistLogic Tests ✅

- [x] `fetchWithRetry()` - succeeds after 1-2 retries
- [x] `fetchWithRetry()` - fails after max attempts
- [x] `scrapePageURLs()` - handle null/empty response
- [x] `getTableElements()` - handle malformed HTML
- [x] `getContentElements()` - handle missing sections

#### 5.1.4 ChecklistFetchWorker Tests ✅

- [x] `doInBackground()` - complete successfully
- [x] `doInBackground()` - handle cancellation
- [x] `process()` - publish progress updates

#### 5.1.5 Coverage Goal ✅

- [x] Target: **60% line coverage** (minimum for library code)
- [x] Focus on: logic paths, error handling, edge cases
- [x] Generate report: `./gradlew test jacocoTestReport`

---

## Phase 5.2 - Integration Tests

**Goal:** Verify end-to-end functionality.

- [ ] Create test Burp project files
- [ ] Document manual test procedures
- [ ] Consider headless Burp testing

### Manual Test Procedures

| Test Case       | Steps                            | Expected Result                       |
| --------------- | -------------------------------- | ------------------------------------- |
| Normal Fetch    | Click "Fetch WSTG Checklist"     | All items loaded, status success      |
| Network Error   | Disconnect internet → Fetch      | Error dialog appears                  |
| Partial Failure | Block 1 URL via proxy → Fetch    | Skip failed URL, continue with others |
| Cancel Fetch    | Click "Cancel Fetch" mid-process | Fetch stops, status cancelled         |

---

## Phase 6.1 - Local Checklist Import ✅

**Goal:** Import WSTG checklist from local files without HTML scraping. *(BApp #8: Offline Support)*

### Local Data Source

The `.legacy-backup/4-Web_Application_Security_Testing/` folder contains 3 data formats:

| Format             | File                    | Purpose                                          |
| ------------------ | ----------------------- | ------------------------------------------------ |
| **JSON**           | `checklist.json` (56KB) | Structured data: id, name, reference, objectives |
| **Markdown Table** | `Testing_Checklist.md`  | Compact overview for Quick View                  |
| **Detail Files**   | `01-*/01-*.md` etc.     | Full content per test item                       |

### JSON Structure

```json
{
  "categories": {
    "Information Gathering": {
      "id": "WSTG-INFO",
      "tests": [
        {
          "name": "Conduct Search Engine Discovery...",
          "id": "WSTG-INFO-01",
          "reference": "https://owasp.org/.../01-Conduct_Search_Engine_Discovery_Reconnaissance...",
          "objectives": ["Identify what sensitive design..."]
        }
      ]
    }
  }
}
```

### Implementation

#### 6.1.1 Copy Data to Resources ✅

- [x] Copy `checklist.json` to `src/main/resources/wstg/checklist.json`

#### 6.1.2 JSON Parser Class ✅

```java
public class LocalChecklistLoader {
    private static final String CHECKLIST_PATH = "/wstg/checklist.json";
    
    public Map<String, Category> loadFromResources() {
        try (InputStream is = getClass().getResourceAsStream(CHECKLIST_PATH)) {
            return new Gson().fromJson(new InputStreamReader(is), ChecklistData.class);
        }
    }
}
```

**Dependencies:** Use Gson (already in project) for JSON parsing.

#### 6.1.3 Refactor ChecklistLogic ✅

- [x] Refactored `loadLocalCopy()` to use `LocalChecklistLoader`
- [x] `LocalChecklistLoader.java` parses bundled JSON

#### 6.1.4 Update UI (Optional) ✅

- [x] Button renamed to "Load Bundled WSTG (Offline)"
- [x] Status shows bundled WSTG version

### Benefits

| Aspect      | Local JSON           | HTML Scraping        |
| ----------- | -------------------- | -------------------- |
| Network     | 100% Offline         | Requires internet    |
| Speed       | < 100ms              | ~5s                  |
| Reliability | Independent of OWASP | Dependent on website |
| Complexity  | Simple JSON parsing  | DOM manipulation     |

### Known Limitations

#### 6.1.5 "How to Test" Content (TODO)

> [!NOTE]
> "How to Test" content is not available in bundled JSON because `checklist.json` only contains objectives, not the full testing methodology.

**Options for future enhancement:**

- [ ] Parse markdown files from `.legacy-backup/4-Web_Application_Security_Testing/` for detailed content
- [ ] Or let users click the OWASP link for complete methodology

**Trade-off:** Keeping local content in sync with the OWASP website is difficult to maintain. For beginners, the OWASP reference link is sufficient as guidance.

---

## Phase 6.2 - GitHub Release & CI/CD ✅

**Goal:** Publish versioned releases with automated builds.

- [x] Set up semantic versioning (v2.0.0)
- [x] Create/maintain CHANGELOG.md
- [x] Configure GitHub Actions for CI/CD (`.github/workflows/release.yml`)
- [x] Automate JAR artifact upload on release

---

## Phase 6.3 - BApp Store Submission

**Goal:** Submit to PortSwigger BApp Store.

### BApp Store Criteria Checklist

Reference: [GUIDELINES.md](./GUIDELINES.md)

| #   | Criteria                 | Status | Notes                                      |
| --- | ------------------------ | ------ | ------------------------------------------ |
| 1   | Unique Function          | ✅      | OWASP WSTG checklist integration           |
| 2   | Clear, Descriptive Name  | ✅      | "Autowasp"                                 |
| 3   | Secure Operation         | ⏳      | Verify untrusted input handling            |
| 4   | Include All Dependencies | ✅      | Fat JAR via Shadow plugin                  |
| 5   | Use Background Threads   | ✅      | Phase 4.2.3 SwingWorker                    |
| 6   | Clean Unload             | ✅      | `registerUnloadingHandler()` implemented   |
| 7   | Use Burp Networking      | ✅      | Phase 4.2.4 - Refactored `Jsoup.connect()` |
| 8   | Support Offline Working  | ✅      | Phase 6.1 Local Import                     |
| 9   | Handle Large Projects    | ⏳      | Audit object references                    |
| 10  | Parent GUI Elements      | ✅      | Phase 4.2.2 `suiteFrame()`                 |
| 11  | Use Montoya API Artifact | ✅      | Gradle dependency configured               |
| 12  | AI Features (if any)     | N/A    | Not applicable                             |

### Submission Tasks

- [ ] Verify all 12 BApp Store criteria above
- [ ] Ensure offline working (bundled WSTG via Phase 6.1)
- [ ] Create extension icon
- [ ] Write BApp Store description (one-line summary + full description)
- [ ] Create demo GIFs/screenshots
- [ ] Submit to PortSwigger

---

## Phase 7.0 - Future Maintenance

**Goal:** Long-term project health and technical debt reduction.

- [ ] Fix Gradle 9.0 deprecation warnings (incompatible with future releases)

---

## Phase 7.1 - Handle Large Projects & Project Persistence

**Goal:** Comply with BApp Store Criteria #9 and enable extension state persistence.

> [!IMPORTANT]
> This phase is a **prerequisite for Phase 4.3** persistence integration features.

### 7.1.1 Memory Management Audit *(BApp Criteria #9)*

| Component                         | Status      | Risk   | Action Required                                               |
| --------------------------------- | ----------- | ------ | ------------------------------------------------------------- |
| `InstanceEntry.java`              | ✅ Compliant | Low    | Uses `HTTPRequestResponse` wrapper                            |
| `HTTPRequestResponse.java`        | ✅ Compliant | Low    | Serializable wrapper with `byte[]` copy                       |
| `ContextMenuFactory.java`         | ⚠️ Review    | Medium | Verify no long-term references to `List<HttpRequestResponse>` |
| `TrafficTable` / `InstancesTable` | ⚠️ Audit     | Medium | Consider pagination for large datasets                        |

**Tasks:**

- [ ] Audit `ContextMenuFactory` for memory leaks
- [ ] Implement pagination for `TrafficTable` (>1000 entries)
- [ ] Add lazy loading for large traffic lists
- [ ] Test with 10k+ entries to verify memory stability

### 7.1.2 Project Persistence *(Montoya Persistence API)*

**API Overview:**

```java
// Access via MontoyaApi
PersistedObject data = api.persistence().extensionData();

// Stored in Burp Project file, survives project save/load
data.setBoolean("WSTG-INFO-01-tested", true);
data.setHttpRequestResponseList("traffic", instanceList);
```

**Persistence Scope:**

| Storage Type      | Scope                 | Use Case                        |
| ----------------- | --------------------- | ------------------------------- |
| `extensionData()` | Per-project           | Checklist state, tagged traffic |
| `preferences()`   | Global (all projects) | User settings, UI preferences   |

**Implementation Tasks:**

- [ ] Create `AutowaspPersistence.java` helper class
- [ ] Save/load checklist checkbox states per WSTG item
- [ ] Persist tagged traffic instances to project file
- [ ] Add "Save Progress" and "Load Progress" menu items
- [ ] Handle temporary project mode gracefully (in-memory fallback)
- [ ] Migrate data on extension version upgrade

### 7.1.3 Integration with Report Generation

- [ ] Load persisted checklist state before report generation
- [ ] Include all historical traffic from project file in report
- [ ] Add "Include Previous Sessions" option in export dialog

---

## Phase 8: Core Mapping & Evidence Features

### Priority: 🔮 Future | Complexity: Medium

This phase focuses on building foundational features for automated WSTG mapping and evidence collection.

### 8.1 Auto-Mapping Burp Issues to WSTG Categories

**Objective:** Automatically map findings from Burp Scanner to relevant OWASP WSTG test cases.

**Montoya API Components:**

- `api.scanner().registerAuditIssueHandler()` - Capture audit issues
- `AuditIssue.name()`, `AuditIssue.severity()`, `AuditIssue.baseUrl()`

**Mapping Table:**

| Burp Issue Pattern               | WSTG ID      | WSTG Category         |
| -------------------------------- | ------------ | --------------------- |
| SQL injection                    | WSTG-INPV-05 | Input Validation      |
| Cross-site scripting (reflected) | WSTG-INPV-01 | Input Validation      |
| Cross-site scripting (stored)    | WSTG-INPV-02 | Input Validation      |
| XML external entity injection    | WSTG-INPV-07 | Input Validation      |
| HTTP request smuggling           | WSTG-INPV-14 | Input Validation      |
| OS command injection             | WSTG-INPV-12 | Input Validation      |
| Path traversal                   | WSTG-INPV-09 | Input Validation      |
| Server-side template injection   | WSTG-INPV-18 | Input Validation      |
| TLS certificate issues           | WSTG-CRYP-01 | Cryptography          |
| Session token in URL             | WSTG-SESS-04 | Session Management    |
| Session fixation                 | WSTG-SESS-03 | Session Management    |
| Cross-site request forgery       | WSTG-SESS-05 | Session Management    |
| Directory listing                | WSTG-CONF-04 | Configuration         |
| Information disclosure           | WSTG-INFO-02 | Information Gathering |
| Stack trace disclosure           | WSTG-ERRH-01 | Error Handling        |
| Clickjacking                     | WSTG-CLNT-09 | Client-side Testing   |
| Open redirection                 | WSTG-CLNT-04 | Client-side Testing   |

**New Files:**

| File                                     | Description                              |
| ---------------------------------------- | ---------------------------------------- |
| `autowasp/mapper/WSTGMapper.java`        | Core mapping logic with pattern matching |
| `autowasp/mapper/WSTGMappingEntry.java`  | Data model for mapping entries           |
| `autowasp/mapper/WSTGMappingConfig.json` | Configurable mapping rules               |

---

### 8.2 Evidence Collector

**Objective:** Automatically collect comprehensive evidence for each finding including HTTP request/response pairs.

**Montoya API Components:**

- `AuditIssue.requestResponses()` - Access request/response pairs
- `HttpRequestResponse.request()`, `.response()`
- `HttpRequest.bodyToString()`, `HttpResponse.bodyToString()`

**New Files:**

| File                                             | Description                       |
| ------------------------------------------------ | --------------------------------- |
| `autowasp/evidence/EvidenceCollector.java`       | Core evidence collection logic    |
| `autowasp/evidence/Evidence.java`                | Evidence data model (Java record) |
| `autowasp/evidence/RequestResponseEvidence.java` | HTTP evidence model               |
| `autowasp/evidence/EvidenceStore.java`           | In-memory evidence storage        |

---

## Phase 9: Analysis & Tracking Features

### Priority: 🔮 Future | Complexity: Medium-High

This phase adds intelligent analysis and state tracking capabilities.

### 9.1 Smart Severity Calculator

**Objective:** Calculate risk severity based on OWASP Risk Rating Methodology.

**Risk Matrix:**

| Likelihood \ Impact | Critical | High   | Medium | Low  |
| ------------------- | -------- | ------ | ------ | ---- |
| **High**            | Critical | High   | Medium | Low  |
| **Medium**          | High     | Medium | Medium | Low  |
| **Low**             | Medium   | Low    | Low    | Info |

**New Files:**

| File                                    | Description                   |
| --------------------------------------- | ----------------------------- |
| `autowasp/risk/SeverityCalculator.java` | Risk calculation engine       |
| `autowasp/risk/RiskLevel.java`          | Risk level enum               |
| `autowasp/risk/BusinessContext.java`    | Business impact configuration |

---

### 9.2 Automated Retest Tracking

**Objective:** Track remediation status and retest results for each finding.

**Status Flow:**

- **Open** → Issue Found
- **In Progress** → Start Retest
- **Fixed** → Verified Fixed
- **Partially Fixed** → Partially Remediated
- **Not Fixed** → Still Vulnerable
- **False Positive** → Confirmed False Positive

**New Files:**

| File                                 | Description             |
| ------------------------------------ | ----------------------- |
| `autowasp/retest/RetestTracker.java` | Retest management logic |
| `autowasp/retest/RetestEntry.java`   | Retest data model       |
| `autowasp/retest/RetestStatus.java`  | Status enum             |
| `autowasp/ui/RetestPanel.java`       | Retest tab UI           |

---

## Phase 10: Integration Features

### Priority: 🔮 Future | Complexity: High

This phase adds integration with external systems and Burp Suite features.

### 10.1 Burp Collaborator Integration (OAST)

**Objective:** Integrate with Burp Collaborator for Out-of-band Application Security Testing.

**Montoya API Components:**

- `api.collaborator().createClient()`
- `CollaboratorClient.generatePayload()`
- `CollaboratorClient.interactions()`

**OAST Test Cases (WSTG-Aligned):**

| WSTG ID      | Test Case                   | Collaborator Use   |
| ------------ | --------------------------- | ------------------ |
| WSTG-INPV-19 | Server-Side Request Forgery | DNS/HTTP callback  |
| WSTG-INPV-07 | XML External Entity         | External DTD fetch |
| WSTG-INPV-11 | HTTP Request Smuggling      | Delayed response   |
| WSTG-INPV-16 | HTTP Incoming Requests      | Reflected request  |

---

### 10.2 External Tool Integration

**Objective:** Integrate with vulnerability management and ticketing systems.

**Integration Targets:**

| System          | Integration Type | Purpose                     |
| --------------- | ---------------- | --------------------------- |
| Jira            | REST API         | Create issues from findings |
| GitHub Issues   | REST API         | Track remediation           |
| DefectDojo      | REST API         | Vulnerability management    |
| Slack           | Webhook          | Real-time notifications     |
| Microsoft Teams | Webhook          | Real-time notifications     |

**New Files:**

| File                                              | Description             |
| ------------------------------------------------- | ----------------------- |
| `autowasp/integration/IntegrationManager.java`    | Integration coordinator |
| `autowasp/integration/JiraIntegration.java`       | Jira API client         |
| `autowasp/integration/GitHubIntegration.java`     | GitHub API client       |
| `autowasp/integration/DefectDojoIntegration.java` | DefectDojo API client   |
| `autowasp/integration/SlackNotifier.java`         | Slack webhook           |
| `autowasp/integration/TeamsNotifier.java`         | Teams webhook           |

---

## Phase 11: Advanced Features

### Priority: 🔮 Future | Complexity: Very High

This phase implements advanced AI and tracking features.

### 11.1 AI-Powered Analysis

**Objective:** Leverage AI capabilities for intelligent vulnerability analysis.

> [!IMPORTANT]
> This feature requires Burp Suite Professional with AI/Bambda support.

**Montoya API Components:**

- `api.ai().prompt()` - Send prompts to AI model

**AI Use Cases:**

| Use Case                     | Description                                          |
| ---------------------------- | ---------------------------------------------------- |
| **Auto-Description**         | Generate natural language vulnerability descriptions |
| **Remediation Suggestions**  | Context-aware fix recommendations                    |
| **False Positive Detection** | Classify potential false positives                   |
| **Executive Summary**        | Generate management-friendly summaries               |
| **Exploit Scenario**         | Describe potential attack scenarios                  |

---

### 11.2 Scope-Aware Testing Tracker

**Objective:** Track testing progress across the application scope with WSTG coverage metrics.

**Montoya API Components:**

- `api.scope()` - Access scope configuration
- `api.siteMap()` - Access discovered endpoints

**Dashboard Metrics:**

| Metric               | Description                       |
| -------------------- | --------------------------------- |
| Endpoints Discovered | Total URLs in scope               |
| Endpoints Tested     | URLs with associated findings     |
| WSTG Coverage        | Test cases completed per category |
| Time Spent           | Duration per endpoint/category    |
| Finding Density      | Findings per endpoint             |

**New Files:**

| File                                   | Description             |
| -------------------------------------- | ----------------------- |
| `autowasp/tracker/TestingTracker.java` | Progress tracking logic |
| `autowasp/tracker/CoverageReport.java` | Coverage data model     |
| `autowasp/ui/DashboardPanel.java`      | Visual dashboard        |

---

## Priority Matrix

| Priority | Phase | Item                  | Rationale     |
| :------- | :---- | :-------------------- | :------------ |
| 🔴 High   | 6.3   | BApp Store Submission | Release goal  |
| 🟡 Medium | 7.1   | Large Projects        | BApp #9       |
| 🟡 Medium | 4.3   | Report Enhancements   | User value    |
| 🟠 Next   | 12.1  | Session Notes         | User selected |
| 🟠 Next   | 12.2  | Payload Manager       | User selected |
| 🟠 Next   | 12.3  | Target Scope Manager  | User selected |
| 🔵 Low    | 4.4   | UI Improvements       | Nice to have  |
| 🔵 Low    | 5.2   | Integration Tests     | Complex setup |
| 🔮 Future | 8-11  | Advanced Features     | Post-release  |

---

## Recommended Next Steps

1. **Phase 6.3**: BApp Store Submission (Focus on Criteria #3 & #9)
2. **Phase 7.1**: Handle Large Projects (Prerequisite for 4.3)
3. **Phase 4.3**: Report Enhancements (Add summary sheet, Markdown export)
4. **Phase 12**: User-Selected Features (Post-release)

---

## Phase 12: User-Selected Features

### Priority: ⏳ Pending | Post-Release

Additional features selected based on user needs.

### 12.1 Session Notes / Finding Notebook

**Objective:** Integrated notebook for capturing findings and observations.

**Effort:** Low

**Use Cases:**
- Capture notes per request/endpoint
- Link notes to WSTG test cases
- Export notes with reports

**Implementation:**

| File                                | Description             |
| ----------------------------------- | ----------------------- |
| `autowasp/notes/NotebookPanel.java` | Main UI panel           |
| `autowasp/notes/Note.java`          | Note data model         |
| `autowasp/notes/NoteStore.java`     | Persistence via Montoya |

**Tasks:**

- [ ] Create `NotebookPanel` UI with text editor
- [ ] Implement linking to WSTG test cases
- [ ] Persist notes to Burp project file
- [ ] Export notes to Markdown/Excel reports

---

### 12.2 Payload Manager

**Objective:** Payload and wordlist management integrated with WSTG test cases.

**Effort:** Medium

**Use Cases:**
- WSTG-aligned payload collections per category
- Quick-insert payloads to Intruder/Repeater
- Custom payload library management

**Implementation:**

| File                                   | Description              |
| -------------------------------------- | ------------------------ |
| `autowasp/payload/PayloadManager.java` | Core management logic    |
| `autowasp/payload/PayloadSet.java`     | Payload collection model |
| `autowasp/ui/PayloadPanel.java`        | UI panel                 |
| `src/main/resources/payloads/`         | Bundled payload files    |

**Bundled Payload Sets:**

| WSTG ID      | Payload Set            |
| ------------ | ---------------------- |
| WSTG-INPV-01 | XSS payloads           |
| WSTG-INPV-05 | SQL injection payloads |
| WSTG-INPV-07 | XXE payloads           |
| WSTG-INPV-12 | OS Command injection   |
| WSTG-ATHZ-02 | IDOR test patterns     |

**Tasks:**

- [ ] Create bundled payload JSON files per WSTG category
- [ ] Build PayloadManager for loading/managing payloads
- [ ] Create UI panel with search and filter
- [ ] Implement context menu "Insert Payload..."
- [ ] Add ability to create custom payload sets

---

### 12.3 Target Scope Manager

**Objective:** Track testing coverage per endpoint integrated with Burp scope.

**Effort:** High

**Montoya API Components:**

- `api.scope()` - Access scope configuration
- `api.siteMap()` - Access discovered endpoints

**Use Cases:**
- Visual map of endpoints vs WSTG test cases
- Track tested endpoints
- Export coverage reports

**Implementation:**

| File                                  | Description             |
| ------------------------------------- | ----------------------- |
| `autowasp/scope/ScopeManager.java`    | Core scope integration  |
| `autowasp/scope/EndpointTracker.java` | Endpoint tracking logic |
| `autowasp/scope/CoverageMatrix.java`  | WSTG x Endpoint matrix  |
| `autowasp/ui/ScopePanel.java`         | Visual dashboard        |

**Tasks:**

- [ ] Integrate with `api.scope()` to get target scope
- [ ] Build endpoint list from `api.siteMap()`
- [ ] Create coverage matrix: endpoint x WSTG test case
- [ ] Visual indicator (tested/not tested/in progress)
- [ ] Export coverage to reports

---

## Notes

- Current approach scrapes GitHub HTML pages via JSoup
- Phase 6.1 replaces this with local JSON import
- All changes follow KISS, YAGNI, DRY principles
- Data from WSTG v4.2 (stable)

---

## References

- [Montoya API Documentation](https://portswigger.github.io/burp-extensions-montoya-api/javadoc/)
- [OWASP WSTG v4.2](https://owasp.org/www-project-web-security-testing-guide/)
- [OWASP Risk Rating Methodology](https://owasp.org/www-community/OWASP_Risk_Rating_Methodology)
- [Burp Collaborator Documentation](https://portswigger.net/burp/documentation/collaborator)
