# Autowasp Burp Extension Architecture

This document describes the architecture and design of Autowasp, a Burp Suite extension that integrates issue logging with the OWASP Web Security Testing Guide (WSTG).

## Overview

Autowasp is an extension for Burp Suite Professional that provides:

- **Testing Checklist**: OWASP WSTG guide for penetration testing
- **Logger Tool**: Consolidation and logging of Burp Scanner issues
- **Report Generation**: Generate Excel reports from security findings

![Autowasp Main Interface](./images/Autowasp1.png)

---

## Main Class/Package Diagram

The following diagram shows the main class structure and relationships between components:

```mermaid
classDiagram
    direction TB
    
    class BurpExtender {
        +main(String[] args)
    }
    
    class Autowasp {
        +IBurpExtenderCallbacks callbacks
        +IExtensionHelpers helpers
        +TrafficLogic trafficLogic
        +ScannerLogic scannerLogic
        +ChecklistLogic checklistLogic
        +ExtenderPanelUI extenderPanelUI
        +ProjectWorkspaceFactory projectWorkspace
        +registerExtenderCallbacks()
        +newScanIssue()
        +processProxyMessage()
    }
    
    class ExtenderPanelUI {
        +run()
        -buildChecklistPanel()
        -buildLoggerPanel()
    }
    
    class ChecklistLogic {
        +fetchWSTGChecklist()
        +loadLocalChecklist()
        +parseChecklistEntry()
    }
    
    class ChecklistTable {
        +ChecklistTableModel model
    }
    
    class ScannerLogic {
        +logNewScan()
        +logNewInstance()
        +getRepeatedIssue()
    }
    
    class TrafficLogic {
        +classifyTraffic()
        +logTrafficEntry()
    }
    
    class LoggerTable {
        +LoggerTableModel model
    }
    
    class InstanceTable {
        +InstancesTableModel model
    }
    
    class ProjectWorkspaceFactory {
        +saveProject()
        +loadProject()
    }
    
    class ContextMenuFactory {
        +createMenuItems()
    }
    
    BurpExtender --|> Autowasp : extends
    Autowasp --> ExtenderPanelUI : creates
    Autowasp --> ChecklistLogic : uses
    Autowasp --> ScannerLogic : uses
    Autowasp --> TrafficLogic : uses
    Autowasp --> ProjectWorkspaceFactory : uses
    Autowasp --> ContextMenuFactory : registers
    
    ExtenderPanelUI --> ChecklistTable : displays
    ExtenderPanelUI --> LoggerTable : displays
    ExtenderPanelUI --> InstanceTable : displays
    
    ChecklistLogic --> ChecklistTable : populates
    ScannerLogic --> LoggerTable : populates
    ScannerLogic --> InstanceTable : populates
    TrafficLogic --> LoggerTable : populates
```

---

## Data Flow Diagram

This diagram shows how data flows from Burp Suite through the Autowasp extension:

```mermaid
flowchart TB
    subgraph BurpSuite["Burp Suite Professional"]
        Proxy[Proxy History]
        Scanner[Scanner]
        Intruder[Intruder]
        Repeater[Repeater]
    end
    
    subgraph Autowasp["Autowasp Extension"]
        subgraph Input["Input Layer"]
            ContextMenu[ContextMenuFactory<br/>Right-click menu]
            ProxyListener[IProxyListener<br/>processProxyMessage]
            ScannerListener[IScannerListener<br/>newScanIssue]
        end
        
        subgraph Core["Core Logic Layer"]
            TrafficLogic[TrafficLogic<br/>Classify & log traffic]
            ScannerLogic[ScannerLogic<br/>Log scan issues]
            ChecklistLogic[ChecklistLogic<br/>Fetch/Parse WSTG]
        end
        
        subgraph Data["Data Layer"]
            LoggerEntry[LoggerEntry<br/>Issue record]
            InstanceEntry[InstanceEntry<br/>Issue instance]
            ChecklistEntry[ChecklistEntry<br/>WSTG test case]
            TrafficEntry[TrafficEntry<br/>HTTP traffic]
        end
        
        subgraph UI["UI Layer"]
            ExtenderPanelUI[ExtenderPanelUI<br/>Main UI Panel]
            ChecklistTable[ChecklistTable<br/>WSTG Checklist]
            LoggerTable[LoggerTable<br/>Issues List]
            InstanceTable[InstanceTable<br/>Issue Instances]
        end
        
        subgraph Output["Output Layer"]
            ProjectWorkspace[ProjectWorkspaceFactory<br/>Save/Load State]
            ExcelReport[Excel Report<br/>Apache POI]
        end
    end
    
    subgraph External["External Resources"]
        WSTG[OWASP WSTG GitHub]
        LocalWSTG[Local WSTG Cache]
    end
    
    Proxy --> ProxyListener
    Scanner --> ScannerListener
    Intruder --> ContextMenu
    Repeater --> ContextMenu
    
    ProxyListener --> TrafficLogic
    ScannerListener --> ScannerLogic
    ContextMenu --> ScannerLogic
    
    TrafficLogic --> TrafficEntry
    ScannerLogic --> LoggerEntry
    ScannerLogic --> InstanceEntry
    ChecklistLogic --> ChecklistEntry
    
    WSTG --> ChecklistLogic
    LocalWSTG --> ChecklistLogic
    
    LoggerEntry --> LoggerTable
    InstanceEntry --> InstanceTable
    ChecklistEntry --> ChecklistTable
    TrafficEntry --> LoggerTable
    
    ExtenderPanelUI --> ChecklistTable
    ExtenderPanelUI --> LoggerTable
    ExtenderPanelUI --> InstanceTable
    
    LoggerTable --> ExcelReport
    ChecklistTable --> ExcelReport
    InstanceTable --> ExcelReport
    
    ExtenderPanelUI --> ProjectWorkspace
```

---

## Architecture Components

### 1. Entry Point

- **BurpExtender**: Main class that extends Autowasp and serves as the entry point for the Burp extension

### 2. Core Class (Autowasp)

Implements Burp Suite interfaces:

- `IBurpExtenderCallbacks`: Callbacks to Burp Suite
- `IExtensionHelpers`: Helper utilities
- `IScannerListener`: Listener for scanner events
- `IProxyListener`: Listener for proxy events

### 3. Logic Layer

| Component          | Description                                                      |
| ------------------ | ---------------------------------------------------------------- |
| **ChecklistLogic** | Fetch and parse OWASP WSTG checklist from GitHub or local cache  |
| **ScannerLogic**   | Manage logging and grouping of scan issues                       |
| **TrafficLogic**   | Classify and log HTTP traffic                                    |

### 4. Data Layer

| Model              | Description                           |
| ------------------ | ------------------------------------- |
| **LoggerEntry**    | Representation of discovered issues   |
| **InstanceEntry**  | Specific instance of an issue         |
| **ChecklistEntry** | Test case from WSTG                   |
| **TrafficEntry**   | HTTP traffic record                   |

### 5. UI Layer

| Component           | Description                           |
| ------------------- | ------------------------------------- |
| **ExtenderPanelUI** | Main panel displayed in Burp tab      |
| **ChecklistTable**  | Table displaying WSTG checklist       |
| **LoggerTable**     | Table displaying discovered issues    |
| **InstanceTable**   | Table displaying instances per issue  |

### 6. Output Layer

- **ProjectWorkspaceFactory**: Save/load project state
- **Excel Report**: Generate reports using Apache POI

---

## Feature and Workflow Diagrams

### Testing Checklist - OWASP WSTG

![OWASP WSTG Checklist](./images/OWASP%20WSTG.PNG)

**Fetch Checklist from OWASP GitHub:**
![Fetch Checklist](./images/fetchChecklist.gif)

**Load Local Checklist:**
![Upload Checklist](./images/uploadChecklist.gif)

---

### Logger Tool

![Logger Tool](./images/Logger%20Tool.PNG)

**Traffic Logging:**
![Traffic Logging](./images/trafficLogging.gif)

**Scanner Logic:**
![Scanner Logic](./images/scannerLogic.gif)

---

### Usage Workflow

**1. Add Target Scope:**
![Add Target Scope](./images/addTargetScope.gif)

**2. Send from Proxy/Intruder/Repeater:**
![Send from Proxy](./images/SendfromProxy.gif)

**3. Map to Checklist:**
![Map to Checklist](./images/mapToCheckList.gif)

**4. Write Comments:**
![Write Comments](./images/writeComments.gif)

**5. Generate Report:**
![Generate Report](./images/generateReport.gif)

---

## Dependencies

| Library                    | Version | Purpose                   |
| -------------------------- | ------- | ------------------------- |
| Apache Commons Collections | 4.3     | Collection utilities      |
| Apache Commons Compress    | 1.18    | Compression support       |
| GSON                       | 2.8.5   | JSON parsing              |
| Jsoup                      | 1.12.1  | HTML parsing (fetch WSTG) |
| Apache POI                 | 4.1.0   | Excel report generation   |
| XMLBeans                   | 3.1.0   | XML support for POI       |
| Burp Extender APIs         | 1.7.13  | Burp Suite integration    |

---

## Source Code Structure

```shell
src/main/java/
├── burp/
│   └── BurpExtender.java          # Entry point
├── autowasp/
│   ├── Autowasp.java              # Core class
│   ├── logic/
│   │   ├── ChecklistLogic.java    # WSTG checklist handling
│   │   ├── ScannerLogic.java      # Scanner issue handling
│   │   └── TrafficLogic.java      # Traffic classification
│   ├── model/
│   │   ├── LoggerEntry.java       # Issue model
│   │   ├── InstanceEntry.java     # Instance model
│   │   ├── ChecklistEntry.java    # Checklist item model
│   │   └── TrafficEntry.java      # Traffic model
│   ├── ui/
│   │   ├── ExtenderPanelUI.java   # Main UI
│   │   ├── ChecklistTable.java    # Checklist display
│   │   ├── LoggerTable.java       # Logger display
│   │   └── InstanceTable.java     # Instance display
│   ├── context/
│   │   └── ContextMenuFactory.java # Right-click menu
│   └── workspace/
│       └── ProjectWorkspaceFactory.java # Save/load state
```

---

## References

- [OWASP Web Security Testing Guide (WSTG)](https://owasp.org/www-project-web-security-testing-guide/)
- [Burp Extender APIs](https://portswigger.net/burp/extender/api/burp/package-summary.html)
- [Repository GitHub Autowasp](https://github.com/govtech-csg/Autowasp)
