# Autowasp User Guide

Welcome to the Autowasp User Guide. This document provides detailed instructions on how to use the extension effectively within your penetration testing workflow.

## Overview

A general testing workflow using Autowasp includes the following steps:

1. Display the OWASP checklist in Autowasp for reference.
2. Add the target URL to **Scope**. The scope function will extract related results from Burp Scanner and listen for insecure web request and responses.
3. Map the scan issues to specific test cases in the checklist. OR
4. Manually explore the website's pages, then click **Enable Burp Scanner Logging** to display the scanner issues under the **Logger** tab.
5. Map findings to the checklist.
6. Insert security observations and evidence associated with the logs.
7. Generate a report containing the checklist, logs, evidence, and comments.

## Detailed Workflow

### 1. Displaying the Testing Checklist

1. Click the **Load WSTG v4.2 Checklist** button to load the bundled checklist data.
2. The checklist will load almost instantly and is available offline.

![Load Checklist](../images/uploadChecklist.gif)

#### Excluding Checklist item(s)

- If you find test cases that do not apply to your test, you can exclude these items by selecting the checkbox on the right.

### 2. Adding to scope and scanning

1. Add the target URL to scope and perform scan.

![Add Target Scope](../images/addTargetScope.gif)

1. Manually explore the website's pages, then click **Enable Burp Scanner Logging** to display the scanner issues under the **Logger** tab.

![Scanner Logic](../images/scannerLogic.gif)

1. Note that items from **Proxy -> HTTP History**, **Intruder** & **Repeater** tabs can be sent to Autowasp by right-clicking on them, followed by clicking **Send to Autowasp**.

![Send from Proxy](../images/SendfromProxy.gif)

### 3. Mapping findings to the checklist

- Click on a specific log in the **Logger** table.
- Click on the empty **Mapped to OWASP WSTG** field on the right side of the table entry.
- Choose a specific test to map the log to using the drop-down list.
- Note that this will only work if you have the checklist already displayed.

![Map to Checklist](../images/mapToCheckList.gif)

### 4. Insert security observations and evidence associated with the logs

1. Click on a specific log in the **Logger** table.
2. On the lowest row of tabs, click on either **Pen Tester Comments** or **Evidence**.
3. Enter what you wish to note down, then click **Save Comments** or **Save Evidence**.

![Write Comments](../images/writeComments.gif)

### 5. Report Generation

1. Click on **Generate Excel File** and choose a location to save the file to.
2. Open the excel file and check that the observation, comments, and evidence have been saved beside the associated test case.
3. You can also find the URL pointing to the full article hosted on OWASP's GitHub repository for every test case in the checklist.

![Generate Report](../images/generateReport.gif)
