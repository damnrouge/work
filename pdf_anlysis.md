---
title: PDF Malware Analysis Notes
description: A comprehensive reference guide for analyzing malicious PDFs.
---

# PDF Malware Analysis Notes



# PDF Malware Analysis Notes

---

## Table of Contents

1. [PDF File Structure](#pdf-file-structure)
2. [PDF Objects](#pdf-objects)
3. [Commonly Abused PDF Keywords](#commonly-abused-pdf-keywords)
4. [String and Data Encoding Techniques](#string-and-data-encoding-techniques)
5. [Obfuscation Techniques in Malicious PDFs](#obfuscation-techniques-in-malicious-pdfs)
6. [PDF Analysis Tools Overview](#pdf-analysis-tools-overview)
7. [Tool Usage and Analysis Scenarios](#tool-usage-and-analysis-scenarios)  
   - [PDFiD](#pdfid)
   - [PDF-Parser](#pdf-parser)
   - [Peepdf](#peepdf)

---

## PDF File Structure

A PDF file follows a standard logical structure that attackers can manipulate to embed malicious content.

### Components:

| Component        | Description                                                                 |
|------------------|-----------------------------------------------------------------------------|
| **Header**       | Starts with `%PDF-x.y`, declares PDF version.                              |
| **Body**         | Contains all PDF objects (text, images, scripts, etc.).                    |
| **Cross-Reference Table (xref)** | Maps object numbers to file offsets. Required for PDF parsing. |
| **Trailer**      | Points to the start of the xref table and root object (catalog).           |

### Relevance to Malware Analysis:
- Malicious objects are embedded in the **Body**.
- Obfuscation or corruption may occur in the **xref** or **trailer** to evade detection.
- **Header tampering** can help identify malformed or suspicious PDFs.

---

## PDF Objects

PDFs are composed of **indirect objects**, each with a type and value. These are often exploited in malware.

### Common Object Types:

| Type        | Description                                      | Malware Relevance                               |
|-------------|--------------------------------------------------|--------------------------------------------------|
| **Dictionary** | Key-value pairs enclosed in `<< >>`.             | Used to define metadata, actions, and streams.   |
| **Stream**   | Binary data between `stream` and `endstream`.    | Often contains compressed or encoded malicious payloads. |
| **Array**    | Ordered lists enclosed in `[ ]`.                 | Can reference multiple objects or actions.       |
| **Name**     | Begins with `/`, identifies dictionary keys.     | Keywords like `/JS`, `/JavaScript`, `/OpenAction`. |

---

## Commonly Abused PDF Keywords

Malware authors use specific PDF keywords to trigger malicious behavior.

| Keyword         | Purpose                                           | Malicious Use Case                               |
|------------------|---------------------------------------------------|--------------------------------------------------|
| **/OpenAction**  | Defines actions when the PDF opens.               | Launch JavaScript payload on open.              |
| **/AA**          | Additional actions like page open/close.          | Trigger code execution on events.               |
| **/JS**          | JavaScript object.                                | Contains malicious JavaScript.                  |
| **/JavaScript**  | Alternate JavaScript keyword.                     | Same as `/JS`, may be used for evasion.         |
| **/Launch**      | Launches external apps or commands.               | Executes shell commands or opens URLs.          |
| **/URI**         | Uniform Resource Identifier.                      | Redirects victims to malicious websites.        |
| **/EmbeddedFile**| Embeds files within the PDF.                      | Drops malware payloads.                         |
| **/ObjStm**      | Object stream.                                    | Used to hide malicious objects.                 |

---

## String and Data Encoding Techniques

Malicious payloads are often encoded to evade detection.

| Encoding         | Description                                         | Example Use                                     |
|------------------|-----------------------------------------------------|-------------------------------------------------|
| **ASCIIHexDecode**| Encodes data in hexadecimal (0-9, A-F).             | Obfuscates JavaScript payload.                  |
| **FlateDecode**   | zlib compression.                                   | Compresses and hides payloads in streams.       |
| **RunLengthDecode**| Simple run-length encoding.                        | Rare, but occasionally used for simple obfuscation. |

**Example:**
```pdf
<</Length 123 /Filter /FlateDecode>>  
stream  
...compressed JavaScript...  
endstream
```

---

## Obfuscation Techniques in Malicious PDFs

Attackers use several methods to bypass detection:

### Obfuscation Techniques:

- **Name Obfuscation**: Using `/JS` instead of `/JS`.
- **Stream Obfuscation**: Compressing and encoding streams using FlateDecode or custom encoders.
- **JavaScript Obfuscation**: String concatenation, hex encoding, or packed scripts.
- **Embedded Files**: Using `/EmbeddedFile` and `/Launch` to drop and run executables.
- **Object Stream Usage**: Storing malicious objects in `/ObjStm` to prevent static detection.

---

## PDF Analysis Tools Overview

| Tool       | Purpose                                    | Key Features                                     |
|------------|--------------------------------------------|--------------------------------------------------|
| **PDFiD**   | Quickly scan for suspicious keywords.       | Identifies JS, OpenAction, Launch, etc.          |
| **PDF-Parser** | Extract and inspect PDF objects.           | Decode streams, search keywords, dump objects.   |
| **Peepdf**  | Interactive PDF analysis framework.         | Supports scripting, decoding, and obfuscation handling. |

---

## Tool Usage and Analysis Scenarios

---

### PDFiD

#### Purpose:
Identify suspicious keywords and structure in a PDF.

#### Basic Syntax:
```bash
pdfid.py malicious.pdf
```

#### Example 1: Detect JavaScript and OpenAction
```bash
pdfid.py suspicious.pdf
```

**Output:**
```
/JS: 2
/OpenAction: 1
/JavaScript: 1
/Launch: 0
```

**Significance:** Indicates likely embedded JavaScript triggered on open.

---

### PDF-Parser

#### Purpose:
Extract and analyze specific PDF objects and streams.

#### Basic Syntax:
```bash
pdf-parser.py -i malicious.pdf
```

#### Example 1: List All Objects
```bash
pdf-parser.py malicious.pdf
```

#### Example 2: Search for JavaScript
```bash
pdf-parser.py -s "/JavaScript" malicious.pdf
```

#### Example 3: Dump a Suspicious Object
```bash
pdf-parser.py -o 5 -d -f malicious.pdf
```

**Significance:** Enables deep inspection of encoded payloads.

---

### Peepdf

#### Purpose:
Advanced PDF analysis with interactive shell.

#### Launch Shell:
```bash
peepdf.py -i malicious.pdf
```

#### Example 1: Analyze Suspicious Object
```bash
> info 8
> stream 8
```

#### Example 2: Decode and Beautify JavaScript
```bash
> js_beautify object8
```

**Significance:** Allows full exploration of obfuscated or embedded scripts.

---

## Visual Aid: PDF Logical Structure

```plaintext
%PDF-1.7
|
|-- Header
|-- Body
|    |-- Obj 1: Catalog
|    |-- Obj 2: Pages
|    |-- Obj 3: Page
|    |-- Obj 4: JavaScript (malicious)
|-- xref
|-- trailer
     |-- Root: Obj 1
```

---

## Summary: Analyst Workflow for PDF Malware

1. **Initial Triage**: Use `pdfid.py` to flag suspicious keywords.
2. **Targeted Analysis**: Use `pdf-parser.py` to isolate and decode objects.
3. **Full Inspection**: Use `peepdf.py` for in-depth stream and JS analysis.
4. **Decode and Deobfuscate**: Identify filters, decode content, extract indicators.
5. **Document Findings**: Record IOC paths, payloads, JS execution triggers.
