<xaiArtifact>
<artifactId>pdf-malware-analysis-notes-v1</artifactId>

# PDF Malware Analysis Notes

## Table of Contents
1. [PDF Structure](#pdf-structure)
2. [PDF Objects](#pdf-objects)
3. [PDF Keywords Exploited in Malware](#pdf-keywords-exploited-in-malware)
4. [String and Data Encoding in PDF Malware](#string-and-data-encoding-in-pdf-malware)
5. [Obfuscation Techniques](#obfuscation-techniques)
6. [PDF Analysis Tools Overview](#pdf-analysis-tools-overview)
7. [Tool Usage Examples](#tool-usage-examples)
   - [PDFiD](#pdfid)
   - [PDF-Parser](#pdf-parser)
   - [Peepdf](#peepdf)

---

## PDF Structure

A PDF file is logically structured into 4 main components:

| Component           | Description                                                                 | Relevance in Malware Analysis                                  |
|---------------------|-----------------------------------------------------------------------------|-----------------------------------------------------------------|
| **Header**          | Contains the version of the PDF specification (e.g., `%PDF-1.5`)           | Indicates format; older versions may lack security controls     |
| **Body**            | Contains objects (e.g., dictionaries, streams)                             | Hosts potentially malicious objects (e.g., JavaScript, files)   |
| **Cross-Reference Table (xref)** | Maps object positions for quick access                             | Can be manipulated to hide malicious objects                    |
| **Trailer**         | Points to the xref and root object of the PDF                              | Key entry point; `/Root` may reference malicious actions        |

### Visual: Basic PDF Structure

