PDF Malware Analysis Notes
This document serves as a concise, self-contained reference for PDF malware analysis, covering essential concepts, tools, and techniques for malware analysts. It is organized for quick navigation and practical use, with examples grounded in realistic scenarios.
1. PDF Structure
A PDF file is structured into four main components, each critical for malware analysis due to their potential to hide malicious content:

Header: Defines the PDF version (e.g., %PDF-1.4). Malicious PDFs may use non-standard headers to evade detection.
Body: Contains PDF objects (e.g., text, images, scripts) that form the document’s content. Malware often resides in objects like JavaScript or embedded files.
Cross-Reference Table (xref): Maps object locations for quick access. Manipulated xref tables can obscure malicious objects.
Trailer: Specifies the location of the xref table and root object. Malicious trailers may point to hidden objects.

Relevance to Malware Analysis:

Malicious code is often embedded in the body’s objects (e.g., JavaScript streams).
Obfuscated xref or trailer entries can hide malicious objects from basic parsers.

Visual Aid: PDF Structure Diagram
{
  "type": "line",
  "data": {
    "labels": ["Header", "Body", "Cross-Reference Table", "Trailer"],
    "datasets": [{
      "label": "PDF File Structure",
      "data": [1, 2, 3, 4],
      "borderColor": "#4CAF50",
      "fill": false,
      "pointRadius": 5,
      "pointBackgroundColor": "#4CAF50"
    }]
  },
  "options": {
    "scales": {
      "y": {
        "display": false
      },
      "x": {
        "title": {
          "display": true,
          "text": "PDF File Components"
        }
      }
    },
    "plugins": {
      "title": {
        "display": true,
        "text": "PDF File Structure Flow"
      }
    }
  }
}

2. PDF Objects
PDF objects are the building blocks of a PDF file, and malware often exploits them to embed malicious content. Common object types include:

Dictionary: Key-value pairs (e.g., /Type /Page) that define object properties. Used to reference malicious scripts or actions.
Stream: Binary data (e.g., images, JavaScript). Malware often hides in encoded streams.
Array: Ordered collections of objects. Can reference malicious objects indirectly.
Name: Strings prefixed with / (e.g., /JS). Used to trigger malicious actions.
String: Text data, often encoded to hide malicious payloads.

Malware Usage:

JavaScript code in streams (e.g., /JS or /JavaScript) can execute malicious actions.
Embedded files in streams can deliver malware payloads (e.g., executables).

3. PDF Keywords
Certain PDF keywords are commonly exploited in malware due to their ability to trigger actions or embed content:



Keyword
Description
Malware Significance



/JS, /JavaScript
References JavaScript code
Executes malicious scripts on document open


/OpenAction
Specifies an action to perform when the PDF opens
Triggers malware without user interaction


/ObjStm
Defines an object stream
Hides multiple objects in a compressed stream


/EmbeddedFile
Embeds external files
Delivers malicious payloads (e.g., EXEs)


/AA
Additional actions (e.g., on page open/close)
Executes scripts during user interactions


Malware Relevance: These keywords are often used to initiate malicious behavior, such as executing scripts or extracting embedded files.
4. PDF Tools
Several tools are designed for PDF malware analysis, each with specific capabilities:

PDFiD: Scans PDFs for suspicious keywords and structures to identify potential malice.
PDF-Parser: Parses PDF objects and streams to reveal hidden content or scripts.
Peepdf: Analyzes and modifies PDF structures, with a focus on JavaScript and embedded files.
Origami: A framework for parsing and manipulating PDFs, useful for advanced analysis.
QPDF: Decrypts and transforms PDFs, aiding in stream extraction.

Purpose: These tools help analysts detect, dissect, and analyze malicious content in PDFs.
5. String and Data Encoding in PDF Malware
Malware authors use encoding to hide malicious content in PDFs. Common techniques include:

ASCIIHexDecode: Encodes binary data as hexadecimal strings (e.g., <48656C6C6F> for "Hello").
FlateDecode: Compresses streams using zlib, often hiding JavaScript or payloads.
RunLengthDecode: Compresses repetitive data, used in streams to obscure content.
Embedded Fonts: Custom fonts can hide encoded data in font streams.

Example:

A malicious JavaScript stream encoded with FlateDecode might appear as compressed gibberish but decode to executable code.

Malware Application: Encoded streams evade signature-based detection and require decoding for analysis.
6. Obfuscation Techniques
Obfuscation makes malicious PDFs harder to detect. Common methods include:

Name Obfuscation: Using non-standard or encoded names (e.g., /J#53 instead of /JS) to hide keywords.
JavaScript Obfuscation: Minifying or encoding JavaScript (e.g., using eval() to execute dynamically generated code).
Embedded Files: Hiding malicious payloads in /EmbeddedFile streams.
Stream Compression: Using multiple encoding layers (e.g., FlateDecode + ASCIIHexDecode) to obscure content.
Object Stream Hiding: Storing malicious objects in /ObjStm to reduce visibility.

Role in Evasion: These techniques bypass static analysis tools and require dynamic or manual analysis.
7. PDF Analysis Tools: Detailed Analysis
PDFiD
Purpose: Scans PDFs for suspicious keywords and structures to flag potential malware.Key Options:

-s: Outputs statistics (e.g., keyword counts).
-f: Forces analysis of non-PDF files.
-e: Extra information (e.g., entropy of streams).

Use Case 1: Detecting Embedded JavaScript

Scenario: A PDF is suspected to contain malicious JavaScript triggered on open.
Command:pdfid.py -s suspicious.pdf


Explanation: The -s flag counts keywords like /JS or /OpenAction.
Outcome: Output shows /JS 1, /OpenAction 1, indicating potential malice. High entropy in streams suggests obfuscation.

Use Case 2: Checking for Embedded Files

Scenario: Verify if a PDF contains embedded executables.
Command:pdfid.py -e suspicious.pdf


Explanation: The -e flag provides entropy and keyword details.
Outcome: Reports /EmbeddedFile 1 and high stream entropy, flagging further investigation.

PDF-Parser
Purpose: Parses PDF objects and decodes streams to reveal hidden content.Key Options:

-a: Displays all objects.
-f: Applies filters to decode streams.
-o <obj>: Analyzes a specific object.

Use Case 1: Extracting JavaScript

Scenario: A PDF contains a suspected malicious JavaScript stream.
Command:pdf-parser.py -f -o 10 suspicious.pdf


Explanation: Targets object 10 (identified via PDFiD) and decodes its stream (-f).
Outcome: Decoded JavaScript reveals a malicious URL or shellcode.

Use Case 2: Analyzing Object Streams

Scenario: A PDF uses /ObjStm to hide objects.
Command:pdf-parser.py -a suspicious.pdf | grep ObjStm


Explanation: Lists objects containing /ObjStm for further inspection.
Outcome: Identifies object numbers in /ObjStm, guiding targeted analysis.

Peepdf
Purpose: Analyzes and modifies PDFs, with strong JavaScript and interactive analysis capabilities.Key Options:

-i: Interactive mode for manual exploration.
-s <script>: Executes a script for automated analysis.
-f: Forces parsing of broken PDFs.

Use Case 1: Analyzing OpenAction Scripts

Scenario: A PDF executes a script on open.
Command:peepdf.py -i suspicious.pdf

In interactive mode: search /OpenAction
Explanation: Searches for /OpenAction and inspects linked objects.
Outcome: Reveals a JavaScript object (e.g., obj 5) with malicious code.

Use Case 2: Decoding Obfuscated Streams

Scenario: A stream is encoded with FlateDecode and contains hidden malware.
Command:peepdf.py -f suspicious.pdf

In interactive mode: stream 7 > decoded.txt
Explanation: Decodes stream in object 7 and saves it.
Outcome: Decoded stream reveals an executable or malicious script.

Visual Aid: Tool Comparison Table



Tool
Strengths
Common Use Cases



PDFiD
Quick keyword detection
Initial triage, flagging suspicious PDFs


PDF-Parser
Detailed object/stream parsing
Extracting scripts, decoding streams


Peepdf
Interactive analysis, JS execution
Deep analysis, script deobfuscation


Conclusion
These notes provide a comprehensive reference for PDF malware analysis, covering structure, objects, keywords, tools, encoding, and obfuscation techniques. The detailed tool examples and visual aids ensure practical applicability for analysts. For further exploration, refer to tool documentation or analyze real-world PDF samples.
