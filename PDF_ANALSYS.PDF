Resources: https://prtksec.github.io/posts/MA_PDF_Notes/

PDF File Structure:
- Header:
    - The PDF file starts with a header containing a magic number (as a readable string) and the version of the format.
    - For example: %PDF-1.7 indicates a PDF version 1.7.
    - The header is organized using ASCII characters.
- Body (Objects):
    - The body of the PDF file contains the actual content, including pages, graphical elements, fonts, annotations, and other data.
    - All content is encoded as a series of objects.
    - Each object has a unique object number and generation number.
    - Objects can represent text, images, fonts, annotations, and more.
- Cross-Reference Table (XRef):
    - The cross-reference table (XRef) lists the position of each object within the file.
    - It facilitates random access to objects.
    - The XRef table provides information about the byte offset of each object in the file.
    - This allows efficient seeking and retrieval of specific objects.
- Trailer Dictionary:
    - The trailer dictionary resides in the file's trailer section (usually at the end of the file).
    - It contains entries that allow the cross-reference table to be read.
    - Key entries in the trailer dictionary include:
        - /Size: Total number of entries in the cross-reference table (usually equal to the number of objects plus one).
        - /Root: An indirect reference to the document catalog (the root of the PDF structure).
        - /Info: An indirect reference to the document information dictionary.
        - /ID: An array of two strings that uniquely identifies the file within a workflow.
- Document Information Dictionary:
    - The document information dictionary contains metadata about the PDF file.
    - Entries within this dictionary include:
        - /Title: The document's title (not necessarily the title displayed on the first page).
        - /Subject: Subject of the document (arbitrary metadata).
        - /Keywords: Keywords associated with the document.
        - /Author: Name of the document's author.
        - /CreationDate: Date when the document was created.
        - /ModDate: Date when the document was last modified.
        - /Creator: Name of the program that originally created the document.
        - /Producer: Name of the program that converted the file to PDF.

Malware analyst POV

Header:
The PDF file begins with a header that contains information about the PDF version (e.g., %PDF-1.7).
As a malware analyst, pay attention to any anomalies in the header, such as unexpected versions or additional headers.
Body (Objects):
The body of the PDF file consists of a series of objects that define the operations performed by the file.
These objects can include text, images, fonts, and scripting code (usually JavaScript).
Malicious PDFs often hide their payload within these objects, so scrutinize them carefully.
Cross-Reference (XRef) Table:
The XRef table lists the byte offsets of each object within the file.
It helps the PDF viewer render the objects correctly.
For malware analysis, focus on identifying any irregularities in the XRef table, such as missing or duplicated entries.
Trailer:
The trailer is a special object within the PDF structure.
It describes essential information, including the first object to be rendered by the PDF viewer (usually identified by the name object /Root).
As a malware analyst, examine the trailer for any unexpected values or references.


Cross ref:
- Object IDs (Indirect References):
    - In a PDF document, object IDs (or indirect references) play a crucial role in linking different objects together.
    - Each object in a PDF can be labeled as an indirect object, giving it a unique identifier.
    - An indirect object is represented using the keywords obj and endobj.
    - The format of an indirect reference is as follows:

<object_number> <generation_number> obj

        - <object_number>: A unique number assigned to the object.
        - <generation_number>: Typically starts at 0 and increments when an object is updated.
    - Indirect references allow one object to refer to another by specifying its object ID.
    - For example, if object A refers to object B, it does so using an indirect reference like B 0 R.
- Versioning:
    - The PDF format has evolved over time, resulting in different versions.
    - The version of a PDF document is specified in the header (e.g., %PDF-1.7 for PDF version 1.7).
    - Newer versions may introduce additional features, security enhancements, or changes to the structure.
    - Malware authors may exploit specific vulnerabilities associated with older PDF versions (e.g., outdated parsers).
- Example (Malware Analysis):
    - Imagine a malicious PDF file that exploits a vulnerability in Adobe Acrobat Reader.
    - Let's say the attacker crafts the PDF with an embedded JavaScript payload.
    - The payload is obfuscated and contains shellcode.
    - Here's how the objects relate:
        - Object A (the main document catalog) contains references to other objects, including the JavaScript stream (Object B).
        - Object B (the JavaScript stream) contains the obfuscated shellcode.
        - The shellcode (malicious payload) aims to exploit a vulnerability in the PDF viewer (e.g., CVE-2007-5659).
        - The shellcode may use API calls like WriteFile and WinExec to execute arbitrary code on the victim's system.

ACTION / KEYWORDS:
- /openAction or /AA
    - Purpose: Triggers actions when the PDF is opened.
    - Malicious Example: Automatically executing a script to install malware upon document opening.
- /javascript or /JS
    - Purpose: Contains JavaScript code within the PDF.
    - Malicious Example: Running a script that exploits a vulnerability in the PDF reader.
- /Names
    - Purpose: Stores named destinations or scripts.
    - Malicious Example: Hiding a malicious script under a benign name.
- /EmbeddedFile
    - Purpose: Indicates a file is embedded within the PDF.
    - Malicious Example: An executable malware file that runs when a user interacts with the PDF.
- /URI or /submit form
    - Purpose: Links to external resources or submits form data.
    - Malicious Example: Sending collected data to an attacker's server or redirecting to a phishing site.
- /launch
    - Purpose: Launches applications or opens documents.
    - Malicious Example: Executing a malware executable hidden within the PDF

FILTERS:
- /ASCIIHexDecode
    - Purpose: Converts hexadecimal-encoded data into binary.
    - Malicious Use: Malware can use this filter to hide its code in hexadecimal form, which is less conspicuous.
- /ASCII85Decode
    - Purpose: Transforms ASCII85-encoded data into binary.
    - Malicious Use: This encoding is more compact than hexadecimal, allowing malware to embed more complex code in a smaller space.
- /LZWDecode
    - Purpose: Decompresses data encoded using LZW compression.
    - Malicious Use: Malware can use LZW compression to make the code smaller and harder to detect.
- /FlateDecode
    - Purpose: Decompresses data encoded using the zlib/deflate compression method.
    - Malicious Use: It's a commonly used filter that malware can use to compress its code, making analysis more difficult.
- /RunLengthDecode
    - Purpose: Decompresses data encoded using run-length encoding.
    - Malicious Use: This filter can be used by malware to simplify the representation of repetitive data, which can help in hiding the code.
- /CCITTFaxDecode
    - Purpose: Decodes data that has been encoded using CCITT Group 3 or Group 4 compression.
    - Malicious Use: This is typically used for image data but can be repurposed by malware to encode non-image data.
- /JBIG2Decode
    - Purpose: Decompresses data encoded using the JBIG2 standard, which is typically used for monochrome images.
    - Malicious Use: Malware can use this for complex obfuscation of code, as it's designed for high compression ratios.
- /DCTDecode
    - Purpose: Decompresses data encoded using the DCT (JPEG) method.
    - Malicious Use: While usually for images, malware can use this to obfuscate code within what appears to be an image.
- /JPXDecode
    - Purpose: Decompresses data encoded using the JPEG2000 standard.
    - Malicious Use: Similar to /DCTDecode, it can be used by malware to hide code within image data.
- /Crypt
    - Purpose: Provides a way for PDF creators to include their own encryption and decryption algorithms.
    - Malicious Use: Malware authors can use custom encryption to make their code unreadable without the proper key.


Tools:
pdfid
pdf-parser (-s for search, -o to go to object)
peepdf  (-i interactive mode)

JAVA CODE OBFUSCATION:
1.Base64 Encoding:
    - Base64 encoding transforms plain text into a different format using a predefined character set. Malware authors encode their malicious JavaScript using Base64 to evade detection.
    - Example:

var encodedPayload = "aGVsbG8gd29ybGQ="; // Encoded string
var decodedPayload = atob(encodedPayload); // Decode the string
console.log(decodedPayload); // Outputs: "hello world"

    - Reference:
2.Invoke-Obfuscation (PowerShell):
    - Invoke-Obfuscation is an open-source PowerShell command and script obfuscator available on GitHub. It provides various obfuscation methods for PowerShell scripts.
    - Usage example:
        - Set your command using SET SCRIPTBLOCK:

Invoke-Obfuscation> set scriptblock Write-Host '(New-Object System.Net.WebClient).DownloadFile("https://secure-tactics.com/", "C:\\temp\\out.txt")'

        - Use menus to select different obfuscation methods, and the encoded output will be printed.
    - GitHub: Invoke-Obfuscation
    - Reference:
3. Whitespace Randomization:
    - Insert random whitespace characters (e.g., space, tab, line feed) into the JavaScript code. This makes it harder to read and analyze.
    - Example:

var obfuscatedCode = "var\x20x\x20=\x20\x31\x20+\x202;";
// Decoded: var x = 1 + 2;

4. Variable and Function Name Mangling:
    - Replace meaningful variable and function names with shorter, meaningless names. This confuses analysts trying to understand the code.
    - Example:

var a = 10;
function b() {
    return a * 2;
}

5. String Encryption:
    - Encrypt strings within the code using custom algorithms or cryptographic libraries. Decrypt them during runtime.
    - Example:

var encryptedString = "encrypted data here";
var decryptedString = customDecrypt(encryptedString);

6. Control Flow Obfuscation:
    - Shuffle the order of statements, use conditional jumps, and insert dead code paths to confuse static analysis tools.
    - Example:

if (Math.random() > 0.5) {
    // Legitimate code path
    // ...
} else {
    // Dead code path
    // ...
}

7. Dynamic Code Generation:
    - Generate JavaScript code dynamically at runtime using eval() or new Function(). This makes static analysis difficult.
    - Example:

var dynamicCode = "console.log('Dynamic code executed!');";
eval(dynamicCode);

8. Anti-Debugging Techniques:
    - Detect if the code is being debugged (e.g., using breakpoints or developer tools) and alter behavior accordingly.
    - Example:

if (window.chrome && window.chrome.devtools) {
    // Debugger detected
    // ...
}

9. Dead Code Insertion:
    - Add irrelevant or unreachable code segments to confuse analysts.
    - Example:

function legitimateFunction() {
    // Legitimate code
    // ...
}
function deadCode() {
    // Irrelevant code
    // ...
}

-10.Obfuscated Shellcode:
    - In malware targeting specific platforms, obfuscate shellcode (machine code) to avoid signature-based detection.
    - Example (for Windows):

var shellcode = "\x90\x90\x90\x90\x90"; // Obfuscated shellcode


