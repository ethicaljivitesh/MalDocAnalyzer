# MalDocAnalyzer
MalDoc Analyzer Pro — Malware Document Analysis &amp; IOC Extraction Tool. Open-source malware document analyzer for security researchers. Detects malicious macros, embedded scripts, obfuscated payloads, and IOCs in PDF, Office, and script files  

MalDoc Analyzer Pro is a free, open-source desktop application for malware document analysis, built for security researchers, incident responders, SOC analysts, and digital forensics professionals.
It analyzes suspicious files — PDFs, Microsoft Office documents, scripts, and archives — and automatically extracts malicious content without requiring any external sandbox or internet connection.

[![Download](https://drive.google.com/file/d/1qbTr2nXIbTFg9bNzMZtXor2CEFZCRLJh/view?usp=sharing)](https://github.com/username/repository) 

What It Detects

VBA Macros — AutoOpen, AutoExec, Workbook_Open triggers with risk scoring
Embedded JavaScript in PDF files (/JS, /JavaScript, /OpenAction, /Launch)
DDE (Dynamic Data Exchange) injection in Office documents
Obfuscated payloads — Base64, hex-encoded shellcode, Chr() concatenation, PowerShell -EncodedCommand, ROT13, URL encoding
Macro indicators — Shell, CreateObject, WScript.Shell, ADODB.Stream, Environ()
Suspicious PDF objects — /EmbeddedFile, /RichMedia, /XObject, /ObjStm, /AcroForm
ActiveX / OLE objects embedded in Office files
External links and remote template injection in OOXML documents

Supported File Types
FormatAnalysisPDFStructure, streams, JavaScript, embedded filesDOC / XLS / PPT (OLE)VBA macros, OLE streams, DDEDOCX / XLSX / PPTX (OOXML)Macros, XML parts, external links, embedded objectsDOCM / XLSM / PPTMMacro-enabled Office formatsPS1 / VBS / JS / HTA / WSFScript deobfuscation and IOC extractionBAT / CMD / PY / RB / SHCommand and script analysisZIP / JARArchive inspection, suspicious file detection
