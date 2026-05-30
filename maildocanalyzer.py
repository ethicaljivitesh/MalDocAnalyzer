#!/usr/bin/env python3

import sys
import os
import re
import json
import hashlib
import zipfile
import binascii
import base64
import struct
import string
import traceback
import threading
import datetime
import zlib
from pathlib import Path
from io import BytesIO, StringIO

# ── PyQt5 ──────────────────────────────────────────────────────────────────
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTabWidget, QTreeWidget, QTreeWidgetItem, QTextEdit, QLabel,
    QPushButton, QFileDialog, QProgressBar, QSplitter, QFrame,
    QScrollArea, QGroupBox, QTableWidget, QTableWidgetItem,
    QHeaderView, QStatusBar, QToolBar, QAction, QMessageBox,
    QLineEdit, QComboBox, QCheckBox, QListWidget, QListWidgetItem,
    QDialog, QDialogButtonBox, QSizePolicy, QMenu, QAbstractItemView,
    QPlainTextEdit
)
from PyQt5.QtCore import (
    Qt, QThread, pyqtSignal, QSize, QTimer, QPoint, QRect
)
from PyQt5.QtGui import (
    QFont, QColor, QPalette, QIcon, QPixmap, QPainter, QBrush,
    QPen, QTextCursor, QSyntaxHighlighter, QTextCharFormat,
    QFontDatabase
)

# ── Analysis Libraries ─────────────────────────────────────────────────────
try:
    from pdfminer.high_level import extract_text
    from pdfminer.pdfparser import PDFParser
    from pdfminer.pdfdocument import PDFDocument
    from pdfminer.pdftypes import resolve1, PDFStream
    from pdfminer.pdfpage import PDFPage
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False

try:
    import olefile
    OLEFILE_AVAILABLE = True
except ImportError:
    OLEFILE_AVAILABLE = False

# ── Fix: colorclass crashes in --windowed .exe because sys.stdout
# is None (no console). Patch streams before oletools import so
# colorclass.Windows.enable() never touches a None stream.
import sys as _sys, io as _io
if _sys.stdout is None:
    _sys.stdout = _io.StringIO()
if _sys.stderr is None:
    _sys.stderr = _io.StringIO()

try:
    # Monkey-patch colorclass.Windows.enable before it fires
    try:
        import colorclass.windows as _cw
        _cw.Windows.enable = staticmethod(lambda *a, **k: None)
    except Exception:
        pass

    from oletools.olevba import VBA_Parser, TYPE_OLE, TYPE_OpenXML
    from oletools.msodde import process_file as dde_process
    from oletools import oleobj
    OLETOOLS_AVAILABLE = True
except (ImportError, Exception):
    OLETOOLS_AVAILABLE = False

try:
    from docx import Document as DocxDocument
    DOCX_AVAILABLE = True
except ImportError:
    DOCX_AVAILABLE = False

try:
    import openpyxl
    OPENPYXL_AVAILABLE = True
except ImportError:
    OPENPYXL_AVAILABLE = False

try:
    from pptx import Presentation
    PPTX_AVAILABLE = True
except ImportError:
    PPTX_AVAILABLE = False

# ── Windows XP Color Palette ───────────────────────────────────────────────
XP_COLORS = {
    "title_bar_start":  "#0A246A",
    "title_bar_end":    "#A6CAF0",
    "window_bg":        "#ECE9D8",
    "button_face":      "#ECE9D8",
    "button_shadow":    "#ACA899",
    "button_highlight": "#FFFFFF",
    "button_dark":      "#716F64",
    "border":           "#716F64",
    "selected_bg":      "#316AC5",
    "selected_fg":      "#FFFFFF",
    "text":             "#000000",
    "text_gray":        "#7A7A7A",
    "panel_bg":         "#D4D0C8",
    "group_bg":         "#F5F4EA",
    "alert_red":        "#CC0000",
    "alert_orange":     "#FF6600",
    "alert_yellow":     "#FFCC00",
    "alert_green":      "#006600",
    "tab_active":       "#ECE9D8",
    "tab_inactive":     "#C1BFBA",
    "output_bg":        "#1A1A2E",
    "output_fg":        "#00FF41",
    "output_warn":      "#FF8C00",
    "output_err":       "#FF2222",
    "output_info":      "#00BFFF",
    "output_ioc":       "#FFD700",
}

# ── IOC REGEX PATTERNS ─────────────────────────────────────────────────────
IOC_PATTERNS = {
    "IPv4":             r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b',
    "IPv6":             r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b',
    "Domain":           r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|edu|gov|io|co|info|biz|xyz|top|ru|cn|tk|pw|cc|su|gg|me|tv|de|uk|fr|br|jp|in|au|ca|nz|us|onion)\b',
    "URL":              r'https?://[^\s\'"<>\]]{4,}',
    "Email":            r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b',
    "MD5":              r'\b[0-9a-fA-F]{32}\b',
    "SHA1":             r'\b[0-9a-fA-F]{40}\b',
    "SHA256":           r'\b[0-9a-fA-F]{64}\b',
    "Registry Key":     r'(?:HKEY_|HKLM|HKCU|HKCR|HKU|HKCC)[\\\w\s]+',
    "File Path Win":    r'[A-Za-z]:\\(?:[^\\\/:*?"<>|\r\n]+\\)*[^\\\/:*?"<>|\r\n]*',
    "File Path Unix":   r'(?:/[\w.\-]+){2,}',
    "CVE":              r'CVE-\d{4}-\d{4,7}',
    "Base64 Block":     r'(?:[A-Za-z0-9+/]{20,}={0,2})',
    "Hex Block":        r'\b(?:0x)?[0-9a-fA-F]{8,}\b',
    "Suspicious Cmd":   r'(?:cmd\.exe|powershell|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin|wmic|schtasks|net\s+user|net\s+start|sc\s+create|reg\s+add)[^\n]{0,200}',
    "Shell Invoke":     r'(?:Invoke-Expression|IEX|Invoke-WebRequest|DownloadString|DownloadFile|Start-Process|New-Object|FromBase64String|EncodedCommand|bypass|ExecutionPolicy\s+bypass)[^\n]{0,200}',
}

MALICIOUS_KEYWORDS = [
    # VBA/Macro
    "AutoOpen","AutoExec","AutoClose","Document_Open","Workbook_Open",
    "Shell","CreateObject","WScript.Shell","Scripting.FileSystemObject",
    "ADODB.Stream","PowerShell","cmd.exe","mshta","wscript","cscript",
    "regsvr32","rundll32","certutil","bitsadmin","msiexec",
    # Obfuscation
    "Chr(","ChrW(","Asc(","String(","Replace(","StrReverse(",
    "Hex(","Oct(","CallByName","Execute","Eval","FromBase64String",
    "EncodedCommand","-enc ","-e ","bypass","hidden","windowstyle",
    # Network
    "XMLHttpRequest","WinHttpRequest","InternetExplorer.Application",
    "MSXML2","ServerXMLHTTP","Environ(","GetSpecialFolder",
    "DownloadFile","DownloadString","WebClient","URLDownloadToFile",
    # Persistence
    "HKEY_","HKLM","HKCU","RegWrite","RegRead","schtasks","at.exe",
    "startup","CurrentVersion\\Run",
    # PDF
    "/JavaScript","/JS","/AA","OpenAction","AcroForm","/Launch",
    "/EmbeddedFile","/RichMedia","/XObject","/ObjStm",
    # Shellcode patterns
    "\\x41\\x41","\\x90\\x90","VirtualAlloc","WriteProcessMemory",
    "CreateThread","NtCreateSection","RtlMoveMemory",
]

OBFUSCATION_INDICATORS = [
    r'Chr\s*\(\s*\d+\s*\)',
    r'[A-Za-z]\s*&\s*[A-Za-z]',
    r'"\s*&\s*"',
    r'(?:Replace|Split|Join)\s*\(',
    r'[Ss]tr[Rr]everse\s*\(',
    r'(?:Hex|Oct)\s*\(',
    r'[Ee]ncode[dD][Cc]ommand',
    r'-[Ee][Nn][Cc]',
    r'(?:0x[0-9a-fA-F]{2}\s*[,+]\s*){4,}',
    r'(?:[A-Za-z0-9+/]{4}){8,}={0,2}',
    r'(?:\\x[0-9a-fA-F]{2}){4,}',
    r'(?:Chr|ChrW)\s*\(.*?\)\s*&',
    r'(?:Invoke-Expression|IEX)\s*\(',
    r'(?:\[char\]|\[byte\]|\[int\])\s*\d+',
    r'\$[A-Za-z_]\w*\s*=\s*".*?"\s*;\s*\$',
]

# ═══════════════════════════════════════════════════════════════════════════
#  SYNTAX HIGHLIGHTER
# ═══════════════════════════════════════════════════════════════════════════
class MalwareHighlighter(QSyntaxHighlighter):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.rules = []
        def rule(pattern, color, bold=False, italic=False):
            fmt = QTextCharFormat()
            fmt.setForeground(QColor(color))
            if bold:   fmt.setFontWeight(QFont.Bold)
            if italic: fmt.setFontItalic(True)
            self.rules.append((re.compile(pattern, re.IGNORECASE), fmt))

        rule(r'\b(?:AutoOpen|AutoExec|AutoClose|Document_Open|Workbook_Open)\b', "#FF4444", bold=True)
        rule(r'\b(?:Shell|CreateObject|Execute|Eval|IEX|Invoke-Expression)\b', "#FF6600", bold=True)
        rule(r'\b(?:PowerShell|cmd\.exe|mshta|wscript|cscript|rundll32|regsvr32|certutil)\b', "#FF8C00", bold=True)
        rule(r'\b(?:Chr|ChrW|Asc|StrReverse|Hex|Oct)\b\s*\(', "#FFD700")
        rule(r'(?:https?://|ftp://)[^\s\'\"<>]+', "#00BFFF", bold=True)
        rule(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', "#00FF7F")
        rule(r'(?:[A-Za-z0-9+/]{20,}={0,2})', "#DA70D6")
        rule(r'(?:\\x[0-9a-fA-F]{2}){3,}', "#FF69B4")
        rule(r'\b(?:HKEY_|HKLM|HKCU|HKCR)\b[\\\w]+', "#FFA500")
        rule(r'"[^"]*"', "#98FB98")
        rule(r"'[^']*'", "#98FB98")
        rule(r'\bREM\b.*', "#888888", italic=True)
        rule(r'#.*$', "#888888", italic=True)
        rule(r'//.*$', "#888888", italic=True)
        rule(r'/JavaScript|/JS\b|/AA\b|/OpenAction|/Launch|/EmbeddedFile', "#FF2222", bold=True)
        rule(r'\b(?:CVE-\d{4}-\d{4,7})\b', "#FFD700", bold=True)
        rule(r'\b(?:VirtualAlloc|WriteProcessMemory|CreateThread|NtCreate)\b', "#FF0080", bold=True)

    def highlightBlock(self, text):
        for pattern, fmt in self.rules:
            for m in pattern.finditer(text):
                self.setFormat(m.start(), m.end() - m.start(), fmt)

# ═══════════════════════════════════════════════════════════════════════════
#  DEOBFUSCATION ENGINE
# ═══════════════════════════════════════════════════════════════════════════
class Deobfuscator:
    @staticmethod
    def decode_base64_blocks(text):
        results = []
        pattern = re.compile(r'(?:[A-Za-z0-9+/]{16,}={0,2})')
        for m in pattern.finditer(text):
            b64 = m.group()
            for pad in range(3):
                try:
                    decoded = base64.b64decode(b64 + '=' * pad)
                    try:
                        s = decoded.decode('utf-8')
                    except:
                        try:
                            s = decoded.decode('utf-16-le')
                        except:
                            s = decoded.decode('latin-1', errors='replace')
                    if any(c in s for c in [' ', '\n', '(', ')', ';', '{']):
                        results.append(("base64", m.start(), b64, s.strip()))
                    break
                except:
                    continue
        return results

    @staticmethod
    def decode_hex_blocks(text):
        results = []
        hex_pattern = re.compile(r'(?:(?:0x[0-9a-fA-F]{2}\s*[,+\s]\s*){4,}|(?:\\x[0-9a-fA-F]{2}){4,})')
        for m in hex_pattern.finditer(text):
            raw = m.group()
            hex_chars = re.findall(r'[0-9a-fA-F]{2}', raw)
            try:
                decoded = bytes(int(h, 16) for h in hex_chars)
                try:
                    s = decoded.decode('utf-8')
                except:
                    try:
                        s = decoded.decode('utf-16-le')
                    except:
                        s = repr(decoded)
                results.append(("hex", m.start(), raw[:60]+"...", s))
            except:
                pass
        return results

    @staticmethod
    def decode_chr_concat(text):
        """Decode VBA Chr(nn) & Chr(nn) ... style obfuscation"""
        results = []
        pattern = re.compile(r'(?:Chr[Ww]?\s*\(\s*(\d+)\s*\)\s*&?\s*)+')
        for m in pattern.finditer(text):
            nums = re.findall(r'Chr[Ww]?\s*\(\s*(\d+)\s*\)', m.group())
            if len(nums) >= 3:
                try:
                    decoded = ''.join(chr(int(n)) for n in nums)
                    results.append(("chr_concat", m.start(), m.group()[:60], decoded))
                except:
                    pass
        return results

    @staticmethod
    def decode_powershell_encoded(text):
        results = []
        pattern = re.compile(
            r'-[Ee](?:nc(?:odedCommand)?)?\s+([A-Za-z0-9+/=]+)',
            re.IGNORECASE
        )
        for m in pattern.finditer(text):
            b64 = m.group(1)
            for pad in range(3):
                try:
                    decoded = base64.b64decode(b64 + '=' * pad).decode('utf-16-le', errors='replace')
                    results.append(("ps_encoded", m.start(), b64[:40]+"...", decoded.strip()))
                    break
                except:
                    continue
        return results

    @staticmethod
    def decode_rot13(text):
        import codecs
        results = []
        words = re.findall(r'\b[A-Za-z]{6,}\b', text)
        for w in words[:30]:
            decoded = codecs.decode(w, 'rot13')
            if any(kw in decoded.lower() for kw in ['shell','create','exec','power','script','http']):
                results.append(("rot13", 0, w, decoded))
        return results

    @staticmethod
    def decode_url_encoding(text):
        from urllib.parse import unquote
        results = []
        pattern = re.compile(r'(?:%[0-9a-fA-F]{2}){4,}')
        for m in pattern.finditer(text):
            try:
                decoded = unquote(m.group())
                results.append(("url_encode", m.start(), m.group()[:60], decoded))
            except:
                pass
        return results

    @classmethod
    def full_deobfuscate(cls, text):
        all_results = []
        all_results += cls.decode_base64_blocks(text)
        all_results += cls.decode_hex_blocks(text)
        all_results += cls.decode_chr_concat(text)
        all_results += cls.decode_powershell_encoded(text)
        all_results += cls.decode_rot13(text)
        all_results += cls.decode_url_encoding(text)
        return all_results

# ═══════════════════════════════════════════════════════════════════════════
#  IOC EXTRACTOR
# ═══════════════════════════════════════════════════════════════════════════
class IOCExtractor:
    PRIVATE_RANGES = [
        re.compile(r'^10\.'), re.compile(r'^192\.168\.'),
        re.compile(r'^172\.(?:1[6-9]|2\d|3[01])\.'),
        re.compile(r'^127\.'), re.compile(r'^0\.'),
    ]

    @classmethod
    def extract_all(cls, text):
        iocs = {}
        for ioc_type, pattern in IOC_PATTERNS.items():
            matches = list(set(re.findall(pattern, text)))
            if ioc_type == "IPv4":
                matches = [ip for ip in matches if not any(p.match(ip) for p in cls.PRIVATE_RANGES)]
            if matches:
                iocs[ioc_type] = matches
        return iocs

# ═══════════════════════════════════════════════════════════════════════════
#  FILE ANALYZERS
# ═══════════════════════════════════════════════════════════════════════════
class PDFAnalyzer:
    @staticmethod
    def analyze(filepath):
        results = {
            "metadata": {},
            "objects": [],
            "suspicious": [],
            "scripts": [],
            "embedded": [],
            "streams": [],
            "raw_text": "",
        }
        try:
            with open(filepath, 'rb') as f:
                data = f.read()

            # Version
            m = re.search(rb'%PDF-(\d+\.\d+)', data)
            if m:
                results["metadata"]["pdf_version"] = m.group(1).decode()

            # Object count
            obj_count = len(re.findall(rb'\d+\s+\d+\s+obj', data))
            results["metadata"]["object_count"] = obj_count

            # Suspicious PDF keywords
            suspicious_keys = [
                b'/JavaScript', b'/JS', b'/AA', b'/OpenAction',
                b'/Launch', b'/EmbeddedFile', b'/RichMedia',
                b'/XObject', b'/ObjStm', b'/URI', b'/AcroForm',
                b'/JBIG2Decode', b'/Colors', b'/XFA',
            ]
            for key in suspicious_keys:
                count = data.count(key)
                if count > 0:
                    results["suspicious"].append({
                        "keyword": key.decode(errors='replace'),
                        "count": count,
                        "risk": "HIGH" if key in [b'/JavaScript', b'/JS', b'/Launch', b'/EmbeddedFile'] else "MEDIUM"
                    })

            # Extract streams and look for scripts
            stream_pattern = re.compile(rb'stream\r?\n(.*?)\r?\nendstream', re.DOTALL)
            for i, m in enumerate(stream_pattern.finditer(data)):
                stream_data = m.group(1)
                decoded = None
                # Try zlib inflate
                try:
                    decoded = zlib.decompress(stream_data)
                except:
                    pass
                if not decoded:
                    # Try raw
                    decoded = stream_data

                try:
                    text_content = decoded.decode('latin-1', errors='replace')
                except:
                    text_content = repr(decoded[:200])

                has_script = any(k in text_content for k in ['function(', 'eval(', 'unescape(', 'String.fromCharCode', 'this.exportDataObject'])
                results["streams"].append({
                    "index": i,
                    "size": len(stream_data),
                    "decoded_size": len(decoded) if decoded else 0,
                    "has_script": has_script,
                    "preview": text_content[:300],
                })
                if has_script:
                    results["scripts"].append(text_content[:2000])

            # Extract JS with context
            js_pattern = re.compile(rb'/(?:JavaScript|JS)\s*\((.*?)\)', re.DOTALL)
            for m in js_pattern.finditer(data):
                results["scripts"].append(m.group(1).decode('latin-1', errors='replace'))

            js_dict_pattern = re.compile(rb'/(?:JavaScript|JS)\s*<<.*?>>', re.DOTALL)
            for m in js_dict_pattern.finditer(data[:50000]):
                results["scripts"].append(m.group(0).decode('latin-1', errors='replace'))

            # Extract text
            if PDF_AVAILABLE:
                try:
                    results["raw_text"] = extract_text(filepath)[:5000]
                except:
                    results["raw_text"] = data[:2000].decode('latin-1', errors='replace')

            # Embedded files
            ef_pattern = re.compile(rb'/EmbeddedFile.*?stream\r?\n(.*?)\r?\nendstream', re.DOTALL)
            for m in ef_pattern.finditer(data):
                results["embedded"].append({
                    "size": len(m.group(1)),
                    "preview": m.group(1)[:100].hex()
                })

        except Exception as e:
            results["error"] = str(e)
        return results


class OfficeAnalyzer:
    @staticmethod
    def analyze_vba(filepath):
        results = {
            "macros": [],
            "suspicious_calls": [],
            "dde": [],
            "embedded_objects": [],
            "metadata": {},
        }
        if not OLETOOLS_AVAILABLE:
            results["error"] = "oletools not available"
            return results
        try:
            vba = VBA_Parser(filepath)
            results["metadata"]["has_macros"] = vba.detect_vba_macros()
            if vba.detect_vba_macros():
                for (filename, stream_path, vba_filename, vba_code) in vba.extract_macros():
                    macro_info = {
                        "filename": str(filename),
                        "stream": str(stream_path),
                        "vba_file": str(vba_filename),
                        "code": vba_code,
                        "suspicious": [],
                        "risk_score": 0,
                    }
                    # Check for suspicious keywords
                    for kw in MALICIOUS_KEYWORDS:
                        if kw.lower() in vba_code.lower():
                            macro_info["suspicious"].append(kw)
                            macro_info["risk_score"] += 2
                    # Check obfuscation
                    for pat in OBFUSCATION_INDICATORS:
                        if re.search(pat, vba_code, re.IGNORECASE):
                            macro_info["risk_score"] += 3
                    results["macros"].append(macro_info)

            # Try DDE detection
            try:
                with open(os.devnull, 'w') as devnull:
                    import io, contextlib
                    buf = io.StringIO()
                    with contextlib.redirect_stdout(buf):
                        dde_process(filepath)
                    dde_out = buf.getvalue()
                    if dde_out.strip():
                        results["dde"] = dde_out.strip().split('\n')
            except:
                pass

        except Exception as e:
            results["error"] = str(e)
        return results

    @staticmethod
    def analyze_ooxml(filepath):
        """Analyze OOXML (xlsx, docx, pptx) ZIP structure"""
        results = {
            "content_types": [],
            "relationships": [],
            "external_links": [],
            "embedded_files": [],
            "suspicious": [],
            "xml_content": {},
        }
        try:
            with zipfile.ZipFile(filepath, 'r') as zf:
                namelist = zf.namelist()
                results["file_count"] = len(namelist)

                for name in namelist:
                    results["content_types"].append(name)
                    # Check for suspicious parts
                    if any(s in name.lower() for s in ['vba', 'macro', 'oleobject', 'activex']):
                        results["suspicious"].append({"file": name, "reason": "Potentially executable content"})

                    if name.endswith('.xml') or name.endswith('.rels'):
                        try:
                            content = zf.read(name).decode('utf-8', errors='replace')
                            results["xml_content"][name] = content

                            # Check for external links
                            ext_links = re.findall(r'Target="(https?://[^"]+)"', content)
                            if ext_links:
                                results["external_links"].extend(ext_links)

                            # Check for DDE
                            if 'DDE' in content or 'dde' in content:
                                results["suspicious"].append({"file": name, "reason": "DDE field detected"})

                            # Check for macros
                            if any(k in content for k in ['vbaProject', 'xl/vba', 'ActiveX', 'oleObject']):
                                results["suspicious"].append({"file": name, "reason": "Macro/ActiveX reference"})

                        except:
                            pass

                    elif not name.endswith('/'):
                        results["embedded_files"].append({
                            "name": name,
                            "size": zf.getinfo(name).file_size
                        })

        except Exception as e:
            results["error"] = str(e)
        return results

    @staticmethod
    def analyze_ole(filepath):
        """Analyze OLE compound document"""
        results = {
            "streams": [],
            "metadata": {},
            "suspicious": [],
        }
        if not OLEFILE_AVAILABLE:
            return results
        try:
            ole = olefile.OleFileIO(filepath)
            results["metadata"] = {
                "clsid": str(ole.root.clsid) if ole.root.clsid else "N/A",
                "create_time": str(ole.root.create_time) if ole.root.create_time else "N/A",
                "modify_time": str(ole.root.modify_time) if ole.root.modify_time else "N/A",
            }
            for entry in ole.listdir():
                stream_path = '/'.join(entry)
                try:
                    data = ole.openstream(entry).read()
                    stream_info = {
                        "path": stream_path,
                        "size": len(data),
                        "preview_hex": data[:32].hex(),
                    }
                    # Check for suspicious content
                    text = data.decode('latin-1', errors='replace')
                    suspicious_found = [kw for kw in MALICIOUS_KEYWORDS if kw.lower() in text.lower()]
                    if suspicious_found:
                        stream_info["suspicious_keywords"] = suspicious_found[:10]
                    results["streams"].append(stream_info)
                except:
                    pass
            ole.close()
        except Exception as e:
            results["error"] = str(e)
        return results


class GenericAnalyzer:
    @staticmethod
    def analyze(filepath):
        results = {
            "file_info": {},
            "strings": [],
            "suspicious": [],
            "entropy": 0.0,
        }
        try:
            with open(filepath, 'rb') as f:
                data = f.read()

            results["file_info"] = {
                "size": len(data),
                "md5": hashlib.md5(data).hexdigest(),
                "sha1": hashlib.sha1(data).hexdigest(),
                "sha256": hashlib.sha256(data).hexdigest(),
                "magic": data[:16].hex(),
                "mime_guess": GenericAnalyzer._guess_type(data),
            }

            # Entropy
            results["entropy"] = GenericAnalyzer._entropy(data)

            # Strings extraction
            printable = set(string.printable)
            cur = []
            strings = []
            for byte in data:
                c = chr(byte)
                if c in printable and c not in '\x00\n\r':
                    cur.append(c)
                else:
                    if len(cur) >= 6:
                        strings.append(''.join(cur))
                    cur = []
            if cur and len(cur) >= 6:
                strings.append(''.join(cur))
            results["strings"] = strings[:500]

            # Suspicious strings
            for s in strings:
                for kw in MALICIOUS_KEYWORDS:
                    if kw.lower() in s.lower():
                        results["suspicious"].append({"string": s[:200], "keyword": kw})
                        break

        except Exception as e:
            results["error"] = str(e)
        return results

    @staticmethod
    def _guess_type(data):
        sigs = {
            b'%PDF': 'PDF', b'PK\x03\x04': 'ZIP/OOXML',
            b'\xd0\xcf\x11\xe0': 'OLE/MSOffice', b'MZ': 'PE Executable',
            b'\x7fELF': 'ELF Executable', b'#!': 'Script',
            b'<?xml': 'XML', b'<html': 'HTML',
        }
        for sig, mime in sigs.items():
            if data[:len(sig)] == sig:
                return mime
        try:
            data[:512].decode('utf-8')
            return 'Text/Script'
        except:
            return 'Binary/Unknown'

    @staticmethod
    def _entropy(data):
        if not data:
            return 0.0
        import math
        freq = [0] * 256
        for b in data:
            freq[b] += 1
        ent = 0.0
        n = len(data)
        for f in freq:
            if f > 0:
                p = f / n
                ent -= p * math.log2(p)
        return round(ent, 4)

# ═══════════════════════════════════════════════════════════════════════════
#  WORKER THREAD
# ═══════════════════════════════════════════════════════════════════════════
class AnalysisWorker(QThread):
    progress      = pyqtSignal(int, str)
    log_message   = pyqtSignal(str, str)   # (message, level)
    analysis_done = pyqtSignal(dict)
    error         = pyqtSignal(str)

    def __init__(self, filepath):
        super().__init__()
        self.filepath = filepath

    def run(self):
        try:
            results = {}
            filepath = self.filepath
            ext = Path(filepath).suffix.lower()

            self.log_message.emit(f"[*] Starting analysis: {Path(filepath).name}", "info")
            self.log_message.emit(f"[*] Extension: {ext.upper()}", "info")
            self.progress.emit(5, "Hashing file...")

            # ── Generic analysis (always run) ──────────────────────────────
            gen = GenericAnalyzer.analyze(filepath)
            results["generic"] = gen
            self.log_message.emit(f"[*] File size  : {gen['file_info'].get('size', 0):,} bytes", "info")
            self.log_message.emit(f"[*] MD5        : {gen['file_info'].get('md5','?')}", "info")
            self.log_message.emit(f"[*] SHA1       : {gen['file_info'].get('sha1','?')}", "info")
            self.log_message.emit(f"[*] SHA256     : {gen['file_info'].get('sha256','?')}", "info")
            self.log_message.emit(f"[*] Type       : {gen['file_info'].get('mime_guess','?')}", "info")
            ent = gen.get("entropy", 0)
            ent_flag = " ⚠ HIGH ENTROPY (possible packed/encrypted)" if ent > 7.0 else ""
            self.log_message.emit(f"[*] Entropy    : {ent}{ent_flag}", "warn" if ent > 7.0 else "info")
            self.progress.emit(20, "Generic analysis done...")

            # ── PDF ────────────────────────────────────────────────────────
            if ext == '.pdf':
                self.log_message.emit("[*] Analyzing PDF structure...", "info")
                pdf_results = PDFAnalyzer.analyze(filepath)
                results["pdf"] = pdf_results
                susp_count = len(pdf_results.get("suspicious", []))
                script_count = len(pdf_results.get("scripts", []))
                self.log_message.emit(f"[+] PDF version     : {pdf_results['metadata'].get('pdf_version','?')}", "info")
                self.log_message.emit(f"[+] Object count    : {pdf_results['metadata'].get('object_count',0)}", "info")
                self.log_message.emit(f"[+] Suspicious keys : {susp_count}", "warn" if susp_count else "info")
                self.log_message.emit(f"[+] Embedded scripts: {script_count}", "err" if script_count else "info")
                for s in pdf_results.get("suspicious", []):
                    self.log_message.emit(f"  [!] {s['keyword']} (x{s['count']}) - {s['risk']}", "err" if s["risk"]=="HIGH" else "warn")
                self.progress.emit(50, "PDF analysis done...")

            # ── OLE / Old Office ───────────────────────────────────────────
            elif ext in ('.doc', '.xls', '.ppt', '.msg', '.mdb'):
                self.log_message.emit("[*] Analyzing OLE document...", "info")
                ole_results = OfficeAnalyzer.analyze_ole(filepath)
                vba_results = OfficeAnalyzer.analyze_vba(filepath)
                results["ole"] = ole_results
                results["vba"] = vba_results
                macro_count = len(vba_results.get("macros", []))
                self.log_message.emit(f"[+] Macros found: {macro_count}", "err" if macro_count else "info")
                for mac in vba_results.get("macros", []):
                    risk = mac.get("risk_score", 0)
                    lvl = "CRITICAL" if risk >= 10 else "HIGH" if risk >= 6 else "MEDIUM" if risk >= 3 else "LOW"
                    self.log_message.emit(f"  [!] {mac['vba_file']} - Risk: {lvl} (score={risk})", "err" if risk >= 6 else "warn")
                    for sk in mac.get("suspicious", [])[:5]:
                        self.log_message.emit(f"      Keyword: {sk}", "warn")
                self.progress.emit(60, "OLE analysis done...")

            # ── OOXML (modern Office) ──────────────────────────────────────
            elif ext in ('.docx', '.xlsx', '.pptx', '.docm', '.xlsm', '.pptm', '.xlsb'):
                self.log_message.emit("[*] Analyzing OOXML (ZIP) structure...", "info")
                ooxml_results = OfficeAnalyzer.analyze_ooxml(filepath)
                vba_results = OfficeAnalyzer.analyze_vba(filepath)
                results["ooxml"] = ooxml_results
                results["vba"] = vba_results
                self.log_message.emit(f"[+] Files in archive : {ooxml_results.get('file_count', 0)}", "info")
                self.log_message.emit(f"[+] External links   : {len(ooxml_results.get('external_links', []))}", "warn" if ooxml_results.get('external_links') else "info")
                for link in ooxml_results.get("external_links", []):
                    self.log_message.emit(f"  [!] External link: {link}", "warn")
                for s in ooxml_results.get("suspicious", []):
                    self.log_message.emit(f"  [!] {s['file']} - {s['reason']}", "warn")
                macro_count = len(vba_results.get("macros", []))
                if macro_count:
                    self.log_message.emit(f"  [!!!] VBA MACROS DETECTED: {macro_count}", "err")
                self.progress.emit(60, "OOXML analysis done...")

            # ── Script / Text files ────────────────────────────────────────
            elif ext in ('.ps1', '.vbs', '.js', '.bat', '.cmd', '.py', '.rb', '.sh', '.hta', '.wsf'):
                self.log_message.emit(f"[*] Analyzing script file ({ext})...", "info")
                results["script"] = {}
                try:
                    with open(filepath, 'rb') as f:
                        raw = f.read()
                    try:
                        code = raw.decode('utf-8')
                    except:
                        code = raw.decode('latin-1', errors='replace')
                    results["script"]["code"] = code
                    hits = [kw for kw in MALICIOUS_KEYWORDS if kw.lower() in code.lower()]
                    results["script"]["suspicious_keywords"] = hits
                    obf_hits = [p for p in OBFUSCATION_INDICATORS if re.search(p, code, re.IGNORECASE)]
                    results["script"]["obfuscation_indicators"] = obf_hits
                    self.log_message.emit(f"[+] Suspicious keywords: {len(hits)}", "err" if hits else "info")
                    self.log_message.emit(f"[+] Obfuscation indicators: {len(obf_hits)}", "err" if obf_hits else "info")
                except Exception as e:
                    results["script"]["error"] = str(e)
                self.progress.emit(55, "Script analysis done...")

            # ── ZIP / generic archives ─────────────────────────────────────
            elif ext in ('.zip', '.jar'):
                self.log_message.emit("[*] Analyzing ZIP archive...", "info")
                results["zip"] = {}
                try:
                    with zipfile.ZipFile(filepath, 'r') as zf:
                        names = zf.namelist()
                        results["zip"]["files"] = names
                        results["zip"]["count"] = len(names)
                        self.log_message.emit(f"[+] Files in ZIP: {len(names)}", "info")
                        suspicious_exts = ['.exe', '.dll', '.scr', '.bat', '.ps1', '.vbs', '.js', '.hta']
                        found_sus = [n for n in names if Path(n).suffix.lower() in suspicious_exts]
                        results["zip"]["suspicious_files"] = found_sus
                        for f in found_sus:
                            self.log_message.emit(f"  [!] Suspicious file in archive: {f}", "warn")
                except Exception as e:
                    results["zip"]["error"] = str(e)
                self.progress.emit(55, "ZIP analysis done...")

            self.progress.emit(75, "Extracting IOCs...")
            # ── IOC Extraction ─────────────────────────────────────────────
            all_text = self._collect_text(results, filepath)
            iocs = IOCExtractor.extract_all(all_text)
            results["iocs"] = iocs
            total_iocs = sum(len(v) for v in iocs.values())
            self.log_message.emit(f"[+] IOCs extracted: {total_iocs}", "ioc" if total_iocs else "info")
            for ioc_type, vals in iocs.items():
                if vals:
                    self.log_message.emit(f"  [{ioc_type}] {len(vals)} found", "ioc")

            self.progress.emit(88, "Deobfuscating...")
            # ── Deobfuscation ──────────────────────────────────────────────
            deob_results = Deobfuscator.full_deobfuscate(all_text)
            results["deobfuscation"] = deob_results
            if deob_results:
                self.log_message.emit(f"[+] Deobfuscation: {len(deob_results)} encoded blocks found", "warn")
                for dtype, pos, original, decoded in deob_results[:5]:
                    self.log_message.emit(f"  [{dtype}] @ {pos}: {decoded[:80]}...", "warn")
            else:
                self.log_message.emit("[+] Deobfuscation: No encoded blocks detected", "info")

            self.progress.emit(95, "Building risk summary...")
            # ── Risk Score ─────────────────────────────────────────────────
            risk_score = 0
            risk_factors = []
            if results.get("pdf", {}).get("scripts"):
                risk_score += 25; risk_factors.append("Embedded JavaScript in PDF")
            if results.get("pdf", {}).get("suspicious"):
                risk_score += 10 * len(results["pdf"]["suspicious"]); risk_factors.append("Suspicious PDF keywords")
            if results.get("vba", {}).get("macros"):
                for m in results["vba"]["macros"]:
                    risk_score += m.get("risk_score", 0) * 3
                risk_factors.append(f"VBA Macros ({len(results['vba']['macros'])})")
            if results.get("ooxml", {}).get("external_links"):
                risk_score += 10; risk_factors.append("External links in document")
            if iocs.get("URL"):
                risk_score += 5 * len(iocs["URL"]); risk_factors.append(f"URLs ({len(iocs['URL'])})")
            if deob_results:
                risk_score += 8 * len(deob_results); risk_factors.append(f"Obfuscated content ({len(deob_results)} blocks)")
            if gen.get("entropy", 0) > 7.0:
                risk_score += 20; risk_factors.append("High entropy (possible encryption)")
            if results.get("generic", {}).get("suspicious"):
                risk_score += len(results["generic"]["suspicious"]); risk_factors.append("Suspicious strings")

            risk_score = min(risk_score, 100)
            if risk_score >= 75:
                risk_level = "CRITICAL"
            elif risk_score >= 50:
                risk_level = "HIGH"
            elif risk_score >= 25:
                risk_level = "MEDIUM"
            elif risk_score >= 5:
                risk_level = "LOW"
            else:
                risk_level = "CLEAN"

            results["risk"] = {
                "score": risk_score,
                "level": risk_level,
                "factors": risk_factors,
            }
            self.log_message.emit(f"\n{'='*50}", "info")
            self.log_message.emit(f"  RISK LEVEL: {risk_level}  (score: {risk_score}/100)", "err" if risk_level in ["CRITICAL","HIGH"] else "warn" if risk_level == "MEDIUM" else "info")
            self.log_message.emit(f"{'='*50}", "info")
            for f in risk_factors:
                self.log_message.emit(f"  [FACTOR] {f}", "warn")

            self.progress.emit(100, "Analysis complete!")
            self.analysis_done.emit(results)

        except Exception as e:
            self.error.emit(traceback.format_exc())

    def _collect_text(self, results, filepath):
        parts = []
        # PDF text
        if "pdf" in results:
            parts.append(results["pdf"].get("raw_text", ""))
            for s in results["pdf"].get("scripts", []):
                parts.append(s)
            for st in results["pdf"].get("streams", []):
                parts.append(st.get("preview", ""))
        # Macros
        if "vba" in results:
            for m in results["vba"].get("macros", []):
                parts.append(m.get("code", ""))
        # OOXML XML
        if "ooxml" in results:
            for content in results["ooxml"].get("xml_content", {}).values():
                parts.append(content)
        # Script
        if "script" in results:
            parts.append(results["script"].get("code", ""))
        # Strings
        if "generic" in results:
            parts.extend(results["generic"].get("strings", []))
        # Raw file text fallback
        try:
            with open(filepath, 'rb') as f:
                raw = f.read()
            parts.append(raw.decode('latin-1', errors='replace'))
        except:
            pass
        return '\n'.join(parts)

# ═══════════════════════════════════════════════════════════════════════════
#  WINDOWS XP STYLED WIDGETS
# ═══════════════════════════════════════════════════════════════════════════
XP_STYLESHEET = """
QMainWindow, QDialog {
    background-color: #ECE9D8;
}
QWidget {
    background-color: #ECE9D8;
    color: #000000;
    font-family: "Tahoma", "MS Sans Serif", sans-serif;
    font-size: 11px;
}
QMenuBar {
    background: qlineargradient(x1:0,y1:0,x2:0,y2:1,
        stop:0 #0A246A, stop:0.5 #3D6EA8, stop:1 #0A246A);
    color: white;
    font-weight: bold;
    padding: 2px;
    font-size: 11px;
}
QMenuBar::item { padding: 3px 8px; background: transparent; }
QMenuBar::item:selected { background: #316AC5; border-radius: 2px; }
QMenu {
    background: #ECE9D8;
    border: 1px solid #716F64;
    color: #000000;
}
QMenu::item { padding: 4px 20px; }
QMenu::item:selected { background: #316AC5; color: white; }

QPushButton {
    background: qlineargradient(x1:0,y1:0,x2:0,y2:1,
        stop:0 #FFFFFF, stop:0.5 #ECE9D8, stop:1 #C1BFBA);
    border: 1px solid #716F64;
    border-top-color: #FFFFFF;
    border-left-color: #FFFFFF;
    padding: 3px 10px;
    color: #000000;
    font-size: 11px;
    min-height: 20px;
}
QPushButton:hover {
    background: qlineargradient(x1:0,y1:0,x2:0,y2:1,
        stop:0 #FFFFFF, stop:1 #D4D0C8);
    border-color: #316AC5;
}
QPushButton:pressed {
    background: qlineargradient(x1:0,y1:0,x2:0,y2:1,
        stop:0 #C1BFBA, stop:1 #ECE9D8);
    border-top-color: #716F64;
    border-left-color: #716F64;
    border-bottom-color: #FFFFFF;
    border-right-color: #FFFFFF;
    padding-top: 4px; padding-left: 11px;
}
QPushButton#danger {
    background: qlineargradient(x1:0,y1:0,x2:0,y2:1,
        stop:0 #FF9999, stop:1 #CC3333);
    color: white;
    font-weight: bold;
    border-color: #990000;
}
QPushButton#scan {
    background: qlineargradient(x1:0,y1:0,x2:0,y2:1,
        stop:0 #6699FF, stop:1 #0033CC);
    color: white;
    font-weight: bold;
    font-size: 12px;
    border-color: #001A66;
    min-height: 28px;
    padding: 4px 20px;
}

QTabWidget::pane {
    border: 1px solid #716F64;
    background: #ECE9D8;
}
QTabBar::tab {
    background: qlineargradient(x1:0,y1:0,x2:0,y2:1,
        stop:0 #D4D0C8, stop:1 #C1BFBA);
    border: 1px solid #716F64;
    padding: 4px 10px;
    margin-right: 2px;
    color: #000000;
    font-size: 11px;
}
QTabBar::tab:selected {
    background: qlineargradient(x1:0,y1:0,x2:0,y2:1,
        stop:0 #FFFFFF, stop:1 #ECE9D8);
    border-bottom-color: #ECE9D8;
    font-weight: bold;
}
QTabBar::tab:hover:!selected {
    background: qlineargradient(x1:0,y1:0,x2:0,y2:1,
        stop:0 #E0DDD5, stop:1 #CFCCC4);
}

QGroupBox {
    border: 1px solid #ACA899;
    border-top: 2px solid #716F64;
    margin-top: 8px;
    padding-top: 4px;
    font-weight: bold;
    background: #F5F4EA;
}
QGroupBox::title {
    subcontrol-origin: margin;
    left: 8px;
    padding: 0 4px;
    color: #000080;
}

QTreeWidget, QListWidget, QTableWidget {
    background: #FFFFFF;
    border: 1px inset #ACA899;
    alternate-background-color: #F0EFE7;
    gridline-color: #D4D0C8;
    selection-background-color: #316AC5;
    selection-color: #FFFFFF;
    font-size: 11px;
}
QHeaderView::section {
    background: qlineargradient(x1:0,y1:0,x2:0,y2:1,
        stop:0 #ECE9D8, stop:1 #C1BFBA);
    border: 1px solid #ACA899;
    padding: 2px 6px;
    font-weight: bold;
    font-size: 11px;
}

QProgressBar {
    border: 1px inset #ACA899;
    background: #FFFFFF;
    text-align: center;
    color: #000000;
    font-size: 11px;
    max-height: 16px;
}
QProgressBar::chunk {
    background: qlineargradient(x1:0,y1:0,x2:1,y2:0,
        stop:0 #316AC5, stop:0.5 #5B93E5, stop:1 #316AC5);
}

QScrollBar:vertical {
    background: #D4D0C8;
    width: 16px;
    border: 1px solid #ACA899;
}
QScrollBar::handle:vertical {
    background: qlineargradient(x1:0,y1:0,x2:1,y2:0,
        stop:0 #FFFFFF, stop:0.5 #ECE9D8, stop:1 #C1BFBA);
    border: 1px solid #ACA899;
    min-height: 20px;
}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    background: #ECE9D8;
    border: 1px solid #ACA899;
    height: 16px;
    subcontrol-position: bottom;
    subcontrol-origin: margin;
}
QScrollBar:horizontal {
    background: #D4D0C8;
    height: 16px;
    border: 1px solid #ACA899;
}
QScrollBar::handle:horizontal {
    background: qlineargradient(x1:0,y1:0,x2:0,y2:1,
        stop:0 #FFFFFF, stop:0.5 #ECE9D8, stop:1 #C1BFBA);
    border: 1px solid #ACA899;
    min-width: 20px;
}

QLineEdit, QComboBox {
    background: #FFFFFF;
    border: 1px inset #ACA899;
    padding: 2px 4px;
    font-size: 11px;
    color: #000000;
}
QComboBox::drop-down {
    border-left: 1px solid #ACA899;
    width: 16px;
}

QLabel {
    background: transparent;
    font-size: 11px;
}
QStatusBar {
    background: qlineargradient(x1:0,y1:0,x2:0,y2:1,
        stop:0 #ECE9D8, stop:1 #C1BFBA);
    border-top: 1px solid #ACA899;
    color: #000000;
    font-size: 11px;
}
QSplitter::handle {
    background: #ACA899;
    width: 4px;
    height: 4px;
}
QToolBar {
    background: qlineargradient(x1:0,y1:0,x2:0,y2:1,
        stop:0 #ECE9D8, stop:1 #C1BFBA);
    border-bottom: 1px solid #ACA899;
    spacing: 4px;
    padding: 2px;
}
"""

# ═══════════════════════════════════════════════════════════════════════════
#  CUSTOM TITLE BAR
# ═══════════════════════════════════════════════════════════════════════════
class XPTitleBar(QWidget):
    def __init__(self, parent=None, title=""):
        super().__init__(parent)
        self.parent_window = parent
        self.setFixedHeight(28)
        self._drag_pos = None
        layout = QHBoxLayout(self)
        layout.setContentsMargins(6, 2, 4, 2)
        layout.setSpacing(4)

        # Icon placeholder
        icon_lbl = QLabel("🛡")
        icon_lbl.setStyleSheet("font-size: 16px; background: transparent; color: white;")
        layout.addWidget(icon_lbl)

        # Title
        self.title_lbl = QLabel(title)
        self.title_lbl.setStyleSheet("color: white; font-weight: bold; font-size: 12px; background: transparent; font-family: Tahoma;")
        layout.addWidget(self.title_lbl)
        layout.addStretch()

        # Buttons
        for symbol, tip, cb, style in [
            ("─", "Minimize", parent.showMinimized, "min_btn"),
            ("□", "Maximize", self._toggle_max, "max_btn"),
            ("✕", "Close",    parent.close,        "close_btn"),
        ]:
            btn = QPushButton(symbol)
            btn.setFixedSize(18, 16)
            btn.setToolTip(tip)
            btn.clicked.connect(cb)
            btn.setObjectName(style)
            btn.setStyleSheet(self._btn_style(symbol == "✕"))
            layout.addWidget(btn)

        self.setStyleSheet("""
            XPTitleBar {
                background: qlineargradient(x1:0,y1:0,x2:1,y2:0,
                    stop:0 #0A246A, stop:0.3 #3D6EA8,
                    stop:0.7 #3D6EA8, stop:1 #0A246A);
                border-bottom: 1px solid #000070;
            }
        """)

    def _btn_style(self, is_close=False):
        base = "#CC2200" if is_close else "#0A246A"
        hover = "#FF0000" if is_close else "#316AC5"
        return f"""
            QPushButton {{
                background: qlineargradient(x1:0,y1:0,x2:0,y2:1,
                    stop:0 #6699CC, stop:1 {base});
                color: white; font-weight: bold; font-size: 10px;
                border: 1px solid #FFFFFF44; border-radius: 2px;
            }}
            QPushButton:hover {{ background: {hover}; }}
            QPushButton:pressed {{ background: #000033; }}
        """

    def _toggle_max(self):
        w = self.parent_window
        if w.isMaximized():
            w.showNormal()
        else:
            w.showMaximized()

    def mousePressEvent(self, e):
        if e.button() == Qt.LeftButton:
            self._drag_pos = e.globalPos() - self.parent_window.frameGeometry().topLeft()

    def mouseMoveEvent(self, e):
        if e.buttons() == Qt.LeftButton and self._drag_pos:
            self.parent_window.move(e.globalPos() - self._drag_pos)

# ═══════════════════════════════════════════════════════════════════════════
#  OUTPUT CONSOLE
# ═══════════════════════════════════════════════════════════════════════════
class ConsoleWidget(QPlainTextEdit):
    def __init__(self):
        super().__init__()
        self.setReadOnly(True)
        self.setFont(QFont("Courier New", 10))
        self.setStyleSheet(f"""
            QPlainTextEdit {{
                background-color: {XP_COLORS['output_bg']};
                color: {XP_COLORS['output_fg']};
                border: 2px inset #333355;
                font-family: 'Courier New', monospace;
                font-size: 11px;
                padding: 4px;
            }}
        """)
        self.setMaximumBlockCount(5000)

    def append_msg(self, text, level="info"):
        color_map = {
            "info":  XP_COLORS["output_fg"],
            "warn":  XP_COLORS["output_warn"],
            "err":   XP_COLORS["output_err"],
            "ioc":   XP_COLORS["output_ioc"],
            "good":  "#44FF44",
        }
        color = color_map.get(level, XP_COLORS["output_fg"])
        cursor = self.textCursor()
        cursor.movePosition(QTextCursor.End)
        fmt = QTextCharFormat()
        fmt.setForeground(QColor(color))
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        cursor.insertText(f"[{ts}] {text}\n", fmt)
        self.setTextCursor(cursor)
        self.ensureCursorVisible()

    def clear_console(self):
        self.clear()
        self.append_msg("Console cleared. Ready for next analysis.", "info")

# ═══════════════════════════════════════════════════════════════════════════
#  IOC TABLE WIDGET
# ═══════════════════════════════════════════════════════════════════════════
class IOCTableWidget(QTableWidget):
    def __init__(self):
        super().__init__()
        self.setColumnCount(3)
        self.setHorizontalHeaderLabels(["IOC Type", "Value", "Risk"])
        self.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.setAlternatingRowColors(True)
        self.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.setEditTriggers(QAbstractItemView.NoEditTriggers)

    def populate(self, iocs: dict):
        self.setRowCount(0)
        risk_map = {
            "URL": "HIGH", "Shell Invoke": "CRITICAL", "Suspicious Cmd": "CRITICAL",
            "IPv4": "MEDIUM", "Domain": "MEDIUM", "Email": "LOW",
            "MD5": "INFO", "SHA1": "INFO", "SHA256": "INFO",
            "Registry Key": "HIGH", "File Path Win": "MEDIUM", "File Path Unix": "LOW",
            "CVE": "INFO", "Base64 Block": "HIGH", "Hex Block": "MEDIUM",
        }
        risk_colors = {
            "CRITICAL": "#FF2222", "HIGH": "#FF8C00",
            "MEDIUM": "#FFD700", "LOW": "#98FB98", "INFO": "#AAAAAA",
        }
        for ioc_type, values in iocs.items():
            for val in values:
                row = self.rowCount()
                self.insertRow(row)
                risk = risk_map.get(ioc_type, "MEDIUM")
                self.setItem(row, 0, QTableWidgetItem(ioc_type))
                self.setItem(row, 1, QTableWidgetItem(str(val)[:300]))
                risk_item = QTableWidgetItem(risk)
                risk_item.setForeground(QColor(risk_colors.get(risk, "#FFFFFF")))
                risk_item.setFont(QFont("Tahoma", 10, QFont.Bold))
                self.setItem(row, 2, risk_item)

# ═══════════════════════════════════════════════════════════════════════════
#  RISK GAUGE WIDGET
# ═══════════════════════════════════════════════════════════════════════════
class RiskGauge(QWidget):
    def __init__(self):
        super().__init__()
        self.score = 0
        self.level = "CLEAN"
        self.setMinimumSize(260, 80)
        self.setMaximumHeight(90)

    def set_risk(self, score, level):
        self.score = score
        self.level = level
        self.update()

    def paintEvent(self, e):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        w, h = self.width(), self.height()

        # Background
        p.fillRect(0, 0, w, h, QColor("#1A1A2E"))

        # Bar background
        bar_x, bar_y, bar_w, bar_h = 10, 30, w - 20, 20
        p.fillRect(bar_x, bar_y, bar_w, bar_h, QColor("#333355"))
        p.setPen(QPen(QColor("#555577"), 1))
        p.drawRect(bar_x, bar_y, bar_w, bar_h)

        # Gradient fill
        fill_w = int(bar_w * self.score / 100)
        if fill_w > 0:
            colors = ["#00CC44", "#00CC44", "#FFCC00", "#FF8800", "#FF2222"]
            idx = min(int(self.score / 25), 4)
            color = colors[idx]
            p.fillRect(bar_x, bar_y, fill_w, bar_h, QColor(color))

        # Labels
        p.setPen(QColor("#CCCCCC"))
        p.setFont(QFont("Tahoma", 8))
        for i, lbl in enumerate(["CLEAN", "LOW", "MEDIUM", "HIGH", "CRITICAL"]):
            x = bar_x + int(bar_w * i / 4) - 10
            p.drawText(x, bar_y + bar_h + 15, lbl)

        # Score text
        level_colors = {
            "CLEAN": "#00CC44", "LOW": "#AAFFAA",
            "MEDIUM": "#FFCC00", "HIGH": "#FF8800", "CRITICAL": "#FF2222",
        }
        p.setPen(QColor(level_colors.get(self.level, "#FFFFFF")))
        p.setFont(QFont("Tahoma", 11, QFont.Bold))
        p.drawText(10, 22, f"Risk: {self.level}  ({self.score}/100)")

# ═══════════════════════════════════════════════════════════════════════════
#  SCRIPT VIEWER
# ═══════════════════════════════════════════════════════════════════════════
class ScriptViewer(QPlainTextEdit):
    def __init__(self):
        super().__init__()
        self.setReadOnly(True)
        self.setFont(QFont("Courier New", 10))
        self.setStyleSheet("""
            QPlainTextEdit {
                background: #1E1E1E;
                color: #D4D4D4;
                border: 1px inset #555555;
                font-family: 'Courier New', monospace;
                font-size: 11px;
            }
        """)
        self.highlighter = MalwareHighlighter(self.document())

    def show_content(self, text):
        self.setPlainText(text)

# ═══════════════════════════════════════════════════════════════════════════
#  DROP ZONE
# ═══════════════════════════════════════════════════════════════════════════
class DropZone(QLabel):
    file_dropped = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.setAcceptDrops(True)
        self.setAlignment(Qt.AlignCenter)
        self.setText("📂  DROP FILE HERE  📂\n\nor click UPLOAD FILE button\n\nPDF · DOC · XLS · PPT · DOCX · XLSX · PPTX\nPS1 · VBS · JS · BAT · ZIP · HTA · WSF · PY")
        self.setStyleSheet("""
            QLabel {
                background: #FFFFFF;
                border: 2px dashed #316AC5;
                color: #316AC5;
                font-size: 13px;
                font-family: Tahoma;
                font-weight: bold;
                padding: 10px;
                min-height: 80px;
            }
        """)

    def dragEnterEvent(self, e):
        if e.mimeData().hasUrls():
            e.accept()
            self.setStyleSheet("""
                QLabel {
                    background: #EEF4FF;
                    border: 2px dashed #0033CC;
                    color: #0033CC;
                    font-size: 13px;
                    font-family: Tahoma;
                    font-weight: bold;
                    padding: 10px;
                    min-height: 80px;
                }
            """)
        else:
            e.ignore()

    def dragLeaveEvent(self, e):
        self.setStyleSheet("""
            QLabel {
                background: #FFFFFF;
                border: 2px dashed #316AC5;
                color: #316AC5;
                font-size: 13px;
                font-family: Tahoma;
                font-weight: bold;
                padding: 10px;
                min-height: 80px;
            }
        """)

    def dropEvent(self, e):
        self.dragLeaveEvent(e)
        for url in e.mimeData().urls():
            path = url.toLocalFile()
            if path:
                self.file_dropped.emit(path)
                break

# ═══════════════════════════════════════════════════════════════════════════
#  MAIN WINDOW
# ═══════════════════════════════════════════════════════════════════════════
class MalwareAnalyzerWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowFlags(Qt.FramelessWindowHint)
        self.setMinimumSize(1024, 700)
        self.resize(1280, 800)
        self.setWindowTitle("MalDoc Analyzer Pro – Malware Analysis Tool")
        self.current_file = None
        self.current_results = {}
        self.worker = None

        # Central widget
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # Title bar
        self.title_bar = XPTitleBar(self, "🛡  MalDoc Analyzer Pro  —  Malware Document Analysis Tool  v2.0")
        main_layout.addWidget(self.title_bar)

        # Menu bar simulation
        menubar_widget = QWidget()
        menubar_widget.setFixedHeight(22)
        menubar_widget.setStyleSheet("background: #ECE9D8; border-bottom: 1px solid #ACA899;")
        mb_layout = QHBoxLayout(menubar_widget)
        mb_layout.setContentsMargins(4, 0, 4, 0)
        mb_layout.setSpacing(0)
        for menu_text in ["File", "Analysis", "Tools", "View", "Help"]:
            btn = QPushButton(menu_text)
            btn.setFlat(True)
            btn.setStyleSheet("""
                QPushButton {
                    background: transparent; border: none; padding: 1px 8px;
                    font-size: 11px; font-family: Tahoma; color: #000000;
                }
                QPushButton:hover {
                    background: #316AC5; color: white; border-radius: 0;
                }
            """)
            mb_layout.addWidget(btn)
        mb_layout.addStretch()
        main_layout.addWidget(menubar_widget)

        # Toolbar
        toolbar_widget = QWidget()
        toolbar_widget.setFixedHeight(36)
        toolbar_widget.setStyleSheet("""
            background: qlineargradient(x1:0,y1:0,x2:0,y2:1,
                stop:0 #ECE9D8, stop:1 #C1BFBA);
            border-bottom: 1px solid #ACA899;
        """)
        tb_layout = QHBoxLayout(toolbar_widget)
        tb_layout.setContentsMargins(6, 2, 6, 2)
        tb_layout.setSpacing(4)

        self.upload_btn = QPushButton("📂  Upload File")
        self.upload_btn.setObjectName("scan")
        self.upload_btn.clicked.connect(self.browse_file)
        tb_layout.addWidget(self.upload_btn)

        self.scan_btn = QPushButton("🔍  Analyze")
        self.scan_btn.setObjectName("scan")
        self.scan_btn.clicked.connect(self.start_analysis)
        self.scan_btn.setEnabled(False)
        tb_layout.addWidget(self.scan_btn)

        tb_layout.addWidget(self._sep())

        self.clear_btn = QPushButton("🗑  Clear Results")
        self.clear_btn.clicked.connect(self.clear_all)
        tb_layout.addWidget(self.clear_btn)

        self.export_btn = QPushButton("💾  Export Report")
        self.export_btn.clicked.connect(self.export_report)
        self.export_btn.setEnabled(False)
        tb_layout.addWidget(self.export_btn)

        tb_layout.addWidget(self._sep())

        self.file_label = QLabel("No file loaded")
        self.file_label.setStyleSheet("color: #7A7A7A; font-style: italic; font-size: 11px;")
        tb_layout.addWidget(self.file_label)
        tb_layout.addStretch()

        # Library status indicators
        for name, avail in [("PDF", PDF_AVAILABLE), ("OLE", OLEFILE_AVAILABLE),
                            ("VBA", OLETOOLS_AVAILABLE), ("DOCX", DOCX_AVAILABLE),
                            ("XLSX", OPENPYXL_AVAILABLE), ("PPTX", PPTX_AVAILABLE)]:
            dot = QLabel(f"● {name}")
            dot.setStyleSheet(f"color: {'#00AA00' if avail else '#AA0000'}; font-size: 10px; font-weight: bold;")
            dot.setToolTip(f"{'Available' if avail else 'Not available'}")
            tb_layout.addWidget(dot)

        main_layout.addWidget(toolbar_widget)

        # ── Main content area ──────────────────────────────────────────────
        content = QWidget()
        content_layout = QHBoxLayout(content)
        content_layout.setContentsMargins(4, 4, 4, 4)
        content_layout.setSpacing(4)

        # ── LEFT PANEL ─────────────────────────────────────────────────────
        left_panel = QWidget()
        left_panel.setMinimumWidth(260)
        left_panel.setMaximumWidth(320)
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(4)

        # Drop zone
        drop_grp = QGroupBox("File Upload")
        drop_lay = QVBoxLayout(drop_grp)
        self.drop_zone = DropZone()
        self.drop_zone.file_dropped.connect(self.load_file)
        drop_lay.addWidget(self.drop_zone)
        left_layout.addWidget(drop_grp)

        # File info
        info_grp = QGroupBox("File Information")
        info_lay = QVBoxLayout(info_grp)
        self.info_tree = QTreeWidget()
        self.info_tree.setHeaderLabels(["Property", "Value"])
        self.info_tree.setMaximumHeight(150)
        self.info_tree.header().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.info_tree.header().setSectionResizeMode(1, QHeaderView.Stretch)
        info_lay.addWidget(self.info_tree)
        left_layout.addWidget(info_grp)

        # Risk gauge
        risk_grp = QGroupBox("Risk Assessment")
        risk_lay = QVBoxLayout(risk_grp)
        self.risk_gauge = RiskGauge()
        risk_lay.addWidget(self.risk_gauge)
        self.risk_factors_list = QListWidget()
        self.risk_factors_list.setMaximumHeight(120)
        risk_lay.addWidget(self.risk_factors_list)
        left_layout.addWidget(risk_grp)

        # Progress
        prog_grp = QGroupBox("Analysis Progress")
        prog_lay = QVBoxLayout(prog_grp)
        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        prog_lay.addWidget(self.progress_bar)
        self.progress_label = QLabel("Ready")
        self.progress_label.setStyleSheet("color: #7A7A7A; font-style: italic;")
        prog_lay.addWidget(self.progress_label)
        left_layout.addWidget(prog_grp)
        left_layout.addStretch()

        content_layout.addWidget(left_panel)

        # ── RIGHT PANEL (tabs) ─────────────────────────────────────────────
        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(4)

        self.tab_widget = QTabWidget()

        # ── Tab 1: Console Output ─────────────────────────────────────────
        tab_console = QWidget()
        tc_lay = QVBoxLayout(tab_console)
        tc_lay.setContentsMargins(4, 4, 4, 4)
        console_header = QHBoxLayout()
        console_header.addWidget(QLabel("Analysis Console Output:"))
        console_header.addStretch()
        clr_btn = QPushButton("Clear Console")
        clr_btn.clicked.connect(lambda: self.console.clear_console())
        console_header.addWidget(clr_btn)
        tc_lay.addLayout(console_header)
        self.console = ConsoleWidget()
        tc_lay.addWidget(self.console)
        self.tab_widget.addTab(tab_console, "📺 Console Output")

        # ── Tab 2: Scripts / Macros ───────────────────────────────────────
        tab_scripts = QWidget()
        ts_lay = QVBoxLayout(tab_scripts)
        ts_lay.setContentsMargins(4, 4, 4, 4)
        scripts_header = QHBoxLayout()
        self.script_selector = QComboBox()
        self.script_selector.currentIndexChanged.connect(self.show_selected_script)
        scripts_header.addWidget(QLabel("Script/Macro:"))
        scripts_header.addWidget(self.script_selector, 1)
        ts_lay.addLayout(scripts_header)
        self.script_viewer = ScriptViewer()
        ts_lay.addWidget(self.script_viewer)
        self.tab_widget.addTab(tab_scripts, "📜 Scripts & Macros")

        # ── Tab 3: IOCs ───────────────────────────────────────────────────
        tab_iocs = QWidget()
        ti_lay = QVBoxLayout(tab_iocs)
        ti_lay.setContentsMargins(4, 4, 4, 4)
        ioc_header = QHBoxLayout()
        ioc_header.addWidget(QLabel("Extracted Indicators of Compromise (IOCs):"))
        ioc_header.addStretch()
        self.ioc_filter = QLineEdit()
        self.ioc_filter.setPlaceholderText("Filter IOCs...")
        self.ioc_filter.setMaximumWidth(200)
        self.ioc_filter.textChanged.connect(self.filter_iocs)
        ioc_header.addWidget(self.ioc_filter)
        ti_lay.addLayout(ioc_header)
        self.ioc_table = IOCTableWidget()
        ti_lay.addWidget(self.ioc_table)
        self.tab_widget.addTab(tab_iocs, "🎯 IOCs")

        # ── Tab 4: Deobfuscation ──────────────────────────────────────────
        tab_deob = QWidget()
        td_lay = QVBoxLayout(tab_deob)
        td_lay.setContentsMargins(4, 4, 4, 4)
        td_lay.addWidget(QLabel("Deobfuscation Results — Decoded Payloads:"))
        self.deob_tree = QTreeWidget()
        self.deob_tree.setHeaderLabels(["Type", "Position", "Original (truncated)", "Decoded Payload"])
        self.deob_tree.header().setSectionResizeMode(3, QHeaderView.Stretch)
        self.deob_tree.setAlternatingRowColors(True)
        td_lay.addWidget(self.deob_tree)

        # Decoded payload viewer
        td_lay.addWidget(QLabel("Full Decoded Content:"))
        self.deob_viewer = ScriptViewer()
        self.deob_viewer.setMaximumHeight(200)
        self.deob_tree.itemClicked.connect(self.show_deob_detail)
        td_lay.addWidget(self.deob_viewer)
        self.tab_widget.addTab(tab_deob, "🔓 Deobfuscation")

        # ── Tab 5: Strings ────────────────────────────────────────────────
        tab_strings = QWidget()
        tstr_lay = QVBoxLayout(tab_strings)
        tstr_lay.setContentsMargins(4, 4, 4, 4)
        str_header = QHBoxLayout()
        str_header.addWidget(QLabel("Extracted Strings:"))
        str_header.addStretch()
        self.str_filter = QLineEdit()
        self.str_filter.setPlaceholderText("Filter strings (min 4 chars)...")
        self.str_filter.setMaximumWidth(200)
        str_header.addWidget(self.str_filter)
        tstr_lay.addLayout(str_header)
        self.strings_list = QPlainTextEdit()
        self.strings_list.setReadOnly(True)
        self.strings_list.setFont(QFont("Courier New", 10))
        self.strings_list.setStyleSheet("""
            background: #1E1E1E; color: #D4D4D4;
            border: 1px inset #555555;
            font-family: 'Courier New'; font-size: 11px;
        """)
        tstr_lay.addWidget(self.strings_list)
        self.tab_widget.addTab(tab_strings, "🔤 Strings")

        # ── Tab 6: Structure ──────────────────────────────────────────────
        tab_struct = QWidget()
        tst_lay = QVBoxLayout(tab_struct)
        tst_lay.setContentsMargins(4, 4, 4, 4)
        tst_lay.addWidget(QLabel("File Structure & Embedded Objects:"))
        self.struct_tree = QTreeWidget()
        self.struct_tree.setHeaderLabels(["Name / Path", "Type", "Size", "Notes"])
        self.struct_tree.header().setSectionResizeMode(0, QHeaderView.Stretch)
        self.struct_tree.setAlternatingRowColors(True)
        tst_lay.addWidget(self.struct_tree)
        self.tab_widget.addTab(tab_struct, "🗂 Structure")

        # ── Tab 7: Raw JSON ───────────────────────────────────────────────
        tab_json = QWidget()
        tj_lay = QVBoxLayout(tab_json)
        tj_lay.setContentsMargins(4, 4, 4, 4)
        tj_lay.addWidget(QLabel("Full Analysis JSON (raw results):"))
        self.json_viewer = QPlainTextEdit()
        self.json_viewer.setReadOnly(True)
        self.json_viewer.setFont(QFont("Courier New", 9))
        self.json_viewer.setStyleSheet("""
            background: #1E1E1E; color: #9CDCFE;
            border: 1px inset #555555;
            font-family: 'Courier New'; font-size: 10px;
        """)
        tj_lay.addWidget(self.json_viewer)
        self.tab_widget.addTab(tab_json, "📋 Raw JSON")

        right_layout.addWidget(self.tab_widget)
        content_layout.addWidget(right_panel, 1)
        main_layout.addWidget(content, 1)

        # ── Status Bar ─────────────────────────────────────────────────────
        self.status_bar = QStatusBar()
        self.status_bar.setFixedHeight(22)
        self.status_bar.showMessage("Ready – Load a file to begin malware analysis")
        main_layout.addWidget(self.status_bar)

        self.setStyleSheet(XP_STYLESHEET)
        self.console.append_msg("MalDoc Analyzer Pro v2.0 initialized.", "info")
        self.console.append_msg("Developed for malware analysis and digital forensics.", "info")
        self.console.append_msg("─" * 60, "info")
        self.console.append_msg(f"PDF engine    : {'OK' if PDF_AVAILABLE else 'UNAVAILABLE'}", "info" if PDF_AVAILABLE else "warn")
        self.console.append_msg(f"OLE engine    : {'OK' if OLEFILE_AVAILABLE else 'UNAVAILABLE'}", "info" if OLEFILE_AVAILABLE else "warn")
        self.console.append_msg(f"VBA engine    : {'OK' if OLETOOLS_AVAILABLE else 'UNAVAILABLE'}", "info" if OLETOOLS_AVAILABLE else "warn")
        self.console.append_msg(f"DOCX engine   : {'OK' if DOCX_AVAILABLE else 'UNAVAILABLE'}", "info" if DOCX_AVAILABLE else "warn")
        self.console.append_msg(f"XLSX engine   : {'OK' if OPENPYXL_AVAILABLE else 'UNAVAILABLE'}", "info" if OPENPYXL_AVAILABLE else "warn")
        self.console.append_msg(f"PPTX engine   : {'OK' if PPTX_AVAILABLE else 'UNAVAILABLE'}", "info" if PPTX_AVAILABLE else "warn")
        self.console.append_msg("─" * 60, "info")
        self.console.append_msg("Drop a file or use 'Upload File' to begin.", "good")

        self._scripts_data = []
        self._iocs_data = {}

    # ── Helper ─────────────────────────────────────────────────────────────
    def _sep(self):
        sep = QFrame()
        sep.setFrameShape(QFrame.VLine)
        sep.setFrameShadow(QFrame.Sunken)
        sep.setStyleSheet("color: #ACA899; max-width: 2px;")
        return sep

    # ── File loading ───────────────────────────────────────────────────────
    def browse_file(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Select File for Analysis", "",
            "All Supported (*.pdf *.doc *.docx *.docm *.xls *.xlsx *.xlsm *.xlsb "
            "*.ppt *.pptx *.pptm *.ps1 *.vbs *.js *.bat *.cmd *.hta *.wsf *.py "
            "*.rb *.sh *.zip *.jar *.msg *.mdb *.mde);;All Files (*.*)"
        )
        if path:
            self.load_file(path)

    def load_file(self, path):
        if not os.path.isfile(path):
            QMessageBox.warning(self, "Error", f"File not found:\n{path}")
            return
        self.current_file = path
        name = Path(path).name
        size = os.path.getsize(path)
        self.file_label.setText(f"📄 {name}  ({size:,} bytes)")
        self.scan_btn.setEnabled(True)
        self.drop_zone.setText(f"✅ Loaded:\n{name}\n\n{size:,} bytes")
        self.drop_zone.setStyleSheet("""
            QLabel {
                background: #EFFFEF;
                border: 2px dashed #009900;
                color: #006600;
                font-size: 11px;
                font-family: Tahoma;
                font-weight: bold;
                padding: 10px;
                min-height: 80px;
            }
        """)
        # Update info tree
        self.info_tree.clear()
        info_items = [
            ("Name", name), ("Path", str(Path(path).parent)),
            ("Size", f"{size:,} bytes"), ("Modified", str(datetime.datetime.fromtimestamp(os.path.getmtime(path)))),
            ("Extension", Path(path).suffix.upper()),
        ]
        for k, v in info_items:
            item = QTreeWidgetItem([k, str(v)[:80]])
            self.info_tree.addTopLevelItem(item)
        self.status_bar.showMessage(f"Loaded: {name} — Click 'Analyze' to begin")
        self.console.append_msg(f"[+] File loaded: {name} ({size:,} bytes)", "good")

    # ── Start analysis ─────────────────────────────────────────────────────
    def start_analysis(self):
        if not self.current_file:
            return
        self.scan_btn.setEnabled(False)
        self.export_btn.setEnabled(False)
        self.progress_bar.setValue(0)
        self.console.append_msg(f"\n{'═'*60}", "info")
        self.console.append_msg(f"  STARTING ANALYSIS: {Path(self.current_file).name}", "ioc")
        self.console.append_msg(f"{'═'*60}", "info")
        self.tab_widget.setCurrentIndex(0)
        self._clear_results()

        self.worker = AnalysisWorker(self.current_file)
        self.worker.progress.connect(self._on_progress)
        self.worker.log_message.connect(self._on_log)
        self.worker.analysis_done.connect(self._on_done)
        self.worker.error.connect(self._on_error)
        self.worker.start()

    def _on_progress(self, val, msg):
        self.progress_bar.setValue(val)
        self.progress_label.setText(msg)
        self.status_bar.showMessage(msg)

    def _on_log(self, msg, level):
        self.console.append_msg(msg, level)

    def _on_error(self, err):
        self.console.append_msg(f"[ERROR] {err}", "err")
        self.scan_btn.setEnabled(True)
        self.progress_bar.setValue(0)
        QMessageBox.critical(self, "Analysis Error", f"An error occurred:\n{err[:500]}")

    def _on_done(self, results):
        self.current_results = results
        self.scan_btn.setEnabled(True)
        self.export_btn.setEnabled(True)

        # Risk gauge
        risk = results.get("risk", {})
        self.risk_gauge.set_risk(risk.get("score", 0), risk.get("level", "UNKNOWN"))
        self.risk_factors_list.clear()
        for factor in risk.get("factors", []):
            item = QListWidgetItem(f"• {factor}")
            item.setForeground(QColor("#CC4400"))
            self.risk_factors_list.addItem(item)
        if not risk.get("factors"):
            item = QListWidgetItem("✓ No significant risk factors detected")
            item.setForeground(QColor("#006600"))
            self.risk_factors_list.addItem(item)

        # IOCs
        iocs = results.get("iocs", {})
        self._iocs_data = iocs
        self.ioc_table.populate(iocs)

        # Scripts
        self._populate_scripts(results)

        # Deobfuscation
        self._populate_deobfuscation(results.get("deobfuscation", []))

        # Strings
        strings = results.get("generic", {}).get("strings", [])
        self.strings_list.setPlainText('\n'.join(strings))

        # Structure
        self._populate_structure(results)

        # JSON
        try:
            safe_results = self._make_json_safe(results)
            self.json_viewer.setPlainText(json.dumps(safe_results, indent=2, default=str)[:100000])
        except:
            self.json_viewer.setPlainText(str(results)[:50000])

        # Hash info update
        gen = results.get("generic", {}).get("file_info", {})
        for k, label in [("md5", "MD5"), ("sha1", "SHA1"), ("sha256", "SHA256"), ("entropy", "Entropy")]:
            val = gen.get(k, "")
            if val:
                item = QTreeWidgetItem([label, str(val)[:80]])
                self.info_tree.addTopLevelItem(item)

        self.status_bar.showMessage(
            f"Analysis complete — Risk: {risk.get('level','?')} ({risk.get('score',0)}/100) — "
            f"IOCs: {sum(len(v) for v in iocs.values())} — "
            f"Deob blocks: {len(results.get('deobfuscation', []))}"
        )
        self.console.append_msg("\n[✓] Analysis complete. Review the tabs for full results.", "good")

    def _populate_scripts(self, results):
        self.script_selector.clear()
        self._scripts_data = []

        # PDF scripts
        for i, script in enumerate(results.get("pdf", {}).get("scripts", [])):
            self.script_selector.addItem(f"[PDF] Embedded Script #{i+1}")
            self._scripts_data.append(script)
        # PDF streams with scripts
        for st in results.get("pdf", {}).get("streams", []):
            if st.get("has_script"):
                self.script_selector.addItem(f"[PDF] Stream #{st['index']} (has script)")
                self._scripts_data.append(st.get("preview", ""))

        # VBA macros
        for mac in results.get("vba", {}).get("macros", []):
            self.script_selector.addItem(f"[VBA] {mac.get('vba_file', 'macro')}")
            self._scripts_data.append(mac.get("code", ""))

        # Script files
        sc = results.get("script", {})
        if sc.get("code"):
            self.script_selector.addItem("[SCRIPT] Source Code")
            self._scripts_data.append(sc["code"])

        # OOXML XML content
        for name, content in results.get("ooxml", {}).get("xml_content", {}).items():
            if any(k in content for k in ['macro', 'vba', 'dde', 'DDE', 'script']):
                self.script_selector.addItem(f"[XML] {name}")
                self._scripts_data.append(content)

        if self._scripts_data:
            self.show_selected_script(0)
            self.tab_widget.setTabText(1, f"📜 Scripts & Macros ({len(self._scripts_data)})")
        else:
            self.script_viewer.show_content("// No scripts or macros found in this file.")

    def show_selected_script(self, idx):
        if 0 <= idx < len(self._scripts_data):
            self.script_viewer.show_content(self._scripts_data[idx])

    def _populate_deobfuscation(self, deob_list):
        self.deob_tree.clear()
        for dtype, pos, original, decoded in deob_list:
            item = QTreeWidgetItem([dtype, str(pos), original[:60], decoded[:120]])
            color_map = {
                "base64": "#FFD700", "hex": "#FFA500", "chr_concat": "#FF6666",
                "ps_encoded": "#FF4444", "rot13": "#DD88FF", "url_encode": "#88DDFF",
            }
            for col in range(4):
                item.setForeground(col, QColor(color_map.get(dtype, "#CCCCCC")))
            item.setData(0, Qt.UserRole, decoded)
            self.deob_tree.addTopLevelItem(item)
        if deob_list:
            self.tab_widget.setTabText(3, f"🔓 Deobfuscation ({len(deob_list)})")

    def show_deob_detail(self, item, col):
        decoded = item.data(0, Qt.UserRole)
        if decoded:
            self.deob_viewer.show_content(decoded)

    def _populate_structure(self, results):
        self.struct_tree.clear()

        def add_item(parent, name, ftype, size, notes=""):
            if parent:
                item = QTreeWidgetItem(parent, [name, ftype, str(size), notes])
            else:
                item = QTreeWidgetItem(self.struct_tree, [name, ftype, str(size), notes])
            return item

        # PDF
        if "pdf" in results:
            root = add_item(None, "📄 PDF Structure", "PDF", "", "")
            for s in results["pdf"].get("streams", []):
                note = "⚠ Contains Script" if s.get("has_script") else ""
                add_item(root, f"Stream #{s['index']}", "PDF Stream", f"{s['size']} bytes", note)
            for emb in results["pdf"].get("embedded", []):
                add_item(root, "Embedded File", "Embedded", f"{emb['size']} bytes", emb["preview"][:30])
            root.setExpanded(True)

        # OLE
        if "ole" in results:
            root = add_item(None, "🗂 OLE Streams", "OLE", "", "")
            for stream in results["ole"].get("streams", []):
                note = "⚠ SUSPICIOUS" if stream.get("suspicious_keywords") else ""
                add_item(root, stream["path"], "OLE Stream", f"{stream['size']} bytes", note)
            root.setExpanded(True)

        # OOXML
        if "ooxml" in results:
            root = add_item(None, "📦 OOXML Archive", "ZIP", f"{results['ooxml'].get('file_count',0)} files", "")
            for name in results["ooxml"].get("content_types", [])[:30]:
                add_item(root, name, "Part", "", "")
            for emb in results["ooxml"].get("embedded_files", []):
                add_item(root, emb["name"], "Embedded", f"{emb['size']} bytes", "")
            root.setExpanded(True)

        # ZIP
        if "zip" in results:
            root = add_item(None, "📦 ZIP Archive", "ZIP", f"{results['zip'].get('count',0)} files", "")
            for name in results["zip"].get("files", [])[:50]:
                sus = "⚠" if name in results["zip"].get("suspicious_files", []) else ""
                add_item(root, name, Path(name).suffix or "file", "", sus)
            root.setExpanded(True)

    def filter_iocs(self, text):
        for row in range(self.ioc_table.rowCount()):
            match = False
            for col in range(self.ioc_table.columnCount()):
                item = self.ioc_table.item(row, col)
                if item and text.lower() in item.text().lower():
                    match = True
                    break
            self.ioc_table.setRowHidden(row, not match)

    def _make_json_safe(self, obj):
        if isinstance(obj, dict):
            return {k: self._make_json_safe(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._make_json_safe(i) for i in obj]
        elif isinstance(obj, bytes):
            return obj.hex()
        elif isinstance(obj, (int, float, str, bool)) or obj is None:
            return obj
        else:
            return str(obj)

    def _clear_results(self):
        self.ioc_table.setRowCount(0)
        self.deob_tree.clear()
        self.struct_tree.clear()
        self.json_viewer.clear()
        self.strings_list.clear()
        self.script_viewer.clear()
        self.script_selector.clear()
        self.deob_viewer.clear()
        self.risk_factors_list.clear()
        self.risk_gauge.set_risk(0, "CLEAN")
        for i in range(self.tab_widget.count()):
            orig = ["📺 Console Output","📜 Scripts & Macros","🎯 IOCs","🔓 Deobfuscation","🔤 Strings","🗂 Structure","📋 Raw JSON"]
            if i < len(orig):
                self.tab_widget.setTabText(i, orig[i])

    def clear_all(self):
        self._clear_results()
        self.console.clear_console()
        self.info_tree.clear()
        self.current_file = None
        self.current_results = {}
        self.scan_btn.setEnabled(False)
        self.export_btn.setEnabled(False)
        self.file_label.setText("No file loaded")
        self.progress_bar.setValue(0)
        self.progress_label.setText("Ready")
        self.drop_zone.setText("📂  DROP FILE HERE  📂\n\nor click UPLOAD FILE button\n\nPDF · DOC · XLS · PPT · DOCX · XLSX · PPTX\nPS1 · VBS · JS · BAT · ZIP · HTA · WSF · PY")
        self.drop_zone.setStyleSheet("""
            QLabel {
                background: #FFFFFF; border: 2px dashed #316AC5;
                color: #316AC5; font-size: 13px; font-family: Tahoma;
                font-weight: bold; padding: 10px; min-height: 80px;
            }
        """)
        self.status_bar.showMessage("Cleared — Ready for new analysis")

    def export_report(self):
        if not self.current_results:
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Save Analysis Report", f"analysis_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
            "Text Report (*.txt);;JSON Report (*.json)"
        )
        if not path:
            return
        try:
            if path.endswith('.json'):
                safe = self._make_json_safe(self.current_results)
                with open(path, 'w', encoding='utf-8') as f:
                    json.dump(safe, f, indent=2, default=str)
            else:
                with open(path, 'w', encoding='utf-8') as f:
                    f.write("=" * 70 + "\n")
                    f.write("  MALDOC ANALYZER PRO - ANALYSIS REPORT\n")
                    f.write(f"  Generated: {datetime.datetime.now()}\n")
                    f.write(f"  File: {self.current_file}\n")
                    f.write("=" * 70 + "\n\n")

                    risk = self.current_results.get("risk", {})
                    f.write(f"RISK LEVEL: {risk.get('level','?')}  (Score: {risk.get('score',0)}/100)\n")
                    for factor in risk.get("factors", []):
                        f.write(f"  • {factor}\n")
                    f.write("\n")

                    iocs = self.current_results.get("iocs", {})
                    if iocs:
                        f.write("─" * 70 + "\n")
                        f.write("INDICATORS OF COMPROMISE (IOCs):\n")
                        for ioc_type, values in iocs.items():
                            f.write(f"\n  [{ioc_type}]\n")
                            for v in values:
                                f.write(f"    {v}\n")

                    deob = self.current_results.get("deobfuscation", [])
                    if deob:
                        f.write("\n" + "─" * 70 + "\n")
                        f.write("DEOBFUSCATION RESULTS:\n")
                        for dtype, pos, original, decoded in deob:
                            f.write(f"\n  Type: {dtype} @ offset {pos}\n")
                            f.write(f"  Original: {original[:100]}\n")
                            f.write(f"  Decoded:  {decoded[:500]}\n")

                    # Scripts
                    for script in self.current_results.get("pdf", {}).get("scripts", []):
                        f.write("\n" + "─" * 70 + "\n")
                        f.write("PDF EMBEDDED SCRIPT:\n")
                        f.write(script[:5000] + "\n")

                    for mac in self.current_results.get("vba", {}).get("macros", []):
                        f.write("\n" + "─" * 70 + "\n")
                        f.write(f"VBA MACRO [{mac.get('vba_file','')}] Risk={mac.get('risk_score',0)}:\n")
                        f.write(mac.get("code", "")[:10000] + "\n")

                    # Console log
                    f.write("\n" + "─" * 70 + "\n")
                    f.write("CONSOLE LOG:\n")
                    f.write(self.console.toPlainText())

            QMessageBox.information(self, "Exported", f"Report saved to:\n{path}")
            self.console.append_msg(f"[+] Report exported: {path}", "good")
        except Exception as e:
            QMessageBox.critical(self, "Export Error", str(e))

# ═══════════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════
def main():
    app = QApplication(sys.argv)
    app.setApplicationName("MalDoc Analyzer Pro")
    app.setOrganizationName("Security Research Tools")

    # Set default font to Tahoma (XP-style)
    font = QFont("Tahoma", 10)
    app.setFont(font)

    # High-DPI support
    app.setAttribute(Qt.AA_UseHighDpiPixmaps, True)

    window = MalwareAnalyzerWindow()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
