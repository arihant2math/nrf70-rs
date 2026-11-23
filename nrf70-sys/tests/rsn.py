"""Compile and test the production RSN parser without the mock firmware.

Run: python3 nrf70-sys/tests/rsn.py
Only AP capability data is used; no passwords or keys.
"""

import os
from pathlib import Path
import subprocess
import tempfile

source = (Path(__file__).resolve().parent.parent / "src/facade.c").read_text()
start = source.index("struct conn_rsn_info {")
end = source.index("/* Called at process() top level", start)
parser = source[start:end]

TEST = r"""
int main(void) {
    /* CCMP group/pairwise, PSK + SAE AKMs, MFPC (transition mode). */
    uint8_t ie[] = {48,24, 1,0, 0,15,172,4, 1,0, 0,15,172,4,
                    2,0, 0,15,172,2, 0,15,172,8, 128,0};
    struct conn_rsn_info r;
    assert(conn_parse_rsn(ie,sizeof(ie),&r)==0);
    assert(r.has_psk && !r.has_psk_sha256 && r.mfpc && !r.mfpr);
    assert(r.group_ccmp && r.pairwise_ccmp);
    /* SAE-only must never become PSK merely due to a scan label. */
    ie[19]=8;
    assert(conn_parse_rsn(ie,sizeof(ie),&r)==0);
    assert(!r.has_psk && !r.has_psk_sha256);
    ie[19]=6;
    assert(conn_parse_rsn(ie,sizeof(ie),&r)==0);
    assert(!r.has_psk && r.has_psk_sha256);
    ie[19]=2;
    /* Unsupported ciphers remain incompatible. */
    ie[7]=2;
    assert(conn_parse_rsn(ie,sizeof(ie),&r)==0 && !r.group_ccmp);
    ie[7]=4; ie[13]=2;
    assert(conn_parse_rsn(ie,sizeof(ie),&r)==0 && !r.pairwise_ccmp);
    ie[13]=4;
    for (unsigned n=0;n<sizeof(ie);n++) assert(conn_parse_rsn(ie,n,&r)!=0);
    assert(conn_parse_rsn(NULL,0,&r)!=0);
    ie[8]=255; assert(conn_parse_rsn(ie,sizeof(ie),&r)!=0);
    ie[8]=0; assert(conn_parse_rsn(ie,sizeof(ie),&r)!=0);
    ie[8]=1; ie[14]=255; assert(conn_parse_rsn(ie,sizeof(ie),&r)!=0);
    ie[14]=0; assert(conn_parse_rsn(ie,sizeof(ie),&r)!=0);
    puts("RSN: transition mode, SAE-only, SHA256, ciphers and malformed input pass");
}
"""

with tempfile.TemporaryDirectory() as directory:
    c = Path(directory) / "rsn.c"
    binary = Path(directory) / "rsn"
    c.write_text("#include <assert.h>\n#include <stdint.h>\n#include <string.h>\n"
                 "#include <stdio.h>\n#define nrf70_os_memset memset\n" + parser + TEST)
    subprocess.run([os.environ.get("CC", "cc"), "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=address,undefined", str(c), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
