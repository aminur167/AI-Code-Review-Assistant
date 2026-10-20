import json
from nexus_engine.pipeline import NexusPipeline

SAMPLES = {
    "Python": """import os, sqlite3, hashlib

API_KEY = "sk_live_51H8xSecretKey12345"

def get_user(conn, user_id):
    query = "SELECT * FROM users WHERE id = " + user_id
    conn.cursor().execute(query)

def handle_request():
    payload = request.args.get("cmd")
    forward(payload)

def forward(data):
    os.system(data)

def ratio(a):
    d = 0
    return a / d

def poll():
    i = 0
    while i < 100:
        print(i)
""",
    "C": """#include <string.h>
#include <stdlib.h>
#include <stdio.h>

void copy(char *src){
    char buf[16];
    strcpy(buf, src);
    system(src);
}

int main(){ 
    char n[64]; 
    gets(n); 
    copy(n); 
    return 0;
}
""",
    "C++": """#include <iostream>
#include <cstdlib>
#include <cstring>
using namespace std;

void process(char *user_input) {
    char buffer[16];
    strcpy(buffer, user_input);
    system(user_input);
}

int main() {
    char input[100];
    cin >> input;
    process(input);
    return 0;
}
""",
    "Java": """import java.io.*;
import java.sql.*;

public class VulnerableApp {
    public void executeQuery(Connection conn, String userId) throws SQLException {
        String sql = "SELECT * FROM accounts WHERE id = " + userId;
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery(sql);
    }

    public void runCommand(String command) throws IOException {
        Runtime.getRuntime().exec(command);
    }
}
""",
    "JavaScript": """const { exec } = require("child_process");

function processCommand(cmd) {
    eval(cmd);
    exec("cat " + cmd);
}

module.exports = { processCommand };
"""
}

pipeline = NexusPipeline(use_llm_xai=False)

print("=" * 75)
print("NEXUSREVIEW EMPIRICAL BENCHMARK & CLAIMS VERIFICATION REPORT")
print("=" * 75)

for lang, code in SAMPLES.items():
    print(f"\n[+] Language: {lang}")
    res = pipeline.run(code, language=lang)
    
    findings = res.get("findings", [])
    metrics = res.get("metrics", {})
    latency = res.get("latency", {})
    qs = res.get("quality_score", 0)
    
    loc = getattr(metrics, "lines_of_code", metrics.get("lines_of_code", "N/A"))
    mi = getattr(metrics, "maintainability_index", metrics.get("maintainability_index", 0.0))
    cc = getattr(metrics, "cyclomatic_complexity", metrics.get("cyclomatic_complexity", "N/A"))
    
    print(f"    - Metrics: LOC={loc}, QualityScore={qs}/100, MI={mi:.2f}, CC={cc}")
    print(f"    - Latency: total={latency.get('total', 0)*1000:.2f}ms (static={latency.get('static_only', 0)*1000:.2f}ms)")
    print(f"    - Total Findings: {len(findings)}")
    
    for i, f in enumerate(findings, 1):
        rule = f.get("rule_id", "N/A")
        cwe = f.get("cwe", "N/A")
        sev = f.get("severity", "N/A")
        msg = f.get("message", "")
        line = f.get("line", 0)
        print(f"      {i}. Line {line} | [{sev}] {rule} ({cwe}): {msg[:60]}...")
        if f.get("pdg_slice", {}).get("slice_lines"):
            print(f"         PDG slice lines: {f['pdg_slice']['slice_lines']}")
        if f.get("xai"):
            x = f["xai"]
            print(f"         XAI explanation: {x.get('root_cause', '')[:70]}...")

print("\n" + "=" * 75)
print("ALL 5 LANGUAGES CHECK COMPLETE")
print("=" * 75)
