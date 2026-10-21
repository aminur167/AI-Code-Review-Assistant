# NexusReview — Comprehensive Dataset & Vulnerability Report 📊

This document provides the full empirical dataset breakdown and reverse-engineered vulnerability taxonomy across all 5 supported programming languages (Python, C, C++, Java, JavaScript).

## 1. Summary Statistics (Datasets & Languages)

| Dataset Name | Total Samples | Vulnerable | Benign | Languages Covered |
|---|:---:|:---:|:---:|---|
| **MultiLang Benchmark** | 8,431 | 4,195 | 4,236 | `C++` (1032), `Python` (2853), `JavaScript` (1402), `Java` (1732), `C` (1412) |
| **NIST Juliet (In-Scope C/C++)** | 6,976 | 1,656 | 5,320 | `C` (6954), `C++` (22) |
| **OWASP Benchmark (Java v1.2)** | 2,740 | 1,415 | 1,325 | `Java` (2740) |
| **QuixBugs (Algorithmic)** | 164 | 82 | 82 | `Python` (84), `Java` (80) |
| **TOTAL** | **18,311** | **7,348** | **10,963** | **All 5 Languages** |

### Language Distribution across Entire Benchmark

| Language | Total Samples | Coverage Share |
|---|:---:|:---:|
| **Python** | 2,937 | 16.0% |
| **C** | 8,366 | 45.7% |
| **C++** | 1,054 | 5.8% |
| **Java** | 4,552 | 24.9% |
| **JavaScript** | 1,402 | 7.7% |

---

## 2. Harmonized 3-Class Vulnerability Taxonomy

### Class 1: Injection & Taint-Flow (Total: 3,485 cases)
> **Description:** Untrusted input flows without sanitization into security-critical sinks (SQL, OS commands, eval, template engines).

### Class 3: Logic, Crypto & Bad Practice (Total: 2,619 cases)
> **Description:** Algorithmic faults, hardcoded credentials, infinite loops, divide-by-zero, and dead store resource anomalies.

### Class 2: Memory & Buffer Safety (Total: 1,244 cases)
> **Description:** Unbounded buffer copies, dangerous memory API calls, and pointer corruption flaws primarily in compiled languages.


---

## 3. Concrete Code Evidence: [Sample Code -> Detected Bug]

Below are exact code snippets from each of the 5 programming languages demonstrating how specific defects are mapped to exact line numbers and CWE identifiers:

### Language: Python (`py_loop_vuln_2365`)

* **Category:** `Class 3: Logic, Crypto & Bad Practice`

* **Vulnerability:** `CWE-835`

* **Defective Line(s):** Line **3**

```python
def p():
    i = 0
    while i < 9:  // <--- BUG: CWE-835 at line 3
        print(i)
```

### Language: C (`c_sprintf_vuln_5665`)

* **Category:** `Class 2: Memory & Buffer Safety`

* **Vulnerability:** `CWE-120`

* **Defective Line(s):** Line **3**

```c
void f(char *s){
  char b[16];
  sprintf(b, "%s", s);  // <--- BUG: CWE-120 at line 3
}
```

### Language: C++ (`cpp_cmdi_vuln_6177`)

* **Category:** `Class 1: Injection & Taint-Flow`

* **Vulnerability:** `CWE-78`

* **Defective Line(s):** Line **3**

```cpp
#include <cstdlib>
void r(char *c){
  system(c);  // <--- BUG: CWE-78 at line 3
}
```

### Language: Java (`java_sqli_vuln_2731`)

* **Category:** `Class 1: Injection & Taint-Flow`

* **Vulnerability:** `CWE-89`

* **Defective Line(s):** Line **4**

```java
public class T {
  void q(String uid) throws Exception {
    String sql = "SELECT * FROM u WHERE id=" + uid;
    stmt.executeQuery(sql);  // <--- BUG: CWE-89 at line 4
  }
}
```

### Language: JavaScript (`js_innerhtml_vuln_7891`)

* **Category:** `Class 1: Injection & Taint-Flow`

* **Vulnerability:** `CWE-79`

* **Defective Line(s):** Line **3**

```javascript
function f(el){
  var x = req.body.data;
  el.innerHTML = x;  // <--- BUG: CWE-79 at line 3
}
```
