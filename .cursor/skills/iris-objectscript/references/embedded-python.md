# Embedded Python & Language Interoperability

IRIS runs Python in the same process as ObjectScript. You can write whole methods
in Python, call Python libraries from ObjectScript, and call IRIS classes/globals
from Python. This file covers Embedded Python methods, the `iris` module, calling
in both directions, type mapping, and when to use the Native SDK instead.

Official docs: *Using Embedded Python* (`GEPYTHON_prereqs`), *InterSystems IRIS
Python Module Reference* (`GEPYTHON_reference`). See `doc-map.md`.

## Contents
1. When to use which
2. Python methods (`[ Language = python ]`)
3. Calling Python libraries from ObjectScript
4. Calling IRIS from Python (the `iris` module)
5. Type mapping
6. Sharing data and gotchas
7. Native SDK (out-of-process) vs Embedded

---

## 1. When to use which

- **Embedded Python method** — implement a class method in Python because a
  Python library does the job best (data science, ML, parsing). Runs in-process,
  full access to IRIS via `import iris`.
- **Call a Python library from ObjectScript** — you're mostly in ObjectScript but
  need one library call (e.g. `requests`, `numpy`).
- **Native SDK for Python** — a *separate* Python application (outside IRIS)
  connects to IRIS over a connection to call methods, run SQL, and manipulate
  globals. Use for external apps, notebooks, microservices.

Rule of thumb: keep each **method** in a single language; choose the language per
task. Don't try to write ObjectScript syntax inside a Python method or vice versa.

## 2. Python methods (`[ Language = python ]`)

Mark the method; the body is then ordinary Python (PEP 8, 4-space indent).

```objectscript
Class MyApp.Analytics Extends %RegisteredObject
{

ClassMethod MeanScore(csv As %String) As %Double [ Language = python ]
{
    # 'csv' arrives as a Python str (scalars convert automatically). A $List would
    # NOT be a Python list — pass scalars or convert explicitly (see Type mapping).
    import statistics
    values = [float(x) for x in csv.split(",") if x.strip() != ""] if csv else []
    return statistics.mean(values) if values else 0.0
}

ClassMethod Slugify(text As %String) As %String [ Language = python ]
{
    import re
    s = (text or "").strip().lower()
    return re.sub(r"[^a-z0-9]+", "-", s).strip("-")
}

}
```

- `self` is the instance in a non-class `Method [ Language = python ]`; access
  properties as `self.PropertyName`.
- Return a value with Python `return`. Raise errors with Python `raise`; they
  surface to ObjectScript callers as exceptions.
- You can mark the whole class `[ Language = python ]` to make Python the default
  for its members, overriding per method with `[ Language = objectscript ]`.

## 3. Calling Python libraries from ObjectScript

Import a module as an object and call it:

```objectscript
ClassMethod Fetch(url As %String) As %String
{
    Set requests = ##class(%SYS.Python).Import("requests")
    Set response = requests.get(url)
    Return response.text
}

ClassMethod Builtins()
{
    Set builtins = ##class(%SYS.Python).Builtins()   // Python builtins module
    Set pyList = builtins.list()
    Do pyList.append("a")
}
```

- `##class(%SYS.Python).Import("module")` → a Python module object; call functions
  as methods, read attributes as properties.
- `##class(%SYS.Python).Builtins()` exposes `list`, `dict`, `str`, etc. for
  constructing Python objects from ObjectScript.
- Install packages into the IRIS Python with
  `Do ##class(%SYS.Python).Shell()` then `pip`, or use the documented
  `irispip` / `pip install --target <iris>/lib/python` procedure
  (see `GEPYTHON_loadlib`).

## 4. Calling IRIS from Python (the `iris` module)

Inside any Embedded Python context, `import iris` gives you the platform:

```python
import iris

# Call a class method:
age = iris.cls("MyApp.Data.Patient").ComputeAge(birth)

# Open and use an object:
patient = iris.cls("MyApp.Data.Patient")._OpenId(pid)   # %OpenId -> _OpenId
name = patient.Name
patient.Name = "New Name"
patient._Save()                                          # %Save -> _Save

# Run SQL:
rs = iris.sql.exec("SELECT MRN, Name FROM MyApp_Data.Patient WHERE Status = ?", "Active")
for row in rs:
    print(row[0], row[1])

# Globals:
iris.gref("^MyApp.Counter")[None] = 0
val = iris.gref("^MyApp.Counter")[None]
```

Name translation: a `%`-prefixed ObjectScript method becomes `_`-prefixed in
Python (`%New` → `_New`, `%Save` → `_Save`, `%OpenId` → `_OpenId`). Reach classes
with `iris.cls("Package.Class")`. Run SQL via `iris.sql.exec(...)`. Access globals
via `iris.gref(...)`.

## 5. Type mapping

| ObjectScript | Python |
|---|---|
| `%String`, `%Integer`, `%Numeric`, `%Boolean` | `str`, `int`, `float`, `bool` |
| OREF (object) | a proxy object (attribute/method access works) |
| `$List` (`%List`) | not a native Python list — use helpers or pass as args |
| multidimensional array | use `iris.gref`/dict patterns, not direct |
| `%Stream` | proxy object with `.Read()`, `.Write()` methods |
| `""` (empty/undefined) | `None` or `""` depending on context |

Numbers and strings convert automatically across the boundary. Objects pass as
proxies. For `$List` and arrays, convert explicitly (build a Python list/dict).

## 6. Sharing data and gotchas

- One process, one Python interpreter per process: module-level state persists
  across calls within a process — don't rely on it for correctness across jobs.
- Exceptions cross the boundary: a Python `raise` becomes an ObjectScript
  exception (`%Exception`), and a thrown ObjectScript error becomes a Python
  exception. Handle on the side that can recover.
- Don't mix syntaxes in one method body. Don't call `Write`/`Set` in Python or
  `print`/`def` in ObjectScript.
- The *Flexible Python Runtime* lets an instance target a specific Python version;
  see `GEPYTHON_flexible` if the deployment pins Python.
- Embedded Python in interoperability productions: business hosts can be written
  in Python; see `GEPYTHON_productions` and `interoperability.md`.

## 7. Native SDK (out-of-process) vs Embedded

For a Python program running **outside** IRIS:

```python
import iris
conn = iris.connect("localhost", 1972, "USER", "user", "pass")
irispy = iris.createIRIS(conn)
irispy.set(0, "^MyApp.Counter")
value = irispy.get("^MyApp.Counter")
result = irispy.classMethodValue("MyApp.Data.Patient", "ComputeAge", birth)
conn.close()
```

- Use the Native SDK / DB-API (`intersystems-irispython` package) for external
  apps, ETL, notebooks. It connects over a network connection rather than running
  in-process.
- DB-API (`BPYDBAPI`) gives a standard PEP-249 relational interface; SQLAlchemy
  and Flask integrations exist (`GPYDEV_*`).

---

### Embedded Python checklist

- [ ] Method body is single-language; Python methods carry `[ Language = python ]`.
- [ ] `import iris` used to reach IRIS; `%`-methods called with `_` prefix.
- [ ] Python errors `raise`d; ObjectScript errors thrown — handled where recoverable.
- [ ] `$List`/array data converted explicitly at the boundary.
- [ ] External programs use the Native SDK/DB-API, not Embedded Python.
