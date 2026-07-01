# Persistence, Storage & SQL Reference

Persistent objects, the object API, storage and indices, Embedded and Dynamic
SQL, class queries, and transactions/locking. In IRIS the object, SQL, and global
views of data are the same data — keep them consistent.

Official docs: *Defining and Using Classes → Persistent Objects* (`GOBJ_persobj`),
*Using InterSystems SQL* (`GSQL_intro`), *InterSystems SQL Reference* (`RSQL_intro`),
*Developing Applications → Transaction Processing* (`GAPPS_tp`). See `doc-map.md`.

## Contents
1. The persistent object lifecycle (object API)
2. Storage — let the compiler own it
3. Indices
4. Embedded SQL
5. Dynamic SQL
6. Class queries & result sets
7. Streams
8. Transactions
9. Locking & concurrency
10. Unit testing data logic

---

## 1. The persistent object lifecycle (object API)

Extend `%Persistent`. Every saved object gets an **ID** (the row id) and an
**OID**. The class is also a SQL table `Package.Class` (dots → underscores in the
SQL schema, e.g. `MyApp.Data.Patient` → schema `MyApp_Data`, table `Patient`).

```objectscript
// CREATE
Set patient = ##class(MyApp.Data.Patient).%New()
Set patient.MRN = "12345"
Set patient.Name = "Novak, Jan"
Set sc = patient.%Save()                 // returns %Status
If $$$ISERR(sc) Quit sc
Set id = patient.%Id()                    // the new row id

// READ
Set patient = ##class(MyApp.Data.Patient).%OpenId(id, , .sc)
If '$IsObject(patient) Quit $$$ERROR($$$GeneralError, "not found")

// UPDATE
Set patient.Name = "Novak, Jan ml."
$$$ThrowOnError(patient.%Save())

// EXISTS / DELETE
If ##class(MyApp.Data.Patient).%ExistsId(id) {
    Set sc = ##class(MyApp.Data.Patient).%DeleteId(id)
}
```

Key methods (most return or take a `%Status`):

- `%New()`, `%Save([related])`, `%OpenId(id, concurrency, .sc)`,
  `%Open(oid, …)`, `%ExistsId(id)`, `%DeleteId(id)`, `%KillExtent()` (delete all —
  dev only), `%Id()`, `%GetSwizzleObject`, `%Reload()`, `%ValidateObject()`.
- `%Save` validates first (running `%OnValidateObject` and property validators),
  saves the whole object graph, and is transactional by default.
- Open with explicit **concurrency**: `%OpenId(id, concurrency)` where
  concurrency 0=no lock … 4=exclusive; default is from the class. See §9.

## 2. Storage — let the compiler own it

When you compile a `%Persistent` class, IRIS generates a `Storage Default`
definition (the `%Storage.Persistent` map) describing how properties map to the
data global (default `^MyApp.Data.PatientD`) and index global
(`^MyApp.Data.PatientI`).

- **Do not hand-edit `Storage`** for normal classes — add/rename properties and
  recompile; the compiler updates the map. Editing it risks data corruption.
- **Do** define `Storage` explicitly only when **mapping to pre-existing
  globals** (legacy data, custom layouts) using `%Storage.SQL` or a custom map.
- `DEFAULTGLOBAL` / `SqlTableName` / `Final` affect global and table naming.
- The id is by default a system-assigned integer; override with an `IdKey` index
  on business keys (see below) when you want the primary key to be meaningful.

## 3. Indices

Indices are class members and drive both SQL query plans and object lookups.

```objectscript
Index MRNIndex On MRN [ Unique ];                 // unique constraint + fast lookup
Index NameIdx On (LastName, FirstName);           // composite
Index StatusIdx On Status [ Type = bitmap ];      // bitmap: low-cardinality columns
Index TextIdx On (Notes) As %iFind.Index.Basic;   // iFind full-text
Index PatientIDKey On MRN [ IdKey, Unique ];       // make MRN the primary key (id)
```

- Types: standard, `bitmap` (few distinct values, great for `WHERE`/`GROUP BY`
  on large extents), `bitslice` (numeric range/aggregate), iFind (text).
- `Unique` enforces a constraint. `IdKey` makes the indexed property(ies) the row
  id — choose this for natural keys; otherwise leave the system id.
- Generated lookup methods: `<Index>Open(keys…)`, `<Index>Exists(keys…)`,
  `<Index>Delete(keys…)` — e.g. `##class(...).MRNIndexOpen("12345")`.
- After adding an index to a populated class, **rebuild** it:
  `Do ##class(MyApp.Data.Patient).%BuildIndices()`.

## 4. Embedded SQL

Compiled into the routine; best for fixed statements and tight loops. Host
variables are prefixed with `:` and must be ObjectScript variables. Always check
`SQLCODE` (0 = ok, 100 = no (more) rows, negative = error).

```objectscript
ClassMethod CountActive(Output count As %Integer) As %Status
{
    &sql(SELECT COUNT(*) INTO :count
         FROM MyApp_Data.Patient
         WHERE Status = 'Active')
    If SQLCODE < 0 Return $$$ERROR($$$SQLError, SQLCODE, $Get(%msg))
    Return $$$OK
}

// Cursor for multi-row:
ClassMethod ListActive() As %Status
{
    &sql(DECLARE C1 CURSOR FOR
         SELECT MRN, Name INTO :mrn, :name
         FROM MyApp_Data.Patient WHERE Status = 'Active')
    &sql(OPEN C1)
    For {
        &sql(FETCH C1)
        Quit:SQLCODE'=0
        Write mrn, " ", name, !
    }
    &sql(CLOSE C1)
    Return $Select(SQLCODE=100:$$$OK, 1:$$$ERROR($$$SQLError, SQLCODE, $Get(%msg)))
}
```

- `SQLCODE` and `%ROWCOUNT` are set after each `&sql(...)`. `%msg` holds error text.
- Embedded SQL is **static** — table/column names are fixed at compile time.

## 5. Dynamic SQL (preferred for flexible/runtime queries)

Use `%SQL.Statement`. **Always parameterize** with `?` placeholders — never
concatenate user input into the SQL text (injection + plan-cache bloat).

```objectscript
ClassMethod FindByStatus(status As %String) As %Status
{
    Set stmt = ##class(%SQL.Statement).%New()
    Set sc = stmt.%Prepare("SELECT ID, MRN, Name FROM MyApp_Data.Patient WHERE Status = ? ORDER BY Name")
    If $$$ISERR(sc) Return sc
    #dim rs As %SQL.StatementResult
    Set rs = stmt.%Execute(status)
    If rs.%SQLCODE < 0 Return $$$ERROR($$$SQLError, rs.%SQLCODE, rs.%Message)
    While rs.%Next() {
        Write rs.%Get("MRN"), " ", rs.%Get("Name"), !
        // or by position: rs.%GetData(1)
    }
    Return $$$OK
}
```

- `%Prepare` returns `%Status`; `%Execute(args…)` returns a
  `%SQL.StatementResult`. Check `rs.%SQLCODE` / `rs.%Message`.
- Iterate with `rs.%Next()`, read with `rs.%Get("Col")` or `rs.%GetData(n)`.
- For class queries: `stmt.%PrepareClassQuery("MyApp.Data.Patient","ByStatus")`.
- One-liner for quick use: `Set rs = ##class(%SQL.Statement).%ExecDirect(,"SELECT …", arg)`.

## 6. Class queries & result sets

Define reusable queries in the class (see classes.md §11). Consume via Dynamic
SQL (`%PrepareClassQuery`) or the generated `<Query>Func()` returning a result set.
Prefer `%SQL.Statement`/`%SQL.StatementResult` over the older `%ResultSet` and
`%Library.ResultSet` in new code.

## 7. Streams

For large character/binary data, use streams instead of `%String` (which is
length-limited):

```objectscript
Property Report As %Stream.GlobalCharacter;       // stored in its own global
// write:
Do patient.Report.Write("line 1"_$Char(13,10))
Do patient.Report.WriteLine("line 2")
$$$ThrowOnError(patient.%Save())
// read:
While 'patient.Report.AtEnd { Set chunk = patient.Report.Read(32000) }
Do patient.Report.Rewind()
```

- `%Stream.GlobalCharacter`/`GlobalBinary` (in DB), `%Stream.FileCharacter`/
  `FileBinary` (filesystem), `%Stream.TmpCharacter` (temp).
- Methods: `Write`, `WriteLine`, `Read(len)`, `ReadLine`, `Rewind`, `MoveToEnd`,
  `Size`, `AtEnd`, `CopyFrom(stream)`, `%Save`.

## 8. Transactions

Group multiple operations atomically. `%Save` is already transactional for one
object graph; wrap multi-object units explicitly:

```objectscript
ClassMethod TransferAll(fromId, toId) As %Status
{
    Set sc = $$$OK
    TSTART
    Try {
        $$$ThrowOnError(obj1.%Save())
        $$$ThrowOnError(obj2.%Save())
        TCOMMIT
    }
    Catch ex {
        TROLLBACK 1                  // roll back all nested levels
        Set sc = ex.AsStatus()
    }
    Return sc
}
```

- `TSTART` / `TCOMMIT` / `TROLLBACK` (use `TROLLBACK 1` to unwind all levels).
- `$TLevel` reports nesting depth. Transactions are journaled.
- Keep transactions short; do not hold them open across user interaction or
  long external calls. Combine with `Lock` for consistency (see §9).

## 9. Locking & concurrency

ObjectScript locks are advisory, name-based, and independent of the data:

```objectscript
Lock +^MyApp.Data.PatientD(id):10        // exclusive, 10-second timeout
If '$Test { Return $$$ERROR($$$GeneralError, "could not acquire lock") }
// … critical section …
Lock -^MyApp.Data.PatientD(id)            // release
```

- `Lock +name` acquire, `Lock -name` release, `Lock name` release-all-then-acquire.
- Suffix `:timeout`; check `$Test` (1 = acquired). `S` = shared, `E` = escalating.
- The object layer takes appropriate locks automatically based on the
  **concurrency** argument to `%OpenId`/`%Save`; explicit `Lock` is for custom
  invariants spanning multiple objects/globals.
- Locking + transactions together give ACID behavior; release locks in a
  `Catch`/`Finally`-style path so they aren't leaked.

## 10. Unit testing data logic

Use `%UnitTest` for non-trivial persistence/SQL logic.

```objectscript
Class MyApp.Tests.PatientTest Extends %UnitTest.TestCase
{
Method TestSaveAndOpen()
{
    Set p = ##class(MyApp.Data.Patient).%New()
    Set p.MRN = "T1", p.Name = "Test"
    Do $$$AssertStatusOK(p.%Save(), "save succeeds")
    Set id = p.%Id()
    Set p2 = ##class(MyApp.Data.Patient).%OpenId(id)
    Do $$$AssertEquals(p2.MRN, "T1", "round-trips MRN")
    Do $$$AssertStatusOK(##class(MyApp.Data.Patient).%DeleteId(id))
}
}
```

- Run: `Do ##class(%UnitTest.Manager).RunTest("MyApp.Tests", "/nodelete")`.
- Assert macros: `$$$AssertEquals`, `$$$AssertNotEquals`, `$$$AssertTrue`,
  `$$$AssertStatusOK`, `$$$AssertStatusNotOK`, `$$$AssertFilesSame`, …
- `OnBeforeAllTests`/`OnAfterAllTests`/`OnBeforeOneTest` set up and tear down
  fixtures; clean up test data so suites are repeatable.

---

### Persistence checklist

- [ ] Right base: `%Persistent` (own extent) vs `%SerialObject` (embedded).
- [ ] Every `%Save`/`%OpenId`/`%DeleteId` status checked or thrown.
- [ ] Indices on lookup/sort columns; bitmap for low-cardinality; rebuilt if added later.
- [ ] SQL parameterized (`?` / `:host`), `SQLCODE`/`%SQLCODE` checked.
- [ ] Multi-object writes wrapped in `TSTART/TCOMMIT` with `TROLLBACK` on error.
- [ ] No direct writes to storage globals; go through object or SQL.
- [ ] `%UnitTest` coverage for non-trivial logic; test data cleaned up.
