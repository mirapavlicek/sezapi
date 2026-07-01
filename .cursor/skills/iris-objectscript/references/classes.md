# Class Definitions Reference

How to define classes in UDL the way the compiler and the Class Definition
Reference expect. Covers class structure, the top-level keywords, and every
member type: parameters, properties, methods, relationships, indices, queries,
triggers, XData, projections, plus inheritance and callbacks.

Official docs: *Defining and Using Classes* (`GOBJ_intro`) and *Class Definition
Reference* (`ROBJ_classdef`). See `doc-map.md`.

## Contents
1. Class skeleton and class kinds
2. Top-level class keywords
3. Parameters
4. Properties (and property parameters)
5. Methods and ClassMethods
6. Data type classes
7. Inheritance
8. Callbacks (`%On*` methods)
9. Indices, foreign keys, triggers (summary — see persistence-and-sql.md)
10. Relationships
11. Queries
12. XData and Projections

---

## 1. Class skeleton and class kinds

```objectscript
Include %occInclude

/// One-line summary shown in the Class Reference.
/// Longer description can follow. Use <b>HTML</b> and {Class.Member} links.
Class MyApp.Data.Patient Extends (%Persistent, %JSON.Adaptor) [ Final ]
{

Parameter VERSION = 1;

Property MRN As %String(MAXLEN = 20) [ Required ];

Method GetAge() As %Integer
{
    Return ..ComputeAge(..BirthDate)
}

}
```

Choose the right **superclass** for the kind of object:

| Need | Extend |
|---|---|
| In-memory object, no persistence | `%RegisteredObject` |
| Persisted to disk + SQL table | `%Persistent` |
| Embeddable value stored inside another object (no own extent) | `%SerialObject` |
| A literal datatype (e.g. a custom `%String` subtype) | `%DataType` family (e.g. `%Library.String`) |
| Abstract base (no instances) | any, with `[ Abstract ]` |
| JSON (de)serialization | add `%JSON.Adaptor` |
| XML (de)serialization | add `%XML.Adaptor` |
| Populate test data | add `%Populate` |

`Extends (%Persistent, %JSON.Adaptor)` — the **first** class is the primary
superclass (defines storage and the inheritance of `$This`). Mixins come after.

## 2. Top-level class keywords

Placed in `[ ... ]` after `Extends (...)`:

- `Abstract` — cannot be instantiated.
- `Final` — cannot be subclassed (small performance win; use when extension isn't intended).
- `Owner` — SQL owner.
- `Sql­RowIdPrivate`, `SqlTableName = MyTable`, `SqlSchemaName` — control SQL projection.
- `DdlAllowed` — permit DDL changes to this class's table.
- `ClassType = persistent | serial | datatype | …` — usually inferred from the superclass.
- `ProcedureBlock` — (default On for new classes) enforce procedure-block scoping.
- `Language = objectscript | python` — default language for members (per-member overrides win).
- `Inheritance = left | right` — multiple-inheritance resolution order (left = default).
- `System` / `Hidden` / `NoExtent` — system/visibility/no-storage flags.

## 3. Parameters

Compile-time constants shared by all instances. Conventionally **UPPERCASE**.

```objectscript
Parameter MAXRETRIES As INTEGER = 3;
Parameter DOMAIN = "MyAppErrors";   // localization domain
Parameter DEFAULTGLOBAL = "^MyApp.Patient";
```

- Reference within the class: `..#MAXRETRIES`. From outside:
  `##class(Pkg.Cls).%GetParameter("MAXRETRIES")` or `$Parameter`.
- Override in subclasses by redeclaring. Many system behaviors are configured via
  parameters (e.g. property parameters `MAXLEN`, `VALUELIST`).

## 4. Properties (and property parameters)

```objectscript
Property Name As %String(MAXLEN = 100) [ Required ];
Property Status As %String(VALUELIST = ",Active,Inactive,Pending") [ InitialExpression = "Active" ];
Property CreatedAt As %TimeStamp [ InitialExpression = {$ZDateTime($Horolog, 3)} ];
Property Tags As list Of %String;
Property Scores As array Of %Numeric;
Property Address As MyApp.Data.Address;          // object-valued (reference or embedded serial)
Property FullName As %String [ Calculated, SqlComputed, SqlComputeCode = {Set {*} = {Last}_", "_{First}} ];
Property Secret As %String [ Private, Internal ];
Property Total As %Numeric [ Transient ];        // not stored
```

Common **property keywords**: `Required`, `Calculated`, `Transient`,
`Private`, `ReadOnly`, `InitialExpression`, `SqlComputed`/`SqlComputeCode`,
`Cardinality`/`Inverse` (relationships), `MultiDimensional`.

Common **property parameters** (in `( … )`): `MAXLEN`, `MINLEN`, `MAXVAL`,
`MINVAL`, `VALUELIST` (allowed display values), `DISPLAYLIST`, `PATTERN`,
`SCALE` (decimals), `TRUNCATE`, `XMLNAME`, `%JSONFIELDNAME`.

Collections: `list Of <type>` and `array Of <type>`; access via
`obj.Tags.Insert(v)`, `obj.Tags.GetAt(i)`, `obj.Scores.SetAt(v, key)`,
`.Count()`, `.GetNext(.key)`. Streams for large data: `%Stream.GlobalCharacter`,
`%Stream.GlobalBinary` (see persistence-and-sql.md).

Every property auto-generates **property methods**: `NameGet()`, `NameSet(val)`,
`NameIsValid(val)`, `NameDisplayToLogical()`, `NameLogicalToDisplay()`, etc.
Override them by defining a method named `<Prop>Get`/`<Prop>Set` to add behavior.

## 5. Methods and ClassMethods

```objectscript
/// Computes age in whole years.
ClassMethod ComputeAge(birth As %Date) As %Integer
{
    Return:birth="" 0
    Return $System.SQL.DATEDIFF("yyyy", birth, +$Horolog)
}

Method Activate() As %Status
{
    Set ..Status = "Active"
    Return ..%Save()
}
```

- `Method` — instance method; has `$This`/`..Prop`. `ClassMethod` — no instance,
  called as `##class(Pkg.Cls).Name()`.
- Signature: `Name(arg As Type = default, ByRef out As Type, Output result As Type) As ReturnType [ keywords ]`.
  - `ByRef` = pass by reference (caller uses `.var`); `Output` = pure out parameter.
  - Use `...args` for variable-length args; access via `args` array + `args` count.
- Method **keywords**: `Private`, `Internal`, `Final`, `Abstract`,
  `ServerOnly`, `SqlProc` (callable as SQL stored proc), `WebMethod`,
  `Language = python`, `ReturnResultsets`, `PlaceAfter`, `CodeMode = code |
  expression | objectgenerator` (generators).
- `CodeMode = objectgenerator` makes a **method generator** — the body runs at
  compile time to write the runtime code (advanced; see *Method & Trigger Generators*).
- Prefer `Return` to exit with a value; reserve `Quit` for blocks/loops.

## 6. Data type classes

Literal property types map to data type classes. Common ones:

`%String`, `%Integer`, `%Numeric`, `%Boolean`, `%Date`, `%Time`, `%TimeStamp`,
`%PosixTime`, `%Currency`, `%Double`, `%Decimal`, `%BigInt`, `%Binary`, `%Status`,
`%List`, `%Name`, `%EnumString`, `%Stream.GlobalCharacter`.

Each datatype has **logical** (stored), **display**, and **ODBC** forms, with
`LogicalToDisplay` / `DisplayToLogical` / `LogicalToOdbc` conversions and an
`IsValid` validator. Define a custom datatype by extending `%DataType` +
`%Library.String` (or the relevant base) and overriding these methods/parameters.

## 7. Inheritance

- Single primary superclass + multiple mixins via `Extends (A, B, C)`.
- `Inheritance = left` (default): when two superclasses define the same member,
  the **left-most** wins. `right` flips it.
- Subclass overrides a member by redefining it; call the inherited version with
  `##super(args)` inside the override.
- `%ClassName(1)` returns the most-derived class name of an instance (polymorphism).
- Abstract methods (`[ Abstract ]`) declare a contract subclasses must implement.

## 8. Callbacks (`%On*` methods)

Override these to hook into the object lifecycle. They return `%Status` (return an
error to **veto** the operation):

| Callback | Fires |
|---|---|
| `%OnNew(args)` | During `%New()` — initialize a new instance |
| `%OnBeforeSave(insert)` | Before `%Save()`; `insert`=1 for new objects — validate/derive here |
| `%OnAfterSave(insert)` | After a successful save |
| `%OnValidateObject()` | During validation (called by `%Save`) — cross-field checks |
| `%OnOpen()` / `%OnClose()` | After `%OpenId` / on object destruction |
| `%OnDelete(oid)` | A *ClassMethod* called during `%DeleteId` |
| `%OnAddToSaveSet` | When the object joins a save set (for graphs) |

```objectscript
Method %OnBeforeSave(insert As %Boolean) As %Status [ Private, ServerOnly = 1 ]
{
    Set:insert ..CreatedAt = $ZDateTime($Horolog, 3)
    If ..MRN = "" Return $$$ERROR($$$GeneralError, "MRN is required")
    Return $$$OK
}
```

## 9. Indices, foreign keys, triggers (summary)

Defined as class members; details and SQL behavior in
`references/persistence-and-sql.md`.

```objectscript
Index MRNIndex On MRN [ Unique ];
Index NameIdx On (LastName, FirstName);
Index StatusBitmap On Status [ Type = bitmap ];
ForeignKey ProviderFK(ProviderId) References MyApp.Data.Provider(ProviderIdKey);
Trigger LogChange [ Event = INSERT/UPDATE, Time = AFTER ] { … }
```

## 10. Relationships

One-to-many / parent-child links between persistent classes, kept consistent
automatically (a special bidirectional property):

```objectscript
// In Order:
Relationship Customer As MyApp.Customer [ Cardinality = one, Inverse = Orders ];
// In Customer:
Relationship Orders As MyApp.Order [ Cardinality = many, Inverse = Customer ];
```

- `Cardinality = one | many | parent | children`. `parent/children` make a
  dependent (cascade-delete) relationship; `one/many` an independent reference.
- Navigate: `order.Customer.Name`; iterate `customer.Orders.GetAt(i)` or via SQL.

## 11. Queries

Named, reusable result sets callable from object code or SQL:

```objectscript
Query ByStatus(status As %String) As %SQLQuery [ SqlProc ]
{
    SELECT ID, MRN, Name FROM MyApp.Data.Patient
    WHERE Status = :status
    ORDER BY Name
}
```

Run with `%SQL.Statement`/`%ResultSet`:
`Set rs = ##class(MyApp.Data.Patient).ByStatusFunc("Active")` (a generated class
query func), or `Do stmt.%PrepareClassQuery("MyApp.Data.Patient","ByStatus")`.
Custom (non-SQL) queries implement `Execute`/`Fetch`/`Close` methods.

## 12. XData and Projections

- **XData** — a named block of XML/JSON/text embedded in the class, read at
  runtime by a method. Used for BPL/DTL definitions, REST `UrlMap`, config:

  ```objectscript
  XData UrlMap [ XMLNamespace = "http://www.intersystems.com/urlmap" ]
  {
  <Routes>
    <Route Url="/patients/:id" Method="GET" Call="GetPatient"/>
  </Routes>
  }
  ```

- **Projection** — customize what happens at compile/delete time
  (`Projection X As %Projection.StudioDocument;`); advanced/codegen use.

---

### Class authoring checklist

- [ ] Correct superclass for the object kind; mixins after the primary class.
- [ ] `///` doc comment on the class and every public member.
- [ ] Properties typed precisely with parameters (`MAXLEN`, `VALUELIST`, …) and
      `Required`/`InitialExpression` where appropriate.
- [ ] Validation in `%OnValidateObject`/`%OnBeforeSave`, returning `%Status`.
- [ ] `Private`/`Internal` on members not part of the public contract.
- [ ] No hand-written `Storage` (let the compiler manage it) unless mapping legacy globals.
