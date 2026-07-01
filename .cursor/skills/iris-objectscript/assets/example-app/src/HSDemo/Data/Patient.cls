/// Demo patient record. Persistent (own SQL table + storage), JSON-serializable,
/// and populatable with random test data.
///
/// Storage is intentionally omitted: the class compiler generates a
/// <class>Storage Default</class> map on first compile. Do not hand-write it.
Class HSDemo.Data.Patient Extends (%Persistent, %JSON.Adaptor, %Populate)
{

/// Medical record number — the natural business key.
Property MRN As %String(MAXLEN = 20) [ Required ];

Property LastName As %String(MAXLEN = 100, POPSPEC = "LastName()") [ Required ];

Property FirstName As %String(MAXLEN = 100, POPSPEC = "FirstName()");

Property BirthDate As %Date(POPSPEC = "Date()");

Property Status As %String(DISPLAYLIST = ",Active,Inactive,Deceased", VALUELIST = ",A,I,D") [ InitialExpression = "A" ];

Property CreatedAt As %TimeStamp [ InitialExpression = {$ZDateTime($Horolog, 3)}, ReadOnly ];

/// Observations recorded for this patient (parent-child: cascade delete).
Relationship Observations As HSDemo.Data.Observation [ Cardinality = children, Inverse = Patient ];

/// "Last, First" computed for display and SQL.
Property FullName As %String(MAXLEN = 201) [ Calculated, SqlComputeCode = {Set {*} = {LastName} _ ", " _ {FirstName}}, SqlComputed ];

/// MRN is unique and used for fast lookup.
Index MRNIndex On MRN [ Unique ];

Index StatusIdx On Status [ Type = bitmap ];

/// Validate cross-field rules before every save; return an error %Status to veto.
Method %OnValidateObject() As %Status [ Private, ServerOnly = 1 ]
{
    If (..BirthDate '= ""), (..BirthDate > +$Horolog) {
        Return $$$ERROR($$$GeneralError, "BirthDate cannot be in the future")
    }
    Return $$$OK
}

/// Age in whole years as of <var>asOf</var> (defaults to today). Returns "" when unknown.
Method GetAge(asOf As %Date = {+$Horolog}) As %Integer
{
    Return:..BirthDate="" ""
    Return $System.SQL.Functions.DATEDIFF("yyyy", ..BirthDate, asOf)
}

}
