/// __DESC__
/// Storage is omitted on purpose — the compiler generates it on first compile.
Class __PKG__.__CLASS__ Extends (%Persistent, %JSON.Adaptor)
{

Property Name As %String(MAXLEN = 100) [ Required ];

Property Status As %String(VALUELIST = ",Active,Inactive") [ InitialExpression = "Active" ];

Property CreatedAt As %TimeStamp [ InitialExpression = {$ZDateTime($Horolog, 3)}, ReadOnly ];

Index NameIndex On Name [ Unique ];

/// Cross-field validation; return an error %Status to veto the save.
Method %OnValidateObject() As %Status [ Private, ServerOnly = 1 ]
{
    Return $$$OK
}

}
