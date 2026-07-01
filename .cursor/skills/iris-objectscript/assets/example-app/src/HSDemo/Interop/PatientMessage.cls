/// Interoperability message carrying a patient registration event between
/// business hosts. Extends Ens.Request so it is persisted and traceable.
Class HSDemo.Interop.PatientMessage Extends Ens.Request
{

Property MRN As %String(MAXLEN = 20) [ Required ];

Property LastName As %String(MAXLEN = 100);

Property FirstName As %String(MAXLEN = 100);

}
