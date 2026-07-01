/// A single clinical observation (e.g. a vital sign) for a patient.
/// Child side of a parent-child relationship with <class>HSDemo.Data.Patient</class>.
Class HSDemo.Data.Observation Extends (%Persistent, %JSON.Adaptor)
{

/// Owning patient. Parent reference; deleting the patient cascades to observations.
Relationship Patient As HSDemo.Data.Patient [ Cardinality = parent, Inverse = Observations ];

/// LOINC-style code for the observation (e.g. "8867-4" heart rate).
Property Code As %String(MAXLEN = 20) [ Required ];

Property Value As %Numeric [ Required ];

Property Unit As %String(MAXLEN = 20);

Property RecordedAt As %TimeStamp [ InitialExpression = {$ZDateTime($Horolog, 3)} ];

Index CodeIdx On Code;

}
