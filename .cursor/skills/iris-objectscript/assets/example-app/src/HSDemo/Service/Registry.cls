Include %occInclude

/// Business-logic facade for the patient registry. Pure ObjectScript, returns
/// %Status, demonstrates the object API, Dynamic SQL, and transactions.
Class HSDemo.Service.Registry Extends %RegisteredObject
{

/// Register a new patient, or update the existing one with the same MRN.
/// Returns the patient id in <var>pId</var>.
ClassMethod RegisterPatient(mrn As %String, last As %String, first As %String = "", birth As %Date = "", Output pId As %Integer) As %Status
{
    Set sc = $$$OK
    Set pId = ""
    TSTART
    Try {
        If mrn = "" $$$ThrowStatus($$$ERROR($$$GeneralError, "MRN is required"))

        // Reuse the existing record for this MRN if present (idempotent register).
        Set patient = ##class(HSDemo.Data.Patient).MRNIndexOpen(mrn, 4, .sc)
        If '$IsObject(patient) {
            Set patient = ##class(HSDemo.Data.Patient).%New()
            Set patient.MRN = mrn
        }
        Set patient.LastName = last
        Set:first'="" patient.FirstName = first
        Set:birth'="" patient.BirthDate = birth

        $$$ThrowOnError(patient.%Save())
        Set pId = patient.%Id()
        TCOMMIT
    }
    Catch ex {
        TROLLBACK 1
        Set sc = ex.AsStatus()
    }
    Return sc
}

/// Add an observation to the patient identified by <var>mrn</var>.
ClassMethod AddObservation(mrn As %String, code As %String, value As %Numeric, unit As %String = "") As %Status
{
    Set sc = $$$OK
    Try {
        Set patient = ##class(HSDemo.Data.Patient).MRNIndexOpen(mrn, 4, .sc)
        If '$IsObject(patient) Return $$$ERROR($$$GeneralError, "Unknown MRN: " _ mrn)

        Set obs = ##class(HSDemo.Data.Observation).%New()
        Set obs.Patient = patient
        Set obs.Code = code
        Set obs.Value = value
        Set obs.Unit = unit
        $$$ThrowOnError(obs.%Save())
    }
    Catch ex {
        Set sc = ex.AsStatus()
    }
    Return sc
}

/// Find a patient object by MRN. Returns "" (and an error %Status) when not found.
ClassMethod FindByMRN(mrn As %String, Output sc As %Status) As HSDemo.Data.Patient
{
    Set sc = $$$OK
    Set patient = ##class(HSDemo.Data.Patient).MRNIndexOpen(mrn, 4, .sc)
    If '$IsObject(patient) {
        Set sc = $$$ERROR($$$GeneralError, "Unknown MRN: " _ mrn)
        Return ""
    }
    Return patient
}

/// Count patients by status using Dynamic SQL (parameterized — never concatenate input).
ClassMethod CountByStatus(status As %String, Output count As %Integer) As %Status
{
    Set count = 0
    Set stmt = ##class(%SQL.Statement).%New()
    Set sc = stmt.%Prepare("SELECT COUNT(*) AS Cnt FROM HSDemo_Data.Patient WHERE Status = ?")
    If $$$ISERR(sc) Return sc
    #dim rs As %SQL.StatementResult = stmt.%Execute(status)
    If rs.%SQLCODE < 0 Return $$$ERROR($$$SQLError, rs.%SQLCODE, rs.%Message)
    If rs.%Next() Set count = rs.%Get("Cnt")
    Return $$$OK
}

}
