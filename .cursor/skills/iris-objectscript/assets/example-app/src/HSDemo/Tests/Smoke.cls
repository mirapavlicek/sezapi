Include %occInclude

/// Deterministic smoke test used as the build gate by the Docker harness.
/// Unlike the %UnitTest suite (which records results in a global), this returns
/// a plain %Status so a CI script can fail the build on the first problem.
Class HSDemo.Tests.Smoke Extends %RegisteredObject
{

/// Run all smoke checks. Returns an error %Status on the first failure.
ClassMethod Run() As %Status
{
    Set sc = $$$OK
    Try {
        Do ##class(HSDemo.Data.Observation).%KillExtent()
        Do ##class(HSDemo.Data.Patient).%KillExtent()

        // Object API + transaction + computed property
        $$$ThrowOnError(##class(HSDemo.Service.Registry).RegisterPatient("SMK1", "Smoke", "Test", $ZDateH("1990-01-01", 3), .id))
        Do ..Check(+id > 0, "patient id assigned")
        Set p = ##class(HSDemo.Service.Registry).FindByMRN("SMK1", .fsc)
        $$$ThrowOnError(fsc)
        Do ..Check(p.FullName = "Smoke, Test", "computed FullName")

        // Observations + Embedded Python over SQL
        $$$ThrowOnError(##class(HSDemo.Service.Registry).AddObservation("SMK1", "8867-4", 70))
        $$$ThrowOnError(##class(HSDemo.Service.Registry).AddObservation("SMK1", "8867-4", 72))
        $$$ThrowOnError(##class(HSDemo.Service.Registry).AddObservation("SMK1", "8867-4", 74))
        Do ..Check(##class(HSDemo.Util.Stats).MeanObservation("SMK1", "8867-4") = 72, "Python+SQL mean = 72")
        Do ..Check(##class(HSDemo.Util.Stats).Mean("70,72,74") = 72, "Python mean = 72")

        // Dynamic SQL
        $$$ThrowOnError(##class(HSDemo.Service.Registry).CountByStatus("A", .cnt))
        Do ..Check(cnt = 1, "one active patient")

        // Validation callback vetoes a bad save
        Set bad = ##class(HSDemo.Data.Patient).%New()
        Set bad.MRN = "SMK2", bad.LastName = "Future", bad.BirthDate = +$Horolog + 365
        Do ..Check($$$ISERR(bad.%Save()), "future BirthDate rejected")

        Do ##class(HSDemo.Data.Observation).%KillExtent()
        Do ##class(HSDemo.Data.Patient).%KillExtent()
    }
    Catch ex {
        Set sc = ex.AsStatus()
    }
    Return sc
}

/// Throw a labelled exception when a condition is false; print on success.
ClassMethod Check(condition As %Boolean, label As %String) [ Private ]
{
    If 'condition {
        Throw ##class(%Exception.General).%New("SmokeAssertFailed", 5001, , "FAILED: " _ label)
    }
    Write "  ok - ", label, !
}

}
