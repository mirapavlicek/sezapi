Include %occInclude

/// Unit tests for the HSDemo registry. Run with:
///   Do ##class(%UnitTest.Manager).RunTest("HSDemo.Tests", "/nodelete")
/// or via the bundled harness (assets/docker/run.sh), which loads, compiles,
/// and runs these tests, failing the build on any assertion failure.
Class HSDemo.Tests.RegistryTest Extends %UnitTest.TestCase
{

/// Start each test from a clean extent so tests are independent and repeatable.
Method OnBeforeOneTest(testname As %String) As %Status
{
    Do ##class(HSDemo.Data.Observation).%KillExtent()
    Do ##class(HSDemo.Data.Patient).%KillExtent()
    Return $$$OK
}

Method TestRegisterAndFind()
{
    Set sc = ##class(HSDemo.Service.Registry).RegisterPatient("UT001", "Test", "Alice", $ZDateH("1990-01-01", 3), .id)
    Do $$$AssertStatusOK(sc, "RegisterPatient succeeds")
    Do $$$AssertTrue(+id > 0, "a positive id is returned")

    Set patient = ##class(HSDemo.Service.Registry).FindByMRN("UT001", .sc)
    Do $$$AssertStatusOK(sc, "FindByMRN succeeds")
    Do $$$AssertTrue($IsObject(patient), "patient object returned")
    Do $$$AssertEquals(patient.FullName, "Test, Alice", "computed FullName is correct")

    // Re-registering the same MRN updates rather than duplicates.
    Set sc = ##class(HSDemo.Service.Registry).RegisterPatient("UT001", "Updated", , , .id2)
    Do $$$AssertStatusOK(sc, "idempotent re-register succeeds")
    Set count = ##class(HSDemo.Data.Patient).MRNIndexExists("UT001")
    Do $$$AssertTrue(count, "MRN still exists exactly once")

    Set missing = ##class(HSDemo.Service.Registry).FindByMRN("NOPE", .sc)
    Do $$$AssertStatusNotOK(sc, "unknown MRN yields an error status")
    Do $$$AssertTrue('$IsObject(missing), "no object for unknown MRN")
}

Method TestObservationsAndSQL()
{
    Do $$$AssertStatusOK(##class(HSDemo.Service.Registry).RegisterPatient("UT002", "Vitals", "Bob", , .id))
    Do $$$AssertStatusOK(##class(HSDemo.Service.Registry).AddObservation("UT002", "8867-4", 70, "/min"))
    Do $$$AssertStatusOK(##class(HSDemo.Service.Registry).AddObservation("UT002", "8867-4", 72, "/min"))
    Do $$$AssertStatusOK(##class(HSDemo.Service.Registry).AddObservation("UT002", "8867-4", 74, "/min"))

    Set sc = ##class(HSDemo.Service.Registry).CountByStatus("A", .cnt)
    Do $$$AssertStatusOK(sc, "CountByStatus runs")
    Do $$$AssertEquals(cnt, 1, "one active patient")

    Set mean = ##class(HSDemo.Util.Stats).MeanObservation("UT002", "8867-4")
    Do $$$AssertEquals(mean, 72, "mean heart rate computed in Python over SQL rows")
}

Method TestPythonMean()
{
    Do $$$AssertEquals(##class(HSDemo.Util.Stats).Mean("70,72,74"), 72, "Python mean of csv")
    Do $$$AssertEquals(##class(HSDemo.Util.Stats).Mean(""), 0, "empty input -> 0")
}

Method TestValidationVetoesFutureBirthDate()
{
    Set patient = ##class(HSDemo.Data.Patient).%New()
    Set patient.MRN = "UT003"
    Set patient.LastName = "Future"
    Set patient.BirthDate = +$Horolog + 365   // ~one year from now
    Set sc = patient.%Save()
    Do $$$AssertStatusNotOK(sc, "future BirthDate is rejected by %OnValidateObject")
}

Method OnAfterAllTests() As %Status
{
    Do ##class(HSDemo.Data.Observation).%KillExtent()
    Do ##class(HSDemo.Data.Patient).%KillExtent()
    Return $$$OK
}

}
