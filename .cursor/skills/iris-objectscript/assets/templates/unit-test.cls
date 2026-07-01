Include %occInclude

/// __DESC__  Run with:
///   set ^UnitTestRoot = "<path to src>"
///   do ##class(%UnitTest.Manager).RunTest("__PKG_PATH__","/noload/nodelete/recursive")
Class __PKG__.__CLASS__ Extends %UnitTest.TestCase
{

Method OnBeforeOneTest(testname As %String) As %Status
{
    // set up / reset fixtures for each test
    Return $$$OK
}

Method TestExample()
{
    Do $$$AssertEquals(1 + 1, 2, "arithmetic works")
    Do $$$AssertTrue($IsObject($This), "have a test instance")
    Do $$$AssertStatusOK($$$OK, "OK status passes")
}

Method OnAfterAllTests() As %Status
{
    // clean up test data so the suite is repeatable
    Return $$$OK
}

}
