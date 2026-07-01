/// Statistics helpers implemented in Embedded Python. Demonstrates a Python
/// method body, the `iris` module for running SQL from Python, and clean
/// ObjectScript<->Python interop. One language per method.
Class HSDemo.Util.Stats Extends %RegisteredObject
{

/// Mean of a comma-delimited list of numbers. Pure Python, no IRIS access.
ClassMethod Mean(csv As %String) As %Double [ Language = python ]
{
    import statistics
    values = [float(x) for x in csv.split(",") if x.strip() != ""] if csv else []
    return statistics.mean(values) if values else 0.0
}

/// Mean value of all observations with a given code for a patient (by MRN),
/// computed in Python over rows fetched from IRIS via SQL.
ClassMethod MeanObservation(mrn As %String, code As %String) As %Double [ Language = python ]
{
    import iris
    import statistics
    rs = iris.sql.exec(
        "SELECT o.Value FROM HSDemo_Data.Observation o "
        "JOIN HSDemo_Data.Patient p ON o.Patient = p.ID "
        "WHERE p.MRN = ? AND o.Code = ?",
        mrn, code)
    values = [float(row[0]) for row in rs]
    return statistics.mean(values) if values else 0.0
}

}
