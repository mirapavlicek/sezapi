/// __DESC__  HL7 -> message DTL transform (IRIS for Health). Field paths use
/// {SEG:field(repeat).component}. Edit visually in the DTL editor if preferred.
Class __PKG__.__CLASS__ Extends Ens.DataTransformDTL [ DependsOn = EnsLib.HL7.Message ]
{

Parameter IGNOREMISSINGSOURCE = 1;

XData DTL [ XMLNamespace = "http://www.intersystems.com/dtl" ]
{
<transform sourceClass="EnsLib.HL7.Message" targetClass="Ens.Request" create="new" language="objectscript">
  <assign value='source.{PID:3(1).1}' property='target.....' action='set'/>
</transform>
}

}
