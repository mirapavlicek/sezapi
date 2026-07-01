/// __DESC__  BPL business process. Define the orchestration in the BPL XData
/// block (or edit it visually in the Business Process Designer).
Class __PKG__.__CLASS__ Extends Ens.BusinessProcessBPL
{

XData BPL [ XMLNamespace = "http://www.intersystems.com/bpl" ]
{
<process language="objectscript" request="Ens.Request" response="Ens.Response">
  <sequence>
    <call name="Forward" target="TargetConfigName" async="0">
      <request type="Ens.Request">
        <assign property="callrequest" value="request" action="set"/>
      </request>
      <response type="Ens.Response"/>
    </call>
  </sequence>
</process>
}

}
