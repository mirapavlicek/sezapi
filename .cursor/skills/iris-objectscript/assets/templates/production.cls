/// __DESC__  Interoperability production. Add <Item> entries for each business
/// host; the Management Portal edits this XData for you.
Class __PKG__.__CLASS__ Extends Ens.Production
{

XData ProductionDefinition
{
<Production Name="__PKG__.__CLASS__" TestingEnabled="true" LogGeneralTraceEvents="false">
  <Description>__DESC__</Description>
  <ActorPoolSize>1</ActorPoolSize>
  <Item Name="My Operation" ClassName="__PKG__.MyOperation" PoolSize="1" Enabled="true">
    <Setting Target="Host" Name="SettingName">value</Setting>
  </Item>
</Production>
}

}
