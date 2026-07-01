/// Demo interoperability production. Hosts the file-writing business operation.
/// Open it in the Management Portal (Interoperability > Configure > Production)
/// after compiling, then start it to test message flow.
Class HSDemo.Interop.Production Extends Ens.Production
{

XData ProductionDefinition
{
<Production Name="HSDemo.Interop.Production" TestingEnabled="true" LogGeneralTraceEvents="false">
  <Description>Demo production for the HSDemo patient registry.</Description>
  <ActorPoolSize>1</ActorPoolSize>
  <Item Name="Patient File Out" Category="" ClassName="HSDemo.Interop.FileOperation" PoolSize="1" Enabled="true" Foreground="false" Comment="" LogTraceEvents="false" Schedule="">
    <Setting Target="Adapter" Name="FilePath">/tmp</Setting>
    <Setting Target="Host" Name="Filename">patients.txt</Setting>
  </Item>
</Production>
}

}
