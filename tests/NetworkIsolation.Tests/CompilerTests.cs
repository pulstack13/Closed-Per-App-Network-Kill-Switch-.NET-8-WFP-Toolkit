using NetworkIsolation.Core;
using Xunit;

public class CompilerTests {
 private static AdapterInfo Adapter(ulong luid, bool up, bool v4, bool v6) => new(luid,Guid.NewGuid(),1,"test","test",6,up?"Up":"Down",v4?[System.Net.IPAddress.Loopback]:[],v6?[System.Net.IPAddress.IPv6Loopback]:[],[],10,10,false,up);
 [Fact] public void DisconnectedBindingHasBaseBlockAndNoPermit() { var p=new NetworkPolicy(AppIdentity.Executable("test.exe"),PolicyMode.Bind,[42],new(false)); var fs=WfpPlanCompiler.Compile(p,[Adapter(42,false,true,true)]); Assert.Equal(6,fs.Count); Assert.DoesNotContain(fs,x=>x.Action==FilterAction.Permit); Assert.Equal(6,fs.Count(x=>x.Action==FilterAction.Block)); }
 [Fact] public void UnassignedHasNoFilters() => Assert.Empty(WfpPlanCompiler.Compile(new(AppIdentity.Executable("test.exe"),PolicyMode.Unassigned,[],new()),[]));
}
