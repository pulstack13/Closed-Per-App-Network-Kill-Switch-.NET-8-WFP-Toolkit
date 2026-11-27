using System.Runtime.InteropServices;
using NetworkIsolation.Wfp;
using NetworkIsolation.Wfp.Native;

namespace NetworkIsolation.Tests;

public class WfpStructLayoutTests
{
    [Fact]
    public void X64UnionHasExpectedSize()
    {
        Assert.Equal(16, Marshal.SizeOf<WfpNative.VALUE>());
        Assert.Equal(16, Marshal.SizeOf<WfpNative.CVALUE>());
        Assert.Equal(16, Marshal.SizeOf<WfpNative.CONTEXT_UNION>());
    }

    [Fact]
    public void AddressStructuresHaveExpectedSize()
    {
        Assert.Equal(8, Marshal.SizeOf<WfpNative.FWP_V4_ADDR_AND_MASK>());
        Assert.Equal(17, Marshal.SizeOf<WfpNative.FWP_V6_ADDR_AND_MASK>());
    }

    [Fact]
    public void ConditionHasExpectedSizeAndOffsets()
    {
        Assert.Equal(40, Marshal.SizeOf<WfpNative.CONDITION>());
        if (!Environment.Is64BitProcess) return;

        Assert.Equal(0, (int)Marshal.OffsetOf<WfpNative.CONDITION>(nameof(WfpNative.CONDITION.field)));
        Assert.Equal(16, (int)Marshal.OffsetOf<WfpNative.CONDITION>(nameof(WfpNative.CONDITION.match)));
        Assert.Equal(24, (int)Marshal.OffsetOf<WfpNative.CONDITION>(nameof(WfpNative.CONDITION.value)));
    }

    [Fact]
    public void X64ManagementStructsMatchWindowsSdkAbi()
    {
        if (!Environment.Is64BitProcess) return;

        Assert.Equal(16, Marshal.SizeOf<WfpNative.DISPLAY>());
        Assert.Equal(16, Marshal.SizeOf<WfpNative.BLOB>());
        Assert.Equal(8, (int)Marshal.OffsetOf<WfpNative.BLOB>(nameof(WfpNative.BLOB.data)));

        Assert.Equal(20, Marshal.SizeOf<WfpNative.ACTION>());
        Assert.Equal(4, (int)Marshal.OffsetOf<WfpNative.ACTION>(nameof(WfpNative.ACTION.callout)));

        Assert.Equal(72, Marshal.SizeOf<WfpNative.SESSION>());
        Assert.Equal(0, (int)Marshal.OffsetOf<WfpNative.SESSION>(nameof(WfpNative.SESSION.sessionKey)));
        Assert.Equal(16, (int)Marshal.OffsetOf<WfpNative.SESSION>(nameof(WfpNative.SESSION.displayData)));
        Assert.Equal(32, (int)Marshal.OffsetOf<WfpNative.SESSION>(nameof(WfpNative.SESSION.flags)));
        Assert.Equal(36, (int)Marshal.OffsetOf<WfpNative.SESSION>(nameof(WfpNative.SESSION.txnWaitTimeoutInMSec)));
        Assert.Equal(40, (int)Marshal.OffsetOf<WfpNative.SESSION>(nameof(WfpNative.SESSION.processId)));
        Assert.Equal(48, (int)Marshal.OffsetOf<WfpNative.SESSION>(nameof(WfpNative.SESSION.sid)));
        Assert.Equal(56, (int)Marshal.OffsetOf<WfpNative.SESSION>(nameof(WfpNative.SESSION.username)));
        Assert.Equal(64, (int)Marshal.OffsetOf<WfpNative.SESSION>(nameof(WfpNative.SESSION.kernelMode)));

        Assert.Equal(64, Marshal.SizeOf<WfpNative.PROVIDER>());
        Assert.Equal(16, (int)Marshal.OffsetOf<WfpNative.PROVIDER>(nameof(WfpNative.PROVIDER.displayData)));
        Assert.Equal(32, (int)Marshal.OffsetOf<WfpNative.PROVIDER>(nameof(WfpNative.PROVIDER.flags)));
        Assert.Equal(40, (int)Marshal.OffsetOf<WfpNative.PROVIDER>(nameof(WfpNative.PROVIDER.providerData)));
        Assert.Equal(56, (int)Marshal.OffsetOf<WfpNative.PROVIDER>(nameof(WfpNative.PROVIDER.serviceName)));

        Assert.Equal(72, Marshal.SizeOf<WfpNative.SUBLAYER>());
        Assert.Equal(16, (int)Marshal.OffsetOf<WfpNative.SUBLAYER>(nameof(WfpNative.SUBLAYER.displayData)));
        Assert.Equal(32, (int)Marshal.OffsetOf<WfpNative.SUBLAYER>(nameof(WfpNative.SUBLAYER.flags)));
        Assert.Equal(40, (int)Marshal.OffsetOf<WfpNative.SUBLAYER>(nameof(WfpNative.SUBLAYER.providerKey)));
        Assert.Equal(48, (int)Marshal.OffsetOf<WfpNative.SUBLAYER>(nameof(WfpNative.SUBLAYER.providerData)));
        Assert.Equal(64, (int)Marshal.OffsetOf<WfpNative.SUBLAYER>(nameof(WfpNative.SUBLAYER.weight)));

        Assert.Equal(200, Marshal.SizeOf<WfpNative.FILTER>());
        Assert.Equal(16, (int)Marshal.OffsetOf<WfpNative.FILTER>(nameof(WfpNative.FILTER.display)));
        Assert.Equal(32, (int)Marshal.OffsetOf<WfpNative.FILTER>(nameof(WfpNative.FILTER.flags)));
        Assert.Equal(40, (int)Marshal.OffsetOf<WfpNative.FILTER>(nameof(WfpNative.FILTER.providerKey)));
        Assert.Equal(48, (int)Marshal.OffsetOf<WfpNative.FILTER>(nameof(WfpNative.FILTER.providerData)));
        Assert.Equal(64, (int)Marshal.OffsetOf<WfpNative.FILTER>(nameof(WfpNative.FILTER.layerKey)));
        Assert.Equal(80, (int)Marshal.OffsetOf<WfpNative.FILTER>(nameof(WfpNative.FILTER.sublayerKey)));
        Assert.Equal(96, (int)Marshal.OffsetOf<WfpNative.FILTER>(nameof(WfpNative.FILTER.weight)));
        Assert.Equal(112, (int)Marshal.OffsetOf<WfpNative.FILTER>(nameof(WfpNative.FILTER.numConditions)));
        Assert.Equal(120, (int)Marshal.OffsetOf<WfpNative.FILTER>(nameof(WfpNative.FILTER.conditions)));
        Assert.Equal(128, (int)Marshal.OffsetOf<WfpNative.FILTER>(nameof(WfpNative.FILTER.action)));
        Assert.Equal(152, (int)Marshal.OffsetOf<WfpNative.FILTER>(nameof(WfpNative.FILTER.context)));
        Assert.Equal(168, (int)Marshal.OffsetOf<WfpNative.FILTER>(nameof(WfpNative.FILTER.reserved)));
        Assert.Equal(176, (int)Marshal.OffsetOf<WfpNative.FILTER>(nameof(WfpNative.FILTER.filterId)));
        Assert.Equal(184, (int)Marshal.OffsetOf<WfpNative.FILTER>(nameof(WfpNative.FILTER.effectiveWeight)));

        Assert.Equal(72, Marshal.SizeOf<WfpNative.ENUM_TEMPLATE>());
        Assert.Equal(0, (int)Marshal.OffsetOf<WfpNative.ENUM_TEMPLATE>(nameof(WfpNative.ENUM_TEMPLATE.providerKey)));
        Assert.Equal(8, (int)Marshal.OffsetOf<WfpNative.ENUM_TEMPLATE>(nameof(WfpNative.ENUM_TEMPLATE.layerKey)));
        Assert.Equal(24, (int)Marshal.OffsetOf<WfpNative.ENUM_TEMPLATE>(nameof(WfpNative.ENUM_TEMPLATE.enumType)));
        Assert.Equal(28, (int)Marshal.OffsetOf<WfpNative.ENUM_TEMPLATE>(nameof(WfpNative.ENUM_TEMPLATE.flags)));
        Assert.Equal(32, (int)Marshal.OffsetOf<WfpNative.ENUM_TEMPLATE>(nameof(WfpNative.ENUM_TEMPLATE.providerContextTemplate)));
        Assert.Equal(40, (int)Marshal.OffsetOf<WfpNative.ENUM_TEMPLATE>(nameof(WfpNative.ENUM_TEMPLATE.numFilterConditions)));
        Assert.Equal(48, (int)Marshal.OffsetOf<WfpNative.ENUM_TEMPLATE>(nameof(WfpNative.ENUM_TEMPLATE.filterCondition)));
        Assert.Equal(56, (int)Marshal.OffsetOf<WfpNative.ENUM_TEMPLATE>(nameof(WfpNative.ENUM_TEMPLATE.actionMask)));
        Assert.Equal(64, (int)Marshal.OffsetOf<WfpNative.ENUM_TEMPLATE>(nameof(WfpNative.ENUM_TEMPLATE.calloutKey)));
    }

    [Fact]
    public void CidrParsingProducesHostOrderV4AndNetworkOrderV6()
    {
        var v4 = WfpEngineManager.ParseIPv4Cidr("127.0.0.0/8");
        Assert.Equal(0x7F000000u, v4.addr);
        Assert.Equal(0xFF000000u, v4.mask);

        var v4Default = WfpEngineManager.ParseIPv4Cidr("0.0.0.0/0");
        Assert.Equal(0u, v4Default.addr);
        Assert.Equal(0u, v4Default.mask);

        var v6 = WfpEngineManager.ParseIPv6Cidr("::1/128");
        Assert.Equal((byte)0, v6.a0);
        Assert.Equal((byte)1, v6.a15);
        Assert.Equal((byte)128, v6.prefix);
    }
}
