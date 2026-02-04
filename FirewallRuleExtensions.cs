using System;
using System.Runtime.InteropServices;
using SharedTypes = global::LibFirewall.Shared;

namespace LibFirewall
{
    internal static class FirewallRuleExtensions
    {
        internal static RuleAction ToNative(this SharedTypes.RuleAction action)
        {
            return (RuleAction)(uint)action;
        }

        internal static RuleDirection ToNative(this SharedTypes.RuleDirection direction)
        {
            return (RuleDirection)(uint)direction;
        }

        internal static ConnectionSecurityRuleType ToNative(this SharedTypes.ConnectionSecurityRuleType type)
        {
            return (ConnectionSecurityRuleType)(uint)type;
        }

        internal static SharedTypes.RuleAction FromNative(this RuleAction action)
        {
            return (SharedTypes.RuleAction)(uint)action;
        }

        internal static SharedTypes.RuleDirection FromNative(this RuleDirection direction)
        {
            return (SharedTypes.RuleDirection)(uint)direction;
        }

        internal static SharedTypes.ConnectionSecurityRuleType FromNative(this ConnectionSecurityRuleType type)
        {
            return (SharedTypes.ConnectionSecurityRuleType)(uint)type;
        }

        internal static unsafe InboundRule ToNative(this SharedTypes.FirewallInboundRule rule)
        {
            return new InboundRule
            {
                name = (byte*)Marshal.StringToCoTaskMemUTF8(rule.Name),
                description = (byte*)Marshal.StringToCoTaskMemUTF8(rule.Description),
                action = rule.Action.ToNative(),
                enabled = rule.Enabled,
                protocol = rule.Protocol,
                local_ports = (byte*)Marshal.StringToCoTaskMemUTF8(rule.LocalPorts),
                remote_ports = (byte*)Marshal.StringToCoTaskMemUTF8(rule.RemotePorts),
                local_addresses = (byte*)Marshal.StringToCoTaskMemUTF8(rule.LocalAddresses),
                remote_addresses = (byte*)Marshal.StringToCoTaskMemUTF8(rule.RemoteAddresses),
                profiles = rule.Profiles,
                interface_types = (byte*)Marshal.StringToCoTaskMemUTF8(rule.InterfaceTypes),
                edge_traversal = rule.EdgeTraversal,
                application_name = (byte*)Marshal.StringToCoTaskMemUTF8(rule.ApplicationName),
                service_name = (byte*)Marshal.StringToCoTaskMemUTF8(rule.ServiceName),
                grouping = (byte*)Marshal.StringToCoTaskMemUTF8(rule.Grouping),
                local_user_authorized_list = (byte*)Marshal.StringToCoTaskMemUTF8(""),
                remote_user_authorized_list = (byte*)Marshal.StringToCoTaskMemUTF8(""),
                remote_machine_authorized_list = (byte*)Marshal.StringToCoTaskMemUTF8("")
            };
        }

        internal static unsafe void FreeNative(InboundRule rule)
        {
            Marshal.FreeCoTaskMem((IntPtr)rule.name);
            Marshal.FreeCoTaskMem((IntPtr)rule.description);
            Marshal.FreeCoTaskMem((IntPtr)rule.local_ports);
            Marshal.FreeCoTaskMem((IntPtr)rule.remote_ports);
            Marshal.FreeCoTaskMem((IntPtr)rule.local_addresses);
            Marshal.FreeCoTaskMem((IntPtr)rule.remote_addresses);
            Marshal.FreeCoTaskMem((IntPtr)rule.interface_types);
            Marshal.FreeCoTaskMem((IntPtr)rule.application_name);
            Marshal.FreeCoTaskMem((IntPtr)rule.service_name);
            Marshal.FreeCoTaskMem((IntPtr)rule.grouping);
            Marshal.FreeCoTaskMem((IntPtr)rule.local_user_authorized_list);
            Marshal.FreeCoTaskMem((IntPtr)rule.remote_user_authorized_list);
            Marshal.FreeCoTaskMem((IntPtr)rule.remote_machine_authorized_list);
        }

        internal static unsafe SharedTypes.FirewallInboundRule FromNative(InboundRule native)
        {
            return new SharedTypes.FirewallInboundRule
            {
                Name = Marshal.PtrToStringUTF8((IntPtr)native.name) ?? "",
                Description = Marshal.PtrToStringUTF8((IntPtr)native.description) ?? "",
                Action = native.action.FromNative(),
                Enabled = native.enabled,
                Protocol = native.protocol,
                LocalPorts = Marshal.PtrToStringUTF8((IntPtr)native.local_ports) ?? "",
                RemotePorts = Marshal.PtrToStringUTF8((IntPtr)native.remote_ports) ?? "",
                LocalAddresses = Marshal.PtrToStringUTF8((IntPtr)native.local_addresses) ?? "",
                RemoteAddresses = Marshal.PtrToStringUTF8((IntPtr)native.remote_addresses) ?? "",
                Profiles = native.profiles,
                InterfaceTypes = Marshal.PtrToStringUTF8((IntPtr)native.interface_types) ?? "",
                EdgeTraversal = native.edge_traversal,
                ApplicationName = Marshal.PtrToStringUTF8((IntPtr)native.application_name) ?? "",
                ServiceName = Marshal.PtrToStringUTF8((IntPtr)native.service_name) ?? "",
                Grouping = Marshal.PtrToStringUTF8((IntPtr)native.grouping) ?? ""
            };
        }


        // FirewallOutboundRule
        internal static unsafe OutboundRule ToNative(this SharedTypes.FirewallOutboundRule rule)
        {
            return new OutboundRule
            {
                name = (byte*)Marshal.StringToCoTaskMemUTF8(rule.Name),
                description = (byte*)Marshal.StringToCoTaskMemUTF8(rule.Description),
                action = rule.Action.ToNative(),
                enabled = rule.Enabled,
                protocol = rule.Protocol,
                local_ports = (byte*)Marshal.StringToCoTaskMemUTF8(rule.LocalPorts),
                remote_ports = (byte*)Marshal.StringToCoTaskMemUTF8(rule.RemotePorts),
                local_addresses = (byte*)Marshal.StringToCoTaskMemUTF8(rule.LocalAddresses),
                remote_addresses = (byte*)Marshal.StringToCoTaskMemUTF8(rule.RemoteAddresses),
                profiles = rule.Profiles,
                interface_types = (byte*)Marshal.StringToCoTaskMemUTF8(rule.InterfaceTypes),
                edge_traversal = rule.EdgeTraversal,
                application_name = (byte*)Marshal.StringToCoTaskMemUTF8(rule.ApplicationName),
                service_name = (byte*)Marshal.StringToCoTaskMemUTF8(rule.ServiceName),
                grouping = (byte*)Marshal.StringToCoTaskMemUTF8(rule.Grouping),
                local_user_authorized_list = (byte*)Marshal.StringToCoTaskMemUTF8(""),
                remote_user_authorized_list = (byte*)Marshal.StringToCoTaskMemUTF8(""),
                remote_machine_authorized_list = (byte*)Marshal.StringToCoTaskMemUTF8("")
            };
        }

        internal static unsafe void FreeNative(OutboundRule rule)
        {
            Marshal.FreeCoTaskMem((IntPtr)rule.name);
            Marshal.FreeCoTaskMem((IntPtr)rule.description);
            Marshal.FreeCoTaskMem((IntPtr)rule.local_ports);
            Marshal.FreeCoTaskMem((IntPtr)rule.remote_ports);
            Marshal.FreeCoTaskMem((IntPtr)rule.local_addresses);
            Marshal.FreeCoTaskMem((IntPtr)rule.remote_addresses);
            Marshal.FreeCoTaskMem((IntPtr)rule.interface_types);
            Marshal.FreeCoTaskMem((IntPtr)rule.application_name);
            Marshal.FreeCoTaskMem((IntPtr)rule.service_name);
            Marshal.FreeCoTaskMem((IntPtr)rule.grouping);
            Marshal.FreeCoTaskMem((IntPtr)rule.local_user_authorized_list);
            Marshal.FreeCoTaskMem((IntPtr)rule.remote_user_authorized_list);
            Marshal.FreeCoTaskMem((IntPtr)rule.remote_machine_authorized_list);
        }

        internal static unsafe SharedTypes.FirewallOutboundRule FromNative(OutboundRule native)
        {
            return new SharedTypes.FirewallOutboundRule
            {
                Name = Marshal.PtrToStringUTF8((IntPtr)native.name) ?? "",
                Description = Marshal.PtrToStringUTF8((IntPtr)native.description) ?? "",
                Action = native.action.FromNative(),
                Enabled = native.enabled,
                Protocol = native.protocol,
                LocalPorts = Marshal.PtrToStringUTF8((IntPtr)native.local_ports) ?? "",
                RemotePorts = Marshal.PtrToStringUTF8((IntPtr)native.remote_ports) ?? "",
                LocalAddresses = Marshal.PtrToStringUTF8((IntPtr)native.local_addresses) ?? "",
                RemoteAddresses = Marshal.PtrToStringUTF8((IntPtr)native.remote_addresses) ?? "",
                Profiles = native.profiles,
                InterfaceTypes = Marshal.PtrToStringUTF8((IntPtr)native.interface_types) ?? "",
                EdgeTraversal = native.edge_traversal,
                ApplicationName = Marshal.PtrToStringUTF8((IntPtr)native.application_name) ?? "",
                ServiceName = Marshal.PtrToStringUTF8((IntPtr)native.service_name) ?? "",
                Grouping = Marshal.PtrToStringUTF8((IntPtr)native.grouping) ?? ""
            };
        }


        // FirewallConnectionRule
        internal static unsafe ConnectionRule ToNative(this SharedTypes.FirewallConnectionRule rule)
        {
            return new ConnectionRule
            {
                name = (byte*)Marshal.StringToCoTaskMemUTF8(rule.Name),
                description = (byte*)Marshal.StringToCoTaskMemUTF8(rule.Description),
                rule_type = rule.RuleType.ToNative(),
                enabled = rule.Enabled,
                profiles = rule.Profiles,
                local_addresses = (byte*)Marshal.StringToCoTaskMemUTF8(rule.LocalAddresses),
                remote_addresses = (byte*)Marshal.StringToCoTaskMemUTF8(rule.RemoteAddresses),
                endpoint1_ports = (byte*)Marshal.StringToCoTaskMemUTF8(rule.Endpoint1Ports),
                endpoint2_ports = (byte*)Marshal.StringToCoTaskMemUTF8(rule.Endpoint2Ports),
                protocol = rule.Protocol,
                auth_type = rule.AuthType
            };
        }

        internal static unsafe void FreeNative(ConnectionRule rule)
        {
            Marshal.FreeCoTaskMem((IntPtr)rule.name);
            Marshal.FreeCoTaskMem((IntPtr)rule.description);
            Marshal.FreeCoTaskMem((IntPtr)rule.local_addresses);
            Marshal.FreeCoTaskMem((IntPtr)rule.remote_addresses);
            Marshal.FreeCoTaskMem((IntPtr)rule.endpoint1_ports);
            Marshal.FreeCoTaskMem((IntPtr)rule.endpoint2_ports);
        }

        internal static unsafe SharedTypes.FirewallConnectionRule FromNative(ConnectionRule native)
        {
            return new SharedTypes.FirewallConnectionRule
            {
                Name = Marshal.PtrToStringUTF8((IntPtr)native.name) ?? "",
                Description = Marshal.PtrToStringUTF8((IntPtr)native.description) ?? "",
                RuleType = native.rule_type.FromNative(),
                Enabled = native.enabled,
                Profiles = native.profiles,
                LocalAddresses = Marshal.PtrToStringUTF8((IntPtr)native.local_addresses) ?? "",
                RemoteAddresses = Marshal.PtrToStringUTF8((IntPtr)native.remote_addresses) ?? "",
                Endpoint1Ports = Marshal.PtrToStringUTF8((IntPtr)native.endpoint1_ports) ?? "",
                Endpoint2Ports = Marshal.PtrToStringUTF8((IntPtr)native.endpoint2_ports) ?? "",
                Protocol = native.protocol,
                AuthType = native.auth_type
            };
        }
    }
}
