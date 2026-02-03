using System;
using System.Collections;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace LibFirewall
{
    public static class Firewall
    {
        public static bool Initialize()
        {
            return NativeMethods.firewall_init();
        }

        public static InboundRuleCollection GetInboundRules()
        {
            return QueryExecutor.Execute(new InboundRuleBuilder());
        }

        public static void AddInboundRule(FirewallInboundRule rule)
        {
            unsafe
            {
                var nativeRule = rule.ToNative();
                try
                {
                    if (!NativeMethods.firewall_add_inbound_rule(&nativeRule))
                    {
                        throw new Exception("Failed to add inbound rule.");
                    }
                }
                finally
                {
                    FirewallInboundRule.FreeNative(nativeRule);
                }
            }
        }

        public static void UpdateInboundRule(FirewallInboundRule rule)
        {
            unsafe
            {
                var nativeRule = rule.ToNative();
                try
                {
                    if (!NativeMethods.firewall_update_inbound_rule(&nativeRule))
                    {
                        throw new Exception("Failed to update inbound rule.");
                    }
                }
                finally
                {
                    FirewallInboundRule.FreeNative(nativeRule);
                }
            }
        }

        public static OutboundRuleCollection GetOutboundRules()
        {
            return QueryExecutor.Execute(new OutboundRuleBuilder());
        }

        public static void AddOutboundRule(FirewallOutboundRule rule)
        {
            unsafe
            {
                var nativeRule = rule.ToNative();
                try
                {
                    if (!NativeMethods.firewall_add_outbound_rule(&nativeRule))
                    {
                        throw new Exception("Failed to add outbound rule.");
                    }
                }
                finally
                {
                    FirewallOutboundRule.FreeNative(nativeRule);
                }
            }
        }

        public static void UpdateOutboundRule(FirewallOutboundRule rule)
        {
            unsafe
            {
                var nativeRule = rule.ToNative();
                try
                {
                    if (!NativeMethods.firewall_update_outbound_rule(&nativeRule))
                    {
                        throw new Exception("Failed to update outbound rule.");
                    }
                }
                finally
                {
                    FirewallOutboundRule.FreeNative(nativeRule);
                }
            }
        }

        public static ConnectionRuleCollection GetConnectionRules()
        {
            return QueryExecutor.Execute(new ConnectionRuleBuilder());
        }

        public static void AddConnectionRule(FirewallConnectionRule rule)
        {
            unsafe
            {
                var nativeRule = rule.ToNative();
                try
                {
                    if (!NativeMethods.firewall_add_connection_rule(&nativeRule))
                    {
                        throw new Exception("Failed to add connection rule.");
                    }
                }
                finally
                {
                    FirewallConnectionRule.FreeNative(nativeRule);
                }
            }
        }

        public static void UpdateConnectionRule(FirewallConnectionRule rule)
        {
            unsafe
            {
                var nativeRule = rule.ToNative();
                try
                {
                    if (!NativeMethods.firewall_update_connection_rule(&nativeRule))
                    {
                        throw new Exception("Failed to update connection rule.");
                    }
                }
                finally
                {
                    FirewallConnectionRule.FreeNative(nativeRule);
                }
            }
        }

        public static void DeleteConnectionRule(string name)
        {
            unsafe
            {
                var bytes = Encoding.UTF8.GetBytes(name);
                var bytesWithNull = new byte[bytes.Length + 1];
                Array.Copy(bytes, bytesWithNull, bytes.Length);
                bytesWithNull[bytes.Length] = 0;


                fixed (byte* pNameNull = bytesWithNull)
                {
                    if (!NativeMethods.firewall_delete_connection_rule(pNameNull))
                    {
                        throw new Exception("Failed to delete connection rule.");
                    }
                }
            }
        }

        public static void DeleteRule(string name)
        {
            unsafe
            {
                var bytes = Encoding.UTF8.GetBytes(name);
                var bytesWithNull = new byte[bytes.Length + 1];
                Array.Copy(bytes, bytesWithNull, bytes.Length);
                bytesWithNull[bytes.Length] = 0;

                fixed (byte* pName = bytesWithNull)
                {
                    if (!NativeMethods.firewall_delete_rule(pName))
                    {
                        throw new Exception("Failed to delete rule.");
                    }
                }
            }
        }
    }

    public interface IQueryBuilder<T>
    {
        T Build();
    }

    public static class QueryExecutor
    {
        public static T Execute<T>(IQueryBuilder<T> builder)
        {
            return builder.Build();
        }
    }

    public class InboundRuleBuilder : IQueryBuilder<InboundRuleCollection>
    {
        public InboundRuleCollection Build()
        {
            unsafe
            {
                int count = 0;
                var ptr = NativeMethods.firewall_get_inbound_rules(&count);
                return new InboundRuleCollection(ptr, count);
            }
        }
    }

    public class OutboundRuleBuilder : IQueryBuilder<OutboundRuleCollection>
    {
        public OutboundRuleCollection Build()
        {
            unsafe
            {
                int count = 0;
                var ptr = NativeMethods.firewall_get_outbound_rules(&count);
                return new OutboundRuleCollection(ptr, count);
            }
        }
    }

    public class ConnectionRuleBuilder : IQueryBuilder<ConnectionRuleCollection>
    {
        public ConnectionRuleCollection Build()
        {
            unsafe
            {
                int count = 0;
                var ptr = NativeMethods.firewall_get_connection_rules(&count);
                return new ConnectionRuleCollection(ptr, count);
            }
        }
    }

    public interface IFirewallRuleCollection : IDisposable, IEnumerable
    {
        int Count { get; }
    }

    // Managed classes for usage
    public class FirewallInboundRule
    {
        public string Name { get; set; } = "";
        public string Description { get; set; } = "";
        public RuleAction Action { get; set; } = RuleAction.Block;
        public bool Enabled { get; set; } = true;
        public int Protocol { get; set; } = 256; // Any
        public string LocalPorts { get; set; } = "";
        public string RemotePorts { get; set; } = "";
        public string LocalAddresses { get; set; } = "";
        public string RemoteAddresses { get; set; } = "";
        public int Profiles { get; set; } = int.MaxValue;
        public string InterfaceTypes { get; set; } = "All";
        public bool EdgeTraversal { get; set; } = false;
        public string ApplicationName { get; set; } = "";
        public string ServiceName { get; set; } = "";
        public string Grouping { get; set; } = "@FirewallAPI.dll,-23255";

        internal unsafe InboundRule ToNative()
        {
            return new InboundRule
            {
                name = (byte*)Marshal.StringToCoTaskMemUTF8(Name),
                description = (byte*)Marshal.StringToCoTaskMemUTF8(Description),
                action = Action,
                enabled = Enabled,
                protocol = Protocol,
                local_ports = (byte*)Marshal.StringToCoTaskMemUTF8(LocalPorts),
                remote_ports = (byte*)Marshal.StringToCoTaskMemUTF8(RemotePorts),
                local_addresses = (byte*)Marshal.StringToCoTaskMemUTF8(LocalAddresses),
                remote_addresses = (byte*)Marshal.StringToCoTaskMemUTF8(RemoteAddresses),
                profiles = Profiles,
                interface_types = (byte*)Marshal.StringToCoTaskMemUTF8(InterfaceTypes),
                edge_traversal = EdgeTraversal,
                application_name = (byte*)Marshal.StringToCoTaskMemUTF8(ApplicationName),
                service_name = (byte*)Marshal.StringToCoTaskMemUTF8(ServiceName),
                grouping = (byte*)Marshal.StringToCoTaskMemUTF8(Grouping),
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

        internal static unsafe FirewallInboundRule FromNative(InboundRule native)
        {
            return new FirewallInboundRule
            {
                Name = Marshal.PtrToStringUTF8((IntPtr)native.name) ?? "",
                Description = Marshal.PtrToStringUTF8((IntPtr)native.description) ?? "",
                Action = native.action,
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
    }

    public class FirewallOutboundRule
    {
        public string Name { get; set; } = "";
        public string Description { get; set; } = "";
        public RuleAction Action { get; set; } = RuleAction.Block;
        public bool Enabled { get; set; } = true;
        public int Protocol { get; set; } = 256;
        public string LocalPorts { get; set; } = "";
        public string RemotePorts { get; set; } = "";
        public string LocalAddresses { get; set; } = "";
        public string RemoteAddresses { get; set; } = "";
        public int Profiles { get; set; } = int.MaxValue;
        public string InterfaceTypes { get; set; } = "All";
        public bool EdgeTraversal { get; set; } = false;
        public string ApplicationName { get; set; } = "";
        public string ServiceName { get; set; } = "";
        public string Grouping { get; set; } = "@FirewallAPI.dll,-23255";

        internal unsafe OutboundRule ToNative()
        {
            return new OutboundRule
            {
                name = (byte*)Marshal.StringToCoTaskMemUTF8(Name),
                description = (byte*)Marshal.StringToCoTaskMemUTF8(Description),
                action = Action,
                enabled = Enabled,
                protocol = Protocol,
                local_ports = (byte*)Marshal.StringToCoTaskMemUTF8(LocalPorts),
                remote_ports = (byte*)Marshal.StringToCoTaskMemUTF8(RemotePorts),
                local_addresses = (byte*)Marshal.StringToCoTaskMemUTF8(LocalAddresses),
                remote_addresses = (byte*)Marshal.StringToCoTaskMemUTF8(RemoteAddresses),
                profiles = Profiles,
                interface_types = (byte*)Marshal.StringToCoTaskMemUTF8(InterfaceTypes),
                edge_traversal = EdgeTraversal,
                application_name = (byte*)Marshal.StringToCoTaskMemUTF8(ApplicationName),
                service_name = (byte*)Marshal.StringToCoTaskMemUTF8(ServiceName),
                grouping = (byte*)Marshal.StringToCoTaskMemUTF8(Grouping),
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

        internal static unsafe FirewallOutboundRule FromNative(OutboundRule native)
        {
            return new FirewallOutboundRule
            {
                Name = Marshal.PtrToStringUTF8((IntPtr)native.name) ?? "",
                Description = Marshal.PtrToStringUTF8((IntPtr)native.description) ?? "",
                Action = native.action,
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
    }

    public class FirewallConnectionRule
    {
        public string Name { get; set; } = "";
        public string Description { get; set; } = "";
        public ConnectionSecurityRuleType RuleType { get; set; } = ConnectionSecurityRuleType.Custom;
        public bool Enabled { get; set; } = true;
        public int Profiles { get; set; } = int.MaxValue;
        public string LocalAddresses { get; set; } = "";
        public string RemoteAddresses { get; set; } = "";
        public string Endpoint1Ports { get; set; } = "";
        public string Endpoint2Ports { get; set; } = "";
        public int Protocol { get; set; } = 256;
        public int AuthType { get; set; } = 0;

        internal unsafe ConnectionRule ToNative()
        {
            return new ConnectionRule
            {
                name = (byte*)Marshal.StringToCoTaskMemUTF8(Name),
                description = (byte*)Marshal.StringToCoTaskMemUTF8(Description),
                rule_type = RuleType,
                enabled = Enabled,
                profiles = Profiles,
                local_addresses = (byte*)Marshal.StringToCoTaskMemUTF8(LocalAddresses),
                remote_addresses = (byte*)Marshal.StringToCoTaskMemUTF8(RemoteAddresses),
                endpoint1_ports = (byte*)Marshal.StringToCoTaskMemUTF8(Endpoint1Ports),
                endpoint2_ports = (byte*)Marshal.StringToCoTaskMemUTF8(Endpoint2Ports),
                protocol = Protocol,
                auth_type = AuthType
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

        internal static unsafe FirewallConnectionRule FromNative(ConnectionRule native)
        {
            return new FirewallConnectionRule
            {
                Name = Marshal.PtrToStringUTF8((IntPtr)native.name) ?? "",
                Description = Marshal.PtrToStringUTF8((IntPtr)native.description) ?? "",
                RuleType = native.rule_type,
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

    public unsafe class InboundRuleCollection(InboundRule* ptr, int count) : IFirewallRuleCollection, IEnumerable<FirewallInboundRule>
    {
        private InboundRule* _ptr = ptr;
        private readonly int _count = count;
        private bool _disposed;

        public int Count => _count;

        public FirewallInboundRule this[int index]
        {
            get
            {
                if (index < 0 || index >= _count) throw new IndexOutOfRangeException();
                return FirewallInboundRule.FromNative(_ptr[index]);
            }
        }

        public IEnumerator<FirewallInboundRule> GetEnumerator()
        {
            for (int i = 0; i < _count; i++)
            {
                yield return this[i];
            }
        }

        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();

        public void Dispose()
        {
            if (!_disposed)
            {
                if (_ptr != null)
                {
                    NativeMethods.firewall_free_inbound_rules(_ptr, _count);
                    _ptr = null;
                }
                _disposed = true;
            }
            GC.SuppressFinalize(this);
        }
    }

    public unsafe class OutboundRuleCollection(OutboundRule* ptr, int count) : IFirewallRuleCollection, IEnumerable<FirewallOutboundRule>
    {
        private OutboundRule* _ptr = ptr;
        private readonly int _count = count;
        private bool _disposed;

        public int Count => _count;

        public FirewallOutboundRule this[int index]
        {
            get
            {
                if (index < 0 || index >= _count) throw new IndexOutOfRangeException();
                return FirewallOutboundRule.FromNative(_ptr[index]);
            }
        }

        public IEnumerator<FirewallOutboundRule> GetEnumerator()
        {
            for (int i = 0; i < _count; i++)
            {
                yield return this[i];
            }
        }

        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();

        public void Dispose()
        {
            if (!_disposed)
            {
                if (_ptr != null)
                {
                    NativeMethods.firewall_free_outbound_rules(_ptr, _count);
                    _ptr = null;
                }
                _disposed = true;
            }
            GC.SuppressFinalize(this);
        }
    }

    public unsafe class ConnectionRuleCollection(ConnectionRule* ptr, int count) : IFirewallRuleCollection, IEnumerable<FirewallConnectionRule>
    {
        private ConnectionRule* _ptr = ptr;
        private readonly int _count = count;
        private bool _disposed;

        public int Count => _count;

        public FirewallConnectionRule this[int index]
        {
            get
            {
                if (index < 0 || index >= _count) throw new IndexOutOfRangeException();
                return FirewallConnectionRule.FromNative(_ptr[index]);
            }
        }

        public IEnumerator<FirewallConnectionRule> GetEnumerator()
        {
            for (int i = 0; i < _count; i++)
            {
                yield return this[i];
            }
        }

        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();

        public void Dispose()
        {
            if (!_disposed)
            {
                if (_ptr != null)
                {
                    NativeMethods.firewall_free_connection_rules(_ptr, _count);
                    _ptr = null;
                }
                _disposed = true;
            }
            GC.SuppressFinalize(this);
        }
    }
}