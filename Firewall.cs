using System;
using System.Collections;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using SharedTypes = global::LibFirewall.Shared;

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

        public static void AddInboundRule(SharedTypes.FirewallInboundRule rule)
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
                    FirewallRuleExtensions.FreeNative(nativeRule);
                }
            }
        }

        public static void UpdateInboundRule(SharedTypes.FirewallInboundRule rule)
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
                    FirewallRuleExtensions.FreeNative(nativeRule);
                }
            }
        }

        public static OutboundRuleCollection GetOutboundRules()
        {
            return QueryExecutor.Execute(new OutboundRuleBuilder());
        }

        public static void AddOutboundRule(SharedTypes.FirewallOutboundRule rule)
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
                    FirewallRuleExtensions.FreeNative(nativeRule);
                }
            }
        }

        public static void UpdateOutboundRule(SharedTypes.FirewallOutboundRule rule)
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
                    FirewallRuleExtensions.FreeNative(nativeRule);
                }
            }
        }

        public static ConnectionRuleCollection GetConnectionRules()
        {
            return QueryExecutor.Execute(new ConnectionRuleBuilder());
        }

        public static void AddConnectionRule(SharedTypes.FirewallConnectionRule rule)
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
                    FirewallRuleExtensions.FreeNative(nativeRule);
                }
            }
        }

        public static void UpdateConnectionRule(SharedTypes.FirewallConnectionRule rule)
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
                    FirewallRuleExtensions.FreeNative(nativeRule);
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

    public unsafe class InboundRuleCollection(InboundRule* ptr, int count) : IFirewallRuleCollection, IEnumerable<SharedTypes.FirewallInboundRule>
    {
        private InboundRule* _ptr = ptr;
        private readonly int _count = count;
        private bool _disposed;

        public int Count => _count;

        public SharedTypes.FirewallInboundRule this[int index]
        {
            get
            {
                if (index < 0 || index >= _count) throw new IndexOutOfRangeException();
                return FirewallRuleExtensions.FromNative(_ptr[index]);
            }
        }

        public IEnumerator<SharedTypes.FirewallInboundRule> GetEnumerator()
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

    public unsafe class OutboundRuleCollection(OutboundRule* ptr, int count) : IFirewallRuleCollection, IEnumerable<SharedTypes.FirewallOutboundRule>
    {
        private OutboundRule* _ptr = ptr;
        private readonly int _count = count;
        private bool _disposed;

        public int Count => _count;

        public SharedTypes.FirewallOutboundRule this[int index]
        {
            get
            {
                if (index < 0 || index >= _count) throw new IndexOutOfRangeException();
                return FirewallRuleExtensions.FromNative(_ptr[index]);
            }
        }

        public IEnumerator<SharedTypes.FirewallOutboundRule> GetEnumerator()
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

    public unsafe class ConnectionRuleCollection(ConnectionRule* ptr, int count) : IFirewallRuleCollection, IEnumerable<SharedTypes.FirewallConnectionRule>
    {
        private ConnectionRule* _ptr = ptr;
        private readonly int _count = count;
        private bool _disposed;

        public int Count => _count;

        public SharedTypes.FirewallConnectionRule this[int index]
        {
            get
            {
                if (index < 0 || index >= _count) throw new IndexOutOfRangeException();
                return FirewallRuleExtensions.FromNative(_ptr[index]);
            }
        }

        public IEnumerator<SharedTypes.FirewallConnectionRule> GetEnumerator()
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