using System;
using System.Collections;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace LibFirewall
{
    public static class Firewall
    {
        public static bool Initialize()
        {
            return NativeMethods.firewall_init();
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

    public interface IFirewallRuleCollection : IDisposable, IEnumerable<IFirewallRule>
    {
        int Count { get; }
        IFirewallRule GetRule(int index);
    }

    public interface IFirewallRule
    {
        string NameStr { get; }
        string DescriptionStr { get; }
    }

    public unsafe partial struct InboundRule : IFirewallRule
    {
        public readonly string NameStr => Marshal.PtrToStringUTF8((IntPtr)name) ?? "";
        public readonly string DescriptionStr => Marshal.PtrToStringUTF8((IntPtr)description) ?? "";
    }

    public unsafe partial struct OutboundRule : IFirewallRule
    {
        public readonly string NameStr => Marshal.PtrToStringUTF8((IntPtr)name) ?? "";
        public readonly string DescriptionStr => Marshal.PtrToStringUTF8((IntPtr)description) ?? "";
    }

    public unsafe class InboundRuleCollection(InboundRule* ptr, int count) : IFirewallRuleCollection, IEnumerable<InboundRule>
    {
        private InboundRule* _ptr = ptr;
        private readonly int _count = count;
        private bool _disposed;

        public int Count => _count;

        public InboundRule this[int index]
        {
            get
            {
                if (index < 0 || index >= _count) throw new IndexOutOfRangeException();
                return _ptr[index];
            }
        }

        public IFirewallRule GetRule(int index) => this[index];

        public IEnumerator<InboundRule> GetEnumerator() => new InboundRuleEnumerator(_ptr, _count);
        IEnumerator<IFirewallRule> IEnumerable<IFirewallRule>.GetEnumerator()
        {
            for (int i = 0; i < _count; i++) yield return this[i];
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

        public struct InboundRuleEnumerator(InboundRule* ptr, int count) : IEnumerator<InboundRule>
        {
            private readonly InboundRule* _ptr = ptr;
            private readonly int _count = count;
            private int _index = -1;

            public readonly InboundRule Current => _ptr[_index];
            readonly object IEnumerator.Current => Current;

            public bool MoveNext()
            {
                _index++;
                return _index < _count;
            }

            public void Reset() => _index = -1;
            public readonly void Dispose() { }
        }
    }

    public unsafe class OutboundRuleCollection(OutboundRule* ptr, int count) : IFirewallRuleCollection, IEnumerable<OutboundRule>
    {
        private OutboundRule* _ptr = ptr;
        private readonly int _count = count;
        private bool _disposed;

        public int Count => _count;

        public OutboundRule this[int index]
        {
            get
            {
                if (index < 0 || index >= _count) throw new IndexOutOfRangeException();
                return _ptr[index];
            }
        }

        public IFirewallRule GetRule(int index) => this[index];

        public IEnumerator<OutboundRule> GetEnumerator() => new OutboundRuleEnumerator(_ptr, _count);
        IEnumerator<IFirewallRule> IEnumerable<IFirewallRule>.GetEnumerator()
        {
            for (int i = 0; i < _count; i++) yield return this[i];
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

        public struct OutboundRuleEnumerator(OutboundRule* ptr, int count) : IEnumerator<OutboundRule>
        {
            private readonly OutboundRule* _ptr = ptr;
            private readonly int _count = count;
            private int _index = -1;

            public readonly OutboundRule Current => _ptr[_index];
            readonly object IEnumerator.Current => Current;

            public bool MoveNext()
            {
                _index++;
                return _index < _count;
            }

            public void Reset() => _index = -1;
            public readonly void Dispose() { }
        }
    }
}

