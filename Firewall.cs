using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace LibFirewall
{
    public partial class Firewall
    {
        public static int TestRustAdd(int a, int b)
        {
            return NativeMethods.rust_add(a, b);
        }
    }
}
