using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace adEditor
{
    public static class Extensions
    {
        public static byte[] Initialize(this byte[] array, byte defaultValue)
        {
            for (int i = 0; i < array.Length; ++i) array[i] = defaultValue;
            return array;
        }
    }    
}
