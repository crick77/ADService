using System;
using System.Collections.Generic;
using System.Linq;
using System.ServiceProcess;
using System.Text;
using System.Threading.Tasks;
#if NOSERVICE
using System.Windows.Forms;
#endif

namespace ADService
{
    static class Program
    {
        /// <summary>
        /// Punto di ingresso principale dell'applicazione.
        /// </summary>
        static void Main()
        {
#if NOSERVICE
            ADService s = new ADService();
            s._onStart(null);
            MessageBox.Show("Press ok to stop", "adService");
            s._onStop();
#else
            ServiceBase[] ServicesToRun;
            ServicesToRun = new ServiceBase[]
            {
                new ADService()
            };
            ServiceBase.Run(ServicesToRun);
#endif
        }
    }
}
