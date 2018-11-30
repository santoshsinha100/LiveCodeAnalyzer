using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace LiveCodeAnalyzer.Utility
{ 
    public class Singleton
    {
        private static Singleton instance = null;

        private Singleton()
        {
        }

        public static Singleton Instance
        {
            get
            {
                if (instance == null)
                {
                    instance = new Singleton();
                }
                return instance;
            }
        }

        public const string NamingDiagnosticId = "LiveAnalyzerNaming";
        public const string ClassDeclarionDiagnosticId = "LiveAnalyzerClassDeclarion";
        public const string MethodDeclarionDiagnosticId = "LiveAnalyzerMethodDeclarion";
        public const string MethodInputValidationDiagnosticId = "LiveAnalyzerMethodInputValidation";
    }   
}
