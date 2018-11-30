using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CodeFixes;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using TestHelper;
using LiveCodeAnalyzer;

namespace LiveCodeAnalyzer.Test
{
    [TestClass]
    public class DiagnosticAnalyzerTests : CodeFixVerifier
    {

        //Diagnostic and CodeFix both triggered and checked for
        [TestMethod]
        public void NameRuleTest()
        {
            var test = @"
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;
    using System.Threading.Tasks;
    using System.Diagnostics;

    namespace ConsoleApplication1
    {
         /// <summary>
        /// 
        /// </summary>
        public class TypeName
        {   

    /////// <summary>
    /////// 
    /////// </summary>
    public string foo(string a, string b)
    {
                string username = input;
                var variable1 = username;
                var variable2 = variable1;

                if(variable2 != """")
                    new SqlCommand(variable2);
    }

        }
    }";
            var expected = new DiagnosticResult
            {
                Id = "LiveCodeAnalyzer",
                Message = String.Format("Type name '{0}' contains lowercase letters", "TypeName"),
                Severity = DiagnosticSeverity.Warning,
                Locations =
                    new[] {
                            new DiagnosticResultLocation("Test0.cs", 11, 15)
                        }
            };
         
            VerifyCSharpDiagnostic(test);
        }


        [TestMethod]
        public void HardCodePasswordDerivedBytes()
        {

            var cSharpTest = @"
            using System.Security.Cryptography;

            namespace VulnerableApp
            {
                class HardCodedPassword
                {
                    static void TestHardcodedValue()
                    {
                        var test = new PasswordDeriveBytes(""hardcode"", new byte[] { 0, 1, 2, 3 });
                    }
                }
            }
            ";
            var expected = new DiagnosticResult
            {
                Id = "SG0015",
                Severity = DiagnosticSeverity.Warning
            };

            VerifyCSharpDiagnostic(cSharpTest, expected);          
        }

        [TestMethod]
        public void ClassMethodDeclarationTest()
        {
            var test = @"
            using System;
            using System.Collections.Generic;
            using System.Linq;
            using System.Text;
            using System.Threading.Tasks;
            using System.Diagnostics;

            namespace ConsoleApplication1
            {
                /// <summary>
                /// the TypeName class
                /// </summary>
                public class TypeName
                { 
                    public void TestMethod()
                    {
                    }
                }
            }";

            var expected = new DiagnosticResult
            {
                Id = "LiveCodeAnalyzer",
                Message = String.Format("Type name '{0}' doesn't have comments", "TypeName"),
                Severity = DiagnosticSeverity.Warning,
                Locations =
                    new[] {
                            new DiagnosticResultLocation("Test0.cs", 11, 15)
                        }
            };

            VerifyCSharpDiagnostic(test, expected);
        }

        /// <summary>
        /// Test Methods for VariableConcatenation
        /// </summary>
        [TestMethod]
        public void VariableConcatenation()
        {
            var cSharpTest = @"
            using System.Data.SqlClient;

            namespace sample
            {
                class SqlConstant
                {
                    public static void Run()
                    {
                        string username = ""Shall we play a game?"";

                        new SqlCommand(""SELECT* FROM users WHERE username = '"" + username + ""' LIMIT 1"");
                    }
                }
            }";
          VerifyCSharpDiagnostic(cSharpTest);            
        }

        /// <summary>
        /// Test Methods for VariableConcatenation
        /// </summary>
        [TestMethod]
        public void HardCodePasswordTest()
        {
            var cSharpTest = @"
           
            namespace sample
            {
                /// <summary>
                /// the TypeName class
                /// </summary>
                class Password
                {

                    /// <summary>
                    /// the TypeName class
                    /// </summary>
                    public static void Run()
                    {
                        string Password = ""pass"";
                        string strcon = ""server = 123.34;"";
                     }
                }
            }";
            VerifyCSharpDiagnostic(cSharpTest);
        }

        /// <summary>
        /// PathTraversalFound2
        /// </summary>
        [TestMethod]
        public void PathTraversalFound2()
        {
            var cSharpTest = @"
using System.IO;

class PathTraversal
{
    public static void Run(string input)
    {
        File.OpenRead(input);
    }
}
";
         
            var expected = new DiagnosticResult
            {
                Id = "SG0018",
                Severity = DiagnosticSeverity.Warning,
            };
            VerifyCSharpDiagnostic(cSharpTest, expected);           
        }

        /// <summary>
        /// PathTraversalFound4
        /// </summary>
        [TestMethod]
        public void PathTraversalFound4()
        {
            var cSharpTest = @"
using System.IO;

class PathTraversal
{
    public static void Run(string input)
    {
        new StreamReader(input);
    }
}
";
         
          
            var expected = new DiagnosticResult
            {
                Id = "SG0018",
                Severity = DiagnosticSeverity.Warning,
            };
            VerifyCSharpDiagnostic(cSharpTest, expected);
        
        }

        /// <summary>
        /// PathTraversalFound5
        /// </summary>
        [TestMethod]
        public void PathTraversalFound5()
        {
            var cSharpTest = @"
using System.IO;

class PathTraversal
{
    public static void Run(string input)
    {
        new StreamReader(input, System.Text.Encoding.ASCII, false, 0);
    }
}
";
           
            var expected = new DiagnosticResult
            {
                Id = "SG0018",
                Severity = DiagnosticSeverity.Warning,
            };
             VerifyCSharpDiagnostic(cSharpTest, expected);          
        }



        protected override CodeFixProvider GetCSharpCodeFixProvider()
        {
            return new LiveCodeAnalyzerCodeFixProvider();
        }

        protected override DiagnosticAnalyzer GetCSharpDiagnosticAnalyzer()
        {
            return new DiagnosticCodeAnalyzer();
        }     
    }
}