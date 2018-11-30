using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Threading;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;
using LiveCodeAnalyzer;
using LiveCodeAnalyzer.Library;
using System.Reflection;
using LiveCodeAnalyzer.Utility;
using CSharpSyntax = Microsoft.CodeAnalysis.CSharp.Syntax;
using CSharp = Microsoft.CodeAnalysis.CSharp;
using LiveCodeAnalyzer.Locale;
using System.Xml.Linq;
using System.Xml;
using System.IO;
using System.Text;
using Microsoft.CodeAnalysis.Text;
using System.Text.RegularExpressions;

namespace LiveCodeAnalyzer
{
    /// <summary>
    /// the DiagnosticCodeAnalyzer
    /// </summary>
    [DiagnosticAnalyzer(LanguageNames.CSharp)]
    public class DiagnosticCodeAnalyzer : DiagnosticAnalyzer
    {
        private readonly List<DiagnosticDescriptor> Descriptors = new List<DiagnosticDescriptor>();

        private MethodBehaviorRepository behaviorRepo = new MethodBehaviorRepository();

        private static List<TaintAnalyzerExtension> extensions = new List<TaintAnalyzerExtension>();

        private CSharpCodeEvaluation csharpCodeEval = new CSharpCodeEvaluation();

        private static readonly LocalizableString TitleName = new LocalizableResourceString(nameof(Resources.AnalyzerTitle), Resources.ResourceManager, typeof(Resources));
        private static readonly LocalizableString MessageFormatName = new LocalizableResourceString(nameof(Resources.AnalyzerMessageFormat), Resources.ResourceManager, typeof(Resources));
        private static readonly LocalizableString DescriptionName = new LocalizableResourceString(nameof(Resources.AnalyzerDescription), Resources.ResourceManager, typeof(Resources));
        private const string CategoryName = "Identifier Naming";

        private static DiagnosticDescriptor RuleName = new DiagnosticDescriptor(Singleton.NamingDiagnosticId, TitleName, MessageFormatName, CategoryName, DiagnosticSeverity.Warning, isEnabledByDefault: true, description: DescriptionName);

        private static readonly LocalizableString TitleClassComments = new LocalizableResourceString(nameof(Resources.AnalyzerClassMissingCommentsTitle), Resources.ResourceManager, typeof(Resources));
        private static readonly LocalizableString MessageFormatClassComments = new LocalizableResourceString(nameof(Resources.AnalyzerClassMissingCommentsDescription), Resources.ResourceManager, typeof(Resources));
        private const string CategoryClassComments = "Identifier Class Comments";
        private static DiagnosticDescriptor RuleClassComments = new DiagnosticDescriptor(Singleton.ClassDeclarionDiagnosticId, TitleClassComments, MessageFormatClassComments, CategoryClassComments, DiagnosticSeverity.Warning, isEnabledByDefault: true, description: MessageFormatClassComments);

        private static readonly LocalizableString TitleMethodComments = new LocalizableResourceString(nameof(Resources.AnalyzerMethodMissingCommentsTitle), Resources.ResourceManager, typeof(Resources));
        private static readonly LocalizableString MessageFormatMethodComments = new LocalizableResourceString(nameof(Resources.AnalyzerMethodMissingCommentsDescription), Resources.ResourceManager, typeof(Resources));
        private const string CategoryMethodComments = "Identifier Methods Comments";
        private static DiagnosticDescriptor RuleMethodComments = new DiagnosticDescriptor(Singleton.ClassDeclarionDiagnosticId, TitleMethodComments, MessageFormatMethodComments, CategoryMethodComments, DiagnosticSeverity.Warning, isEnabledByDefault: true, description: MessageFormatMethodComments);

        private static readonly LocalizableString TitleParameterValidate = new LocalizableResourceString(nameof(Resources.AnalyzerParameterValidateTitle), Resources.ResourceManager, typeof(Resources));
        private static readonly LocalizableString MessageFormatParameterValidate = new LocalizableResourceString(nameof(Resources.AnalyzerParameterValidateDescription), Resources.ResourceManager, typeof(Resources));
        private const string CategoryParameterValidate = "Identifier Parameter Validate";
        private static DiagnosticDescriptor RuleParameterValidate = new DiagnosticDescriptor(Singleton.ClassDeclarionDiagnosticId, TitleParameterValidate, MessageFormatParameterValidate, CategoryParameterValidate, DiagnosticSeverity.Warning, isEnabledByDefault: true, description: MessageFormatParameterValidate);

        private static readonly LocalizableString TitleSensitiveInfo = new LocalizableResourceString(nameof(Resources.AnalyzerSensitiveInfoTitle), Resources.ResourceManager, typeof(Resources));
        private static readonly LocalizableString MessageFormatSensitiveInfo = new LocalizableResourceString(nameof(Resources.AnalyzerSensitiveInfoDescription), Resources.ResourceManager, typeof(Resources));
        private const string CategorySensitiveInfo = "Identifier Sensitive Information";
        private static DiagnosticDescriptor RuleSensitiveInfo = new DiagnosticDescriptor(Singleton.ClassDeclarionDiagnosticId, TitleSensitiveInfo, MessageFormatSensitiveInfo, CategorySensitiveInfo, DiagnosticSeverity.Error, isEnabledByDefault: true, description: MessageFormatSensitiveInfo);

        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics
        {
            get
            {
                //Feed the diagnostic descriptor from the configured sinks
                HashSet<DiagnosticDescriptor> all = new HashSet<DiagnosticDescriptor>(Descriptors);
                //Add the diagnostic that can be reported by taint analysis extension
                foreach (var extension in extensions)
                {
                    var analyzer = extension as DiagnosticAnalyzer;
                    foreach (DiagnosticDescriptor desc in analyzer.SupportedDiagnostics)
                    {
                        all.Add(desc);
                    }
                }
                return ImmutableArray.Create(all.ToArray());
            }
        }

        public DiagnosticCodeAnalyzer()
        {
            //Load injectable APIs
            behaviorRepo.LoadConfiguration("Sinks.yml");
            //Load password APIs
            behaviorRepo.LoadConfiguration("Passwords.yml");
            //
            behaviorRepo.LoadConfiguration("Behavior.yml");

            //Build the descriptor based on the locale fields of the Sinks.yml
            //This must be done in the constructor because, the array need be available before SupportedDiagnostics is first invoked.
            foreach (var desc in behaviorRepo.GetDescriptors())
            {
                Descriptors.Add(desc);
            }

            ///RuleName, RuleClassComments, RuleMethodComments, RuleParameterValidate
            Descriptors.Add(RuleName);
            Descriptors.Add(RuleClassComments);
            Descriptors.Add(RuleMethodComments);          
            Descriptors.Add(RuleSensitiveInfo);

            csharpCodeEval.behaviorRepo = behaviorRepo;
        }

        /// <summary>
        /// the Initialize method.
        /// </summary>
        /// <param name="analysisContext"></param>
        public override void Initialize(AnalysisContext analysisContext)
        {
            analysisContext.RegisterSymbolAction(AnalyzeSymbol, SymbolKind.NamedType);

            //// Need to analyze class
            analysisContext.RegisterSyntaxNodeAction(VisitClassDeclaration, CSharp.SyntaxKind.ClassDeclaration);

            //// Need to analyze methods, anonymous delegates and lambda-expressions
            analysisContext.RegisterSyntaxNodeAction(VisitMethodDeclaration, CSharp.SyntaxKind.MethodDeclaration);

            //// validating the method input parameters
            analysisContext.RegisterSyntaxNodeAction(ValidateMethodWithParameters, CSharp.SyntaxKind.MethodDeclaration);

            //// Need to analyze Sensitive Information
            analysisContext.RegisterSyntaxNodeAction(VisitSensitiveInformation, CSharp.SyntaxKind.ClassDeclaration);

            ///need to analyze the various security injections.
            analysisContext.RegisterSyntaxNodeAction(csharpCodeEval.VisitMethods, CSharp.SyntaxKind.MethodDeclaration);
        }

        /// <summary>
        /// the AnalyzeSymbol method
        /// </summary>
        /// <param name="context"></param>
        private static void AnalyzeSymbol(SymbolAnalysisContext context)
        {
            var namedTypeSymbol = (INamedTypeSymbol)context.Symbol;

            if (namedTypeSymbol.TypeKind == TypeKind.Class || namedTypeSymbol.TypeKind == TypeKind.Interface)
            {
                // Find just those named type symbols with names containing lowercase letters.
                if (char.IsLower(namedTypeSymbol.Name[0]))
                {
                    // For all such symbols, produce a diagnostic.
                    var diagnostic = Diagnostic.Create(RuleName, namedTypeSymbol.Locations[0], namedTypeSymbol.Name);

                    context.ReportDiagnostic(diagnostic);
                }
            }
        }

        /// <summary>
        /// the VisitClassDeclaration method
        /// </summary>
        /// <param name="ctx"></param>
        private static void VisitClassDeclaration(SyntaxNodeAnalysisContext ctx)
        {
            SyntaxNode node = null;
            if (ctx.Node.Language == LanguageNames.CSharp)
            {
                node = ctx.Node as CSharpSyntax.ClassDeclarationSyntax;
                if (node == null) return; //Not the expected node type
            }

            var classSymbol = ctx.SemanticModel.GetDeclaredSymbol(node);
            string classDocumentationComment = classSymbol.GetDocumentationCommentXml();

            if (string.IsNullOrEmpty(classDocumentationComment))
            {
                // For all such symbols, produce a diagnostic.
                var diagnostic = Diagnostic.Create(RuleClassComments, classSymbol.Locations[0], classSymbol.Name);
                ctx.ReportDiagnostic(diagnostic);
            }
        }

        /// <summary>
        /// the VisitMethodDeclaration method
        /// </summary>
        /// <param name="ctx"></param>
        private static void VisitMethodDeclaration(SyntaxNodeAnalysisContext ctx)
        {
            SyntaxNode method = null;

            if (ctx.Node.Language == LanguageNames.CSharp)
            {
                method = ctx.Node as CSharpSyntax.MethodDeclarationSyntax;
                if (method == null) return; //Not the expected node type               
            }

            var methodSymbol = ctx.SemanticModel.GetDeclaredSymbol(method);
            if (string.IsNullOrEmpty(methodSymbol.GetDocumentationCommentXml()))
            {
                // For all such symbols, produce a diagnostic.
                var diagnostic = Diagnostic.Create(RuleMethodComments, methodSymbol.Locations[0], methodSymbol.Name);
                ctx.ReportDiagnostic(diagnostic);
            }
        }

        /// <summary>
        /// to validate method parameters.
        /// </summary>
        /// <param name="ctx"></param>
        private static void ValidateMethodWithParameters(SyntaxNodeAnalysisContext ctx)
        {
            var node = ctx.Node as CSharpSyntax.MethodDeclarationSyntax;

            if (node == null) return;

            //Iterating over the list of annotation for a given method
            foreach (var attribute in node.AttributeLists)
            {
                if (attribute.Attributes.Count == 0) continue; //Bound check .. Unlikely to happens

                var att = attribute.Attributes[0];
                //Extract the annotation identifier
                var identifier = att.Name as CSharpSyntax.IdentifierNameSyntax;

                if (identifier == null) continue;

                if (identifier.Identifier.Text == "ValidateInput")
                {
                    var hasArgumentFalse = false;
                    CSharpSyntax.ExpressionSyntax expression = null;
                    foreach (var arg in att.ArgumentList.Arguments)
                    {
                        var literal = arg.Expression as CSharpSyntax.LiteralExpressionSyntax;
                        if (literal.Token.ValueText == "false")
                        {
                            hasArgumentFalse = true;
                            expression = arg.Expression;
                        }
                    }

                    if (hasArgumentFalse && expression != null)
                    {
                        ctx.ReportDiagnostic(Diagnostic.Create(RuleParameterValidate, expression.GetLocation()));
                    }
                }
            }
        }

        /// <summary>
        /// to verify sensitive information.
        /// </summary>
        /// <param name = "ctx" ></ param >
        private static void VisitSensitiveInformation(SyntaxNodeAnalysisContext ctx)
        {   
            string guidPattern = @"\b[A-F0-9]{8}(?:-[A-F0-9]{4}){3}-[A-F0-9]{12}\b";
            Regex regxGuid = new Regex(Regex.Escape(guidPattern), RegexOptions.IgnoreCase);

            string stringPattern = @"(password|server|connection|database)";
            Regex regxStringPattern = new Regex(stringPattern, RegexOptions.IgnoreCase);

            var classSymbol = ctx.Node as CSharpSyntax.ClassDeclarationSyntax;

            var nodes = classSymbol.DescendantNodes();
            foreach (var node in nodes)
            {
                if (node is VariableDeclarationSyntax || node is PropertyDeclarationSyntax)
                {
                    string variable = node?.ToString().ToLower();

                    if (regxGuid.Match(variable).Success || regxStringPattern.Match(variable).Success)
                    {
                        // For all such symbols, produce a diagnostic.
                        var diagnostic = Diagnostic.Create(RuleSensitiveInfo, node.GetLocation(), variable);
                        ctx.ReportDiagnostic(diagnostic);
                    }
                }
            }
        }
    }
}
