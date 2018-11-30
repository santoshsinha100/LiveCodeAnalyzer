using Microsoft.CodeAnalysis;
using CSharpSyntax = Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;
using System.Collections.Immutable;


namespace LiveCodeAnalyzer.Utility
{
    public abstract class TaintAnalyzerExtension : DiagnosticAnalyzer
    {
        // (i) C#.
        public virtual void VisitStatement(CSharpSyntax.StatementSyntax node, ExecutionState state) { }
        public virtual void VisitInvocationAndCreation(CSharpSyntax.ExpressionSyntax node, CSharpSyntax.ArgumentListSyntax argList, ExecutionState state) { }
        public virtual void VisitAssignment(CSharpSyntax.AssignmentExpressionSyntax node, ExecutionState state, MethodBehavior behavior, ISymbol symbol, VariableState variableRightState) { }
        public virtual void VisitBeginMethodDeclaration(CSharpSyntax.MethodDeclarationSyntax node, ExecutionState state) { }
        public virtual void VisitEndMethodDeclaration(CSharpSyntax.MethodDeclarationSyntax node, ExecutionState state) { }

       }
}
