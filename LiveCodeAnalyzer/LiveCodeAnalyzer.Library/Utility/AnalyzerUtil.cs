﻿using System;

using Microsoft.CodeAnalysis;

using CSharp = Microsoft.CodeAnalysis.CSharp;
using CSharpSyntax = Microsoft.CodeAnalysis.CSharp.Syntax;

using Microsoft.CodeAnalysis.Text;
using System.Collections.Generic;

namespace LiveCodeAnalyzer.Utility
{
    public class AnalyzerUtil
    {
        public static bool SymbolMatch(ISymbol symbol, string type = null, string name = null) {
            if (symbol == null) { //Code did not compile
                //FIXME: Log warning
                return false;
            }

            if (type == null && name == null) {
                throw new InvalidOperationException("At least one parameter must be specified (type, methodName, ...)");
            }

            if (type != null && symbol.ContainingType?.Name != type) {
                return false; //Class name does not match
            }
            if (name != null && symbol.Name != name) {
                return false; //Method name does not match
            }
            return true;
        }


        public static void ForEachAnnotation(SyntaxList<CSharpSyntax.AttributeListSyntax> attributes, Action<string, CSharpSyntax.AttributeSyntax> callback)
        {
            foreach (var attribute in attributes)
            {
                if (attribute.Attributes == null || attribute.Attributes.Count == 0) continue; //Bound check .. Unlikely to happens

                //Extract the annotation identifier
                var identifier = attribute.Attributes[0].Name as CSharpSyntax.IdentifierNameSyntax;

                if (identifier == null) continue;

                callback(identifier.Identifier.Text, attribute.Attributes[0]);
            }
        }


        public static SyntaxNode GetMethodFromNode(SyntaxNode node) {

            SyntaxNode current = node;
            while (current.Parent != null) {
                current = current.Parent;
            }
            return current;
        }


        public static List<string> getAttributesForMethod(CSharpSyntax.MethodDeclarationSyntax node)
        {
            var attributesList = new List<string>();

            if (node.AttributeLists != null)
            {
                foreach (CSharpSyntax.AttributeListSyntax attributeList in node.AttributeLists)
                {
                    if (attributeList.Attributes != null)
                    {
                        foreach (CSharpSyntax.AttributeSyntax attribute in attributeList.Attributes)
                            attributesList.Add(attribute.Name.GetText().ToString());
                    }
                }
            }
            return attributesList;
        }       

        public static List<CSharpSyntax.AttributeSyntax> getAttributesByName(string attributeName, CSharpSyntax.MethodDeclarationSyntax node)
        {
            var attributesList = new List<CSharpSyntax.AttributeSyntax>();

            if (node?.AttributeLists != null)
            {
                foreach (CSharpSyntax.AttributeListSyntax attributeList in node.AttributeLists)
                {
                    if (attributeList.Attributes != null)
                    {
                        foreach (CSharpSyntax.AttributeSyntax attribute in attributeList.Attributes)
                        {
                            if(attribute.Name.GetText().ToString().Equals(attributeName))
                            {
                                attributesList.Add(attribute);
                            }
                        }
                    }
                }
            }
            return attributesList;
        }

        /// <summary>
        /// Verify is the expression passed is a constant string.
        /// </summary>
        /// <param name="expression"></param>
        /// <returns></returns>
        [Obsolete]
        public static bool IsStaticString(CSharpSyntax.ExpressionSyntax expression)
        {
            return expression.Kind() == CSharp.SyntaxKind.StringLiteralExpression && expression is CSharpSyntax.LiteralExpressionSyntax;
        }
        
        public static Location CreateLocation(string path, int lineStart, int linePosition = -1)
        {
            return Location.Create(path, TextSpan.FromBounds(1, 2), new LinePositionSpan(new LinePosition(lineStart, 0), new LinePosition(lineStart, 0)));
        }
    }
}
