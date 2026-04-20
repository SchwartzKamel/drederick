namespace Drederick.Scope;

/// <summary>Raised when a scope file is missing, empty, unsafe, or a target is out of scope.</summary>
public sealed class ScopeException : Exception
{
    public ScopeException(string message) : base(message) { }
}
