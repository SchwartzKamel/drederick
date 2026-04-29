using System.Diagnostics;
using System.Net.Http;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Drederick.Audit;
using Drederick.Doctor;
using Drederick.Scope;

namespace Drederick.Recon.Fuzz;

/// <summary>
/// GraphQL endpoint fuzzing: detect whether introspection is enabled, extract
/// schema metadata (mutations, queries, types), compute a stable schema digest,
/// and optionally run graphql-cop for COP (Confused Officer Problem) detection
/// (alias overloading, batching, CSRF, field suggestion). Pure C# introspection
/// phase; graphql-cop is opt-in subprocess. Scope-enforced, audit-logged.
/// </summary>
public sealed class GraphqlFuzzTool : IFuzzTool, IDisposable
{
    public string Name => "graphql-fuzz";

    public string Description =>
        "GraphQL introspection + optional graphql-cop for COP detection. " +
        "Extracts schema (mutations/queries), computes stable digest, " +
        "detects alias overloading / batching / CSRF / field suggestion. " +
        "Scope-enforced, audit-logged.";

    public FuzzCategory Category => FuzzCategory.WebApi;

    private readonly Scope.Scope _scope;
    private readonly AuditLog _audit;
    private readonly HttpClient _http;
    private readonly bool _ownsHttpClient;
    private readonly string? _graphqlCopPath;
    private readonly IProcessRunner _runner;

    /// <summary>
    /// Standard GraphQL introspection query. Embeds the well-known canonical
    /// query that retrieves the full schema (types, fields, directives, etc.).
    /// </summary>
    private const string IntrospectionQuery = @"
        query IntrospectionQuery {
            __schema {
                queryType { name }
                mutationType { name }
                subscriptionType { name }
                types {
                    ...FullType
                }
                directives {
                    name
                    description
                    locations
                    args {
                        ...InputValue
                    }
                }
            }
        }

        fragment FullType on __Type {
            kind
            name
            description
            fields(includeDeprecated: true) {
                name
                description
                args {
                    ...InputValue
                }
                type {
                    ...TypeRef
                }
                isDeprecated
                deprecationReason
            }
            inputFields {
                ...InputValue
            }
            interfaces {
                ...TypeRef
            }
            enumValues(includeDeprecated: true) {
                name
                description
                isDeprecated
                deprecationReason
            }
            possibleTypes {
                ...TypeRef
            }
        }

        fragment InputValue on __InputValue {
            name
            description
            type { ...TypeRef }
            defaultValue
        }

        fragment TypeRef on __Type {
            kind
            name
            ofType {
                kind
                name
                ofType {
                    kind
                    name
                    ofType {
                        kind
                        name
                        ofType {
                            kind
                            name
                            ofType {
                                kind
                                name
                                ofType {
                                    kind
                                    name
                                    ofType {
                                        kind
                                        name
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    ";

    public GraphqlFuzzTool(
        Scope.Scope scope,
        AuditLog audit,
        HttpClient? httpClient = null,
        string? graphqlCopPath = "graphql-cop",
        IProcessRunner? runner = null)
    {
        _scope = scope;
        _audit = audit;
        _graphqlCopPath = graphqlCopPath;
        _runner = runner ?? (IProcessRunner)new DefaultProcessRunner();

        if (httpClient is null)
        {
            // TLS-permissive, no auto-redirect, short timeout
            var handler = new HttpClientHandler
            {
                AllowAutoRedirect = false,
                ServerCertificateCustomValidationCallback = (_, _, _, _) => true,
                SslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
            };
            _http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(5) };
            _http.DefaultRequestHeaders.UserAgent.ParseAdd("drederick/0.1 (+lab-recon)");
            _ownsHttpClient = true;
        }
        else
        {
            _http = httpClient;
            _ownsHttpClient = false;
        }
    }

    public async Task<GraphqlFuzzResult> ProbeAsync(
        string graphqlEndpointUrl,
        GraphqlFuzzOptions? options = null,
        CancellationToken ct = default)
    {
        var opts = options ?? new GraphqlFuzzOptions();
        var started = DateTimeOffset.UtcNow;

        // Validate URL is absolute and http(s)
        if (!Uri.TryCreate(graphqlEndpointUrl, UriKind.Absolute, out var uri))
        {
            throw new ArgumentException(
                $"GraphQL endpoint URL must be absolute, got: {graphqlEndpointUrl}",
                nameof(graphqlEndpointUrl));
        }

        if (uri.Scheme != "http" && uri.Scheme != "https")
        {
            throw new ArgumentException(
                $"GraphQL endpoint URL must use http or https, got scheme: {uri.Scheme}",
                nameof(graphqlEndpointUrl));
        }

        // Scope enforcement FIRST
        _scope.Require(uri.Host);

        // Audit start
        _audit.Record("graphql-fuzz.start", new Dictionary<string, object?>
        {
            ["url"] = graphqlEndpointUrl,
            ["run_graphql_cop"] = opts.RunGraphqlCop,
            ["max_depth"] = opts.MaxSchemaDepth,
        });

        bool introspectionEnabled = false;
        string? schemaDigest = null;
        List<string> mutations = new();
        List<string> queries = new();
        List<string> copFindings = new();
        string? error = null;

        try
        {
            // Phase 1: Introspection
            var (introEnabled, digest, muts, quers) = await TryIntrospectionAsync(
                graphqlEndpointUrl, opts.MaxSchemaDepth, ct);
            introspectionEnabled = introEnabled;
            schemaDigest = digest;
            mutations.AddRange(muts);
            queries.AddRange(quers);

            // Phase 2: graphql-cop (optional)
            if (opts.RunGraphqlCop && !string.IsNullOrEmpty(_graphqlCopPath))
            {
                copFindings.AddRange(await TryGraphqlCopAsync(graphqlEndpointUrl, ct));
            }
        }
        catch (Exception ex)
        {
            error = ex.Message;
        }

        var duration = DateTimeOffset.UtcNow - started;

        // Audit finish
        _audit.Record("graphql-fuzz.finish", new Dictionary<string, object?>
        {
            ["url"] = graphqlEndpointUrl,
            ["introspection_enabled"] = introspectionEnabled,
            ["mutation_count"] = mutations.Count,
            ["query_count"] = queries.Count,
            ["cop_finding_count"] = copFindings.Count,
            ["duration_ms"] = duration.TotalMilliseconds,
            ["error"] = error,
        });

        return new GraphqlFuzzResult
        {
            Target = graphqlEndpointUrl,
            ToolName = Name,
            StartedAt = started,
            Duration = duration,
            IntrospectionEnabled = introspectionEnabled,
            SchemaDigest = schemaDigest,
            Mutations = mutations,
            Queries = queries,
            CopFindings = copFindings,
            Error = error,
        };
    }

    private async Task<(bool Enabled, string? Digest, List<string> Mutations, List<string> Queries)>
        TryIntrospectionAsync(string url, int maxDepth, CancellationToken ct)
    {
        var mutations = new List<string>();
        var queries = new List<string>();

        try
        {
            // Build introspection request
            var requestBody = new
            {
                query = IntrospectionQuery,
            };
            var json = JsonSerializer.Serialize(requestBody);
            var content = new StringContent(json, Encoding.UTF8, "application/json");

            // POST to GraphQL endpoint
            var response = await _http.PostAsync(url, content, ct);

            // Read response
            var responseBody = await response.Content.ReadAsStringAsync(ct);

            // Parse JSON
            using var doc = JsonDocument.Parse(responseBody);
            var root = doc.RootElement;

            // Check for data.__schema
            if (!root.TryGetProperty("data", out var data) ||
                !data.TryGetProperty("__schema", out var schema))
            {
                // Introspection blocked or error
                return (false, null, mutations, queries);
            }

            // Introspection enabled!
            // Compute stable schema digest (canonicalized JSON)
            var schemaJson = schema.GetRawText();
            var digest = ComputeSchemaDigest(schemaJson);

            // Extract types
            if (schema.TryGetProperty("types", out var types))
            {
                foreach (var type in types.EnumerateArray())
                {
                    if (!type.TryGetProperty("kind", out var kind) ||
                        kind.GetString() != "OBJECT")
                    {
                        continue;
                    }

                    if (!type.TryGetProperty("name", out var nameElem))
                    {
                        continue;
                    }

                    var typeName = nameElem.GetString();
                    if (typeName is null)
                    {
                        continue;
                    }

                    // Mutation type
                    if (schema.TryGetProperty("mutationType", out var mutType) &&
                        mutType.TryGetProperty("name", out var mutTypeName) &&
                        mutTypeName.GetString() == typeName)
                    {
                        // Extract mutation fields
                        if (type.TryGetProperty("fields", out var fields))
                        {
                            foreach (var field in fields.EnumerateArray())
                            {
                                if (field.TryGetProperty("name", out var fieldName))
                                {
                                    var fn = fieldName.GetString();
                                    if (fn is not null)
                                    {
                                        mutations.Add(fn);
                                    }
                                }
                            }
                        }
                    }

                    // Query type
                    if (schema.TryGetProperty("queryType", out var queryType) &&
                        queryType.TryGetProperty("name", out var queryTypeName) &&
                        queryTypeName.GetString() == typeName)
                    {
                        // Extract query fields
                        if (type.TryGetProperty("fields", out var fields))
                        {
                            foreach (var field in fields.EnumerateArray())
                            {
                                if (field.TryGetProperty("name", out var fieldName))
                                {
                                    var fn = fieldName.GetString();
                                    if (fn is not null)
                                    {
                                        queries.Add(fn);
                                    }
                                }
                            }
                        }
                    }
                }
            }

            return (true, digest, mutations, queries);
        }
        catch
        {
            // Any error (HTTP, JSON parse, etc.) → introspection disabled
            return (false, null, mutations, queries);
        }
    }

    private async Task<List<string>> TryGraphqlCopAsync(string url, CancellationToken ct)
    {
        var findings = new List<string>();

        try
        {
            // Validate URL doesn't contain shell metachar (already validated as URI, but double-check)
            if (url.Contains(';') || url.Contains('&') || url.Contains('|') ||
                url.Contains('$') || url.Contains('`') || url.Contains('\\') ||
                url.Contains('\n') || url.Contains('\r'))
            {
                throw new ArgumentException(
                    $"GraphQL endpoint URL contains shell metachar: {url}");
            }

            // Spawn graphql-cop with 2min timeout
            var result = await Task.Run(
                () => _runner.Run(_graphqlCopPath!, $"-t {url} -o json", timeoutSeconds: 120),
                ct);
            int exitCode = result.ExitCode;
            string stdout = result.StdOut;
            string stderr = result.StdErr;

            // Binary missing / nonzero exit → leave findings empty, log to audit
            if (exitCode == 127 || exitCode == 126)
            {
                // Command not found or not executable
                _audit.Record("graphql-fuzz.cop-unavailable", new Dictionary<string, object?>
                {
                    ["url"] = url,
                    ["exit_code"] = exitCode,
                });
                return findings;
            }

            if (exitCode != 0)
            {
                // graphql-cop errored
                _audit.Record("graphql-fuzz.cop-error", new Dictionary<string, object?>
                {
                    ["url"] = url,
                    ["exit_code"] = exitCode,
                    ["stderr"] = stderr.Length > 1024 ? stderr.Substring(0, 1024) : stderr,
                });
                return findings;
            }

            // Parse JSON output
            // graphql-cop emits an array of { "title": "...", "severity": "...", "description": "...", "impact": "..." }
            if (string.IsNullOrWhiteSpace(stdout))
            {
                return findings;
            }

            using var doc = JsonDocument.Parse(stdout);
            var root = doc.RootElement;

            if (root.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in root.EnumerateArray())
                {
                    var title = item.TryGetProperty("title", out var t) ? t.GetString() : "Unknown";
                    var severity = item.TryGetProperty("severity", out var s) ? s.GetString() : "info";
                    var description = item.TryGetProperty("description", out var d) ? d.GetString() : "";

                    findings.Add($"[{severity}] {title} — {description}");
                }
            }
        }
        catch
        {
            // graphql-cop unavailable or errored → graceful degradation
            // Findings stay empty
        }

        return findings;
    }

    private static string ComputeSchemaDigest(string schemaJson)
    {
        // Canonicalize by parsing and re-serializing with sorted keys
        // (JsonDocument preserves insertion order, so we need to manually sort)
        // For now, just hash the raw JSON — stable enough for same-schema detection
        // since GraphQL introspection order is deterministic per server.
        // Future: implement full JSON canonicalization (RFC 8785 JCS).
        var bytes = Encoding.UTF8.GetBytes(schemaJson);
        var hash = SHA256.HashData(bytes);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    public void Dispose()
    {
        if (_ownsHttpClient)
        {
            _http.Dispose();
        }
    }
}

/// <summary>Options for GraphQL fuzzing.</summary>
public sealed class GraphqlFuzzOptions
{
    /// <summary>Whether to run graphql-cop for COP detection (default: true).</summary>
    public bool RunGraphqlCop { get; init; } = true;

    /// <summary>Max schema introspection depth (default: 5).</summary>
    public int MaxSchemaDepth { get; init; } = 5;
}
