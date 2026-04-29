namespace Drederick.Recon.Fuzz;

/// <summary>
/// High-level fuzz attack surfaces. Each category maps to a group of fuzz
/// tools with similar technical profiles and operator opt-in requirements.
/// <see cref="FuzzToolbox"/> uses these to filter tools by category, and
/// <see cref="Agent.AdaptiveRunner"/> uses them to schedule fuzz passes
/// based on fingerprinted services (e.g. only run <see cref="WebApi"/>
/// fuzzers when GraphQL or REST endpoints are detected).
/// </summary>
public enum FuzzCategory
{
    /// <summary>
    /// HTTP parameter fuzzing, vhost discovery, header injection testing.
    /// Targets web applications and reverse proxies. Higher request volume
    /// than passive recon but non-destructive. Opt-in gated by
    /// <c>--allow-fuzz-web</c> in strict mode; default-on in lab mode.
    /// </summary>
    Web,

    /// <summary>
    /// REST API endpoint discovery (kiterunner), GraphQL introspection,
    /// schema fuzzing, and COP (Confused Officer Problem) detection. Targets
    /// API gateways and GraphQL servers. Request volume comparable to
    /// <see cref="Web"/> but often requires authenticated context. Opt-in
    /// gated by <c>--allow-fuzz-webapi</c> in strict mode; default-on in
    /// lab mode.
    /// </summary>
    WebApi,

    /// <summary>
    /// Subdomain brute force against DNS resolvers. High query volume;
    /// may trigger rate-limit or logging spikes at the DNS layer. Non-
    /// destructive to the application layer. Opt-in gated by
    /// <c>--allow-fuzz-dns</c> in strict mode; default-on in lab mode.
    /// </summary>
    Dns,

    /// <summary>
    /// JWT algorithm confusion, weak HMAC secret brute force, KID path
    /// traversal / SQLi / header injection, JKU/X5U injection, and similar
    /// token-based authentication bypass techniques. Targets authentication
    /// layers. Request volume varies; some attacks are single-shot
    /// (alg=none), others are wordlist-driven (weak secret). Opt-in gated
    /// by <c>--allow-fuzz-auth</c> in strict mode; default-on in lab mode.
    /// </summary>
    Auth,

    /// <summary>
    /// Binary protocol fuzzing (boofuzz-driven) for non-HTTP services:
    /// FTP, SSH, SMB, SNMP, RPC, custom protocols. Mutation-based,
    /// potentially destabilizing; can crash services or trigger watchdog
    /// restarts. DESTRUCTIVE category. Requires <c>--allow-fuzz-network</c>
    /// AND <c>--allow-destructive</c> opt-in even in lab mode; default-off
    /// everywhere. Operators must explicitly acknowledge crash risk.
    /// </summary>
    Network,

    /// <summary>
    /// Radamsa / LLM-driven payload mutation for file formats, protocol
    /// messages, or captured inputs. Generates anomalous inputs to test
    /// parser robustness and trigger memory-safety bugs. Potentially
    /// destabilizing; may exhaust disk or trigger OOM on the target.
    /// DESTRUCTIVE category. Requires <c>--allow-fuzz-mutation</c> AND
    /// <c>--allow-destructive</c> opt-in even in lab mode; default-off
    /// everywhere.
    /// </summary>
    Mutation,
}
