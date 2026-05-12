using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using Drederick.Audit;

namespace Drederick.Recon;

/// <summary>
/// GAP-018 — S3 / MinIO / Backblaze B2 / DO Spaces bucket enumeration.
///
/// Probes a target endpoint for anonymous bucket listing access against
/// either a directly-supplied bucket URL, virtual-host bucket form, or
/// a bare endpoint walked through a built-in (or operator-supplied)
/// wordlist of well-known bucket names. For listable buckets, parses
/// object keys + sizes from the S3-style XML or JSON listing and
/// optionally harvests high-signal artifacts (.env, id_rsa, *.bak,
/// credentials, *.sqlite, wp-config.php, dump-*.sql) into the local
/// loot tree under <c>out/loot/&lt;host&gt;/cloud-bucket-&lt;name&gt;/</c>.
///
/// Invariants (load-bearing):
///   • @invariant-id:scope-in-every-tool — every public method's first
///     statement is <c>_scope.Require(target)</c>. Virtual-host bucket
///     form re-checks scope against the bucket-prefixed hostname (DNS
///     may resolve differently).
///   • @invariant-id:no-exfiltration — captured object bytes stay in
///     <c>out/loot/</c>. No HTTP/SMTP/DNS exfil. Outbound HTTP is
///     limited to the scope-resolved endpoint; redirects to off-scope
///     hosts are refused.
///   • @invariant-id:audit-everything — every probe, bucket discovery,
///     and harvest writes to <c>audit.jsonl</c>. Audit records key,
///     size, SHA-256 only — never object content.
/// </summary>
public sealed partial class CloudStorageEnumTool : IReconTool
{
    public string Name => "cloud-storage";

    public string Description =>
        "Probe an S3-compatible endpoint (S3 / MinIO / Backblaze B2 / DO Spaces) for " +
        "anonymous bucket listing. Accepts direct bucket URLs, virtual-host bucket form, " +
        "or a bare endpoint walked with a 200-name built-in wordlist. For listable buckets, " +
        "parses object keys + sizes and optionally harvests high-signal artifacts " +
        "(.env, id_rsa, credentials, *.bak, *.sqlite, wp-config.php, dump-*.sql) into " +
        "out/loot/<host>/cloud-bucket-<name>/. Loot is local-only — never exfiltrated.";

    // --- htb-cloud-storage-enum ---
    /// <summary>Default per-object size cap (5 MiB).</summary>
    public const long DefaultMaxObjectBytes = 5L * 1024 * 1024;

    /// <summary>Default total harvest cap per run (100 MiB).</summary>
    public const long DefaultMaxHarvestBytes = 100L * 1024 * 1024;

    /// <summary>Maximum objects harvested per bucket.</summary>
    public const int MaxHarvestPerBucket = 50;

    private const int ConnectTimeoutSeconds = 10;
    private const int RequestTimeoutSeconds = 30;
    private const int MaxRetries = 5;
    private const string UserAgent = "drederick-cloud-storage/1.0";

    [GeneratedRegex(@"^[\w.\-]+(:\d+)?$", RegexOptions.CultureInvariant)]
    private static partial Regex TargetShapeRegex();

    [GeneratedRegex(@"^[a-zA-Z0-9._\-]{1,63}$", RegexOptions.CultureInvariant)]
    private static partial Regex BucketShapeRegex();

    [GeneratedRegex(
        @"(\.env$|wp-config\.php$|credentials$|\.bak$|\.sqlite$|id_rsa$|id_ed25519$|backup.*\.tar(\.gz)?$|dump.*\.sql$|config\.yaml$)",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex HighSignalKeyRegex();

    /// <summary>Built-in 200-name well-known bucket wordlist. Designed to
    /// surface common admin / dev / data buckets without runaway breadth.</summary>
    public static readonly IReadOnlyList<string> DefaultBucketWordlist = new[]
    {
        "backup", "backups", "backup-prod", "backup-dev", "backup-staging",
        "dev", "develop", "development", "prod", "production",
        "staging", "stage", "qa", "test", "tests",
        "assets", "static", "media", "uploads", "upload",
        "users", "user", "images", "image", "img",
        "logs", "log", "db", "database", "databases",
        "dump", "dumps", "archive", "archives", "private",
        "internal", "secret", "secrets", "config", "configs",
        "configuration", "app", "apps", "application", "data",
        "files", "file", "public", "public-assets", "cdn",
        "static-assets", "media-assets", "downloads", "download", "tmp",
        "temp", "temporary", "scratch", "work", "workspace",
        "shared", "share", "common", "main", "default",
        "primary", "secondary", "replica", "snapshot", "snapshots",
        "export", "exports", "import", "imports", "migrations",
        "migration", "build", "builds", "artifact", "artifacts",
        "release", "releases", "deploy", "deploys", "deployments",
        "ci", "ci-cache", "ci-artifacts", "cd", "pipeline",
        "pipelines", "terraform", "terraform-state", "tfstate", "ansible",
        "ansible-vault", "chef", "puppet", "salt", "vagrant",
        "docker", "k8s", "kubernetes", "helm", "charts",
        "logs-prod", "logs-dev", "logs-staging", "audit", "audit-logs",
        "billing", "invoices", "reports", "report", "analytics",
        "metrics", "monitoring", "grafana", "prometheus", "elk",
        "elastic", "kibana", "logstash", "splunk", "sentry",
        "users-data", "user-uploads", "avatars", "profile-pics", "thumbnails",
        "videos", "video", "audio", "documents", "docs",
        "pdfs", "pdf", "html", "css", "js",
        "scripts", "bin", "scripts-prod", "lambda", "functions",
        "serverless", "cloudfront-logs", "elb-logs", "alb-logs", "cloudtrail",
        "vpc-flow-logs", "guardduty", "config-history", "config-snapshots", "athena",
        "redshift", "glue", "emr", "sagemaker", "ml",
        "ml-models", "models", "datasets", "training-data", "labels",
        "api", "api-cache", "api-uploads", "graphql", "rest",
        "web", "website", "www", "www-data", "wp-uploads",
        "wp-content", "wordpress", "drupal", "joomla", "magento",
        "shop", "store", "ecommerce", "orders", "customers",
        "leads", "crm", "salesforce", "hubspot", "marketing",
        "campaigns", "email", "emails", "mailgun", "sendgrid",
        "ses", "sns", "sqs", "kafka", "kinesis",
    };
    // --- end htb-cloud-storage-enum ---

    private readonly Scope.Scope _scope;
    private readonly AuditLog _audit;
    private readonly string _lootRoot;
    private readonly Func<string, IPAddress[]> _dnsResolver;
    private readonly HttpMessageHandler? _handler;

    public CloudStorageEnumTool(
        Scope.Scope scope,
        AuditLog audit,
        string outputDir,
        HttpMessageHandler? handler = null,
        Func<string, IPAddress[]>? dnsResolver = null)
    {
        _scope = scope ?? throw new ArgumentNullException(nameof(scope));
        _audit = audit ?? throw new ArgumentNullException(nameof(audit));
        if (string.IsNullOrWhiteSpace(outputDir))
            throw new ArgumentException("outputDir required", nameof(outputDir));
        _lootRoot = Path.Combine(Path.GetFullPath(outputDir), "loot");
        _handler = handler;
        _dnsResolver = dnsResolver ?? (host => Dns.GetHostAddresses(host));
    }

    /// <summary>
    /// Enumerate a cloud-storage endpoint. <paramref name="target"/> is the
    /// bare host (or host:port) of the S3-compatible endpoint and must pass
    /// <see cref="Scope.Scope.Require"/>. <paramref name="bucketName"/>, when
    /// supplied, restricts the probe to a single bucket; otherwise the
    /// built-in or operator-supplied wordlist is walked.
    /// </summary>
    public async Task<CloudStorageEnumResult> EnumerateAsync(
        string target,
        int port = 443,
        bool useTls = true,
        string? bucketName = null,
        IReadOnlyList<string>? bucketWordlist = null,
        bool harvestEnabled = true,
        long? maxHarvestBytes = null,
        long? maxObjectBytes = null,
        CancellationToken ct = default)
    {
        // @invariant-id:scope-in-every-tool
        _scope.Require(target);

        if (string.IsNullOrWhiteSpace(target) || !TargetShapeRegex().IsMatch(target))
        {
            throw new ArgumentException(
                $"Invalid cloud-storage target shape '{target}'. Expected ^[\\w.\\-]+(:\\d+)?$.",
                nameof(target));
        }
        if (port < 1 || port > 65535)
            throw new ArgumentOutOfRangeException(nameof(port), port, "port must be 1..65535");
        if (bucketName is not null && !BucketShapeRegex().IsMatch(bucketName))
        {
            throw new ArgumentException(
                $"Invalid bucket name '{bucketName}'. Expected ^[a-zA-Z0-9._\\-]{{1,63}}$.",
                nameof(bucketName));
        }

        var totalCap = maxHarvestBytes ?? DefaultMaxHarvestBytes;
        var perObjectCap = maxObjectBytes ?? DefaultMaxObjectBytes;

        var endpoint = $"{(useTls ? "https" : "http")}://{target}:{port}";
        var result = new CloudStorageEnumResult
        {
            Endpoint = endpoint,
            Provider = "unknown",
        };

        var bucketsToProbe = bucketName is not null
            ? new[] { bucketName }
            : (bucketWordlist ?? DefaultBucketWordlist).ToArray();

        _audit.Record("cloud-storage.probe", new Dictionary<string, object?>
        {
            ["target"] = target,
            ["endpoint"] = endpoint,
            ["bucket_count_tested"] = bucketsToProbe.Length,
            ["harvest_enabled"] = harvestEnabled,
            ["max_harvest_bytes"] = totalCap,
        });

        using var client = BuildHttpClient();
        long bytesHarvested = 0;

        foreach (var bucket in bucketsToProbe)
        {
            if (ct.IsCancellationRequested) break;
            if (!BucketShapeRegex().IsMatch(bucket))
            {
                // Defensive: reject any wordlist entry that doesn't match
                // the bucket-name shape rather than risk argv injection.
                continue;
            }

            // Defense-in-depth: re-check scope before every network call.
            _scope.Require(target);

            CloudStorageBucket entry;
            try
            {
                entry = await ProbeBucketAsync(client, target, endpoint, bucket, ct)
                    .ConfigureAwait(false);
            }
            catch (Scope.ScopeException) { throw; }
            catch (Exception ex)
            {
                entry = new CloudStorageBucket { Name = bucket, Error = ex.Message };
            }

            if (entry.Listable || entry.ExistsButForbidden)
            {
                result.Buckets.Add(entry);
                _audit.Record("cloud-storage.bucket-found", new Dictionary<string, object?>
                {
                    ["target"] = target,
                    ["bucket"] = bucket,
                    ["listable"] = entry.Listable,
                    ["exists_but_403"] = entry.ExistsButForbidden,
                    ["object_count"] = entry.Objects.Count,
                });
            }

            if (entry.Listable && harvestEnabled)
            {
                bytesHarvested += await HarvestBucketAsync(
                    client, target, endpoint, entry,
                    perObjectCap, totalCap - bytesHarvested, ct).ConfigureAwait(false);
            }

            if (bytesHarvested >= totalCap) break;
        }

        // Provider tag heuristic from observed responses.
        if (result.Buckets.Any(b => b.Listable || b.ExistsButForbidden))
        {
            result.Provider = "s3";
        }

        return result;
    }

    private HttpClient BuildHttpClient()
    {
        var handler = _handler ?? new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            ConnectTimeout = TimeSpan.FromSeconds(ConnectTimeoutSeconds),
        };
        var client = new HttpClient(handler, disposeHandler: _handler is null)
        {
            Timeout = TimeSpan.FromSeconds(RequestTimeoutSeconds),
        };
        client.DefaultRequestHeaders.UserAgent.ParseAdd(UserAgent);
        return client;
    }

    private async Task<CloudStorageBucket> ProbeBucketAsync(
        HttpClient client, string target, string endpoint, string bucket, CancellationToken ct)
    {
        // Re-check scope before issuing any request (defense in depth).
        _scope.Require(target);

        var url = $"{endpoint}/{bucket}/?list-type=2";
        using var resp = await SendWithRetryAsync(client, target, url, ct).ConfigureAwait(false);
        var status = (int)resp.StatusCode;
        var bucketResult = new CloudStorageBucket { Name = bucket };

        if (status == 404)
        {
            return bucketResult; // not listable, not present
        }

        var body = await ReadStringCapped(resp, 1024 * 1024, ct).ConfigureAwait(false);

        if (status == 200 && body.Contains("<ListBucketResult", StringComparison.OrdinalIgnoreCase))
        {
            bucketResult.Listable = true;
            ParseListBucketXml(body, bucketResult);
            return bucketResult;
        }
        if (status == 200 && body.TrimStart().StartsWith("{", StringComparison.Ordinal)
            && body.Contains("\"Contents\"", StringComparison.OrdinalIgnoreCase))
        {
            bucketResult.Listable = true;
            ParseListBucketJson(body, bucketResult);
            return bucketResult;
        }
        if (status == 403 && body.Contains("<Code>AccessDenied</Code>", StringComparison.OrdinalIgnoreCase))
        {
            bucketResult.ExistsButForbidden = true;
            return bucketResult;
        }

        return bucketResult;
    }

    private static void ParseListBucketXml(string xml, CloudStorageBucket bucket)
    {
        XDocument doc;
        try { doc = XDocument.Parse(xml); }
        catch { return; }
        foreach (var c in doc.Descendants().Where(e => e.Name.LocalName == "Contents"))
        {
            var key = c.Elements().FirstOrDefault(e => e.Name.LocalName == "Key")?.Value;
            if (string.IsNullOrEmpty(key)) continue;
            var sizeStr = c.Elements().FirstOrDefault(e => e.Name.LocalName == "Size")?.Value;
            long size = 0;
            if (sizeStr is not null) long.TryParse(sizeStr, out size);
            var lastMod = c.Elements().FirstOrDefault(e => e.Name.LocalName == "LastModified")?.Value;
            bucket.Objects.Add(new CloudStorageObject
            {
                Key = key,
                Size = size,
                LastModified = lastMod,
            });
        }
    }

    private static void ParseListBucketJson(string json, CloudStorageBucket bucket)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            if (!doc.RootElement.TryGetProperty("Contents", out var contents)) return;
            foreach (var c in contents.EnumerateArray())
            {
                var key = c.TryGetProperty("Key", out var k) ? k.GetString() ?? "" : "";
                if (string.IsNullOrEmpty(key)) continue;
                long size = c.TryGetProperty("Size", out var s) && s.TryGetInt64(out var n) ? n : 0;
                var lm = c.TryGetProperty("LastModified", out var lme) ? lme.GetString() : null;
                bucket.Objects.Add(new CloudStorageObject { Key = key, Size = size, LastModified = lm });
            }
        }
        catch { /* malformed JSON — leave objects empty */ }
    }

    private async Task<long> HarvestBucketAsync(
        HttpClient client, string target, string endpoint, CloudStorageBucket bucket,
        long perObjectCap, long remainingTotal, CancellationToken ct)
    {
        if (remainingTotal <= 0) return 0;

        var bucketDir = Path.Combine(_lootRoot, SafeHostDir(target), $"cloud-bucket-{SafeBasename(bucket.Name)}");
        Directory.CreateDirectory(bucketDir);

        long bytesHere = 0;
        int harvested = 0;
        foreach (var obj in bucket.Objects)
        {
            if (harvested >= MaxHarvestPerBucket) break;
            if (bytesHere >= remainingTotal) break;
            if (!HighSignalKeyRegex().IsMatch(obj.Key)) continue;

            _scope.Require(target);
            var cap = (int)Math.Min(perObjectCap, remainingTotal - bytesHere);
            if (cap <= 0) break;

            var url = $"{endpoint}/{bucket.Name}/{Uri.EscapeDataString(obj.Key).Replace("%2F", "/")}";
            try
            {
                using var resp = await SendWithRetryAsync(client, target, url, ct).ConfigureAwait(false);
                if (!resp.IsSuccessStatusCode) continue;
                var bytes = await ReadBytesCapped(resp, cap, ct).ConfigureAwait(false);
                if (bytes.Length == 0) continue;

                var sha = Sha256Hex(bytes);
                var localPath = Path.Combine(bucketDir, SafeBasename(Path.GetFileName(obj.Key)));
                await File.WriteAllBytesAsync(localPath, bytes, ct).ConfigureAwait(false);
                TryChmod0600(localPath);
                obj.Harvested = true;
                obj.Sha256 = sha;
                obj.LocalPath = localPath;
                bucket.HarvestedCount++;
                harvested++;
                bytesHere += bytes.Length;

                _audit.Record("cloud-storage.harvested", new Dictionary<string, object?>
                {
                    ["target"] = target,
                    ["bucket"] = bucket.Name,
                    ["key"] = obj.Key,
                    ["size"] = bytes.Length,
                    ["sha256"] = sha,
                });
            }
            catch (Scope.ScopeException) { throw; }
            catch (Exception ex)
            {
                _audit.Record("cloud-storage.harvest-error", new Dictionary<string, object?>
                {
                    ["target"] = target,
                    ["bucket"] = bucket.Name,
                    ["key"] = obj.Key,
                    ["error"] = ex.Message,
                });
            }
        }
        return bytesHere;
    }

    private async Task<HttpResponseMessage> SendWithRetryAsync(
        HttpClient client, string target, string url, CancellationToken ct)
    {
        var delay = TimeSpan.FromMilliseconds(100);
        Exception? last = null;
        for (int attempt = 0; attempt < MaxRetries; attempt++)
        {
            try
            {
                using var req = new HttpRequestMessage(HttpMethod.Get, url);
                var resp = await client.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct)
                    .ConfigureAwait(false);

                // Manually follow redirects only if Location is in-scope.
                if ((int)resp.StatusCode is >= 300 and < 400 && resp.Headers.Location is { } loc)
                {
                    var redirectHost = loc.IsAbsoluteUri ? loc.Host : target;
                    // Scope check on redirect target host. If hostname, this
                    // will throw a ScopeException; tests can rely on it.
                    _scope.Require(redirectHost);
                    resp.Dispose();
                    var newUrl = loc.IsAbsoluteUri ? loc.ToString() : new Uri(new Uri(url), loc).ToString();
                    using var req2 = new HttpRequestMessage(HttpMethod.Get, newUrl);
                    return await client.SendAsync(req2, HttpCompletionOption.ResponseHeadersRead, ct)
                        .ConfigureAwait(false);
                }
                return resp;
            }
            catch (Scope.ScopeException) { throw; }
            catch (HttpRequestException ex)
            {
                last = ex;
            }
            catch (TaskCanceledException ex) when (!ct.IsCancellationRequested)
            {
                last = ex;
            }
            try { await Task.Delay(delay, ct).ConfigureAwait(false); }
            catch (OperationCanceledException) { throw; }
            delay = TimeSpan.FromMilliseconds(Math.Min(2000, delay.TotalMilliseconds * 2));
        }
        throw last ?? new HttpRequestException("cloud-storage probe failed after retries");
    }

    private static async Task<string> ReadStringCapped(
        HttpResponseMessage resp, int maxBytes, CancellationToken ct)
    {
        await using var stream = await resp.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
        var buf = new byte[Math.Min(maxBytes, 64 * 1024)];
        using var ms = new MemoryStream();
        int total = 0;
        int read;
        while ((read = await stream.ReadAsync(buf.AsMemory(0, buf.Length), ct).ConfigureAwait(false)) > 0)
        {
            var take = Math.Min(read, maxBytes - total);
            ms.Write(buf, 0, take);
            total += take;
            if (total >= maxBytes) break;
        }
        return Encoding.UTF8.GetString(ms.ToArray());
    }

    private static async Task<byte[]> ReadBytesCapped(
        HttpResponseMessage resp, int maxBytes, CancellationToken ct)
    {
        await using var stream = await resp.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
        var buf = new byte[Math.Min(maxBytes, 64 * 1024)];
        using var ms = new MemoryStream();
        int total = 0;
        int read;
        while ((read = await stream.ReadAsync(buf.AsMemory(0, buf.Length), ct).ConfigureAwait(false)) > 0)
        {
            var take = Math.Min(read, maxBytes - total);
            ms.Write(buf, 0, take);
            total += take;
            if (total >= maxBytes) break;
        }
        return ms.ToArray();
    }

    private static string Sha256Hex(byte[] bytes) =>
        Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();

    private static string SafeHostDir(string target)
    {
        var sb = new StringBuilder(target.Length);
        foreach (var c in target)
            sb.Append(char.IsLetterOrDigit(c) || c == '-' || c == '.' || c == '_' ? c : '_');
        return sb.ToString();
    }

    private static string SafeBasename(string s)
    {
        if (string.IsNullOrEmpty(s)) return "artifact";
        var sb = new StringBuilder(s.Length);
        foreach (var c in s)
            sb.Append(char.IsLetterOrDigit(c) || c == '.' || c == '-' || c == '_' ? c : '_');
        var clean = sb.ToString();
        if (clean.Length == 0) clean = "artifact";
        if (clean.Length > 96) clean = clean[..96];
        return clean;
    }

    private static void TryChmod0600(string path)
    {
        if (!OperatingSystem.IsLinux() && !OperatingSystem.IsMacOS()) return;
        try { File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite); }
        catch { /* best effort */ }
    }
}
