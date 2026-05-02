using System.Text.RegularExpressions;
using Drederick.Audit;
using Drederick.Recon.Shared;

namespace Drederick.Recon
{
    /// <summary>
    /// Enumerate Active Directory delegation primitives via LDAP. Pure
    /// directory read; this tool does NOT request a TGT, does NOT perform
    /// S4U2Self or S4U2Proxy, and does NOT speak the Kerberos protocol.
    /// It only inspects the four LDAP attributes that reveal which
    /// principals are configured for delegation:
    ///
    /// <list type="bullet">
    ///   <item><c>userAccountControl &amp; 0x80000</c>
    ///   (TRUSTED_FOR_DELEGATION) — unconstrained delegation.</item>
    ///   <item><c>userAccountControl &amp; 0x1000000</c>
    ///   (TRUSTED_TO_AUTH_FOR_DELEGATION) — constrained delegation
    ///   with protocol transition.</item>
    ///   <item><c>msDS-AllowedToDelegateTo</c> populated — constrained
    ///   delegation (target SPN list).</item>
    ///   <item><c>msDS-AllowedToActOnBehalfOfOtherIdentity</c> populated
    ///   — resource-based constrained delegation (RBCD).</item>
    /// </list>
    ///
    /// Scope is enforced first; LDAP bind is anonymous unless explicit
    /// credentials are supplied. Result cardinality is bounded by
    /// <see cref="MaxEntriesPerBucket"/> per bucket. The
    /// <c>msDS-AllowedToActOnBehalfOfOtherIdentity</c> attribute is a raw
    /// security descriptor; we extract only the principal SIDs for
    /// audit/result reporting and never decrypt or replay any tickets.
    /// </summary>
    public sealed class DelegationEnumTool : IReconTool
    {
        public string Name => "delegation-enum";

        public string Description =>
            "Enumerate AD delegation primitives via LDAP — unconstrained, constrained " +
            "(with and without protocol transition), and RBCD. Read-only; no Kerberos " +
            "exchange, no S4U. Anonymous bind by default; simple bind when creds supplied.";

        internal const int MaxEntriesPerBucket = 250;
        internal const int MaxSearchSize = 4000;

        // LDAP_MATCHING_RULE_BIT_AND OID
        internal const string BitAndOid = "1.2.840.113556.1.4.803";

        // userAccountControl bit flags.
        internal const int UAC_TRUSTED_FOR_DELEGATION = 0x80000;
        internal const int UAC_TRUSTED_TO_AUTH_FOR_DELEGATION = 0x1000000;

        private readonly Scope.Scope _scope;
        private readonly AuditLog _audit;
        private readonly Func<string, int, string?, string?, ILdapClient> _connectFactory;

        public DelegationEnumTool(
            Scope.Scope scope,
            AuditLog audit,
            Func<string, int, string?, string?, ILdapClient>? connectFactory = null)
        {
            _scope = scope;
            _audit = audit;
            _connectFactory = connectFactory ?? DefaultConnect;
        }

        private static ILdapClient DefaultConnect(string host, int port, string? user, string? password)
            => new DefaultLdapClient(host, port);

        public Task<DelegationEnumResult> ProbeAsync(
            string target,
            int port = 389,
            string? bindUser = null,
            string? bindPassword = null,
            CancellationToken ct = default)
        {
            _scope.Require(target);

            _audit.Record("delegation-enum.start", new Dictionary<string, object?>
            {
                ["target"] = target,
                ["port"] = port,
                ["authenticated"] = !string.IsNullOrEmpty(bindUser),
            });

            var result = new DelegationEnumResult
            {
                Port = port,
                Authenticated = !string.IsNullOrEmpty(bindUser),
            };

            ILdapClient? client = null;
            try
            {
                client = _connectFactory(target, port, bindUser, bindPassword);
                try
                {
                    client.Bind(bindUser, bindPassword);
                }
                catch (Exception ex)
                {
                    result.Error = string.IsNullOrEmpty(bindUser)
                        ? $"anonymous bind refused: {Tail(ex.Message, 300)}"
                        : $"bind failed: {Tail(ex.Message, 300)}";
                    RecordFinish(target, port, result);
                    return Task.FromResult(result);
                }

                ct.ThrowIfCancellationRequested();

                string? baseDn = null;
                try { baseDn = client.GetDefaultNamingContext(); }
                catch (Exception ex)
                {
                    result.Error = $"rootDSE read failed: {Tail(ex.Message, 300)}";
                    RecordFinish(target, port, result);
                    return Task.FromResult(result);
                }

                if (string.IsNullOrWhiteSpace(baseDn))
                {
                    result.Error = "no defaultNamingContext on rootDSE";
                    RecordFinish(target, port, result);
                    return Task.FromResult(result);
                }
                result.BaseDn = baseDn;
                result.Realm = KerberosTool.RealmFromNamingContext(baseDn) ?? KerberosTool.RealmFromHostname(target);

                // One subtree search keyed off any of the four delegation
                // signals. Filter is the OR of:
                //  • userAccountControl bit-AND with TRUSTED_FOR_DELEGATION
                //  • userAccountControl bit-AND with TRUSTED_TO_AUTH_FOR_DELEGATION
                //  • msDS-AllowedToDelegateTo populated
                //  • msDS-AllowedToActOnBehalfOfOtherIdentity populated
                var filter = string.Format(
                    "(&(|(userAccountControl:{0}:={1})(userAccountControl:{0}:={2})(msDS-AllowedToDelegateTo=*)(msDS-AllowedToActOnBehalfOfOtherIdentity=*))(|(samAccountType=805306368)(samAccountType=805306369)))",
                    BitAndOid, UAC_TRUSTED_FOR_DELEGATION, UAC_TRUSTED_TO_AUTH_FOR_DELEGATION);

                IEnumerable<LdapEntry> entries;
                try
                {
                    entries = client.Search(baseDn, filter, new[]
                    {
                        "sAMAccountName",
                        "userAccountControl",
                        "msDS-AllowedToDelegateTo",
                        "msDS-AllowedToActOnBehalfOfOtherIdentity",
                    }, MaxSearchSize);
                }
                catch (Exception ex)
                {
                    result.Error = $"delegation search failed: {Tail(ex.Message, 300)}";
                    RecordFinish(target, port, result);
                    return Task.FromResult(result);
                }

                foreach (var entry in entries)
                {
                    Classify(entry, result);
                    if (BucketsFull(result)) break;
                }
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex)
            {
                result.Error = Tail(ex.Message, 500);
            }
            finally
            {
                try { client?.Dispose(); } catch { /* best-effort */ }
            }

            RecordFinish(target, port, result);
            return Task.FromResult(result);
        }

        internal static void Classify(LdapEntry entry, DelegationEnumResult result)
        {
            var sam = FirstAttr(entry, "sAMAccountName") ?? "";
            var uacStr = FirstAttr(entry, "userAccountControl");
            int uac = 0;
            if (!string.IsNullOrEmpty(uacStr)) int.TryParse(uacStr, out uac);
            entry.Attributes.TryGetValue("msDS-AllowedToDelegateTo", out var allowedTo);
            entry.Attributes.TryGetValue("msDS-AllowedToActOnBehalfOfOtherIdentity", out var rbcdRaw);

            var isComputer = sam.EndsWith("$", StringComparison.Ordinal);

            // Unconstrained.
            if ((uac & UAC_TRUSTED_FOR_DELEGATION) != 0 &&
                (uac & UAC_TRUSTED_TO_AUTH_FOR_DELEGATION) == 0 &&
                result.Unconstrained.Count < MaxEntriesPerBucket)
            {
                result.Unconstrained.Add(new DelegationPrincipal
                {
                    SamAccountName = sam,
                    DistinguishedName = entry.DistinguishedName,
                    UserAccountControl = uac,
                    IsComputer = isComputer,
                    Severity = "red",
                    Hint =
                        "Unconstrained delegation. If a privileged user authenticates to this " +
                        "host (forced auth via PetitPotam/PrinterBug, or any honest auth), the host " +
                        "stores the user's TGT in memory — extractable to impersonate the user.",
                });
            }

            // Constrained with protocol transition (TRUSTED_TO_AUTH_FOR_DELEGATION).
            if ((uac & UAC_TRUSTED_TO_AUTH_FOR_DELEGATION) != 0 &&
                result.ConstrainedWithProtocolTransition.Count < MaxEntriesPerBucket)
            {
                result.ConstrainedWithProtocolTransition.Add(new DelegationPrincipal
                {
                    SamAccountName = sam,
                    DistinguishedName = entry.DistinguishedName,
                    UserAccountControl = uac,
                    IsComputer = isComputer,
                    AllowedToDelegateTo = allowedTo?.ToList() ?? new List<string>(),
                    Severity = "red",
                    Hint =
                        "Constrained delegation with protocol transition. If we control this " +
                        "principal we can S4U2Self for any user (no original TGT required) then " +
                        "S4U2Proxy to any SPN in msDS-AllowedToDelegateTo — full impersonation " +
                        "to those services.",
                });
            }

            // Constrained without protocol transition.
            if (allowedTo is { Count: > 0 } &&
                (uac & UAC_TRUSTED_TO_AUTH_FOR_DELEGATION) == 0 &&
                result.Constrained.Count < MaxEntriesPerBucket)
            {
                result.Constrained.Add(new DelegationPrincipal
                {
                    SamAccountName = sam,
                    DistinguishedName = entry.DistinguishedName,
                    UserAccountControl = uac,
                    IsComputer = isComputer,
                    AllowedToDelegateTo = allowedTo.ToList(),
                    Severity = "yellow",
                    Hint =
                        "Constrained delegation (no protocol transition). Requires an existing " +
                        "forwardable TGT for the impersonated user — typically obtained by " +
                        "first compromising the principal and waiting for the user to auth.",
                });
            }

            // RBCD.
            if (rbcdRaw is { Count: > 0 } &&
                result.Rbcd.Count < MaxEntriesPerBucket)
            {
                var sids = new List<string>();
                foreach (var raw in rbcdRaw)
                {
                    sids.AddRange(ExtractSidsFromSecurityDescriptor(raw));
                }
                if (sids.Count > 0)
                {
                    result.Rbcd.Add(new DelegationPrincipal
                    {
                        SamAccountName = sam,
                        DistinguishedName = entry.DistinguishedName,
                        UserAccountControl = uac,
                        IsComputer = isComputer,
                        AllowedToActPrincipalSids = sids,
                        Severity = "red",
                        Hint =
                            "Resource-based constrained delegation (RBCD). If we control any of " +
                            "the listed principal SIDs (or can create a computer account via " +
                            "ms-DS-MachineAccountQuota) we can S4U-impersonate any user, including " +
                            "Domain Admins, to this resource.",
                    });
                }
            }
        }

        /// <summary>
        /// Pull principal SIDs out of a serialized security descriptor.
        /// Inputs we accept (callers vary):
        /// <list type="bullet">
        ///   <item>SDDL string already containing <c>(A;;...;;;S-1-...)</c>
        ///   ACE clauses — we regex-extract every <c>S-1-...</c> token.</item>
        ///   <item>Raw binary represented as a hex string (e.g.
        ///   <c>"01000400..."</c>) — we walk the ACL ACE-by-ACE and build
        ///   the SDDL form of each <c>SID</c> field.</item>
        ///   <item>Any other string — best-effort regex of <c>S-1-...</c>.</item>
        /// </list>
        /// We never decrypt anything; we never call into Win32 SDDL APIs
        /// (would require platform-specific code). The intent is recon
        /// reporting, not enforcement.
        /// </summary>
        internal static List<string> ExtractSidsFromSecurityDescriptor(string raw)
        {
            var sids = new List<string>();
            if (string.IsNullOrEmpty(raw)) return sids;

            // Path 1: SDDL or anything with literal "S-1-…" tokens.
            foreach (Match m in Regex.Matches(raw, @"S-\d-\d+(?:-\d+)+"))
            {
                if (!sids.Contains(m.Value, StringComparer.OrdinalIgnoreCase))
                    sids.Add(m.Value);
            }
            if (sids.Count > 0) return sids;

            // Path 2: hex-encoded binary SD. ACL header is at offset 0
            // for an ACL-only blob, but msDS-AllowedToActOnBehalfOf...
            // is a full self-relative SD. Find the DACL via the OffsetDacl
            // field at byte offset 16, then walk ACEs.
            if (!IsHex(raw)) return sids;
            byte[] bytes;
            try { bytes = Convert.FromHexString(raw.Trim()); }
            catch { return sids; }
            if (bytes.Length < 20) return sids;

            int offDacl = BitConverter.ToInt32(bytes, 16);
            if (offDacl <= 0 || offDacl >= bytes.Length - 8) return sids;

            // ACL header: byte 0 revision, byte 1 sbz1, bytes 2-3 ACL size,
            // bytes 4-5 ACE count, bytes 6-7 sbz2.
            int aceCount = BitConverter.ToUInt16(bytes, offDacl + 4);
            int cursor = offDacl + 8;
            for (int i = 0; i < aceCount && cursor + 8 < bytes.Length; i++)
            {
                int aceSize = BitConverter.ToUInt16(bytes, cursor + 2);
                if (aceSize <= 0 || cursor + aceSize > bytes.Length) break;
                // Standard ACE header: type(1) flags(1) size(2) mask(4) sid(...)
                int sidStart = cursor + 8;
                if (sidStart + 8 > bytes.Length) break;
                var sid = TryFormatSid(bytes, sidStart, aceSize - 8);
                if (!string.IsNullOrEmpty(sid) && !sids.Contains(sid, StringComparer.OrdinalIgnoreCase))
                    sids.Add(sid);
                cursor += aceSize;
            }
            return sids;
        }

        /// <summary>
        /// Format a SID from a Win32 self-relative SID at <paramref name="bytes"/>+<paramref name="off"/>.
        /// Layout: revision(1) subAuthCount(1) authority(6 BE) subAuth0..subAuthN-1(4 LE each).
        /// Returns "S-r-a-s0-s1-..." or null on malformed input.
        /// </summary>
        internal static string? TryFormatSid(byte[] bytes, int off, int max)
        {
            if (off + 8 > bytes.Length || max < 8) return null;
            byte rev = bytes[off];
            byte subCount = bytes[off + 1];
            // 6-byte big-endian authority.
            long auth = 0;
            for (int i = 0; i < 6; i++) auth = (auth << 8) | bytes[off + 2 + i];
            int needed = 8 + subCount * 4;
            if (needed > max || off + needed > bytes.Length) return null;
            var sb = new System.Text.StringBuilder();
            sb.Append("S-").Append(rev).Append('-').Append(auth);
            for (int i = 0; i < subCount; i++)
            {
                uint sa = BitConverter.ToUInt32(bytes, off + 8 + i * 4);
                sb.Append('-').Append(sa);
            }
            return sb.ToString();
        }

        private static bool IsHex(string s)
        {
            if (s.Length < 4 || (s.Length & 1) != 0) return false;
            for (int i = 0; i < s.Length; i++)
            {
                var c = s[i];
                if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
                    return false;
            }
            return true;
        }

        private static bool BucketsFull(DelegationEnumResult r) =>
            r.Unconstrained.Count >= MaxEntriesPerBucket
            && r.Constrained.Count >= MaxEntriesPerBucket
            && r.ConstrainedWithProtocolTransition.Count >= MaxEntriesPerBucket
            && r.Rbcd.Count >= MaxEntriesPerBucket;

        private static string? FirstAttr(LdapEntry e, string name)
            => e.Attributes.TryGetValue(name, out var v) && v.Count > 0 ? v[0] : null;

        private void RecordFinish(string target, int port, DelegationEnumResult result)
        {
            _audit.Record("delegation-enum.finish", new Dictionary<string, object?>
            {
                ["target"] = target,
                ["port"] = port,
                ["realm"] = result.Realm,
                ["base_dn"] = result.BaseDn,
                ["unconstrained_count"] = result.Unconstrained.Count,
                ["constrained_count"] = result.Constrained.Count,
                ["constrained_protocol_transition_count"] = result.ConstrainedWithProtocolTransition.Count,
                ["rbcd_count"] = result.Rbcd.Count,
                ["error"] = result.Error,
            });
        }

        private static string Tail(string s, int max) =>
            string.IsNullOrEmpty(s) ? string.Empty : (s.Length <= max ? s : s[^max..]);
    }
}
