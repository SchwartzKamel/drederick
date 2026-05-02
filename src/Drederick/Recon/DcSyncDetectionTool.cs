using Drederick.Audit;
using Drederick.Recon.Shared;

namespace Drederick.Recon
{
    /// <summary>
    /// Read-only AD enumeration tool: detect principals that hold
    /// DS-Replication rights on the domain root object (the classic
    /// "DCSync rights" check).
    ///
    /// Mechanism: fetches <c>nTSecurityDescriptor</c> of the domain root
    /// via a base-scope LDAP search, then parses the DACL for
    /// <c>ACCESS_ALLOWED_OBJECT_ACE</c> entries (type 0x05) whose
    /// <c>ObjectType</c> GUID matches one of the three replication right GUIDs:
    ///
    /// <list type="bullet">
    ///   <item><c>DS-Replication-Get-Changes</c>
    ///   <c>1131f6aa-9c07-11d1-f79f-00c04fc2dcd2</c></item>
    ///   <item><c>DS-Replication-Get-Changes-All</c>
    ///   <c>1131f6ab-9c07-11d1-f79f-00c04fc2dcd2</c></item>
    ///   <item><c>DS-Replication-Get-Changes-In-Filtered-Set</c>
    ///   <c>89e95b76-444d-4c62-991a-0facbeda640c</c></item>
    /// </list>
    ///
    /// Principals with those GUIDs in their ACEs are split into two buckets:
    /// <list type="bullet">
    ///   <item><see cref="DcSyncRightsResult.SuspiciousPrincipals"/> —
    ///   unexpected holders (non-DC / non-admin accounts) that are likely
    ///   indicators of compromise or misconfiguration. Severity <c>red</c>.</item>
    ///   <item><see cref="DcSyncRightsResult.KnownLegitimate"/> — well-known
    ///   holders (Domain Controllers, Domain Admins, Enterprise Admins, SYSTEM,
    ///   BUILTIN\Administrators, Schema Admins, KRBTGT). Still surfaced for
    ///   operator completeness review.</item>
    /// </list>
    ///
    /// Scope is enforced as the first statement. Anonymous bind by default;
    /// simple bind when creds supplied. Plaintext bind password is never logged.
    /// </summary>
    public sealed class DcSyncDetectionTool : IReconTool
    {
        public string Name => "dcsync-detect";

        public string Description =>
            "Detect principals with DS-Replication rights on the domain root via LDAP " +
            "nTSecurityDescriptor parse. Read-only; surfaces unexpected DCSync right holders " +
            "as potential IoC or misconfiguration. Anonymous or simple-bind.";

        // ACCESS_ALLOWED_OBJECT_ACE type.
        internal const byte AceTypeAllowedObject = 0x05;
        // ACE_OBJECT_TYPE_PRESENT flag.
        internal const uint AceFlagObjectTypePresent = 0x1;

        // DS-Replication-Get-Changes: 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2
        // Stored as Windows mixed-endian GUID (bytes).
        internal static readonly byte[] GuidGetChanges =
            new byte[] { 0xaa, 0xf6, 0x31, 0x11, 0x07, 0x9c, 0xd1, 0x11, 0xf7, 0x9f, 0x00, 0xc0, 0x4f, 0xc2, 0xdc, 0xd2 };

        // DS-Replication-Get-Changes-All: 1131f6ab-9c07-11d1-f79f-00c04fc2dcd2
        internal static readonly byte[] GuidGetChangesAll =
            new byte[] { 0xab, 0xf6, 0x31, 0x11, 0x07, 0x9c, 0xd1, 0x11, 0xf7, 0x9f, 0x00, 0xc0, 0x4f, 0xc2, 0xdc, 0xd2 };

        // DS-Replication-Get-Changes-In-Filtered-Set: 89e95b76-444d-4c62-991a-0facbeda640c
        internal static readonly byte[] GuidGetChangesFiltered =
            new byte[] { 0x76, 0x5b, 0xe9, 0x89, 0x4d, 0x44, 0x62, 0x4c, 0x99, 0x1a, 0x0f, 0xac, 0xbe, 0xda, 0x64, 0x0c };

        // SID last-sub-authority (RID) values that identify well-known legitimate holders.
        internal static readonly uint[] LegitimateRids = new uint[]
        {
            502,   // KRBTGT
            512,   // Domain Admins
            516,   // Domain Controllers
            518,   // Schema Admins
            519,   // Enterprise Admins
            544,   // BUILTIN\Administrators (for the S-1-5-32-544 case)
        };

        // Well-known SIDs that are always legitimate (non-domain-relative).
        internal static readonly string[] LegitimateWellKnownSids = new[]
        {
            "S-1-5-9",   // Enterprise Domain Controllers
            "S-1-5-18",  // NT AUTHORITY\SYSTEM
            "S-1-5-32-544", // BUILTIN\Administrators
        };

        internal const int MaxPrincipals = 200;

        private readonly Scope.Scope _scope;
        private readonly AuditLog _audit;
        private readonly Func<string, int, string?, string?, ILdapClient> _connectFactory;

        public DcSyncDetectionTool(
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

        public Task<DcSyncRightsResult> ProbeAsync(
            string target,
            int port = 389,
            string? bindUser = null,
            string? bindPassword = null,
            CancellationToken ct = default)
        {
            _scope.Require(target);

            _audit.Record("dcsync-detect.start", new Dictionary<string, object?>
            {
                ["target"] = target,
                ["port"] = port,
                ["authenticated"] = !string.IsNullOrEmpty(bindUser),
            });

            var result = new DcSyncRightsResult
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

                string? baseDn;
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

                // Fetch the nTSecurityDescriptor of the domain root with a
                // base-scope search so we don't walk the whole tree.
                IEnumerable<LdapEntry> entries;
                try
                {
                    entries = client.Search(
                        baseDn,
                        "(objectClass=domain)",
                        new[] { "nTSecurityDescriptor" },
                        sizeLimit: 1);
                }
                catch (Exception ex)
                {
                    result.Error = $"nTSecurityDescriptor search failed: {Tail(ex.Message, 300)}";
                    RecordFinish(target, port, result);
                    return Task.FromResult(result);
                }

                foreach (var entry in entries)
                {
                    if (!entry.Attributes.TryGetValue("nTSecurityDescriptor", out var vals) ||
                        vals.Count == 0)
                        continue;

                    // The value may be hex-encoded binary or base64-encoded binary,
                    // depending on the DefaultLdapClient implementation. We try both.
                    var raw = vals[0];
                    byte[]? sdBytes = TryDecodeDescriptor(raw);
                    if (sdBytes is null || sdBytes.Length < 20)
                    {
                        result.Error = "nTSecurityDescriptor could not be decoded or is too short";
                        continue;
                    }

                    ParseAcl(sdBytes, result, baseDn);
                    break; // Only one domain root.
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

        /// <summary>
        /// Parse the DACL of a self-relative security descriptor binary blob
        /// for ACCESS_ALLOWED_OBJECT_ACE entries that grant DS-Replication
        /// rights. Appends findings to <paramref name="result"/>.
        /// </summary>
        internal static void ParseAcl(byte[] sd, DcSyncRightsResult result, string? baseDn = null)
        {
            if (sd.Length < 20) return;

            // SD header layout (self-relative):
            //   offset 0: Revision (1)
            //   offset 1: Sbz1 (1)
            //   offset 2: Control (2, LE)
            //   offset 4: OffsetOwner (4, LE)
            //   offset 8: OffsetGroup (4, LE)
            //   offset 12: OffsetSacl (4, LE)
            //   offset 16: OffsetDacl (4, LE)
            int offDacl = BitConverter.ToInt32(sd, 16);
            if (offDacl <= 0 || offDacl >= sd.Length - 8) return;

            // ACL header: Revision(1) Sbz1(1) AclSize(2,LE) AceCount(2,LE) Sbz2(2)
            int aceCount = BitConverter.ToUInt16(sd, offDacl + 4);
            int cursor = offDacl + 8;

            for (int i = 0; i < aceCount && cursor + 4 < sd.Length; i++)
            {
                byte aceType = sd[cursor];
                int aceSize = BitConverter.ToUInt16(sd, cursor + 2);
                if (aceSize < 4 || cursor + aceSize > sd.Length) break;

                if (aceType == AceTypeAllowedObject && aceSize >= 12 + 4)
                {
                    // ACCESS_ALLOWED_OBJECT_ACE layout within ACE:
                    //   cursor+0: type(1), flags(1), size(2)  — ACE header
                    //   cursor+4: Mask(4)
                    //   cursor+8: ObjectFlags(4)
                    //   cursor+12: ObjectType GUID(16) if (Flags & 1)
                    //   cursor+28: InheritedObjectType GUID(16) if (Flags & 2)
                    //   then SID
                    uint objectFlags = BitConverter.ToUInt32(sd, cursor + 8);
                    bool objectTypePresent = (objectFlags & AceFlagObjectTypePresent) != 0;
                    bool inheritedTypePresent = (objectFlags & 0x2) != 0;

                    if (objectTypePresent && cursor + 12 + 16 <= sd.Length)
                    {
                        // Check if ObjectType GUID matches one of the replication right GUIDs.
                        string? rightName = MatchReplicationGuid(sd, cursor + 12);
                        if (rightName != null)
                        {
                            // SID starts after the GUID(s).
                            int sidOffset = cursor + 12 + 16;
                            if (inheritedTypePresent) sidOffset += 16;
                            var sid = DelegationEnumTool.TryFormatSid(sd, sidOffset, cursor + aceSize - sidOffset);
                            if (sid != null)
                            {
                                AddPrincipal(result, sid, rightName, baseDn);
                            }
                        }
                    }
                }

                cursor += aceSize;
            }
        }

        /// <summary>Check if 16 bytes starting at <paramref name="off"/> in
        /// <paramref name="sd"/> match a DS-Replication right GUID.
        /// Returns the right name, or null if no match.</summary>
        internal static string? MatchReplicationGuid(byte[] sd, int off)
        {
            if (off + 16 > sd.Length) return null;
            if (GuidMatches(sd, off, GuidGetChangesAll)) return "DS-Replication-Get-Changes-All";
            if (GuidMatches(sd, off, GuidGetChanges)) return "DS-Replication-Get-Changes";
            if (GuidMatches(sd, off, GuidGetChangesFiltered)) return "DS-Replication-Get-Changes-In-Filtered-Set";
            return null;
        }

        private static bool GuidMatches(byte[] sd, int off, byte[] guid)
        {
            for (int i = 0; i < 16; i++)
            {
                if (sd[off + i] != guid[i]) return false;
            }
            return true;
        }

        private static void AddPrincipal(
            DcSyncRightsResult result,
            string sid,
            string rightName,
            string? baseDn)
        {
            bool isLegit = IsWellKnownLegitimate(sid, baseDn);

            var bucket = isLegit ? result.KnownLegitimate : result.SuspiciousPrincipals;
            if (bucket.Count >= MaxPrincipals) return;

            var existing = bucket.FirstOrDefault(p => p.Sid == sid);
            if (existing != null)
            {
                if (!existing.Rights.Contains(rightName))
                    existing.Rights.Add(rightName);
                return;
            }

            bucket.Add(new DcSyncPrincipal
            {
                Sid = sid,
                Rights = new List<string> { rightName },
                Severity = isLegit ? "green" : "red",
                Hint = isLegit
                    ? "Known-legitimate AD principal with DS-Replication rights."
                    : "Unexpected principal with DS-Replication right — potential DCSync " +
                      "backdoor or misconfiguration. Correlate with AD change logs.",
            });
        }

        /// <summary>
        /// Determine whether a SID is a well-known legitimate holder of
        /// DS-Replication rights in a standard AD deployment.
        ///
        /// Legitimate RIDs (relative to the domain): 502 (KRBTGT), 512
        /// (Domain Admins), 516 (Domain Controllers), 518 (Schema Admins),
        /// 519 (Enterprise Admins). Also S-1-5-9 and S-1-5-18 (SYSTEM) and
        /// S-1-5-32-544 (BUILTIN\Administrators).
        /// </summary>
        internal static bool IsWellKnownLegitimate(string sid, string? baseDn = null)
        {
            if (LegitimateWellKnownSids.Contains(sid, StringComparer.OrdinalIgnoreCase))
                return true;

            // Extract last sub-authority (RID).
            var lastDash = sid.LastIndexOf('-');
            if (lastDash < 0) return false;
            if (!uint.TryParse(sid[(lastDash + 1)..], out var rid)) return false;
            return Array.IndexOf(LegitimateRids, rid) >= 0;
        }

        /// <summary>
        /// Try to decode the LDAP attribute value as a binary security
        /// descriptor. Accepts hex-encoded strings and base64-encoded strings.
        /// </summary>
        internal static byte[]? TryDecodeDescriptor(string raw)
        {
            if (string.IsNullOrEmpty(raw)) return null;
            // Try hex first (most common in LDAP string-encoding for binary attrs).
            if (IsHex(raw))
            {
                try { return Convert.FromHexString(raw.Trim()); } catch { }
            }
            // Try base64.
            try { return Convert.FromBase64String(raw.Trim()); } catch { }
            return null;
        }

        private static bool IsHex(string s)
        {
            if (s.Length < 2 || (s.Length & 1) != 0) return false;
            foreach (var c in s)
            {
                if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
                    return false;
            }
            return true;
        }

        private void RecordFinish(string target, int port, DcSyncRightsResult result)
        {
            _audit.Record("dcsync-detect.finish", new Dictionary<string, object?>
            {
                ["target"] = target,
                ["port"] = port,
                ["realm"] = result.Realm,
                ["suspicious_count"] = result.SuspiciousPrincipals.Count,
                ["legitimate_count"] = result.KnownLegitimate.Count,
                ["error"] = result.Error,
            });
        }

        private static string Tail(string s, int max) =>
            string.IsNullOrEmpty(s) ? string.Empty : (s.Length <= max ? s : s[^max..]);
    }
}
