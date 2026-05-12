using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using Drederick.Agent;
using Drederick.Audit;
using Drederick.Memory;
using Drederick.Recon;
using ToolBudget = Drederick.Agent.Budgets.ToolBudget;
using DifficultyProfile = Drederick.Agent.Budgets.DifficultyProfile;
using Xunit;

namespace Drederick.Tests.Agent;

/// <summary>
/// GAP-054: <see cref="PlanPriorBuilder"/> produces a structured
/// <see cref="PlanPrior"/> snapshot for the planner. Replaces the
/// opaque prose <c>runner.plan</c> "prior" string.
/// </summary>
public class PlanPriorBuilderTests
{
    private static string TempDir()
    {
        var dir = Path.Combine(Path.GetTempPath(), "drederick-planprior-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        return dir;
    }

    [Fact]
    public void Build_With_Empty_Kb_Yields_Empty_Collections_And_Zero_Counts()
    {
        var kb = new KnowledgeBase();
        var prior = PlanPriorBuilder.Build(kb, audit: null, budget: null);

        Assert.NotNull(prior);
        Assert.Empty(prior.Targets);
        Assert.Empty(prior.OpenServices);
        Assert.Empty(prior.PreviouslyAttempted);
        Assert.Equal(0, prior.CapturedCreds.Count);
        Assert.Equal(0, prior.ActiveSessions.Count);
        Assert.Equal(0, prior.Budget.Used);
        Assert.Equal(0, prior.Budget.Remaining);
    }

    [Fact]
    public void Build_Counts_Open_Services_Across_All_Hosts()
    {
        var kb = new KnowledgeBase();
        kb.Hosts["10.0.0.1"] = new HostFinding
        {
            Target = "10.0.0.1",
            Nmap = new NmapResult
            {
                OpenPorts =
                {
                    new NmapPort { Port = 22, Protocol = "tcp", Service = "ssh", Product = "OpenSSH", Version = "8.4" },
                    new NmapPort { Port = 80, Protocol = "tcp", Service = "http", Product = "nginx", Version = "1.18.0" },
                },
            },
        };
        kb.Hosts["10.0.0.2"] = new HostFinding
        {
            Target = "10.0.0.2",
            Nmap = new NmapResult
            {
                OpenPorts = { new NmapPort { Port = 445, Protocol = "tcp", Service = "smb", Product = "Samba", Version = "4.11" } },
            },
        };

        var prior = PlanPriorBuilder.Build(kb, audit: null, budget: null);

        Assert.Equal(3, prior.OpenServices.Count);
        Assert.Contains(prior.OpenServices, s => s.Host == "10.0.0.1" && s.Port == 22 && s.Product == "OpenSSH");
        Assert.Contains(prior.OpenServices, s => s.Host == "10.0.0.1" && s.Port == 80 && s.Product == "nginx");
        Assert.Contains(prior.OpenServices, s => s.Host == "10.0.0.2" && s.Port == 445 && s.Product == "Samba");
    }

    [Fact]
    public void Build_Includes_Cves_Per_Service_From_Findings_Dictionary()
    {
        var kb = new KnowledgeBase();
        var f = new HostFinding
        {
            Target = "10.0.0.1",
            Nmap = new NmapResult
            {
                OpenPorts = { new NmapPort { Port = 80, Protocol = "tcp", Product = "Apache", Version = "2.4.49" } },
            },
        };
        f.Findings["services.80.cves"] = "CVE-2021-41773, CVE-2021-42013";
        kb.Hosts["10.0.0.1"] = f;

        var prior = PlanPriorBuilder.Build(kb, audit: null, budget: null);

        var svc = Assert.Single(prior.OpenServices);
        Assert.Equal(2, svc.Cves.Count);
        Assert.Contains("CVE-2021-41773", svc.Cves);
        Assert.Contains("CVE-2021-42013", svc.Cves);
    }

    [Fact]
    public void Build_Reports_Captured_Cred_Count_Without_Plaintext_Canary()
    {
        const string canary = "hunter2-plaintext-canary";
        var kb = new KnowledgeBase();
        var f = new HostFinding { Target = "10.0.0.1" };
        f.Findings["cred.user.admin"] = canary;
        f.Findings["credentials.svc_account.hash"] = "deadbeef";
        f.Findings["unrelated.note"] = "ignored";
        kb.Hosts["10.0.0.1"] = f;

        var prior = PlanPriorBuilder.Build(kb, audit: null, budget: null);

        Assert.Equal(2, prior.CapturedCreds.Count);

        // The serialized form must not contain the plaintext canary.
        var json = JsonSerializer.Serialize(prior);
        Assert.DoesNotContain(canary, json);
        Assert.DoesNotContain("deadbeef", json);

        // The audit-fields shape must also be canary-free.
        var fields = prior.ToAuditFields();
        var fieldsJson = JsonSerializer.Serialize(fields);
        Assert.DoesNotContain(canary, fieldsJson);
    }

    [Fact]
    public void Build_Counts_Active_Sessions()
    {
        var kb = new KnowledgeBase();
        var f = new HostFinding { Target = "10.0.0.1" };
        f.Findings["session.meterpreter.1"] = "open";
        f.Findings["sessions.ssh.42"] = "open";
        kb.Hosts["10.0.0.1"] = f;

        var prior = PlanPriorBuilder.Build(kb, audit: null, budget: null);

        Assert.Equal(2, prior.ActiveSessions.Count);
    }

    [Fact]
    public void Build_Reports_Budget_Usage()
    {
        var kb = new KnowledgeBase();
        var budget = new ToolBudget(DifficultyProfile.Medium);
        budget.Charge("nmap", "10.0.0.1");
        budget.Charge("nmap", "10.0.0.2");

        var prior = PlanPriorBuilder.Build(kb, audit: null, budget: budget);

        Assert.Equal(2, prior.Budget.Used);
        Assert.Equal(budget.GlobalBudget - 2, prior.Budget.Remaining);
    }

    [Fact]
    public void Build_Dedups_PreviouslyAttempted_By_Tool_And_Target()
    {
        var dir = TempDir();
        try
        {
            var auditPath = Path.Combine(dir, "audit.jsonl");
            using (var audit = new AuditLog(auditPath))
            {
                audit.Record("nmap.start", new Dictionary<string, object?>
                {
                    ["tool"] = "nmap",
                    ["target"] = "10.0.0.1",
                    ["result_kind"] = "start",
                });
                audit.Record("nmap.finish", new Dictionary<string, object?>
                {
                    ["tool"] = "nmap",
                    ["target"] = "10.0.0.1",
                    ["result_kind"] = "success",
                });
                audit.Record("http.finish", new Dictionary<string, object?>
                {
                    ["tool"] = "http",
                    ["target"] = "10.0.0.1",
                    ["result_kind"] = "noop",
                });
                audit.Record("nmap.finish", new Dictionary<string, object?>
                {
                    ["tool"] = "nmap",
                    ["target"] = "10.0.0.2",
                    ["result_kind"] = "success",
                });
            }

            using var audit2 = new AuditLog(auditPath);
            var prior = PlanPriorBuilder.Build(new KnowledgeBase(), audit2, budget: null);

            // Two unique (nmap, 10.0.0.1) attempts collapse to one entry whose
            // result_kind is the most recent ("success", not "start").
            var nmap1 = prior.PreviouslyAttempted.Single(a => a.Tool == "nmap" && a.Target == "10.0.0.1");
            Assert.Equal("success", nmap1.ResultKind);
            Assert.Equal(3, prior.PreviouslyAttempted.Count);
            Assert.Contains(prior.PreviouslyAttempted, a => a.Tool == "http" && a.Target == "10.0.0.1");
            Assert.Contains(prior.PreviouslyAttempted, a => a.Tool == "nmap" && a.Target == "10.0.0.2");
        }
        finally
        {
            try { Directory.Delete(dir, recursive: true); } catch { }
        }
    }

    [Fact]
    public void AuditEmits_Structured_PlanPrior_Json_Not_Prose()
    {
        var dir = TempDir();
        try
        {
            var auditPath = Path.Combine(dir, "audit.jsonl");

            using (var audit = new AuditLog(auditPath))
            {
                var kb = new KnowledgeBase();
                kb.Hosts["10.0.0.1"] = new HostFinding
                {
                    Target = "10.0.0.1",
                    Nmap = new NmapResult
                    {
                        OpenPorts = { new NmapPort { Port = 22, Protocol = "tcp", Service = "ssh" } },
                    },
                };
                var prior = PlanPriorBuilder.Build(kb, audit: null, budget: null,
                    targets: new[] { "10.0.0.1" }, summary: "prior scan: 22/ssh");

                var fields = new Dictionary<string, object?>(prior.ToAuditFields())
                {
                    ["target"] = "10.0.0.1",
                };
                audit.Record("runner.plan.prior", fields);
            }

            var lines = File.ReadAllLines(auditPath);
            var line = Assert.Single(lines);

            using var doc = JsonDocument.Parse(line);
            var root = doc.RootElement;
            Assert.Equal("runner.plan.prior", root.GetProperty("event").GetString());

            // Structured object, not a prose string blob.
            var openServices = root.GetProperty("open_services");
            Assert.Equal(JsonValueKind.Array, openServices.ValueKind);
            Assert.Equal(1, openServices.GetArrayLength());
            Assert.Equal(22, openServices[0].GetProperty("port").GetInt32());

            Assert.Equal(JsonValueKind.Object, root.GetProperty("captured_creds").ValueKind);
            Assert.Equal(JsonValueKind.Object, root.GetProperty("active_sessions").ValueKind);
            Assert.Equal(JsonValueKind.Object, root.GetProperty("budget").ValueKind);
            Assert.Equal(JsonValueKind.Array, root.GetProperty("previously_attempted").ValueKind);

            // Summary is a backwards-compatible human-readable hint.
            Assert.Equal("prior scan: 22/ssh", root.GetProperty("summary").GetString());
        }
        finally
        {
            try { Directory.Delete(dir, recursive: true); } catch { }
        }
    }
}
