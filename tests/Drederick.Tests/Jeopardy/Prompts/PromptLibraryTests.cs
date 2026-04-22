using System.Collections.Generic;
using System.Text.Json;
using System.Text.RegularExpressions;
using Drederick.Jeopardy.Prompts;
using Xunit;

namespace Drederick.Tests.Jeopardy.Prompts;

public sealed class PromptLibraryTests
{
    private static ChallengeContext MakeChal(
        string category = "pwn",
        string name = "babyrop",
        int points = 100,
        IReadOnlyList<string>? attachments = null,
        string? conn = "nc chal.example 31337",
        IReadOnlyList<string>? tags = null,
        string description = "Classic stack buffer overflow. Pop a shell.")
        => new(
            Id: 42,
            Name: name,
            Category: category,
            Points: points,
            DescriptionPlaintext: description,
            AttachmentFileNames: attachments ?? new[] { "chal", "libc.so.6" },
            ConnectionInfo: conn,
            Tags: tags ?? new[] { "rop", "easy" });

    [Fact]
    public void AllSevenCategoriesHaveNonEmptyFragments()
    {
        string[] cats = { "pwn", "rev", "crypto", "forensics", "web", "stego", "misc" };
        foreach (var c in cats)
        {
            Assert.True(PromptLibrary.CategorySpecific.ContainsKey(c), $"missing {c}");
            var frag = PromptLibrary.CategorySpecific[c];
            Assert.False(string.IsNullOrWhiteSpace(frag), $"empty fragment for {c}");
            Assert.True(frag.Length > 500, $"fragment for {c} is suspiciously short");
        }
    }

    [Fact]
    public void PwnBuildMentionsPwntoolsAndChecksec()
    {
        var set = PromptLibrary.Build(MakeChal("pwn"), "solver-1", "gpt-5");
        Assert.Contains("pwntools", set.System, System.StringComparison.OrdinalIgnoreCase);
        Assert.Contains("checksec", set.System, System.StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void CryptoBuildMentionsRsaOrSage()
    {
        var set = PromptLibrary.Build(
            MakeChal("crypto", name: "smalln", conn: null,
                     attachments: new[] { "challenge.py", "output.txt" }),
            "solver-2", "gpt-5");
        var hay = set.System;
        var ok = hay.Contains("RSA", System.StringComparison.OrdinalIgnoreCase)
                 || hay.Contains("sage", System.StringComparison.OrdinalIgnoreCase);
        Assert.True(ok, "expected RSA or sage reference in crypto prompt");
    }

    [Fact]
    public void SharedPreambleContainsFairFightQuote()
    {
        Assert.Contains("fair fight", PromptLibrary.SharedPreamble,
            System.StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Tatum", PromptLibrary.SharedPreamble);
    }

    [Fact]
    public void UnknownCategoryFallsBackToMisc()
    {
        var frag = PromptLibrary.CategoryOrDefault("quantum-blockchain-ai");
        Assert.Equal(PromptLibrary.CategorySpecific["misc"], frag);
        Assert.False(string.IsNullOrWhiteSpace(frag));

        var empty = PromptLibrary.CategoryOrDefault("");
        Assert.Equal(PromptLibrary.CategorySpecific["misc"], empty);
    }

    [Fact]
    public void JsonInjectionCharsInNameRoundTripCleanly()
    {
        var nasty = "weird \"name\" with\nnewlines and \\ backslashes";
        var chal = MakeChal(name: nasty);
        var set = PromptLibrary.Build(chal, "solver-x", "gpt-5");

        var payload = new { system = set.System, user = set.InitialUser };
        var json = JsonSerializer.Serialize(payload);
        using var doc = JsonDocument.Parse(json);
        var sys = doc.RootElement.GetProperty("system").GetString();
        var usr = doc.RootElement.GetProperty("user").GetString();
        Assert.NotNull(sys);
        Assert.NotNull(usr);
        Assert.Contains(nasty, usr!);
        Assert.Contains(nasty, sys!);
    }

    [Fact]
    public void CoordinatorPromptHasBudgetAndCornerTone()
    {
        var p = PromptLibrary.CoordinatorSystemPrompt;
        Assert.Contains("budget", p, System.StringComparison.OrdinalIgnoreCase);
        var toneOk = p.Contains("corner", System.StringComparison.OrdinalIgnoreCase)
                  || p.Contains("round", System.StringComparison.OrdinalIgnoreCase);
        Assert.True(toneOk, "expected corner/round tone language");
    }

    [Fact]
    public void OperatorHintWrapperPreservesVerbatimHintAndMarksOrigin()
    {
        var hint = "try ret2libc";
        var msg = PromptLibrary.OperatorHintWrapper(hint);
        Assert.Contains(hint, msg);
        Assert.Contains("OPERATOR", msg, System.StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void InitialUserIncludesNamePointsCategoryAndAttachments()
    {
        var chal = MakeChal(
            category: "forensics",
            name: "packet_slayer",
            points: 350,
            attachments: new[] { "capture.pcapng", "notes.txt" },
            conn: null);
        var set = PromptLibrary.Build(chal, "solver-3", "gpt-5");
        Assert.Contains("packet_slayer", set.InitialUser);
        Assert.Contains("350", set.InitialUser);
        Assert.Contains("forensics", set.InitialUser, System.StringComparison.OrdinalIgnoreCase);
        Assert.Contains("capture.pcapng", set.InitialUser);
        Assert.Contains("notes.txt", set.InitialUser);
    }

    [Fact]
    public void EachCategoryFragmentMentionsAtLeastTwoConcreteTools()
    {
        // A conservative union of tool names we expect the fragments to
        // reference. Each category fragment must match at least two.
        var toolPattern = new Regex(
            @"\b(pwntools|checksec|gdb|pwndbg|angr|radare2|r2|ltrace|strace|ghidra|z3|sage|sagemath|" +
            @"gmpy2|openssl|factordb|volatility|vol|tshark|wireshark|foremost|mmls|fls|icat|binwalk|" +
            @"exiftool|olevba|pdf-parser|peepdf|apktool|jadx|ffuf|gobuster|sqlmap|jwt_tool|curl|" +
            @"stegsolve|steghide|stegseek|zsteg|sox|zbarimg|multimon-ng|strings|xxd|hashpump|" +
            @"fcrackzip|john|hydra|nc|socat|python3|msfconsole|pwninit|cyberchef|hexdump)\b",
            RegexOptions.IgnoreCase);

        foreach (var kv in PromptLibrary.CategorySpecific)
        {
            var matches = toolPattern.Matches(kv.Value);
            var distinct = new HashSet<string>(System.StringComparer.OrdinalIgnoreCase);
            foreach (Match m in matches) distinct.Add(m.Value);
            Assert.True(distinct.Count >= 2,
                $"category '{kv.Key}' mentions only {distinct.Count} tools");
        }
    }
}
