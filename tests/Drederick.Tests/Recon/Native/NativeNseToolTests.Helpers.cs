using System.Net;
using System.Net.Http;
using Drederick.Audit;
using Drederick.Scope;

namespace Drederick.Tests.Recon.Native;

internal static class NativeTestHelpers
{
    public static string NewAuditPath()
        => Path.Combine(AppContext.BaseDirectory, $"native-{Guid.NewGuid():N}.jsonl");

    public static AuditLog NewAudit() => new AuditLog(NewAuditPath());

    public static Scope.Scope SmallScope() => ScopeLoader.Parse("10.10.10.5");
}

internal sealed class StubHttpHandler : HttpMessageHandler
{
    private readonly Func<HttpRequestMessage, HttpResponseMessage> _respond;
    public List<HttpRequestMessage> Calls { get; } = new();

    public StubHttpHandler(Func<HttpRequestMessage, HttpResponseMessage> respond) => _respond = respond;

    protected override Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        Calls.Add(request);
        return Task.FromResult(_respond(request));
    }
}

internal sealed class ScriptedStream : Stream
{
    private readonly MemoryStream _serverToClient;
    private readonly MemoryStream _clientToServer = new();

    public ScriptedStream(byte[] serverBytes) => _serverToClient = new MemoryStream(serverBytes);

    public byte[] WrittenBytes => _clientToServer.ToArray();

    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => true;
    public override long Length => _serverToClient.Length;
    public override long Position { get => _serverToClient.Position; set => throw new NotSupportedException(); }
    public override void Flush() { }
    public override Task FlushAsync(CancellationToken ct) => Task.CompletedTask;
    public override int Read(byte[] buffer, int offset, int count) => _serverToClient.Read(buffer, offset, count);
    public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default)
        => _serverToClient.ReadAsync(buffer, ct);
    public override void Write(byte[] buffer, int offset, int count) => _clientToServer.Write(buffer, offset, count);
    public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken ct = default)
        => _clientToServer.WriteAsync(buffer, ct);
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
}
