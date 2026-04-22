// Exposes internal helpers (validation helpers, throttle reset hooks) to the
// test assembly so tests can exercise tightly-scoped surfaces without
// promoting them to the public API. The Exploit subsystem uses this pattern
// for argv-building helpers (ValidateOptions, BuildRc, Quote) and static
// state resets (PasswordSprayTool.ResetThrottleForTests).
using System.Runtime.CompilerServices;

[assembly: InternalsVisibleTo("Drederick.Tests")]
