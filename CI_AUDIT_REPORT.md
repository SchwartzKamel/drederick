# CI Workflow Audit Report - `.github/workflows/ci.yml`

## Executive Summary
The CI workflow is well-structured with generally good practices, but has several areas for improvement regarding security hardening, performance optimization, and version currency.

---

## ✅ STRENGTHS

### Best Practices
- **Concurrency & Cancellation**: Properly configured (`cancel-in-progress: true`) to avoid wasting resources on outdated runs
- **Permissions**: Correctly scoped to least-privilege (contents:read, checks:write, pull-requests:write)
- **Caching Strategy**: NuGet cache configured with appropriate hash keys including both .csproj and Directory.Build.props files
- **Error Handling**: Intelligently uses `continue-on-error` for non-Ubuntu runners while failing on primary platform
- **Matrix Coverage**: Tests on three major platforms (ubuntu-latest, windows-latest, macos-latest)
- **Test Reporting**: Uses TRX format for structured test results and publishes them

### Security
- **Action Pinning**: All GitHub Actions pinned to specific versions (v4)
- **dorny/test-reporter**: Pinned to specific SHA (not just version tag)
- **Artifact Uploads**: Test results properly uploaded with matrix-specific names

---

## ⚠️ ISSUES & RECOMMENDATIONS

### CRITICAL / HIGH PRIORITY

#### 1. **Outdated Action Version: dorny/test-reporter**
- **Current**: v2.1.0 (SHA: 890a17cecf52a379fc869ab770a71657660be727)
- **Latest**: v3.0.0 (released 2026-03-21)
- **Gap**: ~13 months behind latest
- **Risk**: Missing bug fixes, performance improvements, and potentially security patches
- **Recommendation**: Update to latest v3.0.0 or the SHA of latest v3 release
  ```yaml
  uses: dorny/test-reporter@v3
  # OR pin to latest v3 SHA
  ```

#### 2. **Action Version Inconsistency: Using Major Versions Without SHA**
- **Current Pattern**: `actions/checkout@v4`, `actions/setup-dotnet@v4`, etc.
- **Issue**: Using major version (v4) without SHA means workflow can change if GitHub updates the v4 tag
- **Best Practice**: Pin to exact commit SHA for maximum reproducibility and security
- **Recommendation**: Pin all GitHub Actions to specific SHAs:
  ```yaml
  uses: actions/checkout@<v4-specific-sha>
  uses: actions/setup-dotnet@<v4-specific-sha>
  uses: actions/cache@<v4-specific-sha>
  uses: actions/upload-artifact@<v4-specific-sha>
  ```

### MEDIUM PRIORITY

#### 3. **Missing Dependency Verification / SLSA Provenance**
- **Issue**: No verification that downloaded actions haven't been compromised
- **Recommendation**: Consider using GitHub Actions with SLSA provenance (available for official GitHub Actions)
- **Status**: v4 versions likely have provenance available

#### 4. **Cache Key Strategy Could Be More Specific**
- **Current**: Uses glob patterns for `.csproj` and `Directory.Build.props`
- **Enhancement**: Consider adding `global.json` hash to cache key if present (affects SDK behavior)
- **Impact**: Minor - current approach is reasonable

#### 5. **No Explicit .NET Version Lock**
- **Current**: `dotnet-version: '10.0.x'` (allows any 10.0.x patch)
- **Recommendation**: Consider using exact version `'10.0.0'` or `'10.0.5'` etc. for reproducibility
- **Trade-off**: Current approach good for receiving critical patches; stricter is better for reproducibility

### LOW PRIORITY

#### 6. **Build Parallelization Opportunity**
- **Current**: All steps run sequentially
- **Opportunity**: Could run format check in parallel with build (non-blocking check)
- **Recommendation**: Consider if format check should fail the job or just report
- **Status**: Current sequential approach is fine for clarity

#### 7. **Windows-Specific Issues Not Addressed**
- **Current**: Sets `continue-on-error: true` for non-Ubuntu runners
- **Question**: Is this intentional? Are there known Windows/macOS issues?
- **Recommendation**: Document why non-Ubuntu runs are allowed to fail
- **Impact**: Could mask platform-specific bugs

#### 8. **Missing Secrets in Workflow**
- **Status**: ✅ Good - no secrets are hardcoded or exposed

---

## SUMMARY TABLE

| Category | Item | Status | Priority |
|----------|------|--------|----------|
| **Security** | Action SHA pinning (GitHub Actions) | ⚠️ Major versions only | HIGH |
| **Security** | dorny/test-reporter version | ⚠️ v2.1.0 vs v3.0.0 | CRITICAL |
| **Security** | SLSA Provenance verification | ⚠️ Not configured | MEDIUM |
| **Best Practice** | Permissions scope | ✅ Correct | - |
| **Best Practice** | Concurrency config | ✅ Good | - |
| **Best Practice** | Cache strategy | ✅ Good | - |
| **Performance** | Build parallelization | ℹ️ Sequential OK | LOW |
| **Coverage** | OS matrix | ✅ Adequate | - |
| **Coverage** | fail-fast behavior | ✅ Correct | - |

---

## VERIFICATION RESULTS

- ✅ dorny/test-reporter SHA `890a17cecf52a379fc869ab770a71657660be727` is valid (v2.1.0, dated 2025-05-17)
- ✅ All GitHub Actions use v4 (current major versions)
- ⚠️ Latest dorny/test-reporter is v3.0.0 (1+ major version ahead)

---

## ACTION ITEMS

1. **[CRITICAL]** Update `dorny/test-reporter` to v3.0.0
2. **[HIGH]** Pin all GitHub Actions to specific commit SHAs
3. **[MEDIUM]** Document why `continue-on-error: true` for Windows/macOS
4. **[MEDIUM]** Consider SLSA provenance verification
5. **[LOW]** Review .NET version pinning strategy
