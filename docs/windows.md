# tailkeeper on Windows

The Windows build (`windows_amd64`) runs the same tools as macOS and Linux, with these differences. They are tracked for Windows hardened mode (`docs/design.md` §4 and §24).

| Area | On macOS and Linux | On Windows |
|---|---|---|
| Audit-log lock | An exclusive `flock` on the log, retried every 1 to 50 ms for up to 2 seconds. It excludes other tailkeeper processes and the other calls of the same process. If it cannot be taken in time, the append fails with `audit_unavailable` ("the audit log stayed locked for 2s"). | No file lock. The appends of one process are serialised by a lock in memory, so one MCP server's parallel calls keep the chain, and that lock gives up after 2 seconds with the same error. Two tailkeeper processes appending at the same moment (for instance `tailkeeper doctor` while the MCP server runs) can still fork the chain: both read the last line and write the next one, so two lines carry one sequence number. `tailkeeper audit verify` then reports a break ("line N has seq M, want N (a line was removed or inserted)") although nothing was altered, `tailkeeper doctor` fails its audit-log check, and later appends go on after the bad line. To go on, stop every tailkeeper process and move `audit.jsonl` aside; the new log is not linked to the old one. |
| `tailkeeper audit rotate` | Verifies the log, keeps it beside the new one as an archive, and starts a new chain whose first entry records where the archive ends. | Refused with `validation_failed` (exit 2): "audit rotate is not available on Windows yet: the log has no file lock there". The log grows without bound; `tailkeeper doctor` warns at 64 MiB and gives the manual procedure: stop every tailkeeper process, then move the log aside; the next run starts a new one. |
| Strict mode (configuration and secret-file ownership) | The configuration file and the directory that holds it must belong to root or to you and be writable by neither group nor others. A `file` provider's credential file must also have no group or other access (mode 0600). A symlink is refused. The file is read through the one that passed the check: the open refuses a symlink and never waits on a FIFO, and the open file must be a regular file with the device, inode, mode, size, modification time and change time that the check saw. | Not enforced; `tailkeeper doctor` warns that ownership and permissions were not checked. The check refuses only a path that is not a regular file (a symlink or a directory); it reads no owner, ACL or mode, of the file or of its directory. The pin on the checked file is a no-op for device and inode: Go reads the identity of the earlier `lstat` by name at the moment the two are compared, so that comparison cannot refuse a swapped file. The kind, mode, size and modification time of the `lstat` are still compared with the open file; Go's `FileInfo` carries no change time on Windows, so none is compared. The open does not refuse a symlink. A system configuration in `%ProgramData%\tailkeeper`, whose location comes from the environment variable of that name, wins outright over yours (as `/etc/tailkeeper` does), and nothing checks who wrote it. |
| Stopping a timed-out `tailscale` call | The CLI runs in its own process group, and on a timeout or a cancellation the whole group gets SIGKILL, so nothing it started survives. | Only `tailscale.exe` itself is stopped. A process it started is not (that needs a Job Object). The call is still bounded: tailkeeper waits 2 seconds for the CLI's output pipes to close, and if a process the CLI started still holds them, the call fails with `local_command_failed` ("tailscale <subcommand> exited but left a process holding its output"). |
| The `exec` credential provider | tailkeeper replaces itself (`execve`) with your wrapper, a secret manager's run command, which starts tailkeeper again with the credential in its environment. Standard input and output survive, so the stdio MCP server works. | Not supported. A command that needs the credential fails with `config_invalid` (exit 6): "the exec provider is not supported on Windows yet", with the fix "start tailkeeper under the wrapper and use the env provider". Start tailkeeper under your secret manager's run command yourself (`docs/recipes/`), so the credential is already in its environment: the `exec` provider accepts variables that are already set, and the `env` provider needs nothing more. The `file` and `oidc` providers are available (the `file` provider's file is not checked for its owner or mode, as above). |

Also different on Windows:

- **Where tailkeeper keeps its files.** Your configuration is `%AppData%\tailkeeper\config.hujson`, a system configuration is `%ProgramData%\tailkeeper\config.hujson`, and the audit log and state are in `%LocalAppData%\tailkeeper` (`audit.jsonl`). `ProgramData`, `AppData` and `LocalAppData` must all be set, or tailkeeper fails with `config_invalid`.
- **The audit log's permissions.** On macOS and Linux tailkeeper creates the log's directory with mode 0700 and the file with 0600. On Windows `os.Chmod` only sets or clears the read-only attribute, so neither mode is applied: access to the log is whatever `%LocalAppData%\tailkeeper` inherits.
- **The local tools.** `tailkeeper local ...` and the `local_*` tools look for `C:\Program Files\Tailscale\tailscale.exe`; anywhere else, set `local.tailscaleBinary` to an absolute path. No test has run them against a real `tailscale.exe`: the tests use a shell script as the stand-in CLI, which Windows cannot run (see the list below).

## Tests that do not run on Windows

The suite runs on Windows in CI (the `test-os` job). These tests do not run there, each for the reason given. `scripts/windows-skips.sh` compares the first list with the tests that report SKIP in that job, by package and test name, and the job fails when they differ, so the list is kept true; a test that stops skipping, or a new one that skips, must change it. A test in the second list is not compiled on Windows, which `internal/workflows/windows_test.go` checks against the source.

### Skipped when the tests run on Windows

<!-- windows-skipped:begin -->
- `TestHarnessWithNothingToAnswer` (`cmd/tailkeeper`): the stand-in binary is a POSIX shell script.
- `TestHarnessCredentialWithoutScope` (`cmd/tailkeeper`): the stand-in binary is a POSIX shell script.
- `TestHarnessFailsWhenDiscoveryFindsNoID` (`cmd/tailkeeper`): the stand-in binary is a POSIX shell script.
- `TestACLTestFailureIsAnAnswer` (`cmd/tailkeeper`): the stand-in binary is a POSIX shell script.
- `TestAnErrorDocumentThatExitsZeroIsAProblem` (`cmd/tailkeeper`): the stand-in binary is a POSIX shell script.
- `TestACredentialShapeInAnErrorDocumentIsCaught` (`cmd/tailkeeper`): the stand-in binary is a POSIX shell script.
- `TestAnExitMustBeTheOneTheResultSays` (`cmd/tailkeeper`): the stand-in binary is a POSIX shell script.
- `TestAuditGrowsByOneLinePerCall` (`cmd/tailkeeper`): the stand-in binary is a POSIX shell script.
- `TestCheckScriptJudgesALiveRun` (`cmd/tailkeeper`): the check is a POSIX shell script.
- `TestLiveReads` (`cmd/tailkeeper`): reads the configured tailnet; skipped on every platform unless `make live` runs it.
- `TestLiveMCP` (`cmd/tailkeeper`): reads the configured tailnet; skipped on every platform unless `make live` runs it.
- `TestExecProviderReexecKeepsStdio` (`cmd/tailkeeper`): the `exec` provider re-executes with `execve`, which Windows lacks.
- `TestInterruptEndsAHungCall` (`cmd/tailkeeper`): `os.Interrupt` cannot be sent to another process on Windows.
- `TestInterruptEndsAHungLocalCall` (`cmd/tailkeeper`): `os.Interrupt` cannot be sent to another process on Windows.
- `TestReadmeChecksumStepFailsWhenItChecksNothing` (`cmd/tailkeeper`): the step it runs is a shell script.
- `TestOperationsMatchTheDocument` (`internal/api/openapi`): compares with a copy of Tailscale's live OpenAPI document; skipped on every platform unless `TAILKEEPER_OPENAPI_LIVE` names one.
- `TestLiveDocumentMatchesThePin` (`internal/api/openapi`): compares with a copy of Tailscale's live OpenAPI document; skipped on every platform unless `TAILKEEPER_OPENAPI_LIVE` names one.
- `TestUnsafeConfigurationRefusesEverything` (`internal/app`): Windows has no strict mode (`docs/design.md` §4).
- `TestOpenTightensExistingModes` (`internal/audit`): Windows reports no POSIX modes: `os.Chmod` only sets the read-only attribute there.
- `TestAuditRotate` (`internal/cli`): `audit rotate` needs the file lock, which Windows does not have yet.
- `TestAuditVerifyWarnsAboutAMissingArchive` (`internal/cli`): `audit rotate` needs the file lock, which Windows does not have yet.
- `TestAuditVerifyEscapesTheNamesItPrints` (`internal/cli`): Windows refuses a control character in a directory name, which the test creates.
- `TestAuditRotateEscapesThePathsItPrints` (`internal/cli`): `audit rotate` needs the file lock, which Windows does not have yet.
- `TestCheckOwnershipRefusesGroupWritable` (`internal/config`): Windows has no strict mode (`docs/design.md` §4).
- `TestStrictModeChecksTheDirectoryAndSecretModes` (`internal/config`): Windows has no strict mode (`docs/design.md` §4).
- `TestLoadReadsOnlyTheFileTheCheckApproved` (`internal/config`): Windows has no strict mode (`docs/design.md` §4).
- `TestReadSecretFileChecksAndReadsTheSameFile` (`internal/config`): Windows has no strict mode (`docs/design.md` §4).
- `TestASystemWithoutReadSecretFileStillReadsThroughTheCheckedFile` (`internal/creds`): Windows has no strict mode (`docs/design.md` §4).
- `TestUnknownDaemonVersionWarns` (`internal/doctor`): the stand-in `tailscale` CLI is a POSIX shell script.
- `TestEnvironmentIsBuiltNotInherited` (`internal/local`): the stand-in `tailscale` CLI is a POSIX shell script.
- `TestArgvAndSocket` (`internal/local`): the stand-in `tailscale` CLI is a POSIX shell script.
- `TestTimeoutKillsProcessGroup` (`internal/local`): the stand-in `tailscale` CLI is a POSIX shell script.
- `TestOutputCap` (`internal/local`): the stand-in `tailscale` CLI is a POSIX shell script.
- `TestClassifiesDaemonStates` (`internal/local`): the stand-in `tailscale` CLI is a POSIX shell script.
- `TestVersionSkewWarning` (`internal/local`): the stand-in `tailscale` CLI is a POSIX shell script.
- `TestRateLimit` (`internal/local`): the stand-in `tailscale` CLI is a POSIX shell script.
- `TestRunRefusesMisuse` (`internal/local`): the stand-in `tailscale` CLI is a POSIX shell script.
- `TestTimeoutNamesTheSubcommand` (`internal/local`): the stand-in `tailscale` CLI is a POSIX shell script.
- `TestCancellationIsReported` (`internal/local`): the stand-in `tailscale` CLI is a POSIX shell script.
- `TestBackgroundChildDoesNotHoldRun` (`internal/local`): the stand-in `tailscale` CLI is a POSIX shell script.
- `TestStderrInErrorsIsSanitized` (`internal/local`): the stand-in `tailscale` CLI is a POSIX shell script.
- `TestStderrInErrorsCannotCloseItsQuotes` (`internal/local`): the stand-in `tailscale` CLI is a POSIX shell script.
- `TestLocalStatusClassifiesPathsAndHidesEndpoints` (`internal/tools`): the stand-in `tailscale` CLI is a POSIX shell script.
- `TestLocalStatusNeedsLoginHidesAuthURL` (`internal/tools`): the stand-in `tailscale` CLI is a POSIX shell script.
- `TestLocalDaemonUnreachable` (`internal/tools`): the stand-in `tailscale` CLI is a POSIX shell script.
- `TestLocalNetcheckRequiresDaemonAndDropsPublicIPs` (`internal/tools`): the stand-in `tailscale` CLI is a POSIX shell script.
- `TestLocalPingOutcomes` (`internal/tools`): the stand-in `tailscale` CLI is a POSIX shell script.
- `TestLocalPingRefusesNonTailnetTargets` (`internal/tools`): the stand-in `tailscale` CLI is a POSIX shell script.
- `TestLocalDNSQueryAllowlist` (`internal/tools`): the stand-in `tailscale` CLI is a POSIX shell script.
- `TestLocalDNSQueryAllowlistBoundaries` (`internal/tools`): the stand-in `tailscale` CLI is a POSIX shell script.
- `TestLocalIPAndMetricsRefuseEmptyOutput` (`internal/tools`): the stand-in `tailscale` CLI is a POSIX shell script.
- `TestLocalSyspolicyRedactsStrings` (`internal/tools`): the stand-in `tailscale` CLI is a POSIX shell script.
- `TestLocalServeStatusIncludesForegroundAndServices` (`internal/tools`): the stand-in `tailscale` CLI is a POSIX shell script.
- `TestLocalLockStatusPinsSchema` (`internal/tools`): the stand-in `tailscale` CLI is a POSIX shell script.
- `TestLocalVersionSkew` (`internal/tools`): the stand-in `tailscale` CLI is a POSIX shell script.
- `TestLocalPrefsAllowlist` (`internal/tools`): the stand-in `tailscale` CLI is a POSIX shell script.
- `TestLocalWhoamiAndWhois` (`internal/tools`): the stand-in `tailscale` CLI is a POSIX shell script.
- `TestLocalIPFamilyFlag` (`internal/tools`): the stand-in `tailscale` CLI is a POSIX shell script.
- `TestLocalDNSStatus` (`internal/tools`): the stand-in `tailscale` CLI is a POSIX shell script.
- `TestNoCLIIsReportedPerCall` (`internal/tools`): the stand-in `tailscale` CLI is a POSIX shell script.
- `TestLocalNetcheckAndDNSQueryRequireRunning` (`internal/tools`): the stand-in `tailscale` CLI is a POSIX shell script.
- `TestLocalUnrecognizedOutputIsAnError` (`internal/tools`): the stand-in `tailscale` CLI is a POSIX shell script.
- `TestLocalSyspolicyRedactsErrors` (`internal/tools`): the stand-in `tailscale` CLI is a POSIX shell script.
- `TestLocalFlagShapedInputNeverReachesTheCLI` (`internal/tools`): the stand-in `tailscale` CLI is a POSIX shell script.
- `TestLocalPrefsShowRouteLists` (`internal/tools`): the stand-in `tailscale` CLI is a POSIX shell script.
- `TestLocalSyspolicyAcceptsNoPolicies` (`internal/tools`): the stand-in `tailscale` CLI is a POSIX shell script.
- `TestLocalSentinelsBehindTheStatusGate` (`internal/tools`): the stand-in `tailscale` CLI is a POSIX shell script.
- `TestLocalIdentitiesAndTailnetNameAreMasked` (`internal/tools`): the stand-in `tailscale` CLI is a POSIX shell script.
- `TestPublicAddressesAreCutUnlessTheOwnerOptsIn` (`internal/tools`): the stand-in `tailscale` CLI is a POSIX shell script.
- `TestPlainConfigurationKeepsItsAddresses` (`internal/tools`): the stand-in `tailscale` CLI is a POSIX shell script.
- `TestLongHealthMessagesAreMaskedBeforeTheyAreCut` (`internal/tools`): the stand-in `tailscale` CLI is a POSIX shell script.
- `TestLongErrorsAreMaskedBeforeTheyAreCut` (`internal/tools`): the stand-in `tailscale` CLI is a POSIX shell script.
- `TestTailnetNameIsMaskedOnlyWhenItIsALogin` (`internal/tools`): the stand-in `tailscale` CLI is a POSIX shell script.
- `TestWindowsSkipCheckJudgesALog` (`internal/workflows`): the check it runs is a POSIX shell script.
- `TestWindowsSkipCheckKnowsATestByPackageAndName` (`internal/workflows`): the check it runs is a POSIX shell script.
- `TestReleaseNotesCheckJudgesALog` (`internal/workflows`): the check it runs is a POSIX shell script.
- `TestChangelogTopSectionGivesReleaseNotes` (`internal/workflows`): the release job's command is a POSIX shell command that runs awk.
- `TestChangelogNotesCheckFindsAnEmptySection` (`internal/workflows`): the release job's command is a POSIX shell command that runs awk.
<!-- windows-skipped:end -->

### Not compiled on Windows

These files carry `//go:build !windows`. Their tests need the file lock (`syscall.Flock`), rotation, FIFOs or the change time of a file, none of which Windows has in this build.

<!-- windows-excluded:begin -->
- `TestRecordDoesNotRetryAnUnavailableLog` (`internal/app`): holds the audit log's file lock with `syscall.Flock`.
- `TestAppendGivesUpOnAStuckLock` (`internal/audit`): holds the file lock from the test with `syscall.Flock`.
- `TestRotateKeepsTheArchiveAndContinuesTheChain` (`internal/audit`): rotation and the archives it makes; `audit rotate` is refused on Windows.
- `TestVerifyChecksTheArchiveARotatedLogContinues` (`internal/audit`): rotation and the archives it makes; `audit rotate` is refused on Windows.
- `TestVerifyRefusesARotatedEntryNamingNoArchive` (`internal/audit`): rotation and the archives it makes; `audit rotate` is refused on Windows.
- `TestRotateRefusesAnEmptyOrDamagedLog` (`internal/audit`): rotation and the archives it makes; `audit rotate` is refused on Windows.
- `TestMissingLogIsUnavailable` (`internal/audit`): rotation and the archives it makes; `audit rotate` is refused on Windows.
- `TestRotateRefusesALogThatFailsVerification` (`internal/audit`): rotation and the archives it makes; `audit rotate` is refused on Windows.
- `TestVerifyHistoryFollowsEveryArchive` (`internal/audit`): rotation and the archives it makes; `audit rotate` is refused on Windows.
- `TestVerifyCatchesAReplacedLastArchiveLine` (`internal/audit`): rotation and the archives it makes; `audit rotate` is refused on Windows.
- `TestRotateFailureAfterTheLinkChangesNothing` (`internal/audit`): rotation and the archives it makes; `audit rotate` is refused on Windows.
- `TestRotateSweepsStaleTempsAndRefusesASymlink` (`internal/audit`): rotation and the archives it makes; `audit rotate` is refused on Windows.
- `TestConcurrentAppendsAndRotationsKeepEveryLineOnce` (`internal/audit`): rotation and the archives it makes; `audit rotate` is refused on Windows.
- `TestRotateVerifiesLinesAppendedWhileItWaited` (`internal/audit`): rotation and the archives it makes; `audit rotate` is refused on Windows.
- `TestRotateCountsCRLFLines` (`internal/audit`): rotation and the archives it makes; `audit rotate` is refused on Windows.
- `TestRotateWaitsForALineBeingWritten` (`internal/audit`): rotation and the archives it makes; `audit rotate` is refused on Windows.
- `TestOverlappingRotationsBothSucceed` (`internal/audit`): rotation and the archives it makes; `audit rotate` is refused on Windows.
- `TestRotateRefusesALogThatShrankMeanwhile` (`internal/audit`): rotation and the archives it makes; `audit rotate` is refused on Windows.
- `TestArchiveErrorsNameTheArchive` (`internal/audit`): rotation and the archives it makes; `audit rotate` is refused on Windows.
- `TestADanglingArchiveLinkIsMissing` (`internal/audit`): rotation and the archives it makes; `audit rotate` is refused on Windows.
- `TestVerifyReportsAMissingFinalNewline` (`internal/audit`): rotation and the archives it makes; `audit rotate` is refused on Windows.
- `TestAppendAfterARotationItWaitedThroughWritesTheNewLog` (`internal/audit`): rotation while an appender waits on the file lock, and a read-only directory (a mode Windows does not report).
- `TestRotateInAReadOnlyDirectoryChangesNothing` (`internal/audit`): rotation while an appender waits on the file lock, and a read-only directory (a mode Windows does not report).
- `TestAFifoSwappedInAfterTheCheckIsRefusedNotWaitedOn` (`internal/config`): needs FIFOs (`syscall.Mkfifo`), `O_NOFOLLOW` and the change time of a file.
- `TestReadCheckedDoesNotFollowASymlinkToTheCheckedFile` (`internal/config`): needs FIFOs (`syscall.Mkfifo`), `O_NOFOLLOW` and the change time of a file.
- `TestReadCheckedRefusesAFifoThatHasTheCheckedFilesDeviceAndInode` (`internal/config`): needs FIFOs (`syscall.Mkfifo`), `O_NOFOLLOW` and the change time of a file.
- `TestReadCheckedRefusesAFileRewrittenInPlaceAfterTheCheck` (`internal/config`): needs FIFOs (`syscall.Mkfifo`), `O_NOFOLLOW` and the change time of a file.
- `TestReadCheckedRefusesAFileWhoseChangeTimeMovedAfterTheCheck` (`internal/config`): needs FIFOs (`syscall.Mkfifo`), `O_NOFOLLOW` and the change time of a file.
- `TestReadCheckedRefusesASameSizeRewriteWithTheModTimeRestoredWithinTheSecond` (`internal/config`): needs FIFOs (`syscall.Mkfifo`), `O_NOFOLLOW` and the change time of a file.
- `TestReadCheckedReadsAnUnchangedFileWhoseAccessTimeMoves` (`internal/config`): needs FIFOs (`syscall.Mkfifo`), `O_NOFOLLOW` and the change time of a file.
- `TestSameChangeTimeFailsClosedWithoutAStat` (`internal/config`): needs FIFOs (`syscall.Mkfifo`), `O_NOFOLLOW` and the change time of a file.
- `TestUnrecordedReadsWarnInTheAuditLogCheck` (`internal/doctor`): holds the audit log's file lock with `syscall.Flock`.
- `TestAuditWarningRearmsAfterRecovery` (`internal/mcpserver`): holds the audit log's file lock with `syscall.Flock`.
<!-- windows-excluded:end -->
