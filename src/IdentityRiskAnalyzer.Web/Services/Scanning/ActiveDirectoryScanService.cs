using System.Diagnostics;
using IdentityRiskAnalyzer.Web.Data;
using IdentityRiskAnalyzer.Web.Domain.Entities;
using IdentityRiskAnalyzer.Web.Domain.Enums;
using IdentityRiskAnalyzer.Web.Domain.Models;
using IdentityRiskAnalyzer.Web.Options;
using IdentityRiskAnalyzer.Web.Services.ActiveDirectory;
using IdentityRiskAnalyzer.Web.Services.Delegation;
using IdentityRiskAnalyzer.Web.Services.GroupAnalysis;
using IdentityRiskAnalyzer.Web.Services.RiskRules;
using IdentityRiskAnalyzer.Web.Services.Scoring;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace IdentityRiskAnalyzer.Web.Services.Scanning;

public sealed class ActiveDirectoryScanService(
    AppDbContext db,
    IActiveDirectoryClient ldap,
    GroupGraphService graph,
    PrivilegedGroupAnalyzer privileges,
    ServiceAccountClassifier serviceAccounts,
    DelegationAnalyzer delegation,
    DuplicateSpnAnalyzer duplicateSpns,
    RiskEngine riskEngine,
    RiskScoringService scoring,
    IOptions<ActiveDirectoryOptions> adOptions,
    IOptions<RiskSettings> riskOptions,
    TimeProvider clock,
    ScanConcurrencyGate gate,
    ILogger<ActiveDirectoryScanService> logger) : IActiveDirectoryScanService
{
    public async Task<ScanExecutionResult> RunScanAsync(CancellationToken cancellationToken)
    {
        using var lease = gate.TryEnter();
        if (lease is null)
        {
            return new ScanExecutionResult { Status = ScanStatus.Running, AlreadyRunning = true,
                ErrorMessage = "A scan is already running in this application instance." };
        }

        var timer = Stopwatch.StartNew();
        ScanRun? run = null;
        var stage = "initialization";
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            await db.Database.MigrateAsync(cancellationToken);
            run = new ScanRun
            {
                StartedAtUtc = clock.GetUtcNow(), Status = ScanStatus.Running,
                Server = adOptions.Value.Server, BaseDn = adOptions.Value.BaseDn
            };
            db.ScanRuns.Add(run);
            await db.SaveChangesAsync(cancellationToken);
            logger.LogInformation("Scan {ScanRunId} started against {Server}, Base DN {BaseDn}.", run.Id, run.Server, run.BaseDn);

            stage = "users";
            var stageTimer = Stopwatch.StartNew();
            cancellationToken.ThrowIfCancellationRequested();
            var users = ldap.GetUsers(cancellationToken);
            logger.LogInformation("Scan {ScanRunId}: {Count} users collected in {ElapsedMs} ms.", run.Id, users.Count, stageTimer.ElapsedMilliseconds);

            stage = "managed service accounts";
            stageTimer.Restart();
            cancellationToken.ThrowIfCancellationRequested();
            var managedAccounts = ldap.GetManagedServiceAccounts(cancellationToken);
            var principals = users.Concat(managedAccounts).DistinctBy(user => user.ObjectGuid).ToArray();
            logger.LogInformation("Scan {ScanRunId}: {Count} managed service accounts collected in {ElapsedMs} ms; {Principals} unique principals.",
                run.Id, managedAccounts.Count, stageTimer.ElapsedMilliseconds, principals.Length);

            stage = "groups";
            stageTimer.Restart();
            cancellationToken.ThrowIfCancellationRequested();
            var groups = ldap.GetGroups(cancellationToken);
            logger.LogInformation("Scan {ScanRunId}: {Count} groups collected in {ElapsedMs} ms.", run.Id, groups.Count, stageTimer.ElapsedMilliseconds);

            stage = "analysis";
            stageTimer.Restart();
            cancellationToken.ThrowIfCancellationRequested();
            var paths = graph.BuildMembershipsForAllUsers(principals, groups, cancellationToken);
            var pathsByUser = paths.GroupBy(path => path.PrincipalObjectGuid)
                .ToDictionary(group => group.Key, group => group.ToArray());
            var duplicateSpnsByObject = duplicateSpns.AnalyzeAll(principals);
            var errors = groups.Count(group => !group.MembersComplete);
            if (errors > 0)
            {
                logger.LogWarning("Scan {ScanRunId}: {Count} groups have incomplete direct member lists.", run.Id, errors);
            }

            // Build privilege classification indexes once in the normal path. A malformed
            // principal falls back to isolated analysis so other principals can complete.
            Dictionary<Guid, PrivilegeAnalysisResult> privilegesByUser;
            try
            {
                privilegesByUser = privileges.AnalyzeAllUsers(principals, paths, groups, cancellationToken)
                    .ToDictionary(item => item.UserObjectGuid);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (Exception exception)
            {
                logger.LogWarning(exception, "Scan {ScanRunId}: batch privilege analysis failed; isolating principals.", run.Id);
                privilegesByUser = [];
            }

            Dictionary<Guid, ServiceAccountClassification> servicesByUser;
            try
            {
                servicesByUser = serviceAccounts.ClassifyAll(principals, cancellationToken)
                    .ToDictionary(item => item.ObjectGuid);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (Exception exception)
            {
                logger.LogWarning(exception, "Scan {ScanRunId}: batch service account classification failed; isolating principals.", run.Id);
                servicesByUser = [];
            }

            var snapshots = new List<AdObjectSnapshot>();
            var memberships = new List<GroupMembership>();
            var delegations = new List<DelegationRecord>();
            var findings = new List<RiskFinding>();
            var objectScores = new List<ObjectRiskScoreResult>();
            var scanUtc = clock.GetUtcNow();

            foreach (var user in principals)
            {
                cancellationToken.ThrowIfCancellationRequested();
                try
                {
                    pathsByUser.TryGetValue(user.ObjectGuid, out var userPaths);
                    var currentPaths = (IReadOnlyCollection<GroupMembershipPathResult>)(userPaths ?? []);
                    var privilege = privilegesByUser.TryGetValue(user.ObjectGuid, out var knownPrivilege)
                        ? knownPrivilege : privileges.AnalyzeUser(user, currentPaths, groups, cancellationToken);
                    var serviceAccount = servicesByUser.TryGetValue(user.ObjectGuid, out var knownService)
                        ? knownService : serviceAccounts.Classify(user);
                    var delegationResults = delegation.Analyze(user);
                    duplicateSpnsByObject.TryGetValue(user.ObjectGuid, out var duplicateEvidence);
                    var context = new AdRiskEvaluationContext
                    {
                        User = user,
                        PrivilegeAnalysis = privilege,
                        ServiceAccountClassification = serviceAccount,
                        DelegationResults = delegationResults,
                        DuplicateSpns = duplicateEvidence ?? [],
                        CurrentUtc = scanUtc,
                        Settings = riskOptions.Value,
                        ObjectType = ScanSnapshotMapper.GetObjectType(user)
                    };
                    var evaluation = riskEngine.EvaluateWithDiagnostics(context);
                    var score = scoring.ScoreObject(user.ObjectGuid, context.ObjectName, evaluation.Findings);
                    var privilegedIds = privilege.PrivilegedMemberships.Select(item => item.GroupObjectGuid).ToHashSet();

                    // Complete one principal in temporary collections before adding it to the snapshot.
                    var snapshot = ScanSnapshotMapper.ToSnapshot(run.Id, user, serviceAccount, privilege, score, scanUtc);
                    var userMemberships = currentPaths.DistinctBy(path => path.TargetGroupObjectGuid)
                        .Select(path => ScanSnapshotMapper.ToMembership(run.Id, path, privilegedIds.Contains(path.TargetGroupObjectGuid))).ToArray();
                    var userDelegations = delegationResults.Select(item => ScanSnapshotMapper.ToDelegation(run.Id, item)).ToArray();
                    // ScoreObject.Findings is the exact deduplicated set used for this object's score.
                    var userFindings = score.Findings.Select(item => ScanSnapshotMapper.ToFinding(run.Id, item)).ToArray();

                    snapshots.Add(snapshot);
                    memberships.AddRange(userMemberships);
                    delegations.AddRange(userDelegations);
                    findings.AddRange(userFindings);
                    objectScores.Add(score);
                    errors += evaluation.ErrorsCount;
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                {
                    throw;
                }
                catch (Exception exception)
                {
                    errors++;
                    logger.LogError(exception, "Scan {ScanRunId}: analysis failed for object {ObjectGuid}; continuing.", run.Id, user.ObjectGuid);
                }
            }

            var securityScore = scoring.Summarize(objectScores);
            logger.LogInformation("Scan {ScanRunId}: analysis completed in {ElapsedMs} ms. Objects {Objects}, findings {Findings}, errors {Errors}, security score {Score}.",
                run.Id, stageTimer.ElapsedMilliseconds, snapshots.Count, findings.Count, errors, securityScore.SecurityScore);

            stage = "persistence";
            stageTimer.Restart();
            cancellationToken.ThrowIfCancellationRequested();
            await using (var transaction = await db.Database.BeginTransactionAsync(cancellationToken))
            {
                try
                {
                    db.AdObjectSnapshots.AddRange(snapshots);
                    db.GroupMemberships.AddRange(memberships);
                    db.DelegationRecords.AddRange(delegations);
                    db.RiskFindings.AddRange(findings);
                    run.ObjectsScanned = snapshots.Count;
                    run.FindingsCount = findings.Count;
                    run.ErrorsCount = errors;
                    run.AdSecurityScore = securityScore.SecurityScore;
                    run.Status = errors == 0 ? ScanStatus.Completed : ScanStatus.CompletedWithErrors;
                    run.FinishedAtUtc = clock.GetUtcNow();
                    await db.SaveChangesAsync(cancellationToken);
                    await transaction.CommitAsync(cancellationToken);
                }
                catch
                {
                    await transaction.RollbackAsync(CancellationToken.None);
                    throw;
                }
            }

            logger.LogInformation("Scan {ScanRunId} finished as {Status}; persistence took {ElapsedMs} ms, total {TotalMs} ms.",
                run.Id, run.Status, stageTimer.ElapsedMilliseconds, timer.ElapsedMilliseconds);
            return ToResult(run, timer.Elapsed);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            logger.LogInformation("Scan {ScanRunId} was cancelled during {Stage}.", run?.Id, stage);
            if (run is null) return new ScanExecutionResult { Status = ScanStatus.Cancelled, Duration = timer.Elapsed };
            return await FinishFailureAsync(run.Id, ScanStatus.Cancelled, null, timer.Elapsed);
        }
        catch (Exception exception)
        {
            logger.LogError(exception, "Scan {ScanRunId} failed during {Stage}.", run?.Id, stage);
            var safeMessage = stage switch
            {
                "initialization" or "persistence" => "The scan could not be saved to the database.",
                "users" or "managed service accounts" or "groups" => "Active Directory collection failed. Check the connection and directory settings.",
                _ => "The scan could not complete its analysis."
            };
            if (run is null) return new ScanExecutionResult { Status = ScanStatus.Failed, Duration = timer.Elapsed, ErrorMessage = safeMessage };
            return await FinishFailureAsync(run.Id, ScanStatus.Failed, safeMessage, timer.Elapsed);
        }
    }

    private async Task<ScanExecutionResult> FinishFailureAsync(long scanRunId, ScanStatus status, string? message, TimeSpan duration)
    {
        // A rolled-back snapshot must not remain tracked when saving the terminal run status.
        db.ChangeTracker.Clear();
        try
        {
            var run = await db.ScanRuns.SingleAsync(item => item.Id == scanRunId, CancellationToken.None);
            run.Status = status;
            run.FinishedAtUtc = clock.GetUtcNow();
            run.ErrorMessage = message;
            await db.SaveChangesAsync(CancellationToken.None);
            return ToResult(run, duration);
        }
        catch (Exception exception)
        {
            logger.LogError(exception, "Scan {ScanRunId}: could not persist terminal status {Status}.", scanRunId, status);
            return new ScanExecutionResult { ScanRunId = scanRunId, Status = status, ErrorMessage = message, Duration = duration };
        }
    }

    private static ScanExecutionResult ToResult(ScanRun run, TimeSpan duration) => new()
    {
        ScanRunId = run.Id, Status = run.Status, ObjectsScanned = run.ObjectsScanned,
        FindingsCount = run.FindingsCount, ErrorsCount = run.ErrorsCount,
        AdSecurityScore = run.AdSecurityScore, ErrorMessage = run.ErrorMessage, Duration = duration
    };
}
