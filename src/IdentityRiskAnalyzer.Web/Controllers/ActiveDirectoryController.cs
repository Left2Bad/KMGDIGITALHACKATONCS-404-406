using IdentityRiskAnalyzer.Web.Domain.Models;
using IdentityRiskAnalyzer.Web.Domain.Enums;
using IdentityRiskAnalyzer.Web.Options;
using IdentityRiskAnalyzer.Web.Services.ActiveDirectory;
using IdentityRiskAnalyzer.Web.Services.Delegation;
using IdentityRiskAnalyzer.Web.Services.GroupAnalysis;
using IdentityRiskAnalyzer.Web.Services.RiskRules;
using IdentityRiskAnalyzer.Web.Services.Scoring;
using IdentityRiskAnalyzer.Web.ViewModels;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

namespace IdentityRiskAnalyzer.Web.Controllers;

[Route("ActiveDirectory")]
public sealed class ActiveDirectoryController(
    IActiveDirectoryClient activeDirectoryClient,
    GroupGraphService groupGraphService,
    PrivilegedGroupAnalyzer privilegedGroupAnalyzer,
    DelegationAnalyzer delegationAnalyzer,
    ServiceAccountClassifier serviceAccountClassifier,
    DuplicateSpnAnalyzer duplicateSpnAnalyzer,
    RiskEngine riskEngine,
    RiskScoringService riskScoringService,
    IOptions<ActiveDirectoryOptions> options,
    IOptions<RiskSettings> riskSettings,
    TimeProvider timeProvider) : Controller
{
    [HttpGet("")]
    public IActionResult Index()
    {
        return View(ActiveDirectoryConnectionViewModel.From(options.Value));
    }

    [HttpPost("TestConnection")]
    [ValidateAntiForgeryToken]
    public IActionResult TestConnection(CancellationToken cancellationToken)
    {
        var result = activeDirectoryClient.TestConnection(cancellationToken);
        var viewModel = ActiveDirectoryConnectionViewModel.From(options.Value, result);
        return View("Index", viewModel);
    }

    [HttpGet("Users")]
    public IActionResult Users(CancellationToken cancellationToken)
    {
        try
        {
            const int displayLimit = 100;
            var users = GetAccountPrincipals(cancellationToken);
            var groups = activeDirectoryClient.GetGroups(cancellationToken);
            var membershipPaths = groupGraphService.BuildMembershipsForAllUsers(users, groups, cancellationToken);
            var privilegeResults = privilegedGroupAnalyzer.AnalyzeAllUsers(users, membershipPaths, groups, cancellationToken)
                .ToDictionary(result => result.UserObjectGuid);
            var serviceAccountResults = serviceAccountClassifier.ClassifyAll(users, cancellationToken)
                .ToDictionary(result => result.ObjectGuid);
            var items = users
                .Take(displayLimit)
                .Select(user =>
                {
                    privilegeResults.TryGetValue(user.ObjectGuid, out var privilegeResult);
                    var serviceAccountResult = serviceAccountResults[user.ObjectGuid];
                    return new AdUserListItemViewModel
                    {
                        ObjectGuid = user.ObjectGuid,
                        SamAccountName = user.SamAccountName,
                        DisplayName = user.DisplayName,
                        UserPrincipalName = user.UserPrincipalName,
                        LastKnownActivityUtc = user.LastKnownActivityUtc,
                        PasswordLastSetUtc = user.PasswordLastSetUtc,
                        SpnCount = user.ServicePrincipalNames.Count,
                        DistinguishedName = user.DistinguishedName,
                        IsPrivileged = privilegeResult?.IsPrivileged ?? false,
                        PrivilegedGroupCount = privilegeResult?.PrivilegedGroupCount ?? 0,
                        ServiceAccountClassification = ServiceAccountClassificationViewModel.From(serviceAccountResult)
                    };
                })
                .ToArray();

            return View(new AdUserListViewModel
            {
                Users = items,
                TotalCount = users.Count,
                DisplayLimit = displayLimit
            });
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            return View(new AdUserListViewModel
            {
                ErrorMessage = "Could not retrieve users from Active Directory. Check the connection settings and try again."
            });
        }
    }

    [HttpGet("Groups")]
    public IActionResult Groups(CancellationToken cancellationToken)
    {
        try
        {
            const int displayLimit = 100;
            var groups = activeDirectoryClient.GetGroups(cancellationToken);
            var items = groups
                .Take(displayLimit)
                .Select(AdGroupListItemViewModel.From)
                .ToArray();

            return View(new AdGroupListViewModel
            {
                Groups = items,
                TotalCount = groups.Count,
                DisplayLimit = displayLimit,
                IncompleteMemberLists = groups.Count(group => !group.MembersComplete)
            });
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            return View(new AdGroupListViewModel
            {
                ErrorMessage = "Could not retrieve groups from Active Directory. Check the connection settings and try again."
            });
        }
    }

    [HttpGet("Users/{objectGuid:guid}/Groups")]
    public IActionResult UserGroups(Guid objectGuid, CancellationToken cancellationToken)
    {
        try
        {
            var users = GetAccountPrincipals(cancellationToken);
            var user = users.FirstOrDefault(candidate => candidate.ObjectGuid == objectGuid);
            if (user is null)
            {
                return NotFound();
            }

            var groups = activeDirectoryClient.GetGroups(cancellationToken);
            var memberships = groupGraphService.GetMembershipsForUser(user, users, groups, cancellationToken);
            var privilegeResult = privilegedGroupAnalyzer.AnalyzeUser(user, memberships, groups, cancellationToken);
            var delegationResults = delegationAnalyzer.Analyze(user);
            var serviceAccountResult = serviceAccountClassifier.Classify(user);
            var duplicateSpns = duplicateSpnAnalyzer.AnalyzeAll(users)
                .TryGetValue(user.ObjectGuid, out var duplicateSpnEvidence)
                    ? duplicateSpnEvidence
                    : Array.Empty<DuplicateSpnEvidence>();
            var accountObjectType = user.ObjectClasses.Any(objectClass =>
                string.Equals(objectClass, "msDS-ManagedServiceAccount", StringComparison.OrdinalIgnoreCase)
                || string.Equals(objectClass, "msDS-GroupManagedServiceAccount", StringComparison.OrdinalIgnoreCase))
                ? AdObjectType.ServiceAccount
                : AdObjectType.User;
            var riskFindings = riskEngine.Evaluate(new AdRiskEvaluationContext
            {
                User = user,
                PrivilegeAnalysis = privilegeResult,
                ServiceAccountClassification = serviceAccountResult,
                DelegationResults = delegationResults,
                DuplicateSpns = duplicateSpns,
                CurrentUtc = timeProvider.GetUtcNow(),
                Settings = riskSettings.Value,
                ObjectType = accountObjectType
            });
            var userName = user.SamAccountName ?? user.UserPrincipalName ?? user.DisplayName ?? user.DistinguishedName;
            var objectRiskScore = riskScoringService.ScoreObject(user.ObjectGuid, userName, riskFindings);
            var viewModel = new UserGroupMembershipViewModel
            {
                UserName = userName,
                DistinguishedName = user.DistinguishedName,
                IsPrivileged = privilegeResult.IsPrivileged,
                Memberships = memberships.Select(GroupMembershipPathItemViewModel.From).ToArray(),
                PrivilegedMemberships = privilegeResult.PrivilegedMemberships
                    .Select(PrivilegedMembershipItemViewModel.From)
                    .ToArray(),
                Delegations = delegationResults.Select(DelegationViewModel.From).ToArray(),
                ServiceAccountClassification = ServiceAccountClassificationViewModel.From(serviceAccountResult),
                RiskFindings = riskFindings.Select(RiskFindingViewModel.From).ToArray(),
                RiskScore = ObjectRiskScoreViewModel.From(objectRiskScore)
            };

            return View("UserGroups", viewModel);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            return View("UserGroups", new UserGroupMembershipViewModel
            {
                ErrorMessage = "Could not analyze group membership from Active Directory. Check the connection settings and try again."
            });
        }
    }

    private IReadOnlyList<AdUserRecord> GetAccountPrincipals(CancellationToken cancellationToken)
    {
        var userAccounts = activeDirectoryClient.GetUsers(cancellationToken);
        var managedServiceAccounts = activeDirectoryClient.GetManagedServiceAccounts(cancellationToken);
        return userAccounts
            .Concat(managedServiceAccounts)
            .DistinctBy(account => account.ObjectGuid)
            .ToArray();
    }
}
