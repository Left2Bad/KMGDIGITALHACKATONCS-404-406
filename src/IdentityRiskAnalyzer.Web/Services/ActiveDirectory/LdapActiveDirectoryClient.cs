using System.ComponentModel.DataAnnotations;
using System.Diagnostics;
using System.DirectoryServices.Protocols;
using System.Net;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using IdentityRiskAnalyzer.Web.Domain.Enums;
using IdentityRiskAnalyzer.Web.Domain.Models;
using IdentityRiskAnalyzer.Web.Options;
using Microsoft.Extensions.Options;

namespace IdentityRiskAnalyzer.Web.Services.ActiveDirectory;

public sealed class LdapActiveDirectoryClient(
    IOptions<ActiveDirectoryOptions> options,
    ILogger<LdapActiveDirectoryClient> logger,
    AdUserRecordMapper userRecordMapper,
    AdGroupRecordMapper groupRecordMapper) : IActiveDirectoryClient
{
    private const string UserSearchFilter = "(&(objectCategory=person)(objectClass=user))";
    private const string ManagedServiceAccountSearchFilter = "(|(objectClass=msDS-ManagedServiceAccount)(objectClass=msDS-GroupManagedServiceAccount))";
    private const string GroupSearchFilter = "(objectCategory=group)";

    private static readonly string[] UserAttributes =
    [
        "objectGUID",
        "objectSid",
        "distinguishedName",
        "sAMAccountName",
        "userPrincipalName",
        "displayName",
        "userAccountControl",
        "msDS-User-Account-Control-Computed",
        "lastLogonTimestamp",
        "pwdLastSet",
        "accountExpires",
        "lockoutTime",
        "memberOf",
        "primaryGroupID",
        "servicePrincipalName",
        "managedBy",
        "description",
        "sIDHistory",
        "msDS-AllowedToDelegateTo",
        "msDS-AllowedToActOnBehalfOfOtherIdentity",
        "objectClass"
    ];

    private static readonly string[] GroupAttributes =
    [
        "objectGUID",
        "objectSid",
        "distinguishedName",
        "cn",
        "sAMAccountName",
        "groupType",
        "member",
        "description",
        "managedBy"
    ];

    private readonly ActiveDirectoryOptions _options = options.Value;

    public LdapConnectionTestResult TestConnection(CancellationToken cancellationToken)
    {
        var stopwatch = Stopwatch.StartNew();
        logger.LogInformation(
            "LDAP connection test started for {Server}:{Port}; LDAPS={UseSsl}.",
            _options.Server,
            _options.Port,
            _options.UseSsl);

        LdapConnectionTestResult result;
        var validationErrors = ValidateOptions();
        if (validationErrors.Count > 0)
        {
            result = CreateResult(
                success: false,
                "Active Directory configuration is invalid: " + string.Join(" ", validationErrors),
                LdapConnectionErrorType.Configuration);
        }
        else
        {
            try
            {
                cancellationToken.ThrowIfCancellationRequested();

                using var connection = CreateConnection(_options);
                connection.Bind();

                cancellationToken.ThrowIfCancellationRequested();

                var request = new SearchRequest(
                    _options.BaseDn,
                    "(objectClass=*)",
                    SearchScope.Base,
                    "objectClass");
                var response = (SearchResponse)connection.SendRequest(request);

                if (response.Entries.Count == 0)
                {
                    result = CreateResult(
                        success: false,
                        "Configured Base DN could not be queried.",
                        LdapConnectionErrorType.BaseDn);
                }
                else
                {
                    result = CreateResult(
                        success: true,
                        _options.UseSsl
                            ? "LDAPS bind and Base DN query succeeded."
                            : "LDAP bind and Base DN query succeeded.",
                        LdapConnectionErrorType.None);
                }
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception exception)
            {
                var errorType = ClassifyError(exception);
                result = CreateResult(false, GetSafeMessage(errorType), errorType);
                logger.LogWarning(
                    "LDAP connection test failed for {Server}:{Port}; LDAPS={UseSsl}; ErrorType={ErrorType}; ExceptionType={ExceptionType}; Message={Message}.",
                    _options.Server,
                    _options.Port,
                    _options.UseSsl,
                    errorType,
                    exception.GetType().Name,
                    result.Message);
            }
        }

        stopwatch.Stop();
        result = new LdapConnectionTestResult
        {
            Success = result.Success,
            Server = result.Server,
            Port = result.Port,
            UseSsl = result.UseSsl,
            Message = result.Message,
            DurationMs = stopwatch.ElapsedMilliseconds,
            ErrorType = result.ErrorType
        };

        if (result.Success)
        {
            logger.LogInformation(
                "LDAP connection test succeeded for {Server}:{Port}; LDAPS={UseSsl}; DurationMs={DurationMs}.",
                result.Server,
                result.Port,
                result.UseSsl,
                result.DurationMs);
        }
        else
        {
            logger.LogWarning(
                "LDAP connection test failed for {Server}:{Port}; LDAPS={UseSsl}; DurationMs={DurationMs}; ErrorType={ErrorType}.",
                result.Server,
                result.Port,
                result.UseSsl,
                result.DurationMs,
                result.ErrorType);
        }

        return result;
    }

    public IReadOnlyList<AdUserRecord> GetUsers(CancellationToken cancellationToken)
    {
        var validationErrors = ValidateOptions();
        if (validationErrors.Count > 0)
        {
            throw new InvalidOperationException(
                "Active Directory configuration is invalid: " + string.Join(" ", validationErrors));
        }

        var stopwatch = Stopwatch.StartNew();
        logger.LogInformation(
            "Starting AD user collection from {Server}:{Port}; LDAPS={UseSsl}; PageSize={PageSize}.",
            _options.Server,
            _options.Port,
            _options.UseSsl,
            _options.PageSize);

        var users = new List<AdUserRecord>();
        var skippedEntries = 0;
        var pageNumber = 0;

        try
        {
            cancellationToken.ThrowIfCancellationRequested();

            using var connection = CreateConnection(_options);
            connection.Bind();
            pageNumber = ExecutePagedSearch(
                connection,
                UserSearchFilter,
                UserAttributes,
                cancellationToken,
                (response, currentPage) =>
                {
                    pageNumber = currentPage;
                    foreach (SearchResultEntry entry in response.Entries)
                    {
                        cancellationToken.ThrowIfCancellationRequested();

                        try
                        {
                            var user = userRecordMapper.Map(entry);
                            if (user is null)
                            {
                                skippedEntries++;
                                continue;
                            }

                            users.Add(user);
                        }
                        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                        {
                            throw;
                        }
                        catch (Exception exception)
                        {
                            skippedEntries++;
                            logger.LogWarning(
                                "Skipping malformed LDAP user entry {DistinguishedName}; ErrorType={ErrorType}.",
                                entry.DistinguishedName,
                                exception.GetType().Name);
                        }
                    }

                    logger.LogInformation(
                        "Received {EntryCount} LDAP entries on page {PageNumber}; collected {UserCount} users so far.",
                        response.Entries.Count,
                        currentPage,
                        users.Count);
                });
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            stopwatch.Stop();
            logger.LogInformation(
                "AD user collection was cancelled after {DurationMs} ms; collected {UserCount} users.",
                stopwatch.ElapsedMilliseconds,
                users.Count);
            throw;
        }
        catch (Exception exception)
        {
            stopwatch.Stop();
            logger.LogError(
                exception,
                "AD user collection failed for {Server}:{Port}; LDAPS={UseSsl}; after page {PageNumber}.",
                _options.Server,
                _options.Port,
                _options.UseSsl,
                pageNumber);
            throw;
        }

        stopwatch.Stop();
        logger.LogInformation(
            "AD user collection completed in {DurationMs} ms; collected {UserCount} users and skipped {SkippedEntryCount} malformed entries across {PageCount} pages.",
            stopwatch.ElapsedMilliseconds,
            users.Count,
            skippedEntries,
            pageNumber);

        return users.AsReadOnly();
    }

    public IReadOnlyList<AdGroupRecord> GetGroups(CancellationToken cancellationToken)
    {
        var validationErrors = ValidateOptions();
        if (validationErrors.Count > 0)
        {
            throw new InvalidOperationException(
                "Active Directory configuration is invalid: " + string.Join(" ", validationErrors));
        }

        var stopwatch = Stopwatch.StartNew();
        logger.LogInformation(
            "Starting AD group collection from {Server}:{Port}; LDAPS={UseSsl}; PageSize={PageSize}.",
            _options.Server,
            _options.Port,
            _options.UseSsl,
            _options.PageSize);

        var groups = new List<AdGroupRecord>();
        var skippedGroups = 0;
        var groupsWithRangedMembers = 0;
        var additionalMemberRanges = 0;
        var incompleteMemberCollections = 0;
        var pageNumber = 0;

        try
        {
            cancellationToken.ThrowIfCancellationRequested();

            using var connection = CreateConnection(_options);
            connection.Bind();
            pageNumber = ExecutePagedSearch(
                connection,
                GroupSearchFilter,
                GroupAttributes,
                cancellationToken,
                (response, currentPage) =>
                {
                    pageNumber = currentPage;
                    foreach (SearchResultEntry entry in response.Entries)
                    {
                        cancellationToken.ThrowIfCancellationRequested();

                        try
                        {
                            var memberResult = GetAllGroupMembers(connection, entry, cancellationToken);
                            var memberBatch = new GroupMemberAttributeBatch(
                                memberResult.Members,
                                HasMemberAttribute: true,
                                HasRangedAttribute: memberResult.UsedRangedRetrieval,
                                IsComplete: memberResult.IsComplete,
                                IsMalformed: false,
                                FirstRangeStart: null,
                                NextRangeStart: null);
                            var group = groupRecordMapper.Map(entry, memberBatch);
                            if (group is null)
                            {
                                skippedGroups++;
                                continue;
                            }

                            if (memberResult.UsedRangedRetrieval)
                            {
                                groupsWithRangedMembers++;
                            }

                            additionalMemberRanges += memberResult.AdditionalRangesRequested;
                            if (!memberResult.IsComplete)
                            {
                                incompleteMemberCollections++;
                            }

                            groups.Add(group);
                        }
                        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                        {
                            throw;
                        }
                        catch (Exception exception)
                        {
                            skippedGroups++;
                            logger.LogWarning(
                                exception,
                                "Skipping malformed LDAP group entry {DistinguishedName}; ErrorType={ErrorType}.",
                                entry.DistinguishedName,
                                exception.GetType().Name);
                        }
                    }

                    logger.LogInformation(
                        "Received {EntryCount} LDAP groups on page {PageNumber}; collected {GroupCount} groups so far.",
                        response.Entries.Count,
                        currentPage,
                        groups.Count);
                });
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            stopwatch.Stop();
            logger.LogInformation(
                "AD group collection was cancelled after {DurationMs} ms; collected {GroupCount} groups.",
                stopwatch.ElapsedMilliseconds,
                groups.Count);
            throw;
        }
        catch (Exception exception)
        {
            stopwatch.Stop();
            logger.LogError(
                exception,
                "AD group collection failed for {Server}:{Port}; LDAPS={UseSsl}; after page {PageNumber}.",
                _options.Server,
                _options.Port,
                _options.UseSsl,
                pageNumber);
            throw;
        }

        stopwatch.Stop();
        logger.LogInformation(
            "AD group collection completed in {DurationMs} ms; collected {GroupCount} groups and skipped {SkippedGroupCount} malformed groups across {PageCount} pages.",
            stopwatch.ElapsedMilliseconds,
            groups.Count,
            skippedGroups,
            pageNumber);
        logger.LogInformation(
            "Group members used ranged retrieval for {RangedGroupCount} groups; requested {AdditionalRangeCount} additional ranges; {IncompleteGroupCount} groups have incomplete member lists.",
            groupsWithRangedMembers,
            additionalMemberRanges,
            incompleteMemberCollections);

        return groups.AsReadOnly();
    }

    public IReadOnlyList<AdUserRecord> GetManagedServiceAccounts(CancellationToken cancellationToken)
    {
        var validationErrors = ValidateOptions();
        if (validationErrors.Count > 0)
        {
            throw new InvalidOperationException(
                "Active Directory configuration is invalid: " + string.Join(" ", validationErrors));
        }

        var stopwatch = Stopwatch.StartNew();
        logger.LogInformation(
            "Starting managed service account collection from {Server}:{Port}; LDAPS={UseSsl}; PageSize={PageSize}.",
            _options.Server,
            _options.Port,
            _options.UseSsl,
            _options.PageSize);

        var accounts = new List<AdUserRecord>();
        var skippedEntries = 0;
        var pageNumber = 0;
        try
        {
            cancellationToken.ThrowIfCancellationRequested();

            using var connection = CreateConnection(_options);
            connection.Bind();
            pageNumber = ExecutePagedSearch(
                connection,
                ManagedServiceAccountSearchFilter,
                UserAttributes,
                cancellationToken,
                (response, currentPage) =>
                {
                    pageNumber = currentPage;
                    foreach (SearchResultEntry entry in response.Entries)
                    {
                        cancellationToken.ThrowIfCancellationRequested();

                        try
                        {
                            var account = userRecordMapper.Map(entry);
                            if (account is null)
                            {
                                skippedEntries++;
                                continue;
                            }

                            accounts.Add(account);
                        }
                        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                        {
                            throw;
                        }
                        catch (Exception exception)
                        {
                            skippedEntries++;
                            logger.LogWarning(
                                exception,
                                "Skipping malformed managed service account entry {DistinguishedName}; ErrorType={ErrorType}.",
                                entry.DistinguishedName,
                                exception.GetType().Name);
                        }
                    }

                    logger.LogInformation(
                        "Received {EntryCount} managed service account entries on page {PageNumber}; collected {AccountCount} so far.",
                        response.Entries.Count,
                        currentPage,
                        accounts.Count);
                });
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            stopwatch.Stop();
            logger.LogInformation(
                "Managed service account collection was cancelled after {DurationMs} ms; collected {AccountCount} accounts.",
                stopwatch.ElapsedMilliseconds,
                accounts.Count);
            throw;
        }
        catch (Exception exception)
        {
            stopwatch.Stop();
            logger.LogError(
                exception,
                "Managed service account collection failed for {Server}:{Port}; LDAPS={UseSsl}; after page {PageNumber}.",
                _options.Server,
                _options.Port,
                _options.UseSsl,
                pageNumber);
            throw;
        }

        stopwatch.Stop();
        logger.LogInformation(
            "Managed service account collection completed in {DurationMs} ms; collected {AccountCount} accounts and skipped {SkippedEntryCount} malformed entries across {PageCount} pages.",
            stopwatch.ElapsedMilliseconds,
            accounts.Count,
            skippedEntries,
            pageNumber);

        return accounts.AsReadOnly();
    }

    private int ExecutePagedSearch(
        LdapConnection connection,
        string filter,
        string[] attributes,
        CancellationToken cancellationToken,
        Action<SearchResponse, int> processPage)
    {
        byte[] cookie = [];
        var pageNumber = 0;
        do
        {
            cancellationToken.ThrowIfCancellationRequested();

            var request = new SearchRequest(
                _options.BaseDn,
                filter,
                SearchScope.Subtree,
                attributes);
            request.Controls.Add(new PageResultRequestControl(_options.PageSize)
            {
                Cookie = cookie,
                IsCritical = true
            });

            var response = (SearchResponse)connection.SendRequest(request);
            pageNumber++;
            processPage(response, pageNumber);

            var responsePageControl = response.Controls.OfType<PageResultResponseControl>().SingleOrDefault();
            if (responsePageControl is null)
            {
                throw new InvalidOperationException("LDAP server did not return the required paging response control.");
            }

            cookie = responsePageControl.Cookie ?? [];
        }
        while (cookie.Length > 0);

        return pageNumber;
    }

    private GroupMemberReadResult GetAllGroupMembers(
        LdapConnection connection,
        SearchResultEntry groupEntry,
        CancellationToken cancellationToken)
    {
        var members = new MemberDnAccumulator();
        var initialBatch = GroupMemberAttributeReader.Read(groupEntry);
        members.AddRange(initialBatch.Members);

        if (!initialBatch.HasRangedAttribute)
        {
            return new GroupMemberReadResult(
                members.ToReadOnlyList(),
                initialBatch.IsComplete,
                AdditionalRangesRequested: 0,
                UsedRangedRetrieval: false);
        }

        var usedRangedRetrieval = true;
        var additionalRangesRequested = 0;
        var allRangesStartAtZero = initialBatch.FirstRangeStart == 0;
        var complete = initialBatch.IsComplete && allRangesStartAtZero;
        var nextStart = initialBatch.NextRangeStart;
        var progressGuard = new LdapRangeProgressGuard();

        if (initialBatch.IsMalformed)
        {
            logger.LogWarning(
                "Initial ranged member attribute could not be parsed; returning an incomplete member list. DN={DistinguishedName}.",
                groupEntry.DistinguishedName);
        }

        if (!allRangesStartAtZero)
        {
            logger.LogWarning(
                "Initial member range did not start at zero; collected member list may be incomplete. DN={DistinguishedName}; RangeStart={RangeStart}.",
                groupEntry.DistinguishedName,
                initialBatch.FirstRangeStart);
        }

        while (!complete && !initialBatch.IsMalformed)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (nextStart is not long requestedStart || !progressGuard.TryRegisterRequest(requestedStart))
            {
                logger.LogWarning(
                    "Member ranged retrieval stopped because the next range was missing or repeated. DN={DistinguishedName}.",
                    groupEntry.DistinguishedName);
                break;
            }

            try
            {
                var request = new SearchRequest(
                    groupEntry.DistinguishedName,
                    "(objectClass=*)",
                    SearchScope.Base,
                    $"member;range={requestedStart.ToString(System.Globalization.CultureInfo.InvariantCulture)}-*");
                additionalRangesRequested++;
                var response = (SearchResponse)connection.SendRequest(request);

                if (response.ResultCode != ResultCode.Success || response.Entries.Count != 1)
                {
                    logger.LogWarning(
                        "LDAP returned no usable group entry for an additional member range. DN={DistinguishedName}; ResultCode={ResultCode}.",
                        groupEntry.DistinguishedName,
                        response.ResultCode);
                    break;
                }

                var batch = GroupMemberAttributeReader.Read(response.Entries[0]);
                members.AddRange(batch.Members);
                if (!batch.HasMemberAttribute)
                {
                    logger.LogWarning(
                        "LDAP omitted the requested member range; collected member list is incomplete. DN={DistinguishedName}; RequestedStart={RangeStart}.",
                        groupEntry.DistinguishedName,
                        requestedStart);
                    break;
                }

                if (batch.HasRangedAttribute && batch.FirstRangeStart != requestedStart)
                {
                    logger.LogWarning(
                        "LDAP returned a different member range than requested; collected member list is incomplete. DN={DistinguishedName}; RequestedStart={RequestedStart}; ReturnedStart={ReturnedStart}.",
                        groupEntry.DistinguishedName,
                        requestedStart,
                        batch.FirstRangeStart);
                    break;
                }

                if (batch.IsMalformed)
                {
                    logger.LogWarning(
                        "LDAP returned a malformed member range; collected member list is incomplete. DN={DistinguishedName}.",
                        groupEntry.DistinguishedName);
                    break;
                }

                if (batch.IsComplete)
                {
                    complete = allRangesStartAtZero;
                    break;
                }

                if (!LdapRangeProgressGuard.Advances(requestedStart, batch.NextRangeStart))
                {
                    logger.LogWarning(
                        "Member ranged retrieval stopped because the server did not advance the range. DN={DistinguishedName}; RequestedStart={RangeStart}; NextStart={NextStart}.",
                        groupEntry.DistinguishedName,
                        requestedStart,
                        batch.NextRangeStart);
                    break;
                }

                nextStart = batch.NextRangeStart;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception exception)
            {
                logger.LogWarning(
                    exception,
                    "Could not retrieve an additional member range; returning the members collected so far. DN={DistinguishedName}; RangeStart={RangeStart}.",
                    groupEntry.DistinguishedName,
                    requestedStart);
                break;
            }
        }

        return new GroupMemberReadResult(
            members.ToReadOnlyList(),
            complete,
            additionalRangesRequested,
            usedRangedRetrieval);
    }

    private sealed record GroupMemberReadResult(
        IReadOnlyList<string> Members,
        bool IsComplete,
        int AdditionalRangesRequested,
        bool UsedRangedRetrieval);

    internal static LdapConnection CreateConnection(ActiveDirectoryOptions options)
    {
        var identifier = new LdapDirectoryIdentifier(options.Server, options.Port);
        var connection = new LdapConnection(identifier)
        {
            AuthType = AuthType.Negotiate,
            Timeout = TimeSpan.FromSeconds(options.ConnectTimeoutSeconds),
            Credential = options.CredentialsConfigured
                ? CreateCredential(options.Username!, options.Password!)
                : CredentialCache.DefaultNetworkCredentials
        };

        connection.SessionOptions.ProtocolVersion = 3;
        connection.SessionOptions.SecureSocketLayer = options.UseSsl;
        return connection;
    }

    internal static NetworkCredential CreateCredential(string username, string password)
    {
        var separator = username.IndexOf('\\');
        return separator > 0 && separator < username.Length - 1
            ? new NetworkCredential(username[(separator + 1)..], password, username[..separator])
            : new NetworkCredential(username, password);
    }

    private List<string> ValidateOptions()
    {
        var results = new List<ValidationResult>();
        Validator.TryValidateObject(
            _options,
            new ValidationContext(_options),
            results,
            validateAllProperties: true);

        return results
            .SelectMany(result => result.MemberNames.Select(member =>
                $"{member}: {result.ErrorMessage}"))
            .Distinct(StringComparer.Ordinal)
            .ToList();
    }

    private LdapConnectionErrorType ClassifyError(Exception exception)
    {
        if (exception is DirectoryOperationException operationException)
        {
            return operationException.Response?.ResultCode switch
            {
                ResultCode.NoSuchObject or ResultCode.InvalidDNSyntax => LdapConnectionErrorType.BaseDn,
                ResultCode.InappropriateAuthentication => LdapConnectionErrorType.Authentication,
                ResultCode.Unavailable => LdapConnectionErrorType.Network,
                ResultCode.TimeLimitExceeded => LdapConnectionErrorType.Timeout,
                _ => LdapConnectionErrorType.Protocol
            };
        }

        if (exception is LdapException ldapException)
        {
            return ldapException.ErrorCode switch
            {
                49 => LdapConnectionErrorType.Authentication,
                85 => LdapConnectionErrorType.Timeout,
                _ when _options.UseSsl && HasTlsFailure(ldapException) => LdapConnectionErrorType.Tls,
                81 or 91 => LdapConnectionErrorType.Network,
                _ => LdapConnectionErrorType.Protocol
            };
        }

        if (exception is SocketException socketException)
        {
            return socketException.SocketErrorCode == SocketError.TimedOut
                ? LdapConnectionErrorType.Timeout
                : LdapConnectionErrorType.Network;
        }

        if (_options.UseSsl && (exception is AuthenticationException or CryptographicException))
        {
            return LdapConnectionErrorType.Tls;
        }

        if (exception is TimeoutException)
        {
            return LdapConnectionErrorType.Timeout;
        }

        if (exception is ArgumentException or InvalidOperationException)
        {
            return LdapConnectionErrorType.Configuration;
        }

        return LdapConnectionErrorType.Unknown;
    }

    private static bool HasTlsFailure(Exception exception)
    {
        for (var current = exception.InnerException; current is not null; current = current.InnerException)
        {
            if (current is AuthenticationException or CryptographicException)
            {
                return true;
            }
        }

        return false;
    }

    private string GetSafeMessage(LdapConnectionErrorType errorType) => errorType switch
    {
        LdapConnectionErrorType.Configuration => "Active Directory configuration is invalid.",
        LdapConnectionErrorType.Network => _options.UseSsl
            ? "LDAPS server is unavailable or a TLS connection could not be established."
            : "LDAP server is unavailable.",
        LdapConnectionErrorType.Timeout => "LDAP connection timed out.",
        LdapConnectionErrorType.Authentication => "LDAP authentication failed.",
        LdapConnectionErrorType.BaseDn => "Configured Base DN could not be queried.",
        LdapConnectionErrorType.Tls => "LDAPS/TLS connection failed. Check the server certificate and client trust.",
        LdapConnectionErrorType.Protocol => "LDAP protocol error occurred.",
        _ => "LDAP connection test failed."
    };

    private LdapConnectionTestResult CreateResult(
        bool success,
        string message,
        LdapConnectionErrorType errorType) => new()
        {
            Success = success,
            Server = _options.Server,
            Port = _options.Port,
            UseSsl = _options.UseSsl,
            Message = message,
            ErrorType = errorType
        };
}
