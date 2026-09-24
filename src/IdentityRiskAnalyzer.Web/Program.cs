using IdentityRiskAnalyzer.Web.Data;
using IdentityRiskAnalyzer.Web.Options;
using IdentityRiskAnalyzer.Web.Services.ActiveDirectory;
using IdentityRiskAnalyzer.Web.Services.Delegation;
using IdentityRiskAnalyzer.Web.Services.Dashboard;
using IdentityRiskAnalyzer.Web.Services.GroupAnalysis;
using IdentityRiskAnalyzer.Web.Services.RiskRules;
using IdentityRiskAnalyzer.Web.Services.RiskRules.Account;
using IdentityRiskAnalyzer.Web.Services.RiskRules.ActiveDirectory;
using IdentityRiskAnalyzer.Web.Services.RiskRules.Delegation;
using IdentityRiskAnalyzer.Web.Services.RiskRules.Password;
using IdentityRiskAnalyzer.Web.Services.RiskRules.Privilege;
using IdentityRiskAnalyzer.Web.Services.RiskRules.ServiceAccount;
using IdentityRiskAnalyzer.Web.Services.RiskRules.Spn;
using IdentityRiskAnalyzer.Web.Services.Scoring;
using IdentityRiskAnalyzer.Web.Services.Scanning;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllersWithViews();
builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseSqlite(builder.Configuration.GetConnectionString("DefaultConnection")));
builder.Services.AddOptions<ActiveDirectoryOptions>()
    .BindConfiguration(ActiveDirectoryOptions.SectionName)
    .ValidateDataAnnotations()
    .ValidateOnStart();
builder.Services.AddOptions<GroupAnalysisOptions>()
    .BindConfiguration(GroupAnalysisOptions.SectionName)
    .ValidateDataAnnotations()
    .ValidateOnStart();
builder.Services.AddOptions<PrivilegeAnalysisOptions>()
    .BindConfiguration(PrivilegeAnalysisOptions.SectionName)
    .ValidateOnStart();
builder.Services.AddOptions<ServiceAccountAnalysisOptions>()
    .BindConfiguration(ServiceAccountAnalysisOptions.SectionName)
    .ValidateDataAnnotations()
    .ValidateOnStart();
builder.Services.AddOptions<RiskSettings>()
    .BindConfiguration(RiskSettings.SectionName)
    .Validate(settings => !settings.Validate(new System.ComponentModel.DataAnnotations.ValidationContext(settings)).Any(), "Risk settings are invalid or incomplete.")
    .ValidateOnStart();
builder.Services.AddScoped<AdUserRecordMapper>();
builder.Services.AddScoped<AdGroupRecordMapper>();
builder.Services.AddScoped<GroupGraphService>();
builder.Services.AddScoped<PrivilegedGroupAnalyzer>();
builder.Services.AddScoped<DelegationAnalyzer>();
builder.Services.AddScoped<ServiceAccountClassifier>();
builder.Services.AddScoped<DuplicateSpnAnalyzer>();
builder.Services.AddScoped<RiskEngine>();
builder.Services.AddScoped<RiskScoringService>();
builder.Services.AddScoped<DashboardQueryService>();
builder.Services.AddSingleton<ScanConcurrencyGate>();
builder.Services.AddScoped<IActiveDirectoryScanService, ActiveDirectoryScanService>();
builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddScoped<IAdRiskRule, StaleEnabledAccountRule>();
builder.Services.AddScoped<IAdRiskRule, ExpiredAccountRule>();
builder.Services.AddScoped<IAdRiskRule, LockedAccountRule>();
builder.Services.AddScoped<IAdRiskRule, PasswordNeverExpiresRule>();
builder.Services.AddScoped<IAdRiskRule, OldPasswordRule>();
builder.Services.AddScoped<IAdRiskRule, ServicePasswordNeverExpiresRule>();
builder.Services.AddScoped<IAdRiskRule, DirectPrivilegedMembershipRule>();
builder.Services.AddScoped<IAdRiskRule, NestedPrivilegedMembershipRule>();
builder.Services.AddScoped<IAdRiskRule, MultipleAdministrativeRolesRule>();
builder.Services.AddScoped<IAdRiskRule, InactivePrivilegedAccountRule>();
builder.Services.AddScoped<IAdRiskRule, UnconstrainedDelegationRule>();
builder.Services.AddScoped<IAdRiskRule, ConstrainedDelegationRule>();
builder.Services.AddScoped<IAdRiskRule, ProtocolTransitionRule>();
builder.Services.AddScoped<IAdRiskRule, ResourceBasedConstrainedDelegationRule>();
builder.Services.AddScoped<IAdRiskRule, SidHistoryRule>();
builder.Services.AddScoped<IAdRiskRule, DuplicateSpnRule>();
builder.Services.AddScoped<IActiveDirectoryClient, LdapActiveDirectoryClient>();

var app = builder.Build();

// Apply the existing EF migrations before the scans history page is queried.
using (var scope = app.Services.CreateScope())
{
    await scope.ServiceProvider.GetRequiredService<AppDbContext>().Database.MigrateAsync();
}

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseRouting();

app.UseAuthorization();

app.MapStaticAssets();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Dashboard}/{action=Index}/{id?}")
    .WithStaticAssets();


app.Run();
