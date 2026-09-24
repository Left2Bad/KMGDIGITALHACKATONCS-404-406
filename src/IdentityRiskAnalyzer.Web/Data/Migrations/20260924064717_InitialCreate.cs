using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace IdentityRiskAnalyzer.Web.Data.Migrations
{
    /// <inheritdoc />
    public partial class InitialCreate : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "ScanRuns",
                columns: table => new
                {
                    Id = table.Column<long>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    StartedAtUtc = table.Column<DateTimeOffset>(type: "TEXT", nullable: false),
                    FinishedAtUtc = table.Column<DateTimeOffset>(type: "TEXT", nullable: true),
                    Status = table.Column<int>(type: "INTEGER", nullable: false),
                    Server = table.Column<string>(type: "TEXT", nullable: false),
                    BaseDn = table.Column<string>(type: "TEXT", nullable: false),
                    ObjectsScanned = table.Column<int>(type: "INTEGER", nullable: false),
                    FindingsCount = table.Column<int>(type: "INTEGER", nullable: false),
                    ErrorsCount = table.Column<int>(type: "INTEGER", nullable: false),
                    AdSecurityScore = table.Column<int>(type: "INTEGER", nullable: true),
                    ErrorMessage = table.Column<string>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ScanRuns", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "AdObjectSnapshots",
                columns: table => new
                {
                    Id = table.Column<long>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    ScanRunId = table.Column<long>(type: "INTEGER", nullable: false),
                    ObjectGuid = table.Column<Guid>(type: "TEXT", nullable: false),
                    Sid = table.Column<string>(type: "TEXT", nullable: true),
                    ObjectType = table.Column<int>(type: "INTEGER", nullable: false),
                    SamAccountName = table.Column<string>(type: "TEXT", nullable: true),
                    DisplayName = table.Column<string>(type: "TEXT", nullable: true),
                    DistinguishedName = table.Column<string>(type: "TEXT", nullable: false),
                    UserPrincipalName = table.Column<string>(type: "TEXT", nullable: true),
                    Enabled = table.Column<bool>(type: "INTEGER", nullable: true),
                    Locked = table.Column<bool>(type: "INTEGER", nullable: true),
                    AccountExpired = table.Column<bool>(type: "INTEGER", nullable: true),
                    IsServiceAccount = table.Column<bool>(type: "INTEGER", nullable: false),
                    IsPrivileged = table.Column<bool>(type: "INTEGER", nullable: false),
                    LastKnownActivityUtc = table.Column<DateTimeOffset>(type: "TEXT", nullable: true),
                    PasswordLastSetUtc = table.Column<DateTimeOffset>(type: "TEXT", nullable: true),
                    PasswordNeverExpires = table.Column<bool>(type: "INTEGER", nullable: true),
                    RiskScore = table.Column<int>(type: "INTEGER", nullable: false),
                    RiskLevel = table.Column<int>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AdObjectSnapshots", x => x.Id);
                    table.ForeignKey(
                        name: "FK_AdObjectSnapshots_ScanRuns_ScanRunId",
                        column: x => x.ScanRunId,
                        principalTable: "ScanRuns",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "DelegationRecords",
                columns: table => new
                {
                    Id = table.Column<long>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    ScanRunId = table.Column<long>(type: "INTEGER", nullable: false),
                    ObjectGuid = table.Column<Guid>(type: "TEXT", nullable: false),
                    ObjectName = table.Column<string>(type: "TEXT", nullable: false),
                    DelegationType = table.Column<int>(type: "INTEGER", nullable: false),
                    TargetsJson = table.Column<string>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_DelegationRecords", x => x.Id);
                    table.ForeignKey(
                        name: "FK_DelegationRecords_ScanRuns_ScanRunId",
                        column: x => x.ScanRunId,
                        principalTable: "ScanRuns",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "GroupMemberships",
                columns: table => new
                {
                    Id = table.Column<long>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    ScanRunId = table.Column<long>(type: "INTEGER", nullable: false),
                    PrincipalObjectGuid = table.Column<Guid>(type: "TEXT", nullable: false),
                    GroupObjectGuid = table.Column<Guid>(type: "TEXT", nullable: false),
                    GroupName = table.Column<string>(type: "TEXT", nullable: false),
                    GroupDistinguishedName = table.Column<string>(type: "TEXT", nullable: false),
                    IsDirect = table.Column<bool>(type: "INTEGER", nullable: false),
                    Depth = table.Column<int>(type: "INTEGER", nullable: false),
                    PathJson = table.Column<string>(type: "TEXT", nullable: false),
                    IsPrivileged = table.Column<bool>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_GroupMemberships", x => x.Id);
                    table.ForeignKey(
                        name: "FK_GroupMemberships_ScanRuns_ScanRunId",
                        column: x => x.ScanRunId,
                        principalTable: "ScanRuns",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "RiskFindings",
                columns: table => new
                {
                    Id = table.Column<long>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    ScanRunId = table.Column<long>(type: "INTEGER", nullable: false),
                    ObjectGuid = table.Column<Guid>(type: "TEXT", nullable: false),
                    ObjectType = table.Column<int>(type: "INTEGER", nullable: false),
                    ObjectName = table.Column<string>(type: "TEXT", nullable: false),
                    RuleId = table.Column<string>(type: "TEXT", nullable: false),
                    Category = table.Column<string>(type: "TEXT", nullable: false),
                    Title = table.Column<string>(type: "TEXT", nullable: false),
                    Description = table.Column<string>(type: "TEXT", nullable: false),
                    Evidence = table.Column<string>(type: "TEXT", nullable: true),
                    Recommendation = table.Column<string>(type: "TEXT", nullable: false),
                    RiskPoints = table.Column<int>(type: "INTEGER", nullable: false),
                    Severity = table.Column<int>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_RiskFindings", x => x.Id);
                    table.ForeignKey(
                        name: "FK_RiskFindings_ScanRuns_ScanRunId",
                        column: x => x.ScanRunId,
                        principalTable: "ScanRuns",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_AdObjectSnapshots_ObjectGuid",
                table: "AdObjectSnapshots",
                column: "ObjectGuid");

            migrationBuilder.CreateIndex(
                name: "IX_AdObjectSnapshots_ScanRunId_ObjectGuid",
                table: "AdObjectSnapshots",
                columns: new[] { "ScanRunId", "ObjectGuid" });

            migrationBuilder.CreateIndex(
                name: "IX_DelegationRecords_ScanRunId",
                table: "DelegationRecords",
                column: "ScanRunId");

            migrationBuilder.CreateIndex(
                name: "IX_GroupMemberships_ScanRunId_PrincipalObjectGuid",
                table: "GroupMemberships",
                columns: new[] { "ScanRunId", "PrincipalObjectGuid" });

            migrationBuilder.CreateIndex(
                name: "IX_RiskFindings_ObjectGuid",
                table: "RiskFindings",
                column: "ObjectGuid");

            migrationBuilder.CreateIndex(
                name: "IX_RiskFindings_RuleId",
                table: "RiskFindings",
                column: "RuleId");

            migrationBuilder.CreateIndex(
                name: "IX_RiskFindings_ScanRunId",
                table: "RiskFindings",
                column: "ScanRunId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "AdObjectSnapshots");

            migrationBuilder.DropTable(
                name: "DelegationRecords");

            migrationBuilder.DropTable(
                name: "GroupMemberships");

            migrationBuilder.DropTable(
                name: "RiskFindings");

            migrationBuilder.DropTable(
                name: "ScanRuns");
        }
    }
}
