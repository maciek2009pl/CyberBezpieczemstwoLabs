using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace CyberBezpieczemstwoLab.Migrations
{
    /// <inheritdoc />
    public partial class RenameCanaryLoginDate : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.RenameColumn(
                name: "LoggedInAtUtc",
                table: "CanaryLogins",
                newName: "CanaryAtDate");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.RenameColumn(
                name: "CanaryAtDate",
                table: "CanaryLogins",
                newName: "LoggedInAtUtc");
        }
    }
}
