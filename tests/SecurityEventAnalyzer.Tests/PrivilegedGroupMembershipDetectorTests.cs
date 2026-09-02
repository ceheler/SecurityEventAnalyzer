using SecurityEventAnalyzer.Cli.Enums;
using SecurityEventAnalyzer.Cli.Models;
using SecurityEventAnalyzer.Cli.Detection;

namespace SecurityEventAnalyzer.Tests
{
    public class PrivilegedGroupMembershipDetectorTests
    {
        [Fact]
        public void Detect_ReturnsHighFinding_WhenUserAddedToDomainAdmins()
        {
            List<SecurityEvent> testList = [
                new SecurityEvent { EventId = 4728, SourceIp = "10.10.10.1" , TargetUser = "hax0r", TargetGroup = "Domain Admins", Timestamp = new DateTime(2026, 8, 31, 05, 00, 0) }
                ];
            var detector = new PrivilegedGroupMembershipDetector();
            var findings = detector.Detect(testList);
            var finding = Assert.Single(findings);

            Assert.Equal("hax0r", finding.TargetUser);
            Assert.Equal("10.10.10.1", finding.SourceIp);
            Assert.Equal(Severity.High, finding.Severity);
            Assert.Equal("Privileged Group Membership Change Detected", finding.RuleName);
            Assert.Equal(new DateTime(2026, 8, 31, 05, 00, 0), finding.Timestamp);
        }

        [Fact]
        public void Detect_ReturnsFinding_PrivilegedAddedEnterpriseAdmin() 
        {
            List<SecurityEvent> testList = [
                new SecurityEvent { EventId = 4728, SourceIp = "10.10.10.1", TargetUser = "hax0r", TargetGroup = "Enterprise Admins", Timestamp = new DateTime(2026, 9, 1, 6, 0 ,0) }
                ];
            var detector = new PrivilegedGroupMembershipDetector();
            var findings = detector.Detect(testList);
            var finding = Assert.Single(findings);

            Assert.Equal("hax0r", finding.TargetUser);
            Assert.Equal("10.10.10.1", finding.SourceIp);
            Assert.Equal(Severity.High, finding.Severity);
            Assert.Equal("Privileged Group Membership Change Detected", finding.RuleName);
            Assert.Equal(new DateTime(2026, 9, 1, 6, 0, 0), finding.Timestamp);
        }

        [Fact]
        public void Detect_ReturnsFinding_PrivilegedAddedOtherAdmin() 
        {
            List<SecurityEvent> testList = [
                new SecurityEvent { EventId = 4728, SourceIp = "10.10.10.1", TargetUser = "hax0r", TargetGroup = "IT Admins", Timestamp = new DateTime(2026, 9, 1, 6, 0 ,0) }
                ];
            var detector = new PrivilegedGroupMembershipDetector();
            var findings = detector.Detect(testList);
            var finding = Assert.Single(findings);

            Assert.Equal("hax0r", finding.TargetUser);
            Assert.Equal("10.10.10.1", finding.SourceIp);
            Assert.Equal(Severity.Medium, finding.Severity);
            Assert.Equal("Privileged Group Membership Change Detected", finding.RuleName);
            Assert.Equal(new DateTime(2026, 9, 1, 6, 0, 0), finding.Timestamp);
        }

        [Fact]
        public void Detect_ReturnsFinding_PrivilegeAddedNonAdminUser() 
        {
            List<SecurityEvent> testList = [
                new SecurityEvent { EventId = 4728, SourceIp = "10.10.10.1", TargetUser = "hax0r", TargetGroup = "Sales Users", Timestamp = new DateTime(2026, 9, 1, 6, 0 ,0) }
                ];
            var detector = new PrivilegedGroupMembershipDetector();
            var findings = detector.Detect(testList);
            var finding = Assert.Single(findings);

            Assert.Equal("hax0r", finding.TargetUser);
            Assert.Equal("10.10.10.1", finding.SourceIp);
            Assert.Equal(Severity.Low, finding.Severity);
            Assert.Equal("Privileged Group Membership Change Detected", finding.RuleName);
            Assert.Equal(new DateTime(2026, 9, 1, 6, 0, 0), finding.Timestamp);
        }

        [Fact]
        public void Detect_ReturnsFinding_PrivilegeAddedNullTargetGroup()
        {
            List<SecurityEvent> testList = [
                new SecurityEvent { EventId = 4728, SourceIp = "10.10.10.1", TargetUser = "hax0r", TargetGroup = null, Timestamp = new DateTime(2026, 9, 1, 6, 0 ,0) }
                ];
            var detector = new PrivilegedGroupMembershipDetector();
            var findings = detector.Detect(testList);
            var finding = Assert.Single(findings);

            Assert.Equal("hax0r", finding.TargetUser);
            Assert.Equal("10.10.10.1", finding.SourceIp);
            Assert.Equal(Severity.Low, finding.Severity);
            Assert.Equal("Privileged Group Membership Change Detected", finding.RuleName);
            Assert.Equal(new DateTime(2026, 9, 1, 6, 0, 0), finding.Timestamp);
        }

        [Fact]
        public void Detect_ReturnsFinding_PrivilegeAddedMultipleEventsDetected()
        {
            List<SecurityEvent> testList = [
                new SecurityEvent { EventId = 4728, SourceIp = "10.10.10.1", TargetUser = "hax0r", TargetGroup = "Domain Admins", Timestamp = new DateTime(2026, 9, 1, 6, 0 ,0) },
                new SecurityEvent { EventId = 4728, SourceIp = "10.10.10.1", TargetUser = "hax0r", TargetGroup = "Enterprise Admins", Timestamp = new DateTime(2026, 9, 1, 6, 0 ,0) }
                ];
            var detector = new PrivilegedGroupMembershipDetector();
            var findings = detector.Detect(testList);
            Assert.Equal(2, findings.Count);
        }

        [Fact]
        public void Detect_ReturnsNoFinding_PrivilegeNotAdded()
        {
            List<SecurityEvent> testList = [
                new SecurityEvent { EventId = 4724, SourceIp = "10.10.10.1", TargetUser = "hax0r", TargetGroup = "Sales Users", Timestamp = new DateTime(2026, 9, 1, 6, 0 ,0) }
                ];
            var detector = new PrivilegedGroupMembershipDetector();
            var findings = detector.Detect(testList);
            Assert.Empty(findings);
        }

        [Fact]
        public void Detect_ReturnsNoFinding_PrivilegeEmptyInput()
        {
            List<SecurityEvent> testList = [];
            var detector = new PrivilegedGroupMembershipDetector();
            var findings = detector.Detect(testList);
            Assert.Empty(findings);
        }
    }
}
