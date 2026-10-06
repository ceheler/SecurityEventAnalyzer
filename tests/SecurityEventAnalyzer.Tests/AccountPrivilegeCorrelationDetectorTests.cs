using SecurityEventAnalyzer.Cli.Detection;
using SecurityEventAnalyzer.Cli.Enums;
using SecurityEventAnalyzer.Cli.Models;

namespace SecurityEventAnalyzer.Tests
{
    public class AccountPrivilegeCorrelationDetectorTests
    {
        [Fact]
        public void Detect_ReturnsFinding_WhenAccountCreatedAndPrivilegeEscalationDetected()
        {
            List<SecurityEvent> testList = [
                new SecurityEvent { EventId = 4720, SourceIp = "10.10.10.1", TargetSid = "S-1-5-21-1234567890-1234567890-1234567890-1001", Username = "John", Timestamp = new DateTime(2026, 10, 06, 05, 00, 0), Computer = "Computer1" },
                new SecurityEvent { EventId = 4732, SourceIp = "10.10.10.1", TargetUser = "BadMan", MemberSid = "S-1-5-21-1234567890-1234567890-1234567890-1001", TargetSid = "S-1-5-32-544", Username = "John", Timestamp = new DateTime(2026, 10, 06, 05, 30, 0), Computer = "Computer1" }
            ];

            var detector = new AccountPrivilegeCorrelationDetector();
            var findings = detector.Detect(testList);
            Assert.Single(findings);
            Assert.Equal("AccountPrivilegeCorrelation", findings[0].RuleName);
            Assert.Equal("Computer1", findings[0].Computer);
            Assert.Equal(Severity.Critical, findings[0].Severity);
            Assert.Equal("10.10.10.1", findings[0].SourceIp);
        }

        [Fact]
        public void Detect_ReturnsNoFinding_WhenAccountCreatedAndPrivilegeEscalationDetectedOutsideCorrelationWindow()
        {
            List<SecurityEvent> testList = [
                new SecurityEvent { EventId = 4720, SourceIp = "10.10.10.1", TargetSid = "S-1-5-21-1234567890-1234567890-1234567890-1001", Username = "John", Timestamp = new DateTime(2026, 10, 05, 05, 00, 0), Computer = "Computer1" },
                new SecurityEvent { EventId = 4732, SourceIp = "10.10.10.1", TargetUser = "BadMan", MemberSid = "S-1-5-21-1234567890-1234567890-1234567890-1001", TargetSid = "S-1-5-32-544", Username = "John", Timestamp = new DateTime(2026, 10, 06, 05, 30, 0), Computer = "Computer1" }
            ];
            var detector = new AccountPrivilegeCorrelationDetector();
            var findings = detector.Detect(testList);
            Assert.Empty(findings);
        }

        [Fact]
        public void Detect_ReturnsNoFinding_WhenAccountCreatedAndPrivilegeEscalationDetectedOnDifferentComputer()
        {
            List<SecurityEvent> testList = [
                new SecurityEvent { EventId = 4720, SourceIp = "10.10.10.1", TargetSid = "S-1-5-21-1234567890-1234567890-1234567890-1001", Username = "John", Timestamp = new DateTime(2026, 10, 06, 05, 00, 0), Computer = "Computer1" },
                new SecurityEvent { EventId = 4732, SourceIp = "10.10.10.1", TargetUser = "BadMan", MemberSid = "S-1-5-21-1234567890-1234567890-1234567890-1001", TargetSid = "S-1-5-32-544", Username = "John", Timestamp = new DateTime(2026, 10, 06, 05, 30, 0), Computer = "Computer2" }
            ];
            var detector = new AccountPrivilegeCorrelationDetector();
            var findings = detector.Detect(testList);
            Assert.Empty(findings);
        }

        [Fact]
        public void Detect_ReturnsNoFinding_WhenAccountCreatedAndAddedToNonPrivilegedGroup()
        {
             List<SecurityEvent> testList = [
                new SecurityEvent { EventId = 4720, SourceIp = "10.10.10.1", TargetSid = "S-1-5-21-1234567890-1234567890-1234567890-1001", Username = "John", Timestamp = new DateTime(2026, 10, 06, 05, 00, 0), Computer = "Computer1" },
                new SecurityEvent { EventId = 4732, SourceIp = "10.10.10.1", TargetUser = "BadMan", MemberSid = "S-1-5-21-1234567890-1234567890-1234567890-1001", TargetSid = "S-1-5-28-123", Username = "John", Timestamp = new DateTime(2026, 10, 06, 05, 30, 0), Computer = "Computer1" }
            ];
            var detector = new AccountPrivilegeCorrelationDetector();
            var findings = detector.Detect(testList);
            Assert.Empty(findings);
        }

        [Fact]
        public void Detect_ReturnsNoFinding_WhenInputListIsEmpty()
        {
            List<SecurityEvent> testList = [];
            var detector = new AccountPrivilegeCorrelationDetector();
            var findings = detector.Detect(testList);
            Assert.Empty(findings);
        }

        [Fact]
        public void Detect_ReturnsNoFinding_WhenAccountSidDoesNotMatchGroupMemberSid()
        {
            List<SecurityEvent> testList = [
                new SecurityEvent { EventId = 4720, SourceIp = "10.10.10.1", TargetSid = "S-1-5-21-1234567890-1234567890-1234567890-1001", Username = "John", Timestamp = new DateTime(2026, 10, 06, 05, 00, 0), Computer = "Computer1" },
                new SecurityEvent { EventId = 4732, SourceIp = "10.10.10.1", MemberSid = "S-1-5-21-1234567890-1234567890-1234567890-1002", TargetSid = "S-1-5-32-544", Username = "John", Timestamp = new DateTime(2026, 10, 06, 05, 30, 0), Computer = "Computer1" }
            ];

            var detector = new AccountPrivilegeCorrelationDetector();
            var findings = detector.Detect(testList);
            Assert.Empty(findings);
        }
    }
}