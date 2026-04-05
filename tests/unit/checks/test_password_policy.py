"""Unit tests for Password Policy checks."""

import pytest

from adsentinel.checks.registry import CheckRegistry

# Import to trigger @check registration
from adsentinel.checks.password_policy.domain_policy import *
from adsentinel.checks.password_policy.fine_grained import *

from adsentinel.engine.context import SharedContext
from adsentinel.models.domain import PasswordPolicy, FineGrainedPolicy


class TestPP001MinLength:
    def test_weak_length(self, context):
        context.password_policy.min_length = 7
        check = PP001_MinPasswordLength(context)
        findings = check.run()
        assert len(findings) == 1
        assert findings[0].severity.value in ("HIGH", "MEDIUM")

    def test_strong_length(self, context):
        context.password_policy.min_length = 14
        check = PP001_MinPasswordLength(context)
        findings = check.run()
        assert len(findings) == 0

    def test_very_weak_length_is_high(self, context):
        context.password_policy.min_length = 5
        check = PP001_MinPasswordLength(context)
        findings = check.run()
        assert findings[0].severity.value == "HIGH"


class TestPP002Complexity:
    def test_no_complexity(self, context):
        context.password_policy.complexity_enabled = False
        check = PP002_PasswordComplexity(context)
        findings = check.run()
        assert len(findings) == 1

    def test_with_complexity(self, context):
        context.password_policy.complexity_enabled = True
        check = PP002_PasswordComplexity(context)
        assert len(check.run()) == 0


class TestPP003Lockout:
    def test_no_lockout(self, context):
        context.password_policy.lockout_threshold = 0
        check = PP003_AccountLockoutThreshold(context)
        findings = check.run()
        assert len(findings) == 1
        assert findings[0].severity.value == "HIGH"

    def test_high_lockout(self, context):
        context.password_policy.lockout_threshold = 20
        check = PP003_AccountLockoutThreshold(context)
        findings = check.run()
        assert len(findings) == 1
        assert findings[0].severity.value == "MEDIUM"

    def test_good_lockout(self, context):
        context.password_policy.lockout_threshold = 5
        check = PP003_AccountLockoutThreshold(context)
        assert len(check.run()) == 0


class TestPP007ReversibleEncryption:
    def test_reversible_on(self, context):
        context.password_policy.reversible_encryption = True
        check = PP007_ReversibleEncryption(context)
        findings = check.run()
        assert len(findings) == 1
        assert findings[0].severity.value == "CRITICAL"

    def test_reversible_off(self, context):
        context.password_policy.reversible_encryption = False
        check = PP007_ReversibleEncryption(context)
        assert len(check.run()) == 0


class TestPP010PasswordNeverExpires:
    def test_never_expires_found(self, context):
        check = PP010_PasswordNeverExpires(context)
        findings = check.run()
        # Our test context has at least one user with password_never_expires
        assert len(findings) >= 1

    def test_no_never_expires(self, context):
        for user in context.users:
            user.password_never_expires = False
        check = PP010_PasswordNeverExpires(context)
        assert len(check.run()) == 0


class TestPP017PasswordNotRequired:
    def test_found(self, context):
        check = PP017_PasswordNotRequired(context)
        findings = check.run()
        assert len(findings) == 1
        assert findings[0].severity.value == "CRITICAL"


class TestPP019PasswordInDescription:
    def test_found(self, context):
        check = PP019_PasswordInDescription(context)
        findings = check.run()
        assert len(findings) == 1
        assert findings[0].severity.value == "CRITICAL"

    def test_clean(self, context):
        for user in context.users:
            user.description = "Normal description"
        check = PP019_PasswordInDescription(context)
        assert len(check.run()) == 0


class TestPP011NoFGPP:
    def test_no_fgpp(self, context):
        context.fine_grained_policies = []
        check = PP011_NoFGPP(context)
        findings = check.run()
        assert len(findings) == 1

    def test_has_fgpp(self, context):
        context.fine_grained_policies = [FineGrainedPolicy(name="Admin Policy", min_length=20)]
        check = PP011_NoFGPP(context)
        assert len(check.run()) == 0


class TestPP014FGPPReversible:
    def test_reversible_fgpp(self, context):
        context.fine_grained_policies = [
            FineGrainedPolicy(name="Bad Policy", reversible_encryption=True, dn="CN=Bad,DC=corp,DC=com")
        ]
        check = PP014_FGPPReversibleEncryption(context)
        findings = check.run()
        assert len(findings) == 1
        assert findings[0].severity.value == "CRITICAL"
