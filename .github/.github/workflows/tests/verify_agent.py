from qwed_finance import ComplianceGuard, OpenResponsesIntegration

def test_aml_compliance():
    guard = ComplianceGuard()
    result = guard.verify_aml_flag(
        amount=15000,
        country_code="US",
        llm_flagged=True
    )
    assert result.compliant, f"AML check failed!"
    print("✅ Verification passed!")

if __name__ == "__main__":
    test_aml_compliance()
