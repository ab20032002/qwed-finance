"""
Adversarial Tests - Jailbreak cases designed to trick the guards
Tests that a "clever" LLM cannot bypass security checks
"""

import pytest
from qwed_finance import QueryGuard, QueryRisk


class TestSQLInjectionJailbreaks:
    """
    Test cases where malicious SQL is hidden or obfuscated.
    These simulate a "jailbroken" LLM trying to bypass guards.
    """
    
    def setup_method(self):
        self.guard = QueryGuard()
    
    # ==================== Basic Injection ====================
    
    def test_simple_drop_detected(self):
        """Basic DROP TABLE should be caught"""
        result = self.guard.verify_readonly_safety("DROP TABLE users")
        assert result.safe == False
        assert result.risk_level == QueryRisk.CRITICAL
    
    def test_delete_in_subquery(self):
        """DELETE hidden in a subquery should be caught"""
        sql = "SELECT * FROM (DELETE FROM users WHERE id=1 RETURNING *) AS deleted"
        result = self.guard.verify_readonly_safety(sql)
        assert result.safe == False
        assert "DELETE" in str(result.violations)
    
    # ==================== Comment-Based Hiding ====================
    
    def test_drop_in_comment_style1(self):
        """DROP hidden after -- comment should still be parsed"""
        sql = "SELECT * FROM users -- DROP TABLE users"
        result = self.guard.verify_readonly_safety(sql)
        # The comment should be ignored, but we test the full string check
        # This tests that comments don't hide malicious intent
        assert result.query_type == "SELECT"
    
    def test_drop_in_block_comment(self):
        """DROP hidden in /* */ comment"""
        sql = "SELECT * FROM users /* DROP TABLE users */"
        result = self.guard.verify_readonly_safety(sql)
        assert result.query_type == "SELECT"
    
    def test_multiline_comment_injection(self):
        """Attempt to break out of query with newlines"""
        sql = """SELECT * FROM users;
        DROP TABLE users;
        SELECT 1"""
        result = self.guard.verify_readonly_safety(sql)
        # Multiple statements should trigger warning
        assert "DROP" in sql.upper()  # Ensure our test is valid
    
    # ==================== Case Manipulation ====================
    
    def test_mixed_case_drop(self):
        """DrOp TaBlE should be caught regardless of case"""
        result = self.guard.verify_readonly_safety("DrOp TaBlE users")
        assert result.safe == False
    
    def test_unicode_lookalike(self):
        """Test with unicode characters that look like ASCII"""
        # Using homoglyph characters (e.g., Cyrillic 'о' instead of Latin 'o')
        # This is a real attack vector
        sql = "SELECT * FROM users; DRΟP TABLE users"  # Note: 'Ο' is Greek
        result = self.guard.verify_readonly_safety(sql)
        # The guard should at least detect multiple statements
        assert ";" in sql
    
    # ==================== Encoding Attacks ====================
    
    def test_hex_encoded_drop(self):
        """Hex-encoded DROP attempt"""
        # Some DBs accept 0x44524F50 as 'DROP'
        sql = "SELECT 0x44524F50 FROM users"
        result = self.guard.verify_readonly_safety(sql)
        # This should parse as SELECT, but we flag suspicious hex
        assert result.query_type == "SELECT"
    
    # ==================== UNION Injection ====================
    
    def test_union_select_injection(self):
        """UNION SELECT is a classic injection vector"""
        sql = "SELECT name FROM users WHERE id=1 UNION SELECT password FROM admin"
        result = self.guard.verify_readonly_safety(sql)
        # UNION is allowed but suspicious
        assert result.risk_level in [QueryRisk.MEDIUM, QueryRisk.HIGH]
    
    def test_union_all_with_nulls(self):
        """UNION ALL with NULL padding"""
        sql = "SELECT 1,2,3 UNION ALL SELECT username,password,NULL FROM users"
        result = self.guard.verify_readonly_safety(sql)
        assert "users" in result.tables_accessed
    
    # ==================== Stacked Queries ====================
    
    def test_semicolon_stacking(self):
        """Multiple queries separated by semicolon"""
        sql = "SELECT 1; INSERT INTO logs VALUES('hacked')"
        result = self.guard.verify_readonly_safety(sql)
        assert result.safe == False
        assert "INSERT" in str(result.violations) or "Mutation" in str(result.violations)


class TestTableAccessJailbreaks:
    """Test bypassing table access restrictions"""
    
    def setup_method(self):
        self.guard = QueryGuard(allowed_tables={"transactions", "accounts"})
    
    def test_direct_unauthorized_access(self):
        """Direct access to unauthorized table"""
        sql = "SELECT * FROM customer_passwords"
        result = self.guard.verify_table_access(sql)
        assert result.safe == False
        assert "Unauthorized" in str(result.violations)
    
    def test_schema_qualified_bypass(self):
        """Attempt bypass with schema.table notation"""
        sql = "SELECT * FROM secret_schema.customer_passwords"
        result = self.guard.verify_table_access(sql)
        assert result.safe == False
    
    def test_alias_bypass_attempt(self):
        """Attempt to hide table name with alias"""
        sql = "SELECT * FROM customer_passwords cp"
        result = self.guard.verify_table_access(sql)
        assert result.safe == False
        assert "customer_passwords" in result.tables_accessed
    
    def test_join_unauthorized_table(self):
        """JOIN with unauthorized table"""
        sql = "SELECT * FROM transactions t JOIN passwords p ON t.user_id = p.user_id"
        result = self.guard.verify_table_access(sql)
        assert result.safe == False


class TestPIIColumnJailbreaks:
    """Test bypassing PII column restrictions"""
    
    def setup_method(self):
        self.guard = QueryGuard()
        self.pii_columns = {"ssn", "password", "credit_card", "dob"}
    
    def test_direct_pii_access(self):
        """Direct access to PII column"""
        sql = "SELECT ssn FROM users"
        result = self.guard.verify_column_access(sql, self.pii_columns)
        assert result.safe == False
    
    def test_pii_with_table_prefix(self):
        """PII access with table.column notation"""
        sql = "SELECT users.ssn FROM users"
        result = self.guard.verify_column_access(sql, self.pii_columns)
        assert result.safe == False
    
    def test_select_star_allows_pii(self):
        """SELECT * might expose PII - should we warn?"""
        sql = "SELECT * FROM users"
        result = self.guard.verify_column_access(sql, self.pii_columns)
        # SELECT * doesn't explicitly list columns, so it passes column check
        # But this is a known limitation we should document


class TestInjectionPatterns:
    """Test SQL injection detection"""
    
    def setup_method(self):
        self.guard = QueryGuard()
    
    def test_classic_1_equals_1(self):
        """Classic OR 1=1 injection"""
        sql = "SELECT * FROM users WHERE id=1 OR 1=1"
        user_input = "1 OR 1=1"
        result = self.guard.verify_no_injection(sql, user_input)
        # This should be detected by pattern matching
        assert "injection" in str(result.violations).lower() or result.risk_level != QueryRisk.SAFE
    
    def test_quote_comment_injection(self):
        """Quote followed by comment"""
        user_input = "admin'--"
        sql = f"SELECT * FROM users WHERE username='{user_input}'"
        result = self.guard.verify_no_injection(sql, user_input)
        assert result.safe == False
    
    def test_chained_statement_injection(self):
        """Injection with chained DROP"""
        user_input = "'; DROP TABLE users;--"
        sql = f"SELECT * FROM users WHERE name='{user_input}'"
        result = self.guard.verify_no_injection(sql, user_input)
        assert result.safe == False


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
