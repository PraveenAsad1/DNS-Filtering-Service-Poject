from main import shannon_entropy, calculate_threat_score


class TestShannonEntropy:
    def test_empty_string_has_zero_entropy(self):
        assert shannon_entropy("") == 0.0

    def test_repeated_character_has_low_entropy(self):
        # "aaaaaaaa" is fully predictable — entropy should be exactly 0
        assert shannon_entropy("aaaaaaaa") == 0.0

    def test_varied_string_has_higher_entropy_than_repeated(self):
        varied_entropy = shannon_entropy("xk29fjq8z")
        repeated_entropy = shannon_entropy("aaaaaaaaa")
        assert varied_entropy > repeated_entropy


class TestCalculateThreatScore:
    def test_known_clean_domain_scores_low(self):
        score = calculate_threat_score("google.com")
        assert score < 0.4

    def test_domain_with_suspicious_tld_scores_higher(self):
        clean_score = calculate_threat_score("example.com")
        suspicious_tld_score = calculate_threat_score("example.tk")
        assert suspicious_tld_score > clean_score

    def test_very_long_domain_increases_score(self):
        short_score = calculate_threat_score("abc.com")
        long_score = calculate_threat_score("a" * 45 + ".com")
        assert long_score > short_score

    def test_high_digit_ratio_increases_score(self):
        letters_score = calculate_threat_score("normalname.com")
        digits_score = calculate_threat_score("123456789012.com")
        assert digits_score > letters_score

    def test_excessive_hyphens_increase_score(self):
        # isolate the hyphen variable specifically: same repeated character,
        # only difference is hyphen count, so entropy stays low for both
        no_hyphen_score = calculate_threat_score("aaaaaaaa.com")
        many_hyphens_score = calculate_threat_score("a-a-a-a-a-a.com")
        assert many_hyphens_score > no_hyphen_score

    def test_score_never_exceeds_cap(self):
        # stack every suspicious signal at once — score must still be capped at 0.99
        worst_case = "aa11-bb22-cc33-dd44-ee55-verylongrandomstring1234567890.tk"
        score = calculate_threat_score(worst_case)
        assert score <= 0.99

    def test_worst_case_domain_crosses_block_threshold(self):
        # a domain stacking length + hyphens + digits + suspicious TLD should
        # score above the 0.7 threshold used by the Java proxy
        worst_case = "aa11-bb22-cc33-dd44-ee55-verylongrandomstring1234567890.tk"
        score = calculate_threat_score(worst_case)
        assert score > 0.7
