package com.dns;

import org.springframework.stereotype.Service;

import java.util.Arrays;
import java.util.List;

@Service
public class TyposquatDetector {

    // High-value brands commonly targeted by phishing/typosquatting.
    // A small, curated list — not exhaustive, but demonstrates the technique.
    private static final List<String> PROTECTED_BRANDS = Arrays.asList(
            "google.com", "paypal.com", "microsoft.com", "apple.com",
            "amazon.com", "facebook.com", "netflix.com", "github.com",
            "bankofamerica.com", "chase.com"
    );

    // A domain within this edit distance of a protected brand (but not an exact match)
    // is flagged as a likely typosquat.
    private static final int SUSPICIOUS_DISTANCE_THRESHOLD = 2;

    // Returns the brand name it's suspiciously close to, or null if no match.
    public String checkTyposquat(String cleanDomain) {
        for (String brand : PROTECTED_BRANDS) {
            if (cleanDomain.equals(brand)) {
                continue; // exact match to the real brand is not typosquatting
            }
            int distance = levenshteinDistance(cleanDomain, brand);
            if (distance > 0 && distance <= SUSPICIOUS_DISTANCE_THRESHOLD) {
                return brand;
            }
        }
        return null;
    }

    // Classic dynamic-programming edit-distance calculation: minimum number of
    // single-character insertions, deletions, or substitutions to turn a into b.
    static int levenshteinDistance(String a, String b) {
        int[][] dp = new int[a.length() + 1][b.length() + 1];

        for (int i = 0; i <= a.length(); i++) dp[i][0] = i;
        for (int j = 0; j <= b.length(); j++) dp[0][j] = j;

        for (int i = 1; i <= a.length(); i++) {
            for (int j = 1; j <= b.length(); j++) {
                if (a.charAt(i - 1) == b.charAt(j - 1)) {
                    dp[i][j] = dp[i - 1][j - 1];
                } else {
                    dp[i][j] = 1 + Math.min(dp[i - 1][j - 1], Math.min(dp[i - 1][j], dp[i][j - 1]));
                }
            }
        }
        return dp[a.length()][b.length()];
    }
}
