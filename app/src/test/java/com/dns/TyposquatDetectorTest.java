package com.dns;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class TyposquatDetectorTest {

    private final TyposquatDetector detector = new TyposquatDetector();

    // --- levenshteinDistance ---

    @Test
    void levenshteinDistance_identicalStrings_isZero() {
        assertEquals(0, TyposquatDetector.levenshteinDistance("google.com", "google.com"));
    }

    @Test
    void levenshteinDistance_oneCharSubstitution_isOne() {
        assertEquals(1, TyposquatDetector.levenshteinDistance("paypal.com", "paypa1.com"));
    }

    @Test
    void levenshteinDistance_oneCharInsertion_isOne() {
        assertEquals(1, TyposquatDetector.levenshteinDistance("apple.com", "aapple.com"));
    }

    @Test
    void levenshteinDistance_completelyDifferentStrings_isLarge() {
        int distance = TyposquatDetector.levenshteinDistance("google.com", "unrelated-site.net");
        assertTrue(distance > 5);
    }

    // --- checkTyposquat ---

    @Test
    void checkTyposquat_exactBrandMatch_returnsNull() {
        // the real domain itself should never be flagged as its own typosquat
        assertNull(detector.checkTyposquat("google.com"));
    }

    @Test
    void checkTyposquat_nearMissOfProtectedBrand_returnsMatchedBrand() {
        String result = detector.checkTyposquat("paypa1.com"); // "1" instead of "l"
        assertEquals("paypal.com", result);
    }

    @Test
    void checkTyposquat_unrelatedDomain_returnsNull() {
        assertNull(detector.checkTyposquat("my-personal-blog.com"));
    }

    @Test
    void checkTyposquat_tooFarFromAnyBrand_returnsNull() {
        // "amaz0nblahblahblah.com" is not within the suspicious edit-distance threshold
        assertNull(detector.checkTyposquat("completely-different-name-xyz.com"));
    }
}
