package com.dns;

import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class BlocklistServiceTest {

    private final BlocklistService blocklistService = new BlocklistService();

    @Test
    void parseHostfileFormat_extractsDomainFromValidLine() {
        String raw = "127.0.0.1\tbadguy.com";
        Set<String> parsed = blocklistService.parseHostfileFormat(raw);
        assertTrue(parsed.contains("badguy.com"));
    }

    @Test
    void parseHostfileFormat_skipsCommentLines() {
        String raw = "# this is a comment\n127.0.0.1\tbadguy.com";
        Set<String> parsed = blocklistService.parseHostfileFormat(raw);
        assertEquals(1, parsed.size());
        assertTrue(parsed.contains("badguy.com"));
    }

    @Test
    void parseHostfileFormat_skipsBlankLines() {
        String raw = "\n\n127.0.0.1\tbadguy.com\n\n";
        Set<String> parsed = blocklistService.parseHostfileFormat(raw);
        assertEquals(1, parsed.size());
    }

    @Test
    void parseHostfileFormat_lowercasesDomains() {
        String raw = "127.0.0.1\tBADGUY.COM";
        Set<String> parsed = blocklistService.parseHostfileFormat(raw);
        assertTrue(parsed.contains("badguy.com"));
        assertFalse(parsed.contains("BADGUY.COM"));
    }

    @Test
    void parseHostfileFormat_handlesMultipleDomains() {
        String raw = "127.0.0.1\tfirst.com\n127.0.0.1\tsecond.com\n127.0.0.1\tthird.com";
        Set<String> parsed = blocklistService.parseHostfileFormat(raw);
        assertEquals(3, parsed.size());
    }

    @Test
    void parseHostfileFormat_ignoresMalformedLines() {
        // a line with only one field (no domain) shouldn't be counted
        String raw = "malformed_line_no_tab\n127.0.0.1\tvalid.com";
        Set<String> parsed = blocklistService.parseHostfileFormat(raw);
        assertEquals(1, parsed.size());
        assertTrue(parsed.contains("valid.com"));
    }

    @Test
    void isBlocked_returnsFalseForAnyDomainBeforeRefresh() {
        // blocklistCache starts empty until refreshFromLiveFeed() actually runs —
        // no silent fallback state that could mask whether refresh happened
        assertFalse(blocklistService.isBlocked("badguy.com"));
        assertFalse(blocklistService.isBlocked("google.com"));
    }

    @Test
    void size_isZeroBeforeRefresh() {
        assertEquals(0, blocklistService.size());
    }
}
