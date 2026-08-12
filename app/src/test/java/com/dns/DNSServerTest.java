package com.dns;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.xbill.DNS.*;
import org.xbill.DNS.Record;

import static org.junit.jupiter.api.Assertions.*;

class DNSServerTest {

    private DNSServer dnsServer;

    @BeforeEach
    void setUp() {
        dnsServer = new DNSServer();
        dnsServer.threatThreshold = 0.7; // simulate what @Value would inject in production
    }

    // --- cleanDomain ---

    @Test
    void cleanDomain_stripsTrailingDot() {
        assertEquals("google.com", DNSServer.cleanDomain("google.com."));
    }

    @Test
    void cleanDomain_lowercasesMixedCase() {
        assertEquals("google.com", DNSServer.cleanDomain("GOOGLE.COM."));
    }

    @Test
    void cleanDomain_handlesNoTrailingDot() {
        assertEquals("google.com", DNSServer.cleanDomain("google.com"));
    }

    // --- isBlocklisted ---

    @Test
    void isBlocklisted_returnsTrueForKnownBadDomain() {
        assertTrue(DNSServer.isBlocklisted("badguy.com"));
    }

    @Test
    void isBlocklisted_returnsFalseForCleanDomain() {
        assertFalse(DNSServer.isBlocklisted("google.com"));
    }

    @Test
    void isBlocklisted_isCaseSensitive_soCallerMustLowercaseFirst() {
        // documents the contract: cleanDomain() must run before isBlocklisted()
        assertFalse(DNSServer.isBlocklisted("BADGUY.COM"));
    }

    // --- isAboveThreshold ---

    @Test
    void isAboveThreshold_returnsTrueWhenScoreExceedsThreshold() {
        assertTrue(dnsServer.isAboveThreshold(0.8));
    }

    @Test
    void isAboveThreshold_returnsFalseWhenScoreBelowThreshold() {
        assertFalse(dnsServer.isAboveThreshold(0.5));
    }

    @Test
    void isAboveThreshold_returnsFalseWhenScoreEqualsThreshold() {
        // boundary case: exactly at threshold should NOT be blocked ("above", not "at or above")
        assertFalse(dnsServer.isAboveThreshold(0.7));
    }

    // --- buildSinkholeResponse ---

    @Test
    void buildSinkholeResponse_returnsRecordPointingTo0000() throws Exception {
        Name queriedName = Name.fromString("badguy.com.");
        Record question = Record.newRecord(queriedName, Type.A, DClass.IN);
        Message query = Message.newQuery(question);

        byte[] responseBytes = dnsServer.buildSinkholeResponse(query);
        Message response = new Message(responseBytes);

        Record[] answers = response.getSectionArray(Section.ANSWER);
        assertEquals(1, answers.length, "sinkhole response should contain exactly one answer record");

        ARecord aRecord = (ARecord) answers[0];
        assertEquals("0.0.0.0", aRecord.getAddress().getHostAddress());
    }

    @Test
    void buildSinkholeResponse_preservesOriginalQuestionName() throws Exception {
        Name queriedName = Name.fromString("phishing-test.com.");
        Record question = Record.newRecord(queriedName, Type.A, DClass.IN);
        Message query = Message.newQuery(question);

        byte[] responseBytes = dnsServer.buildSinkholeResponse(query);
        Message response = new Message(responseBytes);

        assertEquals(queriedName, response.getQuestion().getName());
    }
}
