package com.dns;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.*;

@Service
public class BlocklistService {

    private static final Set<String> FALLBACK_DOMAINS = new HashSet<>(Arrays.asList(
            "badguy.com",
            "malware.example.com",
            "phishing-test.com"
    ));

    // Defaults to the live URLhaus feed; overridable via env var for held-out evaluation.
    private final String feedUrl = System.getenv().getOrDefault(
            "BLOCKLIST_FEED_URL", "https://urlhaus.abuse.ch/downloads/hostfile/");

    @Autowired
    private BlocklistEntryRepository blocklistEntryRepository;

    // In-memory cache for fast O(1) lookup during actual query handling —
    // the DB is the source of truth, this is just the runtime-hot copy of it.
    private Set<String> blocklistCache = Collections.emptySet();

    private final HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .build();

    // Called once at startup. Tries the live feed first; falls back to whatever
    // was last persisted in the DB; falls back further to the hardcoded list
    // only if the DB has never been populated (e.g. first run with no network).
    public void refreshFromLiveFeed() {
        Set<String> liveDomains = fetchLiveFeed();

        if (!liveDomains.isEmpty()) {
            persistFreshFeed(liveDomains);
            blocklistCache = liveDomains;
            System.out.println("Blocklist refreshed from live feed: " + liveDomains.size() + " domains loaded and persisted");
            return;
        }

        System.err.println("Live feed unavailable — falling back to last known good blocklist from DB");
        Set<String> persisted = loadFromDatabase();

        if (!persisted.isEmpty()) {
            blocklistCache = persisted;
            System.out.println("Loaded " + persisted.size() + " domains from DB (last known good)");
            return;
        }

        System.err.println("No persisted blocklist found — using hardcoded fallback list");
        persistFreshFeed(FALLBACK_DOMAINS, "fallback");
        blocklistCache = FALLBACK_DOMAINS;
    }

    private Set<String> fetchLiveFeed() {
        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(feedUrl))
                    .timeout(Duration.ofSeconds(15))
                    .GET()
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            return parseHostfileFormat(response.body());
        } catch (Exception e) {
            System.err.println("Failed to fetch live threat feed: " + e.getMessage());
            return Collections.emptySet();
        }
    }

    Set<String> parseHostfileFormat(String rawContent) {
        Set<String> domains = new HashSet<>();
        for (String line : rawContent.split("\n")) {
            line = line.trim();
            if (line.isEmpty() || line.startsWith("#")) continue;

            String[] parts = line.split("\\s+");
            if (parts.length == 2) {
                domains.add(parts[1].toLowerCase());
            }
        }
        return domains;
    }

    private void persistFreshFeed(Set<String> domains) {
        persistFreshFeed(domains, "urlhaus");
    }

    private void persistFreshFeed(Set<String> domains, String source) {
        // clear out old entries from this source, then bulk-insert the fresh set
        blocklistEntryRepository.deleteBySource(source);
        for (String domain : domains) {
            blocklistEntryRepository.save(new BlocklistEntry(domain, source));
        }
    }

    private Set<String> loadFromDatabase() {
        Set<String> domains = new HashSet<>();
        for (BlocklistEntry entry : blocklistEntryRepository.findAll()) {
            domains.add(entry.getDomain());
        }
        return domains;
    }

    public boolean isBlocked(String cleanDomain) {
        return blocklistCache.contains(cleanDomain);
    }

    public int size() {
        return blocklistCache.size();
    }
}
