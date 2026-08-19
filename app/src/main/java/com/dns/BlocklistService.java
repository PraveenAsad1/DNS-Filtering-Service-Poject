package com.dns;

import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

@Service
public class BlocklistService {

    // Defaults to the live URLhaus feed; overridable via env var so held-out
    // evaluation can point this at a filtered local snapshot instead.
    private final String feedUrl = System.getenv().getOrDefault(
            "BLOCKLIST_FEED_URL", "https://urlhaus.abuse.ch/downloads/hostfile/");

    // Fallback list, used if the live feed can't be fetched at startup —
    // ensures the proxy still has *some* blocklist even if the feed is down.
    private static final Set<String> FALLBACK_DOMAINS = new HashSet<>(Arrays.asList(
            "badguy.com",
            "malware.example.com",
            "phishing-test.com"
    ));

    private Set<String> blocklist = Collections.unmodifiableSet(FALLBACK_DOMAINS);

    private final HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .build();

    // Fetches the live URLhaus threat feed and replaces the in-memory blocklist.
    // Called once at startup; falls back to the hardcoded list on any failure.
    public void refreshFromLiveFeed() {
        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(feedUrl))
                    .timeout(Duration.ofSeconds(15))
                    .GET()
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            Set<String> parsed = parseHostfileFormat(response.body());

            if (!parsed.isEmpty()) {
                blocklist = Collections.unmodifiableSet(parsed);
                System.out.println("Blocklist refreshed from live feed: " + blocklist.size() + " domains loaded");
            } else {
                System.err.println("Live feed returned no parseable domains — keeping fallback blocklist");
            }
        } catch (Exception e) {
            System.err.println("Failed to fetch live threat feed, using fallback blocklist: " + e.getMessage());
        }
    }

    // URLhaus hostfile format: "127.0.0.1<TAB>domain.com" per line, "#" comment lines
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

    public boolean isBlocked(String cleanDomain) {
        return blocklist.contains(cleanDomain);
    }

    public int size() {
        return blocklist.size();
    }
}
