package com.dns;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

@Service
public class MLClient {

    // injected from application.yml — no hardcoded URL in the code
    @Value("${dns.ml-service.url}")
    private String mlServiceUrl;

    private final HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(2)) // don't let a hung service stall DNS resolution
            .build();

    private final ObjectMapper objectMapper = new ObjectMapper();

    // Calls the Python heuristic scoring service for a given domain.
    // Returns a neutral fallback score (0.5) if the service is unreachable,
    // so a scoring-service outage never crashes the DNS proxy itself.
    public double analyzeDomain(String domain) {
        try {
            String url = mlServiceUrl + "?domain=" + domain;

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .timeout(Duration.ofSeconds(2))
                    .GET()
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

            JsonNode json = objectMapper.readTree(response.body());
            return json.get("threat_score").asDouble();

        } catch (Exception e) {
            System.err.println("MLClient error for domain " + domain + ": " + e.getMessage());
            return 0.5; // conservative neutral fallback — neither auto-block nor auto-allow
        }
    }
}
