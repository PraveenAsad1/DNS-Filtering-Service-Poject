package com.dns;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

@RestController
public class DashboardController {

    @Autowired
    private QueryLogRepository queryLogRepository;

    // Returns total/blocked/allowed counts and block rate, computed from all stored queries
    @GetMapping("/api/stats")
    public Map<String, Object> getStats() {
        List<QueryLog> all = queryLogRepository.findAll();
        long total = all.size();
        long blocked = all.stream().filter(QueryLog::isBlocked).count();
        double blockRate = total > 0 ? (double) blocked / total : 0.0;

        return Map.of(
                "total_queries", total,
                "blocked_queries", blocked,
                "block_rate", blockRate
        );
    }

    // Returns the most recent 50 queries, newest first
    @GetMapping("/api/queries")
    public List<QueryLog> getRecentQueries() {
        List<QueryLog> all = new ArrayList<>(queryLogRepository.findAll());
        Collections.reverse(all); // newest first
        return all.size() > 50 ? all.subList(0, 50) : all;
    }
}
