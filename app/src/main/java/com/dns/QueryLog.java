package com.dns;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "query_log")
public class QueryLog {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY) // auto-incrementing primary key
    private Long id;

    private String domain;
    private boolean blocked;
    private double threatScore;
    private String blockReason;   // "blocklist", "heuristic", or null if allowed
    private LocalDateTime timestamp;

    // JPA requires a no-args constructor — it uses reflection to build objects
    public QueryLog() {}

    public QueryLog(String domain, boolean blocked, double threatScore, String blockReason) {
        this.domain = domain;
        this.blocked = blocked;
        this.threatScore = threatScore;
        this.blockReason = blockReason;
        this.timestamp = LocalDateTime.now();
    }

    // Getters and setters — required by JPA/Hibernate to read and populate fields
    public Long getId() { return id; }
    public String getDomain() { return domain; }
    public boolean isBlocked() { return blocked; }
    public double getThreatScore() { return threatScore; }
    public String getBlockReason() { return blockReason; }
    public LocalDateTime getTimestamp() { return timestamp; }
}
