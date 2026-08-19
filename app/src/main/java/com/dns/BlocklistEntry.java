package com.dns;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "blocklist_entry")
public class BlocklistEntry {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String domain;

    private String source;       // "urlhaus" or "fallback"
    private LocalDateTime addedAt;

    public BlocklistEntry() {}

    public BlocklistEntry(String domain, String source) {
        this.domain = domain;
        this.source = source;
        this.addedAt = LocalDateTime.now();
    }

    public Long getId() { return id; }
    public String getDomain() { return domain; }
    public String getSource() { return source; }
    public LocalDateTime getAddedAt() { return addedAt; }
}
