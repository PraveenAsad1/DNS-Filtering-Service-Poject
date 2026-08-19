package com.dns;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

public interface BlocklistEntryRepository extends JpaRepository<BlocklistEntry, Long> {

    // used to clear out stale entries before persisting a fresh feed refresh
    @Modifying
    @Transactional
    @Query("DELETE FROM BlocklistEntry b WHERE b.source = :source")
    void deleteBySource(String source);

    List<BlocklistEntry> findBySource(String source);
}
