package com.dns;

import org.springframework.data.jpa.repository.JpaRepository;

// Extending JpaRepository gives us save(), findAll(), findById(), count(), etc. for free —
// no SQL written by us for these basic operations.
public interface QueryLogRepository extends JpaRepository<QueryLog, Long> {
}
