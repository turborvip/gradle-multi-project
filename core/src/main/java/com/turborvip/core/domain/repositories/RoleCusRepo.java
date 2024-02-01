package com.turborvip.core.domain.repositories;

import com.turborvip.core.model.entity.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Set;

@Repository
public interface RoleCusRepo extends JpaRepository<Role, Long> {
     Set<Role> findByUsers_Username(String username);
}
