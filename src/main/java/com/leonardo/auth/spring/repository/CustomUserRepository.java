package com.leonardo.auth.spring.repository;

import com.leonardo.auth.spring.domain.User;
import jakarta.transaction.Transactional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Repository;

@Repository
public interface CustomUserRepository extends JpaRepository<User, Long> {
    UserDetails findByUsername(String userName);

    UserDetails getReferenceByFirstNameAndEmail(String userName, String Email);

    @Transactional
    @Modifying
    @Query("UPDATE users u SET u.password = ?2 WHERE u.username = ?1")
    void setPasswordWhereByUsername(String username, String newPassword);

    boolean existsByUsername(String name);

    boolean existsByEmail(String email);

    @Transactional
    @Modifying
    @Query("UPDATE users u SET u.isEnable = false WHERE u.username = ?1")
    void logicalDelete(String username);

    @Transactional
    void deleteByIdAndUsername(Long id, String username);

}
