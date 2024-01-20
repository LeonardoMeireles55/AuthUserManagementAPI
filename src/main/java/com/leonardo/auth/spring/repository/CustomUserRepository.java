package com.leonardo.auth.spring.repository;

import com.leonardo.auth.spring.domain.User;
import com.leonardo.auth.spring.enums.UserRoles;

import io.micrometer.common.lang.NonNull;
import jakarta.transaction.Transactional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

@Repository
public interface CustomUserRepository extends JpaRepository<User, Long> {

    User findByUsername(String userName);

    User getReferenceByUsernameAndEmail(String userName, String Email);

    User getReferenceByEmail(String Email);

    @Transactional
    @Modifying
    @Query("UPDATE users u SET u.password = ?2 WHERE u.username = ?1")
    void setPasswordWhereByUsername(String username, String newPassword);

    boolean existsByUsername(String name);

    boolean existsByEmail(String email);

    @Transactional
    @Modifying
    @Query("UPDATE users u SET u.enabled = false WHERE u.id = ?1")
    void softDeletion(@NonNull Long id);
 
    @Transactional
    @Modifying
    @Query("UPDATE users u SET u.userRoles = ?2 WHERE u.id = ?1")
    void updateUserRoles(Long id, UserRoles userRoles);

    @Transactional
    @Modifying
    @Query("UPDATE users u SET u.accountNonExpired = NOT u.accountNonExpired WHERE u.id = ?1")
    void toggleAccountNonExpired(Long id);

    @Transactional
    @Modifying
    @Query("UPDATE users u SET u.accountNonLocked = NOT u.accountNonLocked WHERE u.id = ?1")
    void toggleAccountNonLockedById(Long id);

    @Transactional
    @Modifying
    @Query("UPDATE users u SET u.credentialsNonExpired = NOT u.credentialsNonExpired WHERE u.id = ?1")
    void credentialsNonExpired(Long id);

    @Transactional
    @Modifying
    @Query("UPDATE users u SET u.enabled = NOT u.enabled WHERE u.id = ?1")
    void toggleEnabledById(Long id);
}
