package com.leonardo.auth.spring.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.leonardo.auth.spring.domain.ForgotPassword;

public interface ForgotPasswordRepositoryCustom extends JpaRepository<ForgotPassword, Long> {

    ForgotPassword getReferenceByUserEmail(String email);

}
