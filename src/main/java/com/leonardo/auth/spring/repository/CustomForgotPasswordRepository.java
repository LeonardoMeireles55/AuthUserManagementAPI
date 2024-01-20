package com.leonardo.auth.spring.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.leonardo.auth.spring.domain.ForgotPassword;

public interface CustomForgotPasswordRepository extends JpaRepository<ForgotPassword, Long> {

    ForgotPassword getReferenceByUserEmail(String email);

}
