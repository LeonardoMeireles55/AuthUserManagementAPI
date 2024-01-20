package com.leonardo.auth.spring.record;

import jakarta.validation.constraints.NotBlank;

public record AlterTableDTO(
    @NotBlank
    String username,
    @NotBlank
    String firstName,
    @NotBlank
    String lastName,
    @NotBlank
    String dateBirth,
    @NotBlank
    String email,
    @NotBlank
    String password,
    @NotBlank
    String userRoles
) {

}
