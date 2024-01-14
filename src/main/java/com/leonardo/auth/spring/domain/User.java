package com.leonardo.auth.spring.domain;

import com.leonardo.auth.spring.enums.UserRoles;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

@Entity(name = "users")
@Getter
@Setter
@RequiredArgsConstructor
public class User implements UserDetails {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @Column(name = "username")
    private String username;
    @Column(name = "first_name")
    private String firstName;
    @Column(name = "last_name")
    private String lastName;
    @Column(name = "date_birth")
    private String dateBirth;
    @Column(name = "email")
    private String email;
    @Column(name = "password")
    private String password;
    @Column(name = "is_enable")
    private Boolean isEnable;
    @Enumerated(EnumType.STRING)
    @Column(name = "user_roles")
    private UserRoles userRoles;
    @Column(name = "is_account_non_expired")
    private Boolean isAccountNonExpired;
    @Column(name = "is_account_non_locked")
    private Boolean isAccountNonLocked;
    @Column(name = "is_Credential_non_expired")
    private Boolean isCredentialsNonExpired;

    public User(String userName, String firstName, String lastName, String dateBirth, String email, String password) {
        this.username = userName;
        this.firstName = firstName;
        this.lastName = lastName;
        this.dateBirth = dateBirth;
        this.email = email;
        this.password = password;
        this.userRoles = UserRoles.FREE;
        this.isEnable = true;
        this.isAccountNonExpired = true;
        this.isAccountNonLocked = true;
        this.isCredentialsNonExpired = true;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        if (this.userRoles == UserRoles.ADMIN) {
            return List.of(new SimpleGrantedAuthority("ROLE_ADMIN"), new SimpleGrantedAuthority("ROLE_FREE"),
                    new SimpleGrantedAuthority("ROLE_PREMIUM"));
        } else return List.of(new SimpleGrantedAuthority("ROLE_FREE"));
    }

    @Override
    public boolean isAccountNonExpired() {
        return getIsAccountNonExpired();
    }

    @Override
    public boolean isAccountNonLocked() {
        return getIsAccountNonLocked();
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return getIsCredentialsNonExpired();
    }

    @Override
    public boolean isEnabled() {
        return getIsEnable();
    }
}
