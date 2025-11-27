package com.services;

import com.dtos.LoginRequest;
import com.dtos.RegisterRequest;
import com.dtos.TokenResponse;
import com.dtos.ValidateResponse;
import com.entities.Credential;
import com.enums.Role;
import com.repositories.CredentialRepository;
import io.jsonwebtoken.Claims;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;


@Service
@RequiredArgsConstructor
public class AuthService {

    private final CredentialRepository repo;
    private final JwtService jwtService;
    private final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    @Transactional
    public void register(RegisterRequest req) {
        if (req.getRole() == null) {
            throw new IllegalArgumentException("Role is required");
        }
        if (repo.findByUsername(req.getUsername()).isPresent()) {
            throw new IllegalArgumentException("Username already exists");
        }
        if (req.getUserId() == null) {
            throw new IllegalArgumentException("userId is required");
        }

        Credential c = Credential.builder()
                .userId(req.getUserId())
                .username(req.getUsername())
                .passwordHash(passwordEncoder.encode(req.getPassword()))
                .role(req.getRole())
                .build();
        repo.save(c);
    }

    public TokenResponse login(LoginRequest req) {
        Credential cred = repo.findByUsername(req.getUsername())
                .orElseThrow(() -> new IllegalArgumentException("Invalid username or password"));

        if (!passwordEncoder.matches(req.getPassword(), cred.getPasswordHash())) {
            throw new IllegalArgumentException("Invalid username or password");
        }

        Long userId = cred.getUserId();
        // if userId null, we still can encode userId in token as 0 or throw.
        if (userId == null) throw new IllegalArgumentException("Credential is not linked to userId");

        Role role = cred.getRole();

        String access = jwtService.generateAccessToken(userId, role);
        String refresh = jwtService.generateRefreshToken(userId, role);
        return new TokenResponse(access, refresh);
    }

    public TokenResponse refresh(String refreshToken) {
        if (!jwtService.validate(refreshToken)) {
            throw new IllegalArgumentException("Invalid refresh token");
        }

        Claims claims = jwtService.parse(refreshToken);
        Long userId = Long.valueOf(claims.getSubject());
        Role role = Role.valueOf(claims.get("role", String.class));

        return new TokenResponse(
                jwtService.generateAccessToken(userId, role),
                jwtService.generateRefreshToken(userId, role)
        );
    }

    public ValidateResponse validate(String token) {
        if (!jwtService.validate(token)) {
            return new ValidateResponse(null, null, false);
        }

        Claims claims = jwtService.parse(token);
        Long userId = Long.valueOf(claims.getSubject());
        Role role = Role.valueOf(claims.get("role", String.class));

        return new ValidateResponse(userId, role, true);
    }
}
