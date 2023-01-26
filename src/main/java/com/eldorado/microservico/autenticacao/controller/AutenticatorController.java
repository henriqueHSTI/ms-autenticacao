package com.eldorado.microservico.autenticacao.controller;

import com.eldorado.microservico.autenticacao.dto.JwtDto;
import com.eldorado.microservico.autenticacao.dto.UserLoginDto;
import com.eldorado.microservico.autenticacao.security.JwtUtils;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

@CrossOrigin(origins = "*")
@RestController
@RequestMapping("/eldorado/auth")
@Slf4j
@RequiredArgsConstructor
public class AutenticatorController {

    @Qualifier("authenticationManagerBean")
    private AuthenticationManager authenticationManager;

    @Autowired(required = false)
    private PasswordEncoder passwordEncoder;
    @Autowired
    private JwtUtils jwtUtils;

    @PostMapping
    public ResponseEntity<?> authenticator(@Valid @RequestBody UserLoginDto userLoginDto) {

        var authenticator = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(userLoginDto.getLogin(),
                        userLoginDto.getPassword()));

        SecurityContextHolder.getContext().setAuthentication(authenticator);

        var jwt = jwtUtils.generationJwtToken(authenticator);

        User user = (User) authenticator.getPrincipal();
        return ResponseEntity.ok(JwtDto.builder()
                .token(jwt).
                userName(user.getUsername())
                .build());
    }


}
