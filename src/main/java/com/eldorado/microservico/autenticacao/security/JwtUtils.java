package com.eldorado.microservico.autenticacao.security;


import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;

import java.util.Calendar;
import java.util.Date;

@Component
@Slf4j
public class JwtUtils {

    @Value("${eldorado.jwt.secret}")
    private String jwtSecret;
    @Value("${eldorado.jwt.expirationMs}")
    private int jwtTTL;

    public String generationJwtToken(Authentication authentication) {

        User user = (User) authentication.getPrincipal();
        var date = Calendar.getInstance().getTime();
        return Jwts.builder()
                .setSubject(user.getUsername())
                .setIssuedAt(date)
                .setExpiration(new Date(date.getTime() + jwtTTL))
                .signWith(SignatureAlgorithm.HS512, jwtSecret)
                .compact();
    }

}
