package com.eldorado.microservico.autenticacao.service;

import com.eldorado.microservico.autenticacao.dto.JwtDto;
import com.eldorado.microservico.autenticacao.dto.UserLoginDto;
import com.eldorado.microservico.autenticacao.security.AuthUtils;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;

import java.util.Collections;

@Service
@RequiredArgsConstructor
public class UserDetailsServiceImpl implements UserDetailsService {
    private final AuthUtils authUtils;

    public JwtDto doAuthentication(UserLoginDto userLoginDto, Authentication authentication) {
        SecurityContextHolder.getContext().setAuthentication(authentication);

        var jwt = authUtils.generationJwtToken(authentication);

        User user = (User) authentication.getPrincipal();

        return JwtDto.builder()
                .token(jwt)
                .userName(user.getUsername().replaceAll("@.*", ""))
                .email(userLoginDto.getLogin())
                .build();
    }

    @Override
    public UserDetails loadUserByUsername(String username) {
        return new User("eldorado@eldorado.com",
                "$2a$10$slYQmyNdGzTn7ZLBXBChFOC9f6kFjAqPhccnP6DxlWXx2lPk1C3G6", Collections.emptyList());
    }
}
