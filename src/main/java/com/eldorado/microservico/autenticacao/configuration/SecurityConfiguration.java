package com.eldorado.microservico.autenticacao.configuration;

import com.eldorado.microservico.autenticacao.security.AuthEntryPointJwt;
import com.eldorado.microservico.autenticacao.service.UserDatailsServiceImpl;
import lombok.SneakyThrows;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableMethodSecurity

public class SecurityConfiguration {


    @Autowired
    private AuthEntryPointJwt authEntryPointJwt;

    @Autowired
    private UserDatailsServiceImpl userDatailsService;

    @Bean
    public DaoAuthenticationProvider authenticationProvider() {
        var authenticationProvider = new DaoAuthenticationProvider();
        authenticationProvider.setUserDetailsService(userDatailsService);
        return authenticationProvider;
    }

    @Bean
    @SneakyThrows
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) {
        httpSecurity.cors().and().csrf().disable()
                .exceptionHandling().authenticationEntryPoint(authEntryPointJwt).and()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
                .authorizeHttpRequests().requestMatchers("/eldorado/auth").permitAll()
                .anyRequest().authenticated();
        httpSecurity.authenticationProvider(authenticationProvider());
        return httpSecurity.build();
    }

}
