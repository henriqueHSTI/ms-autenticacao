package com.eldorado.microservico.autenticacao.dto;

import lombok.*;

@Builder
@NoArgsConstructor
@AllArgsConstructor
@Data
public class UserLoginDto {

    @NonNull
    private String login;
    @NonNull
    private String password;
}
