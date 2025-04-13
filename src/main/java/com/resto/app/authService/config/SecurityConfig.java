package com.resto.app.authService.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.userdetails.MapReactiveUserDetailsService;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.server.SecurityWebFilterChain;


@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {


    @Bean
    public MapReactiveUserDetailsService userDetailsService(PasswordEncoder passwordEncoder) {
        UserDetails user = User.builder()
                .username("user")
                .password(passwordEncoder.encode("password")) // Codifica la contraseña
                .roles("USER")
                .build();
        return new MapReactiveUserDetailsService(user);
    }

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        http.csrf(ServerHttpSecurity.CsrfSpec::disable)
                .authorizeExchange(exchanges -> {
                    // Permitir acceso sin autenticación a estos endpoints:
                    exchanges.pathMatchers(HttpMethod.POST, "/auth/login").permitAll();
                    exchanges.pathMatchers(HttpMethod.POST, "/auth/validate").permitAll();
                    exchanges.pathMatchers(HttpMethod.GET, "/users/find/**").permitAll();
                    exchanges.pathMatchers(HttpMethod.GET, "/actuator/**").permitAll();

                    // Permitir acceso a Customer Service sin bloquearlo en el Auth Service
                    exchanges.pathMatchers("/customer/**").permitAll();

                    // Proteger rutas específicas con autenticación:
                    exchanges.pathMatchers("/auth/protected/**").authenticated();
                });
        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

}
