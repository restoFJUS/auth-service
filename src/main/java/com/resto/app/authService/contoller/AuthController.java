package com.resto.app.authService.contoller;


import com.resto.app.authService.model.LoginRequest;
import com.resto.app.authService.service.JwtTokenUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;


@RestController
@RequestMapping("/auth")
public class AuthController {


    @Autowired
    private WebClient.Builder webClientBuilder;

    @Autowired
    private JwtTokenUtil jwtTokenUtil;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @PostMapping("/login")
    public Mono<ResponseEntity<?>> login(@RequestBody LoginRequest loginRequest) {
        /* Validar usuario y contraseña (esto es un ejemplo básico)
        //TODO:servicio de login para recuperar datos del usuario en la base de datos

        User user = webClientBuilder.build()
                .get()
                .uri("http://user-service:8081/users/find/" + loginRequest.getUsername())
                .retrieve()
                .bodyToMono(User.class)
                .block();

        if (user != null && passwordEncoder.matches(loginRequest.getPassword(), user.getPassword())) {
            String token = jwtTokenUtil.generateToken(user.getUsername());
            return ResponseEntity.ok(token);
        }
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();



        if ("user".equals(loginRequest.getUsername()) && "password".equals(loginRequest.getPassword())) {
            String token = jwtTokenUtil.generateToken(loginRequest.getUsername());
            return ResponseEntity.ok(token);
        }
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();





        // Consultar el User Service para obtener el usuario
        User user = webClientBuilder.build()
                .get()
                .uri("http://user-service:8081/users/find/" + loginRequest.getUsername())
                .retrieve()
                .bodyToMono(User.class)
                .block();

        if (user != null && passwordEncoder.matches(loginRequest.getPassword(), user.getPassword())) {
            String token = jwtTokenUtil.generateToken(user.getUsername());
            return ResponseEntity.ok(token);
        }
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
*/




        return webClientBuilder.build()
                .get()
                .uri("http://user-service:9093/users/find/" + loginRequest.getUsername())
                .retrieve()
                .bodyToMono(new ParameterizedTypeReference<Map<String, Object>>() {})
                .flatMap(userData -> {
                    String username = (String) userData.get("username");
                    String password = (String) userData.get("password");

                    List<String> roles = ((List<?>) userData.get("roles"))
                            .stream()
                            .map(Object::toString)
                            .collect(Collectors.toList());

                    if (passwordEncoder.matches(loginRequest.getPassword(), password)) {
                        String token = jwtTokenUtil.generateToken(username, roles);
                        return Mono.just(ResponseEntity.ok(token));
                    } else {
                        return Mono.just(ResponseEntity.status(HttpStatus.UNAUTHORIZED).build());
                    }
                })
                .defaultIfEmpty(ResponseEntity.status(HttpStatus.UNAUTHORIZED).build()); // Manejar usuario no encontrado
    }




    @PostMapping("/validate")
    public boolean validateToken(@RequestHeader("Authorization") String token) {
        // Eliminar el prefijo "Bearer " del token
        if (token != null && token.startsWith("Bearer ")) {
            token = token.substring(7);
        }
        return jwtTokenUtil.validateToken(token);
    }


}
