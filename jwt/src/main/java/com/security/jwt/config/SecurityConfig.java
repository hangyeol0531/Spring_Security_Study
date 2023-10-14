package com.security.jwt.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity // spring security 필터가 스프링 필터체인에 등록
@RequiredArgsConstructor
// secure, preAuthorized, postAuthorized 어노테이션 활성화
public class SecurityConfig {

    private final CorsConfig corsConfig;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf(CsrfConfigurer::disable);
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) // 세션 사용 X
            .and()
            .apply(new MyCustomDsl())
            .and()
            .formLogin().disable()
            .httpBasic().disable()
            .authorizeRequests(authorize ->
                authorize
                    .requestMatchers("/api/v1/user/**")
                    .access("hasRole('ROLE_USRR') or hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
                    .requestMatchers("/api/v1/manager/**")
                    .access("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
                    .requestMatchers("/api/v1/admin/**")
                    .access("hasRole('ROLE_ADMIN')")
                    .anyRequest().permitAll()
            );
        return http.build();
    }

    public class MyCustomDsl extends AbstractHttpConfigurer<MyCustomDsl, HttpSecurity> {
        @Override
        public void configure(HttpSecurity http) throws Exception {
            http
                .addFilter(corsConfig.corsFilter());
        }
    }
}
