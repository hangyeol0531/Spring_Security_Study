package com.security.jwt.config;

import com.security.jwt.JwtAuthenticationFilter;
import com.security.jwt.JwtAuthorizationFilter;
import com.security.jwt.filter.MyFilter3;
import com.security.jwt.model.UserRepository;
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
import org.springframework.security.web.context.SecurityContextPersistenceFilter;

@Configuration
@EnableWebSecurity // spring security 필터가 스프링 필터체인에 등록
@RequiredArgsConstructor
// secure, preAuthorized, postAuthorized 어노테이션 활성화
public class SecurityConfig {

    private final CorsConfig corsConfig;
    private final UserRepository userRepository;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf(CsrfConfigurer::disable);
        http
//            .addFilterBefore(new MyFilter3(), SecurityContextPersistenceFilter.class)
            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) // 세션 사용 X
            .and()
            .apply(new MyCustomDsl())
            .and()
            .formLogin().disable()
            .httpBasic().disable() // Bearer 인증 방식을 쓰기 위해 기본 인증방식을 비활성화
            .authorizeRequests(authorize ->
                authorize
                    .requestMatchers("/api/v1/user/**")
                    .access("hasRole('ROLE_USER') or hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
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
        public void configure(HttpSecurity http) {
            AuthenticationManager authenticationManager = http.getSharedObject(AuthenticationManager.class);

            http
                .addFilter(corsConfig.corsFilter())
                .addFilter(new JwtAuthenticationFilter(authenticationManager)) // authentication Manger
                .addFilter(new JwtAuthorizationFilter(authenticationManager, userRepository));
        }
    }
}
