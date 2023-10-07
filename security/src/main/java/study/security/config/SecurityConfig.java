package study.security.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import study.security.config.oauth.PrincipalOauth2UserService;

@Configuration
@EnableWebSecurity // spring security 필터가 스프링 필터체인에 등록
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true) // secure, preAuthorized, postAuthorized 어노테이션 활성화
public class SecurityConfig {

    @Autowired
    private PrincipalOauth2UserService principalOauth2UserService;

    // 해당 메서드의 리턴되는 오브젝트를 Ioc로 등록해줌
//    @Bean
//    public BCryptPasswordEncoder encodePwd(){
//        return new BCryptPasswordEncoder();
//    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf(CsrfConfigurer::disable);
        http.authorizeHttpRequests(authorize ->
                authorize
                    .requestMatchers("/user/**").authenticated()
                    .requestMatchers("/manager/**").hasAnyRole("ADMIN", "MANAGER")
                    .requestMatchers("/admin/**").hasAnyRole("ADMIN")
                    .anyRequest().permitAll() // 다른 요청들은 전부 허용
            )

            .formLogin()
            .loginPage("/loginForm")
            .loginProcessingUrl("/login")// login 호출이 되면 낚아채서 대신 로그인 진행
            .defaultSuccessUrl("/")

            .and()
            .oauth2Login()
            .loginPage("/loginForm") // oauth login 후에 (access Token + profile 정보) 받게됨
            .userInfoEndpoint()
            .userService(principalOauth2UserService);

        return http.build();
    }
}
