package com.security.jwt;


import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.security.jwt.auth.PrincipalDetails;
import com.security.jwt.model.User;
import com.security.jwt.model.UserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import java.io.IOException;

// security - BasicAuthenticationFilter -> 권한, 인증이 필요한 특정 주소를 요청 후 실행되는 필터
// 필요한 권한은 SecurityConfig에서 requestMatchers로 설정한 부분을 말함
// 권한 인증 필요 없으면 위 필터는 실행이 안된다.
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

    private UserRepository userRepository;

    public JwtAuthorizationFilter(AuthenticationManager authenticationManager, UserRepository userRepository) {
        super(authenticationManager);
        this.userRepository = userRepository;
    }

    // 인증 권한이 필요한 주소 요청이 있을때 해당 필터를 실행 시킨다.
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        String jwtHeader = request.getHeader("Authorization");
        System.out.println("jwtHeader = " + jwtHeader);

        // validate jwt
        if (jwtHeader == null || !jwtHeader.startsWith("Bearer")) {
            chain.doFilter(request, response);
            return;
        }

        String jwtToken = request.getHeader("Authorization").replace("Bearer ", "");

        String username = JWT.require(Algorithm.HMAC512("cos")).build()
            .verify(jwtToken)
            .getClaim("username")
            .asString();

        if (username != null) {
            User user = userRepository.findByUsername(username);
            PrincipalDetails principalDetails = new PrincipalDetails(user);

            // 정상이면 Authentication 객체 생성
            Authentication authentication = new
                UsernamePasswordAuthenticationToken(principalDetails, null, principalDetails.getAuthorities());

            // 강제 session에 Authentication 저장
            SecurityContextHolder.getContext().setAuthentication(authentication);

            chain.doFilter(request, response);
        }
    }
}
