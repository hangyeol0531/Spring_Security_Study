package study.security.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import study.security.config.auth.PrincipalDetails;
import study.security.model.User;
import study.security.repository.UserRepository;

@Controller
public class IndexController {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    // 일반적인 로그인 같은 경우에는 authentication 안에 userDetails가 들어감
    @GetMapping("/test/login")
    public @ResponseBody
    String testLoginTest(
        Authentication authentication,
        @AuthenticationPrincipal PrincipalDetails userDetails // DI
    ) {
        PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
        System.out.println("authentication = " + principalDetails.getUser());

        System.out.println("userDetails = " + userDetails.getUser());
        return "test";
    }

    // 일반적인 로그인 같은 경우에는 authentication 안에 oAuth2User가 들어감
    @GetMapping("/test/oauthLogin")
    public @ResponseBody
    String testOauthLoginTest(
        Authentication authentication,
        @AuthenticationPrincipal OAuth2User oauth
    ) {
        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
        System.out.println("oAuth2User.getAttributes() = " + oAuth2User.getAttributes());
        System.out.println("oauth.getAttributes() = " + oauth.getAttributes());
        return "test";
    }

    @GetMapping({"", "/"})
    public String index() {
        return "index";
    }

    @GetMapping("/user")
    public @ResponseBody
    String user() {
        return "user";
    }

    @GetMapping("/admin")
    public @ResponseBody
    String admin() {
        return "admin";
    }

    @GetMapping("/manager")
    public @ResponseBody
    String manager() {
        return "manager";
    }

    @GetMapping("/loginForm") // SecurityConfig 생성 후 내장 login url로 Redirect 안됨
    public String loginForm() {
        return "loginForm";
    }

    @GetMapping("/joinForm")
    public String joinForm() {
        return "joinForm";
    }

    @PostMapping("/join")
    public String join(User user) {
        user.setRole("USER");
        String rawPassword = user.getPassword();
        String encPassword = bCryptPasswordEncoder.encode(rawPassword);
        user.setPassword(encPassword);
        userRepository.save(user);
        return "redirect:/loginForm";
    }

    @Secured("ROLE_ADMIN")
    @GetMapping("/info")
    public @ResponseBody
    String info() {
        return "개인정보";
    }

    @PreAuthorize("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
//    @PostAuthorize()
    @GetMapping("/data")
    public @ResponseBody
    String data() {
        return "데이터";
    }
}
