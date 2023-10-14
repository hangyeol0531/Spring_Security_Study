package study.security.config.auth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import study.security.model.User;
import study.security.repository.UserRepository;

// 시큐리티 설정에서 loginProcessingUrl 요청이 오면 자동으로 loadUserByUsername 함수 실행
@Service
public class PrincipalDetailsService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    // 함수 종료시 @AuthenticationPrincipal 어노테이션 만들어진다.
    // 최초 로그인시에만 실행되고 후 세션을 넘겨준다., 세션 스토리지에 저장 후 요청이 오면 스토리지 값을 넘겨줌
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username);
        if (user != null) {
            return new PrincipalDetails(user);
        }
        return null;
    }
}
