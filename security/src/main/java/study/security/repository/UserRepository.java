package study.security.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import study.security.model.User;

public interface UserRepository extends JpaRepository<User, Long> {

    public User findByUsername(String username);
}
