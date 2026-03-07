package st.ana.accounts.user.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import st.ana.accounts.user.model.User;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByGoogleId(String googleId);
    Optional<User> findByHandle(String handle);
}
