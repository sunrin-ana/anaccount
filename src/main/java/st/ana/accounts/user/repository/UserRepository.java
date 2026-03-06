package st.ana.accounts.user.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import st.ana.accounts.user.model.User;

public interface UserRepository extends JpaRepository<User, Long> {
    User findByGoogleId(String googleId);
    User findByHandle(String handle);
}
