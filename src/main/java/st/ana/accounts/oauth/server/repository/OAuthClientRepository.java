package st.ana.accounts.oauth.server.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import st.ana.accounts.oauth.server.model.OAuthClient;

public interface OAuthClientRepository extends JpaRepository<OAuthClient, String> {
}
