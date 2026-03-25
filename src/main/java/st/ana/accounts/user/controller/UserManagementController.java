package st.ana.accounts.user.controller;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/user")
public class UserManagementController {
    @GetMapping("/me")
    public Map<String, Object> user(@AuthenticationPrincipal OAuth2AuthenticatedPrincipal principal) {
        return principal.getAttributes();
    }
}
