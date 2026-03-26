package st.ana.accounts.user.controller;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/user")
public class UserManagementController {
    @GetMapping("/me")
    public Map<String, Object> user(@AuthenticationPrincipal Jwt jwt) {
        Map<String, Object> response = new HashMap<>();

        response.put("user_info", jwt.getClaims());
        response.put("scopes", jwt.getClaim("scope"));

        return response;
    }
}
