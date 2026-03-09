package st.ana.accounts.user.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.List;

@Controller
@RequestMapping("/oauth2/consent")
public class OAuthConsentController {

    /**
     * Renders the OAuth2 consent/authorization page.
     * In production this will be wired to the authorization server's consent endpoint.
     */
    @GetMapping
    public String consentPage(
            @RequestParam(name = "client_id") String clientId,
            @RequestParam(name = "client_name", defaultValue = "An Apply") String clientName,
            @RequestParam(name = "scope", required = false, defaultValue = "") String scopeParam,
            @RequestParam(name = "state", required = false, defaultValue = "") String state,
            Model model) {

        List<String> scopes = scopeParam.isBlank()
                ? List.of()
                : List.of(scopeParam.split("\\s+"));

        model.addAttribute("clientId", clientId);
        model.addAttribute("clientName", clientName);
        model.addAttribute("scopes", scopes);
        model.addAttribute("state", state);

        return "oauth-consent";
    }
}
