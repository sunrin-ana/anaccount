package st.ana.accounts.user.controller;

import dev.samstevens.totp.time.TimeProvider;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import st.ana.accounts.oauth.client.UnknownOAuthPrincipal;
import st.ana.accounts.user.model.User;
import st.ana.accounts.user.repository.UserRepository;

import java.time.Instant;
import java.util.Set;

@Slf4j
@Controller
public class UserController {

    private final UserRepository userRepository;
    private final TimeProvider time;

    public UserController(UserRepository userRepository, TimeProvider time) {
        this.userRepository = userRepository;
        this.time = time;
    }

    @GetMapping("/continue")
    public String continuePage(Authentication authentication) {
        if(!authentication.isAuthenticated()) return "redirect:/login";
        if(authentication.getPrincipal() == null) return "redirect:/login";

        if(authentication.getPrincipal() instanceof UnknownOAuthPrincipal) return "redirect:/signup";
        return "redirect:/";
    }

    @GetMapping("/login")
    public String loginPage() {
        return "login";
    }

    @GetMapping("/signup")
    public String signupPage(@AuthenticationPrincipal OidcUser auth, Model model) {
        if(auth == null) return "redirect:/login";
        log.info("auth: {}", auth instanceof UnknownOAuthPrincipal);
        log.info("auth: {}", auth);
        if(!(auth instanceof UnknownOAuthPrincipal principal)) return "redirect:/";

        model.addAttribute("handle", principal.getAttributes().get("email").toString().split("@")[0]);
        model.addAttribute("fullName", principal.getAttributes().get("given_name"));
        return "signup";
    }

    @PostMapping("/signup")
    public String submitSignup(
            @AuthenticationPrincipal OidcUser auth,
            @RequestParam String handle,
            @RequestParam String fullName,
            @RequestParam String phone) {
        if (handle.isEmpty() || fullName.isEmpty() || phone.isEmpty()) return "redirect:/signup?error=badReq";
        if (userRepository.findByHandle(handle).isPresent()) return "redirect:/signup?error=handleAlreadyTaken";

        User user = User.builder()
                .id(time.getTime())
                .email(auth.getEmail())
                .roles(auth.getEmail().equals("ana@sunrint.hs.kr") ? Set.of("ROLE_ADMIN", "ROLE_MEMBER") : Set.of("ROLE_USER"))
                .handle(handle)
                .name(fullName)
                .phoneNumber(phone)
                .googleId(auth.getSubject())
                .generation(auth.getEmail().equals("ana@sunrint.hs.kr") ? 0 : -1)
                .createdAt(Instant.now())
                .updatedAt(Instant.now())
                .build();

        userRepository.save(user);
        return "redirect:/";
    }
}
