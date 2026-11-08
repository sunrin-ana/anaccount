package st.ana.accounts.user.controller;

import dev.samstevens.totp.time.TimeProvider;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
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

import java.io.IOException;
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

    /**
     * 로그인 페이지.
     *
     * <p>
     * 일부 클라이언트(예: assignment.ana.st)는 인가 요청 파라미터를
     * {@code /oauth2/authorize}가 아니라 {@code /login}에 붙여서 보낸다. 이때 그냥
     * 로그인 화면만 렌더링하면 {@code client_id}, {@code redirect_uri}, {@code state}
     * 등이 버려져서, 구글 로그인을 마친 뒤 되돌아갈 곳(saved request)이 없어진다.
     * 그래서 인가 요청으로 보이는 경우에는 쿼리 스트링을 그대로 유지한 채
     * {@code /oauth2/authorize}로 넘긴다. 해당 엔드포인트가 클라이언트와
     * redirect URI를 DB 기준으로 검증하고, 로그인 후 원래 요청을 재생해 준다.
     */
    @GetMapping("/login")
    public String loginPage(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String queryString = request.getQueryString();
        if (isAuthorizationRequest(request, queryString)) {
            // 인코딩된 쿼리 스트링을 그대로 넘겨야 한다. redirect: 뷰를 쓰면
            // 퍼센트 인코딩이 다시 인코딩될 수 있어서 원본을 직접 보낸다.
            response.sendRedirect(request.getContextPath() + "/oauth2/authorize?" + queryString);
            return null;
        }
        return "login";
    }

    private static boolean isAuthorizationRequest(HttpServletRequest request, String queryString) {
        return queryString != null
                && request.getParameter(OAuth2ParameterNames.CLIENT_ID) != null
                && request.getParameter(OAuth2ParameterNames.RESPONSE_TYPE) != null;
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
