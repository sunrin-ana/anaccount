package st.ana.accounts.user.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class SignupController {

    @GetMapping("/signup")
    public String signupPage(Model model) {
        return "signup";
    }

    @PostMapping("/signup")
    public String submitSignup(
            @RequestParam String fullName,
            @RequestParam String phone,
            Model model) {
        // TODO: persist user profile and complete registration
        return "redirect:/";
    }
}
