package st.ana.accounts.user.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
@RequestMapping("/device-code")
public class DeviceCodeController {

    @GetMapping
    public String deviceCodePage(Model model) {
        return "device-code";
    }

    @PostMapping
    public String submitDeviceCode(@RequestParam(name = "userCode", defaultValue = "") String userCode) {
        // TODO: validate device user code against the authorization server
        return "redirect:/";
    }
}
