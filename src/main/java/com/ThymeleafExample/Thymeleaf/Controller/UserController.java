package com.ThymeleafExample.Thymeleaf.Controller;

import com.ThymeleafExample.Thymeleaf.Entity.User;
import com.ThymeleafExample.Thymeleaf.Repository.UserRepository;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.*;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

@Controller
public class UserController {

    @Autowired
    private UserRepository userRepository;

    @GetMapping("/register")
    public String registrationForm(Model model) {
        model.addAttribute("user", new User());
        return "registration";
    }

    @PostMapping("/register")
    public String registrationSubmit( @ModelAttribute("user")  User user) {
      boolean cutternt=  userRepository.existsByUsernameOrEmail(user.getUsername(),user.getEmail());
        System.out.println("Current  "+cutternt);
        if(cutternt){
            return "redirect:/register?error=true";
        }else{
            userRepository.save(user);
            return "redirect:/login";

        }



    }

    @GetMapping("/login")
    public String loginForm() {
        return "login";
    }
    @PostMapping("/login")
    public String loginSubmit(@RequestParam  String username, @RequestParam  String password , HttpSession session)
    {
        User user = userRepository.findByUsername(username);
        if (user != null && user.getPassword().equals(password)) {
            System.out.println("The user name+"+ username);
            session.setAttribute("user",user);
            return "redirect:/dashboard";
        } else {
            return "redirect:/login?error=true";
        }
    }




    @GetMapping("/dashboard")
    public String dashboard( Model model, HttpSession session ){

        User user1 = (User) session.getAttribute("user");
      User user=  userRepository.findByUsername(user1.getUsername());

        model.addAttribute("user",user);
        return "dashboard";

    }
    @GetMapping("/home")
    public String home() {
        return "home";
    }


}

