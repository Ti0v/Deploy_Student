package com.ThymeleafExample.Thymeleaf.Security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfing {
    @Bean
    public PasswordEncoder passwordEncoder(){
        return  new BCryptPasswordEncoder();
    }
    @Bean
    public UserDetailsService userDetailsService(){
        UserDetails mazen = User.builder()
                .username("Mazen")
                .password(passwordEncoder()
                        .encode("Na1234567..")).roles("ADMIN")
                .build();
        return new InMemoryUserDetailsManager(mazen);
    }
//    @Bean
//     public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
//       httpSecurity
//               .authorizeHttpRequests((authorize)->{
//                   authorize.anyRequest().authenticated()
//                           .requestMatchers("/","/students").permitAll();
//               }).formLogin(Customizer.withDefaults());
//        return httpSecurity.build();
//    }
    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http.csrf().disable()
                .authorizeHttpRequests((authorize) -> {
                    authorize.requestMatchers("/students","/").permitAll()
                            .requestMatchers("/**").hasRole("ADMIN");

                }).formLogin(Customizer.withDefaults());
        return http.build();
    }

}
