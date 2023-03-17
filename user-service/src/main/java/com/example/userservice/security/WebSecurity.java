package com.example.userservice.security;


import com.example.userservice.service.UserService;
import lombok.AllArgsConstructor;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.expression.WebExpressionAuthorizationManager;

@Configuration(enforceUniqueMethods = false)
@EnableWebSecurity
@AllArgsConstructor
public class WebSecurity{

    private UserService userService;

    private Environment env;
    private AuthenticationConfiguration authenticationConfiguration;

    @Autowired
    public void setUserService(@Lazy UserService userService) {
        this.userService = userService;
    }


    @Autowired
    public void setEnvironment(@Lazy Environment env) {
        this.env = env;
    }

    @Autowired
    public void setAuthenticationConfiguration(@Lazy AuthenticationConfiguration authenticationConfiguration) {
        this.authenticationConfiguration = authenticationConfiguration;
    }

    @Bean
    public BCryptPasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager() throws Exception{
        return this.authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception{
        http.csrf().disable();
        http.authorizeHttpRequests().requestMatchers("/actuator/**").permitAll();
        http.authorizeHttpRequests()
                .requestMatchers("/**").permitAll()
//                .access(new WebExpressionAuthorizationManager("hasIpAddress('" + "192.168.139.1" + "')"))
                .and()
                .addFilter(getAuthenticationFilter());
        http.headers().frameOptions().disable();
        return http.build();
    }


    private AuthenticationFilter getAuthenticationFilter() throws Exception{
        AuthenticationFilter authenticationFilter =
                new AuthenticationFilter(authenticationManager(), userService, env);
//        authenticationFilter.setAuthenticationManager(authenticationManager());
        return authenticationFilter;
    }

    @Bean
    AuthenticationManager authenticationManager(AuthenticationManagerBuilder builder) throws Exception {
        return builder.userDetailsService(userService).passwordEncoder(passwordEncoder()).and().build();
    }

}
