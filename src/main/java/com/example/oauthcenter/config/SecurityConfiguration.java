package com.example.oauthcenter.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.*;
import org.springframework.security.crypto.scrypt.SCryptPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.HashMap;
import java.util.Map;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter{

    @Autowired
    MyUserDetailService myUserDetailService;

//    @Bean
//    public  PasswordEncoder createDelegatingPasswordEncoder() {
//        //???????????????Bean?????? PasswordEncoder????????????????????? PasswordEncoderFactories.createDelegatingPasswordEncoder() ????????????????????? ???????????????
//        String encodingId = "bcrypttest";
//        Map<String, PasswordEncoder> encoders = new HashMap();
//        encoders.put(encodingId, new BCryptPasswordEncoder());
//        encoders.put("noop", NoOpPasswordEncoder.getInstance());
//        return new DelegatingPasswordEncoder(encodingId, encoders);
//    }

//    @Bean
//    public  static PasswordEncoder passwordEncoder( ){
//        //???????????????????????????{id}password ??????????????????????????????????????? DelegatingPasswordEncoder ??????????????????????????? NoOpPasswordEncoder??????????????????????????? bcrypt
//        DelegatingPasswordEncoder delegatingPasswordEncoder =
//                (DelegatingPasswordEncoder) PasswordEncoderFactories.createDelegatingPasswordEncoder();
//        //??????defaultPasswordEncoderForMatches???NoOpPasswordEncoder
//        delegatingPasswordEncoder.setDefaultPasswordEncoderForMatches(NoOpPasswordEncoder.getInstance());
//        return  delegatingPasswordEncoder;
//    }


    @Autowired
    public void globalUserDetails(AuthenticationManagerBuilder auth) throws Exception {
        //??????????????????????????????
        //???inMemoryAuthentication()????????????".passwordEncoder(new BCryptPasswordEncoder())",?????????????????????BCrypt??????????????????????????????????????????
        //???????????????roler?????????????????????ROLLER_??????
//        auth.inMemoryAuthentication().passwordEncoder(new BCryptPasswordEncoder()).withUser("user")
//                .password(new BCryptPasswordEncoder().encode("user")).roles("USER");
        //SpringSecurity5 ??????  PasswordEncoderFactories.createDelegatingPasswordEncoder(); ?????????????????????
//        auth.inMemoryAuthentication().withUser("user")
//                .password("{bcrypttest}$2a$10$szxj4uW7MhxVlgLsCyE/KuH8WEIk8Dr67u9iIPTW9MTwc90V7UMhu").roles("USER").and()
//                .withUser("test").password("12345").roles("TEST");
        //???????????????????????????
        //??????userDetailsService????????????,?????????????????????????????? ?????? ??????
        auth.userDetailsService(myUserDetailService).passwordEncoder(NoOpPasswordEncoder.getInstance());
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.formLogin() //????????????????????????permit All
                .and()
                .authorizeRequests().antMatchers("/auth/**","/","/home").permitAll() //??????????????????????????????
                .and()
                .authorizeRequests().anyRequest().authenticated() //??????????????????????????????????????????
                .and()
                .csrf() //??????CSRF??????????????????????????????
                .requireCsrfProtectionMatcher(new AntPathRequestMatcher("/oauth/authorize")).disable();
    }

    @Override
    @Bean
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    public static void main(String[] args) {
        String pd = "123456";
        System.out.println(new BCryptPasswordEncoder().encode(pd));
        System.out.println(NoOpPasswordEncoder.getInstance().encode(pd));
        PasswordEncoder passwordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
        System.out.println(passwordEncoder.encode(pd));
    }
}