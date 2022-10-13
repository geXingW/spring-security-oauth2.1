package com.gexingw.auth.resource.controller;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Created by IntelliJ IDEA.
 *
 * @author: GeXingW
 * @date: 2022/10/13
 * @time: 16:46
 */
@RestController
@RequestMapping("messages")
public class MessageController {
    @GetMapping("")
    public String[] getMessages() {
        return new String[] {"Message 1", "Message 2", "Message 3"};
    }

    @GetMapping("/user")
    public String getGreetingString(@AuthenticationPrincipal Jwt jwt) {
        return String.format("Hello, %s!", jwt.getSubject());
    }
}
