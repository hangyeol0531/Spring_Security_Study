package com.security.jwt.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class RestApiController {


    @GetMapping("home")
    private String home(){
        return "<h1>home</h1>";
    }
}
