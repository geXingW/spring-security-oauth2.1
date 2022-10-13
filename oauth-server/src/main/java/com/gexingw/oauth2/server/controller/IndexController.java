package com.gexingw.oauth2.server.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.client.RestTemplate;

/**
 * Created by IntelliJ IDEA.
 *
 * @author: GeXingW
 * @date: 2022/10/12
 * @time: 21:22
 */
@RequestMapping
@Controller
public class IndexController {

    @GetMapping("authorized")
    public String authorized(@RequestParam String code){
        return "authorized";
    }

}
