package com.example.demo;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

//controller不一定要在controller包里才可启动
//函数名与接口名并不必须相同也可以启动
@RestController
public class HelloController {
    @GetMapping("/hello")
    public String hello1() {
        return "hello world";
    }
}
