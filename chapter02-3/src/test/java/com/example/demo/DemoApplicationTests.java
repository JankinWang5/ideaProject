package com.example.demo;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;

//两个public
@RunWith(SpringRunner.class)
@SpringBootTest
public class DemoApplicationTests {

//    @Autowired
//    User0 user0;
//
//    @Test
//    public void contextLoads() {
//        System.out.println(user0);
//    }

    @Autowired
    Users users;

    @Test
    public void contextLoads(){
        System.out.println(users);
    }
}
