package com.example.demo;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;

import java.util.ArrayList;
import java.util.List;

@RestController
public class bookController {
    @GetMapping("/books")
    public ModelAndView books(){
        List<Book> books = new ArrayList<>();
        Book b1 = new Book();
        b1.setId(1);
        b1.setAuthor("wang");
        b1.setName("三字经");
        Book b2 = new Book();
        b2.setId(2);
        b2.setAuthor("sun");
        b2.setName("java");
        books.add(b1);
        books.add(b2);
        //ModelAndView指定数据模型+指定视图名；
        ModelAndView mv = new ModelAndView();
        mv.addObject("books",books);//指定数据模型
        //设置mv的名为books，与GetMapping相对应
        mv.setViewName("books");//指定视图名
        return mv;
    }
}
