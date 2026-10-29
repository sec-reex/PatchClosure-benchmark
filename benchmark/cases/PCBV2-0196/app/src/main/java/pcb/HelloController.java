package pcb;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;

/**
 * Minimal controller that binds a Greeting POJO from request parameters.
 * Spring's data binding introspects all reachable properties of the command
 * object, including Object.getClass() descendants -- the surface exploited
 * by CVE-2010-1622 and CVE-2022-22965.
 */
@Controller
public class HelloController {

    @RequestMapping("/hello")
    public String hello(Greeting greeting, Model model) {
        model.addAttribute("greeting", greeting);
        return "hello";
    }
}
