package lab;

import java.util.List;
import java.util.Map;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@SpringBootApplication
@RestController
public class App {
    public static void main(String[] args) {
        SpringApplication.run(App.class, args);
    }

    // There is no mapping for "/": the lab wants the Whitelabel error page there.
    @GetMapping("/api/grades")
    public List<Map<String, Object>> grades() {
        return List.of(Map.of("course", "Sieci komputerowe", "grade", 4.5), Map.of("course", "Bazy danych", "grade", 5.0));
    }
}
