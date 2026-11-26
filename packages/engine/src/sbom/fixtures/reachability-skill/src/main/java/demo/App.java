package demo;
import org.apache.commons.text.StringSubstitutor;
import java.util.Map;

public class App {
  public static String render(String template, Map<String, String> values) {
    return new StringSubstitutor(values).replace(template);
  }
}
