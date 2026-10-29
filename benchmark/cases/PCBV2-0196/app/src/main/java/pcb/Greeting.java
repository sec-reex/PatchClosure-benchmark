package pcb;

/**
 * Minimal POJO bound from HTTP request parameters by Spring MVC data binding.
 * The exploit does NOT target this class's own properties; it abuses the
 * inherited Object.getClass() -> Class.getModule() -> ... chain that Spring's
 * BeanWrapperImpl traverses for nested property paths.
 */
public class Greeting {
    private String name;

    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
}
