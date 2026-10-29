// PatchClosure-Bench tiny harness (NOT part of Spring Framework code).
// Calls the REAL, unmodified UriComponentsBuilder.fromUriString(url).build().getHost()
// -- the exact host-parsing sink guarded by the CVE-2024-22243 fix and bypassed
// by CVE-2024-22259. We only invoke the library API; we do not reimplement it.
// This is the application-side GUARD an app uses before redirecting/fetching a URL:
//   host = UriComponentsBuilder.fromUriString(input).build().getHost();
//   if (allowlist.contains(host)) { navigate(input); }
import org.springframework.web.util.UriComponentsBuilder;

public class Driver {
  public static void main(String[] args) throws Exception {
    String url = args[0];
    String host;
    try {
      host = UriComponentsBuilder.fromUriString(url).build().getHost();
      System.out.println("SPRING_HOST=" + (host == null ? "<null>" : host));
    } catch (Throwable t) {
      String msg = t.getMessage();
      System.out.println("SPRING_HOST=EXC:" + t.getClass().getSimpleName()
          + (msg != null ? ":" + msg.replace("\n", " ") : ""));
    }
  }
}
