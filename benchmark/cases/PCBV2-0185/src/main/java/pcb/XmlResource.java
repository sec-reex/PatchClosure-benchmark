package pcb;

import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;

/**
 * REAL JAX-RS resource. An EXTERNAL HTTP client POSTs an application/xml body to /app/xml; RESTEasy
 * selects the REAL, unmodified JAXB provider (AbstractJAXBProvider -> ExternalEntityUnmarshaller when
 * resteasy.document.expand.entity.references=false) to unmarshal the body into a {@link Foo} bean, and
 * this method returns the bean's text value. Whether an XXE external entity resolves (surfacing the
 * planted /flag content in the returned value) is decided ENTIRELY by the pinned RESTEasy version's
 * own SAX feature configuration. No RESTEasy code is modified.
 */
@Path("/xml")
public class XmlResource {

    @POST
    @Consumes("application/xml")
    @Produces("text/plain")
    public String post(Foo foo) {
        return "parsed=[" + (foo != null && foo.value != null ? foo.value : "") + "]";
    }

    @GET
    @Produces("text/plain")
    public String health() {
        return "ok";
    }
}
