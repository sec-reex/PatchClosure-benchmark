package pcb;

import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlValue;

/**
 * Minimal JAXB bean bound to &lt;foo&gt;. Its text content (@XmlValue) captures whatever the RESTEasy
 * JAXB provider's parser expands into the element body -- including any XXE-resolved external entity.
 * The REST resource returns this value, so an XXE-injected file read surfaces in the HTTP response.
 */
@XmlRootElement(name = "foo")
public class Foo {
    @XmlValue
    public String value;
}
