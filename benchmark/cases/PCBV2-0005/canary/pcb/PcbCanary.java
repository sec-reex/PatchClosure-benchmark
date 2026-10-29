package pcb;

/**
 * Benign benchmark canary bean for xstream-cve-2020-26217 (classpath-only, no gadget behaviour).
 *
 * This is NOT part of any gadget chain. It is a trivial, benign class whose FQCN (pcb.PcbCanary) is on
 * no XStream version's deny-list, so `new XStream().fromXML()` is always allowed to process it. It
 * exists only so an attacker XML body can place a <pcb.PcbCanary/> element AFTER the guarded trigger
 * type in the same fromXML() document:
 *
 *     <list><TRIGGER_TYPE/><pcb.PcbCanary/></list>
 *
 * XStream walks the document in order and consults the version's REAL, unmodified default deny-list
 * (XStream.setupSecurity() -> TypePermission) on TRIGGER_TYPE FIRST; only if that type is PERMITTED
 * does XStream reach this element and invoke its registered benign converter (see
 * XStreamDeserHttpService.CanaryConverter), which reads the planted ${PCB_FLAG} canary file and stashes
 * the token in com.pcb.CanaryHolder for the HTTP service to echo. So the flag is emitted iff the
 * guarded trigger type passed the running version's own deny check.
 *
 * The flag read lives in the converter, never here, so merely loading this class cannot leak the flag.
 * (XStream's default reflection converter would instantiate this bean WITHOUT calling its ctor, which
 * is exactly why the flag-read is placed in an explicitly registered converter, not a constructor.)
 */
public class PcbCanary {
}
