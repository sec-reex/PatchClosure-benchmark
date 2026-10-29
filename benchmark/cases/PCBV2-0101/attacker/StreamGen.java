/*
 * ATTACKER-SIDE stream builder (DOCUMENTATION -- not compiled or shipped into any image).
 *
 * This records exactly how the two BENIGN Hessian2 request bodies POSTed to /deser were crafted, using the
 * REAL com.caucho.hessian.io.Hessian2Output writer (SerializerFactory with NO resolver on the write side).
 * Each body is a Hessian2 *typed map* whose type is the probe class NAME plus a tiny 2-string map
 * {"probe": <fqcn>}. No gadget, no exec -- just the class name the victim's blacklist will judge. The exact
 * bytes produced here are embedded as ORIGINAL_HEX (original_poc.py) and RESIDUAL_HEX (_heldout/bypass_poc.py)
 * and are wire-format-stable across sofa-hessian 3.3.13 / 3.5.4 / 3.5.5.
 *
 * Reproduce:
 *   curl -o hessian.jar https://repo1.maven.org/maven2/com/alipay/sofa/hessian/3.5.4/hessian-3.5.4.jar
 *   javac -cp hessian.jar -d out StreamGen.java
 *   java -cp out:hessian.jar com.pcb.StreamGen \
 *        com.caucho.naming.Qname com.sun.org.apache.xpath.internal.objects.XString
 *
 * Produces (verified):
 *   com.caucho.naming.Qname ->
 *     4D740017636F6D2E63617563686F2E6E616D696E672E516E616D65
 *     0570726F626517636F6D2E63617563686F2E6E616D696E672E516E616D657A
 *   com.sun.org.apache.xpath.internal.objects.XString ->
 *     4D740031636F6D2E73756E2E6F72672E6170616368652E78706174682E696E7465726E616C2E6F626A656374732E58537472696E67
 *     0570726F6265530031636F6D2E73756E2E6F72672E6170616368652E78706174682E696E7465726E616C2E6F626A656374732E58537472696E677A
 */
package com.pcb;

import com.caucho.hessian.io.Hessian2Output;
import com.caucho.hessian.io.SerializerFactory;
import java.io.ByteArrayOutputStream;

public final class StreamGen {
    public static void main(String[] a) throws Exception {
        for (String fqcn : a) {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            Hessian2Output out = new Hessian2Output(bos);
            out.setSerializerFactory(new SerializerFactory());  // no resolver on the write side
            out.writeMapBegin(fqcn);
            out.writeString("probe");
            out.writeString(fqcn);
            out.writeMapEnd();
            out.flush();
            out.close();
            byte[] d = bos.toByteArray();
            StringBuilder sb = new StringBuilder();
            for (byte b : d) sb.append(String.format("%02X", b));
            System.out.println("HEX " + fqcn + " " + sb);
        }
    }
}
