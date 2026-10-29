import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.OutputStreamWriter;
import java.io.Serializable;

/**
 * Benign deserialization canary for PatchClosure-Bench.
 * When deserialized, writes the PCB_FLAG environment variable to a marker file
 * at /tmp/pcb_marker.txt, which is read by marker.jsp served by Tomcat.
 * This is NOT a real exploit gadget -- it only writes a planted benchmark token
 * to verify that deserialization occurred.
 *
 * Compatible with JDK 8+.
 */
public class BenignMarker implements Serializable {
    private static final long serialVersionUID = 1L;

    private void readObject(ObjectInputStream in)
            throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        String flag = System.getenv("PCB_FLAG");
        if (flag == null) flag = "NO_FLAG_SET";
        File marker = new File("/tmp/pcb_marker.txt");
        try (OutputStreamWriter w = new OutputStreamWriter(
                new FileOutputStream(marker), "UTF-8")) {
            w.write(flag);
        }
    }
}
