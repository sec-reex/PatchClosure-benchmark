import java.io.FileOutputStream;
import java.io.ObjectOutputStream;

/**
 * Utility to serialize a BenignMarker instance to a file.
 * Usage: java SerializeGadget <output-path>
 */
public class SerializeGadget {
    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.err.println("Usage: java SerializeGadget <output-file>");
            System.exit(1);
        }
        try (FileOutputStream fos = new FileOutputStream(args[0]);
             ObjectOutputStream oos = new ObjectOutputStream(fos)) {
            oos.writeObject(new BenignMarker());
        }
        System.out.println("Serialized BenignMarker to " + args[0]);
    }
}
