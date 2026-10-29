/**
 * Server-side side-channel for the STATIC-INITIALIZER flag (the CVE-2026-42778 residual channel).
 *
 * When a non-allowlisted class is RESOLVED by the MINA decoder's readClassDescriptor()
 * (Class.forName(name, initialize=true, cl)) its static initializer runs BEFORE resolveClass()
 * rejects it -- so no object is ever delivered to the IoHandler (messageReceived never fires with it).
 * The static initializer therefore cannot use the reconstructed instance to surface the flag; instead
 * PcbCanary's static initializer writes the read canary token here, and the server's exceptionCaught()
 * (fired when the allowlist rejects the class) reads it back and echoes it over the SAME TCP connection.
 *
 * The server resets this to "" on every new connection (sessionCreated), so a stale value from a prior
 * probe can never leak into an unrelated one. Populated only server-side, only from the planted
 * /canary/flag.txt; never travels on the wire.
 */
public final class Beacon {
    public static volatile String staticInitFlag = "";
    private Beacon() {}
}
