<%@ page import="java.io.*" %><%
File f = new File("/tmp/pcb_marker.txt");
if (f.exists()) {
    BufferedReader br = new BufferedReader(new FileReader(f));
    String line = br.readLine();
    br.close();
    if (line != null) out.print(line);
} else {
    out.print("NO_MARKER");
}
%>