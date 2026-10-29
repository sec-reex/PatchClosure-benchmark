// PatchClosure-Bench legacy file-upload action (profiles v0=6.3.0, v1=6.3.0.2).
//
// The classic Struts 2 single-file-upload convention driven by the LEGACY FileUploadInterceptor:
// the interceptor maps the multipart file to `upload` and its name to `uploadFileName` (= inputName
// + "FileName"), and the ParametersInterceptor OGNL-binds those onto this action. execute() saves
// the file under getRealPath("/uploads") using the (attacker-influenceable) uploadFileName -- the
// path-traversal SINK. NO struts code is modified; this is ordinary application code exactly as the
// Struts docs/showcase illustrate the legacy mechanism.
//
// BENIGN CANARY: the uploaded body is a tiny JSP that only echoes System.getenv("PCB_FLAG") (the
// per-run canary token). No webshell, no command execution, no persistence beyond the test file.
package pcb;

import com.opensymphony.xwork2.ActionSupport;
import org.apache.struts2.ServletActionContext;

import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintWriter;

public class UploadAction extends ActionSupport {

    private File upload;
    private String uploadFileName;
    private String uploadContentType;

    public void setUpload(File upload) { this.upload = upload; }
    public File getUpload() { return upload; }

    public void setUploadFileName(String uploadFileName) { this.uploadFileName = uploadFileName; }
    public String getUploadFileName() { return uploadFileName; }

    public void setUploadContentType(String uploadContentType) { this.uploadContentType = uploadContentType; }
    public String getUploadContentType() { return uploadContentType; }

    public String execute() throws Exception {
        HttpServletResponse resp = ServletActionContext.getResponse();
        resp.setContentType("text/plain");
        PrintWriter w = resp.getWriter();
        if (upload == null) { w.println("no-file"); return NONE; }

        String base = ServletActionContext.getServletContext().getRealPath("/uploads");
        new File(base).mkdirs();
        // uploadFileName is attacker-influenceable via the multipart param binding (the SINK):
        File dest = new File(base, uploadFileName);
        try (InputStream in = new FileInputStream(upload);
             OutputStream out = new FileOutputStream(dest)) {
            byte[] b = new byte[8192];
            int n;
            while ((n = in.read(b)) > 0) out.write(b, 0, n);
        }
        w.println("saved=" + dest.getCanonicalPath());
        return NONE;
    }
}
