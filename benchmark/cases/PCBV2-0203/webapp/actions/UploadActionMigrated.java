// PatchClosure-Bench migrated file-upload action (profile v2=6.4.0) -- the S2-067 REMEDIATION.
//
// Struts 6.4.0 deprecated FileUploadInterceptor and introduced ActionFileUploadInterceptor +
// UploadedFilesAware: uploaded files are delivered through withUploadedFiles(List<UploadedFile>)
// with a framework-controlled name (getOriginalName()), and the file name is NO LONGER an
// OGNL-settable request parameter. This action therefore derives the save name ONLY from the
// UploadedFile the framework hands it -- an attacker `top.UploadFileName` (or any case variant of
// the filename param) can no longer steer the destination path. Same webapp, same save-to-uploads
// logic; only the upload mechanism is the migrated one. NO struts code is modified.
package pcb;

import com.opensymphony.xwork2.ActionSupport;
import org.apache.struts2.ServletActionContext;
import org.apache.struts2.action.UploadedFilesAware;
import org.apache.struts2.dispatcher.multipart.UploadedFile;

import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.util.List;

public class UploadAction extends ActionSupport implements UploadedFilesAware {

    private transient UploadedFile uploaded;
    private String originalName;

    @Override
    public void withUploadedFiles(List<UploadedFile> files) {
        if (files != null && !files.isEmpty()) {
            this.uploaded = files.get(0);
            this.originalName = uploaded.getOriginalName();
        }
    }

    public String execute() throws Exception {
        HttpServletResponse resp = ServletActionContext.getResponse();
        resp.setContentType("text/plain");
        PrintWriter w = resp.getWriter();
        if (uploaded == null) { w.println("no-file"); return NONE; }

        String base = ServletActionContext.getServletContext().getRealPath("/uploads");
        new File(base).mkdirs();
        // Name comes ONLY from the framework-provided UploadedFile, not an OGNL request param:
        File dest = new File(base, originalName);
        Object content = uploaded.getContent();
        InputStream in;
        if (content instanceof File) in = new FileInputStream((File) content);
        else if (content instanceof InputStream) in = (InputStream) content;
        else { w.println("no-content"); return NONE; }
        try (OutputStream out = new FileOutputStream(dest)) {
            byte[] b = new byte[8192];
            int n;
            while ((n = in.read(b)) > 0) out.write(b, 0, n);
        } finally {
            in.close();
        }
        w.println("saved=" + dest.getCanonicalPath());
        return NONE;
    }
}
