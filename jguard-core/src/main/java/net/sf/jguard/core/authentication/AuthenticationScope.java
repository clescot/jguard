package net.sf.jguard.core.authentication;

/**
 * define scope of authentication.
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Gay</a>
 */
public enum AuthenticationScope {
    LOCAL("local"),
    JVM("jvm");


    private String label;
    AuthenticationScope(String label) {
        this.label = label;
    }

    public String getLabel() {
      return this.label;
   }
}
