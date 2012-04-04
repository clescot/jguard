package net.sf.jguard.core.authorization;

/**
 * define scope of Authorization.
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 */
public enum AuthorizationScope {
    LOCAL("local"),
    JVM("jvm");


    private String label;
    AuthorizationScope(String label) {
        this.label = label;
    }

    public String getLabel() {
      return this.label;
   }
}
