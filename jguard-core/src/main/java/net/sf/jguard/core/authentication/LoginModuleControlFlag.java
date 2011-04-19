package net.sf.jguard.core.authentication;

/**
 * enum listing flag from {@link javax.security.auth.login.AppConfigurationEntry.LoginModuleControlFlag}.
 */
public enum LoginModuleControlFlag {
    REQUIRED("REQUIRED"),
    OPTIONAL("OPTIONAL"),
    REQUISITE("REQUISITE"),
    SUFFICIENT("SUFFICIENT");


    private String label;
    LoginModuleControlFlag(String label) {
        this.label = label;
    }

    public String getLabel() {
      return this.label;
   }
}
