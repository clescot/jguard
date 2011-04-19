package net.sf.jguard.jee.authentication.http;


public enum AuthenticationSchemes {
   BASIC_AUTH("BASIC"),
   CLIENT_CERT_AUTH("CLIENT-CERT"),
   DIGEST_AUTH("DIGEST"),
   FORM_AUTH("FORM");



    protected String label;

   AuthenticationSchemes(String label) {
      this.label = label;
   }

   public String getLabel() {
      return this.label;
   }
}
