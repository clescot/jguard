package net.sf.jguard.core.authorization.permissions;

import org.apache.commons.lang.StringEscapeUtils;

import java.io.Serializable;
import java.util.*;

/**
 * Used to resolve URLPermission with parameters
 *
 * @author <a href="mailto:vberetti@users.sourceforge.net">Vincent Beretti</a>
 */
public class URLParameterCollection implements Serializable {

    private static final long serialVersionUID = -6533685803360570616L;

    private Set parameters;

    private boolean impliesMissingKeyParameters;

    public URLParameterCollection() {
        parameters = new HashSet();
        impliesMissingKeyParameters = false;
    }

    void add(URLParameter parameter) {
        parameters.add(parameter);
    }

    public boolean implies(URLParameter impliedParameter) {
        for (Object parameter1 : parameters) {
            URLParameter parameter = (URLParameter) parameter1;
            if (parameter.impliesKey(impliedParameter.getKey())) {
                return parameter.impliesValues(impliedParameter.getValue());
            }
        }
        // impliedParameter has not been implied for key
        return impliesMissingKeyParameters;
    }

    public boolean getImpliesMissingKeyParameters() {
        return impliesMissingKeyParameters;
    }

    void setImpliesMissingKeyParameters(
            boolean impliesMissingKeyParameters) {
        this.impliesMissingKeyParameters = impliesMissingKeyParameters;
    }

    public boolean isEmpty() {
        return parameters.isEmpty();
    }

    /**
     * from an URI and a Permission associated
     *
     * @param strParams
     * @return
     */
    static URLParameterCollection getURLParameters(String strParams) {

        URLParameterCollection parametersCollection = new URLParameterCollection();
        strParams = StringEscapeUtils.unescapeHtml(strParams);
        if (strParams != null && !"".equals(strParams)) {
            List tokens = Arrays.asList(strParams.split("&"));
            for (Object token1 : tokens) {
                String token = (String) token1;
                String[] parts = token.split("=");
                if (parts.length == 2) {
                    URLParameter param = new URLParameter();
                    param.setKey(buildRegexpFromString(parts[0]));
                    String[] values = parts[1].split(";");
                    for (int i = 0; i < values.length; i++) {
                        values[i] = buildRegexpFromString(values[i]);
                    }
                    param.setValue(values);
                    parametersCollection.add(param);
                } else if (parts.length == 1 && "*".equals(parts[0])) {
                    parametersCollection.setImpliesMissingKeyParameters(true);
                }
            }

        }
        return parametersCollection;
    }

    /**
     * convenient method to escape regexp special characters, and only use the '*' characters for building the regexp Pattern.
     *
     * @param regexp
     * @return escaped regexp candidate
     */
    public static String buildRegexpFromString(String regexp) {

        // replace '\' by '\\'
        regexp = regexp.replaceAll("\\\\", "\\\\\\\\");
        // replace '**' by '\*\*'
        regexp = regexp.replaceAll("\\*\\*", "\\\\*\\\\*");
        // replace '?' by '\\?'
        regexp = regexp.replaceAll("\\?", "\\\\\\\\?");
        // replace '+' by '\\+'
        regexp = regexp.replaceAll("\\+", "\\\\\\\\+");
        // replace '{' by '\\{'
//		regexp = regexp.replaceAll("\\{", "\\\\\\\\{");
        // replace '}' by '\\}'
//		regexp = regexp.replaceAll("\\}", "\\\\\\\\}");
        // replace '[' by '\\['
        regexp = regexp.replaceAll("\\[", "\\\\\\\\[");
        // replace ']' by '\\]'
        regexp = regexp.replaceAll("\\[", "\\\\\\\\]");
        // replace '^' by '\\^'
        regexp = regexp.replaceAll("\\^", "\\\\\\\\^");
        // replace '$' by '\\$'
//		regexp = regexp.replaceAll("\\$", "\\\\\\\\$");

        // replace '&' by '\\&'
        regexp = regexp.replaceAll("\\&", "\\\\\\\\&");

        // replace '*' by '\.*'
        regexp = regexp.replaceAll("\\*", "\\.\\*");
        return regexp;
    }


    public int size() {
        return parameters.size();
    }

    public Collection getParameters() {
        return parameters;
    }

    public String toString() {
        Iterator itParameters = parameters.iterator();
        int count = 0;
        StringBuffer sb = new StringBuffer();
        while (itParameters.hasNext()) {
            URLParameter param = (URLParameter) itParameters.next();
            count++;
            sb.append(" param").append(count).append('=');
            sb.append(param.toString());
            sb.append("\n");
        }
        return sb.toString();
    }
}
