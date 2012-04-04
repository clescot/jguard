package net.sf.jguard.core;

import com.google.inject.BindingAnnotation;

import java.lang.annotation.Retention;
import java.lang.annotation.Target;

import static java.lang.annotation.ElementType.*;
import static java.lang.annotation.RetentionPolicy.RUNTIME;

@BindingAnnotation
@Target({FIELD, PARAMETER, METHOD})
@Retention(RUNTIME)

/**
 * permits to identify the string which owns the unique name of the application.
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 */
public @interface AuthorizationXmlFileLocation {
}
