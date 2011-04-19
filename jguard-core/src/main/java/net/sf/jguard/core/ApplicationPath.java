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
 * permits to identify the string which to the path of the application (mainly in a jee way).
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Gay</a>
 */
public @interface ApplicationPath {
}
