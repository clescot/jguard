/*
 * Created by IntelliJ IDEA.
 * User: charles
 * Date: 8 avr. 2010
 * Time: 23:38:30
 */
package net.sf.jguard.core.authentication;

import com.google.inject.BindingAnnotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.TYPE, ElementType.FIELD, ElementType.PARAMETER})
@BindingAnnotation
public @interface Guest {
}
