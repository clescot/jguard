package net.sf.jguard.core.authorization;

import net.sf.jguard.core.authorization.permissions.Permission;
import org.junit.Test;

import javax.sound.sampled.AudioPermission;
import java.security.AllPermission;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertThat;

public class PermissionTest {


    public static final String PLAY_AUDIO_PERMISSION_ACTION = "play";
    public static final String DUMMY_PERMISSION_NAME = "toto";
    public static final String DUMMY_PERMISSION_ACTIONS = "weirdActions";
    public static final String EMPTY = "";
    public static final String ALL_PERMISSIONS_PERMISSION_NAME = "<all permissions>";
    private static final String ALL_PERMISSIONS_PERMISSION_ACTIONS = "<all actions>";

    @Test(expected = IllegalArgumentException.class)
    public void testGetPermission_with_a_class_which_is_not_a_subclass_of_java_security_Permission() throws ClassNotFoundException {
        Permission.getPermission(String.class, DUMMY_PERMISSION_NAME, DUMMY_PERMISSION_ACTIONS);
    }

    @Test
    public void test_regular_permission_class_subclass_of_basic_permission() throws Exception {

        //given
        //when
        java.security.Permission playPermission = Permission.getPermission(AudioPermission.class, PLAY_AUDIO_PERMISSION_ACTION, null);
        //then
        assertThat(playPermission, is(not(nullValue())));
        assertThat(playPermission.getName(), is(PLAY_AUDIO_PERMISSION_ACTION));
        assertThat(playPermission.getActions(), is(EMPTY));
    }

    @Test
    public void test_regular_permission_class_not_subclass_of_basic_permission_with_constructor_with_2_arguments() throws Exception {

        //given
        //when
        java.security.Permission playPermission = Permission.getPermission(AllPermission.class, null, null);
        //then
        assertThat(playPermission, is(not(nullValue())));
        assertThat(playPermission.getName(), is(ALL_PERMISSIONS_PERMISSION_NAME));
        assertThat(playPermission.getActions(), is(ALL_PERMISSIONS_PERMISSION_ACTIONS));
    }





    @Test
    public void test_hashcode_is_constant() throws Exception {
        Permission permission = new Permission(AudioPermission.class,PLAY_AUDIO_PERMISSION_ACTION,EMPTY);
        assertThat(permission.hashCode(),is(permission.hashCode()));
    }

    @Test
    public void test_hashcode_with_different_permissions() throws Exception {
        Permission permission = new Permission(AudioPermission.class,PLAY_AUDIO_PERMISSION_ACTION,EMPTY);
        Permission permission2 = new Permission(AllPermission.class,ALL_PERMISSIONS_PERMISSION_NAME,ALL_PERMISSIONS_PERMISSION_ACTIONS);
        assertThat(permission.hashCode(),is(not(permission2.hashCode())));
    }

    @Test
    public void test_hashcode_with_different_actions_but_same_clazz_and_name() throws Exception {
        Permission permission = new Permission(AudioPermission.class,PLAY_AUDIO_PERMISSION_ACTION,EMPTY);
        Permission permission2 = new Permission(AudioPermission.class,PLAY_AUDIO_PERMISSION_ACTION,ALL_PERMISSIONS_PERMISSION_ACTIONS);
        assertThat(permission.hashCode(),is(not(permission2.hashCode())));
    }


    @Test
    public void test_hashcode_with_differentclazz_but_same_name_and_actions() throws Exception {
        Permission permission = new Permission(AudioPermission.class,PLAY_AUDIO_PERMISSION_ACTION,EMPTY);
        Permission permission2 = new Permission(AllPermission.class,PLAY_AUDIO_PERMISSION_ACTION,PLAY_AUDIO_PERMISSION_ACTION);
        assertThat(permission.hashCode(),is(not(permission2.hashCode())));
    }


    @Test
    public void test_equals_is_constant() throws Exception {
        Permission permission = new Permission(AudioPermission.class,PLAY_AUDIO_PERMISSION_ACTION,EMPTY);
        assertThat(permission.equals(permission),is(true));
    }

    @Test
    public void test_equals_with_different_permissions() throws Exception {
        Permission permission = new Permission(AudioPermission.class,PLAY_AUDIO_PERMISSION_ACTION,EMPTY);
        Permission permission2 = new Permission(AllPermission.class,ALL_PERMISSIONS_PERMISSION_NAME,ALL_PERMISSIONS_PERMISSION_ACTIONS);
        assertThat(permission.equals(permission2),is(false));
    }

    @Test
    public void test_equals_with_different_actions_but_same_clazz_and_name() throws Exception {
        Permission permission = new Permission(AudioPermission.class,PLAY_AUDIO_PERMISSION_ACTION,EMPTY);
        Permission permission2 = new Permission(AudioPermission.class,PLAY_AUDIO_PERMISSION_ACTION,ALL_PERMISSIONS_PERMISSION_ACTIONS);
        assertThat(permission.equals(permission2),is(false));
    }


    @Test
    public void test_equals_with_differentclazz_but_same_name_and_actions() throws Exception {
        Permission permission = new Permission(AudioPermission.class,PLAY_AUDIO_PERMISSION_ACTION,EMPTY);
        Permission permission2 = new Permission(AllPermission.class,PLAY_AUDIO_PERMISSION_ACTION,PLAY_AUDIO_PERMISSION_ACTION);
        assertThat(permission.equals(permission2),is(false));
    }




    @Test(expected = IllegalArgumentException.class)
    public void test_constructor_with_null_values() throws Exception {
        new Permission(null,null,null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void test_constructor_with_clazz_parameter_as_a_null_value() throws Exception {
        new Permission(null,ALL_PERMISSIONS_PERMISSION_NAME,ALL_PERMISSIONS_PERMISSION_ACTIONS);
    }

    @Test(expected = IllegalArgumentException.class)
    public void test_constructor_with_name_parameter_as_a_null_value() throws Exception {
        new Permission(AllPermission.class,null,ALL_PERMISSIONS_PERMISSION_ACTIONS);
    }

    @Test
    public void test_constructor_with_actions_parameter_as_a_null_value() throws Exception {
        new Permission(AllPermission.class,ALL_PERMISSIONS_PERMISSION_NAME,null);
    }


    @Test
    public void test_to_java_permission() throws Exception {
        Permission<AllPermission> permission = new Permission(AllPermission.class, ALL_PERMISSIONS_PERMISSION_NAME, ALL_PERMISSIONS_PERMISSION_ACTIONS);
        AllPermission allPermission = permission.toJavaPermission();
        assertThat(allPermission,is(not(nullValue())));
    }
}
