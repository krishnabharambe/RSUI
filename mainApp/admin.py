from mainApp.forms import UserAdminChangeForm, UserAdminCreationForm
from django.contrib import admin

# Register your models here.
from .models import M_Services, M_SubServices, PhoneOTP, Profile, User, RServices
# Register your models here.
from import_export import resources
from import_export.admin import ImportExportModelAdmin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin


@admin.register(M_Services)
class M_ServicesAdmin(ImportExportModelAdmin):
    pass


@admin.register(M_SubServices)
class M_SubServicesAdmin(ImportExportModelAdmin):
    pass


@admin.register(PhoneOTP)
class PhoneOTPAdmin(ImportExportModelAdmin):
    pass


@admin.register(RServices)
class RServicesAdmin(ImportExportModelAdmin):
    pass


class ProfileInline(admin.StackedInline):
    model = Profile
    can_delete = False
    verbose_name_plural = 'Profile'
    fk_name = 'user'


class UserAdmin(BaseUserAdmin):
    # The forms to add and change user instances
    form = UserAdminChangeForm
    add_form = UserAdminCreationForm

    # The fields to be used in displaying the User model.
    # These override the definitions on the base UserAdmin
    # that reference specific fields on auth.User.
    list_display = ('name', 'phone',  'standard',  'admin',)
    list_filter = ('standard', 'staff', 'active', 'admin', )
    fieldsets = (
        (None, {'fields': ('phone', 'password')}),
        ('Personal info', {'fields': ('name', 'standard', 'score',)}),
        ('Permissions', {'fields': ('admin', 'staff', 'active')}),
    )
    # add_fieldsets is not a standard ModelAdmin attribute. UserAdmin
    # overrides get_fieldsets to use this attribute when creating a user.
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('phone', 'password1', 'password2')}
         ),
    )

    search_fields = ('phone', 'name')
    ordering = ('phone', 'name')
    filter_horizontal = ()

    inlines = (ProfileInline, )

    def get_inline_instances(self, request, obj=None):
        if not obj:
            return list()
        return super(UserAdmin, self).get_inline_instances(request, obj)


admin.site.register(User, UserAdmin)
