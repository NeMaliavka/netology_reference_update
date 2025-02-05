from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from backend.models import User, Shop, Category, Product, ProductInfo, Parameter, ProductParameter, Order, OrderItem, Contact, ConfirmEmailToken

@admin.register(User)
class CustomUserAdmin(UserAdmin):
    """
    Панель управления пользователями
    """
    model = User

    fieldsets = (
        (None, {'fields': ('email', 'password', 'type')}),  # Основные поля
        ('Личная информация', {'fields': ('first_name', 'last_name', 'company', 'position')}),  # Персональные данные
        ('Права доступа', {
            'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions'),
        }),
        ('Важные даты', {'fields': ('last_login', 'date_joined')}),  # Даты
    )
    list_display = ('email', 'first_name', 'last_name', 'is_staff')  # Поля для отображения в списке


@admin.register(Shop)
class ShopAdmin(admin.ModelAdmin):
    """
    Панель управления магазинами
    """
    list_display = ('name', 'user', 'state')  # Поля для отображения в списке


@admin.register(Category)
class CategoryAdmin(admin.ModelAdmin):
    """
    Панель управления категориями
    """
    list_display = ('name',)  # Поля для отображения в списке


@admin.register(Product)
class ProductAdmin(admin.ModelAdmin):
    """
    Панель управления продуктами
    """
    list_display = ('name', 'category')  # Поля для отображения в списке


@admin.register(ProductInfo)
class ProductInfoAdmin(admin.ModelAdmin):
    """
    Панель управления информацией о продуктах
    """
    list_display = ('model', 'product', 'shop', 'quantity', 'price')  # Поля для отображения в списке


@admin.register(Parameter)
class ParameterAdmin(admin.ModelAdmin):
    """
    Панель управления параметрами
    """
    list_display = ('name',)  # Поля для отображения в списке


@admin.register(ProductParameter)
class ProductParameterAdmin(admin.ModelAdmin):
    """
    Панель управления параметрами продукта
    """
    list_display = ('product_info', 'parameter', 'value')  # Поля для отображения в списке


@admin.register(Order)
class OrderAdmin(admin.ModelAdmin):
    """
    Панель управления заказами
    """
    list_display = ('user', 'dt', 'state')  # Поля для отображения в списке


@admin.register(OrderItem)
class OrderItemAdmin(admin.ModelAdmin):
    """
    Панель управления заказанными позициями
    """
    list_display = ('order', 'product_info', 'quantity')  # Поля для отображения в списке


@admin.register(Contact)
class ContactAdmin(admin.ModelAdmin):
    """
    Панель управления контактами пользователей
    """
    list_display = ('user', 'city', 'street', 'phone')  # Поля для отображения в списке


@admin.register(ConfirmEmailToken)
class ConfirmEmailTokenAdmin(admin.ModelAdmin):
    """
    Панель управления токенами подтверждения Email
    """
    list_display = ('user', 'key', 'created_at')  # Поля для отображения в списке
