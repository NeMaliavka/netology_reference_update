from django.urls import path
from django_rest_passwordreset.views import reset_password_request_token, reset_password_confirm

from backend.views import (
    PartnerUpdate, RegisterAccount, LoginAccount, CategoryView, ShopView, ProductInfoView,
    BasketView, AccountDetails, ContactView, OrderView, PartnerState, PartnerOrders, ConfirmAccount
)

app_name = 'backend'
urlpatterns = [
    path('partner/update', PartnerUpdate.as_view(), name='partner-update'),  # Обновление информации о партнере
    path('partner/state', PartnerState.as_view(), name='partner-state'),      # Получение и изменение состояния партнера
    path('partner/orders', PartnerOrders.as_view(), name='partner-orders'),    # Получение заказов партнера
    path('user/register', RegisterAccount.as_view(), name='user-register'),    # Регистрация пользователя
    path('user/register/confirm', ConfirmAccount.as_view(), name='user-register-confirm'),  # Подтверждение регистрации
    path('user/details', AccountDetails.as_view(), name='user-details'),        # Получение и изменение данных пользователя
    path('user/contact', ContactView.as_view(), name='user-contact'),          # Работа с контактами пользователя
    path('user/login', LoginAccount.as_view(), name='user-login'),              # Авторизация пользователя
    path('user/password_reset', reset_password_request_token, name='password-reset'),  # Запрос сброса пароля
    path('user/password_reset/confirm', reset_password_confirm, name='password-reset-confirm'),  # Подтверждение сброса пароля
    path('categories', CategoryView.as_view(), name='categories'),              # Получение списка категорий
    path('shops', ShopView.as_view(), name='shops'),                            # Получение списка магазинов
    path('products', ProductInfoView.as_view(), name='products'),              # Получение информации о продуктах
    path('basket', BasketView.as_view(), name='basket'),                        # Работа с корзиной
    path('order', OrderView.as_view(), name='order'),                          # Работа с заказами
]
