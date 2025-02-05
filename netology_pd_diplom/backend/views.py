from distutils.util import strtobool
from rest_framework.request import Request
from django.contrib.auth import authenticate
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.core.validators import URLValidator
from django.db import IntegrityError
from django.db.models import Q, Sum, F
from django.http import JsonResponse
from requests import get
from rest_framework.authtoken.models import Token
from rest_framework.generics import ListAPIView
from rest_framework.response import Response
from rest_framework.views import APIView
from ujson import loads as load_json
from yaml import load as load_yaml, Loader

from backend.models import Shop, Category, Product, ProductInfo, Parameter, ProductParameter, Order, OrderItem, \
    Contact, ConfirmEmailToken
from backend.serializers import UserSerializer, CategorySerializer, ShopSerializer, ProductInfoSerializer, \
    OrderItemSerializer, OrderSerializer, ContactSerializer, ProductSerializer
from backend.signals import new_user_registered, new_order
from backend.tasks import send_email, do_import  # Импортируем задачи Celery
from rest_framework.permissions import IsAdminUser
from django.http import HttpResponse
import csv, io


class ExportProductsView(APIView):
    """
    Класс для экспорта товаров в CSV
    """

    def get(self, request, *args, **kwargs):
        """
        Экспорт товаров в CSV файл.
        """
        # Создаем HTTP-ответ с заголовками для CSV
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename="products.csv"'

        # Используем StringIO для создания CSV в нужной кодировке
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['ID', 'Name', 'Category', 'Price', 'Quantity'])  # Заголовки колонок

        # Получаем все продукты и записываем их в CSV
        products_info = ProductInfo.objects.select_related('product__category').all()  # Используем ProductInfo
        for product_info in products_info:
            writer.writerow([
                product_info.id,
                product_info.model,  # Используем поле model из ProductInfo
                product_info.product.category.name,  # Доступ к категории через связь
                product_info.price,  # Поле price из ProductInfo
                product_info.quantity  # Поле quantity из ProductInfo
            ])

        # Получаем данные в CSV формате из StringIO
        response.write(output.getvalue())
        output.close()  # Закрываем StringIO

        return response

class ImportProductsView(APIView):
    """
    Класс для импорта продуктов.
    """
    permission_classes = [IsAdminUser]  # Ограничиваем доступ только для администраторов

    def post(self, request, *args, **kwargs):
        """
        Запускает задачу импорта продуктов.

        Args:
            request (Request): Объект запроса Django.

        Returns:
            Response: Ответ, указывающий статус операции.
        """
        url = request.data.get('url')
        if not url:
            return Response({'Status': False, 'Error': 'URL is required'}, status=400)

        # Запускаем задачу импорта
        do_import.delay(url)  # Запускаем асинхронную задачу
        return Response({'Status': True, 'Message': 'Import started'})


class OrderView(APIView):
    """
    Класс для получения и размещения заказов пользователями.
    """

    def get(self, request, *args, **kwargs):
        """
        Получить детали заказов аутентифицированного пользователя.

        Args:
            request (Request): Объект запроса Django.

        Returns:
            Response: Ответ, содержащий детали заказов пользователя.
        """
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Error': 'Authorization required'}, status=403)

        # Получаем все заказы пользователя, исключая те, что в состоянии "корзина"
        orders = Order.objects.filter(user_id=request.user.id).exclude(state='basket').prefetch_related(
            'ordered_items__product_info__product__category',
            'ordered_items__product_info__product_parameters__parameter'
        ).select_related('contact').annotate(
            total_sum=Sum(F('ordered_items__quantity') * F('ordered_items__product_info__price'))
        ).distinct()

        serializer = OrderSerializer(orders, many=True)  # Сериализуем данные заказов
        return Response(serializer.data)  # Возвращаем ответ с данными заказов

    def post(self, request, *args, **kwargs):
        """
        Разместить новый заказ из корзины.

        Args:
            request (Request): Объект запроса Django.

        Returns:
            JsonResponse: Ответ, указывающий статус операции и любые ошибки.
        """
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Error': 'Authorization required'}, status=403)

        if {'id', 'contact'}.issubset(request.data):
            if request.data['id'].isdigit():
                try:
                    # Обновляем состояние заказа
                    is_updated = Order.objects.filter(
                        user_id=request.user.id, id=request.data['id']
                    ).update(contact_id=request.data['contact'], state='new')
                except IntegrityError as error:
                    return JsonResponse({'Status': False, 'Errors': 'Incorrect arguments'})
                else:
                    if is_updated:
                        new_order.send(sender=self.__class__, user_id=request.user.id)  # Отправляем сигнал о новом заказе
                        return JsonResponse({'Status': True})

        return JsonResponse({'Status': False, 'Errors': 'All required arguments are not provided'})


class PartnerOrders(APIView):
    """
    Класс для получения заказов, связанных с аутентифицированным партнером.
    """

    def get(self, request, *args, **kwargs):
        """
        Получить заказы, связанные с аутентифицированным партнером.

        Args:
            request (Request): Объект запроса Django.

        Returns:
            Response: Ответ, содержащий заказы партнера.
        """
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Error': 'Authorization required'}, status=403)

        if request.user.type != 'shop':
            return JsonResponse({'Status': False, 'Error': 'Only for shops'}, status=403)

        # Получаем заказы, связанные с магазином партнера
        orders = Order.objects.filter(
            ordered_items__product_info__shop__user_id=request.user.id
        ).exclude(state='basket').prefetch_related(
            'ordered_items__product_info__product__category',
            'ordered_items__product_info__product_parameters__parameter'
        ).select_related('contact').annotate(
            total_sum=Sum(F('ordered_items__quantity') * F('ordered_items__product_info__price'))
        ).distinct()

        serializer = OrderSerializer(orders, many=True)  # Сериализуем данные заказов
        return Response(serializer.data)  # Возвращаем ответ с данными заказов


class ContactView(APIView):
    """
    Класс для управления контактной информацией.
    """

    def get(self, request, *args, **kwargs):
        """
        Получить контактную информацию аутентифицированного пользователя.

        Args:
            request (Request): Объект запроса Django.

        Returns:
            Response: Ответ, содержащий контактную информацию.
        """
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Error': 'Authorization required'}, status=403)

        contacts = Contact.objects.filter(user_id=request.user.id)
        serializer = ContactSerializer(contacts, many=True)
        return Response(serializer.data)

    def post(self, request, *args, **kwargs):
        """
        Создать новый контакт для аутентифицированного пользователя.

        Args:
            request (Request): Объект запроса Django.

        Returns:
            JsonResponse: Ответ, указывающий статус операции и любые ошибки.
        """
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Error': 'Authorization required'}, status=403)

        # Обработка данных для создания контакта
        request.data['user'] = request.user.id
        serializer = ContactSerializer(data=request.data)

        if serializer.is_valid():
            serializer.save()
            return JsonResponse({'Status': True})
        else:
            return JsonResponse({'Status': False, 'Errors': serializer.errors})


class PartnerUpdate(APIView):
    """
    Класс для обновления информации о партнере, включая импорт данных о продуктах.
    """
    def post(self, request, *args, **kwargs):
        """
        Обновить информацию о ценах партнера.

        Args:
            request (Request): Объект запроса Django.

        Returns:
            JsonResponse: Ответ, указывающий статус операции и любые ошибки.
        """
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Error': 'Authorization required'}, status=403)

        if request.user.type != 'shop':
            return JsonResponse({'Status': False, 'Error': 'Only for shops'}, status=403)

        url = request.data.get('url')
        if url:
            validate_url = URLValidator()
            try:
                validate_url(url)
            except ValidationError as e:
                return JsonResponse({'Status': False, 'Error': str(e)})
            else:
                stream = get(url).content
                data = load_yaml(stream, Loader=Loader)

                shop, _ = Shop.objects.get_or_create(name=data['shop'], user_id=request.user.id)
                for category in data['categories']:
                    category_object, _ = Category.objects.get_or_create(id=category['id'], name=category['name'])
                    category_object.shops.add(shop.id)
                    category_object.save()

                ProductInfo.objects.filter(shop_id=shop.id).delete()
                for item in data['goods']:
                    product, _ = Product.objects.get_or_create(name=item['name'], category_id=item['category'])
                    product_info = ProductInfo.objects.create(product_id=product.id,
                                                              external_id=item['id'],
                                                              model=item['model'],
                                                              price=item['price'],
                                                              price_rrc=item['price_rrc'],
                                                              quantity=item['quantity'],
                                                              shop_id=shop.id)
                    for name, value in item['parameters'].items():
                        parameter_object, _ = Parameter.objects.get_or_create(name=name)
                        ProductParameter.objects.create(product_info_id=product_info.id,
                                                        parameter_id=parameter_object.id,
                                                        value=value)

                return JsonResponse({'Status': True})

        return JsonResponse({'Status': False, 'Errors': 'All required arguments are not provided'})


class PartnerState(APIView):
    """
    Класс для управления состоянием партнера, позволяющий получать и изменять состояние.
    """
    def get(self, request, *args, **kwargs):
        """
        Получить текущее состояние партнера.

        Args:
            request (Request): Объект запроса Django.

        Returns:
            Response: Ответ, содержащий состояние партнера.
        """
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Error': 'Authorization required'}, status=403)

        if request.user.type != 'shop':
            return JsonResponse({'Status': False, 'Error': 'Only for shops'}, status=403)

        shop = request.user.shop
        serializer = ShopSerializer(shop)
        return Response(serializer.data)

    def post(self, request, *args, **kwargs):
        """
        Изменить текущее состояние партнера.

        Args:
            request (Request): Объект запроса Django.

        Returns:
            JsonResponse: Ответ, указывающий статус операции и любые ошибки.
        """
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Error': 'Authorization required'}, status=403)

        if request.user.type != 'shop':
            return JsonResponse({'Status': False, 'Error': 'Only for shops'}, status=403)

        state = request.data.get('state')
        if state:
            try:
                Shop.objects.filter(user_id=request.user.id).update(state=strtobool(state))
                return JsonResponse({'Status': True})
            except ValueError as error:
                return JsonResponse({'Status': False, 'Errors': str(error)})

        return JsonResponse({'Status': False, 'Errors': 'All required arguments are not provided'})


class RegisterAccount(APIView):
    """
    Класс для регистрации пользователей. Обрабатывает данные и создает нового пользователя, проверяя уникальность и сложность пароля.
    """
    def post(self, request, *args, **kwargs):
        """
        Обрабатывает POST запрос и создает нового пользователя.

        Args:
            request (Request): Объект запроса Django.

        Returns:
            JsonResponse: Ответ, указывающий статус операции и любые ошибки.
        """
        # Проверяем обязательные аргументы
        if {'first_name', 'last_name', 'email', 'password', 'company', 'position'}.issubset(request.data):
            # Проверяем пароль на сложность
            try:
                validate_password(request.data['password'])
            except Exception as password_error:
                error_array = [str(item) for item in password_error]
                return JsonResponse({'Status': False, 'Errors': {'password': error_array}})
            else:
                # Проверяем данные для уникальности имени пользователя
                user_serializer = UserSerializer(data=request.data)
                if user_serializer.is_valid():
                    # Сохраняем пользователя
                    user = user_serializer.save()
                    user.set_password(request.data['password'])
                    user.save()
                    return JsonResponse({'Status': True})
                else:
                    return JsonResponse({'Status': False, 'Errors': user_serializer.errors})

        return JsonResponse({'Status': False, 'Errors': 'Не указаны все необходимые аргументы'})


class ConfirmAccount(APIView):
    """
    Класс для подтверждения почтового адреса пользователя. Проверяет токен и активирует пользователя.
    """
    def post(self, request, *args, **kwargs):
        """
        Подтверждает почтовый адрес пользователя.

        Args:
            request (Request): Объект запроса Django.

        Returns:
            JsonResponse: Ответ, указывающий статус операции и любые ошибки.
        """
        # Проверяем обязательные аргументы
        if {'email', 'token'}.issubset(request.data):
            token = ConfirmEmailToken.objects.filter(user__email=request.data['email'],
                                                     key=request.data['token']).first()
            if token:
                token.user.is_active = True
                token.user.save()
                token.delete()
                return JsonResponse({'Status': True})
            else:
                return JsonResponse({'Status': False, 'Errors': 'Неправильно указан токен или email'})

        return JsonResponse({'Status': False, 'Errors': 'Не указаны все необходимые аргументы'})


class AccountDetails(APIView):
    """
    Класс для получения и обновления данных аутентифицированного пользователя.
    """
    def get(self, request: Request, *args, **kwargs):
        """
        Получить данные аутентифицированного пользователя.

        Args:
            request (Request): Объект запроса Django.

        Returns:
            Response: Ответ, содержащий детали аутентифицированного пользователя.
        """
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Error': 'Требуется авторизация'}, status=403)

        serializer = UserSerializer(request.user)
        return Response(serializer.data)

    def post(self, request, *args, **kwargs):
        """
        Обновить детали аккаунта аутентифицированного пользователя.

        Args:
            request (Request): Объект запроса Django.

        Returns:
            JsonResponse: Ответ, указывающий статус операции и любые ошибки.
        """
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Error': 'Требуется авторизация'}, status=403)

        if 'password' in request.data:
            try:
                validate_password(request.data['password'])
            except Exception as password_error:
                error_array = [str(item) for item in password_error]
                return JsonResponse({'Status': False, 'Errors': {'password': error_array}})
            else:
                request.user.set_password(request.data['password'])

        user_serializer = UserSerializer(request.user, data=request.data, partial=True)
        if user_serializer.is_valid():
            user_serializer.save()
            return JsonResponse({'Status': True})
        else:
            return JsonResponse({'Status': False, 'Errors': user_serializer.errors})


class LoginAccount(APIView):
    """
    Класс для авторизации пользователей. Проверяет учетные данные и выдает токен.
    """
    def post(self, request, *args, **kwargs):
        """
        Авторизовать пользователя.

        Args:
            request (Request): Объект запроса Django.

        Returns:
            JsonResponse: Ответ, указывающий статус операции и любые ошибки.
        """
        if {'email', 'password'}.issubset(request.data):
            user = authenticate(request, username=request.data['email'], password=request.data['password'])

            if user is not None and user.is_active:
                token, _ = Token.objects.get_or_create(user=user)
                return JsonResponse({'Status': True, 'Token': token.key})

            return JsonResponse({'Status': False, 'Errors': 'Не удалось авторизовать'})

        return JsonResponse({'Status': False, 'Errors': 'Не указаны все необходимые аргументы'})


class CategoryView(ListAPIView):
    """
    Класс для получения списка категорий.
    """
    queryset = Category.objects.all()
    serializer_class = CategorySerializer


class ShopView(ListAPIView):
    """
    Класс для получения списка магазинов.
    """
    queryset = Shop.objects.filter(state=True)
    serializer_class = ShopSerializer


class ProductInfoView(APIView):
    """
    Класс для получения информации о продуктах с фильтрацией по магазину и категории.
    """
    def get(self, request: Request, *args, **kwargs):
        """
        Получить информацию о продукте на основе указанных фильтров.

        Args:
            request (Request): Объект запроса Django.

        Returns:
            Response: Ответ, содержащий информацию о продукте.
        """
        query = Q(shop__state=True)
        shop_id = request.query_params.get('shop_id')
        category_id = request.query_params.get('category_id')

        if shop_id:
            query &= Q(shop_id=shop_id)

        if category_id:
            query &= Q(product__category_id=category_id)

        queryset = ProductInfo.objects.filter(query).select_related(
            'shop', 'product__category').prefetch_related(
            'product_parameters__parameter').distinct()

        serializer = ProductInfoSerializer(queryset, many=True)
        return Response(serializer.data)


class BasketView(APIView):
    """
    Класс для управления корзиной пользователя. 
    Включает методы для получения, добавления, удаления и обновления товаров в корзине.
    """
    def get(self, request, *args, **kwargs):
        """
        Получить товары в корзине пользователя.

        Args:
            request (Request): Объект запроса Django.

        Returns:
            Response: Ответ, содержащий товары в корзине пользователя.
        """
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Error': 'Требуется авторизация'}, status=403)

        basket = Order.objects.filter(user_id=request.user.id, state='basket').prefetch_related(
            'ordered_items__product_info__product__category',
            'ordered_items__product_info__product_parameters__parameter').annotate(
            total_sum=Sum(F('ordered_items__quantity') * F('ordered_items__product_info__price'))).distinct()

        serializer = OrderSerializer(basket, many=True)
        return Response(serializer.data)

    def post(self, request, *args, **kwargs):
        """
        Добавить товары в корзину пользователя.

        Args:
            request (Request): Объект запроса Django.

        Returns:
            JsonResponse: Ответ, указывающий статус операции и любые ошибки.
        """
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Error': 'Требуется авторизация'}, status=403)

        items_string = request.data.get('items')
        if items_string:
            try:
                items_dict = load_json(items_string)
            except ValueError:
                return JsonResponse({'Status': False, 'Errors': 'Неверный формат запроса'})
            else:
                basket, _ = Order.objects.get_or_create(user_id=request.user.id, state='basket')
                objects_created = 0
                for order_item in items_dict:
                    order_item.update({'order': basket.id})
                    serializer = OrderItemSerializer(data=order_item)
                    if serializer.is_valid():
                        try:
                            serializer.save()
                        except IntegrityError as error:
                            return JsonResponse({'Status': False, 'Errors': str(error)})
                        else:
                            objects_created += 1
                    else:
                        return JsonResponse({'Status': False, 'Errors': serializer.errors})

                return JsonResponse({'Status': True, 'Создано объектов': objects_created})
        return JsonResponse({'Status': False, 'Errors': 'Не указаны все необходимые аргументы'})

    def delete(self, request, *args, **kwargs):
        """
        Удалить товары из корзины пользователя.

        Args:
            request (Request): Объект запроса Django.

        Returns:
            JsonResponse: Ответ, указывающий статус операции и любые ошибки.
        """
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Error': 'Требуется авторизация'}, status=403)

        items_string = request.data.get('items')
        if items_string:
            items_list = items_string.split(',')
            basket, _ = Order.objects.get_or_create(user_id=request.user.id, state='basket')
            query = Q()
            objects_deleted = False
            for order_item_id in items_list:
                if order_item_id.isdigit():
                    query |= Q(order_id=basket.id, id=order_item_id)
                    objects_deleted = True

            if objects_deleted:
                deleted_count = OrderItem.objects.filter(query).delete()[0]
                return JsonResponse({'Status': True, 'Удалено объектов': deleted_count})
        return JsonResponse({'Status': False, 'Errors': 'Не указаны все необходимые аргументы'})

    def put(self, request, *args, **kwargs):
        """
        Обновить товары в корзине пользователя.

        Args:
            request (Request): Объект запроса Django.

        Returns:
            JsonResponse: Ответ, указывающий статус операции и любые ошибки.
        """
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Error': 'Требуется авторизация'}, status=403)

        items_string = request.data.get('items')
        if items_string:
            try:
                items_dict = load_json(items_string)
            except ValueError:
                return JsonResponse({'Status': False, 'Errors': 'Неверный формат запроса'})
            else:
                basket, _ = Order.objects.get_or_create(user_id=request.user.id, state='basket')
                objects_updated = 0
                for order_item in items_dict:
                    if isinstance(order_item['id'], int) and isinstance(order_item['quantity'], int):
                        objects_updated += OrderItem.objects.filter(order_id=basket.id, id=order_item['id']).update(
                            quantity=order_item['quantity'])

                return JsonResponse({'Status': True, 'Обновлено объектов': objects_updated})
        return JsonResponse({'Status': False, 'Errors': 'Не указаны все необходимые аргументы'})




