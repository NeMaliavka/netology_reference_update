from celery import shared_task
from django.core.mail import EmailMultiAlternatives
from django.conf import settings
from backend.models import ProductInfo
import requests


@shared_task
def send_email(subject, message, recipient_list):
    """
    Отправка электронного письма.

    Args:
        subject (str): Тема письма.
        message (str): Содержимое письма.
        recipient_list (list): Список получателей.
    """
    msg = EmailMultiAlternatives(subject, message, settings.EMAIL_HOST_USER, recipient_list)
    msg.send()


@shared_task
def do_import(url):
    """
    Импорт данных из внешнего источника.

    Args:
        url (str): URL для импорта данных.
    """
    response = requests.get(url)
    data = response.json()  # Предполагаем, что данные приходят в формате JSON
    for item in data['goods']:
        product_info = ProductInfo(
            model=item['model'],
            external_id=item['id'],
            price=item['price'],
            quantity=item['quantity'],
        )
        product_info.save()
