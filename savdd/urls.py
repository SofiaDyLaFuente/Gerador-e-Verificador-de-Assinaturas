from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name='assinatura'),
    path('gerar_chave/', views.gerar_chave_view, name='gerar_chave'),
    #path('assinar/', views.assinar_documento_view, name='assinar'),
    #path('verificar/', views.verificar_assinatura_view, name='verificar'),
]