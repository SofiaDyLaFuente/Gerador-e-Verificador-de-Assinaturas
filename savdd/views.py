from django.shortcuts import render
from django.views import View
from django.http import JsonResponse, HttpResponse
from .rsa_utils import gerar_chave
import json

def index(request):
    return render(request, 'savdd/index.html')

def gerar_chave_view(request):
    if request.method == 'POST':
        try:
            tamanho_bits = int(request.POST.get('tamanho', 1024))
            chave_publica, chave_privada = gerar_chave(tamanho_bits)
            
            response_data = {
                'publica': chave_publica,
                'privada': chave_privada,
                'tamanho': tamanho_bits
            }
            return JsonResponse(response_data)
        except Exception as e:
            return JsonResponse({'erro': str(e)}, status=400)
    return JsonResponse({'erro': 'Método não permitido'}, status=405)
