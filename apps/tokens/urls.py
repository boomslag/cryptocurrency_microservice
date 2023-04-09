from django.urls import path

from .views import *


urlpatterns = [
    path('list/', ListTokensView.as_view()),
    path('list/balances/', TokenBalancesView.as_view()),
    path('list/balances/polygon/', PolygonTokenBalancesView.as_view()),
    path('list/add/', AddTokenToList.as_view()),
    path('send/', SendTokensView.as_view()),
    path('send/polygon/', SendTokensPolygonView.as_view()),
    # path('<post_slug>', PostDetailView.as_view()),
    # path("search/<str:search_term>",SearchBlogView.as_view()),
]